//! The server's side of one control connection: what a Receive Location
//! that accepts uploads directly runs, and what a test puts at the far end.
//!
//! Not an FTP server. One session serves one client over one directory kept
//! in memory: what is stored is handed up as a Stream, what was given is
//! served to `RETR` and `NLST`. Users are not checked; a Location that needs
//! accounts and a file system behind them talks to a server through
//! [`crate::Client`].

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use transport::Arrived;
use transport::error::{Result, classify, protocol_error};
use transport::socket;

use crate::reply::format;

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client stored a file; here is the Stream.
    Stored(Arrived),
    /// The client retrieved this name.
    Retrieved(String),
    /// The client deleted this name.
    Deleted(String),
}

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    peer: SocketAddr,
    timeout: Option<Duration>,
    files: BTreeMap<String, Vec<u8>>,
    passive: Option<TcpListener>,
}

impl Session {
    /// Accept one client on `listener` and greet it.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept(listener: &TcpListener, timeout: Option<Duration>) -> Result<Self> {
        let (stream, peer) = socket::accept_tcp(listener, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut session = Self {
            reader,
            writer,
            peer,
            timeout,
            files: BTreeMap::new(),
            passive: None,
        };
        session.reply(220, "xmip ready")?;
        Ok(session)
    }

    /// Serve these names to `RETR` and `NLST`.
    #[must_use]
    pub fn with_files(mut self, files: BTreeMap<String, Vec<u8>>) -> Self {
        self.files = files;
        self
    }

    /// What the directory holds now, stores included.
    #[must_use]
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    /// The next file the client stores, or `None` when it quit.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_store(&mut self) -> Result<Option<Arrived>> {
        loop {
            match self.next_event()? {
                Some(Event::Stored(arrived)) => return Ok(Some(arrived)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
    }

    /// The next thing the client did with the directory, or `None` when it
    /// quit. Login, mode and passive commands are answered on the way.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            let mut line = String::new();
            let read = self
                .reader
                .read_line(&mut line)
                .map_err(|e| classify("reading a command", &e))?;
            if read == 0 {
                return Ok(None);
            }
            let line = line.trim_end_matches(['\r', '\n']);
            let (verb, argument) = line.split_once(' ').unwrap_or((line, ""));
            match verb.to_ascii_uppercase().as_str() {
                "USER" => self.reply(331, "password please")?,
                "PASS" => self.reply(230, "logged in")?,
                "TYPE" | "NOOP" => self.reply(200, "ok")?,
                "CWD" => self.reply(250, "directory changed")?,
                "PWD" => self.reply(257, "\"/\"")?,
                "PASV" => self.enter_passive()?,
                "STOR" => return self.store(argument).map(Some),
                "RETR" => {
                    if self.retrieve(argument)? {
                        return Ok(Some(Event::Retrieved(argument.to_string())));
                    }
                }
                "NLST" | "LIST" => self.list()?,
                "DELE" => {
                    if self.files.remove(argument).is_some() {
                        self.reply(250, "deleted")?;
                        return Ok(Some(Event::Deleted(argument.to_string())));
                    }
                    self.reply(550, "no such file")?;
                }
                "QUIT" => {
                    self.reply(221, "goodbye")?;
                    return Ok(None);
                }
                _ => self.reply(502, "not implemented")?,
            }
        }
    }

    fn enter_passive(&mut self) -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| classify("binding the data listener", &e))?;
        let address = listener
            .local_addr()
            .map_err(|e| classify("reading the data address", &e))?;
        let port = address.port();
        let text = match address.ip() {
            std::net::IpAddr::V4(ip) => {
                let [a, b, c, d] = ip.octets();
                format!(
                    "Entering Passive Mode ({a},{b},{c},{d},{},{})",
                    port / 256,
                    port % 256
                )
            }
            std::net::IpAddr::V6(_) => return Err(protocol_error("passive mode needs IPv4")),
        };
        self.passive = Some(listener);
        self.reply(227, &text)
    }

    fn data(&mut self) -> Result<TcpStream> {
        let listener = self
            .passive
            .take()
            .ok_or_else(|| protocol_error("a transfer without PASV first"))?;
        let (stream, _) = listener
            .accept()
            .map_err(|e| classify("accepting the data connection", &e))?;
        if let Some(timeout) = self.timeout {
            stream
                .set_read_timeout(Some(timeout))
                .map_err(|e| classify("setting the data timeout", &e))?;
        }
        Ok(stream)
    }

    fn store(&mut self, name: &str) -> Result<Event> {
        if self.passive.is_none() {
            self.reply(425, "use PASV first")?;
            return Err(protocol_error("a STOR without PASV"));
        }
        self.reply(150, "ok to send data")?;
        let mut data = self.data()?;
        let mut bytes = Vec::new();
        data.read_to_end(&mut bytes)
            .map_err(|e| classify("reading the data", &e))?;
        drop(data);
        self.files.insert(name.to_string(), bytes.clone());
        self.reply(226, "transfer complete")?;
        Ok(Event::Stored(Arrived::new(
            format!("ftp://{}/{name}", self.peer),
            bytes,
        )))
    }

    fn retrieve(&mut self, name: &str) -> Result<bool> {
        let Some(bytes) = self.files.get(name).cloned() else {
            self.reply(550, "no such file")?;
            return Ok(false);
        };
        if self.passive.is_none() {
            self.reply(425, "use PASV first")?;
            return Ok(false);
        }
        self.reply(150, "opening data connection")?;
        let mut data = self.data()?;
        data.write_all(&bytes)
            .map_err(|e| classify("writing the data", &e))?;
        drop(data);
        self.reply(226, "transfer complete")?;
        Ok(true)
    }

    fn list(&mut self) -> Result<()> {
        if self.passive.is_none() {
            return self.reply(425, "use PASV first");
        }
        self.reply(150, "here comes the listing")?;
        let mut data = self.data()?;
        for name in self.files.keys() {
            data.write_all(format!("{name}\r\n").as_bytes())
                .map_err(|e| classify("writing the listing", &e))?;
        }
        drop(data);
        self.reply(226, "transfer complete")
    }

    fn reply(&mut self, code: u16, text: &str) -> Result<()> {
        self.writer
            .write_all(&format(code, text))
            .map_err(|e| classify("writing a reply", &e))?;
        self.writer
            .flush()
            .map_err(|e| classify("flushing a reply", &e))
    }
}
