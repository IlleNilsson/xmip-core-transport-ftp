//! The server's side of one control connection: what a Receive Location
//! that accepts uploads directly runs, and what a test or the Playground
//! puts at the far end.
//!
//! Not an FTP server. One session serves one client over a directory kept
//! in memory ([`Store`]), which several sessions may share
//! ([`Session::sharing`], and `serving.rs` for a listener's every client):
//! what is stored is handed up as a Stream, what is there is served to
//! `RETR`, `NLST` and `MLSD`, its length to `SIZE` and its write to `MDTM`
//! (RFC 3659), and `MKD`, `RMD`, `RNFR`, `RNTO` and `DELE` change it as the
//! claim needs (ADR-0024, amendment 2026-10-13). Given a certificate it
//! answers `AUTH TLS`, `PBSZ` and `PROT` (RFC 4217). Users are not checked;
//! a Location that needs accounts and a file system behind them talks to a
//! server through [`crate::Client`].

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use net::read;
use transport::error::{Result, classify, protocol_error};
use transport::socket;
use transport::taken::Taken;

use crate::listing::written;
use crate::reply::format;
use crate::store::Store;
use crate::wire::{Data, Line};

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client stored a file; here is what it stored.
    Stored(Taken),
    /// The client retrieved this name.
    Retrieved(String),
    /// The client deleted this name.
    Deleted(String),
}

pub struct Session {
    line: Line,
    peer: SocketAddr,
    timeout: Option<Duration>,
    store: Store,
    passive: Option<TcpListener>,
    /// The name an `RNFR` named, for the `RNTO` after it.
    renaming: Option<String>,
    #[cfg(feature = "tls")]
    tls: Option<std::sync::Arc<tls::ServerConfig>>,
    /// Whether `PROT P` guards the data connections.
    protected: bool,
}

impl Session {
    /// Accept one client on `listener` and greet it.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept(listener: &TcpListener, timeout: Option<Duration>) -> Result<Self> {
        let (stream, peer) = socket::accept_tcp(listener, timeout)?;
        Self::serving(stream, peer, timeout)
    }

    /// Serve the client `peer` on the accepted `stream`, and greet it.
    ///
    /// # Errors
    /// Where the greeting could not be written.
    pub fn serving(stream: TcpStream, peer: SocketAddr, timeout: Option<Duration>) -> Result<Self> {
        socket::settle(&stream, timeout)?;
        let mut session = Self {
            line: Line::plain(stream)?,
            peer,
            timeout,
            store: Store::default(),
            passive: None,
            renaming: None,
            #[cfg(feature = "tls")]
            tls: None,
            protected: false,
        };
        session.reply(220, "xmip ready")?;
        Ok(session)
    }

    /// Serve these names to `RETR` and `NLST`.
    #[must_use]
    pub fn with_files(mut self, files: BTreeMap<String, Vec<u8>>) -> Self {
        self.store = Store::holding(files);
        self
    }

    /// Serve `store`, which other sessions may serve too.
    #[must_use]
    pub fn sharing(mut self, store: Store) -> Self {
        self.store = store;
        self
    }

    /// Answer `AUTH TLS` presenting what `config` holds: FTPS.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn guarding(mut self, config: std::sync::Arc<tls::ServerConfig>) -> Self {
        self.tls = Some(config);
        self
    }

    /// What the directory holds now, stores included.
    #[must_use]
    pub fn files(&self) -> BTreeMap<String, Vec<u8>> {
        self.store.files()
    }

    /// The next file the client stores, or `None` when it quit.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_store(&mut self) -> Result<Option<Taken>> {
        loop {
            match self.next_event()? {
                Some(Event::Stored(arrived)) => return Ok(Some(arrived)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
    }

    /// The next thing the client did with the directory, or `None` when it
    /// quit. Login, mode, passive and directory commands are answered on
    /// the way.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            let Some(line) = read::line(&mut self.line.reader)? else {
                return Ok(None);
            };
            let (verb, argument) = line.split_once(' ').unwrap_or((&line, ""));
            let argument = argument.to_string();
            match verb.to_ascii_uppercase().as_str() {
                "USER" => self.reply(331, "password please")?,
                "PASS" => self.reply(230, "logged in")?,
                "TYPE" | "NOOP" => self.reply(200, "ok")?,
                "CWD" => self.reply(250, "directory changed")?,
                "PWD" => self.reply(257, "\"/\"")?,
                "PASV" => self.enter_passive()?,
                "AUTH" => self.authenticate()?,
                "PBSZ" => self.reply(200, "PBSZ=0")?,
                "PROT" => self.protect(&argument)?,
                "STOR" => return self.store(&argument).map(Some),
                "RETR" => {
                    if self.retrieve(&argument)? {
                        return Ok(Some(Event::Retrieved(argument)));
                    }
                }
                "NLST" | "LIST" => self.list(&argument, false)?,
                "MLSD" => self.list(&argument, true)?,
                "SIZE" => match self.store.stamp(&argument) {
                    Some((size, _)) => self.reply(213, &size.to_string())?,
                    None => self.reply(550, "no such file")?,
                },
                "MDTM" => match self.store.stamp(&argument) {
                    Some((_, modified)) => self.reply(213, &modified)?,
                    None => self.reply(550, "no such file")?,
                },
                "DELE" => {
                    if self.store.delete(&argument) {
                        self.reply(250, "deleted")?;
                        return Ok(Some(Event::Deleted(argument)));
                    }
                    self.reply(550, "no such file")?;
                }
                "QUIT" => {
                    self.reply(221, "goodbye")?;
                    return Ok(None);
                }
                other => self.change(other, argument)?,
            }
        }
    }

    /// A command that changes the directory's names, or one not spoken.
    fn change(&mut self, verb: &str, argument: String) -> Result<()> {
        match verb {
            "MKD" if self.store.make_directory(&argument) => self.reply(257, "created"),
            "MKD" => self.reply(550, "exists"),
            "RMD" if self.store.remove_directory(&argument) => self.reply(250, "removed"),
            "RMD" => self.reply(550, "no such empty directory"),
            "RNFR" if self.store.exists(&argument) => {
                self.renaming = Some(argument);
                self.reply(350, "ready for the new name")
            }
            "RNFR" => self.reply(550, "no such file"),
            "RNTO" => match self.renaming.take() {
                Some(from) if self.store.rename(&from, &argument) => self.reply(250, "renamed"),
                Some(_) => self.reply(553, "the new name is taken, or the file is gone"),
                None => self.reply(503, "RNFR first"),
            },
            _ => self.reply(502, "not implemented"),
        }
    }

    /// `AUTH TLS`: the control connection turned over to TLS in place.
    fn authenticate(&mut self) -> Result<()> {
        #[cfg(feature = "tls")]
        if let Some(config) = self.tls.clone() {
            self.reply(234, "AUTH TLS ok")?;
            let socket = self
                .line
                .socket
                .try_clone()
                .map_err(|e| classify("cloning the control connection", &e))?;
            let plain = std::mem::replace(&mut self.line, Line::plain(socket)?);
            self.line = crate::secure::answered(&config, plain)?;
            return Ok(());
        }
        self.reply(504, "no TLS here")
    }

    fn protect(&mut self, level: &str) -> Result<()> {
        #[cfg(feature = "tls")]
        if self.tls.is_some() {
            self.protected = level.eq_ignore_ascii_case("P");
            return self.reply(200, "protection set");
        }
        let _ = level;
        self.reply(534, "no TLS here")
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

    /// The data connection the client opened for the transfer just
    /// announced, guarded where `PROT P` said.
    fn data(&mut self) -> Result<Data> {
        let listener = self
            .passive
            .take()
            .ok_or_else(|| protocol_error("a transfer without PASV first"))?;
        // The wait for the data connection is bounded as well as the reads.
        // It was bare until 2026-09-21, and a client that never opened one
        // left the session waiting for good.
        let (stream, _) = socket::accept_tcp(&listener, self.timeout)?;
        socket::settle(&stream, self.timeout)?;
        #[cfg(feature = "tls")]
        if let (true, Some(config)) = (self.protected, &self.tls) {
            return Ok(Data::over(crate::secure::served(config, stream)?));
        }
        let _ = self.protected;
        Ok(Data::plain(stream))
    }

    fn store(&mut self, name: &str) -> Result<Event> {
        if self.passive.is_none() {
            self.reply(425, "use PASV first")?;
            return Err(protocol_error("a STOR without PASV"));
        }
        self.reply(150, "ok to send data")?;
        let mut data = self.data()?;
        let bytes = read::to_end(&mut data, net::MAX_BODY)?;
        drop(data);
        // Whole or not at all: nothing lists it half stored.
        self.store.write(name, bytes.clone());
        self.reply(226, "transfer complete")?;
        Ok(Event::Stored(Taken::new(
            format!("ftp://{}/{name}", self.peer),
            bytes,
        )))
    }

    fn retrieve(&mut self, name: &str) -> Result<bool> {
        let Some(bytes) = self.store.read(name) else {
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
        data.finish()?;
        self.reply(226, "transfer complete")?;
        Ok(true)
    }

    /// The entries of the directory `argument` names, the top where it
    /// names none: one name a line, or `MLSD`'s facts.
    fn list(&mut self, argument: &str, facts: bool) -> Result<()> {
        if self.passive.is_none() {
            return self.reply(425, "use PASV first");
        }
        let directory = (!argument.is_empty() && !argument.starts_with('-')).then_some(argument);
        if directory.is_some_and(|dir| !self.store.exists(dir)) {
            return self.reply(550, "no such directory");
        }
        self.reply(150, "here comes the listing")?;
        let mut data = self.data()?;
        for (name, file, size, modified) in self.store.list(directory) {
            let line = if facts {
                let own = name.rsplit('/').next().unwrap_or_default();
                written(own, file, size, &modified)
            } else {
                name
            };
            data.write_all(format!("{line}\r\n").as_bytes())
                .map_err(|e| classify("writing the listing", &e))?;
        }
        data.finish()?;
        self.reply(226, "transfer complete")
    }

    fn reply(&mut self, code: u16, text: &str) -> Result<()> {
        self.line
            .writer
            .write_all(&format(code, text))
            .map_err(|e| classify("writing a reply", &e))?;
        self.line
            .writer
            .flush()
            .map_err(|e| classify("flushing a reply", &e))
    }
}
