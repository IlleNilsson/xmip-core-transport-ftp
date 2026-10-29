//! The client's side: a control connection, kept between transfers, and a
//! passive data connection per transfer — stream mode says a file has
//! ended by closing its data connection, so that one is the protocol's to
//! open each time. Either is guarded where the client speaks FTPS
//! (`secure.rs`).

use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

use transport::error::{Result, TransportError, classify};
use transport::pool::{Pooled, alive};
use transport::{Login, socket};

use crate::listing::{self, Stamp};
use crate::reply::{self, Reply};
#[cfg(feature = "tls")]
use crate::secure::Secured;
use crate::wire::{Data, Line};

/// The anonymous login, what a Location presents unless it names a user.
#[must_use]
pub fn anonymous() -> Login {
    Login::new("anonymous", "xmip@")
}

/// One logged-in control connection, kept between transfers while the
/// server keeps it open.
pub struct Client {
    line: Line,
    server: String,
    timeout: Option<Duration>,
    /// Whether the server answers `MLSD`; asked once, by the first listing.
    listing: Option<bool>,
    #[cfg(feature = "tls")]
    secured: Option<Secured>,
}

impl Client {
    /// Connect to `server`, log in, and switch to binary.
    ///
    /// # Errors
    /// Where the server could not be reached, did not greet, or refused the
    /// login.
    pub fn connect(server: &str, login: &Login, timeout: Option<Duration>) -> Result<Self> {
        let stream = socket::connect_tcp(server, timeout)?;
        let mut client = Self {
            line: Line::plain(stream)?,
            server: server.to_string(),
            timeout,
            listing: None,
            #[cfg(feature = "tls")]
            secured: None,
        };
        client.greeted()?;
        client.logged_in(login)?;
        Ok(client)
    }

    /// Connect to `server` as FTPS: `AUTH TLS` before the login, then every
    /// transfer guarded (RFC 4217).
    ///
    /// # Errors
    /// As [`Self::connect`], and where the server refused TLS or the
    /// handshake failed.
    #[cfg(feature = "tls")]
    pub fn connect_secured(
        server: &str,
        login: &Login,
        timeout: Option<Duration>,
        secured: &Secured,
    ) -> Result<Self> {
        let stream = socket::connect_tcp(server, timeout)?;
        let mut plain = Self {
            line: Line::plain(stream)?,
            server: server.to_string(),
            timeout,
            listing: None,
            secured: Some(secured.clone()),
        };
        plain.greeted()?;
        let auth = plain.command("AUTH TLS")?;
        if auth.code != 234 {
            return Err(refused("TLS", &auth));
        }
        let mut client = Self {
            line: secured.control(server, plain.line)?,
            ..plain
        };
        client.logged_in(login)?;
        for command in ["PBSZ 0", "PROT P"] {
            let reply = client.command(command)?;
            if !reply.is_completion() {
                return Err(refused("data protection", &reply));
            }
        }
        Ok(client)
    }

    fn greeted(&mut self) -> Result<()> {
        let greeting = reply::read(&mut self.line.reader)?;
        if greeting.is_completion() {
            Ok(())
        } else {
            Err(refused("the greeting", &greeting))
        }
    }

    fn logged_in(&mut self, login: &Login) -> Result<()> {
        let user = self.command(&format!("USER {}", login.user))?;
        if user.is_intermediate() {
            let pass = self.command(&format!("PASS {}", login.password))?;
            if !pass.is_completion() {
                return Err(refused("the login", &pass));
            }
        } else if !user.is_completion() {
            return Err(refused("the user", &user));
        }
        self.completed("TYPE I", "binary mode")
    }

    /// Send one command and read its reply.
    ///
    /// # Errors
    /// Where the control connection broke.
    pub fn command(&mut self, command: &str) -> Result<Reply> {
        self.line
            .writer
            .write_all(format!("{command}\r\n").as_bytes())
            .map_err(|e| classify("writing a command", &e))?;
        self.line
            .writer
            .flush()
            .map_err(|e| classify("flushing a command", &e))?;
        reply::read(&mut self.line.reader)
    }

    /// Change to `directory` (`CWD`), where a Location's address names one.
    ///
    /// # Errors
    /// Where the server refused the directory or the connection broke.
    pub fn change_directory(&mut self, directory: &str) -> Result<()> {
        self.completed(&format!("CWD {directory}"), "the directory")
    }

    /// Send `command` and hold its reply to a completion.
    fn completed(&mut self, command: &str, what: &str) -> Result<()> {
        let reply = self.command(command)?;
        if reply.is_completion() {
            Ok(())
        } else {
            Err(refused(what, &reply))
        }
    }

    /// Store `outgoing`'s body as `name` in the current directory, written
    /// to the data connection as it is read, never whole in memory.
    ///
    /// # Errors
    /// Where the server refused the store or the data connection broke.
    pub fn store(&mut self, name: &str, outgoing: &transport::Outgoing<'_>) -> Result<()> {
        let mut data = self.opened(&format!("STOR {name}"), "the store")?;
        outgoing.write_to(&mut data)?;
        data.finish()?;
        self.completion("the store")
    }

    /// Start retrieving `name` from the current directory: the data
    /// connection to read it from, to its end. The control connection is
    /// the transfer's until [`Self::retrieved`] reads its completion.
    ///
    /// # Errors
    /// Where the file is not there or the data connection could not open.
    pub fn retrieving(&mut self, name: &str) -> Result<Data> {
        self.opened(&format!("RETR {name}"), "the retrieve")
    }

    /// The server's completion of a retrieve whose data connection was read
    /// to its end and closed.
    ///
    /// # Errors
    /// Where the server said the transfer failed.
    pub fn retrieved(&mut self) -> Result<()> {
        self.completion("the retrieve")
    }

    /// The names `NLST` gives, of the current directory or of `directory`.
    ///
    /// # Errors
    /// Where the listing was refused or the data connection broke.
    pub fn names_in(&mut self, directory: Option<&str>) -> Result<Vec<String>> {
        let command = directory.map_or_else(|| "NLST".to_string(), |dir| format!("NLST {dir}"));
        let data = self.opened(&command, "the listing")?;
        let names = BufReader::new(data)
            .lines()
            .map_while(std::result::Result::ok)
            .filter(|line| !line.is_empty())
            .map(|line| line.rsplit('/').next().unwrap_or_default().to_string())
            .collect();
        self.completion("the listing")?;
        Ok(names)
    }

    /// The names in the current directory, one per line of `NLST`.
    ///
    /// # Errors
    /// Where the listing was refused or the data connection broke.
    pub fn names(&mut self) -> Result<Vec<String>> {
        self.names_in(None)
    }

    /// Every entry of the current directory with its kind and stamp:
    /// `MLSD` (RFC 3659) where the server answers it, else `NLST` and each
    /// name's [`Self::stamp`], every name then taken for a file.
    ///
    /// # Errors
    /// Where the listing was refused or the data connection broke.
    pub fn listing(&mut self) -> Result<Vec<listing::Entry>> {
        if self.listing != Some(false) {
            let data = self.passive()?;
            let opened = self.command("MLSD")?;
            if opened.is_preliminary() {
                self.listing = Some(true);
                let data = self.guarded(data)?;
                let lines: Vec<String> = BufReader::new(data)
                    .lines()
                    .map_while(std::result::Result::ok)
                    .collect();
                self.completion("the listing")?;
                return Ok(lines
                    .iter()
                    .filter_map(|line| listing::fact_line(line))
                    .collect());
            }
            if opened.is_transient() {
                return Err(refused("the listing", &opened));
            }
            self.listing = Some(false);
        }
        let mut entries = Vec::new();
        for name in self.names()? {
            let stamp = self.stamp(&name)?;
            entries.push(listing::Entry::file(name, stamp));
        }
        Ok(entries)
    }

    /// What says `name` is unchanged: its length (`SIZE`) and its
    /// modification time (`MDTM`), RFC 3659, as the server writes them.
    /// `None` where the server answers neither — it is gone, or cannot say.
    ///
    /// # Errors
    /// Where the control connection broke.
    pub fn stamp(&mut self, name: &str) -> Result<Option<Stamp>> {
        let size = self.command(&format!("SIZE {name}"))?;
        let time = self.command(&format!("MDTM {name}"))?;
        let answered = |reply: &Reply| (reply.code == 213).then(|| reply.text.trim().to_string());
        Ok(Stamp::of(answered(&size), answered(&time)))
    }

    /// Delete `name`.
    ///
    /// # Errors
    /// Where the server refused.
    pub fn delete(&mut self, name: &str) -> Result<()> {
        self.completed(&format!("DELE {name}"), "the delete")
    }

    /// The reply to `command`: what the claim's directory operations need
    /// to tell a refusal from a failure.
    ///
    /// # Errors
    /// Where the control connection broke.
    pub fn asked(&mut self, command: &str) -> Result<Reply> {
        self.command(command)
    }

    /// Rename `from` to `to`: `RNFR`, then `RNTO`. The reply that ended it:
    /// `RNFR`'s where it was refused, `RNTO`'s otherwise.
    ///
    /// # Errors
    /// Where the control connection broke.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<Reply> {
        let asked = self.command(&format!("RNFR {from}"))?;
        if !asked.is_intermediate() {
            return Ok(asked);
        }
        self.command(&format!("RNTO {to}"))
    }

    /// Say goodbye.
    ///
    /// # Errors
    /// Where the control connection was already gone.
    pub fn quit(mut self) -> Result<()> {
        self.command("QUIT").map(|_| ())
    }

    /// A data connection for `command`, opened once the server said it is
    /// about to transfer.
    fn opened(&mut self, command: &str, what: &str) -> Result<Data> {
        let data = self.passive()?;
        let opened = self.command(command)?;
        if !opened.is_preliminary() {
            return Err(refused(what, &opened));
        }
        self.guarded(data)
    }

    fn passive(&mut self) -> Result<std::net::TcpStream> {
        let reply = self.command("PASV")?;
        if reply.code != 227 {
            return Err(refused("passive mode", &reply));
        }
        // The connect is bounded as well as the reads. It was bare until
        // 2026-09-21, and a machine out of ephemeral ports waited without end.
        socket::connect_tcp(&reply.passive_address()?, self.timeout)
    }

    /// `socket` as this client's transfers speak: guarded where it speaks
    /// FTPS.
    #[allow(clippy::unnecessary_wraps)]
    fn guarded(&self, socket: std::net::TcpStream) -> Result<Data> {
        #[cfg(feature = "tls")]
        if let Some(secured) = &self.secured {
            return Ok(Data::over(secured.data(&self.server, socket)?));
        }
        let _ = &self.server;
        Ok(Data::plain(socket))
    }

    fn completion(&mut self, what: &str) -> Result<()> {
        let reply = reply::read(&mut self.line.reader)?;
        if reply.is_completion() {
            Ok(())
        } else {
            Err(refused(what, &reply))
        }
    }
}

impl Pooled for Client {
    /// While the server has not closed the control connection — an idle
    /// timeout closes it, with a 421 first.
    fn usable(&mut self) -> bool {
        alive(&self.line.socket)
    }
}

/// The server's `reply` to `what`, as a failure: retryable where the reply
/// is transient.
#[must_use]
pub fn refused(what: &str, reply: &Reply) -> TransportError {
    let message = format!(
        "the server answered {what} with {} {}",
        reply.code, reply.text
    );
    if reply.is_transient() {
        TransportError::retryable(message)
    } else {
        TransportError::permanent(message)
    }
}
