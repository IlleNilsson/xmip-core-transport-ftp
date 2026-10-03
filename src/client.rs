//! The client's side: a control connection, kept between transfers, and a
//! passive data connection per transfer — stream mode says a file has
//! ended by closing its data connection, so that one is the protocol's to
//! open each time.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use transport::error::{Result, TransportError, classify};
use transport::pool::{Pooled, alive};
use transport::{Login, socket};

use crate::reply::{self, Reply};

/// The anonymous login, what a Location presents unless it names a user.
#[must_use]
pub fn anonymous() -> Login {
    Login::new("anonymous", "xmip@")
}

/// One logged-in control connection, kept between transfers while the
/// server keeps it open.
pub struct Client {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    timeout: Option<Duration>,
}

impl Client {
    /// Connect to `server`, log in, and switch to binary.
    ///
    /// # Errors
    /// Where the server could not be reached, did not greet, or refused the
    /// login.
    pub fn connect(server: &str, login: &Login, timeout: Option<Duration>) -> Result<Self> {
        let stream = socket::connect_tcp(server, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut client = Self {
            reader,
            writer,
            timeout,
        };
        let greeting = reply::read(&mut client.reader)?;
        if !greeting.is_completion() {
            return Err(refused("the greeting", &greeting));
        }
        let user = client.command(&format!("USER {}", login.user))?;
        if user.is_intermediate() {
            let pass = client.command(&format!("PASS {}", login.password))?;
            if !pass.is_completion() {
                return Err(refused("the login", &pass));
            }
        } else if !user.is_completion() {
            return Err(refused("the user", &user));
        }
        let binary = client.command("TYPE I")?;
        if !binary.is_completion() {
            return Err(refused("binary mode", &binary));
        }
        Ok(client)
    }

    /// Send one command and read its reply.
    ///
    /// # Errors
    /// Where the control connection broke.
    pub fn command(&mut self, command: &str) -> Result<Reply> {
        self.writer
            .write_all(format!("{command}\r\n").as_bytes())
            .map_err(|e| classify("writing a command", &e))?;
        self.writer
            .flush()
            .map_err(|e| classify("flushing a command", &e))?;
        reply::read(&mut self.reader)
    }

    /// Store `bytes` as `name` in the current directory.
    ///
    /// # Errors
    /// Where the server refused the store or the data connection broke.
    pub fn store(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut data = self.passive()?;
        let opened = self.command(&format!("STOR {name}"))?;
        if !opened.is_preliminary() {
            return Err(refused("the store", &opened));
        }
        data.write_all(bytes)
            .map_err(|e| classify("writing the data", &e))?;
        drop(data);
        self.completion("the store")
    }

    /// Start retrieving `name` from the current directory: the data
    /// connection to read it from, to its end. The control connection is
    /// the transfer's until [`Self::retrieved`] reads its completion.
    ///
    /// # Errors
    /// Where the file is not there or the data connection could not open.
    pub fn retrieving(&mut self, name: &str) -> Result<TcpStream> {
        let data = self.passive()?;
        let opened = self.command(&format!("RETR {name}"))?;
        if !opened.is_preliminary() {
            return Err(refused("the retrieve", &opened));
        }
        Ok(data)
    }

    /// The server's completion of a retrieve whose data connection was read
    /// to its end and closed.
    ///
    /// # Errors
    /// Where the server said the transfer failed.
    pub fn retrieved(&mut self) -> Result<()> {
        self.completion("the retrieve")
    }

    /// The names in the current directory, one per line of `NLST`.
    ///
    /// # Errors
    /// Where the listing was refused or the data connection broke.
    pub fn names(&mut self) -> Result<Vec<String>> {
        let data = self.passive()?;
        let opened = self.command("NLST")?;
        if !opened.is_preliminary() {
            return Err(refused("the listing", &opened));
        }
        let names = BufReader::new(data)
            .lines()
            .map_while(std::result::Result::ok)
            .filter(|line| !line.is_empty())
            .collect();
        self.completion("the listing")?;
        Ok(names)
    }

    /// Delete `name`.
    ///
    /// # Errors
    /// Where the server refused.
    pub fn delete(&mut self, name: &str) -> Result<()> {
        let reply = self.command(&format!("DELE {name}"))?;
        if reply.is_completion() {
            Ok(())
        } else {
            Err(refused("the delete", &reply))
        }
    }

    /// Say goodbye.
    ///
    /// # Errors
    /// Where the control connection was already gone.
    pub fn quit(mut self) -> Result<()> {
        self.command("QUIT").map(|_| ())
    }

    fn passive(&mut self) -> Result<TcpStream> {
        let reply = self.command("PASV")?;
        if reply.code != 227 {
            return Err(refused("passive mode", &reply));
        }
        // The connect is bounded as well as the reads. It was bare until
        // 2026-09-21, and a machine out of ephemeral ports waited without end.
        socket::connect_tcp(&reply.passive_address()?, self.timeout)
    }

    fn completion(&mut self, what: &str) -> Result<()> {
        let reply = reply::read(&mut self.reader)?;
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
        alive(&self.writer)
    }
}

fn refused(what: &str, reply: &Reply) -> TransportError {
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
