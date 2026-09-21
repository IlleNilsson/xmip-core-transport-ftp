//! The client's side: a control connection, and a passive data connection
//! per transfer.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use transport::error::{Result, TransportError, classify};
use transport::socket;

use crate::reply::{self, Reply};

/// What a Location presents when it logs in.
#[derive(Clone, Debug)]
pub struct Login {
    pub user: String,
    pub password: String,
}

impl Default for Login {
    fn default() -> Self {
        Self {
            user: "anonymous".to_string(),
            password: "xmip@".to_string(),
        }
    }
}

/// One logged-in control connection.
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

    /// Retrieve `name` from the current directory.
    ///
    /// # Errors
    /// Where the file is not there, or the data connection broke.
    pub fn retrieve(&mut self, name: &str) -> Result<Vec<u8>> {
        let mut data = self.passive()?;
        let opened = self.command(&format!("RETR {name}"))?;
        if !opened.is_preliminary() {
            return Err(refused("the retrieve", &opened));
        }
        let mut bytes = Vec::new();
        data.read_to_end(&mut bytes)
            .map_err(|e| classify("reading the data", &e))?;
        drop(data);
        self.completion("the retrieve")?;
        Ok(bytes)
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
