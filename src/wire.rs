//! The two connections FTP speaks over, plain or guarded alike: the control
//! connection as a line reader and a writer, and a data connection read or
//! written to its end.
//!
//! FTPS (RFC 4217) is FTP over the estate's TLS (`xmip-core-library-tls`,
//! ADR-0033): `AUTH TLS` turns the control connection over to TLS in place,
//! and `PROT P` guards every data connection after it (`secure.rs`, behind
//! the `tls` feature). Everything above this file speaks to a [`Line`] and a
//! [`Data`] and never asks which.

use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;

use transport::error::{Result, classify};

/// The reading half of a control connection.
pub type Reader = BufReader<Box<dyn Read + Send>>;

/// The writing half of a control connection.
pub type Writer = Box<dyn Write + Send>;

/// A control connection: its two halves, and the socket under them, which
/// answers whether the peer is still there.
pub struct Line {
    pub reader: Reader,
    pub writer: Writer,
    pub socket: TcpStream,
}

impl Line {
    /// A control connection in the clear.
    ///
    /// # Errors
    /// Where the socket could not be shared between the halves.
    pub fn plain(socket: TcpStream) -> Result<Self> {
        let reading = socket
            .try_clone()
            .map_err(|e| classify("cloning the control connection", &e))?;
        let writing = socket
            .try_clone()
            .map_err(|e| classify("cloning the control connection", &e))?;
        Ok(Self {
            reader: BufReader::new(Box::new(reading)),
            writer: Box::new(writing),
            socket,
        })
    }
}

/// A data connection, read to its end or written and finished.
pub trait DataStream: Read + Write + Send {
    /// Say the transfer is over: nothing in the clear, where TLS says so
    /// before the socket closes, so the peer can tell an end from a cut.
    ///
    /// # Errors
    /// Where the close could not be sent.
    fn finish(&mut self) -> io::Result<()>;
}

impl DataStream for TcpStream {
    fn finish(&mut self) -> io::Result<()> {
        self.flush()
    }
}

/// One transfer's data connection.
pub struct Data(Box<dyn DataStream>);

impl Data {
    /// A data connection in the clear.
    #[must_use]
    pub fn plain(socket: TcpStream) -> Self {
        Self(Box::new(socket))
    }

    /// A data connection over `stream`.
    #[must_use]
    pub fn over(stream: Box<dyn DataStream>) -> Self {
        Self(stream)
    }

    /// Everything written, the transfer said to be over, and the connection
    /// closed: how stream mode ends a file.
    ///
    /// # Errors
    /// Where the close could not be sent.
    pub fn finish(mut self) -> Result<()> {
        self.0
            .finish()
            .map_err(|e| classify("ending the transfer", &e))
    }
}

impl Read for Data {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer)
    }
}

impl Write for Data {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
