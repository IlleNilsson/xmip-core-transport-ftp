//! The kept control connection, shared by the pool and the arrivals of the
//! receive that listed on it.
//!
//! A receive lists on the control connection and hands each file back
//! unread: its body opens the transfer when the runtime first reads it and
//! reads the server's completion at its end, and its acknowledgement
//! deletes it on `Accepted`. Both need the control connection after the
//! receive has put it back in the pool, so the pool keeps it shared. The
//! lock is held for one command and its reply, never while the data
//! connection is read; a send or a receive that finds a transfer running
//! on it fails, and the pool opens it a connection of its own.

use std::io::{self, Read};
use std::net::TcpStream;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use transport::body::opened;
use transport::error::{Result, TransportError, protocol_error};
use transport::pool::Pooled;
use transport::{Acknowledgement, Arrived, Verdict};

use crate::client::Client;

/// The client, and whether a transfer is running on it.
struct Line {
    /// `None` once a transfer was left half read: the control connection
    /// then owes a reply nobody will read, so it carries nothing more.
    client: Option<Client>,
    transferring: bool,
}

/// A logged-in control connection, kept by the pool and shared with the
/// arrivals of the receive that listed on it.
#[derive(Clone)]
pub struct Control(Arc<Mutex<Line>>);

impl Control {
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self(Arc::new(Mutex::new(Line {
            client: Some(client),
            transferring: false,
        })))
    }

    fn line(&self) -> MutexGuard<'_, Line> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Run `act` on the client when no transfer is running on it.
    ///
    /// # Errors
    /// Where a transfer is running or was left half read — the pool then
    /// opens a connection of its own — or as `act`.
    pub fn with<T>(&self, act: impl FnOnce(&mut Client) -> Result<T>) -> Result<T> {
        let mut line = self.line();
        if line.transferring {
            return Err(TransportError::retryable(
                "a retrieve is running on the control connection",
            ));
        }
        let client = line
            .client
            .as_mut()
            .ok_or_else(|| protocol_error("the control connection was left mid-transfer"))?;
        act(client)
    }

    /// `name`, listed on this connection, as an arrival from `origin`: read
    /// as the runtime asks, deleted on `Accepted` and on `Refused` where
    /// `delete` says — a directory has no place for a refused file — and
    /// left on `Failed`.
    #[must_use]
    pub fn arrival(&self, origin: String, name: String, delete: bool) -> Arrived {
        let control = self.clone();
        let deleting = name.clone();
        let acknowledgement = Acknowledgement::deferred(move |verdict| match verdict {
            Verdict::Accepted | Verdict::Refused(_) if delete => {
                control.with(|client| client.delete(&deleting))
            }
            Verdict::Accepted | Verdict::Refused(_) | Verdict::Failed => Ok(()),
        });
        let control = self.clone();
        let body = opened(move || {
            let data = control.retrieving(&name)?;
            Ok(Transfer {
                control,
                data: Some(data),
            })
        });
        Arrived::new(origin, body, acknowledgement)
    }

    /// Open the transfer of `name`: the control connection is the
    /// transfer's until [`Self::retrieved`].
    fn retrieving(&self, name: &str) -> Result<TcpStream> {
        let data = self.with(|client| client.retrieving(name))?;
        self.line().transferring = true;
        Ok(data)
    }

    /// The transfer's completion read, and the control connection free.
    fn retrieved(&self) -> Result<()> {
        let mut line = self.line();
        line.transferring = false;
        let client = line
            .client
            .as_mut()
            .ok_or_else(|| protocol_error("the control connection was left mid-transfer"))?;
        client.retrieved()
    }

    /// A transfer left half read: the connection is let go.
    fn abandoned(&self) {
        let mut line = self.line();
        line.transferring = false;
        line.client = None;
    }
}

impl Pooled for Control {
    fn usable(&mut self) -> bool {
        self.line().client.as_mut().is_some_and(Pooled::usable)
    }
}

/// One file's transfer, opened by its body's first read: the data
/// connection read to its end, the server's completion read after it.
struct Transfer {
    control: Control,
    /// `None` once the data connection ended.
    data: Option<TcpStream>,
}

impl Read for Transfer {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let Some(data) = self.data.as_mut() else {
            return Ok(0);
        };
        let read = data.read(buffer)?;
        if read == 0 {
            // Stream mode ends a file by closing its data connection.
            self.data = None;
            self.control.retrieved().map_err(io::Error::other)?;
        }
        Ok(read)
    }
}

impl Drop for Transfer {
    fn drop(&mut self) {
        if self.data.is_some() {
            self.control.abandoned();
        }
    }
}
