//! The kept control connection, shared by the pool and the arrivals of the
//! receive that listed on it, and the directory it reaches as the claim
//! sees one (`transport::claim::ClaimSite`).
//!
//! A receive lists and claims on the control connection and hands each
//! claimed file back unread: its body opens the transfer when the runtime
//! first reads it and reads the server's completion at its end, and its
//! acknowledgement deletes it on `Accepted` and returns it otherwise. Both
//! need the control connection after the receive has put it back in the
//! pool, so the pool keeps it shared. The lock is held for one command and
//! its reply, never while the data connection is read; a send or a receive
//! that finds a transfer running on it fails, and the pool opens it a
//! connection of its own.
//!
//! **The claim in FTP's words** (ADR-0024, amendment 2026-10-13). A turn is
//! a directory, `MKD <name>.xmip-claim`, which a server refuses where
//! anything of that name exists — the one exclusive step FTP has — and
//! inside it a directory named for its holder, so a starting node finds
//! its own. The claim is `RNFR` and `RNTO`. A return asks `SIZE` of the
//! dropped name first and renames back only where nothing lies there; a
//! server whose `RNTO` replaces an existing file could still lose one a
//! producer drops between the two, which no FTP command prevents — Xmip's
//! own server refuses such an `RNTO` (`session.rs`).

use std::io::{self, Read};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use transport::claim::{ClaimSite, Listed, Restore, is_turn};
use transport::error::{Result, TransportError, protocol_error};
use transport::pool::Pooled;
use transport::{Acknowledgement, Arrived};

use crate::client::{Client, refused};
use crate::listing::Stamp;
use crate::wire::Data;

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

    /// The file claimed as `claimed`, listed on this connection, as an
    /// arrival from `origin`: read as the runtime asks, its verdict told
    /// through `acknowledgement`.
    #[must_use]
    pub fn arrival(
        &self,
        origin: String,
        claimed: String,
        acknowledgement: Acknowledgement,
    ) -> Arrived {
        let control = self.clone();
        let body = transport::body::opened(move || {
            let data = control.retrieving(&claimed)?;
            Ok(Transfer {
                control,
                data: Some(data),
            })
        });
        Arrived::new(origin, body, acknowledgement).detected()
    }

    /// Open the transfer of `name`: the control connection is the
    /// transfer's until [`Self::retrieved`].
    fn retrieving(&self, name: &str) -> Result<Data> {
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

impl ClaimSite for Control {
    type Stamp = Stamp;

    fn listed(&self) -> Result<Vec<Listed<Stamp>>> {
        Ok(self
            .with(Client::listing)?
            .into_iter()
            .filter(|entry| entry.file)
            .map(|entry| (entry.name, entry.stamp))
            .collect())
    }

    fn turns(&self) -> Result<Vec<String>> {
        Ok(self
            .with(Client::listing)?
            .into_iter()
            .map(|entry| entry.name)
            .filter(|name| is_turn(name))
            .collect())
    }

    fn stamp(&self, name: &str) -> Result<Option<Stamp>> {
        self.with(|client| client.stamp(name))
    }

    /// `MKD`, refused where anything of the name exists, then the holder's
    /// directory inside it.
    fn take_turn(&self, turn: &str, claimant: &str) -> Result<bool> {
        self.with(|client| {
            let made = client.asked(&format!("MKD {turn}"))?;
            if made.is_transient() {
                return Err(refused("the turn", &made));
            }
            if !made.is_completion() {
                return Ok(false);
            }
            let held = client.asked(&format!("MKD {turn}/{claimant}"))?;
            if held.is_completion() {
                return Ok(true);
            }
            let _ = client.asked(&format!("RMD {turn}"))?;
            Err(refused("the turn's holder", &held))
        })
    }

    fn holder(&self, turn: &str) -> Result<Option<String>> {
        self.with(|client| {
            Ok(client
                .names_in(Some(turn))
                .ok()
                .and_then(|mut names| names.pop()))
        })
    }

    fn drop_turn(&self, turn: &str, claimant: &str) -> Result<()> {
        self.with(|client| {
            let _ = client.asked(&format!("RMD {turn}/{claimant}"))?;
            let removed = client.asked(&format!("RMD {turn}"))?;
            if removed.is_transient() {
                return Err(refused("removing the turn", &removed));
            }
            Ok(())
        })
    }

    fn rename(&self, from: &str, to: &str) -> Result<bool> {
        self.with(|client| {
            let renamed = client.rename(from, to)?;
            if renamed.is_transient() {
                return Err(refused("the claim", &renamed));
            }
            Ok(renamed.is_completion())
        })
    }

    fn restore(&self, claimed: &str, dropped: &str) -> Result<Restore> {
        self.with(|client| {
            if client.asked(&format!("SIZE {dropped}"))?.code == 213 {
                return Ok(Restore::Kept(format!(
                    "returning {dropped}: a file of that name was dropped since"
                )));
            }
            let renamed = client.rename(claimed, dropped)?;
            if renamed.is_completion() {
                return Ok(Restore::Back);
            }
            if client.asked(&format!("SIZE {claimed}"))?.code == 213 {
                return Ok(Restore::Kept(format!(
                    "returning {dropped}: the server answered {} {}",
                    renamed.code, renamed.text
                )));
            }
            Ok(Restore::Gone)
        })
    }

    fn delete(&self, name: &str) -> Result<()> {
        self.with(|client| {
            let deleted = client.asked(&format!("DELE {name}"))?;
            // 550: gone already, consumed, which is what was asked.
            if deleted.is_completion() || deleted.code == 550 {
                Ok(())
            } else {
                Err(refused("the delete", &deleted))
            }
        })
    }
}

/// One file's transfer, opened by its body's first read: the data
/// connection read to its end, the server's completion read after it.
struct Transfer {
    control: Control,
    /// `None` once the data connection ended.
    data: Option<Data>,
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
