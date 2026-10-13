//! FTP at both ends on this machine (ADR-0051): a client storing one file
//! into a session's directory, and the session handing the store up whole.

use std::net::TcpListener;

use transport::ArrivalIdentity;
use transport::Transport;
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::taken::Taken;

use crate::FtpTransport;

impl FtpTransport {
    /// Both ends on this machine: an ephemeral local port, an anonymous
    /// login, the loopback timeout on every read.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0").timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for FtpTransport {
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        // The client keeps its control connection for the next store.
        self.accept_one(listener)?
            .next_store()?
            .ok_or_else(|| protocol_error("the client quit without storing"))
    }
}

impl Loopback for FtpTransport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::Unnamed(
            "a file names no sender: the share it was taken from is in its origin",
        )
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::new(address)
            .timing_out_after(LOOPBACK_TIMEOUT)
            .send("probe.bin", payload)
    }
}
