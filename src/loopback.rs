//! FTP at both ends on this machine (ADR-0051): a client storing one file
//! into a session's directory, and the session handing the store up whole.

use std::net::TcpListener;

use net::login::{self, Check};
use transport::ArrivalIdentity;
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::taken::Taken;
use transport::{Login, Transport};

use crate::FtpTransport;

impl FtpTransport {
    /// Both ends on this machine: an ephemeral local port, the user `xmip`
    /// with a password minted for this loopback, which its far end alone
    /// admits, and the loopback timeout on every read.
    #[must_use]
    pub fn loopback() -> Self {
        let minted = codec::hex::encode(&codec::random::array::<32>());
        Self::new("127.0.0.1:0")
            .logging_in(Login::new("xmip", minted))
            .timing_out_after(LOOPBACK_TIMEOUT)
    }

    /// What its far end is handed: the one login its near end presents,
    /// and no one where it presents none.
    fn own_login(&self) -> Check {
        self.login.as_ref().map_or_else(login::nobody, |own| {
            login::only(own.user.clone(), own.password.clone())
        })
    }
}

impl Accepting for FtpTransport {
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        // The client keeps its control connection for the next store.
        let check = self.own_login();
        self.accept_one(listener, check)?
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
        let near = Self::new(address).timing_out_after(LOOPBACK_TIMEOUT);
        match &self.login {
            Some(own) => near.logging_in(own.clone()),
            None => near,
        }
        .send("probe.bin", payload)
    }
}
