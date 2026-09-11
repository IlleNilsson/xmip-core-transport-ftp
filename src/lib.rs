#![forbid(unsafe_code)]

//! Streams that arrive as files over FTP. One file is one Stream, its name
//! kept beside it.
//!
//! FTP is the partner drop box that predates every other one: a control
//! connection on port 21, a data connection per transfer, files in
//! directories. A Receive Location logs in, lists a directory and retrieves
//! what is there, deleting each file once it is safely a Stream; a Send
//! Location logs in and stores. Either may instead accept clients directly
//! through [`Session`], one client's worth of server over one directory.
//!
//! What is here is RFC 959 in passive mode and binary type — the shape a
//! firewall lets through. FTPS is TLS on both connections and joins when the
//! transport capability's TLS reaches this socket (ADR-0033).
//!
//! FTP has artefacts and no locking, so [`Transport::claims`] answers
//! [`NoNativeClaim`], ADR-0024 clause 5: a producer writes to a temporary
//! name and renames, or a Location waits for a listing to stop changing.
//!
//! The origin URI carries what the server knew: `ftp://server/orders/1.edi`.

pub mod client;
pub mod reply;
pub mod session;

use std::net::TcpListener;
use std::time::Duration;

pub use client::{Client, Login};
pub use reply::Reply;
pub use session::{Event, Session};
use transport::error::{Result, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{Arrived, Directions, NoNativeClaim, ResourceClaim, Transport};

#[derive(Clone)]
pub struct FtpTransport {
    server: String,
    login: Login,
    delete_after_retrieve: bool,
    timeout: Option<Duration>,
}

impl FtpTransport {
    /// Speak to the server at `server`, anonymous unless [`Self::logging_in`].
    #[must_use]
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            login: Login::default(),
            delete_after_retrieve: true,
            timeout: None,
        }
    }

    /// Log in as this.
    #[must_use]
    pub fn logging_in(mut self, login: Login) -> Self {
        self.login = login;
        self
    }

    /// Leave retrieved files in place rather than deleting them.
    #[must_use]
    pub const fn leaving_files(mut self) -> Self {
        self.delete_after_retrieve = false;
        self
    }

    /// Give up on a peer that stops mid-transfer.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Connect and log in.
    ///
    /// # Errors
    /// Where the server could not be reached or refused the login.
    pub fn connect(&self) -> Result<Client> {
        Client::connect(&self.server, &self.login, self.timeout)
    }

    /// Bind as the far end clients connect to, and report the address.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.server)
    }

    /// Accept one client on an already-bound listener.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Session> {
        Session::accept(listener, self.timeout)
    }

    /// Where a target names the server and file itself — `ftp://host/name`
    /// — or is a name alone on this transport's server.
    fn resolve<'a>(&'a self, target: &'a str) -> (&'a str, &'a str) {
        socket::target("ftp", target).unwrap_or((&self.server, target))
    }
}

impl Transport for FtpTransport {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// Every file in the directory, each deleted once retrieved unless the
    /// transport was told to leave them.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let mut client = self.connect()?;
        let mut arrived = Vec::new();
        for name in client.names()? {
            let bytes = client.retrieve(&name)?;
            if self.delete_after_retrieve {
                client.delete(&name)?;
            }
            arrived.push(Arrived::new(format!("ftp://{}/{name}", self.server), bytes));
        }
        client.quit()?;
        Ok(arrived)
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (server, name) = self.resolve(target);
        let mut client = Client::connect(server, &self.login, self.timeout)?;
        client.store(name, bytes)?;
        client.quit()
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl FtpTransport {
    /// Both ends on this machine: an ephemeral local port, an anonymous
    /// login, the loopback timeout on every read.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0").timing_out_after(LOOPBACK_TIMEOUT)
    }
}

/// A bound listener waiting for the one client that stores one file.
struct Listening {
    transport: FtpTransport,
    listener: TcpListener,
    address: String,
}

impl FarEnd for Listening {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let mut session = self.transport.accept_one(&self.listener)?;
        let arrived = session
            .next_store()?
            .ok_or_else(|| protocol_error("the client quit without storing"))?;
        // Serve the QUIT that follows, so the client's goodbye is answered
        // rather than met by a closed socket.
        session.next_store()?;
        Ok(arrived)
    }
}

impl Loopback for FtpTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind()?;
        Ok(Box::new(Listening {
            transport: self.clone(),
            listener,
            address,
        }))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::new(address)
            .timing_out_after(LOOPBACK_TIMEOUT)
            .send("probe.bin", payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn edges() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
        ]
    }

    #[test]
    fn the_loopback_stores_one_file_and_takes_it() {
        let arrived = FtpTransport::loopback().round(b"UNA:+.? '").expect("round");
        assert_eq!(arrived.bytes, b"UNA:+.? '");
        assert!(arrived.origin_uri.starts_with("ftp://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/probe.bin"));
        let long = vec![0x2a; 100_000];
        assert_eq!(
            FtpTransport::loopback().round(&long).expect("long").bytes,
            long
        );
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let transport = FtpTransport::loopback();
        assert!(transport.ceiling().is_none());
        for (name, bytes) in edges() {
            assert!(transport.refuses(&bytes).is_none(), "{name}");
            let arrived = transport
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
    }

    #[test]
    fn a_client_stores_into_a_session_and_the_session_serves_it_back() {
        let far_end = FtpTransport::new("127.0.0.1:0").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            let near = FtpTransport::new(address.clone()).timing_out_after(secs(2));
            near.send("orders/1.edi", b"UNA:+.? '")?;
            near.send(&format!("ftp://{address}/2.edi"), b"")?;
            let mut arrived = near.receive()?;
            arrived.sort_by(|a, b| a.origin_uri.cmp(&b.origin_uri));
            Ok::<_, transport::TransportError>(arrived)
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        let first = session.next_store().expect("first").expect("one");
        assert_eq!(first.bytes, b"UNA:+.? '");
        assert!(first.origin_uri.ends_with("/orders/1.edi"));
        assert!(session.next_store().expect("quit").is_none());
        let mut session = far_end.accept_one(&listener).expect("second");
        let second = session.next_store().expect("second").expect("one");
        assert!(second.bytes.is_empty());
        assert!(session.next_store().expect("quit").is_none());
        let files = session.files().clone();
        let mut session = far_end
            .accept_one(&listener)
            .expect("third")
            .with_files(files);
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("serving") {
            events.push(event);
        }
        assert_eq!(events.len(), 2, "one retrieve and one delete: {events:?}");
        let arrived = sender.join().expect("thread").expect("round trip");
        assert_eq!(arrived.len(), 1);
        assert_eq!(arrived[0].bytes, b"");
        assert!(arrived[0].origin_uri.ends_with("/2.edi"));
        assert!(session.files().is_empty(), "deleted after retrieve");
    }

    #[test]
    fn a_refusal_is_permanent_and_a_transient_one_is_retryable() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            std::io::Write::write_all(&mut stream, b"421 too busy\r\n").expect("write");
        });
        let Err(error) = FtpTransport::new(address)
            .timing_out_after(secs(2))
            .connect()
        else {
            panic!("connected");
        };
        assert!(error.retryable, "{error}");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
            let mut writer = stream;
            std::io::Write::write_all(&mut writer, b"220 hi\r\n").expect("write");
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).expect("USER");
            std::io::Write::write_all(&mut writer, b"530 not welcome\r\n").expect("write");
        });
        let Err(error) = FtpTransport::new(address)
            .timing_out_after(secs(2))
            .connect()
        else {
            panic!("connected");
        };
        assert!(!error.retryable, "{error}");
        assert!(FtpTransport::new("127.0.0.1:0").claims().is_some());
    }
}
