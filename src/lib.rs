#![forbid(unsafe_code)]

//! Streams that arrive as files over FTP. One file is one Stream, its name
//! kept beside it.
//!
//! FTP is the Party drop box that predates every other one: a control
//! connection on port 21, a data connection per transfer, files in
//! directories. A Receive Location logs in, lists a directory and hands each
//! file back unread: the runtime reads its transfer as it asks, and the file
//! is deleted only when the receive cycle accepted it; a Send Location logs
//! in and stores. Either may instead accept clients directly
//! through [`Session`], one client's worth of server over one directory.
//!
//! What is here is RFC 959 in passive mode and binary type — the shape a
//! firewall lets through. FTPS is TLS on both connections and joins when the
//! estate's TLS (`xmip-core-library-tls`) reaches this socket (ADR-0033).
//!
//! FTP has artefacts and no locking, so [`Transport::claims`] answers
//! [`NoNativeClaim`], ADR-0024 clause 5: a producer writes to a temporary
//! name and renames, or a Location waits for a listing to stop changing.
//!
//! The origin URI carries what the server knew: `ftp://server/orders/1.edi`.

pub mod client;
pub mod control;
pub mod reply;
pub mod session;

use std::net::TcpListener;
use std::time::Duration;

pub use client::{Client, anonymous};
pub use control::Control;
use net::Target;
pub use reply::Reply;
pub use session::{Event, Session};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::taken::Taken;
use transport::{
    Arrived, Configured, Directions, Login, NoNativeClaim, Pool, Refused, ResourceClaim, Transport,
};
use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// Whether an accepted file is deleted, unless a Location says.
pub const DELETE_AFTER_RETRIEVE: bool = true;

#[derive(Clone)]
pub struct FtpTransport {
    server: String,
    login: Login,
    delete_after_retrieve: bool,
    timeout: Option<Duration>,
    /// The control connections a send stores on and a receive retrieves on,
    /// logged in once per server and kept, shared with what a receive
    /// handed back until each is acknowledged.
    controls: Pool<Control>,
    /// The files refused and left, not listed again while unchanged.
    /// Cloned, the same memory.
    refused: Refused<String, String>,
}

impl FtpTransport {
    /// Speak to the server at `server`, anonymous unless [`Self::logging_in`].
    #[must_use]
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            login: anonymous(),
            delete_after_retrieve: DELETE_AFTER_RETRIEVE,
            timeout: None,
            controls: Pool::new(),
            refused: Refused::default(),
        }
    }

    /// Log in as this.
    #[must_use]
    pub fn logging_in(mut self, login: Login) -> Self {
        self.login = login;
        self
    }

    /// Leave accepted files in place rather than deleting them.
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
        Target::under(&["ftp"], target).map_or((&self.server, target), |named| {
            (named.authority(), named.path())
        })
    }
}

impl Transport for FtpTransport {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a receive lists again what is not yet told")
    }

    /// Every file in the directory, listed on the control connection kept
    /// for the server, logged in on the first receive, and handed back
    /// unread, but those refused and still as they were refused — each
    /// stamped (`SIZE`, `MDTM`) only where it was refused. Each body is its
    /// `RETR`, read as the runtime asks, and its server's completion;
    /// `Accepted` deletes the file (`DELE`) unless the transport was told
    /// to leave files, `Refused` leaves it and remembers it, `Failed`
    /// leaves it for the next receive.
    fn receive(&self) -> Result<Vec<Arrived>> {
        self.controls.exchange(
            self.server.as_str(),
            || self.connect().map(Control::new),
            |control| {
                let names = control.with(Client::names)?;
                let stamp = |name: &String| control.with(|client| client.stamp(name)).ok()?;
                Ok(self
                    .refused
                    .sift(names, |name| name, stamp)
                    .into_iter()
                    .map(|name| {
                        let origin = format!("ftp://{}/{name}", self.server);
                        let refused = self.refused.clone();
                        control.arrival(origin, name, self.delete_after_retrieve, refused)
                    })
                    .collect())
            },
        )
    }

    /// STOR on the control connection kept for the server, logged in on
    /// the first send to it; the data connection is the transfer's own.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (server, name) = self.resolve(target);
        self.controls.exchange(
            server,
            || Client::connect(server, &self.login, self.timeout).map(Control::new),
            |control| control.with(|client| client.store(name, bytes)),
        )
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl Configured for FtpTransport {
    /// The address is the server's host and port: where a Location logs in.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "user",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The user a Location logs in as; anonymous when left out.",
                applies: Applies::Both,
            },
            Setting {
                name: "delete_after_retrieve",
                kind: Kind::Boolean,
                presence: Presence::Default(Fixed::Boolean(DELETE_AFTER_RETRIEVE)),
                meaning: "Whether a file is deleted once its receive cycle accepted it.",
                applies: Applies::Receive,
            },
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a server that stops mid-transfer is waited on; unbounded \
                          when left out.",
                applies: Applies::Both,
            },
        ],
    };

    /// A named user's password comes through the Location's credentials,
    /// never a setting; the login is built without it.
    fn configured(address: &str, settings: &xcore::settings::Read) -> Result<Self> {
        let mut transport = Self::new(address);
        if let Some(user) = settings.optional_text("user") {
            transport = transport.logging_in(Login::new(user, ""));
        }
        if settings.optional_boolean("delete_after_retrieve") == Some(false) {
            transport = transport.leaving_files();
        }
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        Ok(transport)
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

impl Accepting for FtpTransport {
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        // The client keeps its control connection for the next store.
        self.accept_one(listener)?
            .next_store()?
            .ok_or_else(|| protocol_error("the client quit without storing"))
    }
}

impl Loopback for FtpTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
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
    use transport::payload::edge_payloads;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn ftp_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(FtpTransport::SETTINGS.problems(), Vec::<String>::new());
        let given = [
            ("user".to_string(), Given::Text("party".to_string())),
            ("delete_after_retrieve".to_string(), Given::Boolean(false)),
            ("timeout".to_string(), Given::Text("30s".to_string())),
        ];
        let built = FtpTransport::open("ftp.example:21", Applies::Receive, &given).expect("built");
        assert_eq!(built.login.user, "party");
        assert!(!built.delete_after_retrieve);
        assert_eq!(built.timeout, Some(secs(30)));
        let plain = FtpTransport::open("ftp.example:21", Applies::Send, &[]).expect("plain");
        assert_eq!(plain.login.user, "anonymous");
        let Err(refused) = FtpTransport::open("ftp.example:21", Applies::Send, &given[1..2]) else {
            panic!("a Send Location deletes nothing");
        };
        assert!(
            refused.message.contains("\"delete_after_retrieve\""),
            "{}",
            refused.message
        );
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
        for (name, bytes) in edge_payloads() {
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
            arrived
                .into_iter()
                .map(Arrived::taken)
                .collect::<Result<Vec<_>>>()
        });
        // One server, so one control connection for both stores and the
        // receive that takes them back.
        let mut session = far_end.accept_one(&listener).expect("accepting");
        let first = session.next_store().expect("first").expect("one");
        assert_eq!(first.bytes, b"UNA:+.? '");
        assert!(first.origin_uri.ends_with("/orders/1.edi"));
        let second = session.next_store().expect("second").expect("one");
        assert!(second.bytes.is_empty());
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("serving") {
            events.push(event);
        }
        assert_eq!(events.len(), 4, "two retrieves and two deletes: {events:?}");
        let arrived = sender.join().expect("thread").expect("round trip");
        assert_eq!(arrived.len(), 2);
        assert_eq!(arrived[0].bytes, b"");
        assert!(arrived[0].origin_uri.ends_with("/2.edi"));
        assert_eq!(arrived[1].bytes, b"UNA:+.? '");
        assert!(session.files().is_empty(), "deleted after retrieve");
    }

    #[test]
    fn a_failed_file_stays_on_the_server_and_an_accepted_one_is_deleted() {
        let far_end = FtpTransport::new("127.0.0.1:0").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = FtpTransport::new(address).timing_out_after(secs(2));
            let first = transport::arrived::one_arrival(near.receive()?, "listed")?;
            assert!(first.defers());
            let (_, mut body, acknowledgement) = first.into_parts();
            let mut read = Vec::new();
            std::io::Read::read_to_end(&mut body, &mut read).expect("reading");
            drop(body);
            acknowledgement.acknowledge(transport::Verdict::Failed)?;
            let again = transport::arrived::one_arrival(near.receive()?, "listed again")?;
            Ok::<_, transport::TransportError>((read, again.taken()?))
        });
        let files = std::collections::BTreeMap::from([("1.edi".to_string(), b"UNB".to_vec())]);
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_files(files);
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("serving") {
            events.push(event);
        }
        let (read, taken) = receiver.join().expect("thread").expect("received");
        assert_eq!(
            (read.as_slice(), taken.bytes.as_slice()),
            (&b"UNB"[..], &b"UNB"[..])
        );
        let one = "1.edi".to_string();
        assert_eq!(
            events,
            [
                Event::Retrieved(one.clone()),
                Event::Retrieved(one.clone()),
                Event::Deleted(one)
            ],
            "the failed retrieve deleted nothing"
        );
        assert!(session.files().is_empty(), "deleted once accepted");
    }

    #[test]
    fn a_refused_file_is_left_and_not_listed_again_until_stored_again() {
        let far_end = FtpTransport::new("127.0.0.1:0").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = FtpTransport::new(address).timing_out_after(secs(2));
            let first = transport::arrived::one_arrival(near.receive()?, "listed")?;
            first.refused(transport::Refusal::Unacceptable)?;
            let unchanged = near.receive()?.len();
            near.send("1.edi", b"UNB again")?;
            let again = transport::arrived::one_arrival(near.receive()?, "stored again")?;
            again.refused(transport::Refusal::Unacceptable)?;
            Ok::<_, transport::TransportError>(unchanged)
        });
        let files = std::collections::BTreeMap::from([("1.edi".to_string(), b"UNB".to_vec())]);
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_files(files);
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("serving") {
            events.push(event);
        }
        assert_eq!(receiver.join().expect("thread").expect("received"), 0);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Deleted(_))),
            "nothing deleted: {events:?}"
        );
        assert_eq!(
            session.files().get("1.edi").map(Vec::as_slice),
            Some(&b"UNB again"[..]),
            "the refused file is still there"
        );
    }

    #[test]
    fn a_hundred_stores_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        // A hundred rather than a thousand: each store opens its own data
        // connection, which is the protocol's, and spends a local port.
        const SENDS: usize = 100;
        let far_end = FtpTransport::new("127.0.0.1:0").timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = FtpTransport::new(address).timing_out_after(secs(5));
        let sending = near.clone();
        let sender = std::thread::spawn(move || {
            for n in 0..SENDS {
                sending.send(&format!("{n}.edi"), n.to_string().as_bytes())?;
            }
            sending.send("last.edi", b"after the close")
        });
        // One USER and PASS for every store: one control connection.
        let mut session = far_end.accept_one(&listener).expect("accepting");
        for n in 0..SENDS {
            let stored = session.next_store().expect("store").expect("one");
            assert_eq!(stored.bytes, n.to_string().as_bytes());
        }
        drop(session);
        let mut again = far_end.accept_one(&listener).expect("a new connection");
        let last = again.next_store().expect("store").expect("one");
        assert_eq!(last.bytes, b"after the close");
        sender.join().expect("thread").expect("sending");
        assert_eq!(near.controls.opened(), 2);
    }

    #[test]
    fn a_hundred_receives_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        // Each receive lists the directory on a data connection of its own,
        // which is the protocol's; the control connection is kept.
        const RECEIVES: usize = 100;
        let far_end = FtpTransport::new("127.0.0.1:0").timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = FtpTransport::new(address).timing_out_after(secs(5));
        let (go, going) = std::sync::mpsc::channel();
        let receiver = std::thread::spawn(move || {
            for _ in 0..RECEIVES {
                assert!(near.receive()?.is_empty());
            }
            // A store on the same kept connection says the listings are done.
            near.send("listed.edi", b"listed")?;
            going.recv().expect("go");
            Ok::<_, transport::TransportError>((near.receive()?, near.controls.opened()))
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        let marker = session.next_store().expect("served").expect("the store");
        assert_eq!(marker.bytes, b"listed");
        drop(session);
        go.send(()).expect("went");
        let mut again = far_end.accept_one(&listener).expect("a new connection");
        assert!(again.next_event().expect("served").is_none());
        let (arrived, opened) = receiver.join().expect("thread").expect("listed");
        assert!(arrived.is_empty());
        assert_eq!(opened, 2);
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
