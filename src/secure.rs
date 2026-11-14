//! FTPS: FTP over the estate's TLS (RFC 4217, explicit), behind the `tls`
//! feature.
//!
//! The client asks `AUTH TLS` in the clear; on `234` both ends hand the
//! control connection to TLS in place (`xmip-core-library-tls`, ADR-0033),
//! and the login follows guarded. `PBSZ 0` and `PROT P` then guard every
//! data connection: each is its own TLS session over the login's own
//! client configuration (`tls::ClientSettings::login`), so it
//! resumes the control connection's session where the server keeps one —
//! what a server that insists on session reuse checks (vsftpd's
//! `require_ssl_reuse`) — and no connection of another login does.
//! A transfer ends with TLS's own close before the socket's, so a
//! connection cut short is never read as a whole file.

use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::Arc;

use tls::duplex::split;
use transport::error::Result;

use crate::wire::{DataStream, Line};

/// `socket`, a connection to `server`, guarded as `settings` say — the
/// estate's one pair of trust store and name (`tls::ClientSettings`) — and
/// its handshake begun.
fn guard(settings: &tls::ClientSettings, server: &str, socket: TcpStream) -> Result<tls::Guarded> {
    Ok(settings.client(net::authority::host_of(server), socket)?)
}

/// The control connection to `server`, turned over to TLS once the server
/// agreed to `AUTH TLS`, its certificate checked as `settings` say — a
/// login's own (`tls::ClientSettings::login`).
///
/// # Errors
/// Where the handshake failed, the server's certificate among the reasons.
pub fn control(settings: &tls::ClientSettings, server: &str, line: Line) -> Result<Line> {
    let socket = line.socket;
    let guarded = guard(settings, server, clone(&socket)?)?;
    let halves = split(guarded)?;
    Ok(Line {
        reader: std::io::BufReader::new(Box::new(halves.reading)),
        writer: Box::new(halves.writing),
        socket,
    })
}

/// A data connection to `server`, guarded as the login's `settings` say.
///
/// # Errors
/// Where the handshake could not be started.
pub fn data(
    settings: &tls::ClientSettings,
    server: &str,
    socket: TcpStream,
) -> Result<Box<dyn DataStream>> {
    Ok(Box::new(guard(settings, server, socket)?))
}

/// The server's side of `AUTH TLS`: the control connection on `line`,
/// guarded with `config`.
///
/// # Errors
/// Where the handshake failed.
pub fn answered(config: &Arc<tls::ServerConfig>, line: Line) -> Result<Line> {
    let socket = line.socket;
    let guarded = tls::server(clone(&socket)?, Arc::clone(config))?;
    let halves = split(guarded)?;
    Ok(Line {
        reader: std::io::BufReader::new(Box::new(halves.reading)),
        writer: Box::new(halves.writing),
        socket,
    })
}

/// The server's side of a guarded data connection.
///
/// # Errors
/// Where the handshake could not be started.
pub fn served(config: &Arc<tls::ServerConfig>, socket: TcpStream) -> Result<Box<dyn DataStream>> {
    Ok(Box::new(tls::server(socket, Arc::clone(config))?))
}

impl DataStream for tls::Guarded {
    fn finish(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        self.flush()?;
        drained(self, &self.sock.try_clone()?);
        Ok(())
    }
}

impl DataStream for tls::GuardedServer {
    fn finish(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        self.flush()?;
        drained(self, &self.sock.try_clone()?);
        Ok(())
    }
}

/// The writing half shut once TLS said the transfer is over, and whatever
/// the peer still sends read until it closes — a session ticket sent after
/// the handshake among it. Closed with that unread, a socket is reset
/// rather than closed (Windows does so), and the reset can take the last of
/// the file with it before the peer reads it.
fn drained(stream: &mut impl io::Read, socket: &TcpStream) {
    let _ = socket.shutdown(std::net::Shutdown::Write);
    let mut sink = [0; 512];
    while let Ok(read) = stream.read(&mut sink) {
        if read == 0 {
            break;
        }
    }
}

fn clone(socket: &TcpStream) -> Result<TcpStream> {
    socket
        .try_clone()
        .map_err(|e| transport::error::classify("cloning the control connection", &e))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use provision::{Order, Purpose, Source};
    use provision_self_signed::{SETTINGS, SelfSigned, TECHNOLOGY};
    use xcore::settings::Given;

    /// A server's configuration for `localhost`, signed by the estate's own
    /// self-signed source, and a client's trusting it.
    pub(crate) fn certificate() -> (Arc<tls::ServerConfig>, Arc<tls::ClientConfig>) {
        let given = [
            ("source".to_string(), Given::Text(TECHNOLOGY.to_string())),
            ("names".to_string(), Given::Text("localhost".to_string())),
            ("lifetime".to_string(), Given::Text("1h".to_string())),
        ];
        let read = provision::read("node", &given, &[SETTINGS]).expect("read");
        let names = vec!["localhost".to_string()];
        let order = Order {
            purpose: Purpose::Node,
            names: &names,
            keep: std::path::Path::new("."),
        };
        let held = SelfSigned::configured(&read.settings)
            .obtain(&order)
            .expect("signed");
        let server = tls::server_config(held.chain.as_bytes(), held.key.as_bytes())
            .expect("a server configuration");
        let anchors = held.anchors.as_deref().unwrap_or_default();
        let client = tls::trusting(anchors.as_bytes()).expect("a client configuration");
        (Arc::new(server), Arc::new(client))
    }

    #[test]
    fn a_store_and_a_retrieve_cross_ftps_whole() {
        use std::net::TcpListener;
        use std::time::Duration;

        use transport::Transport;

        let (server, client) = certificate();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
        let store = crate::Store::default();
        let timeout = Some(Duration::from_secs(5));
        let serving = crate::serving(
            listener,
            store.clone(),
            (timeout, crate::fixture::check()),
            Some(server),
        )
        .expect("serving");
        let near = crate::FtpTransport::new(serving.address())
            .logging_in(crate::fixture::login())
            .timing_out_after(Duration::from_secs(5))
            .secured(tls::ClientSettings::trusting(client).named("localhost"));
        near.send("order.edi", b"UNB+UNOC").expect("stored");
        assert!(near.receive().expect("found").is_empty());
        let taken = near
            .receive()
            .expect("claimed")
            .remove(0)
            .taken()
            .expect("read");
        assert_eq!(taken.bytes, b"UNB+UNOC");
        assert!(store.files().is_empty(), "accepted, deleted");
    }
}
