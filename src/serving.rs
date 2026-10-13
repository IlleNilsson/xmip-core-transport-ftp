//! A far end that serves every client a listener accepts at once, over one
//! shared [`Store`], until it is let go: what several receiving nodes reach
//! to race for the same files (the Playground's drop box; ADR-0028,
//! amendment 2026-10-13). The accepting is the capability's
//! (`transport::concurrent`); each client's session is this crate's.

use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use transport::concurrent::Concurrent;
use transport::error::Result;

use crate::session::Session;
use crate::store::Store;

/// Serve every client `listener` accepts over `store`, each read given up
/// after `timeout`; FTPS where `guard` is given. Dropped, it stops
/// accepting, and the sessions end as their clients leave.
///
/// # Errors
/// Where the listener's address could not be read.
pub fn serving(
    listener: TcpListener,
    store: Store,
    timeout: Option<Duration>,
    guard: Option<Guard>,
) -> Result<Concurrent> {
    Concurrent::start(listener, "ftp-session", move |stream| {
        serve(stream, store.clone(), timeout, guard.as_ref());
    })
}

/// What a server presents for `AUTH TLS`; nothing without the `tls`
/// feature.
#[cfg(feature = "tls")]
pub type Guard = std::sync::Arc<tls::ServerConfig>;

/// What a server presents for `AUTH TLS`; nothing without the `tls`
/// feature.
#[cfg(not(feature = "tls"))]
#[derive(Clone, Debug)]
pub enum Guard {}

/// One client's session, to its end.
fn serve(stream: TcpStream, store: Store, timeout: Option<Duration>, guard: Option<&Guard>) {
    let Ok(peer) = stream.peer_addr() else {
        return;
    };
    let Ok(session) = Session::serving(stream, peer, timeout) else {
        return;
    };
    let mut session = session.sharing(store);
    #[cfg(feature = "tls")]
    if let Some(config) = guard {
        session = session.guarding(std::sync::Arc::clone(config));
    }
    #[cfg(not(feature = "tls"))]
    let _ = guard;
    while let Ok(Some(_)) = session.next_event() {}
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use transport::{Configured, NodeLocation, Transport};

    use super::*;
    use crate::FtpTransport;

    const FILES: usize = 60;

    /// A node location for the node at `place`; it names no node.
    fn node(place: usize) -> NodeLocation {
        NodeLocation::new(format!("process-{}/place-{place}", std::process::id()))
    }

    fn server(guard: Option<Guard>) -> (Concurrent, Store) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
        let store = Store::default();
        let timeout = Some(Duration::from_secs(10));
        let serving = serving(listener, store.clone(), timeout, guard).expect("serving");
        (serving, store)
    }

    /// Two receiving nodes over one directory until it is empty: what each
    /// took.
    fn race(receivers: &[FtpTransport; 2], store: &Store) -> Vec<Vec<Vec<u8>>> {
        std::thread::scope(|scope| {
            let racing: Vec<_> = receivers
                .iter()
                .map(|receiver| {
                    scope.spawn(move || {
                        let mut took = Vec::new();
                        while !store.list(None).is_empty() {
                            for arrived in receiver.receive().expect("receiving") {
                                took.push(arrived.taken().expect("taken").bytes);
                            }
                        }
                        took
                    })
                })
                .collect();
            racing
                .into_iter()
                .map(|one| one.join().expect("a receiver"))
                .collect()
        })
    }

    fn exactly_once(took: &[Vec<Vec<u8>>]) {
        let all: Vec<&Vec<u8>> = took.iter().flatten().collect();
        let once: BTreeSet<&Vec<u8>> = all.iter().copied().collect();
        assert_eq!(all.len(), FILES, "every file taken, none twice");
        assert_eq!(once.len(), FILES);
    }

    fn receivers(address: &str, built: impl Fn(FtpTransport) -> FtpTransport) -> [FtpTransport; 2] {
        [0, 1].map(|place| {
            built(FtpTransport::new(address).timing_out_after(Duration::from_secs(10)))
                .on_node(&node(place))
                .expect("built on its node")
        })
    }

    #[test]
    fn two_nodes_over_one_server_take_each_file_once() {
        let (serving, store) = server(None);
        for file in 0..FILES {
            store.write(&format!("order-{file}.edi"), file.to_string().into_bytes());
        }
        let took = race(&receivers(serving.address(), |plain| plain), &store);
        exactly_once(&took);
    }

    #[test]
    fn a_starting_node_returns_the_claims_its_name_left_on_the_server() {
        let (serving, store) = server(None);
        store.write("mine.edi", b"ISA".to_vec());
        let [first, _] = receivers(serving.address(), |plain| plain);
        assert!(first.receive().expect("found").is_empty());
        let held = first.receive().expect("claimed");
        assert_eq!(held.len(), 1);
        // The node dies holding its claim: nothing told, nothing returned.
        std::mem::forget(held);
        assert!(
            store
                .list(None)
                .iter()
                .all(|(name, ..)| name.contains(".xmip-claim."))
        );

        let [again, _] = receivers(serving.address(), |plain| plain);
        let first_listing = again.receive().expect("listed");
        assert!(first_listing.is_empty(), "returned, then found");
        assert!(store.read("mine.edi").is_some(), "returned under its name");
        let taken = again
            .receive()
            .expect("taken")
            .remove(0)
            .taken()
            .expect("read");
        assert_eq!(taken.bytes, b"ISA");
        assert!(
            store.list(None).is_empty(),
            "accepted, deleted: {:?}",
            store.list(None)
        );
    }

    #[test]
    fn a_failed_file_goes_back_under_its_name_and_no_turn_is_left() {
        let (serving, store) = server(None);
        store.write("order.edi", b"ISA".to_vec());
        let [near, _] = receivers(serving.address(), |plain| plain);
        let _ = near.receive().expect("found");
        let arrived = near.receive().expect("claimed").remove(0);
        arrived.failed().expect("failed");
        let names: Vec<String> = store
            .list(None)
            .into_iter()
            .map(|(name, ..)| name)
            .collect();
        assert_eq!(names, ["order.edi"]);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn two_nodes_over_one_ftps_server_take_each_file_once() {
        let (server_config, client_config) = crate::secure::tests::certificate();
        let (serving, store) = server(Some(server_config));
        for file in 0..FILES {
            store.write(&format!("order-{file}.edi"), file.to_string().into_bytes());
        }
        let secured = crate::Secured::trusting(client_config).named("localhost");
        let receivers = receivers(serving.address(), |plain| plain.secured(secured.clone()));
        exactly_once(&race(&receivers, &store));
        // A send over FTPS lands whole.
        receivers[0].send("sent.edi", b"UNB").expect("sent");
        assert_eq!(store.read("sent.edi").as_deref(), Some(&b"UNB"[..]));
    }
}
