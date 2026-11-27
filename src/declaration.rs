//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// Every setting a Location takes beyond its address, the server, the user
/// and the directory, `ftp://user@host:21/dir`, or `host:21` alone: where a
/// Location logs in, as whom — no one where it names none, which a server
/// that checks who logs in refuses — and where it lists and stores.
/// `ftps://` is FTPS: `AUTH TLS` on the control connection and `PROT P` on
/// every transfer (RFC 4217).
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long a server that stops mid-transfer is waited on; unbounded \
             when left out.",
        ),
        Setting {
            name: "tls_name",
            kind: Kind::Text,
            presence: Presence::Optional,
            meaning: "The name an ftps:// server's certificate is checked for; the \
                      address's host when left out.",
            applies: Applies::Both,
        },
    ],
};

/// `ftp://`, and `ftps://` for FTPS.
pub const SCHEMES: &[&str] = &["ftp", "ftps"];
