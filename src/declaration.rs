//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

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
