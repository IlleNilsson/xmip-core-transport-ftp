//! A session's login: `USER` and `PASS` asked of the check the session was
//! handed, anonymous FTP refused before any check is asked.

use net::login::{Offer, Offered};
use transport::error::Result;

use super::Session;

/// What a client may say before it is logged in.
pub(super) const BEFORE_LOGIN: [&str; 7] = ["USER", "PASS", "AUTH", "PBSZ", "PROT", "NOOP", "QUIT"];

/// The users that are anonymous FTP (RFC 1635), refused whatever the
/// check would say.
const ANONYMOUS: [&str; 2] = ["anonymous", "ftp"];

impl Session {
    /// `USER`: the name the `PASS` after it logs in, a new login begun;
    /// anonymous FTP refused.
    pub(super) fn named(&mut self, user: String) -> Result<()> {
        self.logged_in = false;
        if ANONYMOUS.iter().any(|one| user.eq_ignore_ascii_case(one)) {
            self.user = None;
            return self.reply(530, "anonymous logins are refused");
        }
        self.user = Some(user);
        self.reply(331, "password please")
    }

    /// `PASS`: the user `USER` named logged in where the check admits
    /// it with `secret`.
    pub(super) fn pass(&mut self, secret: &str) -> Result<()> {
        let Some(user) = self.user.take() else {
            return self.reply(503, "USER first");
        };
        if (self.check)(&Offer::Password(Offered {
            user: &user,
            secret,
        })) {
            self.logged_in = true;
            self.reply(230, "logged in")
        } else {
            self.reply(530, "not logged in")
        }
    }
}
