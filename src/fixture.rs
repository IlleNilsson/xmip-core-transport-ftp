//! The one login the tests' far ends check and their near ends present: a
//! user, and a password minted for the test run.

use std::sync::LazyLock;

use net::login::{self, Check};
use transport::Login;

/// The user the tests log in as.
pub const USER: &str = "party";

/// The password, drawn once a run.
pub static SECRET: LazyLock<String> =
    LazyLock::new(|| codec::hex::encode(&codec::random::array::<32>()));

/// What a test's far end is handed: the one login.
pub fn check() -> Check {
    login::only(USER, SECRET.as_str())
}

/// What a test's near end presents.
pub fn login() -> Login {
    Login::new(USER, SECRET.as_str())
}
