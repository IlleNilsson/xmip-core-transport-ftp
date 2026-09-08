//! RFC 959 replies on the control connection: a three-digit code, one line
//! or several, and the passive-mode address a `227` carries.

use std::io::BufRead;

use transport::error::{Result, classify, protocol_error};

/// One reply, its code and its text with the code stripped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub text: String,
}

impl Reply {
    /// Positive preliminary, `1xx`: the data transfer is about to start.
    #[must_use]
    pub const fn is_preliminary(&self) -> bool {
        self.code / 100 == 1
    }

    /// Positive completion, `2xx`.
    #[must_use]
    pub const fn is_completion(&self) -> bool {
        self.code / 100 == 2
    }

    /// Positive intermediate, `3xx`: send the next command of the sequence.
    #[must_use]
    pub const fn is_intermediate(&self) -> bool {
        self.code / 100 == 3
    }

    /// Whether a failure is worth trying again: `4xx` is transient, `5xx`
    /// is not.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        self.code / 100 == 4
    }

    /// The `h1,h2,h3,h4,p1,p2` a `227 Entering Passive Mode` carries, as
    /// `host:port`.
    ///
    /// # Errors
    /// A 227 without six numbers in it.
    pub fn passive_address(&self) -> Result<String> {
        let open = self.text.find('(').map_or(0, |at| at + 1);
        let digits: Vec<u16> = self.text[open..]
            .trim_start()
            .split(|c: char| !c.is_ascii_digit())
            .filter(|part| !part.is_empty())
            .filter_map(|part| part.parse().ok())
            .take(6)
            .collect();
        match digits.as_slice() {
            [h1, h2, h3, h4, p1, p2] => Ok(format!("{h1}.{h2}.{h3}.{h4}:{}", p1 * 256 + p2)),
            _ => Err(protocol_error("a 227 without a passive address in it")),
        }
    }
}

/// Read one reply, multi-line replies (`123-` ... `123 `) joined.
///
/// # Errors
/// A connection that closed, or a line that does not open with a code.
pub fn read(reader: &mut impl BufRead) -> Result<Reply> {
    let first = line(reader)?;
    let code = code_of(&first)?;
    let mut text = first[4..].to_string();
    if first.as_bytes().get(3) == Some(&b'-') {
        loop {
            let next = line(reader)?;
            if next.len() >= 4 && code_of(&next).ok() == Some(code) && next.as_bytes()[3] == b' ' {
                text.push('\n');
                text.push_str(&next[4..]);
                break;
            }
            text.push('\n');
            text.push_str(&next);
        }
    }
    Ok(Reply { code, text })
}

fn line(reader: &mut impl BufRead) -> Result<String> {
    let mut raw = String::new();
    let read = reader
        .read_line(&mut raw)
        .map_err(|e| classify("reading a reply", &e))?;
    if read == 0 {
        return Err(protocol_error("the peer closed the control connection"));
    }
    Ok(raw.trim_end_matches(['\r', '\n']).to_string())
}

fn code_of(line: &str) -> Result<u16> {
    let digits = line.get(..3).unwrap_or("");
    let code: u16 = digits
        .parse()
        .map_err(|_| protocol_error(format!("{line:?} does not open with a reply code")))?;
    if !(100..600).contains(&code) || line.len() < 4 {
        return Err(protocol_error(format!("{line:?} is not a reply")));
    }
    Ok(code)
}

/// `code text` as the server writes it.
#[must_use]
pub fn format(code: u16, text: &str) -> Vec<u8> {
    format!("{code} {text}\r\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_read_single_and_multi_line() {
        let reply = read(&mut &b"220 Service ready\r\n"[..]).expect("reply");
        assert_eq!(reply.code, 220);
        assert_eq!(reply.text, "Service ready");
        assert!(reply.is_completion());
        let multi =
            read(&mut &b"211-Features:\r\n UTF8\r\n211 End\r\n215 next\r\n"[..]).expect("multi");
        assert_eq!(multi.code, 211);
        assert_eq!(multi.text, "Features:\n UTF8\nEnd");
        assert!(read(&mut &b"hello\r\n"[..]).is_err());
        assert!(read(&mut &b""[..]).is_err());
        assert!(read(&mut &b"999 no\r\n"[..]).is_err());
    }

    #[test]
    fn a_227_carries_the_passive_address() {
        let reply = Reply {
            code: 227,
            text: "Entering Passive Mode (127,0,0,1,195,80).".into(),
        };
        assert_eq!(reply.passive_address().expect("address"), "127.0.0.1:50000");
        let bare = Reply {
            code: 227,
            text: "=127,0,0,1,4,1".into(),
        };
        assert_eq!(bare.passive_address().expect("address"), "127.0.0.1:1025");
        let none = Reply {
            code: 227,
            text: "Entering Passive Mode".into(),
        };
        assert!(none.passive_address().is_err());
        assert!(
            Reply {
                code: 421,
                text: String::new()
            }
            .is_transient()
        );
        assert!(
            Reply {
                code: 331,
                text: String::new()
            }
            .is_intermediate()
        );
        assert!(
            Reply {
                code: 150,
                text: String::new()
            }
            .is_preliminary()
        );
    }
}
