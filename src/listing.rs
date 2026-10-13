//! A directory as an FTP server lists it: each entry's name, whether it is
//! a file, and what says it is unchanged — its size and modification time
//! (RFC 3659), from `MLSD`'s facts or from `SIZE` and `MDTM`, which write
//! them alike, so the two compare.

/// What says a listed file is unchanged: its size and its modification
/// time, as the server writes them; either may be missing where the server
/// does not say.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Stamp {
    pub size: Option<String>,
    pub modified: Option<String>,
}

impl Stamp {
    /// The stamp of a size and a time; `None` where neither was given.
    #[must_use]
    pub fn of(size: Option<String>, modified: Option<String>) -> Option<Self> {
        (size.is_some() || modified.is_some()).then_some(Self { size, modified })
    }
}

/// One entry of a listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub name: String,
    /// A file, not a directory.
    pub file: bool,
    pub stamp: Option<Stamp>,
}

impl Entry {
    /// A file named `name`, stamped `stamp`.
    #[must_use]
    pub fn file(name: String, stamp: Option<Stamp>) -> Self {
        Self {
            name,
            file: true,
            stamp,
        }
    }
}

/// One line of `MLSD`: `fact=value;…; name`. `None` for `.` and `..`, and a
/// line that is not one.
#[must_use]
pub fn fact_line(line: &str) -> Option<Entry> {
    let (facts, name) = line.split_once(' ')?;
    let mut kind = None;
    let (mut size, mut modified) = (None, None);
    for fact in facts.split(';').filter(|fact| !fact.is_empty()) {
        let (key, value) = fact.split_once('=')?;
        match key.to_ascii_lowercase().as_str() {
            "type" => kind = Some(value.to_ascii_lowercase()),
            "size" => size = Some(value.to_string()),
            "modify" => modified = Some(value.to_string()),
            _ => {}
        }
    }
    let kind = kind.unwrap_or_else(|| "file".to_string());
    if kind == "cdir" || kind == "pdir" || name.is_empty() {
        return None;
    }
    Some(Entry {
        name: name.to_string(),
        file: kind == "file",
        stamp: Stamp::of(size, modified),
    })
}

/// The `MLSD` line of an entry, as a server writes it.
#[must_use]
pub fn written(name: &str, file: bool, size: usize, modified: &str) -> String {
    if file {
        format!("type=file;size={size};modify={modified}; {name}")
    } else {
        format!("type=dir;modify={modified}; {name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fact_line_reads_back_as_written_and_a_directory_is_no_file() {
        let file = fact_line(&written("order.edi", true, 12, "20261013120000")).expect("a file");
        assert_eq!(file.name, "order.edi");
        assert!(file.file);
        assert_eq!(
            file.stamp,
            Stamp::of(Some("12".into()), Some("20261013120000".into()))
        );
        let turn = fact_line(&written("a.xmip-claim", false, 0, "1")).expect("a directory");
        assert!(!turn.file);
        assert!(fact_line("type=cdir; .").is_none());
        assert!(fact_line("nonsense").is_none());
        assert_eq!(
            fact_line("Type=File;Size=3; spaced name.edi").map(|entry| entry.name),
            Some("spaced name.edi".to_string())
        );
    }
}
