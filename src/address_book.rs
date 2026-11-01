//! "My contacts": the addresses this wallet sends to, by a name of its own.
//!
//! An entry is a payment address on the chain ("tq21…"), checked before it is
//! kept, under a name the holder chose ("Mum", "Exchange") and an optional
//! note. It is what the Send page offers instead of an address typed again.
//!
//! Not the channel contacts of [`crate::contacts`]: those are people reached
//! through a channel session and pinned to an identity key. These are only
//! addresses, for an ordinary payment.
//!
//! Strictly local: kept in the wallet file, sealed with it, never sent.

use crate::contacts::{clean_label, clean_text, look_alike_key};
use std::collections::BTreeMap;

/// Most entries the book holds.
pub const MAX_ENTRIES: usize = 1000;

/// Longest note, in characters.
pub const MAX_NOTE_LEN: usize = 120;

/// One entry of the book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The address, in its canonical form (checked by the caller).
    pub address: String,
    /// The holder's name for it.
    pub name: String,
    /// What the address is for, if the holder said so.
    pub note: String,
}

/// Why an entry is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BookError {
    /// The name is empty once cleaned.
    EmptyName,
    /// Another address already has this name.
    NameTaken,
    /// This address is already in the book, under this name.
    AlreadyKept(String),
    /// The book is full ([`MAX_ENTRIES`]).
    Full,
    /// No entry for this address.
    Unknown,
}

/// The book, by address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressBook {
    by_address: BTreeMap<String, Entry>,
}

/// A note as it is kept: cleaned as a name is, cut at [`MAX_NOTE_LEN`] — not
/// at the shorter length of a name.
pub fn clean_note(text: &str) -> String {
    clean_text(text, MAX_NOTE_LEN)
}

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<String> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

impl AddressBook {
    /// Every entry, sorted by name.
    pub fn list(&self) -> Vec<&Entry> {
        let mut v: Vec<&Entry> = self.by_address.values().collect();
        v.sort_by_key(|e| e.name.to_lowercase());
        v
    }

    pub fn get(&self, address: &str) -> Option<&Entry> {
        self.by_address.get(address)
    }

    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    fn name_taken(&self, name: &str, other_than: &str) -> bool {
        // Two names that look alike are one name: a second contact must not
        // pass for the first in the list (red-team campaign 6, W1).
        let key = look_alike_key(name);
        self.by_address
            .values()
            .any(|e| e.address != other_than && look_alike_key(&e.name) == key)
    }

    /// Keeps a new address. An address already kept is refused with the
    /// name it has: two names for one address would only confuse.
    pub fn add(&mut self, name: &str, address: &str, note: &str) -> Result<&Entry, BookError> {
        let name = clean_label(name);
        if name.is_empty() {
            return Err(BookError::EmptyName);
        }
        if let Some(e) = self.by_address.get(address) {
            return Err(BookError::AlreadyKept(e.name.clone()));
        }
        if self.name_taken(&name, address) {
            return Err(BookError::NameTaken);
        }
        if self.by_address.len() >= MAX_ENTRIES {
            return Err(BookError::Full);
        }
        let entry = Entry {
            address: address.to_string(),
            name,
            note: clean_note(note),
        };
        self.by_address.insert(address.to_string(), entry);
        Ok(self.by_address.get(address).expect("just inserted"))
    }

    /// Renames an entry, and replaces its note.
    pub fn update(&mut self, address: &str, name: &str, note: &str) -> Result<&Entry, BookError> {
        let name = clean_label(name);
        if name.is_empty() {
            return Err(BookError::EmptyName);
        }
        if !self.by_address.contains_key(address) {
            return Err(BookError::Unknown);
        }
        if self.name_taken(&name, address) {
            return Err(BookError::NameTaken);
        }
        let e = self.by_address.get_mut(address).expect("checked above");
        e.name = name;
        e.note = clean_note(note);
        Ok(e)
    }

    pub fn remove(&mut self, address: &str) -> Result<(), BookError> {
        self.by_address
            .remove(address)
            .map(|_| ())
            .ok_or(BookError::Unknown)
    }

    /// The `address_book=` line of the wallet file: `address:name:note`,
    /// the texts in hexadecimal, entries separated by commas.
    pub fn to_line(&self) -> String {
        self.by_address
            .values()
            .map(|e| format!("{}:{}:{}", e.address, hex(&e.name), hex(&e.note)))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Reads the `address_book=` line back. `valid` says whether an address
    /// may be kept (its checksum and network): a malformed entry is skipped
    /// on its own — losing a contact is an inconvenience, losing the wallet
    /// is not an option.
    pub fn from_line(value: &str, valid: impl Fn(&str) -> Option<String>) -> AddressBook {
        let mut book = AddressBook::default();
        for item in value.split(',').filter(|s| !s.is_empty()) {
            let parts: Vec<&str> = item.split(':').collect();
            let [address, name, note] = parts.as_slice() else {
                continue;
            };
            let (Some(address), Some(name), Some(note)) =
                (valid(address), unhex(name), unhex(note))
            else {
                continue;
            };
            let _ = book.add(&name, &address, &note);
        }
        book
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any(s: &str) -> Option<String> {
        Some(s.to_string())
    }

    #[test]
    fn an_address_is_kept_under_one_name() {
        let mut b = AddressBook::default();
        b.add("Mum", "tq21aaa", "her phone").unwrap();
        assert_eq!(
            b.add("Mother", "tq21aaa", ""),
            Err(BookError::AlreadyKept("Mum".into()))
        );
        assert_eq!(b.add("mum", "tq21bbb", ""), Err(BookError::NameTaken));
        assert_eq!(
            b.add("  \u{200B} ", "tq21bbb", ""),
            Err(BookError::EmptyName)
        );
        b.add("Dad", "tq21bbb", "").unwrap();
        let names: Vec<&str> = b.list().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["Dad", "Mum"]);
    }

    #[test]
    fn an_entry_is_renamed_and_removed() {
        let mut b = AddressBook::default();
        b.add("Mum", "tq21aaa", "").unwrap();
        b.add("Dad", "tq21bbb", "").unwrap();
        assert_eq!(b.update("tq21aaa", "Dad", ""), Err(BookError::NameTaken));
        let e = b.update("tq21aaa", "Maman", "savings").unwrap();
        assert_eq!((e.name.as_str(), e.note.as_str()), ("Maman", "savings"));
        // Its own name, in another case, is not "taken".
        b.update("tq21aaa", "MAMAN", "").unwrap();
        assert_eq!(b.update("tq21zzz", "X", ""), Err(BookError::Unknown));
        b.remove("tq21aaa").unwrap();
        assert_eq!(b.remove("tq21aaa"), Err(BookError::Unknown));
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn invisible_characters_and_long_notes_are_cleaned() {
        let mut b = AddressBook::default();
        let long = "n".repeat(MAX_NOTE_LEN + 50);
        let e = b.add("\u{202E}Exchange\u{200F}", "tq21aaa", &long).unwrap();
        assert_eq!(e.name, "Exchange");
        assert_eq!(
            e.note.chars().count(),
            MAX_NOTE_LEN,
            "a note keeps its 120 characters"
        );
        // A pile of accents on one letter is cut to two.
        let e = b
            .add("Z\u{0301}\u{0302}\u{0303}\u{0304}oe", "tq21zal", "")
            .unwrap();
        assert_eq!(e.name, "Z\u{0301}\u{0302}oe");
    }

    /// Red-team campaign 6, W1: a name drawn like another — a Cyrillic М, a
    /// Greek ο, a zero for an o, another case or accent — is that name.
    #[test]
    fn a_look_alike_name_is_the_same_name() {
        let mut b = AddressBook::default();
        b.add("Mum", "tq21aaa", "").unwrap();
        for twin in ["\u{041C}um", "MUM", "M\u{03C5}m", "M\u{00F9}m", "M u m"] {
            assert_eq!(
                b.add(twin, "tq21bbb", ""),
                Err(BookError::NameTaken),
                "{twin}"
            );
        }
        b.add("Binance", "tq21ccc", "").unwrap();
        assert_eq!(
            b.add("Bin\u{0430}nce", "tq21ddd", ""),
            Err(BookError::NameTaken)
        );
        assert_eq!(
            b.add("B1nance", "tq21ddd", "").map(|e| e.name.clone()),
            Ok("B1nance".into()),
            "1 is not i"
        );
        // Real names with accents are kept as written.
        let e = b.add("H\u{00E9}l\u{00E8}ne", "tq21eee", "").unwrap();
        assert_eq!(e.name, "H\u{00E9}l\u{00E8}ne");
    }

    #[test]
    fn the_line_round_trips_and_skips_what_it_cannot_read() {
        let mut b = AddressBook::default();
        b.add("Mum, at home: 1", "tq21aaa", "a:b,c").unwrap();
        b.add("Binance", "tq21bbb", "").unwrap();
        let line = b.to_line();
        assert_eq!(AddressBook::from_line(&line, any), b);
        // A bad entry, and an address refused by the check, go alone.
        let bad = format!("{line},nothex:zz:00,tq21ccc:{}:", hex("Bad"));
        let only_known = |s: &str| (s != "tq21ccc").then(|| s.to_string());
        assert_eq!(AddressBook::from_line(&bad, only_known), b);
        assert!(AddressBook::from_line("", any).is_empty());
    }

    #[test]
    fn the_book_has_a_limit() {
        let mut b = AddressBook::default();
        for i in 0..MAX_ENTRIES {
            b.add(&format!("n{i}"), &format!("a{i}"), "").unwrap();
        }
        assert_eq!(b.add("one more", "a-last", ""), Err(BookError::Full));
    }
}
