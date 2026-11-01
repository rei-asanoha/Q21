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

use crate::contacts::{
    clean_label, clean_text, imitates_letters, look_alike_key, look_alike_loose,
};
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
    /// Another address already has this name, or one that looks just like
    /// it: the name it has.
    NameTaken(String),
    /// The name is written with characters that imitate letters.
    Imitation,
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

    /// The name of another entry that `name` cannot be told apart from.
    fn name_taken(&self, name: &str, other_than: &str) -> Option<String> {
        // Two names that look alike are one name: a second contact must not
        // pass for the first in the list (red-team campaign 6, W1).
        let key = look_alike_key(name);
        self.by_address
            .values()
            .find(|e| e.address != other_than && look_alike_key(&e.name) == key)
            .map(|e| e.name.clone())
    }

    /// The name of another entry that looks like this one's, accents aside
    /// (or from a book written before look-alikes were refused): shown with
    /// a warning, so the holder checks the address before paying.
    pub fn looks_like(&self, entry: &Entry) -> Option<String> {
        let key = look_alike_loose(&entry.name);
        self.by_address
            .values()
            .find(|e| e.address != entry.address && look_alike_loose(&e.name) == key)
            .map(|e| e.name.clone())
    }

    /// Keeps a new address. An address already kept is refused with the
    /// name it has: two names for one address would only confuse.
    pub fn add(&mut self, name: &str, address: &str, note: &str) -> Result<&Entry, BookError> {
        let name = clean_label(name);
        if name.is_empty() {
            return Err(BookError::EmptyName);
        }
        if imitates_letters(&name) {
            return Err(BookError::Imitation);
        }
        if let Some(e) = self.by_address.get(address) {
            return Err(BookError::AlreadyKept(e.name.clone()));
        }
        if let Some(other) = self.name_taken(&name, address) {
            return Err(BookError::NameTaken(other));
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
        if imitates_letters(&name) {
            return Err(BookError::Imitation);
        }
        if !self.by_address.contains_key(address) {
            return Err(BookError::Unknown);
        }
        if let Some(other) = self.name_taken(&name, address) {
            return Err(BookError::NameTaken(other));
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
            // Kept as written, look-alikes included: a book written before
            // they were refused must lose none of its entries on loading
            // (red-team campaign 6, W1b). The page shows the pair with a
            // warning instead ([`AddressBook::looks_like`]).
            let name = clean_label(&name);
            if name.is_empty()
                || book.by_address.len() >= MAX_ENTRIES
                || book.by_address.contains_key(&address)
            {
                continue;
            }
            book.by_address.insert(
                address.clone(),
                Entry {
                    address,
                    name,
                    note: clean_note(&note),
                },
            );
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
        assert_eq!(
            b.add("mum", "tq21bbb", ""),
            Err(BookError::NameTaken("Mum".into()))
        );
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
        assert_eq!(
            b.update("tq21aaa", "Dad", ""),
            Err(BookError::NameTaken("Dad".into()))
        );
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

    /// Red-team campaign 6, W1: a name drawn like another — a Cyrillic or
    /// Greek letter, a fullwidth or invisible character, a zero for an o, a
    /// capital I for an l, another case, an accent written in two pieces — is
    /// that name, and the refusal says which.
    #[test]
    fn a_look_alike_name_is_the_same_name() {
        let mut b = AddressBook::default();
        b.add("Mum", "tq21aaa", "").unwrap();
        for twin in [
            "\u{041C}um",
            "MUM",
            "M\u{03C5}m",
            "M u m",
            "\u{FF2D}um",
            "Mum\u{E0041}",
            "Mum\u{E0100}",
            "Mu\u{180B}m",
            "Mu\u{206A}m",
        ] {
            assert_eq!(
                b.add(twin, "tq21bbb", ""),
                Err(BookError::NameTaken("Mum".into())),
                "{twin:?}"
            );
        }
        b.add("Bill", "tq21ccc", "").unwrap();
        assert!(matches!(
            b.add("BiII", "tq21ddd", ""),
            Err(BookError::NameTaken(_))
        ));
        b.add("Zoe", "tq21eee", "").unwrap();
        assert!(matches!(
            b.add("\u{0396}oe", "tq21fff", ""),
            Err(BookError::NameTaken(_))
        ));
        b.add("Nina", "tq21ggg", "").unwrap();
        assert!(matches!(
            b.add("\u{039D}ina", "tq21hhh", ""),
            Err(BookError::NameTaken(_))
        ));
        // Letters drawn from symbol blocks are refused outright.
        for fake in [
            "\u{1D40C}\u{1D42E}\u{1D426}",
            "\u{2133}um",
            "\u{13B7}um",
            "\u{216F}um",
        ] {
            assert_eq!(
                b.add(fake, "tq21iii", ""),
                Err(BookError::Imitation),
                "{fake:?}"
            );
        }
        // An accent written in one piece or in two is the same name.
        b.add("L\u{00E9}a", "tq21jjj", "").unwrap();
        assert!(matches!(
            b.add("Le\u{0301}a", "tq21kkk", ""),
            Err(BookError::NameTaken(_))
        ));
    }

    /// Two people can bear names that differ by an accent only: both are
    /// kept, and each shows the other, so the holder checks the address.
    #[test]
    fn names_that_differ_by_an_accent_are_kept_and_shown_together() {
        let mut b = AddressBook::default();
        b.add("Zoe", "tq21aaa", "").unwrap();
        b.add("Zo\u{00E9}", "tq21bbb", "").unwrap();
        b.add("Ono", "tq21ccc", "").unwrap();
        b.add("\u{014C}no", "tq21ddd", "").unwrap();
        b.add("Paul", "tq21eee", "").unwrap();
        let by = |a: &str| b.get(a).cloned().unwrap();
        assert_eq!(b.looks_like(&by("tq21aaa")), Some("Zo\u{00E9}".into()));
        assert_eq!(b.looks_like(&by("tq21bbb")), Some("Zoe".into()));
        assert_eq!(b.looks_like(&by("tq21ddd")), Some("Ono".into()));
        assert_eq!(b.looks_like(&by("tq21eee")), None);
    }

    /// A book written before look-alikes were refused loses none of its
    /// entries on loading: the pair is kept and shown with a warning.
    #[test]
    fn an_older_book_with_look_alikes_loses_nothing() {
        let line = format!("tq21aaa:{}:,tq21bbb:{}:", hex("Mum"), hex("\u{041C}um"));
        let b = AddressBook::from_line(&line, any);
        assert_eq!(b.len(), 2);
        let impostor = b.get("tq21bbb").cloned().unwrap();
        assert_eq!(b.looks_like(&impostor), Some("Mum".into()));
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
