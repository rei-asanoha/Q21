//! The contact book: the people this wallet pays, by a name of its own.
//!
//! A contact is a local name ("Delbu"), chosen by the holder and seen by no
//! one else, attached to an **identity address**: the hash of the key a
//! peer's channel session proves (see [`crate::channel::transport`]). The
//! address is pinned: every later session is checked against it, and a peer
//! that proves another key is not that contact, whatever it says.
//!
//! A contact is either verified — the two holders read the same words aloud,
//! from the two screens ([`crate::channel::verify`]) — or not. A payment or a
//! channel toward an unverified contact asks for a stronger confirmation.
//!
//! Strictly local: kept in the wallet file, sealed with it, never sent.

use crate::hash::Hash256;
use std::collections::BTreeMap;

/// Most contacts a book holds.
pub const MAX_CONTACTS: usize = 1000;

/// Longest local name, in characters.
pub const MAX_LABEL_LEN: usize = 64;

/// A contact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// The holder's name for it.
    pub label: String,
    /// The identity address it is pinned to.
    pub owner: Hash256,
    /// The registered name it was found by, if any ([`crate::names`]).
    pub name: Option<String>,
    /// Words read aloud to verify it: 0 when not verified, else 4 or 6.
    pub verified_words: u8,
}

impl Contact {
    pub fn is_verified(&self) -> bool {
        self.verified_words > 0
    }
}

/// Why a contact is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContactError {
    /// The local name is empty once cleaned.
    EmptyLabel,
    /// Another contact already holds this local name.
    LabelTaken,
    /// The book is full ([`MAX_CONTACTS`]).
    Full,
    /// No contact with this identity address.
    Unknown,
}

/// The book, by identity address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContactBook {
    by_owner: BTreeMap<Hash256, Contact>,
}

/// A local name as it is kept: control characters turned to spaces, trimmed,
/// cut at [`MAX_LABEL_LEN`] characters, never in the middle of one.
pub fn clean_label(text: &str) -> String {
    let s: String = text
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_LABEL_LEN)
        .collect();
    s.trim().to_string()
}

impl ContactBook {
    /// Every contact, sorted by local name.
    pub fn list(&self) -> Vec<&Contact> {
        let mut v: Vec<&Contact> = self.by_owner.values().collect();
        v.sort_by_key(|a| a.label.to_lowercase());
        v
    }

    pub fn get(&self, owner: &Hash256) -> Option<&Contact> {
        self.by_owner.get(owner)
    }

    pub fn len(&self) -> usize {
        self.by_owner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_owner.is_empty()
    }

    /// Adds a contact, or renames one already pinned to `owner`; keeps its
    /// verification only if `owner` is the one it was verified for, which it
    /// is by construction: the book is keyed by it.
    pub fn add(
        &mut self,
        label: &str,
        owner: Hash256,
        name: Option<String>,
    ) -> Result<&Contact, ContactError> {
        let label = clean_label(label);
        if label.is_empty() {
            return Err(ContactError::EmptyLabel);
        }
        let lower = label.to_lowercase();
        if self
            .by_owner
            .values()
            .any(|c| c.owner != owner && c.label.to_lowercase() == lower)
        {
            return Err(ContactError::LabelTaken);
        }
        if !self.by_owner.contains_key(&owner) && self.by_owner.len() >= MAX_CONTACTS {
            return Err(ContactError::Full);
        }
        let verified_words = self.by_owner.get(&owner).map_or(0, |c| c.verified_words);
        let name = name.or_else(|| self.by_owner.get(&owner).and_then(|c| c.name.clone()));
        self.by_owner.insert(
            owner,
            Contact {
                label,
                owner,
                name,
                verified_words,
            },
        );
        Ok(&self.by_owner[&owner])
    }

    pub fn remove(&mut self, owner: &Hash256) -> Result<Contact, ContactError> {
        self.by_owner.remove(owner).ok_or(ContactError::Unknown)
    }

    /// Records that the holder confirmed `words` matching words for `owner`.
    pub fn mark_verified(&mut self, owner: &Hash256, words: u8) -> Result<(), ContactError> {
        let c = self.by_owner.get_mut(owner).ok_or(ContactError::Unknown)?;
        c.verified_words = c.verified_words.max(words);
        Ok(())
    }

    /// The book as the value of the `contacts=` line of the wallet file:
    /// entries separated by commas, each `owner:label:name:words`, the texts
    /// in hexadecimal so that no character typed by a person can break the
    /// one-line-per-key format. Sorted, so that two writes of one book are
    /// the same bytes.
    pub fn to_line(&self) -> String {
        let hex = |s: &str| -> String { s.bytes().map(|b| format!("{b:02x}")).collect() };
        self.by_owner
            .values()
            .map(|c| {
                format!(
                    "{}:{}:{}:{}",
                    c.owner.to_hex(),
                    hex(&c.label),
                    c.name.as_deref().map(hex).unwrap_or_default(),
                    c.verified_words
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Reads the `contacts=` line back. A malformed entry is skipped on its
    /// own: losing a contact is an inconvenience, losing the wallet is not
    /// an option.
    pub fn from_line(value: &str) -> ContactBook {
        let unhex = |s: &str| -> Option<String> {
            if s.len() % 2 != 0 {
                return None;
            }
            let bytes: Option<Vec<u8>> = (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
                .collect();
            String::from_utf8(bytes?).ok()
        };
        let mut book = ContactBook::default();
        for entry in value.split(',').filter(|s| !s.is_empty()) {
            let parts: Vec<&str> = entry.split(':').collect();
            let [owner, label, name, words] = parts.as_slice() else {
                continue;
            };
            let (Some(owner), Some(label), Some(name), Ok(words)) = (
                Hash256::from_hex(owner),
                unhex(label),
                unhex(name),
                words.parse::<u8>(),
            ) else {
                continue;
            };
            let label = clean_label(&label);
            if label.is_empty() || book.by_owner.len() >= MAX_CONTACTS {
                continue;
            }
            let name = crate::names::normalize(&name);
            book.by_owner.insert(
                owner,
                Contact {
                    label,
                    owner,
                    name,
                    verified_words: if matches!(words, 4 | 6) { words } else { 0 },
                },
            );
        }
        book
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Hash256 {
        Hash256([n; 32])
    }

    #[test]
    fn a_contact_is_pinned_to_its_identity_address() {
        let mut b = ContactBook::default();
        b.add("Delbu", h(1), Some("delbu".into())).unwrap();
        assert_eq!(b.get(&h(1)).unwrap().label, "Delbu");
        assert!(!b.get(&h(1)).unwrap().is_verified());
        // The same local name for another key is refused, whatever the case.
        assert_eq!(b.add("delbu", h(2), None), Err(ContactError::LabelTaken));
        // Renaming the same contact keeps it.
        b.add("Delbu (work)", h(1), None).unwrap();
        assert_eq!(b.get(&h(1)).unwrap().name.as_deref(), Some("delbu"));
        assert_eq!(b.len(), 1);
        assert_eq!(b.add("  \n ", h(3), None), Err(ContactError::EmptyLabel));
    }

    #[test]
    fn verification_survives_a_rename_and_never_goes_down() {
        let mut b = ContactBook::default();
        b.add("Delbu", h(1), None).unwrap();
        b.mark_verified(&h(1), 6).unwrap();
        b.mark_verified(&h(1), 4).unwrap();
        b.add("Delbu B.", h(1), None).unwrap();
        assert_eq!(b.get(&h(1)).unwrap().verified_words, 6);
        assert_eq!(b.mark_verified(&h(9), 4), Err(ContactError::Unknown));
    }

    #[test]
    fn the_book_survives_the_wallet_file() {
        let mut b = ContactBook::default();
        b.add("Delbu, the \"plumber\" = 1", h(1), Some("delbu".into()))
            .unwrap();
        b.add("Mac", h(2), None).unwrap();
        b.mark_verified(&h(2), 4).unwrap();
        let line = b.to_line();
        assert!(!line.contains('\n') && !line.contains('='));
        assert_eq!(ContactBook::from_line(&line), b);
        assert_eq!(ContactBook::from_line(""), ContactBook::default());
        // A damaged entry is dropped alone.
        let damaged = format!("{line},zz:00:00:4,{}:6869::9", h(3).to_hex());
        let back = ContactBook::from_line(&damaged);
        assert_eq!(back.len(), 3);
        assert_eq!(back.get(&h(3)).unwrap().verified_words, 0);
    }

    #[test]
    fn labels_are_cleaned_and_bounded() {
        assert_eq!(clean_label("  a\tb  "), "a b");
        assert_eq!(
            clean_label(&"\u{e9}".repeat(100)).chars().count(),
            MAX_LABEL_LEN
        );
    }
}
