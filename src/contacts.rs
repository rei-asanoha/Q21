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
    /// The name is written with characters that imitate letters
    /// ([`imitates_letters`]).
    Imitation,
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

/// A local name as it is kept: control characters turned to spaces, the
/// invisible characters that reorder or hide text dropped, trimmed, cut at
/// [`MAX_LABEL_LEN`] characters, never in the middle of one.
pub fn clean_label(text: &str) -> String {
    clean_text(text, MAX_LABEL_LEN)
}

/// [`clean_label`] with another length: control characters turned to
/// spaces, invisible characters dropped, at most two combining marks kept on
/// a letter (a pile of them overflows the line and hides what is next to
/// it), trimmed, cut at `max` characters.
pub fn clean_text(text: &str, max: usize) -> String {
    let mut out = String::new();
    let mut marks = 0usize;
    for c in text.trim().chars().filter(|c| !is_invisible(*c)) {
        if is_combining(c) {
            marks += 1;
            if marks > 2 {
                continue;
            }
        } else {
            marks = 0;
        }
        out.push(if c.is_control() { ' ' } else { c });
    }
    let s: String = out.chars().take(max).collect();
    s.trim().to_string()
}

/// The combining marks: accents placed on the letter before them.
fn is_combining(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}'
            | '\u{0483}'..='\u{0489}'
            | '\u{0591}'..='\u{05BD}'
            | '\u{0610}'..='\u{061A}'
            | '\u{064B}'..='\u{065F}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{A66F}'..='\u{A67F}'
            | '\u{FE20}'..='\u{FE2F}'
    )
}

/// Characters drawn to imitate letters and digits — mathematical letters,
/// letter-like symbols, Roman numerals, Cherokee, small capitals, circled
/// and fullwidth forms used as letters elsewhere — refused in a contact's
/// name: no one names their mother in mathematical bold, and each would have
/// to be told apart from the letter it copies (red-team campaign 6, W1).
pub fn imitates_letters(name: &str) -> bool {
    name.chars().any(|c| {
        matches!(
            c,
            '\u{1D00}'..='\u{1DBF}'
                | '\u{2100}'..='\u{218F}'
                | '\u{2460}'..='\u{24FF}'
                | '\u{13A0}'..='\u{13FF}'
                | '\u{AB70}'..='\u{ABBF}'
                | '\u{FB00}'..='\u{FB4F}'
                | '\u{1D400}'..='\u{1D7FF}'
                | '\u{1F100}'..='\u{1F1FF}'
        )
    })
}

/// A precomposed accented letter, as its base letter and its accent.
fn decompose(c: char) -> Option<(char, char)> {
    match c {
        '\u{00E0}' => Some(('\u{0061}', '\u{0300}')),
        '\u{00E1}' => Some(('\u{0061}', '\u{0301}')),
        '\u{00E2}' => Some(('\u{0061}', '\u{0302}')),
        '\u{00E3}' => Some(('\u{0061}', '\u{0303}')),
        '\u{00E4}' => Some(('\u{0061}', '\u{0308}')),
        '\u{00E5}' => Some(('\u{0061}', '\u{030A}')),
        '\u{0101}' => Some(('\u{0061}', '\u{0304}')),
        '\u{0103}' => Some(('\u{0061}', '\u{0306}')),
        '\u{0105}' => Some(('\u{0061}', '\u{0328}')),
        '\u{00E7}' => Some(('\u{0063}', '\u{0327}')),
        '\u{0107}' => Some(('\u{0063}', '\u{0301}')),
        '\u{010D}' => Some(('\u{0063}', '\u{030C}')),
        '\u{010F}' => Some(('\u{0064}', '\u{030C}')),
        '\u{00E8}' => Some(('\u{0065}', '\u{0300}')),
        '\u{00E9}' => Some(('\u{0065}', '\u{0301}')),
        '\u{00EA}' => Some(('\u{0065}', '\u{0302}')),
        '\u{00EB}' => Some(('\u{0065}', '\u{0308}')),
        '\u{0113}' => Some(('\u{0065}', '\u{0304}')),
        '\u{0117}' => Some(('\u{0065}', '\u{0307}')),
        '\u{0119}' => Some(('\u{0065}', '\u{0328}')),
        '\u{011B}' => Some(('\u{0065}', '\u{030C}')),
        '\u{011F}' => Some(('\u{0067}', '\u{0306}')),
        '\u{00EC}' => Some(('\u{0069}', '\u{0300}')),
        '\u{00ED}' => Some(('\u{0069}', '\u{0301}')),
        '\u{00EE}' => Some(('\u{0069}', '\u{0302}')),
        '\u{00EF}' => Some(('\u{0069}', '\u{0308}')),
        '\u{012B}' => Some(('\u{0069}', '\u{0304}')),
        '\u{012F}' => Some(('\u{0069}', '\u{0328}')),
        '\u{00F1}' => Some(('\u{006E}', '\u{0303}')),
        '\u{0144}' => Some(('\u{006E}', '\u{0301}')),
        '\u{0148}' => Some(('\u{006E}', '\u{030C}')),
        '\u{00F2}' => Some(('\u{006F}', '\u{0300}')),
        '\u{00F3}' => Some(('\u{006F}', '\u{0301}')),
        '\u{00F4}' => Some(('\u{006F}', '\u{0302}')),
        '\u{00F5}' => Some(('\u{006F}', '\u{0303}')),
        '\u{00F6}' => Some(('\u{006F}', '\u{0308}')),
        '\u{014D}' => Some(('\u{006F}', '\u{0304}')),
        '\u{0151}' => Some(('\u{006F}', '\u{030B}')),
        '\u{0159}' => Some(('\u{0072}', '\u{030C}')),
        '\u{015B}' => Some(('\u{0073}', '\u{0301}')),
        '\u{0161}' => Some(('\u{0073}', '\u{030C}')),
        '\u{015F}' => Some(('\u{0073}', '\u{0327}')),
        '\u{0165}' => Some(('\u{0074}', '\u{030C}')),
        '\u{0163}' => Some(('\u{0074}', '\u{0327}')),
        '\u{00F9}' => Some(('\u{0075}', '\u{0300}')),
        '\u{00FA}' => Some(('\u{0075}', '\u{0301}')),
        '\u{00FB}' => Some(('\u{0075}', '\u{0302}')),
        '\u{00FC}' => Some(('\u{0075}', '\u{0308}')),
        '\u{016B}' => Some(('\u{0075}', '\u{0304}')),
        '\u{016F}' => Some(('\u{0075}', '\u{030A}')),
        '\u{0171}' => Some(('\u{0075}', '\u{030B}')),
        '\u{0173}' => Some(('\u{0075}', '\u{0328}')),
        '\u{00FD}' => Some(('\u{0079}', '\u{0301}')),
        '\u{00FF}' => Some(('\u{0079}', '\u{0308}')),
        '\u{017A}' => Some(('\u{007A}', '\u{0301}')),
        '\u{017C}' => Some(('\u{007A}', '\u{0307}')),
        '\u{017E}' => Some(('\u{007A}', '\u{030C}')),
        '\u{0451}' => Some(('\u{0065}', '\u{0308}')),
        '\u{0457}' => Some(('\u{0069}', '\u{0308}')),
        '\u{0439}' => Some(('\u{0438}', '\u{0306}')),
        _ => None,
    }
}

/// A capital drawn like a Latin letter, read as that letter.
fn capital_look_alike(c: char) -> Option<char> {
    match c {
        '\u{0391}' => Some('\u{0061}'),
        '\u{0392}' => Some('\u{0062}'),
        '\u{0395}' => Some('\u{0065}'),
        '\u{0396}' => Some('\u{007A}'),
        '\u{0397}' => Some('\u{0068}'),
        '\u{0399}' => Some('\u{006C}'),
        '\u{039A}' => Some('\u{006B}'),
        '\u{039C}' => Some('\u{006D}'),
        '\u{039D}' => Some('\u{006E}'),
        '\u{039F}' => Some('\u{006F}'),
        '\u{03A1}' => Some('\u{0070}'),
        '\u{03A4}' => Some('\u{0074}'),
        '\u{03A5}' => Some('\u{0079}'),
        '\u{03A7}' => Some('\u{0078}'),
        '\u{0410}' => Some('\u{0061}'),
        '\u{0412}' => Some('\u{0062}'),
        '\u{0415}' => Some('\u{0065}'),
        '\u{041A}' => Some('\u{006B}'),
        '\u{041C}' => Some('\u{006D}'),
        '\u{041D}' => Some('\u{0068}'),
        '\u{041E}' => Some('\u{006F}'),
        '\u{0420}' => Some('\u{0070}'),
        '\u{0421}' => Some('\u{0063}'),
        '\u{0422}' => Some('\u{0074}'),
        '\u{0425}' => Some('\u{0078}'),
        '\u{04AE}' => Some('\u{0079}'),
        '\u{04C0}' => Some('\u{006C}'),
        '\u{0405}' => Some('\u{0073}'),
        '\u{0406}' => Some('\u{006C}'),
        '\u{0408}' => Some('\u{006A}'),
        '\u{0049}' => Some('\u{006C}'),
        _ => None,
    }
}

/// A small letter or a digit drawn like a Latin letter, read as that letter.
fn small_look_alike(c: char) -> char {
    match c {
        '\u{0430}' => '\u{0061}',
        '\u{03B1}' => '\u{0061}',
        '\u{0432}' => '\u{0062}',
        '\u{03B2}' => '\u{0062}',
        '\u{0441}' => '\u{0063}',
        '\u{03F2}' => '\u{0063}',
        '\u{0501}' => '\u{0064}',
        '\u{0435}' => '\u{0065}',
        '\u{03B5}' => '\u{0065}',
        '\u{04BB}' => '\u{0068}',
        '\u{043D}' => '\u{0068}',
        '\u{03B7}' => '\u{0068}',
        '\u{0456}' => '\u{0069}',
        '\u{03B9}' => '\u{0069}',
        '\u{0131}' => '\u{0069}',
        '\u{04CF}' => '\u{006C}',
        '\u{0458}' => '\u{006A}',
        '\u{043A}' => '\u{006B}',
        '\u{03BA}' => '\u{006B}',
        '\u{043C}' => '\u{006D}',
        '\u{03BC}' => '\u{006D}',
        '\u{00B5}' => '\u{0075}',
        '\u{043E}' => '\u{006F}',
        '\u{03BF}' => '\u{006F}',
        '\u{03C3}' => '\u{006F}',
        '\u{0585}' => '\u{006F}',
        '\u{1D0F}' => '\u{006F}',
        '\u{0440}' => '\u{0070}',
        '\u{03C1}' => '\u{0070}',
        '\u{051B}' => '\u{0071}',
        '\u{0455}' => '\u{0073}',
        '\u{0442}' => '\u{0074}',
        '\u{03C4}' => '\u{0074}',
        '\u{0443}' => '\u{0079}',
        '\u{03B3}' => '\u{0079}',
        '\u{04AF}' => '\u{0079}',
        '\u{03C5}' => '\u{0075}',
        '\u{057D}' => '\u{0075}',
        '\u{0578}' => '\u{006E}',
        '\u{0445}' => '\u{0078}',
        '\u{03C7}' => '\u{0078}',
        '\u{03BD}' => '\u{0076}',
        '\u{051D}' => '\u{0077}',
        '\u{03C9}' => '\u{0077}',
        '\u{0437}' => '\u{0033}',
        '\u{0030}' => '\u{006F}',
        '\u{0031}' => '\u{006C}',
        '\u{007C}' => '\u{006C}',
        other => other,
    }
}

/// What a name looks like, for telling two names apart: invisible
/// characters and spaces dropped; fullwidth forms read as plain ones; a
/// capital I read as an l; the Cyrillic, Greek and Armenian letters drawn
/// like Latin ones, and digits drawn like letters, read as those letters;
/// accented letters written as their letter and their accent, so one
/// written in one piece and one written in two are the same. "Mum" and "Мum"
/// (a Cyrillic М) are one name to the eye, so they are one name here too: a
/// second contact cannot pass for the first in a list (red-team campaign 6,
/// W1). Accents are kept: a name with an accent and the same name without
/// it are two names, which [`look_alike_loose`] still notices.
pub fn look_alike_key(name: &str) -> String {
    let mut out = String::new();
    for c in name
        .chars()
        .filter(|c| !is_invisible(*c) && !c.is_whitespace())
    {
        // Fullwidth ASCII, as the ASCII it copies.
        let c = match c {
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            _ => c,
        };
        if let Some(l) = capital_look_alike(c) {
            out.push(l);
            continue;
        }
        for c in c.to_lowercase() {
            match decompose(c) {
                Some((base, mark)) => {
                    out.push(small_look_alike(base));
                    out.push(mark);
                }
                None => out.push(small_look_alike(c)),
            }
        }
    }
    out
}

/// [`look_alike_key`] without the accents: a name with an accent and the
/// same name without it meet here. Not a refusal — two people can bear them
/// — but a name to show with a warning, so the holder checks the address.
pub fn look_alike_loose(name: &str) -> String {
    look_alike_key(name)
        .chars()
        .filter(|c| !is_combining(*c))
        .collect()
}

/// The characters that show nothing yet change what is shown: the
/// direction overrides and isolates, which can make "Alice" read backward
/// or a label run into the text after it; the zero-width and blank fillers,
/// soft hyphens, variation selectors and line or paragraph separators,
/// which make two labels that look the same differ.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFFC}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
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
        if imitates_letters(&label) {
            return Err(ContactError::Imitation);
        }
        let key = look_alike_key(&label);
        if self
            .by_owner
            .values()
            .any(|c| c.owner != owner && look_alike_key(&c.label) == key)
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
        // Direction overrides and zero-width characters are dropped.
        assert_eq!(clean_label("\u{202E}ecila\u{202C}"), "ecila");
        assert_eq!(clean_label("Ma\u{200B}c\u{2066}"), "Mac");
        assert_eq!(clean_label("\u{FEFF}\u{200D}"), "");
        assert_eq!(
            clean_label("De\u{00AD}lbu\u{3164}\u{FE0F}\u{2028}"),
            "Delbu"
        );
        assert_eq!(
            clean_label(&"\u{e9}".repeat(100)).chars().count(),
            MAX_LABEL_LEN
        );
    }
}
