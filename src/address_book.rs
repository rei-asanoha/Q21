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
    clean_label, clean_text, imitates_letters, look_alike_loose, name_keys, same_keys,
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
        let keys = name_keys(name);
        self.by_address
            .values()
            .find(|e| e.address != other_than && same_keys(&name_keys(&e.name), &keys))
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

    /// [`Self::looks_like`] for every entry at once, each name read once:
    /// the address of each entry that looks like another, with that other's
    /// name.
    pub fn look_alikes(&self) -> BTreeMap<String, String> {
        let keyed: Vec<(String, &Entry)> = self
            .by_address
            .values()
            .map(|e| (look_alike_loose(&e.name), e))
            .collect();
        let mut by_key: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
        for (k, e) in &keyed {
            by_key.entry(k.as_str()).or_default().push(e);
        }
        let mut out = BTreeMap::new();
        for (k, e) in &keyed {
            if let Some(other) = by_key[k.as_str()].iter().find(|o| o.address != e.address) {
                out.insert(e.address.clone(), other.name.clone());
            }
        }
        out
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
        let Some(current) = self.by_address.get(address) else {
            return Err(BookError::Unknown);
        };
        // A book written before look-alikes were refused can still have its
        // notes edited: the name kept as it is passes. Anything else is a
        // new name, and goes through every check — except that a look-alike
        // the entry already had is not held against it.
        let (old, new) = (name_keys(&current.name), name_keys(&name));
        let kept = old == new;
        if !kept && imitates_letters(&name) {
            return Err(BookError::Imitation);
        }
        if let Some(other) = self.by_address.values().find(|e| {
            e.address != address && {
                let theirs = name_keys(&e.name);
                same_keys(&theirs, &new) && !(kept && same_keys(&theirs, &old))
            }
        }) {
            return Err(BookError::NameTaken(other.name.clone()));
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
        // A pile of accents on one letter is cut to three.
        let e = b
            .add("Z\u{0301}\u{0302}\u{0303}\u{0304}\u{0305}oe", "tq21zal", "")
            .unwrap();
        assert_eq!(e.name, "Z\u{0301}\u{0302}\u{0303}oe");
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

    /// Red-team campaign 6, round 3: the names that still slipped through —
    /// a case variant with an i, letters of other scripts written in one
    /// piece or in two, two accents on one letter, a kana with its voicing
    /// mark, tag characters beyond the first block — are the same name; marks
    /// of every script are capped; symbols that copy no letter are allowed.
    #[test]
    fn the_round_three_look_alikes_are_the_same_name() {
        let mut b = AddressBook::default();
        b.add("Ivan", "tq21aaa", "").unwrap();
        assert!(matches!(
            b.add("ivan", "tq21bbb", ""),
            Err(BookError::NameTaken(_))
        ));
        assert!(matches!(
            b.add("lvan", "tq21bbb", ""),
            Err(BookError::NameTaken(_))
        ));
        for (one, two) in [
            ("\u{0219}tefan", "s\u{0326}tefan"),
            ("Ng\u{1EC5}n", "Nge\u{0302}\u{0303}n"),
            ("\u{304C}\u{304F}", "\u{304B}\u{3099}\u{304F}"),
            ("B\u{1EE5}i", "Bu\u{0323}i"),
        ] {
            b.add(one, "tq21ccc", "").unwrap();
            assert!(
                matches!(b.add(two, "tq21ddd", ""), Err(BookError::NameTaken(_))),
                "{two:?}"
            );
            b.remove("tq21ccc").unwrap();
        }
        b.add("Tom", "tq21eee", "").unwrap();
        for twin in ["To\u{E0200}m", "T\u{1BCA0}om"] {
            assert!(
                matches!(b.add(twin, "tq21fff", ""), Err(BookError::NameTaken(_))),
                "{twin:?}"
            );
        }
        // Thai and Devanagari marks are piled no higher than Latin accents.
        let thai = b
            .add(
                "\u{0E01}\u{0E34}\u{0E35}\u{0E36}\u{0E37}\u{0E38}",
                "tq21ggg",
                "",
            )
            .unwrap();
        assert_eq!(thai.name.chars().count(), 4);
        let deva = b
            .add("\u{0915}\u{0941}\u{0942}\u{0943}\u{0944}", "tq21hhh", "")
            .unwrap();
        assert_eq!(deva.name.chars().count(), 4);
        // Symbols that copy no letter are names like any other.
        for (i, ok) in [
            "Shop\u{2122}",
            "Flat \u{2116}3",
            "Team \u{2460}",
            "Ana \u{1F1EB}\u{1F1F7}",
        ]
        .iter()
        .enumerate()
        {
            b.add(ok, &format!("tq21ok{i}"), "").unwrap();
        }
        // The letters among symbols are still refused.
        for fake in ["\u{24B6}na", "\u{1F130}na", "\u{FB01}ona", "\u{2102}ana"] {
            assert_eq!(
                b.add(fake, "tq21iii", ""),
                Err(BookError::Imitation),
                "{fake:?}"
            );
        }
    }

    /// Red-team campaign 6, round 4: the look-alikes found by drawing every
    /// character of common fonts — accented capitals, Hangul written in
    /// letters, compatibility ideographs, Greek accents in two encodings,
    /// Indic vowels in two parts, Persian and Arabic letter variants, letters
    /// of other scripts drawn like Latin ones, dashes and apostrophes, marks
    /// in another order — are the same name; a name and the same with a
    /// number moved across a right-to-left word are shown together.
    #[test]
    fn the_round_four_look_alikes_are_the_same_name() {
        let pairs = [
            ("\u{0130}lker", "l\u{0307}lker"),
            ("\u{00CD}var", "\u{013A}var"),
            ("\u{0130}smail", "I\u{0307}smaiI"),
            ("\u{0178}vonne", "\u{03AB}vonne"),
            (
                "\u{AE40}\u{BBFC}\u{C900}",
                "\u{1100}\u{1175}\u{11B7}\u{BBFC}\u{C900}",
            ),
            ("\u{674E}\u{660E}", "\u{F9E1}\u{660E}"),
            (
                "\u{03A3}\u{03BF}\u{03C6}\u{03AF}\u{03B1}",
                "\u{03A3}\u{03BF}\u{03C6}\u{1F77}\u{03B1}",
            ),
            (
                "\u{09AE}\u{09CB}\u{09B9}\u{09A8}",
                "\u{09AE}\u{09C7}\u{09BE}\u{09B9}\u{09A8}",
            ),
            (
                "\u{0643}\u{0631}\u{064A}\u{0645}",
                "\u{06A9}\u{0631}\u{06CC}\u{0645}",
            ),
            ("\u{0639}\u{0644}\u{0649}", "\u{0639}\u{0644}\u{06CC}"),
            ("Greg", "Gre\u{0261}"),
            ("John", "\u{037F}ohn"),
            ("Hannah", "Hanna\u{0570}"),
            ("Fran\u{00E7}ois", "Fran\u{04AB}ois"),
            ("MARK", "\u{A4DF}\u{A4EE}\u{A4E3}\u{A4D7}"),
            ("Dijkstra", "D\u{0133}kstra"),
            ("Jean-Paul", "Jean\u{2011}Paul"),
            ("O\u{2019}Brien", "O\u{02BC}Brien"),
            (
                "\u{0E19}\u{0E49}\u{0E33}",
                "\u{0E19}\u{0E4D}\u{0E49}\u{0E32}",
            ),
            ("S\u{00F8}ren", "So\u{0338}ren"),
            ("L\u{1ED9}c", "L\u{00F4}\u{0323}c"),
            ("\u{0110}or\u{0111}e", "\u{0110}OR\u{0110}E"),
            ("\u{00D0}or\u{0111}e", "\u{0110}or\u{0111}e"),
        ];
        for (one, two) in pairs {
            let mut b = AddressBook::default();
            b.add(one, "tq21aaa", "").unwrap();
            assert!(
                matches!(b.add(two, "tq21bbb", ""), Err(BookError::NameTaken(_))),
                "{one:?} {two:?}"
            );
        }
        // Names that only resemble each other stay apart.
        for (one, two) in [
            ("Ali", "Ala"),
            ("Anna", "Anne"),
            ("Mum", "Mom"),
            ("Zoe", "Zo\u{00E9}"),
        ] {
            let mut b = AddressBook::default();
            b.add(one, "tq21aaa", "").unwrap();
            b.add(two, "tq21bbb", "").unwrap();
        }
        // Compatibility forms that copy a letter are refused.
        let mut b = AddressBook::default();
        for fake in [
            "\u{2F2D}\u{2F65}",
            "\u{FEE3}\u{FEA4}\u{FEE4}\u{FEAA}",
            "\u{2E9F}",
        ] {
            assert_eq!(
                b.add(fake, "tq21ccc", ""),
                Err(BookError::Imitation),
                "{fake:?}"
            );
        }
        // A number moved across a right-to-left name: shown together.
        b.add("\u{0645}\u{062D}\u{0645}\u{062F} 2", "tq21ddd", "")
            .unwrap();
        b.add("2 \u{0645}\u{062D}\u{0645}\u{062F}", "tq21eee", "")
            .unwrap();
        let e = b.get("tq21eee").cloned().unwrap();
        assert!(b.looks_like(&e).is_some());
        // Real names keep what makes them: three marks, a Tibetan stack,
        // a Persian joiner, an emoji sequence.
        for (i, n) in [
            "\u{05D9}\u{05E9}\u{05BC}\u{05B8}\u{05C2}",
            "\u{0F66}\u{0F92}\u{0FB2}\u{0F7C}\u{0F63}",
            "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}",
            "Team \u{1F469}\u{200D}\u{1F4BB}",
        ]
        .iter()
        .enumerate()
        {
            let e = b.add(n, &format!("tq21keep{i}"), "").unwrap();
            assert_eq!(e.name, *n);
        }
    }

    /// Red-team campaign 6, round 5: capitals of one look read alike in both
    /// keys, more letters found alike in more fonts; the joiners of an emoji
    /// sequence kept, never left at an end; Tibetan stacks capped; a new
    /// emoji allowed.
    #[test]
    fn the_round_five_look_alikes_are_the_same_name() {
        for (one, two) in [
            (
                "\u{0398}\u{0391}\u{039D}\u{0391}\u{03A3}",
                "\u{03F4}\u{0391}N\u{0391}\u{03A3}",
            ),
            ("Ilya", "\u{0196}Iya"),
            ("Ilya", "\u{A646}Iya"),
            ("\u{0110}or\u{0111}e", "D\u{0335}or\u{0111}e"),
            ("\u{0197}van", "I\u{0335}van"),
            (
                "\u{03A6}\u{03CE}\u{03C4}\u{03B7}\u{03C2}",
                "\u{0424}\u{03CE}\u{03C4}\u{03B7}\u{03C2}",
            ),
            (
                "\u{0432}\u{0456}\u{0454}\u{043D}",
                "\u{0432}\u{0456}\u{03F5}\u{043D}",
            ),
            ("\u{0B95}\u{0BA3}", "\u{0BE7}\u{0BA3}"),
            ("J. Smith", "J\u{A4F8} Smith"),
            ("John", "\u{A4D9}ohn"),
            ("Lea", "\u{053C}ea"),
            // Campaign 7: the small capitals of the phonetic block.
            ("nora", "\u{0274}ora"),
            ("Greg", "\u{0262}reg"),
            ("Lina", "\u{029F}ina"),
            ("Rita", "\u{0280}ita"),
            ("Anna", "\u{0251}nna"),
        ] {
            let mut b = AddressBook::default();
            b.add(one, "tq21aaa", "").unwrap();
            assert!(
                matches!(b.add(two, "tq21bbb", ""), Err(BookError::NameTaken(_))),
                "{one:?} {two:?}"
            );
        }
        let mut b = AddressBook::default();
        assert_eq!(
            b.add("\u{2C9E}lga", "tq21ccc", ""),
            Err(BookError::Imitation)
        );
        let flag = b
            .add("\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}", "tq21ddd", "")
            .unwrap();
        assert_eq!(flag.name, "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}");
        let edge = b
            .add("\u{0001}\u{200D}Ann\u{200D}\u{0001}", "tq21eee", "")
            .unwrap();
        assert_eq!(edge.name, "Ann");
        let tower = b
            .add(&format!("\u{0F40}{}", "\u{0F90}".repeat(10)), "tq21fff", "")
            .unwrap();
        assert_eq!(tower.name.chars().count(), 4);
        b.add("Dad \u{1FAE9}", "tq21ggg", "").unwrap();
    }

    /// A rename to a name that would be refused on adding is refused too:
    /// only the name kept as it is passes the checks it already failed.
    #[test]
    fn a_rename_cannot_make_a_look_alike() {
        let mut b = AddressBook::default();
        b.add("Nina", "tq21aaa", "").unwrap();
        b.add("vina", "tq21bbb", "").unwrap();
        assert!(matches!(
            b.update("tq21bbb", "\u{039D}ina", ""),
            Err(BookError::NameTaken(_))
        ));
        b.add("\u{0130}lker", "tq21ccc", "").unwrap();
        b.add("Ilkay", "tq21ddd", "").unwrap();
        assert!(matches!(
            b.update("tq21ddd", "I\u{0307}lker", ""),
            Err(BookError::NameTaken(_))
        ));
    }

    /// An entry of a book written before look-alikes were refused keeps
    /// its name while its note is edited, or its name's case changed; and
    /// the list's warnings, read once for all, match the ones read one by one.
    #[test]
    fn an_older_look_alike_can_still_have_its_note_edited() {
        let line = format!(
            "tq21aaa:{}:,tq21bbb:{}:,tq21ccc:{}:",
            hex("Mum"),
            hex("\u{041C}um"),
            hex("\u{2133}ax")
        );
        let mut b = AddressBook::from_line(&line, any);
        b.update("tq21bbb", "\u{041C}um", "the other one").unwrap();
        b.update("tq21bbb", "\u{041C}UM", "the other one").unwrap();
        b.update("tq21ccc", "\u{2133}ax", "old").unwrap();
        // A real rename still goes through every check.
        assert!(matches!(
            b.update("tq21ccc", "MUM", ""),
            Err(BookError::NameTaken(_))
        ));
        assert_eq!(
            b.update("tq21ccc", "\u{2133}um", ""),
            Err(BookError::Imitation)
        );
        let all = b.look_alikes();
        for e in b.list() {
            assert_eq!(
                all.get(&e.address).cloned(),
                b.looks_like(e),
                "{}",
                e.address
            );
        }
        assert_eq!(all.len(), 2);
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
