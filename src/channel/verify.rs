//! Verifying a contact by words read aloud.
//!
//! Two wallets hold an authenticated session ([`crate::channel::transport`]):
//! each knows the identity key the other proved. What neither knows is
//! whether that key belongs to the person on the phone. They settle it by
//! reading the same words from both screens.
//!
//! # The exchange
//!
//! ```text
//! initiator                                   responder
//!   draws nI; sends Commit(id, words, H(nI)) ──▶
//!                                         ◀── draws nR; sends Nonce(id, nR)
//!   sends Reveal(id, nI) ─────────────────────▶ checks H(nI)
//!   words = W(binding, keys, nI, nR)           words = W(binding, keys, nI, nR)
//! ```
//!
//! Each side fixes its random value before it sees the other's: the
//! initiator by its commitment, the responder by answering before the reveal.
//! A party sitting in the middle runs two exchanges, one with each side, and
//! must make their words agree. Whatever it picks, one of the two values in
//! each exchange is drawn by an honest side after the attacker's own is fixed:
//! the words of that exchange are a fresh draw, and match the other with
//! probability 2^-44 for four words, 2^-66 for six. One try, no search.
//!
//! The words also bind the session's own binding value and both identity
//! addresses: the same two nonces under another session or other keys give
//! other words.
//!
//! # The words
//!
//! 11 bits each, read as indices into the BIP 39 lists ([`Language`]): the
//! same index is the same word in a language on both sides, so both screens
//! must show the same language.

use crate::channel::kmac::CShake256;
use crate::hash::Hash256;
use std::sync::OnceLock;

/// Words read by default.
pub const WORDS_DEFAULT: u8 = 4;
/// Words read in the stronger mode.
pub const WORDS_STRONG: u8 = 6;

/// Customization strings of the two hashes, so that neither can stand for
/// the other or for any other hash of the protocol.
const S_COMMIT: &[u8] = b"Q21 verify commitment";
const S_WORDS: &[u8] = b"Q21 verify words";

/// Message types, inside a verification frame.
const T_COMMIT: u8 = 1;
const T_NONCE: u8 = 2;
const T_REVEAL: u8 = 3;

/// Bytes of a verification id.
pub const ID_LEN: usize = 16;

/// A language of the word lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Language {
    English,
    French,
    Japanese,
}

impl Language {
    pub fn from_code(code: &str) -> Option<Language> {
        match code {
            "en" => Some(Language::English),
            "fr" => Some(Language::French),
            "ja" => Some(Language::Japanese),
            _ => None,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Language::English => "en",
            Language::French => "fr",
            Language::Japanese => "ja",
        }
    }

    fn source(self) -> &'static str {
        match self {
            Language::English => include_str!("words/english.txt"),
            Language::French => include_str!("words/french.txt"),
            Language::Japanese => include_str!("words/japanese.txt"),
        }
    }

    /// The 2,048 words of the list.
    pub fn words(self) -> &'static [&'static str] {
        static EN: OnceLock<Vec<&'static str>> = OnceLock::new();
        static FR: OnceLock<Vec<&'static str>> = OnceLock::new();
        static JA: OnceLock<Vec<&'static str>> = OnceLock::new();
        let cell = match self {
            Language::English => &EN,
            Language::French => &FR,
            Language::Japanese => &JA,
        };
        cell.get_or_init(|| self.source().lines().collect())
    }
}

/// The commitment to a nonce.
pub fn commitment(nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = CShake256::new(b"", S_COMMIT);
    h.update(nonce);
    h.finalize32()
}

/// The word indices of an exchange: `count` indices of 11 bits each.
pub fn indices(
    binding: &[u8; 32],
    initiator: &Hash256,
    responder: &Hash256,
    initiator_nonce: &[u8; 32],
    responder_nonce: &[u8; 32],
    count: u8,
) -> Vec<u16> {
    let mut h = CShake256::new(b"", S_WORDS);
    h.update(binding);
    h.update(initiator.as_bytes());
    h.update(responder.as_bytes());
    h.update(initiator_nonce);
    h.update(responder_nonce);
    h.update(&[count]);
    let mut out = [0u8; 9];
    h.finalize_into(&mut out);
    let mut bits: u128 = 0;
    for b in out {
        bits = (bits << 8) | u128::from(b);
    }
    // 72 bits held, read from the top, 11 at a time.
    (0..u32::from(count))
        .map(|i| ((bits >> (72 - 11 * (i + 1))) & 0x7ff) as u16)
        .collect()
}

/// The words of `indices` in `language`.
pub fn words(indices: &[u16], language: Language) -> Vec<&'static str> {
    let list = language.words();
    indices
        .iter()
        .map(|&i| list.get(usize::from(i)).copied().unwrap_or("?"))
        .collect()
}

/// A verification message, as it travels in a session frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyMsg {
    Commit {
        id: [u8; ID_LEN],
        count: u8,
        commitment: [u8; 32],
    },
    Nonce {
        id: [u8; ID_LEN],
        nonce: [u8; 32],
    },
    Reveal {
        id: [u8; ID_LEN],
        nonce: [u8; 32],
    },
}

impl VerifyMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + ID_LEN + 1 + 32);
        match self {
            VerifyMsg::Commit {
                id,
                count,
                commitment,
            } => {
                v.push(T_COMMIT);
                v.extend_from_slice(id);
                v.push(*count);
                v.extend_from_slice(commitment);
            }
            VerifyMsg::Nonce { id, nonce } => {
                v.push(T_NONCE);
                v.extend_from_slice(id);
                v.extend_from_slice(nonce);
            }
            VerifyMsg::Reveal { id, nonce } => {
                v.push(T_REVEAL);
                v.extend_from_slice(id);
                v.extend_from_slice(nonce);
            }
        }
        v
    }

    /// Decodes a message; exact length, known type and word count, or
    /// nothing.
    pub fn decode(b: &[u8]) -> Option<VerifyMsg> {
        let (&t, rest) = b.split_first()?;
        let id: [u8; ID_LEN] = rest.get(..ID_LEN)?.try_into().ok()?;
        let rest = &rest[ID_LEN..];
        match t {
            T_COMMIT if rest.len() == 33 => {
                let count = rest[0];
                if count != WORDS_DEFAULT && count != WORDS_STRONG {
                    return None;
                }
                Some(VerifyMsg::Commit {
                    id,
                    count,
                    commitment: rest[1..].try_into().ok()?,
                })
            }
            T_NONCE if rest.len() == 32 => Some(VerifyMsg::Nonce {
                id,
                nonce: rest.try_into().ok()?,
            }),
            T_REVEAL if rest.len() == 32 => Some(VerifyMsg::Reveal {
                id,
                nonce: rest.try_into().ok()?,
            }),
            _ => None,
        }
    }
}

/// Where a verification on one session stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// We committed and wait for the peer's nonce.
    Committed {
        id: [u8; ID_LEN],
        count: u8,
        nonce: [u8; 32],
    },
    /// We answered a commitment and wait for its reveal.
    Answered {
        id: [u8; ID_LEN],
        count: u8,
        commitment: [u8; 32],
        nonce: [u8; 32],
    },
    /// The words are known; `initiator` says which side asked.
    Ready {
        id: [u8; ID_LEN],
        count: u8,
        initiator: bool,
        indices: Vec<u16>,
    },
    /// The reveal did not match its commitment, or the holder said the words
    /// differ: no new verification on this session.
    Failed,
}

/// What one session's two parties are, for the words.
#[derive(Clone, Copy, Debug)]
pub struct Parties {
    pub binding: [u8; 32],
    /// Our identity address, and the one the session proved for the peer.
    pub us: Hash256,
    pub peer: Hash256,
}

/// Starts a verification: the state to keep and the message to send.
pub fn start(count: u8, id: [u8; ID_LEN], nonce: [u8; 32]) -> (State, VerifyMsg) {
    (
        State::Committed { id, count, nonce },
        VerifyMsg::Commit {
            id,
            count,
            commitment: commitment(&nonce),
        },
    )
}

/// Handles a received message against the current state. `fresh` is the
/// nonce to draw if we answer. Returns the new state and what to send back;
/// `Err` is a protocol fault of the peer.
pub fn receive(
    state: Option<&State>,
    msg: VerifyMsg,
    parties: &Parties,
    fresh: [u8; 32],
) -> Result<(State, Option<VerifyMsg>), &'static str> {
    match (state, msg) {
        (
            Some(State::Failed),
            VerifyMsg::Commit { .. } | VerifyMsg::Nonce { .. } | VerifyMsg::Reveal { .. },
        ) => Err("verification refused on this session"),
        // Two requests crossing: the one with the smaller id goes on, on
        // both sides, so that exactly one side stays the initiator.
        (Some(s @ State::Committed { id: mine, .. }), VerifyMsg::Commit { id: theirs, .. })
            if *mine < theirs =>
        {
            Ok((s.clone(), None))
        }
        // A commitment: we answer with a nonce of ours. It replaces a
        // verification that was ready, or our own request that lost the
        // crossing above.
        (
            None | Some(State::Ready { .. }) | Some(State::Committed { .. }),
            VerifyMsg::Commit {
                id,
                count,
                commitment,
            },
        ) => Ok((
            State::Answered {
                id,
                count,
                commitment,
                nonce: fresh,
            },
            Some(VerifyMsg::Nonce { id, nonce: fresh }),
        )),
        (Some(State::Answered { .. }), VerifyMsg::Commit { .. }) => {
            Err("a verification is already under way")
        }
        (Some(State::Committed { id, count, nonce }), VerifyMsg::Nonce { id: got, nonce: r })
            if *id == got =>
        {
            let indices = indices(
                &parties.binding,
                &parties.us,
                &parties.peer,
                nonce,
                &r,
                *count,
            );
            Ok((
                State::Ready {
                    id: *id,
                    count: *count,
                    initiator: true,
                    indices,
                },
                Some(VerifyMsg::Reveal {
                    id: *id,
                    nonce: *nonce,
                }),
            ))
        }
        (
            Some(State::Answered {
                id,
                count,
                commitment: c,
                nonce,
            }),
            VerifyMsg::Reveal { id: got, nonce: i },
        ) if *id == got => {
            if commitment(&i) != *c {
                return Ok((State::Failed, None));
            }
            let indices = indices(
                &parties.binding,
                &parties.peer,
                &parties.us,
                &i,
                nonce,
                *count,
            );
            Ok((
                State::Ready {
                    id: *id,
                    count: *count,
                    initiator: false,
                    indices,
                },
                None,
            ))
        }
        _ => Err("unexpected verification message"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(s: &str) -> String {
        crate::sha256::sha256(s.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The lists are BIP 39's, byte for byte: the same index must be the
    /// same word on both screens, whatever version either side runs.
    #[test]
    fn the_word_lists_are_the_bip39_ones() {
        assert_eq!(
            sha256_hex(Language::English.source()),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert_eq!(
            sha256_hex(Language::French.source()),
            "ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59"
        );
        assert_eq!(
            sha256_hex(Language::Japanese.source()),
            "2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd"
        );
        for l in [Language::English, Language::French, Language::Japanese] {
            let w = l.words();
            assert_eq!(w.len(), 2048);
            let mut sorted = w.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), 2048, "{l:?}: no duplicate");
        }
        assert_eq!(Language::English.words()[0], "abandon");
        assert_eq!(Language::English.words()[2047], "zoo");
    }

    fn parties(binding: u8, us: u8, peer: u8) -> Parties {
        Parties {
            binding: [binding; 32],
            us: Hash256([us; 32]),
            peer: Hash256([peer; 32]),
        }
    }

    /// Runs the three messages between two honest sides.
    fn exchange(count: u8, a: &Parties, b: &Parties) -> (State, State) {
        let (sa, commit) = start(count, [7; ID_LEN], [0xa1; 32]);
        let (sb, nonce) = receive(None, commit, b, [0xb2; 32]).unwrap();
        let (sa, reveal) = receive(Some(&sa), nonce.unwrap(), a, [0; 32]).unwrap();
        let (sb, none) = receive(Some(&sb), reveal.unwrap(), b, [0; 32]).unwrap();
        assert!(none.is_none());
        (sa, sb)
    }

    fn ready(s: &State) -> (&[u16], bool) {
        match s {
            State::Ready {
                indices, initiator, ..
            } => (indices, *initiator),
            other => panic!("not ready: {other:?}"),
        }
    }

    #[test]
    fn both_screens_show_the_same_words() {
        for count in [WORDS_DEFAULT, WORDS_STRONG] {
            let (a, b) = exchange(count, &parties(9, 1, 2), &parties(9, 2, 1));
            let ((wa, ia), (wb, ib)) = (ready(&a), ready(&b));
            assert_eq!(wa, wb);
            assert_eq!(wa.len(), usize::from(count));
            assert!(ia && !ib);
            assert!(wa.iter().all(|&i| i < 2048));
            assert_eq!(words(wa, Language::French).len(), usize::from(count));
        }
    }

    #[test]
    fn other_keys_or_another_session_give_other_words() {
        let base = indices(
            &[9; 32],
            &Hash256([1; 32]),
            &Hash256([2; 32]),
            &[3; 32],
            &[4; 32],
            6,
        );
        let changed = [
            indices(
                &[8; 32],
                &Hash256([1; 32]),
                &Hash256([2; 32]),
                &[3; 32],
                &[4; 32],
                6,
            ),
            indices(
                &[9; 32],
                &Hash256([5; 32]),
                &Hash256([2; 32]),
                &[3; 32],
                &[4; 32],
                6,
            ),
            indices(
                &[9; 32],
                &Hash256([1; 32]),
                &Hash256([5; 32]),
                &[3; 32],
                &[4; 32],
                6,
            ),
            indices(
                &[9; 32],
                &Hash256([1; 32]),
                &Hash256([2; 32]),
                &[5; 32],
                &[4; 32],
                6,
            ),
            indices(
                &[9; 32],
                &Hash256([1; 32]),
                &Hash256([2; 32]),
                &[3; 32],
                &[5; 32],
                6,
            ),
            indices(
                &[9; 32],
                &Hash256([2; 32]),
                &Hash256([1; 32]),
                &[3; 32],
                &[4; 32],
                6,
            ),
        ];
        for c in changed {
            assert_ne!(c, base);
        }
        // Four words are not the first four of six: the count is bound too.
        let four = indices(
            &[9; 32],
            &Hash256([1; 32]),
            &Hash256([2; 32]),
            &[3; 32],
            &[4; 32],
            4,
        );
        assert_ne!(four[..], base[..4]);
    }

    /// A party in the middle holds one session with each side, so the
    /// bindings and the keys it proves differ: the words differ.
    #[test]
    fn a_party_in_the_middle_gets_two_different_word_sets() {
        let (a, _) = exchange(4, &parties(1, 10, 66), &parties(1, 66, 10));
        let (_, b) = exchange(4, &parties(2, 66, 20), &parties(2, 20, 66));
        assert_ne!(ready(&a).0, ready(&b).0);
    }

    #[test]
    fn a_reveal_that_breaks_its_commitment_fails_the_verification() {
        let b = parties(9, 2, 1);
        let (_, commit) = start(4, [7; ID_LEN], [0xa1; 32]);
        let (sb, _) = receive(None, commit, &b, [0xb2; 32]).unwrap();
        let lie = VerifyMsg::Reveal {
            id: [7; ID_LEN],
            nonce: [0xee; 32],
        };
        let (sb, _) = receive(Some(&sb), lie, &b, [0; 32]).unwrap();
        assert_eq!(sb, State::Failed);
        let again = start(4, [8; ID_LEN], [1; 32]).1;
        assert!(receive(Some(&sb), again, &b, [0; 32]).is_err());
    }

    #[test]
    fn messages_round_trip_and_reject_anything_else() {
        let msgs = [
            VerifyMsg::Commit {
                id: [1; ID_LEN],
                count: 6,
                commitment: [2; 32],
            },
            VerifyMsg::Nonce {
                id: [3; ID_LEN],
                nonce: [4; 32],
            },
            VerifyMsg::Reveal {
                id: [5; ID_LEN],
                nonce: [6; 32],
            },
        ];
        for m in msgs {
            let b = m.encode();
            assert_eq!(VerifyMsg::decode(&b), Some(m));
            assert_eq!(VerifyMsg::decode(&b[..b.len() - 1]), None);
            let mut longer = b.clone();
            longer.push(0);
            assert_eq!(VerifyMsg::decode(&longer), None);
        }
        let mut five = VerifyMsg::Commit {
            id: [1; ID_LEN],
            count: 4,
            commitment: [2; 32],
        }
        .encode();
        five[1 + ID_LEN] = 5;
        assert_eq!(VerifyMsg::decode(&five), None, "4 or 6 words only");
        assert_eq!(VerifyMsg::decode(&[9; 50]), None);
        assert_eq!(VerifyMsg::decode(&[]), None);
    }

    /// Both holders press "verify" at once: one request wins on both sides,
    /// and the words still come out the same.
    #[test]
    fn crossing_requests_settle_on_one() {
        let a = parties(9, 1, 2);
        let b = parties(9, 2, 1);
        let (sa, ca) = start(4, [1; ID_LEN], [0xa1; 32]);
        let (sb, cb) = start(4, [2; ID_LEN], [0xb2; 32]);
        // A keeps its own (smaller id) and ignores B's.
        let (sa2, none) = receive(Some(&sa), cb, &a, [0xa9; 32]).unwrap();
        assert_eq!(sa2, sa);
        assert!(none.is_none());
        // B answers A's.
        let (sb2, nonce) = receive(Some(&sb), ca, &b, [0xb9; 32]).unwrap();
        let (sa3, reveal) = receive(Some(&sa2), nonce.unwrap(), &a, [0; 32]).unwrap();
        let (sb3, _) = receive(Some(&sb2), reveal.unwrap(), &b, [0; 32]).unwrap();
        assert_eq!(ready(&sa3).0, ready(&sb3).0);
    }

    #[test]
    fn out_of_order_messages_are_faults() {
        let p = parties(9, 1, 2);
        let nonce = VerifyMsg::Nonce {
            id: [7; ID_LEN],
            nonce: [1; 32],
        };
        assert!(receive(None, nonce.clone(), &p, [0; 32]).is_err());
        let (s, _) = start(4, [8; ID_LEN], [1; 32]);
        assert!(receive(Some(&s), nonce, &p, [0; 32]).is_err(), "wrong id");
    }
}
