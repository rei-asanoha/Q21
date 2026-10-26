//! The authenticated, encrypted session between two channel peers.
//!
//! Channel frames used to cross the P2P connection in clear, bound to a
//! self-declared node id and a challenge whose nonces a relay could pass
//! along. A party relaying between two nodes could read every frame, drop or
//! delay any, and get both of its connections taken for the counterparty.
//! This module removes the relay: each side proves a static ML-DSA-87 node
//! identity ([`NodeIdentity`]) over a transcript that holds both ends'
//! ephemeral ML-KEM-1024 keys, and every engine frame then travels in a
//! record only the two holders of the session keys can open or forge.
//!
//! Nothing here touches the network; [`crate::channel::link`] carries the
//! bytes and bounds the work a stranger can cause.
//!
//! # Handshake (1.5 round trips)
//!
//! Roles follow the P2P connection: the side that dialed is the initiator
//! `I`, the side that accepted is the responder `R`. Every frame is a
//! payload of the P2P `channel` message and begins with the transport
//! version ([`VERSION`]) and a type byte.
//!
//! ```text
//! I -> R  Init  ek_I, pk_I, legacy_I
//! R -> I  Resp  ek_R, ct_R = Encaps(ek_I), pk_R, legacy_R, sig_R
//! I -> R  Fin   ct_I = Encaps(ek_R), sig_I
//! ```
//!
//! `ek_*` are fresh ML-KEM-1024 encapsulation keys (FIPS 203), `pk_*` the
//! static ML-DSA-87 identity keys, `legacy_*` the 16-byte node id a wallet
//! advertised before this transport (it is signed, but authenticates
//! nothing). Each side encapsulates to the other's ephemeral key, so the
//! session keys depend on randomness from both ends: one side's broken
//! generator alone does not expose the session, and both ephemeral
//! decapsulation keys are dropped (and wiped) once used, for forward secrecy.
//!
//! The transcript `T` is a cSHAKE256 (SP 800-185) over, in order and each
//! field length-prefixed: the version, the network, the initiator's and the
//! responder's P2P `Version` nonces, `ek_I`, `pk_I`, `legacy_I`, `ek_R`,
//! `ct_R`, `pk_R`, `legacy_R` (= `T2`), then `sig_R`, `ct_I` (= `T3`), then
//! `sig_I` (= `Tf`). `sig_R` is the responder's signature over
//! `cSHAKE256("R" || T2)` and `sig_I` the initiator's over
//! `cSHAKE256("I" || T3)`, each under its own customization string, so a
//! signature from one role never verifies in the other.
//!
//! What this gives against an active party between the two:
//!
//! - substituting `ek_I`, `ek_R` or `ct_R` changes `T2` on one side only, and
//!   `sig_R` no longer verifies at `I`; substituting `ct_I` changes `T3` and
//!   `sig_I` fails at `R`;
//! - running its own handshake on each side means signing with its own
//!   identity: each end sees the relay's node id, not the peer's, and no
//!   channel is bound to it (channels are bound to the node id alone);
//! - forwarding unchanged but with P2P nonces of its own changes the nonce
//!   fields: both signatures fail. Forwarding with copied nonces only makes
//!   it a pipe for a session it holds no key of: it can drop or delay
//!   records, as any hop can, and nothing else.
//!
//! The P2P nonces are each node's own, drawn once per process and the same on
//! all its connections: they bind a handshake to the two node instances at
//! its ends, as each saw the other introduce itself, not to one connection.
//! What makes every session unique is the pair of fresh ephemeral keys; the
//! nonces only stop a relay that does not take the trouble to copy them, and
//! the protection against one that does is the signatures over the keys.
//!
//! # Key schedule
//!
//! ```text
//! okm  = KMAC256(K = ss_R || ss_I, X = Tf, L = 768, S = "...session")
//! okm  = T_IR (32) || T_RI (32) || binding (32)
//! keys = KMAC256(K = T, X = "", L = 512, S = "...record keys")  = k_enc || k_mac
//! T'   = KMAC256(K = T, X = "", L = 256, S = "...rekey")
//! ```
//!
//! `ss_R` is the secret `R` encapsulated to `ek_I`, `ss_I` the one `I`
//! encapsulated to `ek_R`. `T_IR` carries `I -> R` traffic, `T_RI` the other
//! direction. The `binding` names the session to the channel layer, which
//! signs it in its reestablish proofs so a proof is good for one session
//! only. A direction rekeys after [`REKEY_RECORDS`] records or
//! [`REKEY_BYTES`] bytes, whichever comes first: both ends count the same
//! records, so no message is needed, and the old traffic secret is wiped.
//!
//! # Records
//!
//! ```text
//! record = VERSION || T_RECORD || seq (8, big-endian) || c || tag (32)
//! c      = p XOR cSHAKE256(X = bytepad(encode_string(k_enc), 136) || seq,
//!                          L = 8|p|, N = "", S = "...record stream")
//! tag    = KMAC256(K = k_mac, X = VERSION || T_RECORD || seq || c,
//!                  L = 256, S = "...record tag")
//! ```
//!
//! Encrypt-then-MAC. The keystream is cSHAKE256 keyed the way KMAC keys it
//! (the key alone in its padded block), under its own customization, at a
//! nonce that never repeats under one key: the sequence number counts each
//! direction from zero and is never reset, rekeys included. A record is
//! taken only at exactly the next sequence number: one below is a replay,
//! one above means a record was lost; either ends the session, as does a tag
//! that does not verify (compared in constant time, before anything is
//! decrypted). A record carries at most [`MAX_RECORD`] bytes, so it fits the
//! P2P `channel` message.

use crate::address::Network;
use crate::channel::keys::{node_id, NodeIdentity, CHANNEL_SCHEME, LEGACY_NODE_ID_LEN};
use crate::channel::kmac::{kmac256, CShake256};
use crate::hash::Hash256;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{MlKem1024, B32};

/// The transport version, first byte of every frame. Version 3 is the first
/// with a transport: the channel frames of 0.4.10 (engine wire 2) went in
/// clear, and a peer still speaking them advertises another capability (see
/// [`crate::wire::CHANNELS_CAPABILITY`]).
pub const VERSION: u8 = 3;

pub const T_INIT: u8 = 1;
pub const T_RESP: u8 = 2;
pub const T_FIN: u8 = 3;
pub const T_RECORD: u8 = 4;
/// Responder -> initiator: "I hold no session with you; start one." It
/// carries nothing and proves nothing; what it can cause is a handshake,
/// which the link layer rate-limits.
pub const T_RESET: u8 = 5;

/// An ML-KEM-1024 encapsulation key.
pub const EK_LEN: usize = 1568;
/// An ML-KEM-1024 ciphertext.
pub const CT_LEN: usize = 1568;
/// A node identity public key.
pub const PK_LEN: usize = CHANNEL_SCHEME.pubkey_len();
/// A node identity signature.
pub const SIG_LEN: usize = CHANNEL_SCHEME.sig_len();

pub const INIT_LEN: usize = 2 + EK_LEN + PK_LEN + LEGACY_NODE_ID_LEN;
pub const RESP_LEN: usize = 2 + EK_LEN + CT_LEN + PK_LEN + LEGACY_NODE_ID_LEN + SIG_LEN;
pub const FIN_LEN: usize = 2 + CT_LEN + SIG_LEN;

pub const TAG_LEN: usize = 32;
/// Version, type and sequence number.
pub const RECORD_HEADER: usize = 2 + 8;
pub const RECORD_OVERHEAD: usize = RECORD_HEADER + TAG_LEN;
/// Largest record plaintext: a record fills at most one P2P `channel`
/// message.
pub const MAX_RECORD: usize = crate::wire::MAX_CHANNEL_MSG - RECORD_OVERHEAD;

// Every frame fits one P2P `channel` message, and so does a record of the
// heaviest engine frame (three tier signatures, a channel id and a kind).
const _: () = assert!(INIT_LEN <= crate::wire::MAX_CHANNEL_MSG);
const _: () = assert!(RESP_LEN <= crate::wire::MAX_CHANNEL_MSG);
const _: () = assert!(FIN_LEN <= crate::wire::MAX_CHANNEL_MSG);
const _: () = assert!(33 + 64 + 3 * (SIG_LEN + 4) < MAX_RECORD);

/// Records a direction carries under one key before it rekeys.
pub const REKEY_RECORDS: u64 = 1 << 20;
/// Plaintext bytes a direction carries under one key before it rekeys.
pub const REKEY_BYTES: u64 = 1 << 30;

const S_TRANSCRIPT: &[u8] = b"Q21 channel transport v3 transcript";
const S_SIGNATURE: &[u8] = b"Q21 channel transport v3 signature";
const S_SESSION: &[u8] = b"Q21 channel transport v3 session";
const S_RECORD_KEYS: &[u8] = b"Q21 channel transport v3 record keys";
const S_REKEY: &[u8] = b"Q21 channel transport v3 rekey";
const S_STREAM: &[u8] = b"Q21 channel transport v3 record stream";
const S_TAG: &[u8] = b"Q21 channel transport v3 record tag";

const ROLE_INITIATOR: u8 = b'I';
const ROLE_RESPONDER: u8 = b'R';

// Transcript field labels.
const F_VERSION: u8 = 0;
const F_NETWORK: u8 = 1;
const F_NONCE_I: u8 = 2;
const F_NONCE_R: u8 = 3;
const F_EK_I: u8 = 4;
const F_PK_I: u8 = 5;
const F_LEGACY_I: u8 = 6;
const F_EK_R: u8 = 7;
const F_CT_R: u8 = 8;
const F_PK_R: u8 = 9;
const F_LEGACY_R: u8 = 10;
const F_SIG_R: u8 = 11;
const F_CT_I: u8 = 12;
const F_SIG_I: u8 = 13;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TransportError {
    /// A frame of the wrong length, version or type.
    Malformed,
    /// An ephemeral key that is not a valid ML-KEM-1024 encapsulation key.
    BadKey,
    /// A transcript signature that does not verify.
    BadSignature,
    /// The peer presented our own identity: a reflected handshake.
    Reflected,
    /// No randomness for an ephemeral key.
    NoRandomness,
    /// A plaintext over [`MAX_RECORD`].
    TooLarge,
    /// A record below the next sequence number: a replay.
    Replayed,
    /// A record above the next sequence number: one was lost.
    Gap,
    /// A record whose tag does not verify.
    BadTag,
    /// The sequence number reached its end; a new session is needed.
    Exhausted,
}

/// What both ends know of their connection before the handshake, and bind
/// into the transcript: the network, and each side's P2P `Version` nonce by
/// role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub network: Network,
    pub initiator_nonce: u64,
    pub responder_nonce: u64,
}

/// The authenticated counterparty of a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// Its identity public key, proven by its transcript signature.
    pub pubkey: Vec<u8>,
    /// [`node_id`] of that key: what channels are bound to.
    pub id: Hash256,
    /// The legacy node id it signed (see [`NodeIdentity::legacy_id`]).
    pub legacy_id: [u8; LEGACY_NODE_ID_LEN],
    /// The session's binding value (see the module documentation).
    pub binding: [u8; 32],
}

/// The running transcript hash.
#[derive(Clone)]
struct Transcript(CShake256);

impl Transcript {
    fn new(ctx: &Context) -> Transcript {
        let mut t = Transcript(CShake256::new(b"", S_TRANSCRIPT));
        t.field(F_VERSION, &[VERSION]);
        t.field(F_NETWORK, ctx.network.hrp().as_bytes());
        t.field(F_NONCE_I, &ctx.initiator_nonce.to_le_bytes());
        t.field(F_NONCE_R, &ctx.responder_nonce.to_le_bytes());
        t
    }

    fn field(&mut self, label: u8, bytes: &[u8]) {
        self.0.update(&[label]);
        self.0.update(&(bytes.len() as u32).to_le_bytes());
        self.0.update(bytes);
    }

    fn value(&self) -> [u8; 32] {
        self.0.clone().finalize32()
    }
}

/// What a role signs: the transcript so far, under the role's label.
fn signed_message(role: u8, transcript: &[u8; 32]) -> Hash256 {
    let mut h = CShake256::new(b"", S_SIGNATURE);
    h.update(&[role]);
    h.update(transcript);
    Hash256(h.finalize32())
}

fn verify(
    pubkey: &[u8],
    role: u8,
    transcript: &[u8; 32],
    sig: &[u8],
) -> Result<(), TransportError> {
    crate::sig::verify(
        CHANNEL_SCHEME,
        pubkey,
        &signed_message(role, transcript),
        sig,
    )
    .map_err(|_| TransportError::BadSignature)
}

/// A fresh ML-KEM-1024 key pair. The decapsulation key wipes itself when
/// dropped (the crate is built with `zeroize`); its seed is wiped here.
struct Ephemeral {
    dk: ml_kem::DecapsulationKey<MlKem1024>,
    ek: Vec<u8>,
}

fn ephemeral() -> Result<Ephemeral, TransportError> {
    let mut seed = crate::rng::bytes::<64>().map_err(|_| TransportError::NoRandomness)?;
    let mut s = ml_kem::Seed::from(seed);
    let dk = ml_kem::DecapsulationKey::<MlKem1024>::from_seed(s);
    crate::kdf::wipe(&mut seed);
    crate::kdf::wipe(&mut s);
    let ek = dk.encapsulation_key().to_bytes().to_vec();
    Ok(Ephemeral { dk, ek })
}

/// Encapsulates a fresh secret to the encapsulation key `ek`: the ciphertext,
/// with the shared secret written into `ss`, where its holder keeps it — not
/// returned by value, which would leave a copy on the stack.
fn encapsulate_into(ek: &[u8], ss: &mut [u8; 32]) -> Result<Vec<u8>, TransportError> {
    let key = ml_kem::Key::<ml_kem::EncapsulationKey<MlKem1024>>::try_from(ek)
        .map_err(|_| TransportError::BadKey)?;
    let ek =
        ml_kem::EncapsulationKey::<MlKem1024>::new(&key).map_err(|_| TransportError::BadKey)?;
    let mut m = crate::rng::bytes::<32>().map_err(|_| TransportError::NoRandomness)?;
    let mut mb = B32::from(m);
    let (ct, mut k) = ek.encapsulate_deterministic(&mb);
    crate::kdf::wipe(&mut m);
    crate::kdf::wipe(&mut mb);
    ss.copy_from_slice(&k);
    crate::kdf::wipe(&mut k);
    Ok(ct.to_vec())
}

/// [`encapsulate_into`] a local the caller wipes.
fn encapsulate(ek: &[u8]) -> Result<(Vec<u8>, [u8; 32]), TransportError> {
    let mut ss = [0u8; 32];
    let ct = encapsulate_into(ek, &mut ss)?;
    Ok((ct, ss))
}

fn decapsulate(dk: &ml_kem::DecapsulationKey<MlKem1024>, ct: &[u8]) -> [u8; 32] {
    // The length is checked by the frame parser; ML-KEM rejects implicitly:
    // a ciphertext that was tampered with gives an unrelated secret, and the
    // transcript signature already refused it.
    let mut k = dk.decapsulate_slice(ct).expect("ciphertext length checked");
    let mut ss = [0u8; 32];
    ss.copy_from_slice(&k);
    crate::kdf::wipe(&mut k);
    ss
}

/// The two traffic secrets and the binding, from both shared secrets and
/// the final transcript.
fn session_secrets(ss_r: &[u8; 32], ss_i: &[u8; 32], tf: &[u8; 32]) -> [[u8; 32]; 3] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ss_r);
    ikm[32..].copy_from_slice(ss_i);
    let mut okm = [0u8; 96];
    kmac256(&ikm, S_SESSION, &[tf], &mut okm);
    let mut out = [[0u8; 32]; 3];
    for (i, o) in out.iter_mut().enumerate() {
        o.copy_from_slice(&okm[32 * i..32 * (i + 1)]);
    }
    crate::kdf::wipe(&mut ikm);
    crate::kdf::wipe(&mut okm);
    out
}

/// Splits `frame` into fields of the given lengths after the version and the
/// expected type byte; the lengths must cover it exactly.
fn fields<const N: usize>(
    frame: &[u8],
    kind: u8,
    lens: [usize; N],
) -> Result<[&[u8]; N], TransportError> {
    if frame.len() != 2 + lens.iter().sum::<usize>() || frame[0] != VERSION || frame[1] != kind {
        return Err(TransportError::Malformed);
    }
    let mut out = [&frame[..0]; N];
    let mut at = 2;
    for (o, len) in out.iter_mut().zip(lens) {
        *o = &frame[at..at + len];
        at += len;
    }
    Ok(out)
}

fn legacy_of(bytes: &[u8]) -> [u8; LEGACY_NODE_ID_LEN] {
    let mut l = [0u8; LEGACY_NODE_ID_LEN];
    l.copy_from_slice(bytes);
    l
}

/// The initiator, between its `Init` and the responder's `Resp`.
pub struct Initiator {
    eph: Ephemeral,
    transcript: Transcript,
}

impl Initiator {
    /// Starts a handshake: the initiator's state and its `Init` frame.
    pub fn start(me: &NodeIdentity, ctx: Context) -> Result<(Initiator, Vec<u8>), TransportError> {
        let eph = ephemeral()?;
        let mut transcript = Transcript::new(&ctx);
        transcript.field(F_EK_I, &eph.ek);
        transcript.field(F_PK_I, me.pubkey());
        transcript.field(F_LEGACY_I, &me.legacy_id());
        let mut frame = Vec::with_capacity(INIT_LEN);
        frame.extend_from_slice(&[VERSION, T_INIT]);
        frame.extend_from_slice(&eph.ek);
        frame.extend_from_slice(me.pubkey());
        frame.extend_from_slice(&me.legacy_id());
        Ok((Initiator { eph, transcript }, frame))
    }

    /// Takes the responder's `Resp`: the session, the authenticated peer,
    /// and the `Fin` frame to send.
    pub fn finish(
        self,
        me: &NodeIdentity,
        resp: &[u8],
    ) -> Result<(Session, Peer, Vec<u8>), TransportError> {
        self.try_finish(me, resp)
    }

    /// [`Initiator::finish`], leaving the initiator as it was when `resp` is
    /// refused: a `Resp` to an earlier `Init` of the same connection, one that
    /// crossed a restart, does not cost the handshake under way.
    pub fn try_finish(
        &self,
        me: &NodeIdentity,
        resp: &[u8],
    ) -> Result<(Session, Peer, Vec<u8>), TransportError> {
        let [ek_r, ct_r, pk_r, legacy_r, sig_r] = fields(
            resp,
            T_RESP,
            [EK_LEN, CT_LEN, PK_LEN, LEGACY_NODE_ID_LEN, SIG_LEN],
        )?;
        if pk_r == me.pubkey() {
            return Err(TransportError::Reflected);
        }
        let mut transcript = self.transcript.clone();
        let t = &mut transcript;
        t.field(F_EK_R, ek_r);
        t.field(F_CT_R, ct_r);
        t.field(F_PK_R, pk_r);
        t.field(F_LEGACY_R, legacy_r);
        verify(pk_r, ROLE_RESPONDER, &t.value(), sig_r)?;
        let (ct_i, mut ss_i) = encapsulate(ek_r)?;
        let mut ss_r = decapsulate(&self.eph.dk, ct_r);
        t.field(F_SIG_R, sig_r);
        t.field(F_CT_I, &ct_i);
        let sig_i = me.sign(&signed_message(ROLE_INITIATOR, &t.value()));
        t.field(F_SIG_I, &sig_i);
        let mut secrets = session_secrets(&ss_r, &ss_i, &t.value());
        crate::kdf::wipe(&mut ss_r);
        crate::kdf::wipe(&mut ss_i);
        let session = Session::new(&secrets[0], &secrets[1], secrets[2]);
        let peer = Peer {
            pubkey: pk_r.to_vec(),
            id: node_id(pk_r),
            legacy_id: legacy_of(legacy_r),
            binding: secrets[2],
        };
        for s in secrets.iter_mut() {
            crate::kdf::wipe(s);
        }
        let mut fin = Vec::with_capacity(FIN_LEN);
        fin.extend_from_slice(&[VERSION, T_FIN]);
        fin.extend_from_slice(&ct_i);
        fin.extend_from_slice(&sig_i);
        Ok((session, peer, fin))
    }
}

/// The responder, between its `Resp` and the initiator's `Fin`. The secret
/// it encapsulated is wiped when it is dropped, used or not.
pub struct Responder {
    eph: Ephemeral,
    transcript: Transcript,
    /// On the heap from the start: moving the state moves only the pointer.
    ss_r: Box<[u8; 32]>,
    peer_pubkey: Vec<u8>,
    peer_legacy: [u8; LEGACY_NODE_ID_LEN],
}

impl Responder {
    fn wipe(&mut self) {
        crate::kdf::wipe(&mut self.ss_r[..]);
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl Responder {
    /// Answers an `Init`: the responder's state and its `Resp` frame. This
    /// signs before the initiator has proven anything, which is why the
    /// link layer rate-limits it.
    pub fn accept(
        me: &NodeIdentity,
        ctx: Context,
        init: &[u8],
    ) -> Result<(Responder, Vec<u8>), TransportError> {
        let [ek_i, pk_i, legacy_i] = fields(init, T_INIT, [EK_LEN, PK_LEN, LEGACY_NODE_ID_LEN])?;
        if pk_i == me.pubkey() {
            return Err(TransportError::Reflected);
        }
        let mut ss_r = Box::new([0u8; 32]);
        let ct_r = encapsulate_into(ek_i, &mut ss_r)?;
        let eph = ephemeral()?;
        let mut transcript = Transcript::new(&ctx);
        let t = &mut transcript;
        t.field(F_EK_I, ek_i);
        t.field(F_PK_I, pk_i);
        t.field(F_LEGACY_I, legacy_i);
        t.field(F_EK_R, &eph.ek);
        t.field(F_CT_R, &ct_r);
        t.field(F_PK_R, me.pubkey());
        t.field(F_LEGACY_R, &me.legacy_id());
        let sig_r = me.sign(&signed_message(ROLE_RESPONDER, &t.value()));
        t.field(F_SIG_R, &sig_r);
        let mut resp = Vec::with_capacity(RESP_LEN);
        resp.extend_from_slice(&[VERSION, T_RESP]);
        resp.extend_from_slice(&eph.ek);
        resp.extend_from_slice(&ct_r);
        resp.extend_from_slice(me.pubkey());
        resp.extend_from_slice(&me.legacy_id());
        resp.extend_from_slice(&sig_r);
        Ok((
            Responder {
                eph,
                transcript,
                ss_r,
                peer_pubkey: pk_i.to_vec(),
                peer_legacy: legacy_of(legacy_i),
            },
            resp,
        ))
    }

    /// Takes the initiator's `Fin`: the session and the authenticated peer.
    pub fn finish(mut self, fin: &[u8]) -> Result<(Session, Peer), TransportError> {
        let [ct_i, sig_i] = fields(fin, T_FIN, [CT_LEN, SIG_LEN])?;
        let t = &mut self.transcript;
        t.field(F_CT_I, ct_i);
        verify(&self.peer_pubkey, ROLE_INITIATOR, &t.value(), sig_i)?;
        let mut ss_i = decapsulate(&self.eph.dk, ct_i);
        t.field(F_SIG_I, sig_i);
        let tf = t.value();
        let mut secrets = session_secrets(&self.ss_r, &ss_i, &tf);
        crate::kdf::wipe(&mut ss_i);
        // Our receiving direction is the initiator's sending one.
        let session = Session::new(&secrets[1], &secrets[0], secrets[2]);
        let peer = Peer {
            id: node_id(&self.peer_pubkey),
            pubkey: std::mem::take(&mut self.peer_pubkey),
            legacy_id: self.peer_legacy,
            binding: secrets[2],
        };
        for s in secrets.iter_mut() {
            crate::kdf::wipe(s);
        }
        Ok((session, peer))
    }
}

/// When a direction rekeys: after this many records or plaintext bytes
/// under one key. Both ends must use the same limits, as they do in
/// production ([`REKEY_RECORDS`], [`REKEY_BYTES`]); tests shorten them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub records: u64,
    pub bytes: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            records: REKEY_RECORDS,
            bytes: REKEY_BYTES,
        }
    }
}

/// One direction of a session: its traffic secret, the record keys of the
/// current epoch, and its counters. Every key is wiped on drop and on rekey.
struct Direction {
    secret: [u8; 32],
    enc: [u8; 32],
    mac: [u8; 32],
    /// The next sequence number: never reset, rekeys included.
    seq: u64,
    epoch: u32,
    records: u64,
    bytes: u64,
}

impl Direction {
    fn new(secret: &[u8; 32]) -> Direction {
        let mut d = Direction {
            secret: *secret,
            enc: [0; 32],
            mac: [0; 32],
            seq: 0,
            epoch: 0,
            records: 0,
            bytes: 0,
        };
        d.load_keys();
        d
    }

    fn load_keys(&mut self) {
        let mut okm = [0u8; 64];
        kmac256(&self.secret, S_RECORD_KEYS, &[], &mut okm);
        self.enc.copy_from_slice(&okm[..32]);
        self.mac.copy_from_slice(&okm[32..]);
        crate::kdf::wipe(&mut okm);
    }

    /// Replaces the traffic secret by the next one, wiping it.
    fn rekey(&mut self) {
        let mut next = [0u8; 32];
        kmac256(&self.secret, S_REKEY, &[], &mut next);
        self.secret = next;
        crate::kdf::wipe(&mut next);
        self.load_keys();
        self.epoch += 1;
        self.records = 0;
        self.bytes = 0;
    }

    /// XORs the keystream for `seq` into `buf`.
    fn apply_stream(&self, seq: u64, buf: &mut [u8]) {
        let mut h = CShake256::new(b"", S_STREAM);
        h.absorb_key(&self.enc);
        h.update(&seq.to_be_bytes());
        let mut ks = vec![0u8; buf.len()];
        h.finalize_into(&mut ks);
        for (b, k) in buf.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
        crate::kdf::wipe(&mut ks);
    }

    fn tag(&self, authenticated: &[u8]) -> [u8; TAG_LEN] {
        let mut t = [0u8; TAG_LEN];
        kmac256(&self.mac, S_TAG, &[authenticated], &mut t);
        t
    }

    /// Counts one record of `len` bytes, rekeying at the limits.
    fn advance(&mut self, len: usize, limits: Limits) {
        self.seq += 1;
        self.records += 1;
        self.bytes = self.bytes.saturating_add(len as u64);
        if self.records >= limits.records || self.bytes >= limits.bytes {
            self.rekey();
        }
    }
}

impl Drop for Direction {
    fn drop(&mut self) {
        crate::kdf::wipe(&mut self.secret);
        crate::kdf::wipe(&mut self.enc);
        crate::kdf::wipe(&mut self.mac);
    }
}

/// An established session: seals what we send, opens what we receive.
pub struct Session {
    send: Direction,
    recv: Direction,
    limits: Limits,
    binding: [u8; 32],
}

impl Session {
    fn new(send: &[u8; 32], recv: &[u8; 32], binding: [u8; 32]) -> Session {
        Session {
            send: Direction::new(send),
            recv: Direction::new(recv),
            limits: Limits::default(),
            binding,
        }
    }

    /// The session's binding value.
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }

    /// Changes when the session rekeys; both ends must agree.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// `(send, receive)` epochs: how many times each direction rekeyed.
    pub fn epochs(&self) -> (u32, u32) {
        (self.send.epoch, self.recv.epoch)
    }

    /// Encrypts and authenticates one record.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        if plaintext.len() > MAX_RECORD {
            return Err(TransportError::TooLarge);
        }
        let seq = self.send.seq;
        if seq == u64::MAX {
            return Err(TransportError::Exhausted);
        }
        let mut out = Vec::with_capacity(RECORD_OVERHEAD + plaintext.len());
        out.extend_from_slice(&[VERSION, T_RECORD]);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(plaintext);
        self.send.apply_stream(seq, &mut out[RECORD_HEADER..]);
        let tag = self.send.tag(&out);
        out.extend_from_slice(&tag);
        self.send.advance(plaintext.len(), self.limits);
        Ok(out)
    }

    /// Authenticates and decrypts one record, which must be the next one.
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, TransportError> {
        if record.len() < RECORD_OVERHEAD
            || record.len() > RECORD_OVERHEAD + MAX_RECORD
            || record[0] != VERSION
            || record[1] != T_RECORD
        {
            return Err(TransportError::Malformed);
        }
        let seq = u64::from_be_bytes(record[2..RECORD_HEADER].try_into().expect("eight bytes"));
        if seq < self.recv.seq {
            return Err(TransportError::Replayed);
        }
        if seq > self.recv.seq {
            return Err(TransportError::Gap);
        }
        let body = record.len() - TAG_LEN;
        let want = self.recv.tag(&record[..body]);
        let mut diff = 0u8;
        for (a, b) in want.iter().zip(&record[body..]) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(TransportError::BadTag);
        }
        let mut plaintext = record[RECORD_HEADER..body].to_vec();
        self.recv.apply_stream(seq, &mut plaintext);
        self.recv.advance(plaintext.len(), self.limits);
        Ok(plaintext)
    }
}

/// The frame type of a transport frame, if it carries this version.
pub fn frame_type(frame: &[u8]) -> Option<u8> {
    match frame {
        [VERSION, t, ..] => Some(*t),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: Network = Network::Regtest;

    fn ctx() -> Context {
        Context {
            network: NET,
            initiator_nonce: 0x1111,
            responder_nonce: 0x2222,
        }
    }

    fn identity(b: u8) -> NodeIdentity {
        NodeIdentity::derive(&[b; 32])
    }

    /// A full handshake: (initiator session, responder session, what the
    /// initiator authenticated, what the responder authenticated).
    fn handshake(i: &NodeIdentity, r: &NodeIdentity) -> (Session, Session, Peer, Peer) {
        let (ini, init) = Initiator::start(i, ctx()).unwrap();
        let (resp_state, resp) = Responder::accept(r, ctx(), &init).unwrap();
        let (si, peer_r, fin) = ini.finish(i, &resp).unwrap();
        let (sr, peer_i) = resp_state.finish(&fin).unwrap();
        (si, sr, peer_r, peer_i)
    }

    #[test]
    fn a_handshake_authenticates_both_ends_and_agrees_on_keys() {
        let (a, b) = (identity(1), identity(2));
        let (mut sa, mut sb, peer_b, peer_a) = handshake(&a, &b);
        assert_eq!(peer_b.id, b.id());
        assert_eq!(peer_a.id, a.id());
        assert_eq!(peer_b.pubkey, b.pubkey());
        assert_eq!(peer_a.legacy_id, a.legacy_id());
        assert_eq!(peer_a.binding, peer_b.binding);
        assert_eq!(sa.binding(), sb.binding());
        for i in 0..5u8 {
            let r = sa.seal(&[i; 100]).unwrap();
            assert_eq!(sb.open(&r).unwrap(), vec![i; 100]);
            let r = sb.seal(&[i; 3]).unwrap();
            assert_eq!(sa.open(&r).unwrap(), vec![i; 3]);
        }
        // Empty and largest records.
        let r = sa.seal(&[]).unwrap();
        assert_eq!(sb.open(&r).unwrap(), Vec::<u8>::new());
        let big = vec![0x5a; MAX_RECORD];
        let r = sa.seal(&big).unwrap();
        assert!(r.len() <= crate::wire::MAX_CHANNEL_MSG);
        assert_eq!(sb.open(&r).unwrap(), big);
        assert_eq!(sa.seal(&[0; MAX_RECORD + 1]), Err(TransportError::TooLarge));
        // Two sessions between the same identities share no key.
        let (mut sa2, _, _, _) = handshake(&a, &b);
        assert_ne!(sa2.binding(), sa.binding());
        let r = sa2.seal(b"x").unwrap();
        assert!(sb.open(&r).is_err());
    }

    #[test]
    fn a_record_is_encrypted() {
        let (a, b) = (identity(1), identity(2));
        let (mut sa, _, _, _) = handshake(&a, &b);
        let secret = b"revocation secret of state 41, never in clear".to_vec();
        let r = sa.seal(&secret).unwrap();
        assert!(!r.windows(16).any(|w| secret.windows(16).any(|s| s == w)));
    }

    #[test]
    fn a_tampered_record_is_refused() {
        let (a, b) = (identity(1), identity(2));
        let (mut sa, mut sb, _, _) = handshake(&a, &b);
        let r = sa.seal(b"pay 1000").unwrap();
        // Every byte of the ciphertext and the tag is covered.
        for at in [
            RECORD_HEADER,
            RECORD_HEADER + 4,
            r.len() - TAG_LEN,
            r.len() - 1,
        ] {
            let mut t = r.clone();
            t[at] ^= 0x01;
            assert_eq!(sb.open(&t), Err(TransportError::BadTag), "byte {at}");
        }
        let mut t = r.clone();
        t[1] = T_FIN;
        assert_eq!(sb.open(&t), Err(TransportError::Malformed));
        assert_eq!(sb.open(&r[..r.len() - 1]), Err(TransportError::BadTag));
        // Refusals consumed nothing: the genuine record still opens.
        assert_eq!(sb.open(&r).unwrap(), b"pay 1000");
    }

    #[test]
    fn a_replayed_or_reordered_record_is_refused() {
        let (a, b) = (identity(1), identity(2));
        let (mut sa, mut sb, _, _) = handshake(&a, &b);
        let r0 = sa.seal(b"zero").unwrap();
        let r1 = sa.seal(b"one").unwrap();
        let r2 = sa.seal(b"two").unwrap();
        // Out of order: the later record waits for none, it is refused.
        assert_eq!(sb.open(&r1), Err(TransportError::Gap));
        assert_eq!(sb.open(&r0).unwrap(), b"zero");
        assert_eq!(sb.open(&r1).unwrap(), b"one");
        // Replayed, whether just now or long before.
        assert_eq!(sb.open(&r1), Err(TransportError::Replayed));
        assert_eq!(sb.open(&r0), Err(TransportError::Replayed));
        // A record whose sequence number was rewritten to the expected one
        // is still refused: the tag covers it.
        let mut moved = r0.clone();
        moved[2..RECORD_HEADER].copy_from_slice(&2u64.to_be_bytes());
        assert_eq!(sb.open(&moved), Err(TransportError::BadTag));
        assert_eq!(sb.open(&r2).unwrap(), b"two");
    }

    #[test]
    fn a_handshake_with_a_bad_signature_fails() {
        let (a, b) = (identity(1), identity(2));
        let (ini, init) = Initiator::start(&a, ctx()).unwrap();
        let (_, mut resp) = Responder::accept(&b, ctx(), &init).unwrap();
        let last = resp.len() - 10;
        resp[last] ^= 1;
        assert_eq!(
            ini.finish(&a, &resp).err(),
            Some(TransportError::BadSignature)
        );

        let (ini, init) = Initiator::start(&a, ctx()).unwrap();
        let (r, resp) = Responder::accept(&b, ctx(), &init).unwrap();
        let (_, _, mut fin) = ini.finish(&a, &resp).unwrap();
        let last = fin.len() - 10;
        fin[last] ^= 1;
        assert_eq!(r.finish(&fin).err(), Some(TransportError::BadSignature));
    }

    #[test]
    fn malformed_handshake_frames_and_bad_keys_are_refused() {
        let (a, b) = (identity(1), identity(2));
        let (ini, init) = Initiator::start(&a, ctx()).unwrap();
        assert_eq!(
            Responder::accept(&b, ctx(), &init[..init.len() - 1]).err(),
            Some(TransportError::Malformed)
        );
        let mut v2 = init.clone();
        v2[0] = 2;
        assert_eq!(
            Responder::accept(&b, ctx(), &v2).err(),
            Some(TransportError::Malformed)
        );
        // An encapsulation key whose coefficients exceed the modulus.
        let mut bad = init.clone();
        bad[2..2 + EK_LEN].fill(0xff);
        assert_eq!(
            Responder::accept(&b, ctx(), &bad).err(),
            Some(TransportError::BadKey)
        );
        // Our own Init reflected back to us.
        assert_eq!(
            Responder::accept(&a, ctx(), &init).err(),
            Some(TransportError::Reflected)
        );
        let (_, resp) = Responder::accept(&b, ctx(), &init).unwrap();
        assert_eq!(
            ini.finish(&a, &resp[..100]).err(),
            Some(TransportError::Malformed)
        );
    }

    /// The P2P nonces and the network are bound: a handshake whose two ends
    /// saw different connections does not complete.
    #[test]
    fn the_connection_context_is_bound() {
        let (a, b) = (identity(1), identity(2));
        for other in [
            Context {
                initiator_nonce: 0x9999,
                ..ctx()
            },
            Context {
                responder_nonce: 0x9999,
                ..ctx()
            },
            Context {
                network: Network::Testnet,
                ..ctx()
            },
        ] {
            let (ini, init) = Initiator::start(&a, ctx()).unwrap();
            let (_, resp) = Responder::accept(&b, other, &init).unwrap();
            assert_eq!(
                ini.finish(&a, &resp).err(),
                Some(TransportError::BadSignature)
            );
        }
    }

    /// A party that holds another identity key cannot pass for `b`: claiming
    /// `b`'s public key, its signature does not verify; using its own, it is
    /// authenticated as itself, whatever legacy id it claims.
    #[test]
    fn a_wrong_identity_is_never_authenticated_as_the_right_one() {
        let (a, b, mallory) = (identity(1), identity(2), identity(3));
        let (ini, init) = Initiator::start(&a, ctx()).unwrap();
        let (_, mut resp) = Responder::accept(&mallory, ctx(), &init).unwrap();
        let pk_at = 2 + EK_LEN + CT_LEN;
        resp[pk_at..pk_at + PK_LEN].copy_from_slice(b.pubkey());
        let legacy_at = pk_at + PK_LEN;
        resp[legacy_at..legacy_at + LEGACY_NODE_ID_LEN].copy_from_slice(&b.legacy_id());
        assert_eq!(
            ini.finish(&a, &resp).err(),
            Some(TransportError::BadSignature)
        );

        let (_, _, peer, _) = handshake(&a, &mallory);
        assert_eq!(peer.id, mallory.id());
        assert_ne!(peer.id, b.id());
    }

    /// The relay R sits between A (initiator) and B (responder) and sees
    /// every frame.
    #[test]
    fn a_relay_can_neither_complete_the_handshake_nor_read_or_forge_records() {
        let (a, b, r) = (identity(1), identity(2), identity(3));

        // 1. It substitutes its own ephemeral key for A's, to decapsulate
        //    what B encapsulates: A refuses B's signature over that key.
        let (ini, init) = Initiator::start(&a, ctx()).unwrap();
        let mine = ephemeral().unwrap();
        let mut forged = init.clone();
        forged[2..2 + EK_LEN].copy_from_slice(&mine.ek);
        let (_, resp) = Responder::accept(&b, ctx(), &forged).unwrap();
        assert_eq!(
            ini.finish(&a, &resp).err(),
            Some(TransportError::BadSignature)
        );

        // 2. It substitutes B's ephemeral key and ciphertext in the Resp.
        let (ini, init) = Initiator::start(&a, ctx()).unwrap();
        let (_, resp) = Responder::accept(&b, ctx(), &init).unwrap();
        let mut forged = resp.clone();
        forged[2..2 + EK_LEN].copy_from_slice(&mine.ek);
        let (ct, _) = encapsulate(&init[2..2 + EK_LEN]).unwrap();
        forged[2 + EK_LEN..2 + EK_LEN + CT_LEN].copy_from_slice(&ct);
        assert_eq!(
            ini.finish(&a, &forged).err(),
            Some(TransportError::BadSignature)
        );

        // 3. It substitutes A's ciphertext in the Fin.
        let (ini, init) = Initiator::start(&a, ctx()).unwrap();
        let (rs, resp) = Responder::accept(&b, ctx(), &init).unwrap();
        let (_, _, fin) = ini.finish(&a, &resp).unwrap();
        let mut forged = fin.clone();
        let (ct, _) = encapsulate(&mine.ek).unwrap();
        forged[2..2 + CT_LEN].copy_from_slice(&ct);
        assert_eq!(rs.finish(&forged).err(), Some(TransportError::BadSignature));

        // 4. It forwards every frame unchanged, but over connections of its
        //    own, with its own P2P nonces: the transcripts differ.
        let ctx_ar = ctx();
        let ctx_rb = Context {
            initiator_nonce: 0x3333,
            ..ctx()
        };
        let (ini, init) = Initiator::start(&a, ctx_ar).unwrap();
        let (_, resp) = Responder::accept(&b, ctx_rb, &init).unwrap();
        assert_eq!(
            ini.finish(&a, &resp).err(),
            Some(TransportError::BadSignature)
        );

        // 5. It forwards unchanged and copies the nonces, so the handshake
        //    completes end to end: it is a pipe that holds no key. It can
        //    read nothing, and nothing it injects or reuses is taken.
        let (ini, init) = Initiator::start(&a, ctx()).unwrap();
        let (rs, resp) = Responder::accept(&b, ctx(), &init).unwrap();
        let (mut sa, peer_b, fin) = ini.finish(&a, &resp).unwrap();
        let (mut sb, peer_a) = rs.finish(&fin).unwrap();
        assert_eq!((peer_b.id, peer_a.id), (b.id(), a.id()));
        let record = sa.seal(b"Close fee=20000").unwrap();
        assert!(!record.windows(5).any(|w| w == b"Close"));
        //    Its own session with B, under its own identity, seals records B
        //    opens only in that session, never in A's.
        let (mut s_rb, _, _, _) = handshake(&r, &b);
        let injected = s_rb.seal(b"Close fee=0").unwrap();
        assert_eq!(sb.open(&injected), Err(TransportError::BadTag));
        assert_eq!(sb.open(&record).unwrap(), b"Close fee=20000");

        // 6. It runs a full handshake with each side, as itself: each side
        //    authenticates R, never its real counterparty.
        let (_, _, seen_by_a, _) = handshake(&a, &r);
        let (_, _, _, seen_by_b) = handshake(&r, &b);
        assert_eq!(seen_by_a.id, r.id());
        assert_eq!(seen_by_b.id, r.id());
    }

    #[test]
    fn a_session_rekeys_by_records_and_by_bytes() {
        let (a, b) = (identity(1), identity(2));
        let (mut sa, mut sb, _, _) = handshake(&a, &b);
        let limits = Limits {
            records: 3,
            bytes: 1000,
        };
        sa.set_limits(limits);
        sb.set_limits(limits);
        // Records: 3 per epoch.
        for i in 0..10u8 {
            let r = sa.seal(&[i; 10]).unwrap();
            assert_eq!(sb.open(&r).unwrap(), vec![i; 10]);
        }
        assert_eq!(sa.epochs().0, 3);
        assert_eq!(sb.epochs().1, 3);
        // Bytes: two records of 600 cross the 1000-byte limit.
        for _ in 0..2 {
            let r = sb.seal(&[7; 600]).unwrap();
            assert_eq!(sa.open(&r).unwrap(), vec![7; 600]);
        }
        assert_eq!(sb.epochs().0, 1);
        assert_eq!(sa.epochs().1, 1);
    }

    /// After a rekey the keys change: a record sealed at the same sequence
    /// number under the old keys is refused. Without the rekey both ends
    /// would still accept it.
    #[test]
    fn a_rekey_changes_the_keys() {
        let (a, b) = (identity(1), identity(2));
        let (mut sa, mut sb, _, _) = handshake(&a, &b);
        let limits = Limits {
            records: 2,
            bytes: u64::MAX,
        };
        sa.set_limits(limits);
        sb.set_limits(limits);
        // A copy of A's sending direction that never rekeys.
        let mut stale = Session::new(&sa.send.secret, &[0; 32], [0; 32]);
        stale.set_limits(Limits {
            records: u64::MAX,
            bytes: u64::MAX,
        });
        for _ in 0..2 {
            let r = sa.seal(b"x").unwrap();
            assert_eq!(stale.seal(b"x").unwrap(), r);
            sb.open(&r).unwrap();
        }
        let old_keys = stale.seal(b"y").unwrap();
        assert_eq!(sb.open(&old_keys), Err(TransportError::BadTag));
        assert_eq!(sb.open(&sa.seal(b"y").unwrap()).unwrap(), b"y");
    }

    #[test]
    fn session_keys_are_wiped_on_drop_and_on_rekey() {
        let (a, b) = (identity(1), identity(2));
        let (sa, _, _, _) = handshake(&a, &b);
        let mut slot = std::mem::ManuallyDrop::new(sa);
        let before = slot.send.secret;
        slot.send.rekey();
        assert_ne!(slot.send.secret, before);
        let ptrs: Vec<*const [u8; 32]> = vec![
            &slot.send.secret,
            &slot.send.enc,
            &slot.send.mac,
            &slot.recv.secret,
            &slot.recv.enc,
            &slot.recv.mac,
        ];
        assert!(ptrs.iter().all(|p| unsafe { **p } != [0; 32]));
        unsafe { std::mem::ManuallyDrop::drop(&mut slot) };
        for p in ptrs {
            assert_eq!(unsafe { std::ptr::read_volatile(p) }, [0; 32]);
        }

        // A responder's encapsulated secret, when the handshake is dropped
        // before its Fin: wiped by its drop.
        let (_, init) = Initiator::start(&a, ctx()).unwrap();
        let (mut r, _) = Responder::accept(&b, ctx(), &init).unwrap();
        assert_ne!(*r.ss_r, [0; 32]);
        r.wipe();
        assert_eq!(*r.ss_r, [0; 32]);
    }

    /// The responder's secret is written once, where it stays: moving the
    /// state, as returning it and storing it per connection do, leaves no
    /// copy of it behind.
    #[test]
    fn the_responder_secret_never_moves() {
        let (a, b) = (identity(1), identity(2));
        let (_, init) = Initiator::start(&a, ctx()).unwrap();
        let (r, _) = Responder::accept(&b, ctx(), &init).unwrap();
        let at: *const [u8; 32] = &*r.ss_r;
        let stored = Box::new(r);
        assert_eq!(&*stored.ss_r as *const [u8; 32], at);
    }
}
