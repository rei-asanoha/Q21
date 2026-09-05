//! Protocole de fil : cadrage et messages.
//!
//! Format d'une trame, inspire de Bitcoin parce qu'il a vingt ans de service et
//! qu'aucune de ses proprietes n'a mal vieilli :
//!
//! ```text
//! [ magie 4 o ][ commande 12 o ][ longueur 4 o ][ somme 4 o ][ charge utile ]
//! ```
//!
//! La magie separe les reseaux : un message de testnet ne peut pas etre lu par
//! erreur sur le reseau principal. La somme de controle detecte la corruption de
//! transport ; elle ne protege de rien d'autre, et ne pretend pas le faire.
//!
//! # Toute donnee arrivant ici est hostile jusqu'a preuve du contraire
//!
//! Ce fichier est la premiere chose que touche un octet venu d'un inconnu. Deux
//! regles en decoulent, appliquees sans exception :
//!
//! - **aucune allocation avant controle.** Un pair annoncant quatre milliards
//!   d'elements ne doit pas faire reserver quatre milliards d'emplacements. Toute
//!   longueur est bornee avant d'etre utilisee ;
//! - **aucune panique.** Une trame malformee rend une erreur, jamais un panic.
//!   Un noeud qu'on arrete a distance avec dix octets n'est pas un noeud.

use crate::block::{Block, BlockHeader};
use crate::compact::{CompactBlock, CompactError};
use crate::hash::Hash256;
use crate::ser::{ReadError, Reader, Writer};
use crate::sha256::sha256;
use crate::tx::Transaction;

/// Version du protocole, annoncee a la poignee de main.
///
/// 1 : lancement. 2 : revue de septembre 2026 — nouvelle preuve de travail,
/// condensat signe engageant le reseau et la sortie depensee, feuille de
/// Merkle engageant le temoin, poussiere refusee, oncles retires.
pub const PROTOCOL_VERSION: u32 = 2;

/// Version minimale acceptee d'un pair.
///
/// Un pair plus ancien valide d'autres regles : chaque bloc qu'il enverrait
/// serait refuse, chaque bloc qu'on lui enverrait le serait aussi, et les
/// deux se puniraient mutuellement. On coupe a la poignee de main, sans
/// penalite : ce n'est pas une faute, c'est une autre epoque.
pub const MIN_PROTOCOL_VERSION: u32 = 2;

/// Taille maximale d'une charge utile, en octets.
///
/// Doit rester au-dessus de la taille maximale d'un bloc, sinon un bloc licite
/// serait injustement refuse.
pub const MAX_PAYLOAD: usize = 8 * 1024 * 1024;

/// Bornes de securite a la lecture. Chacune evite une allocation dictee par un
/// inconnu.
pub const MAX_INV: usize = 50_000;
pub const MAX_HEADERS: usize = 2_000;
pub const MAX_LOCATOR: usize = 64;
pub const MAX_ADDR: usize = 1_000;
pub const MAX_BLOCK_TXN: usize = 100_000;
pub const MAX_USER_AGENT: usize = 64;

/// Taille de l'en-tete de trame.
pub const HEADER_LEN: usize = 4 + 12 + 4 + 4;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WireError {
    MagieInconnue([u8; 4]),
    CommandeInvalide,
    CommandeInconnue(String),
    ChargeTropGrande(usize),
    SommeIncorrecte,
    TropDElements {
        max: usize,
        recu: usize,
    },
    Lecture(ReadError),
    ContenuInvalide(&'static str),
    /// Trame incomplete : il faut lire davantage d'octets.
    Incomplet,
}

impl From<ReadError> for WireError {
    fn from(e: ReadError) -> Self {
        WireError::Lecture(e)
    }
}

impl From<CompactError> for WireError {
    fn from(_: CompactError) -> Self {
        WireError::ContenuInvalide("bloc compact")
    }
}

/// Type d'objet annonce dans un inventaire.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[repr(u8)]
pub enum InvKind {
    Tx = 1,
    Block = 2,
    /// Annonce qu'un bloc est disponible en relais compact.
    CompactBlock = 3,
}

impl InvKind {
    pub fn from_u8(v: u8) -> Option<InvKind> {
        match v {
            1 => Some(InvKind::Tx),
            2 => Some(InvKind::Block),
            3 => Some(InvKind::CompactBlock),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct InvItem {
    pub kind: InvKind,
    pub hash: Hash256,
}

/// Adresse d'un pair, telle qu'elle circule sur le reseau.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct NetAddr {
    pub ip: [u8; 4],
    pub port: u16,
    /// Horodatage de derniere activite connue, pour vieillir les adresses.
    pub last_seen: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Message {
    Version {
        version: u32,
        timestamp: u64,
        /// Identifiant aleatoire, qui sert a detecter une connexion a soi-meme.
        nonce: u64,
        user_agent: String,
        start_height: u64,
    },
    VerAck,
    Ping(u64),
    Pong(u64),
    /// Demande d'en-tetes a partir d'un localisateur de blocs.
    GetHeaders {
        locator: Vec<Hash256>,
        stop: Hash256,
    },
    Headers(Vec<BlockHeader>),
    Inv(Vec<InvItem>),
    GetData(Vec<InvItem>),
    Block(Box<Block>),
    Tx(Box<Transaction>),
    CmpctBlock(Box<CompactBlock>),
    GetBlockTxn {
        block: Hash256,
        indices: Vec<u32>,
    },
    BlockTxn {
        block: Hash256,
        txs: Vec<Transaction>,
    },
    GetAddr,
    Addr(Vec<NetAddr>),
    /// Refus motive, pour que l'autre bout sache pourquoi.
    Reject {
        commande: String,
        raison: String,
    },
    /// Demande a un pair de decrire l'amorce de synchronisation rapide qu'il peut
    /// servir.
    GetAmorce,
    /// Metadonnees de l'amorce : de quoi savoir quoi demander et a quoi
    /// s'attendre, avant d'en recevoir le moindre morceau.
    AmorceInfo {
        hauteur: u64,
        tete: Hash256,
        empreinte: Hash256,
        taille: u64,
        tranches: u32,
    },
    /// Demande la tranche numero `index` de l'amorce serialisee.
    GetAmorceTranche {
        index: u32,
    },
    /// Une tranche de l'amorce serialisee, a reassembler dans l'ordre.
    AmorceTranche {
        index: u32,
        donnees: Vec<u8>,
    },
}

impl Message {
    pub fn command(&self) -> &'static str {
        match self {
            Message::Version { .. } => "version",
            Message::VerAck => "verack",
            Message::Ping(_) => "ping",
            Message::Pong(_) => "pong",
            Message::GetHeaders { .. } => "getheaders",
            Message::Headers(_) => "headers",
            Message::Inv(_) => "inv",
            Message::GetData(_) => "getdata",
            Message::Block(_) => "block",
            Message::Tx(_) => "tx",
            Message::CmpctBlock(_) => "cmpctblock",
            Message::GetBlockTxn { .. } => "getblocktxn",
            Message::BlockTxn { .. } => "blocktxn",
            Message::GetAddr => "getaddr",
            Message::Addr(_) => "addr",
            Message::Reject { .. } => "reject",
            Message::GetAmorce => "getamorce",
            Message::AmorceInfo { .. } => "amorceinfo",
            Message::GetAmorceTranche { .. } => "getamotrn",
            Message::AmorceTranche { .. } => "amotranche",
        }
    }

    fn encode_payload(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Message::Version {
                version,
                timestamp,
                nonce,
                user_agent,
                start_height,
            } => {
                w.u32(*version);
                w.u64(*timestamp);
                w.u64(*nonce);
                w.var_bytes(user_agent.as_bytes());
                w.u64(*start_height);
            }
            Message::VerAck | Message::GetAddr => {}
            Message::Ping(n) | Message::Pong(n) => {
                w.u64(*n);
            }
            Message::GetHeaders { locator, stop } => {
                w.varint(locator.len() as u64);
                for h in locator {
                    w.bytes(h.as_bytes());
                }
                w.bytes(stop.as_bytes());
            }
            Message::Headers(v) => {
                w.varint(v.len() as u64);
                for h in v {
                    w.bytes(&h.encode());
                }
            }
            Message::Inv(v) | Message::GetData(v) => {
                w.varint(v.len() as u64);
                for i in v {
                    w.u8(i.kind as u8);
                    w.bytes(i.hash.as_bytes());
                }
            }
            Message::Block(b) => {
                w.bytes(&b.encode());
            }
            Message::Tx(t) => {
                w.bytes(&t.encode());
            }
            Message::CmpctBlock(c) => {
                w.bytes(&c.encode());
            }
            Message::GetBlockTxn { block, indices } => {
                w.bytes(block.as_bytes());
                w.varint(indices.len() as u64);
                for i in indices {
                    w.varint(*i as u64);
                }
            }
            Message::BlockTxn { block, txs } => {
                w.bytes(block.as_bytes());
                w.varint(txs.len() as u64);
                for t in txs {
                    w.var_bytes(&t.encode());
                }
            }
            Message::Addr(v) => {
                w.varint(v.len() as u64);
                for a in v {
                    w.bytes(&a.ip);
                    w.u32(a.port as u32);
                    w.u64(a.last_seen);
                }
            }
            Message::Reject { commande, raison } => {
                w.var_bytes(commande.as_bytes());
                w.var_bytes(raison.as_bytes());
            }
            Message::GetAmorce => {}
            Message::AmorceInfo {
                hauteur,
                tete,
                empreinte,
                taille,
                tranches,
            } => {
                w.u64(*hauteur);
                w.bytes(tete.as_bytes());
                w.bytes(empreinte.as_bytes());
                w.u64(*taille);
                w.u32(*tranches);
            }
            Message::GetAmorceTranche { index } => {
                w.u32(*index);
            }
            Message::AmorceTranche { index, donnees } => {
                w.u32(*index);
                w.var_bytes(donnees);
            }
        }
        w.finish()
    }

    fn decode_payload(commande: &str, data: &[u8]) -> Result<Message, WireError> {
        let mut r = Reader::new(data);

        /// Lit une longueur en la bornant avant toute allocation.
        ///
        /// # Le defaut que `minimum` repare
        ///
        /// Borner par le maximum du protocole ne suffisait pas. Une trame de
        /// vingt-sept octets annoncant cinquante mille inventaires passait le
        /// controle — cinquante mille est la borne — et faisait reserver un
        /// million six cent cinquante mille octets, avant d'echouer sur une fin
        /// prematuree. Soit **soixante et un mille fois** ce qui avait ete
        /// recu, pour le prix d'un `send()`.
        ///
        /// Le rapport a ete mesure, pas suppose : voir `rapport_allocation_par_message`
        /// dans `tests/audit_arith.rs`, qui l'imprime message par message.
        ///
        /// La regle qui ferme cela tient en une phrase : **on ne reserve jamais
        /// de place pour plus d'elements que le reste de la trame ne peut en
        /// contenir.** Chaque element ayant une taille minimale connue, la
        /// comparaison est exacte et ne coute rien.
        ///
        /// `minimum` est le nombre d'octets qu'un element ne peut pas ne pas
        /// occuper. Zero signifie « inconnu » et desactive le controle — a
        /// n'employer que si aucune borne inferieure n'existe.
        fn borne_avec(r: &mut Reader<'_>, max: usize, minimum: usize) -> Result<usize, WireError> {
            let n = r.varint()? as usize;
            if n > max {
                return Err(WireError::TropDElements { max, recu: n });
            }
            if let Some(tenable) = r.remaining().checked_div(minimum) {
                if n > tenable {
                    return Err(WireError::TropDElements {
                        max: tenable,
                        recu: n,
                    });
                }
            }
            Ok(n)
        }

        let m = match commande {
            "version" => {
                let version = r.u32()?;
                let timestamp = r.u64()?;
                let nonce = r.u64()?;
                let ua = r.var_bytes()?;
                if ua.len() > MAX_USER_AGENT {
                    return Err(WireError::TropDElements {
                        max: MAX_USER_AGENT,
                        recu: ua.len(),
                    });
                }
                let user_agent = String::from_utf8_lossy(ua).into_owned();
                let start_height = r.u64()?;
                r.expect_end()?;
                Message::Version {
                    version,
                    timestamp,
                    nonce,
                    user_agent,
                    start_height,
                }
            }
            "verack" => {
                r.expect_end()?;
                Message::VerAck
            }
            "getaddr" => {
                r.expect_end()?;
                Message::GetAddr
            }
            "ping" => {
                let n = r.u64()?;
                r.expect_end()?;
                Message::Ping(n)
            }
            "pong" => {
                let n = r.u64()?;
                r.expect_end()?;
                Message::Pong(n)
            }
            "getheaders" => {
                let n = borne_avec(&mut r, MAX_LOCATOR, 32)?;
                let mut locator = Vec::with_capacity(n);
                for _ in 0..n {
                    locator.push(Hash256(r.array32()?));
                }
                let stop = Hash256(r.array32()?);
                r.expect_end()?;
                Message::GetHeaders { locator, stop }
            }
            "headers" => {
                let n = borne_avec(&mut r, MAX_HEADERS, BlockHeader::SIZE)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let mut buf = [0u8; BlockHeader::SIZE];
                    for o in buf.iter_mut() {
                        *o = r.u8()?;
                    }
                    v.push(BlockHeader::decode(&buf)?);
                }
                r.expect_end()?;
                Message::Headers(v)
            }
            "inv" | "getdata" => {
                let n = borne_avec(&mut r, MAX_INV, 33)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let brut = r.u8()?;
                    let kind = InvKind::from_u8(brut)
                        .ok_or(WireError::ContenuInvalide("type d'inventaire"))?;
                    v.push(InvItem {
                        kind,
                        hash: Hash256(r.array32()?),
                    });
                }
                r.expect_end()?;
                if commande == "inv" {
                    Message::Inv(v)
                } else {
                    Message::GetData(v)
                }
            }
            "block" => Message::Block(Box::new(
                Block::decode(data).map_err(|_| WireError::ContenuInvalide("bloc"))?,
            )),
            "tx" => Message::Tx(Box::new(
                Transaction::decode(data).map_err(|_| WireError::ContenuInvalide("transaction"))?,
            )),
            "cmpctblock" => Message::CmpctBlock(Box::new(CompactBlock::decode(data)?)),
            "getblocktxn" => {
                let block = Hash256(r.array32()?);
                let n = borne_avec(&mut r, MAX_BLOCK_TXN, 1)?;
                let mut indices = Vec::with_capacity(n);
                for _ in 0..n {
                    // Meme regle que pour le port : un indice qui ne tient pas
                    // sur trente-deux bits n'est pas ramene a zero en silence.
                    // Le ramener a zero ferait servir la transaction 0 a qui
                    // demande la 2^32-ieme — une reponse fausse, pas seulement
                    // un encodage redondant.
                    let brut = r.varint()?;
                    if brut > u32::MAX as u64 {
                        return Err(WireError::ContenuInvalide(
                            "indice hors des trente-deux bits : encodage non canonique",
                        ));
                    }
                    indices.push(brut as u32);
                }
                r.expect_end()?;
                Message::GetBlockTxn { block, indices }
            }
            "blocktxn" => {
                let block = Hash256(r.array32()?);
                let n = borne_avec(&mut r, MAX_BLOCK_TXN, 1)?;
                let mut txs = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    let brut = r.var_bytes()?;
                    txs.push(
                        Transaction::decode(brut)
                            .map_err(|_| WireError::ContenuInvalide("transaction"))?,
                    );
                }
                r.expect_end()?;
                Message::BlockTxn { block, txs }
            }
            "addr" => {
                let n = borne_avec(&mut r, MAX_ADDR, 16)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let mut ip = [0u8; 4];
                    for o in ip.iter_mut() {
                        *o = r.u8()?;
                    }
                    // --- Un decodeur refuse ce qu'il ne sait pas representer.
                    //
                    // Le port etait ecrit sur trente-deux bits et relu tronque
                    // a seize : soixante-cinq mille cinq cent trente-six
                    // trames distinctes decodaient vers la meme adresse. Rien
                    // n'y volait de fonds — aucune signature ne couvre les
                    // messages P2P — mais un decodeur qui tronque en silence
                    // est un decodeur qui ment sur ce qu'il a lu, et deux
                    // octets differents devenaient indistinguables.
                    let port_brut = r.u32()?;
                    if port_brut > u16::MAX as u32 {
                        return Err(WireError::ContenuInvalide(
                            "port hors des seize bits : encodage non canonique",
                        ));
                    }
                    let port = port_brut as u16;
                    let last_seen = r.u64()?;
                    v.push(NetAddr {
                        ip,
                        port,
                        last_seen,
                    });
                }
                r.expect_end()?;
                Message::Addr(v)
            }
            "reject" => {
                let c = r.var_bytes()?;
                let raison = r.var_bytes()?;
                if c.len() > 64 || raison.len() > 256 {
                    return Err(WireError::ContenuInvalide("refus trop verbeux"));
                }
                r.expect_end()?;
                Message::Reject {
                    commande: String::from_utf8_lossy(c).into_owned(),
                    raison: String::from_utf8_lossy(raison).into_owned(),
                }
            }
            "getamorce" => {
                r.expect_end()?;
                Message::GetAmorce
            }
            "amorceinfo" => {
                let hauteur = r.u64()?;
                let tete = Hash256(r.array32()?);
                let empreinte = Hash256(r.array32()?);
                let taille = r.u64()?;
                let tranches = r.u32()?;
                r.expect_end()?;
                Message::AmorceInfo {
                    hauteur,
                    tete,
                    empreinte,
                    taille,
                    tranches,
                }
            }
            "getamotrn" => {
                let index = r.u32()?;
                r.expect_end()?;
                Message::GetAmorceTranche { index }
            }
            "amotranche" => {
                let index = r.u32()?;
                // La tranche est bornee par la trame elle-meme : la charge ne
                // depasse jamais MAX_PAYLOAD, controle avant meme d'arriver ici.
                let donnees = r.var_bytes()?.to_vec();
                r.expect_end()?;
                Message::AmorceTranche { index, donnees }
            }
            autre => return Err(WireError::CommandeInconnue(autre.to_string())),
        };
        Ok(m)
    }

    /// Serialise le message en une trame complete.
    pub fn frame(&self, magie: [u8; 4]) -> Vec<u8> {
        let charge = self.encode_payload();
        let somme = sha256(&charge);

        let mut cmd = [0u8; 12];
        let nom = self.command().as_bytes();
        cmd[..nom.len()].copy_from_slice(nom);

        let mut out = Vec::with_capacity(HEADER_LEN + charge.len());
        out.extend_from_slice(&magie);
        out.extend_from_slice(&cmd);
        out.extend_from_slice(&(charge.len() as u32).to_le_bytes());
        out.extend_from_slice(&somme[..4]);
        out.extend_from_slice(&charge);
        out
    }

    /// Tente de lire une trame depuis un tampon.
    ///
    /// Rend le message et le nombre d'octets consommes, ou [`WireError::Incomplet`]
    /// si le tampon ne contient pas encore la trame entiere.
    pub fn parse(tampon: &[u8], magie: [u8; 4]) -> Result<(Message, usize), WireError> {
        if tampon.len() < HEADER_LEN {
            return Err(WireError::Incomplet);
        }
        let mut m = [0u8; 4];
        m.copy_from_slice(&tampon[..4]);
        if m != magie {
            return Err(WireError::MagieInconnue(m));
        }

        let cmd_brut = &tampon[4..16];
        let fin = cmd_brut.iter().position(|c| *c == 0).unwrap_or(12);
        let commande = core::str::from_utf8(&cmd_brut[..fin])
            .map_err(|_| WireError::CommandeInvalide)?
            .to_string();
        // Le rembourrage doit etre nul : sinon deux encodages designeraient la
        // meme commande.
        if cmd_brut[fin..].iter().any(|c| *c != 0) {
            return Err(WireError::CommandeInvalide);
        }

        let mut lg = [0u8; 4];
        lg.copy_from_slice(&tampon[16..20]);
        let longueur = u32::from_le_bytes(lg) as usize;

        // Borne AVANT d'attendre les octets : sinon un pair annoncant 4 Gio
        // ferait grossir le tampon de lecture jusqu'a l'epuisement memoire.
        if longueur > MAX_PAYLOAD {
            return Err(WireError::ChargeTropGrande(longueur));
        }
        if tampon.len() < HEADER_LEN + longueur {
            return Err(WireError::Incomplet);
        }

        let charge = &tampon[HEADER_LEN..HEADER_LEN + longueur];
        if sha256(charge)[..4] != tampon[20..24] {
            return Err(WireError::SommeIncorrecte);
        }

        let msg = Message::decode_payload(&commande, charge)?;
        Ok((msg, HEADER_LEN + longueur))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::NETWORK_MAGIC_TESTNET as MAGIE;

    fn aller_retour(m: Message) {
        let trame = m.frame(MAGIE);
        let (relu, consomme) = Message::parse(&trame, MAGIE).expect("analyse");
        assert_eq!(relu, m, "aller-retour infidele pour {}", m.command());
        assert_eq!(consomme, trame.len());
    }

    fn entete() -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: Hash256([1u8; 32]),
            merkle_root: Hash256([2u8; 32]),
            uncles_root: Hash256([3u8; 32]),
            miner: Hash256([4u8; 32]),
            time: 1_755_000_000,
            bits: 0x2000_ffff,
            height: 42,
            nonce: 7,
        }
    }

    #[test]
    fn aller_retour_sur_tous_les_messages_simples() {
        aller_retour(Message::VerAck);
        aller_retour(Message::GetAddr);
        aller_retour(Message::Ping(0x0123_4567_89ab_cdef));
        aller_retour(Message::Pong(1));
        aller_retour(Message::Version {
            version: PROTOCOL_VERSION,
            timestamp: 1_755_000_000,
            nonce: 0xdead_beef,
            user_agent: "q21:0.2".into(),
            start_height: 12_345,
        });
        aller_retour(Message::Reject {
            commande: "tx".into(),
            raison: "frais trop bas".into(),
        });
    }

    #[test]
    fn aller_retour_sur_les_inventaires() {
        let v = vec![
            InvItem {
                kind: InvKind::Tx,
                hash: Hash256([9u8; 32]),
            },
            InvItem {
                kind: InvKind::Block,
                hash: Hash256([8u8; 32]),
            },
            InvItem {
                kind: InvKind::CompactBlock,
                hash: Hash256([7u8; 32]),
            },
        ];
        aller_retour(Message::Inv(v.clone()));
        aller_retour(Message::GetData(v));
    }

    #[test]
    fn aller_retour_sur_les_entetes_et_localisateurs() {
        aller_retour(Message::Headers(vec![entete(), entete()]));
        aller_retour(Message::GetHeaders {
            locator: vec![Hash256([1u8; 32]), Hash256([2u8; 32])],
            stop: Hash256::ZERO,
        });
    }

    #[test]
    fn aller_retour_sur_les_adresses() {
        aller_retour(Message::Addr(vec![
            NetAddr {
                ip: [127, 0, 0, 1],
                port: 21_021,
                last_seen: 1_755_000_000,
            },
            NetAddr {
                ip: [10, 0, 0, 5],
                port: 8_333,
                last_seen: 0,
            },
        ]));
    }

    #[test]
    fn aller_retour_sur_les_messages_d_amorce() {
        aller_retour(Message::GetAmorce);
        aller_retour(Message::AmorceInfo {
            hauteur: 98_993,
            tete: Hash256([0x11; 32]),
            empreinte: Hash256([0x22; 32]),
            taille: 54_321_000,
            tranches: 52,
        });
        aller_retour(Message::GetAmorceTranche { index: 7 });
        aller_retour(Message::AmorceTranche {
            index: 7,
            donnees: vec![0xcd; 4096],
        });
        aller_retour(Message::AmorceTranche {
            index: 0,
            donnees: Vec::new(),
        });
    }

    #[test]
    fn aller_retour_sur_les_demandes_de_transactions_de_bloc() {
        aller_retour(Message::GetBlockTxn {
            block: Hash256([5u8; 32]),
            indices: vec![0, 1, 300, 70_000],
        });
    }

    #[test]
    fn une_magie_etrangere_est_refusee() {
        let trame = Message::VerAck.frame(MAGIE);
        let autre = crate::consensus::NETWORK_MAGIC_MAINNET;
        assert!(matches!(
            Message::parse(&trame, autre),
            Err(WireError::MagieInconnue(_))
        ));
    }

    #[test]
    fn une_trame_incomplete_demande_a_lire_davantage() {
        let trame = Message::Ping(1).frame(MAGIE);
        for coupure in 0..trame.len() {
            assert!(
                matches!(
                    Message::parse(&trame[..coupure], MAGIE),
                    Err(WireError::Incomplet)
                ),
                "coupure a {coupure} aurait du rendre Incomplet"
            );
        }
        assert!(Message::parse(&trame, MAGIE).is_ok());
    }

    #[test]
    fn une_charge_corrompue_est_detectee() {
        let mut trame = Message::Ping(1).frame(MAGIE);
        let dernier = trame.len() - 1;
        trame[dernier] ^= 0xff;
        assert_eq!(
            Message::parse(&trame, MAGIE),
            Err(WireError::SommeIncorrecte)
        );
    }

    /// Le controle qui empeche un inconnu de faire allouer des gigaoctets.
    #[test]
    fn une_charge_absurde_est_refusee_sans_attendre_les_octets() {
        let mut trame = Vec::new();
        trame.extend_from_slice(&MAGIE);
        trame.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
        trame.extend_from_slice(&u32::MAX.to_le_bytes());
        trame.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            Message::parse(&trame, MAGIE),
            Err(WireError::ChargeTropGrande(_))
        ));
    }

    #[test]
    fn un_inventaire_absurde_est_refuse_avant_allocation() {
        let mut charge = Writer::new();
        charge.varint(MAX_INV as u64 + 1);
        let charge = charge.finish();
        let somme = sha256(&charge);

        let mut trame = Vec::new();
        trame.extend_from_slice(&MAGIE);
        trame.extend_from_slice(b"inv\0\0\0\0\0\0\0\0\0");
        trame.extend_from_slice(&(charge.len() as u32).to_le_bytes());
        trame.extend_from_slice(&somme[..4]);
        trame.extend_from_slice(&charge);

        assert!(matches!(
            Message::parse(&trame, MAGIE),
            Err(WireError::TropDElements { .. })
        ));
    }

    #[test]
    fn une_commande_inconnue_est_signalee_sans_paniquer() {
        let charge: Vec<u8> = vec![];
        let somme = sha256(&charge);
        let mut trame = Vec::new();
        trame.extend_from_slice(&MAGIE);
        trame.extend_from_slice(b"inexistant\0\0");
        trame.extend_from_slice(&0u32.to_le_bytes());
        trame.extend_from_slice(&somme[..4]);
        assert!(matches!(
            Message::parse(&trame, MAGIE),
            Err(WireError::CommandeInconnue(_))
        ));
    }

    #[test]
    fn un_rembourrage_de_commande_non_nul_est_refuse() {
        let charge: Vec<u8> = vec![];
        let somme = sha256(&charge);
        let mut trame = Vec::new();
        trame.extend_from_slice(&MAGIE);
        trame.extend_from_slice(b"ping\0X\0\0\0\0\0\0");
        trame.extend_from_slice(&0u32.to_le_bytes());
        trame.extend_from_slice(&somme[..4]);
        assert_eq!(
            Message::parse(&trame, MAGIE),
            Err(WireError::CommandeInvalide)
        );
    }

    /// Aucune entree, si tordue soit-elle, ne doit arreter le noeud.
    #[test]
    fn aucune_entree_aleatoire_ne_fait_paniquer() {
        let mut graine = 0x1234_5678_9abc_def0u64;
        for _ in 0..3_000 {
            graine = graine
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let n = (graine % 200) as usize;
            let mut brut = Vec::with_capacity(n + 4);
            brut.extend_from_slice(&MAGIE);
            let mut g = graine;
            for _ in 0..n {
                g = g.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                brut.push((g >> 33) as u8);
            }
            // Ne doit jamais paniquer, quel que soit le resultat.
            let _ = Message::parse(&brut, MAGIE);
        }
    }

    #[test]
    fn deux_messages_a_la_suite_se_lisent_l_un_apres_l_autre() {
        let mut flux = Message::Ping(1).frame(MAGIE);
        flux.extend_from_slice(&Message::Pong(2).frame(MAGIE));

        let (a, n) = Message::parse(&flux, MAGIE).unwrap();
        assert_eq!(a, Message::Ping(1));
        let (b, m) = Message::parse(&flux[n..], MAGIE).unwrap();
        assert_eq!(b, Message::Pong(2));
        assert_eq!(n + m, flux.len());
    }
}
