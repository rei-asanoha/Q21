//! Fuzzing des décodeurs — tout ce qui lit des octets venus d'un inconnu.
//!
//! # Pourquoi ce fichier existe
//!
//! Un nœud lit des octets que n'importe qui peut fabriquer : trames du
//! protocole, paquet d'amorce, instantané portable, blocs, transactions,
//! adresses. Chacun de ces décodeurs est une porte d'entrée. Un audit humain lit
//! le code et raisonne ; une machine, elle, essaie des millions de cas tordus
//! que personne n'aurait imaginés. Les deux se complètent, et le second trouve
//! ce que le premier ne voit pas.
//!
//! # Ce que ce fuzzer fait de plus que les épreuves existantes
//!
//! Les épreuves d'entrée aléatoire déjà présentes envoient des octets tirés au
//! hasard. C'est utile, mais superficiel : la trame porte une **somme de
//! contrôle**, et des octets aléatoires ne la satisfont jamais. Le décodage
//! s'arrête donc au portier, et tout ce qui est derrière — les boucles qui
//! lisent des listes, les allocations bornées, l'arithmétique des longueurs —
//! n'est jamais atteint.
//!
//! Celui-ci procède autrement, comme un vrai fuzzer :
//!
//! 1. il part d'**encodages valides** (un corpus de graines) ;
//! 2. il les **mute** — bits retournés, octets écrasés, troncatures,
//!    greffes entre deux graines, et surtout **falsification des champs de
//!    longueur**, qui est là où se cachent les débordements et les allocations
//!    démesurées ;
//! 3. pour une trame, il **recalcule la somme de contrôle** après mutation, de
//!    sorte que la charge mutée franchit le portier et atteint vraiment le
//!    décodeur qu'on veut éprouver.
//!
//! # Ce qu'il vérifie
//!
//! Une seule chose, mais elle est absolue : **aucune entrée ne doit faire
//! paniquer le processus**. Un décodeur qui panique est un nœud qu'un inconnu
//! arrête à distance avec un message bien choisi. Refuser proprement est
//! toujours acceptable ; s'arrêter ne l'est jamais.
//!
//! Le profil de test conserve `overflow-checks` : un dépassement arithmétique
//! panique donc, et sera attrapé ici plutôt qu'en production.
//!
//! # Reproductibilité
//!
//! La graine est fixe : deux exécutions éprouvent exactement les mêmes cas. En
//! cas d'échec, le test imprime l'entrée fautive en hexadécimal et le numéro du
//! tour, de quoi rejouer le cas à la main.

use q21_core::address::Network;
use q21_core::block::{Block, BlockHeader};
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::hash::Hash256;
use q21_core::sha256::sha256;
use q21_core::sig::SchemeId;
use q21_core::synchro_rapide::Amorce;
use q21_core::tx::Transaction;
use q21_core::wire::{InvItem, InvKind, Message, NetAddr};

const RESEAU: Network = Network::Regtest;
const MAGIE: [u8; 4] = [0x51, 0x32, 0x31, 0x72];
const ESSAIS: u64 = 50_000_000;
const HEADER_LEN: usize = 24;

// ---------------------------------------------------------------------------
// Générateur déterministe
// ---------------------------------------------------------------------------

/// splitmix64 : court, sans dépendance, et de qualité suffisante pour semer des
/// mutations. On ne cherche pas du hasard cryptographique, on cherche de la
/// variété reproductible.
struct Alea(u64);

impl Alea {
    fn suivant(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Un entier dans `[0, n)`. Rend 0 si `n` est nul, pour n'avoir jamais à
    /// s'en soucier chez l'appelant.
    fn borne(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.suivant() % n as u64) as usize
        }
    }
    fn octet(&mut self) -> u8 {
        (self.suivant() >> 24) as u8
    }
    /// Vrai une fois sur `n`.
    fn parfois(&mut self, n: u64) -> bool {
        n != 0 && self.suivant() % n == 0
    }
}

// ---------------------------------------------------------------------------
// Corpus de graines valides
// ---------------------------------------------------------------------------

fn chaine(n: u64) -> Chain {
    let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
    for i in 1..=n {
        let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
    }
    c
}

/// Les trames valides de chaque message du protocole. C'est le point de départ
/// des mutations : une graine valide mutée atteint le décodeur, là où du bruit
/// pur s'arrête au portier.
fn corpus_trames(c: &Chain) -> Vec<Vec<u8>> {
    let entetes = c.headers();
    let bloc = c.block_at(1).expect("bloc 1");
    let tx = bloc.transactions[0].clone();
    let inv = vec![
        InvItem {
            kind: InvKind::Block,
            hash: c.tip_id(),
        },
        InvItem {
            kind: InvKind::Tx,
            hash: Hash256([7u8; 32]),
        },
    ];

    let messages = vec![
        Message::Version {
            version: 1,
            timestamp: 1_755_000_000,
            nonce: 42,
            user_agent: "q21:epreuve".into(),
            start_height: 7,
        },
        Message::VerAck,
        Message::Ping(0xdead_beef),
        Message::Pong(1),
        Message::GetHeaders {
            locator: vec![c.tip_id(), Hash256::ZERO],
            stop: Hash256::ZERO,
        },
        Message::Headers(entetes.clone()),
        Message::Inv(inv.clone()),
        Message::GetData(inv),
        Message::Block(Box::new(bloc)),
        Message::Tx(Box::new(tx)),
        Message::GetAddr,
        Message::Addr(vec![NetAddr {
            ip: [192, 168, 1, 1],
            port: 21121,
            last_seen: 1_755_000_000,
        }]),
        Message::GetAmorce,
        Message::AmorceInfo {
            hauteur: 12,
            tete: c.tip_id(),
            empreinte: Hash256([9u8; 32]),
            taille: 4096,
            tranches: 1,
        },
        Message::GetAmorceTranche { index: 0 },
        Message::AmorceTranche {
            index: 0,
            donnees: vec![0xab; 512],
        },
    ];
    messages.iter().map(|m| m.frame(MAGIE)).collect()
}

/// Les autres formats : ils ne passent pas par une trame, mais viennent tout
/// autant d'un inconnu — un fichier d'amorce, un instantané téléchargé.
fn corpus_formats(c: &Chain) -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = Vec::new();
    if let Some(a) = c.construire_amorce() {
        v.push(("amorce", a.encode()));
    }
    if let Some(s) = c.snapshot_at_depth(1) {
        v.push(("instantane", s.to_portable_bytes()));
    }
    if let Some(b) = c.block_at(1) {
        v.push(("transaction", b.transactions[0].encode()));
        v.push(("entete", b.header.encode()));
        v.push(("bloc", b.encode()));
    }
    v
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/// Applique une mutation au hasard. C'est ici que se joue l'efficacité du
/// fuzzer : les opérateurs sont choisis pour viser ce qui casse réellement un
/// décodeur — les longueurs, les comptes, les bornes.
fn muter(a: &mut Alea, v: &mut Vec<u8>) {
    if v.is_empty() {
        v.push(a.octet());
        return;
    }
    match a.borne(7) {
        // Retourner un bit : la mutation la plus fine.
        0 => {
            let i = a.borne(v.len());
            v[i] ^= 1u8 << a.borne(8);
        }
        // Écraser un octet.
        1 => {
            let i = a.borne(v.len());
            v[i] = a.octet();
        }
        // Les valeurs extrêmes trouvent les bornes mal écrites.
        2 => {
            let i = a.borne(v.len());
            v[i] = if a.parfois(2) { 0x00 } else { 0xFF };
        }
        // Tronquer : éprouve le « et s'il en manque ? » de chaque lecture.
        3 => {
            let n = a.borne(v.len());
            v.truncate(n);
        }
        // Rallonger : éprouve le « et s'il en reste ? ».
        4 => {
            let n = 1 + a.borne(64);
            for _ in 0..n {
                v.push(a.octet());
            }
        }
        // Falsifier un champ de longueur ou de compte. LA mutation qui compte :
        // c'est ainsi qu'on demande à un décodeur de réserver quatre
        // gibioctets pour une trame de vingt octets.
        5 => {
            if v.len() >= 4 {
                let i = a.borne(v.len() - 3);
                let absurde: u32 = match a.borne(4) {
                    0 => u32::MAX,
                    1 => 0x7FFF_FFFF,
                    2 => 0x00FF_FFFF,
                    _ => 0xFFFF_0000,
                };
                v[i..i + 4].copy_from_slice(&absurde.to_le_bytes());
            }
        }
        // Greffer un morceau au milieu : produit des structures hybrides
        // qu'aucun encodeur honnête ne fabriquerait.
        _ => {
            let i = a.borne(v.len());
            let n = 1 + a.borne(16);
            let morceau: Vec<u8> = (0..n).map(|_| a.octet()).collect();
            v.splice(i..i, morceau);
        }
    }
}

/// Recalcule longueur et somme de contrôle d'une trame mutée.
///
/// Sans cela, la charge mutée serait rejetée par le portier et le décodeur du
/// message ne serait **jamais** atteint — exactement la limite des épreuves
/// aléatoires existantes. On répare donc l'enveloppe pour que la mutation porte
/// là où on veut l'éprouver : à l'intérieur.
fn reparer_trame(v: &mut [u8]) {
    if v.len() < HEADER_LEN {
        return;
    }
    let charge_len = v.len() - HEADER_LEN;
    let somme = sha256(&v[HEADER_LEN..]);
    v[..4].copy_from_slice(&MAGIE);
    v[16..20].copy_from_slice(&(charge_len as u32).to_le_bytes());
    v[20..24].copy_from_slice(&somme[..4]);
}

fn hex(v: &[u8]) -> String {
    let court: Vec<u8> = v.iter().take(96).copied().collect();
    let mut s: String = court.iter().map(|o| format!("{o:02x}")).collect();
    if v.len() > 96 {
        s.push_str(&format!("… ({} octets)", v.len()));
    }
    s
}

/// Exécute un décodeur en rattrapant une éventuelle panique, pour pouvoir dire
/// **quelle** entrée l'a provoquée. Un fuzzer qui échoue sans montrer son cas ne
/// sert qu'à inquiéter.
fn sans_panique(nom: &str, tour: u32, entree: &[u8], f: impl FnOnce() + std::panic::UnwindSafe) {
    if std::panic::catch_unwind(f).is_err() {
        panic!(
            "PANIQUE dans le decodeur « {nom} » au tour {tour}.\n\
             Entree fautive : {}\n\
             Un decodeur qui panique est un noeud qu'un inconnu arrete a distance.",
            hex(entree)
        );
    }
}

// ---------------------------------------------------------------------------
// L'épreuve
// ---------------------------------------------------------------------------

/// Aucune entrée, si tordue soit-elle, ne doit faire paniquer un décodeur.
#[test]
fn aucun_decodeur_ne_panique_sur_entree_mutee() {
    // Silence les traces de panique : on en attrape volontairement, et la
    // sortie serait illisible. Le message final, lui, dit tout.
    let precedent = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let c = chaine(12);
    let trames = corpus_trames(&c);
    let formats = corpus_formats(&c);
    assert!(!trames.is_empty(), "corpus de trames vide");
    assert!(
        formats.len() >= 4,
        "corpus de formats trop maigre : {}",
        formats.len()
    );

    let mut a = Alea(0x5150_2131_4A21_0001);
    // Le nombre de tours se regle de l'exterieur, pour qu'une campagne longue
    // emploie exactement le meme code que l'epreuve courte de la chaine
    // d'integration — deux intensites, une seule implementation, donc aucune
    // derive possible entre ce qu'on eprouve tous les jours et ce qu'on eprouve
    // a fond :
    //
    //   Q21_FUZZ_TOURS=2000000 cargo test --release --test fuzz_decodeurs
    let tours: u32 = std::env::var("Q21_FUZZ_TOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(150_000);

    for tour in 0..tours {
        // --- Les trames du protocole.
        let base = &trames[a.borne(trames.len())];
        let mut v = base.clone();
        for _ in 0..=a.borne(3) {
            muter(&mut a, &mut v);
        }
        // Deux tiers du temps on répare l'enveloppe, pour atteindre le
        // décodeur ; le reste éprouve le portier lui-même.
        if !a.parfois(3) {
            reparer_trame(&mut v);
        }
        sans_panique("Message::parse", tour, &v, || {
            let _ = Message::parse(&v, MAGIE);
        });

        // --- Les autres formats.
        let (nom, base) = &formats[a.borne(formats.len())];
        let mut w = base.clone();
        for _ in 0..=a.borne(3) {
            muter(&mut a, &mut w);
        }
        sans_panique(nom, tour, &w, || match *nom {
            "amorce" => {
                let _ = Amorce::decode(&w);
            }
            "instantane" => {
                let _ = q21_core::state::Snapshot::from_portable_bytes(&w, RESEAU);
            }
            "transaction" => {
                let _ = Transaction::decode(&w);
            }
            "entete" => {
                let _ = BlockHeader::decode(&w);
            }
            _ => {
                let _ = Block::decode(&w);
            }
        });
    }

    std::panic::set_hook(precedent);
}

/// Les adresses viennent d'un humain qui les recopie, donc de partout : un
/// courriel, un message, un code-barres mal lu. Le décodeur doit refuser sans
/// jamais s'arrêter.
#[test]
fn aucune_adresse_tordue_ne_fait_paniquer() {
    let precedent = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let mut w = q21_core::wallet::Wallet::from_seed([3u8; 32], RESEAU);
    let valide = w.new_address().to_string_bech32();

    let mut a = Alea(0x5150_2131_4A21_0002);
    let tours: u32 = std::env::var("Q21_FUZZ_TOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(80_000);
    for tour in 0..tours {
        let mut v = valide.clone().into_bytes();
        for _ in 0..=a.borne(3) {
            muter(&mut a, &mut v);
        }
        // Une adresse est du texte : on n'éprouve que ce qui peut en être.
        let s = String::from_utf8_lossy(&v).to_string();
        sans_panique("Address::parse", tour, s.as_bytes(), || {
            let _ = q21_core::address::Address::parse(&s);
        });
        sans_panique("bech32::decode", tour, s.as_bytes(), || {
            let _ = q21_core::bech32::decode(&s);
        });
    }

    std::panic::set_hook(precedent);
}
