//! Epreuves de non-regression reseau, issues de l'audit adverse de la phase 8.
//!
//! Ces tests se connectent au noeud comme le ferait un pair hostile. Chacun a
//! d'abord ete un exploit qui fonctionnait ; il verifie desormais que l'attaque
//! echoue.

use q21_core::block::Block;
use q21_core::chain::{genesis_block, Chain};
use q21_core::net::{magic_for, Node};
use q21_core::wire::{InvItem, InvKind, Message, MAX_BLOCK_TXN, MAX_INV, PROTOCOL_VERSION};
use q21_core::Network;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const RESEAU: Network = Network::Regtest;

fn noeud() -> Node {
    let g = genesis_block(RESEAU);
    Node::new(RESEAU, Chain::new(RESEAU, g))
}

/// Lit du flux pendant `secs` au plus, rend tout ce qui est arrive.
fn aspirer(mut s: TcpStream, secs: u64) -> Vec<u8> {
    s.set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let debut = std::time::Instant::now();
    let mut tout = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    while debut.elapsed() < Duration::from_secs(secs) {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => tout.extend_from_slice(&buf[..n]),
            Err(_) => {
                if !tout.is_empty() {
                    break;
                }
            }
        }
    }
    tout
}

/// `getblocktxn` a indices repetes : plus d'amplification.
///
/// L'exploit demandait cent mille fois le meme indice. Le noeud clonait la
/// transaction autant de fois et assemblait une trame de 15,5 Mio — qui
/// depassait meme son propre `MAX_PAYLOAD`, donc illisible par un pair honnete.
/// Fabriquer une reponse que personne ne peut lire est la definition d'un
/// vecteur de deni de service.
///
/// Trois regles referment la porte : poignee de main exigee, indices
/// dedoublonnes, budget d'octets en sortie.
#[test]
fn getblocktxn_a_indices_repetes_n_amplifie_plus() {
    let a = noeud();
    let addr = a.listen("127.0.0.1:0").expect("ecoute");
    let magie = magic_for(RESEAU);

    // Le bloc de genese existe toujours ; sa coinbase est a l'indice 0.
    let genese_id = a.tip_id();

    let indices = vec![0u32; MAX_BLOCK_TXN]; // 100_000 fois le meme indice
    let requete = Message::GetBlockTxn {
        block: genese_id,
        indices,
    };
    let trame = requete.frame(magie);
    let taille_requete = trame.len();

    let mut s = TcpStream::connect(addr).expect("connexion");
    s.write_all(&trame).expect("envoi");

    let recu = aspirer(s.try_clone().unwrap(), 8);

    eprintln!(
        "requete = {} octets, reponse = {} octets",
        taille_requete,
        recu.len()
    );
    assert!(
        recu.len() <= taille_requete,
        "la reponse ({} octets) amplifie encore la requete ({} octets)",
        recu.len(),
        taille_requete
    );
    assert!(
        recu.len() < q21_core::wire::MAX_PAYLOAD,
        "le noeud emet encore plus que son propre MAX_PAYLOAD"
    );
    a.shutdown();
}

/// `getdata` a hachages repetes : plus d'amplification.
///
/// L'exploit demandait vingt mille fois le meme bloc : le noeud en renvoyait
/// vingt mille copies, chacune dans sa propre trame, et pour un bloc compact
/// recalculait a chaque fois tous les identifiants courts. Mesure de l'audit :
/// 660 Kio de requete pour 6,8 Mio de reponse — sur des blocs reels de 4 Mio,
/// 80 Gio.
#[test]
fn getdata_a_hachages_repetes_n_amplifie_plus() {
    let a = noeud();
    let addr = a.listen("127.0.0.1:0").expect("ecoute");
    let magie = magic_for(RESEAU);
    let genese_id = a.tip_id();

    const K: usize = 20_000;
    let items = vec![
        InvItem {
            kind: InvKind::Block,
            hash: genese_id,
        };
        K
    ];
    const _: () = assert!(K <= MAX_INV);
    let trame = Message::GetData(items).frame(magie);
    let taille_requete = trame.len();

    let mut s = TcpStream::connect(addr).expect("connexion");
    s.write_all(&trame).expect("envoi");

    let recu = aspirer(s.try_clone().unwrap(), 10);

    // Compte les trames `block` renvoyees.
    let mut reste = &recu[..];
    let mut blocs = 0usize;
    while let Ok((m, n)) = Message::parse(reste, magie) {
        if matches!(m, Message::Block(_)) {
            blocs += 1;
        }
        reste = &reste[n..];
        if reste.is_empty() {
            break;
        }
    }

    eprintln!(
        "requete = {} octets, reponse = {} octets, trames block = {}",
        taille_requete,
        recu.len(),
        blocs
    );
    assert!(
        blocs <= 1,
        "un hachage demande vingt mille fois doit etre servi au plus une fois \
         (recu {blocs} copies)"
    );
    assert!(
        recu.len() <= taille_requete,
        "la reponse amplifie encore la requete"
    );
    a.shutdown();
}

/// Rien de couteux n'est servi avant la poignee de main.
///
/// Les deux attaques ci-dessus fonctionnaient sur une simple connexion TCP,
/// sans `version` ni `verack` : leur cout pour l'attaquant se resumait a un
/// `connect()`.
#[test]
fn rien_n_est_servi_avant_la_poignee_de_main() {
    let a = noeud();
    let addr = a.listen("127.0.0.1:0").expect("ecoute");
    let magie = magic_for(RESEAU);
    let genese_id = a.tip_id();

    // Directement un getdata, sans version prealable.
    let trame = Message::GetData(vec![InvItem {
        kind: InvKind::Block,
        hash: genese_id,
    }])
    .frame(magie);

    let mut s = TcpStream::connect(addr).expect("connexion");
    s.write_all(&trame).expect("envoi");
    let recu = aspirer(s.try_clone().unwrap(), 5);

    // Rien ne doit revenir, et la connexion doit tomber.
    let servi = Message::parse(&recu, magie)
        .map(|(m, _)| matches!(m, Message::Block(_)))
        .unwrap_or(false);
    assert!(
        !servi,
        "un bloc a ete servi sans poignee de main prealable ({} octets recus)",
        recu.len()
    );
    let _ = Block::decode; // silence si non utilise
    a.shutdown();
}

/// Un bloc compact dont le parent est inconnu ne coute rien.
///
/// La version fautive clonait **tout le reservoir** — jusqu'a 64 Mio — sous le
/// verrou global, a chaque annonce compacte. Un message de 170 octets suffisait
/// a serialiser le noeud entier ; repete, il le figeait.
///
/// On verifie deux choses : le noeud n'entame aucune reconstruction (aucun
/// `getblocktxn` en reponse), et il reste parfaitement reactif ensuite.
#[test]
fn un_bloc_compact_orphelin_ne_declenche_aucun_travail() {
    use q21_core::block::BlockHeader;
    use q21_core::compact::CompactBlock;
    use q21_core::hash::Hash256;

    let a = noeud();
    let addr = a.listen("127.0.0.1:0").expect("ecoute");
    let magie = magic_for(RESEAU);

    let mut s = TcpStream::connect(addr).expect("connexion");

    // Poignee de main complete : on se place dans le cas le plus favorable a
    // l'attaquant, celui d'un pair legitime.
    s.write_all(
        &Message::Version {
            version: PROTOCOL_VERSION,
            timestamp: 0,
            nonce: 0xdead_beef,
            user_agent: "epreuve".into(),
            start_height: 0,
        }
        .frame(magie),
    )
    .expect("envoi version");
    s.write_all(&Message::VerAck.frame(magie)).expect("verack");
    std::thread::sleep(Duration::from_millis(300));

    // Deux cents annonces compactes dont le parent n'existe pas.
    for k in 0..200u8 {
        let entete = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_block: Hash256([k; 32]), // parent inconnu
            merkle_root: Hash256([1u8; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([2u8; 32]),
            time: 1_800_000_000,
            bits: 0x2000_ffff,
            height: 1,
            nonce: 0,
        };
        let c = CompactBlock {
            header: entete,
            nonce: 7,
            short_ids: vec![1, 2, 3],
            prefilled: Vec::new(),
            uncles: Vec::new(),
        };
        let _ = s.write_all(&Message::CmpctBlock(Box::new(c)).frame(magie));
    }

    // Le noeud doit rester reactif : on lui demande un pong.
    s.write_all(&Message::Ping(0x1234).frame(magie))
        .expect("ping");
    let recu = aspirer(s.try_clone().unwrap(), 5);

    let mut reste = &recu[..];
    let mut pong = false;
    let mut demandes = 0usize;
    while let Ok((m, n)) = Message::parse(reste, magie) {
        match m {
            Message::Pong(0x1234) => pong = true,
            Message::GetBlockTxn { .. } | Message::GetData(_) => demandes += 1,
            _ => {}
        }
        reste = &reste[n..];
        if reste.is_empty() {
            break;
        }
    }

    assert_eq!(
        demandes, 0,
        "le noeud a entame une reconstruction pour un bloc dont il ignore le parent"
    );
    assert!(
        pong,
        "le noeud ne repond plus apres 200 annonces compactes orphelines"
    );
    a.shutdown();
}
