//! Epreuves de non-regression reseau, issues du second audit adverse.
//!
//! Comme celles de `regression_reseau.rs`, ces epreuves se connectent au noeud
//! comme le ferait un pair hostile. Chacune a d'abord ete un exploit qui
//! fonctionnait ; elle verifie desormais que l'attaque echoue.

use q21_core::block::BlockHeader;
use q21_core::chain::{genesis_block, Chain};
use q21_core::hash::Hash256;
use q21_core::net::{groupe_entrant, magic_for, GroupeReseau, Node};
use q21_core::net::{CMPCT_SEAU_MAX, CORPS_EN_VOL_MAX, ENTRANTS_PAR_GROUPE};
use q21_core::wire::{Message, MAX_HEADERS, PROTOCOL_VERSION};
use q21_core::Network;

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::Ordering;
use std::time::Duration;

const RESEAU: Network = Network::Regtest;

fn noeud() -> Node {
    let g = genesis_block(RESEAU);
    Node::new(RESEAU, Chain::new(RESEAU, g))
}

/// Lit du flux pendant `secs` au plus, rend tout ce qui est arrive.
fn aspirer(mut s: TcpStream, secs: u64) -> Vec<u8> {
    let _ = s.set_read_timeout(Some(Duration::from_millis(400)));
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

/// Poignee de main complete : on se place dans le cas le plus favorable a
/// l'attaquant, celui d'un pair presente.
fn presenter(s: &mut TcpStream, magie: [u8; 4], nonce: u64) {
    s.write_all(
        &Message::Version {
            version: PROTOCOL_VERSION,
            timestamp: 0,
            nonce,
            user_agent: "epreuve".into(),
            start_height: 0,
        }
        .frame(magie),
    )
    .expect("version");
    s.write_all(&Message::VerAck.frame(magie)).expect("verack");
    std::thread::sleep(Duration::from_millis(300));
}

/// Une suite de `n` en-tetes parfaitement chainee sur `prev`, sans un seul
/// nonce mine : `graine` en change le contenu, donc les identifiants.
fn entetes_chainees(prev: Hash256, n: usize, graine: u8) -> Vec<BlockHeader> {
    let mut v = Vec::with_capacity(n);
    let mut prev = prev;
    for i in 0..n {
        let h = BlockHeader {
            version: 1,
            prev_block: prev,
            merkle_root: Hash256([graine; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([2u8; 32]),
            time: 1_800_000_000 + i as u64,
            bits: 0x2000_ffff,
            height: 1 + i as u64,
            nonce: 0,
        };
        prev = h.block_id();
        v.push(h);
    }
    v
}

/// Ce que le noeud a demande : nombre d'items `getdata`, et hachages distincts.
fn demandes(recu: &[u8], magie: [u8; 4]) -> (usize, usize) {
    let mut reste = recu;
    let mut total = 0usize;
    let mut distincts: HashSet<Hash256> = HashSet::new();
    while let Ok((m, n)) = Message::parse(reste, magie) {
        if let Message::GetData(items) = m {
            total += items.len();
            distincts.extend(items.iter().map(|i| i.hash));
        }
        reste = &reste[n..];
        if reste.is_empty() {
            break;
        }
    }
    (total, distincts.len())
}

/// Des en-tetes poussees sans poignee de main ne font rien demander.
///
/// `getheaders` exigeait la poignee de main ; `headers` ne l'exigeait pas. Le
/// message pousse — celui qui fait hacher deux mille en-tetes et demander
/// deux mille corps — franchissait la porte que le message demande gardait
/// fermee. Une simple connexion TCP, sans `version`, faisait reclamer au noeud
/// dix mille corps de blocs en cinq trames.
#[test]
fn des_entetes_anonymes_ne_font_rien_demander() {
    let a = noeud();
    let addr = a.listen("127.0.0.1:0").expect("ecoute");
    let magie = magic_for(RESEAU);
    let genese = a.tip_id();

    let mut s = TcpStream::connect(addr).expect("connexion");
    // Meme connexion anonyme : d'abord `getheaders`, qui doit rester muet.
    s.write_all(
        &Message::GetHeaders {
            locator: vec![genese],
            stop: Hash256::ZERO,
        }
        .frame(magie),
    )
    .expect("getheaders");
    // Puis `headers`, sans `Version` ni `VerAck`.
    for lot in 0..5u8 {
        let entetes = entetes_chainees(genese, MAX_HEADERS, lot + 1);
        s.write_all(&Message::Headers(entetes).frame(magie))
            .expect("headers");
    }
    let recu = aspirer(s.try_clone().unwrap(), 4);

    let mut reste = &recu[..];
    let mut entetes_servies = 0usize;
    while let Ok((m, n)) = Message::parse(reste, magie) {
        if let Message::Headers(v) = m {
            entetes_servies += v.len();
        }
        reste = &reste[n..];
        if reste.is_empty() {
            break;
        }
    }
    let (total, distincts) = demandes(&recu, magie);
    eprintln!(
        "anonyme : getheaders -> {entetes_servies} en-tete(s) servie(s) ; \
         headers -> {total} item(s) getdata, {distincts} distinct(s)"
    );
    assert_eq!(entetes_servies, 0, "getheaders anonyme a ete servi");
    assert_eq!(
        total, 0,
        "des en-tetes anonymes ont fait demander {total} corps de blocs"
    );
    a.shutdown();
}

/// Les corps en vol par pair sont plafonnes, quoi que le pair annonce.
///
/// Les en-tetes ne sont verifies qu'en chainage, pas en travail : une suite
/// chainee sur la tete se fabrique hors ligne, gratuitement. Chaque lot de
/// deux mille faisait inscrire deux mille jetons dans une table sans plafond,
/// dont la seule purge etait temporelle. Cinq lots : dix mille corps reclames,
/// dix mille entrees, et le pair jamais coupe.
///
/// Desormais, quel que soit le nombre de lots, le noeud ne reclame jamais plus
/// de `CORPS_EN_VOL_MAX` corps distincts a un pair qui ne livre rien.
#[test]
fn les_corps_en_vol_sont_plafonnes_par_pair() {
    let a = noeud();
    let addr = a.listen("127.0.0.1:0").expect("ecoute");
    let magie = magic_for(RESEAU);
    let genese = a.tip_id();

    let mut s = TcpStream::connect(addr).expect("connexion");
    presenter(&mut s, magie, 0xc0ff_ee01);

    for lot in 0..5u8 {
        let entetes = entetes_chainees(genese, MAX_HEADERS, lot + 1);
        s.write_all(&Message::Headers(entetes).frame(magie))
            .expect("headers");
    }
    let recu = aspirer(s.try_clone().unwrap(), 6);
    let (total, distincts) = demandes(&recu, magie);
    eprintln!(
        "presente : 5 lots de {MAX_HEADERS} en-tetes forgees -> {total} item(s) \
         getdata, {distincts} corps distinct(s) reclame(s), plafond {CORPS_EN_VOL_MAX}"
    );
    assert!(
        distincts <= CORPS_EN_VOL_MAX,
        "{distincts} corps distincts reclames a un pair qui ne livre rien : \
         le plafond de {CORPS_EN_VOL_MAX} n'est pas applique"
    );
    assert!(
        distincts > 0,
        "un pair presente aux en-tetes chainees doit se voir demander des corps"
    );
    a.shutdown();
}

/// Les annonces compactes sont mesurees, et l'insistance coupe.
///
/// Apres la poignee de main, une annonce compacte dont le parent est la tete
/// declenchait sans frein un balayage du reservoir et une allocation de la
/// taille annoncee, sous le verrou global — sans seau ni sanction, la ou `tx`
/// et l'amorce en avaient. Deux cents annonces de vingt mille identifiants :
/// deux cents reconstructions, pair toujours connecte.
///
/// Desormais la reserve est de `CMPCT_SEAU_MAX` annonces non sollicitees ; au-
/// dela, rien n'est reconstruit et le pair perd des points jusqu'a la coupure.
///
/// L'en-tete annonce est **vrai** — mine, a la bonne difficulte, a l'heure —
/// parce que depuis la 2e campagne de la phase 8b un en-tete faux est refuse
/// avant meme le seau (voir `attaque_bloc_compact_sans_travail`) : c'est bien
/// le seau qu'on mesure ici, pas le controle d'en-tete. Seule la clef SipHash
/// change d'une annonce a l'autre ; les identifiants courts, eux, ne
/// correspondent a rien, donc chaque annonce entame une reconstruction sans
/// jamais l'achever.
#[test]
fn les_annonces_compactes_sont_mesurees_et_l_insistance_coupe() {
    use q21_core::chain::GENESIS_TIME;
    use q21_core::compact::CompactBlock;
    use q21_core::consensus::TARGET_BLOCK_SECS;
    use q21_core::sig::SchemeId;

    let a = noeud();
    let addr = a.listen("127.0.0.1:0").expect("ecoute");
    let magie = magic_for(RESEAU);

    let t = GENESIS_TIME + TARGET_BLOCK_SECS;
    let vrai = a
        .with_chain(|c| c.mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 50_000_000))
        .expect("minage");
    let entete: BlockHeader = vrai.header;

    let mut s = TcpStream::connect(addr).expect("connexion");
    presenter(&mut s, magie, 0xc0ff_ee02);

    const ANNONCES: u64 = 200;
    let mut envoyees = 0u64;
    for k in 0..ANNONCES {
        let c = CompactBlock {
            header: entete,
            nonce: k, // clef SipHash differente a chaque annonce
            short_ids: (0..20_000u64)
                .map(|i| i.wrapping_mul(0x9e37_79b9))
                .collect(),
            prefilled: Vec::new(),
            uncles: Vec::new(),
        };
        if s.write_all(&Message::CmpctBlock(Box::new(c)).frame(magie))
            .is_err()
        {
            break;
        }
        envoyees += 1;
    }

    // On le demande au noeud, pas a la socket.
    let mut restants = a.peer_count();
    for _ in 0..80 {
        if restants == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        restants = a.peer_count();
    }
    let recues = a.stats.compacts_recus.load(Ordering::Relaxed);
    let reconstruites = a.stats.compacts_reconstruits.load(Ordering::Relaxed);
    let refusees = a.stats.compacts_refuses.load(Ordering::Relaxed);
    eprintln!(
        "{envoyees} annonces envoyees, {recues} recues, {reconstruites} \
         reconstruction(s) entamee(s), {refusees} refusee(s) par le seau ; \
         pairs restants = {restants}"
    );
    assert_eq!(
        restants, 0,
        "un pair qui insiste au-dela de son budget d'annonces doit etre coupe"
    );
    // La reserve, plus ce que le debit a pu rendre pendant l'envoi : sur une
    // machine lente, quelques secondes.
    let marge = 4;
    assert!(
        reconstruites <= CMPCT_SEAU_MAX + marge,
        "{reconstruites} reconstructions entamees pour une reserve de \
         {CMPCT_SEAU_MAX} : le seau ne borne pas la depense"
    );
    assert!(refusees > 0, "aucune annonce refusee par le seau");
    a.shutdown();
}

/// La poignee de main se conclut en un echange, pas en boucle.
///
/// Trouve en eprouvant le plafond de corps en vol : la synchronisation se
/// poursuivait meme sans reprise, parce que chaque `Version` recu faisait
/// renvoyer un `Version` — y compris a celui qui repondait au notre. Deux
/// noeuds s'echangeaient `Version`/`VerAck`/`GetAddr`/`Addr` sans fin :
/// quarante-huit mille `Version` en deux secondes sur la boucle locale, et une
/// demande d'en-tetes a chaque tour.
///
/// Un pair qui se comporte comme un noeud — il repond `VerAck` + `Version` a
/// chaque `Version` — ne doit recevoir qu'un seul `Version`, et la poignee de
/// main doit neanmoins se conclure (le noeud demande alors son carnet).
#[test]
fn la_poignee_de_main_ne_boucle_pas() {
    let a = noeud();
    let addr = a.listen("127.0.0.1:0").expect("ecoute");
    let magie = magic_for(RESEAU);

    let mut s = TcpStream::connect(addr).expect("connexion");
    let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
    let notre = Message::Version {
        version: PROTOCOL_VERSION,
        timestamp: 0,
        nonce: 0xc0ff_ee03,
        user_agent: "epreuve".into(),
        start_height: 0,
    };
    s.write_all(&notre.frame(magie)).expect("version");

    let debut = std::time::Instant::now();
    let mut tampon = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    let (mut versions, mut veracks, mut getaddr) = (0usize, 0usize, 0usize);
    while debut.elapsed() < Duration::from_secs(2) {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => tampon.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
        while let Ok((m, n)) = Message::parse(&tampon, magie) {
            tampon.drain(..n);
            match m {
                Message::Version { .. } => {
                    versions += 1;
                    // Comme un noeud : on accuse, et on se presente a notre tour.
                    s.write_all(&Message::VerAck.frame(magie)).expect("verack");
                    s.write_all(&notre.frame(magie)).expect("version");
                }
                Message::VerAck => veracks += 1,
                Message::GetAddr => getaddr += 1,
                _ => {}
            }
        }
    }
    eprintln!("versions recues = {versions}, veracks = {veracks}, getaddr = {getaddr}");
    assert_eq!(
        versions, 1,
        "le noeud doit se presenter une seule fois, pas a chaque Version recu"
    );
    assert_eq!(veracks, 1, "un seul accuse de reception");
    assert!(
        getaddr >= 1,
        "la poignee de main ne s'est pas conclue : aucun GetAddr"
    );
    a.shutdown();
}

/// La diversite de groupe s'applique aussi aux entrants IPv6.
///
/// Le plafond `ENTRANTS_PAR_GROUPE` n'etait calcule que pour l'IPv4 : toute
/// connexion IPv6 tombait dans « pas de groupe ». Un seul `/64` — le lot de
/// n'importe quel serveur loue — pouvait occuper toutes les places entrantes
/// d'un noeud ecoutant sur `[::]`.
///
/// Le bac a sable n'a pas d'IPv6 : on ne peut pas ouvrir
/// `ENTRANTS_PAR_GROUPE + 1` connexions depuis `::1`. On eprouve donc la
/// fonction de groupe elle-meme, celle que l'admission applique — l'epreuve
/// d'admission sur des pairs a l'adresse choisie est dans `net.rs`
/// (`l_admission_borne_aussi_les_entrants_ipv6`).
#[test]
fn la_diversite_de_groupe_s_applique_aussi_en_ipv6() {
    // ENTRANTS_PAR_GROUPE + 1 adresses d'un meme /64 : un seul groupe.
    let groupes: HashSet<Option<GroupeReseau>> = (1..=ENTRANTS_PAR_GROUPE as u16 + 1)
        .map(|k| {
            let a: SocketAddr = format!("[2001:db8:1:2::{k:x}]:21021").parse().unwrap();
            groupe_entrant(a)
        })
        .collect();
    assert_eq!(groupes.len(), 1, "un /64 doit former un seul groupe");
    let seul = groupes.into_iter().next().unwrap();
    assert!(
        seul.is_some(),
        "une adresse IPv6 publique doit avoir un groupe : sans lui, le plafond \
         de {ENTRANTS_PAR_GROUPE} par groupe ne s'applique pas"
    );
    assert_eq!(
        seul,
        Some(GroupeReseau::V6([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2])),
        "le groupe IPv6 est le /64 : les huit premiers octets"
    );

    // Un autre /64 du meme /48 : un autre groupe.
    let voisin: SocketAddr = "[2001:db8:1:3::1]:21021".parse().unwrap();
    assert_ne!(groupe_entrant(voisin), seul);

    // Une IPv4 presentee en IPv6 (ecoute sur `[::]`) reste une IPv4 de son
    // /16 : sinon tout l'Internet v4 tomberait dans un seul /64.
    let mappee: SocketAddr = "[::ffff:203.0.113.7]:21021".parse().unwrap();
    let v4: SocketAddr = "203.0.113.200:21021".parse().unwrap();
    assert_eq!(groupe_entrant(mappee), groupe_entrant(v4));
    assert_eq!(groupe_entrant(v4), Some(GroupeReseau::V4([203, 0])));

    // La boucle locale n'est un groupe dans aucune famille.
    assert_eq!(groupe_entrant("[::1]:21021".parse().unwrap()), None);
    assert_eq!(groupe_entrant("127.0.0.1:21021".parse().unwrap()), None);
    assert_eq!(
        groupe_entrant("[::ffff:127.0.0.1]:21021".parse().unwrap()),
        None
    );
}
