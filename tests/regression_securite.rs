//! Épreuves de non-régression issues de l'audit adverse de la phase 8.
//!
//! Chaque test de ce fichier a d'abord existé sous forme d'**exploit**, écrit
//! par un auditeur qui cherchait à casser Q21, et qui a réussi. Le test a
//! ensuite été retourné : il vérifie désormais que l'attaque échoue.
//!
//! Un correctif sans le test qui l'accompagne n'est pas un correctif : c'est un
//! pari sur le fait que personne ne réintroduira le défaut.

use q21_core::address::Network;
use q21_core::block::{Block, BlockHeader};
use q21_core::chain::{genesis_block, Chain, ChainError, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::emission::block_subsidy;
use q21_core::hash::Hash256;
use q21_core::memhard::{epoch_of, PowTable, TableParams};
use q21_core::pow::{self, PowEngine, Q21Pow};
use q21_core::sig::SchemeId;
use q21_core::validate::{self, BlockContext, ValidationError};
use std::collections::{HashMap, HashSet};

const RESEAU: Network = Network::Regtest;

/// Fournisseur de corps en mémoire : tient le rôle du fichier de blocs.
struct CorpsDeLaChaine(HashMap<Hash256, Block>);
impl q21_core::chain::BodySource for CorpsDeLaChaine {
    fn body(&self, id: &Hash256) -> Option<Block> {
        self.0.get(id).cloned()
    }
}
const ESSAIS: u64 = 50_000_000;

fn horodatage(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

fn remine(b: &mut Block) {
    b.header.merkle_root = b.compute_merkle_root();
    b.header.uncles_root = b.compute_uncles_root();
    b.header.nonce = 0;
    let t = PowTable::build(TableParams::for_network(RESEAU), epoch_of(b.header.height));
    pow::mine_with_table(&mut b.header, &t, ESSAIS).expect("re-minage");
}

fn chaine(n: u64) -> Chain {
    let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
    for i in 1..=n {
        let t = horodatage(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
    }
    c
}

/// En-tête d'oncle fabriqué sans le moindre calcul : cible quasi maximale,
/// nonce à zéro. C'est exactement ce que l'audit a exploité.
fn faux_oncle(prev: Hash256, hauteur_oncle: u64, sel: u8) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block: prev,
        merkle_root: Hash256([sel; 32]),
        uncles_root: Hash256::ZERO,
        miner: Hash256([0xaa; 32]),
        time: horodatage(hauteur_oncle),
        bits: 0x2100_ffff,
        height: hauteur_oncle,
        nonce: 0,
    }
}

/// Une chaîne de hauteur `n`, plus un oncle **authentique** à la hauteur `n` :
/// un vrai bloc, réellement miné, qui a perdu la course de propagation.
///
/// On mine deux blocs concurrents sur le même parent, on en connecte un, et
/// l'autre devient l'orphelin que le bloc suivant pourra réclamer.
fn chaine_avec_oncle(n: u64) -> (Chain, BlockHeader) {
    let mut c = chaine(n - 1);
    let t = horodatage(n);

    let perdant = c
        .mine_block(Hash256([0xbb; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
        .expect("minage du perdant");
    let gagnant = c
        .mine_block(Hash256([0x2a; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
        .expect("minage du gagnant");
    assert_ne!(perdant.header.block_id(), gagnant.header.block_id());

    c.connect(&gagnant, t + 1).expect("connexion du gagnant");
    (c, perdant.header)
}

// ---------------------------------------------------------------------------
// 1. Un oncle doit porter la difficulté de sa hauteur
// ---------------------------------------------------------------------------

/// L'exploit d'origine : `pow.check(oncle)` validait le travail contre
/// `oncle.bits`, un champ que son auteur remplit. Avec une cible quasi
/// maximale, un en-tête à nonce zéro passait — et se faisait payer.
#[test]
fn un_oncle_sans_travail_est_refuse() {
    let mut c = chaine(4);
    let hauteur = c.height() + 1;
    let parent = c.tip_id();

    let oncles: Vec<BlockHeader> = (0..MAX_UNCLES as u8)
        .map(|k| faux_oncle(parent, hauteur - 1, k))
        .collect();

    // La preuve de travail « passe » toujours contre la cible que l'attaquant a
    // choisie : c'est bien la comparaison de difficulté qui protège, pas elle.
    assert!(
        Q21Pow::new(RESEAU).check(&oncles[0]).is_ok(),
        "le montage de l'attaque doit rester valide"
    );

    let t = horodatage(hauteur);
    let b = c
        .mine_block_with_uncles(
            Hash256([2u8; 32]),
            SchemeId::LamportOts,
            &[],
            &oncles,
            t,
            ESSAIS,
        )
        .expect("minage");

    match c.connect(&b, t + 1) {
        Err(ValidationError::DifficulteDOncleInvalide { .. }) => {}
        autre => panic!("l'oncle sans travail aurait dû être refusé : {autre:?}"),
    }
}

// ---------------------------------------------------------------------------
// 2. Un bloc émet exactement sa subvention, oncles compris
// ---------------------------------------------------------------------------

/// La faille la plus grave de l'audit : les parts d'oncles étaient **ajoutées**
/// à la subvention. Un bloc pouvait émettre 210 % de son dû, et l'émission
/// maximale réelle du protocole s'établissait à 44 099 999 Q21.
#[test]
fn un_bloc_emet_exactement_sa_subvention_meme_avec_des_oncles() {
    for n_oncles in 0..=MAX_UNCLES {
        let r = validate::uncle_rewards(1_000, n_oncles);
        let total = r.part_mineur + r.par_oncle * n_oncles as u64;
        assert_eq!(
            total,
            block_subsidy(1_000).units(),
            "avec {n_oncles} oncle(s), le total émis doit rester la subvention"
        );
    }
}

/// La même propriété, mesurée sur une chaîne réelle avec un oncle authentique.
#[test]
fn l_emission_reelle_ne_depasse_jamais_la_subvention() {
    let (mut c, oncle) = chaine_avec_oncle(4);

    let hauteur = c.height() + 1;
    let avant = c.total_issued().units();
    let t = horodatage(hauteur);
    let b = c
        .mine_block_with_uncles(
            Hash256([2u8; 32]),
            SchemeId::LamportOts,
            &[],
            &[oncle],
            t,
            ESSAIS,
        )
        .expect("minage");
    c.connect(&b, t + 1)
        .expect("un oncle authentique est valide");

    let emis = c.total_issued().units() - avant;
    assert_eq!(
        emis,
        block_subsidy(hauteur).units(),
        "un bloc avec oncle a émis {emis} au lieu de sa subvention"
    );
}

// ---------------------------------------------------------------------------
// 3. Le plafond absolu
// ---------------------------------------------------------------------------

/// Le dernier rempart : quoi qu'affirment le calendrier d'émission et les
/// oncles, aucun bloc ne peut porter l'émission cumulée au-delà de
/// 21 000 001 Q21.
#[test]
fn aucun_bloc_ne_franchit_le_plafond_absolu() {
    let c = chaine(2);
    let hauteur = c.height() + 1;
    let t = horodatage(hauteur);
    let b = c
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
        .expect("minage");

    let emission = b.transactions[0].total_output().unwrap().units();
    assert!(emission > 0);

    let times: Vec<u64> = vec![t - 1];
    let anc: Vec<Hash256> = vec![c.tip_id()];
    let claimed: HashSet<Hash256> = HashSet::new();
    let mut bits = HashMap::new();
    bits.insert(c.tip_id(), INITIAL_BITS);

    // Juste sous le plafond : le bloc passe.
    let ctx_ok = BlockContext {
        network: RESEAU,
        height: hauteur,
        prev_id: c.tip_id(),
        recent_times: &times,
        expected_bits: INITIAL_BITS,
        now: t + 1,
        ancestors: &anc,
        claimed_uncles: &claimed,
        uncle_expected_bits: &bits,
        cumul_emis: MAX_SUPPLY - emission,
    };
    assert!(
        validate::check_block(&b, &c.utxo, &ctx_ok, &Q21Pow::new(RESEAU)).is_ok(),
        "le bloc qui atteint exactement le plafond doit passer"
    );

    // Un seul satoshi de plus : refusé.
    let ctx_ko = BlockContext {
        cumul_emis: MAX_SUPPLY - emission + 1,
        ..ctx_ok
    };
    match validate::check_block(&b, &c.utxo, &ctx_ko, &Q21Pow::new(RESEAU)) {
        Err(ValidationError::PlafondDepasse { plafond, .. }) => {
            assert_eq!(plafond, MAX_SUPPLY);
        }
        autre => panic!("le plafond doit être infranchissable : {autre:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. Unicité des identifiants de coinbase (BIP 30 / BIP 34)
// ---------------------------------------------------------------------------

/// Deux coinbases du même mineur, pour le même montant, produisaient le même
/// `txid`. La seconde écrasait la première dans le jeu d'UTXO, et la défaire
/// détruisait la sortie de la première : deux nœuds honnêtes finissaient avec
/// la même tête et des soldes différents.
#[test]
fn deux_coinbases_de_hauteurs_differentes_ont_des_identifiants_differents() {
    let mut c = chaine(3);
    let mut vus: HashSet<Hash256> = HashSet::new();

    for _ in 0..5 {
        let hauteur = c.height() + 1;
        let t = horodatage(hauteur);
        // Même bénéficiaire, même montant réclamé : tout est identique sauf la
        // hauteur, qui est désormais engagée dans l'identifiant.
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        let txid = b.transactions[0].txid();
        assert!(
            vus.insert(txid),
            "deux coinbases partagent l'identifiant {txid} : BIP 30 est ouvert"
        );
        c.connect(&b, t + 1).expect("connexion");
    }
}

/// Et la règle qui garantit cette unicité est vérifiée, pas espérée.
#[test]
fn une_coinbase_sans_hauteur_est_refusee() {
    let mut c = chaine(2);
    let hauteur = c.height() + 1;
    let t = horodatage(hauteur);
    let mut b = c
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
        .expect("minage");

    b.transactions[0].inputs[0].witness.signature = b"pas la hauteur".to_vec();
    remine(&mut b);

    assert!(matches!(
        c.connect(&b, t + 1),
        Err(ValidationError::CoinbaseSansHauteur)
    ));
}

// ---------------------------------------------------------------------------
// 5. Une branche latérale doit coûter du travail
// ---------------------------------------------------------------------------

/// Sans contrôle de difficulté, `submit` indexait des en-têtes fabriqués avec
/// une cible quasi maximale : mémoire épuisée gratuitement, et éviction des
/// corps dont dépendent les réorganisations.
#[test]
fn une_branche_laterale_sans_travail_est_refusee() {
    let mut c = chaine(5);
    // On bifurque d'un bloc ancien : c'est le chemin « branche latérale » de
    // `submit`, celui que l'attaque exploitait.
    let parent = c.active_at(2).expect("ancêtre");
    let hauteur = 3;
    let connus_avant = c.known_blocks();

    for k in 0..50u8 {
        let entete = BlockHeader {
            version: 1,
            prev_block: parent,
            merkle_root: Hash256([k; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([0xcc; 32]),
            time: horodatage(hauteur),
            bits: 0x2100_ffff,
            height: hauteur,
            nonce: u64::from(k),
        };
        let bloc = Block {
            header: entete,
            transactions: vec![],
            uncles: vec![],
        };
        assert!(
            matches!(
                c.submit(&bloc, horodatage(hauteur) + 1),
                Err(ChainError::Validation(
                    ValidationError::DifficulteIncorrecte { .. }
                ))
            ),
            "une branche sans travail ne doit jamais entrer dans l'index"
        );
    }
    assert_eq!(
        c.known_blocks(),
        connus_avant,
        "l'index a grossi malgré le refus"
    );
}

// ---------------------------------------------------------------------------
// 6. `disconnect` ne corrompt rien quand il refuse
// ---------------------------------------------------------------------------

/// La version fautive écrasait le compteur d'émission **avant** de constater
/// qu'aucune annulation n'était disponible.
#[test]
fn un_disconnect_refuse_ne_touche_a_rien() {
    let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
    let emis_avant = c.total_issued();
    let hauteur_avant = c.height();
    let utxo_avant = c.utxo.clone();

    // À la genèse, il n'y a rien à défaire.
    assert!(!c.disconnect());

    assert_eq!(c.total_issued(), emis_avant, "émission modifiée");
    assert_eq!(c.height(), hauteur_avant, "hauteur modifiée");
    assert_eq!(c.utxo, utxo_avant, "jeu d'UTXO modifié");
}

// ---------------------------------------------------------------------------
// 7. Aucune boucle infinie de réorganisation
// ---------------------------------------------------------------------------

/// `try_reorg` jetait la valeur de retour de `disconnect`. Après une reprise sur
/// instantané, la boucle de restauration ne progressait jamais et le nœud
/// tournait indéfiniment, verrou de chaîne tenu.
///
/// Le test tourne dans un fil à part avec un délai : s'il boucle, il échoue.
#[test]
fn une_reorganisation_impossible_echoue_au_lieu_de_boucler() {
    let (envoi, reception) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // Un nœud qui vient de reprendre sur instantané : sa fenêtre
        // d'annulation ne couvre que ce qu'il a rejoué.
        let complete = chaine(6);
        let instantane = complete.snapshot_at_depth(1).expect("instantané");
        let entetes: Vec<BlockHeader> = (0..=complete.height())
            .filter_map(|h| complete.active_at(h))
            .filter_map(|id| complete.header_of(&id))
            .collect();
        let r = Chain::from_snapshot(RESEAU, instantane, &entetes).expect("reprise");
        let mut c = r.chain;
        // Comme un vrai nœud : les corps anciens restent lisibles sur disque.
        c.set_body_source(std::sync::Arc::new(CorpsDeLaChaine(
            (0..=complete.height())
                .filter_map(|h| complete.active_at(h))
                .filter_map(|id| complete.block_by_id(&id).map(|b| (id, b)))
                .collect(),
        )));
        for id in &r.a_rejouer {
            let b = complete.block_by_id(id).expect("corps");
            c.connect(&b, b.header.time + 1).expect("rejeu");
        }
        assert_eq!(c.undo_window(), 1, "fenêtre d'annulation d'un seul bloc");

        let parent = c.active_at(3).expect("ancêtre");
        let mut branche = Vec::new();
        let mut prev = parent;
        for h in 4..=8u64 {
            let mut b = Block {
                header: BlockHeader {
                    version: 1,
                    prev_block: prev,
                    merkle_root: Hash256::ZERO,
                    uncles_root: Hash256::ZERO,
                    miner: Hash256([0xdd; 32]),
                    time: horodatage(h) + 1,
                    bits: INITIAL_BITS,
                    height: h,
                    nonce: 0,
                },
                transactions: vec![],
                uncles: vec![],
            };
            b.header.nonce = 0;
            let t = PowTable::build(TableParams::for_network(RESEAU), epoch_of(h));
            pow::mine_with_table(&mut b.header, &t, ESSAIS).expect("minage");
            prev = b.header.block_id();
            branche.push(b);
        }

        let mut refuse = false;
        for b in &branche {
            if let Err(e) = c.submit(b, horodatage(9)) {
                refuse = matches!(e, ChainError::FenetreDAnnulationInsuffisante { .. });
            }
        }
        let _ = envoi.send(refuse);
    });

    match reception.recv_timeout(std::time::Duration::from_secs(60)) {
        Ok(refuse) => assert!(
            refuse,
            "la réorganisation impossible aurait dû être refusée explicitement"
        ),
        Err(_) => panic!("try_reorg boucle indéfiniment : le fil n'a jamais rendu la main"),
    }
}

// ---------------------------------------------------------------------------
// 8. Un oncle déjà payé le reste après un redémarrage sur instantané
// ---------------------------------------------------------------------------

/// La règle anti-double-paiement lisait les corps de blocs **en mémoire**.
/// Après une reprise sur instantané ils sont absents : l'ensemble des oncles
/// déjà réclamés était incomplet, et un nœud fraîchement redémarré acceptait ce
/// qu'un nœud complet refusait. Deux nœuds honnêtes, deux verdicts — scission.
#[test]
fn un_oncle_deja_paye_reste_refuse_apres_une_reprise() {
    // Une chaîne où l'oncle de hauteur 4 a été réclamé par le bloc 5.
    let (mut complete, oncle) = chaine_avec_oncle(4);
    let t5 = horodatage(5);
    let b5 = complete
        .mine_block_with_uncles(
            Hash256([2u8; 32]),
            SchemeId::LamportOts,
            &[],
            &[oncle],
            t5,
            ESSAIS,
        )
        .expect("minage");
    complete
        .connect(&b5, t5 + 1)
        .expect("le bloc 5 paie l'oncle");

    let t6 = horodatage(6);
    let b6 = complete
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t6, ESSAIS)
        .expect("minage");
    complete.connect(&b6, t6 + 1).expect("connexion");

    // Le nœud complet refuse de repayer le même oncle.
    let t7 = horodatage(7);
    let rejoue = complete
        .mine_block_with_uncles(
            Hash256([2u8; 32]),
            SchemeId::LamportOts,
            &[],
            &[oncle],
            t7,
            ESSAIS,
        )
        .expect("minage");
    assert!(
        matches!(
            complete.connect(&rejoue, t7 + 1),
            Err(ValidationError::OncleDejaReclame(_))
        ),
        "le nœud complet doit refuser de repayer un oncle"
    );

    // Un nœud repris sur instantané doit rendre le MÊME verdict.
    let instantane = complete.snapshot_at_depth(1).expect("instantané");
    let entetes: Vec<BlockHeader> = (0..=complete.height())
        .filter_map(|h| complete.active_at(h))
        .filter_map(|id| complete.header_of(&id))
        .collect();
    let r = Chain::from_snapshot(RESEAU, instantane, &entetes).expect("reprise");
    let mut repris = r.chain;
    repris.set_body_source(std::sync::Arc::new(CorpsDeLaChaine(
        (0..=complete.height())
            .filter_map(|h| complete.active_at(h))
            .filter_map(|id| complete.block_by_id(&id).map(|b| (id, b)))
            .collect(),
    )));
    for id in &r.a_rejouer {
        let b = complete.block_by_id(id).expect("corps");
        repris.connect(&b, b.header.time + 1).expect("rejeu");
    }
    assert_eq!(repris.height(), complete.height());

    match repris.connect(&rejoue, t7 + 1) {
        Err(ValidationError::OncleDejaReclame(_)) => {}
        autre => panic!(
            "un nœud repris a rendu un verdict différent d'un nœud complet : {autre:?} \
             — c'est exactement ainsi qu'une chaîne se scinde"
        ),
    }
}

// ---------------------------------------------------------------------------
// 9. Le nombre de transactions par bloc est dérivé, pas posé à la main
// ---------------------------------------------------------------------------

/// La borne valait 500 000, choisie arbitrairement : une annonce compacte de
/// trois mégaoctets déclenchait une allocation de plusieurs dizaines de
/// mégaoctets. Elle découle désormais de la taille maximale d'un bloc.
#[test]
fn le_nombre_de_transactions_par_bloc_est_borne_par_la_taille_du_bloc() {
    assert_eq!(MAX_TX_PAR_BLOC, MAX_BLOCK_SIZE / MIN_TX_SIZE);
    // Vérifiées à la compilation : ce sont des invariants sur des constantes,
    // pas des observations à l'exécution.
    const _: () = assert!(MAX_TX_PAR_BLOC * MIN_TX_SIZE <= MAX_BLOCK_SIZE);
    // L'allocation qu'un adversaire peut provoquer reste du même ordre que ce
    // qu'il envoie : six octets d'identifiant court par entrée annoncée.
    const _: () = assert!(MAX_TX_PAR_BLOC <= 100_000);
}
