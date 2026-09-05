//! Épreuves de non-régression de la seconde vague d'audit (phase 8b).
//!
//! Cinq auditeurs ont travaillé sur cinq axes que la première vague n'avait pas
//! couverts : difficulté et économie du minage, arithmétique et sérialisation,
//! réservoir de transactions, surface RPC, persistance. Ce fichier verrouille
//! les corrections qui en sont sorties.

use q21_core::address::Network;
use q21_core::block::BlockHeader;
use q21_core::chain::{genesis_block, next_bits, Chain, ChainError, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::memhard::{self, epoch_of, TableParams};
use q21_core::pow;
use q21_core::sig::SchemeId;
use q21_core::validate::ValidationError;

const RESEAU: Network = Network::Regtest;
const ESSAIS: u64 = 50_000_000;

fn entetes(n: usize, pas: impl Fn(usize) -> u64) -> Vec<BlockHeader> {
    let mut v = Vec::with_capacity(n);
    let mut t = GENESIS_TIME;
    for h in 0..n {
        t += pas(h);
        v.push(BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            uncles_root: Hash256::ZERO,
            miner: Hash256::ZERO,
            time: t,
            bits: INITIAL_BITS,
            height: h as u64,
            nonce: 0,
        });
    }
    v
}

// ---------------------------------------------------------------------------
// 1. Le temps de résolution est signé
// ---------------------------------------------------------------------------

/// L'attaque mesurée : un mineur inscrivant `parent + 6T` injectait à chaque
/// bloc du temps apparent que rien ne venait soustraire. Avec 20 % de la
/// puissance, la difficulté s'effondrait de 97,3 %.
///
/// Avec un temps de résolution signé, le temps avancé est rendu par le bloc
/// suivant. Ce test le vérifie directement sur `next_bits`.
#[test]
fn avancer_les_horodatages_ne_fait_plus_chuter_la_difficulte() {
    let t = TARGET_BLOCK_SECS;
    // Chaîne honnête : chaque bloc met exactement T.
    let honnete = next_bits(&entetes(91, |_| t));

    // Un bloc sur cinq inscrit parent + 6T, les autres rattrapent (donc un
    // temps de résolution réel négatif du point de vue des horodatages).
    let attaquee = next_bits(&entetes(91, |h| if h % 5 == 0 { 6 * t } else { 0 }));

    let cible_h = pow::target_from_compact(honnete).unwrap();
    let cible_a = pow::target_from_compact(attaquee).unwrap();
    assert!(
        cible_a <= cible_h.mul_div(150, 100).unwrap(),
        "la difficulté a chuté de plus de 50 % sous manipulation d'horodatage"
    );
}

/// La borne symétrique doit aussi protéger dans l'autre sens : une suite
/// d'horodatages reculés ne doit pas faire exploser la difficulté d'un coup.
#[test]
fn reculer_les_horodatages_ne_fait_pas_exploser_la_difficulte() {
    let bits = next_bits(&entetes(91, |_| 0));
    let cible = pow::target_from_compact(bits).unwrap();
    assert!(!cible.is_zero(), "la cible ne doit jamais tomber à zéro");
    // Le plancher de la somme pondérée (5 % de la durée attendue) borne la
    // hausse : au pire un facteur MAX_TARGET_CHANGE par bloc.
    let reference = pow::target_from_compact(INITIAL_BITS).unwrap();
    assert!(cible >= reference.checked_div_u64(MAX_TARGET_CHANGE * 2).unwrap());
}

/// La tolérance d'horodatage futur a été ramenée de deux heures à vingt
/// minutes : avec un ajustement à chaque bloc, deux heures étaient un levier.
#[test]
fn la_tolerance_d_horodatage_futur_est_adaptee_a_un_ajustement_par_bloc() {
    assert_eq!(MAX_FUTURE_TIME, 20 * 60);
    // Verifie a la compilation : la tolerance doit rester du meme ordre que la
    // borne de resolution.
    const _: () = assert!(MAX_FUTURE_TIME < 6 * TARGET_BLOCK_SECS * 2);
}

// ---------------------------------------------------------------------------
// 2. La pénalité de réorganisation porte sur la fourche, pas sur l'histoire
// ---------------------------------------------------------------------------

/// La pénalité multipliait le travail **cumulé depuis la genèse**. Dès la
/// hauteur 71 400 — trois mois après le lancement — aucune réorganisation de
/// profondeur 7 ne pouvait plus aboutir, même avec 100 % de la puissance. La
/// finalité réelle était de six blocs, pas de 720.
#[test]
fn une_reorganisation_profonde_reste_possible_sur_une_longue_chaine() {
    let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
    for i in 1..=40u64 {
        let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
    }

    // Une branche concurrente partant de la hauteur 30 : profondeur 10, donc
    // au-delà du seuil de gratuité (6). Elle doit pouvoir l'emporter avec un
    // surplus de travail raisonnable — quelques blocs, pas des centaines.
    let fourche = c.active_at(30).expect("ancêtre");
    let profondeur = c.height() - 30;
    let requis = c.travail_requis_pour_reorg(30, profondeur);
    let travail_actif = c.total_work();

    // Le surplus exigé doit être de l'ordre du travail de la fourche, pas de
    // celui de toute la chaîne.
    let surplus = requis.checked_sub(travail_actif).unwrap_or_default();
    let un_bloc = pow::block_work(INITIAL_BITS);
    let blocs_de_surplus = surplus
        .div_rem(un_bloc)
        .map(|(q, _)| q.low_u64())
        .unwrap_or(u64::MAX);

    assert!(
        blocs_de_surplus <= profondeur,
        "il faut {blocs_de_surplus} blocs de surplus pour une fourche de \
         profondeur {profondeur} : la pénalité porte encore sur toute l'histoire"
    );
    let _ = fourche;
}

// ---------------------------------------------------------------------------
// 3. La preuve de travail refuse un cache d'une autre époque
// ---------------------------------------------------------------------------

/// `hash_verify_avec_cache` acceptait n'importe quel cache sans contrôler son
/// époque, et rendait alors un condensat différent **en silence**. Deux nœuds,
/// l'un à jour et l'autre non, auraient rendu deux verdicts opposés sur le même
/// bloc.
#[test]
fn un_cache_d_une_autre_epoque_ne_fausse_pas_le_verdict() {
    let params = TableParams::for_network(RESEAU);
    let entete = BlockHeader {
        version: 1,
        prev_block: Hash256::ZERO,
        merkle_root: Hash256([7u8; 32]),
        uncles_root: Hash256::ZERO,
        miner: Hash256([9u8; 32]),
        time: GENESIS_TIME,
        bits: INITIAL_BITS,
        height: POW_EPOCH_BLOCKS, // époque 1
        nonce: 0,
    };
    assert_eq!(epoch_of(entete.height), 1);

    let cache_perime = memhard::cache_for(params, 0);
    let attendu = memhard::hash_verify(&entete, params);
    let avec_cache_perime = memhard::hash_verify_avec_cache(&entete, params, &cache_perime);

    assert_eq!(
        avec_cache_perime, attendu,
        "un cache périmé a produit un condensat différent, en silence"
    );
}

// ---------------------------------------------------------------------------
// 4. Une hauteur arbitraire ne fait plus construire un cache arbitraire
// ---------------------------------------------------------------------------

/// L'époque de la preuve de travail se dérive de `header.height`. Un en-tête
/// annonçant une hauteur quelconque faisait construire le cache — puis la
/// table — de l'époque correspondante : environ dix secondes de cache et cinq
/// minutes de table sur le réseau principal, pour un message de 160 octets.
#[test]
fn une_hauteur_incoherente_est_refusee_avant_tout_calcul() {
    let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
    for i in 1..=3u64 {
        let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
    }

    let mut b = c
        .mine_block(
            Hash256([2u8; 32]),
            SchemeId::LamportOts,
            &[],
            GENESIS_TIME + 4 * TARGET_BLOCK_SECS,
            ESSAIS,
        )
        .expect("minage");
    // Hauteur absurde : très loin dans le futur, donc une époque très lointaine.
    b.header.height = 4_000_000_000;

    let debut = std::time::Instant::now();
    let verdict = c.submit(&b, GENESIS_TIME + 5 * TARGET_BLOCK_SECS);
    let duree = debut.elapsed();

    assert!(
        matches!(
            verdict,
            Err(ChainError::Validation(
                ValidationError::HauteurIncorrecte { .. }
            ))
        ),
        "une hauteur incohérente doit être refusée : {verdict:?}"
    );
    assert!(
        duree < std::time::Duration::from_millis(200),
        "le refus a coûté {duree:?} : un calcul a été engagé avant le contrôle"
    );
}
