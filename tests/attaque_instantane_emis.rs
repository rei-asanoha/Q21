//! ATTAQUE (red-team 8b, 2e campagne, point 6c) — un instantane au total emis
//! reecrit, sous la bonne empreinte.
//!
//! L'empreinte que l'on recopie pour adopter un instantane etait le MuHash du
//! jeu d'UTXO, et rien d'autre. Or le total emis n'en decoule pas : un pair
//! pouvait servir l'instantane authentique avec un total emis reecrit — dans la
//! plage que les invariants tolerent —, et il passait la comparaison a la
//! valeur de confiance. L'affichage de la masse monetaire etait faux, et la
//! borne du plafond se calculait sur un total faux.
//!
//! Correction : l'empreinte d'etat lie le MuHash et le total emis. Le MuHash ne
//! change pas, le format de l'instantane non plus ; seule la valeur que l'on
//! compare en derive.

use q21_core::chain::{genesis_block, AdoptionError, Chain, GENESIS_TIME};
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::state::empreinte_etat;
use q21_core::Network;

const RESEAU: Network = Network::Regtest;
const ESSAIS: u64 = 50_000_000;

fn chaine_minee(n: u64) -> Chain {
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

#[test]
fn un_total_emis_reecrit_ne_passe_plus_sous_l_empreinte_de_confiance() {
    let chain = chaine_minee(20);
    let honnete = chain.snapshot_at_depth(5).expect("instantane");
    let entetes = chain.headers();

    // Ce qu'une source de confiance affiche pour cette hauteur : l'empreinte
    // d'etat d'un noeud complet a cette meme tete.
    let confiance = honnete.empreinte();

    // L'attaque : le meme jeu, le meme MuHash, un total emis reecrit.
    let mut falsifie = honnete.clone();
    falsifie.emis += 1;
    assert_eq!(
        falsifie.muhash, honnete.muhash,
        "le MuHash seul ne voit pas le total emis : c'etait la faille"
    );
    assert_ne!(
        falsifie.empreinte(),
        confiance,
        "l'empreinte d'etat, elle, change avec le total emis"
    );

    let r = Chain::adopter_instantane(RESEAU, falsifie, &entetes, honnete.tip, confiance);
    assert_eq!(
        r.err(),
        Some(AdoptionError::EmpreinteInattendue),
        "un instantane au total emis reecrit doit etre refuse sous l'empreinte de confiance"
    );

    // Le temoin : l'instantane honnete s'adopte toujours sous la meme valeur.
    let r = Chain::adopter_instantane(RESEAU, honnete.clone(), &entetes, honnete.tip, confiance);
    assert!(
        r.is_ok(),
        "l'instantane honnete doit s'adopter : {:?}",
        r.err()
    );

    // Et ce qu'un noeud complet affiche a cette hauteur est bien cette valeur,
    // par construction : la chaine ramenee a la hauteur de l'instantane porte
    // la meme empreinte d'etat que lui.
    let mut temoin = chain;
    while temoin.height() > honnete.height {
        assert!(temoin.disconnect());
    }
    assert_eq!(temoin.empreinte_etat(), confiance);
    assert_eq!(
        temoin.empreinte_etat(),
        empreinte_etat(temoin.utxo_commitment(), temoin.total_issued().units())
    );
}
