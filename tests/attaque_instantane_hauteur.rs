//! ATTAQUE (red-team 8b, 2e campagne) — plantage a distance d'un noeud en
//! synchronisation rapide par une hauteur d'instantane demesuree.
//!
//! Un noeud qui adopte un instantane (`--adopter-empreinte`) recoit de son pair
//! un `Snapshot` decode, dont le champ `height` n'est valide qu'a l'interieur
//! de la boucle d'authentification. Auparavant, la capacite du vecteur de chemin
//! etait reservee AVANT cette boucle, a `instantane.height as usize + 1`. Une
//! hauteur adverse de `u64::MAX` faisait deborder l'addition — donc, sous
//! `overflow-checks` et `panic = "abort"`, AVORTER le processus : un plantage
//! fiable de tout nouveau noeud se synchronisant depuis ce pair.
//!
//! Correction : la capacite est bornee au nombre d'en-tetes reellement fournis.
//! Une hauteur demesuree ne provoque plus qu'un refus propre.

use q21_core::address::Network;
use q21_core::chain::{AdoptionError, Chain};
use q21_core::hash::Hash256;
use q21_core::state::Snapshot;
use q21_core::utxo::UtxoSet;

#[test]
fn une_hauteur_d_instantane_demesuree_est_refusee_sans_planter() {
    let tete = Hash256([0x11; 32]);

    // Un instantane dont la hauteur est maximale — ce qu'un pair adverse pose.
    // On aligne `tip` et l'empreinte sur les valeurs de confiance pour franchir
    // les deux premiers controles et atteindre la ligne autrefois vulnerable.
    let instantane = Snapshot {
        network: Network::Testnet,
        height: u64::MAX,
        tip: tete,
        emis: 0,
        utxo: UtxoSet::new(),
        muhash: Hash256([0x22; 32]),
    };
    let empreinte = instantane.empreinte();

    // Aucun en-tete fourni : la boucle d'authentification echoue de toute facon,
    // mais la capacite du vecteur est calculee AVANT elle. Sans la correction,
    // `u64::MAX as usize + 1` deborde et le processus avorte ici meme.
    let r = Chain::adopter_instantane(Network::Testnet, instantane, &[], tete, empreinte);

    assert_eq!(
        r.err(),
        Some(AdoptionError::EntetesInauthentiques),
        "une hauteur demesuree doit valoir un refus propre, jamais un avortement"
    );
}
