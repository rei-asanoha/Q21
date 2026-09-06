//! Elagage du fichier de blocs.
//!
//! # Pourquoi
//!
//! Le fichier de blocs ne faisait que grossir. Un noeud qui valide pour lui —
//! un portefeuille, un mineur sur Raspberry — n'a pourtant besoin que de ce
//! qu'il peut encore defaire (la fenetre de reorganisation) et de ce que son
//! historique affiche : tout ce qui precede se resume dans l'instantane. Une
//! carte SD ne tient pas dix ans de corps ; elle tient dix ans d'instantanes.
//!
//! # Ce qui rend l'elagage sur : l'ordre des ecritures
//!
//! Un noeud elague est, au redemarrage, dans la situation exacte d'un noeud
//! qui a adopte un instantane : il repart de l'etat enregistre, relit ses
//! en-tetes dans le magasin d'en-tetes, et rejoue les corps posterieurs a
//! l'instantane. Trois choses doivent donc etre vraies **avant** de retirer
//! un seul corps :
//!
//! 1. l'instantane vient d'etre ecrit — l'appelant l'assure, [`elaguer`] est
//!    appelee juste apres ;
//! 2. le magasin d'en-tetes couvre la genese jusqu'a la hauteur de
//!    l'instantane — on le complete ici, et si cela echoue on n'elague pas ;
//! 3. les corps posterieurs a l'instantane restent — la fenetre conservee
//!    depasse largement le recul de l'instantane, et c'est verifie ici.
//!
//! La reecriture du fichier ne prend pas le verrou de la chaine plus
//! longtemps que la lecture des en-tetes ; l'archive serialise elle-meme ses
//! lectures et ecritures.
//!
//! # Ce qu'un noeud elague ne peut plus faire
//!
//! Servir d'explorateur (l'index d'adresses renvoie a des corps qu'il n'a
//! plus), et revalider son histoire sans qu'on lui fournisse les corps d'un
//! noeud complet. Il verifie toujours tout ce qu'il recoit ; il ne garde
//! simplement pas ce qu'il ne relira jamais.

use crate::address::Network;
use crate::block::BlockHeader;
use crate::chain::Chain;
use crate::consensus::BODY_WINDOW;
use crate::store::{BlockArchive, Elagage, HeaderStore};

/// Ce qu'un noeud elague conserve, et a quel rythme il elague.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Politique {
    /// Corps conserves sous la tete.
    pub corps_conserves: u64,
    /// Blocs entre deux elagages.
    pub pas: u64,
}

/// La politique par defaut : la fenetre d'historique du portefeuille plus la
/// fenetre de reorganisation — tout ce qu'un noeud peut encore avoir a relire
/// ou a afficher —, et une reecriture tous les deux mille blocs (moins de
/// trois jours), assez pour tenir le fichier a sa taille de croisiere sans
/// le reecrire toutes les cinq minutes.
pub const POLITIQUE_DEFAUT: Politique = Politique {
    corps_conserves: crate::rpc::FENETRE_HISTORIQUE + BODY_WINDOW as u64,
    pas: 2_016,
};

/// Elague si assez de blocs se sont accumules depuis le dernier elagage.
///
/// `hauteur_instantane` est la hauteur de l'instantane **qui vient d'etre
/// ecrit** sur le disque. `derniere` est la hauteur de la tete au dernier
/// elagage, mise a jour ici.
///
/// Rend `Ok(None)` quand il n'y avait rien a faire, `Ok(Some(bilan))` apres
/// une reecriture, et une erreur — le fichier alors intact — si le magasin
/// d'en-tetes n'a pas pu etre complete ou si l'instantane ne couvre pas la
/// fenetre.
pub fn elaguer(
    chain: &Chain,
    archive: &BlockArchive,
    entetes: &HeaderStore,
    reseau: Network,
    hauteur_instantane: u64,
    politique: Politique,
    derniere: &mut u64,
) -> Result<Option<Elagage>, String> {
    let tete = chain.height();
    if tete < *derniere + politique.pas || tete <= politique.corps_conserves {
        return Ok(None);
    }
    // Garde-fou 3 : ce qui suit l'instantane doit rester. La politique par
    // defaut le garantit de loin ; une politique d'epreuve pourrait l'oublier.
    let garde = tete.saturating_sub(politique.corps_conserves);
    if hauteur_instantane < garde {
        return Err(format!(
            "l'instantane (hauteur {hauteur_instantane}) est plus ancien que la fenetre \
             conservee (a partir de {garde}) : elaguer perdrait des corps a rejouer"
        ));
    }
    *derniere = tete;

    // Garde-fou 2 : le magasin d'en-tetes, de la genese a l'instantane.
    let deja = if entetes.exists() {
        entetes
            .load(reseau)
            .map_err(|e| format!("magasin d'en-tetes illisible : {e}"))?
            .last()
            .map(|h| h.height + 1)
            .unwrap_or(0)
    } else {
        0
    };
    if deja <= hauteur_instantane {
        let nouveaux: Vec<BlockHeader> = chain
            .headers()
            .into_iter()
            .filter(|h| h.height >= deja && h.height <= hauteur_instantane)
            .collect();
        entetes
            .append(&nouveaux)
            .map_err(|e| format!("en-tetes non ecrits : {e}"))?;
    }

    // Les corps : la genese, et tout ce qui est a moins de `corps_conserves`
    // de la tete. Ce qui est plus ancien est resume dans l'instantane.
    archive
        .elaguer(|h| h.height == 0 || h.height >= garde)
        .map(Some)
        .map_err(|e| format!("reecriture du fichier de blocs : {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{genesis_block, BodySource};
    use crate::consensus::TARGET_BLOCK_SECS;
    use crate::hash::Hash256;
    use crate::sig::SchemeId;
    use crate::state::Snapshot;
    use std::path::PathBuf;
    use std::sync::Arc;

    const RESEAU: Network = Network::Regtest;

    fn dossier(nom: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("q21-elagage-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn miner(c: &mut Chain, archive: &BlockArchive, n: usize) {
        for _ in 0..n {
            let t = c.tip().time + TARGET_BLOCK_SECS;
            let b = c
                .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
                .expect("minage");
            c.connect(&b, t + 1).expect("connexion");
            archive.append(&b).unwrap();
        }
    }

    /// Un noeud elague redemarre exactement la ou il en etait.
    ///
    /// On mine une chaine, on la journalise, on l'elague avec une politique
    /// courte ; puis on la « redemarre » comme le fait le binaire : instantane,
    /// en-tetes du magasin completes par ceux des corps restants, rejeu des
    /// corps posterieurs a l'instantane depuis l'archive elaguee. La tete, le
    /// jeu d'UTXO et l'emission doivent etre ceux de la chaine d'origine — et
    /// la chaine redemarree doit pouvoir continuer.
    #[test]
    fn un_noeud_elague_redemarre_la_ou_il_en_etait() {
        let d = dossier("redemarrage");
        let (archive, _, _) = BlockArchive::open(d.join("blocks.dat"), RESEAU).unwrap();
        let archive = Arc::new(archive);
        let magasin = HeaderStore::new(d.join("entetes.dat"));

        let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
        archive.append(&genesis_block(RESEAU)).unwrap();
        miner(&mut c, &archive, 120);
        let tete = c.height();
        let instantane: Snapshot = c.snapshot_at_depth(20).expect("instantane");
        assert_eq!(instantane.height, tete - 20);

        let politique = Politique {
            corps_conserves: 40,
            pas: 10,
        };
        let mut derniere = 0;
        let bilan = elaguer(
            &c,
            &archive,
            &magasin,
            RESEAU,
            instantane.height,
            politique,
            &mut derniere,
        )
        .expect("elagage")
        .expect("il y avait a elaguer");
        // Genese + les corps de hauteur 80..=120.
        assert_eq!(bilan.conserves, 1 + 41);
        assert_eq!(bilan.retires, 120 - 41);
        assert_eq!(derniere, tete);

        // Trop tot pour recommencer.
        assert_eq!(
            elaguer(
                &c,
                &archive,
                &magasin,
                RESEAU,
                instantane.height,
                politique,
                &mut derniere
            )
            .unwrap(),
            None
        );

        // Le magasin couvre la genese jusqu'a l'instantane.
        let base = magasin.load(RESEAU).expect("magasin lisible");
        assert_eq!(base.first().map(|h| h.height), Some(0));
        assert_eq!(base.last().map(|h| h.height), Some(instantane.height));

        // --- Le redemarrage, tel que le fait le binaire.
        let (archive2, restants, souci) = BlockArchive::open(d.join("blocks.dat"), RESEAU).unwrap();
        assert!(souci.is_none());
        let h_inst = base.last().unwrap().height;
        let mut entetes = base.clone();
        let mut posterieurs: Vec<BlockHeader> = restants
            .iter()
            .copied()
            .filter(|h| h.height > h_inst)
            .collect();
        posterieurs.sort_by_key(|h| h.height);
        entetes.extend(posterieurs);

        let r = Chain::from_snapshot(RESEAU, instantane, &entetes).expect("reprise");
        let archive2 = Arc::new(archive2);
        let mut rc = r.chain;
        rc.set_body_source(archive2.clone());
        for id in &r.a_rejouer {
            let b = archive2.body(id).expect("corps posterieur a l'instantane");
            rc.connect(&b, b.header.time + 1).expect("rejeu");
        }
        assert_eq!(rc.height(), c.height());
        assert_eq!(rc.tip_id(), c.tip_id());
        assert_eq!(rc.utxo, c.utxo);
        assert_eq!(rc.total_issued(), c.total_issued());

        // Et elle continue.
        miner(&mut rc, &archive2, 1);
        assert_eq!(rc.height(), tete + 1);

        // Un second elagage, plus tard, complete le magasin sans le reecrire.
        miner(&mut rc, &archive2, 30);
        let inst2 = rc.snapshot_at_depth(5).expect("instantane");
        let bilan2 = elaguer(
            &rc,
            &archive2,
            &magasin,
            RESEAU,
            inst2.height,
            politique,
            &mut derniere,
        )
        .expect("second elagage")
        .expect("il y avait a elaguer");
        assert!(bilan2.retires > 0);
        let base2 = magasin.load(RESEAU).expect("magasin lisible");
        assert_eq!(base2.last().map(|h| h.height), Some(inst2.height));
        assert!(base2.windows(2).all(|w| w[1].height == w[0].height + 1));

        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un instantane plus ancien que la fenetre conservee est refuse : on ne
    /// jette jamais un corps qu'il faudrait rejouer.
    #[test]
    fn un_instantane_trop_ancien_empeche_l_elagage() {
        let d = dossier("trop-ancien");
        let (archive, _, _) = BlockArchive::open(d.join("blocks.dat"), RESEAU).unwrap();
        let magasin = HeaderStore::new(d.join("entetes.dat"));
        let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
        archive.append(&genesis_block(RESEAU)).unwrap();
        miner(&mut c, &archive, 60);
        let politique = Politique {
            corps_conserves: 10,
            pas: 1,
        };
        let mut derniere = 0;
        let avant = archive.len();
        let r = elaguer(&c, &archive, &magasin, RESEAU, 20, politique, &mut derniere);
        assert!(
            r.is_err(),
            "un instantane a la hauteur 20 ne couvre pas les corps 21..50"
        );
        assert_eq!(archive.len(), avant, "le fichier est intact");
        assert!(!magasin.exists(), "rien n'a ete ecrit");
        let _ = std::fs::remove_dir_all(&d);
    }
}
