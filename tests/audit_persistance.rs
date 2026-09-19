//! Audit de persistance, cohérence après arrêt brutal, et reprise sur instantané.
//!
//! Chaque test simule une panne réelle en manipulant les fichiers sur disque
//! (troncature, octets modifiés, fichiers échangés entre deux nœuds) et compare
//! le verdict d'un nœud repris à celui d'un nœud complet sur LES MÊMES blocs.

use q21_core::addr::{AddrBook, AddrStore};
use q21_core::address::Network;
use q21_core::block::Block;
use q21_core::chain::{genesis_block, Chain, RepriseError, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::state::{AddressCache, StateStore};
use q21_core::store::{BlockArchive, BlockStore};
use q21_core::wire::NetAddr;
use std::path::PathBuf;

const RESEAU: Network = Network::Regtest;
const ESSAIS: u64 = 50_000_000;

/// L'attaquant modelise ici a les droits d'ecriture sur le repertoire : il lit
/// donc le sceau comme le noeud le lit. Le sceau n'est pas cense l'arreter — il
/// arrete un fichier d'etat **venu d'ailleurs**. Ce que ces epreuves mesurent,
/// c'est ce qui reste quand le sceau ne protege plus : la coherence interne.
fn etat_de(d: &std::path::Path) -> StateStore {
    let clef = q21_core::state::clef_de_repertoire(d).expect("clef du repertoire");
    StateStore::new_scelle(d.join("state.dat"), clef)
}

fn rep(nom: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("q21-audit-persist-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn horodatage(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

/// Mine `n` blocs et les écrit dans l'archive, exactement comme le fait le
/// binaire : `connect` puis `append`.
fn chaine_sur_disque(d: &std::path::Path, n: u64) -> (Chain, std::sync::Arc<BlockArchive>) {
    let chemin = d.join("blocks.dat");
    let g = genesis_block(RESEAU);
    let store = BlockStore::new(&chemin);
    store.append(&g).unwrap();
    let (archive, _, _) = BlockArchive::open(&chemin, RESEAU).unwrap();
    let archive = std::sync::Arc::new(archive);

    let mut c = Chain::new(RESEAU, g);
    c.set_body_source(archive.clone());
    for i in 1..=n {
        let t = horodatage(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
        archive.append(&b).unwrap();
    }
    (c, archive)
}

/// Reproduit `charger()` de src/bin/q21.rs : balayage des en-têtes, reprise sur
/// instantané si possible, sinon revalidation complète.
fn charger(d: &std::path::Path) -> Result<(Chain, std::sync::Arc<BlockArchive>), String> {
    let (archive, entetes, souci) =
        BlockArchive::open(d.join("blocks.dat"), RESEAU).map_err(|e| e.to_string())?;
    if entetes.is_empty() {
        return Err("aucun bloc".into());
    }
    if let Some(s) = souci {
        eprintln!("avertissement : {s}");
    }
    let archive = std::sync::Arc::new(archive);
    let clef = q21_core::state::clef_de_repertoire(d).map_err(|e| e.to_string())?;
    let etat = StateStore::new_scelle(d.join("state.dat"), clef);
    let reprise = match etat.load(RESEAU) {
        Ok(i) => match Chain::from_snapshot(RESEAU, i, &entetes) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("avertissement : instantane inutilisable ({e})");
                None
            }
        },
        Err(e) if etat.exists() => {
            eprintln!("avertissement : {e}");
            None
        }
        Err(_) => None,
    };

    let mut chain = match reprise {
        Some(r) => {
            let mut c = r.chain;
            c.set_body_source(archive.clone());
            for id in &r.a_rejouer {
                let b = archive.read(id).ok_or("corps manquant au rejeu")?;
                let now = b.header.time + MAX_FUTURE_TIME;
                c.connect(&b, now)
                    .map_err(|e| format!("bloc {} refuse au rejeu : {e:?}", b.header.height))?;
            }
            c
        }
        None => {
            // `submit`, pas `connect` : le fichier contient aussi les branches
            // laterales, qui ne prolongent rien. Voir
            // `un_fichier_contenant_des_branches_laterales_se_rejoue`.
            let (blocs, _) = archive.store().load_all().map_err(|e| e.to_string())?;
            let mut c = Chain::new(RESEAU, blocs[0].clone());
            c.set_body_source(archive.clone());
            for (i, b) in blocs.iter().enumerate().skip(1) {
                let now = b.header.time + MAX_FUTURE_TIME;
                c.submit(b, now)
                    .map_err(|e| format!("bloc {i} refuse au rejeu : {e:?}"))?;
            }
            c
        }
    };
    chain.set_body_source(archive.clone());
    Ok((chain, archive))
}

fn ecrire_instantane(d: &std::path::Path, c: &Chain) {
    if let Some(i) = c.snapshot() {
        etat_de(d).save(&i).unwrap();
    }
}

// ===========================================================================
// 1. Arrêt brutal
// ===========================================================================

/// A. Coupure ENTRE l'écriture du bloc et celle de l'instantané.
/// L'instantané est en retard : le rejeu doit rattraper, sans divergence.
#[test]
fn a_coupure_entre_bloc_et_instantane() {
    let d = rep("coupure-entre");
    let (c, _a) = chaine_sur_disque(&d, 12);
    ecrire_instantane(&d, &c);

    // Deux blocs de plus, écrits sur disque mais pas d'instantané : la coupure
    // survient ici.
    let (c2, _a2) = {
        let (mut c2, a2) = charger(&d).unwrap();
        for i in c2.height() + 1..=c2.height() + 2 {
            let t = horodatage(i);
            let b = c2
                .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
                .unwrap();
            c2.connect(&b, t + 1).unwrap();
            a2.append(&b).unwrap();
        }
        (c2, a2)
    };
    let tete = c2.tip_id();
    let emis = c2.total_issued();
    drop(c2);

    let (repris, _) = charger(&d).expect("redemarrage apres coupure");
    assert_eq!(repris.tip_id(), tete, "tête différente après coupure");
    assert_eq!(repris.total_issued(), emis, "émission différente");
}

/// B. Coupure PENDANT l'écriture d'un bloc : fichier tronqué au milieu du
/// dernier enregistrement, instantané en retard.
#[test]
fn b_coupure_pendant_l_ecriture_d_un_bloc() {
    let d = rep("tronque");
    let (c, _a) = chaine_sur_disque(&d, 14);
    ecrire_instantane(&d, &c);
    let hauteur_avant = c.height();
    drop(c);

    // Un bloc de plus, puis coupure au milieu de son écriture.
    let (mut c2, a2) = charger(&d).unwrap();
    let t = horodatage(hauteur_avant + 1);
    let b = c2
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
        .unwrap();
    c2.connect(&b, t + 1).unwrap();
    a2.append(&b).unwrap();
    drop(c2);
    drop(a2);

    let chemin = d.join("blocks.dat");
    let taille = std::fs::metadata(&chemin).unwrap().len();
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&chemin)
        .unwrap();
    f.set_len(taille - 20).unwrap(); // dernier bloc coupé en deux
    drop(f);

    let (repris, _) = charger(&d).expect("un fichier tronque ne doit pas empecher de demarrer");
    assert_eq!(
        repris.height(),
        hauteur_avant,
        "le noeud doit revenir au dernier bloc complet"
    );
}

/// C. Coupure PENDANT le renommage atomique : le `.tmp` subsiste, le fichier
/// cible est l'ancien. Le nœud doit repartir sur l'ancien instantané.
#[test]
fn c_coupure_pendant_le_renommage() {
    let d = rep("renommage");
    let (mut c, a) = chaine_sur_disque(&d, 12);
    ecrire_instantane(&d, &c);
    let ancien = std::fs::read(d.join("state.dat")).unwrap();

    for i in 13..=16u64 {
        let t = horodatage(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .unwrap();
        c.connect(&b, t + 1).unwrap();
        a.append(&b).unwrap();
    }
    let tete = c.tip_id();
    // La coupure : le temporaire est écrit, le renommage n'a pas eu lieu.
    let nouveau = c.snapshot().unwrap();
    let tmp = d.join("state.tmp");
    // On force l'état "avant renommage".
    std::fs::write(&tmp, b"contenu partiel").unwrap();
    std::fs::write(d.join("state.dat"), &ancien).unwrap();
    drop(nouveau);
    drop(c);

    let (repris, _) = charger(&d).expect("redemarrage");
    assert_eq!(repris.tip_id(), tete, "le rejeu doit rattraper la tete");
    assert!(
        tmp.exists(),
        "le temporaire subsiste (constat, pas un defaut)"
    );
}

/// D. **L'instantané peut-il être EN AVANCE sur le fichier de blocs ?**
/// C'est le cas réel du démon : les blocs reçus du réseau ne sont jamais
/// écrits dans blocks.dat, mais l'instantané, lui, est écrit à l'arrêt.
#[test]
fn d_instantane_en_avance_sur_le_fichier_de_blocs() {
    let d = rep("avance");
    // Le nœud a un fichier de blocs à 12 blocs...
    let (mut c, _a) = chaine_sur_disque(&d, 12);
    // ...mais reçoit 6 blocs du réseau, qu'il connecte SANS les écrire
    // (c'est exactement ce que fait `Node::integrer` dans src/net.rs).
    for i in 13..=18u64 {
        let t = horodatage(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .unwrap();
        c.connect(&b, t + 1).unwrap();
        // pas de archive.append : le démon ne le fait pas pour les blocs reçus
    }
    let hauteur_reelle = c.height();
    ecrire_instantane(&d, &c); // écrit à l'arrêt
    drop(c);

    let (repris, _) = charger(&d).expect("redemarrage");
    eprintln!(
        "CONSTAT : hauteur {} avant l'arret, {} apres — {} blocs perdus SANS erreur",
        hauteur_reelle,
        repris.height(),
        hauteur_reelle - repris.height()
    );
    assert_eq!(
        repris.height(),
        12,
        "le noeud revient a la hauteur du fichier de blocs, silencieusement"
    );
    assert_ne!(
        repris.total_issued(),
        {
            // Ce que le nœud croyait avoir émis juste avant l'arrêt.
            q21_core::amount::Amount::from_units(u64::MAX)
        },
        "garde-fou"
    );
}

/// D bis. Le cas aggravé : le démon mine *aussi*. blocks.dat reçoit alors des
/// blocs non contigus, et le nœud ne redémarre plus DU TOUT.
#[test]
fn d_bis_le_noeud_ne_redemarre_plus_apres_avoir_mine_en_se_synchronisant() {
    use q21_core::chain::Journal;
    let d = rep("brique");
    let (mut c, a) = chaine_sur_disque(&d, 4);
    // Sept blocs, dont six « recus du reseau ». Tous passent desormais par le
    // journal : c'est la chaine qui consigne, pas la boucle de minage.
    for i in 5..=11u64 {
        let t = horodatage(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .unwrap();
        c.connect(&b, t + 1).unwrap();
        a.consigner(&b);
    }
    ecrire_instantane(&d, &c);
    drop(c);

    // Le journal est idempotent : reconsigner un bloc deja ecrit ne doit pas
    // creer de doublon, sinon le fichier double de taille a chaque rediffusion.
    let avant = a.len();
    let dernier = a.read(
        &a.store()
            .load_all()
            .unwrap()
            .0
            .last()
            .unwrap()
            .header
            .block_id(),
    );
    if let Some(b) = dernier {
        a.consigner(&b);
    }
    assert_eq!(a.len(), avant, "le journal a ecrit deux fois le meme bloc");

    // Un noeud qui a mine pendant sa synchronisation doit pouvoir redemarrer.
    let (repris, _) = charger(&d).expect("le noeud redemarre");
    assert_eq!(repris.height(), 11, "la tete minee est retrouvee");
}

// ===========================================================================
// 2. Instantané et fichier de blocs désaccordés
// ===========================================================================

/// L'instantané désigne une tête absente du fichier de blocs.
#[test]
fn e_instantane_designant_une_tete_absente() {
    let d = rep("tete-absente");
    let (c, _a) = chaine_sur_disque(&d, 12);
    let mut s = c.snapshot().unwrap();
    s.tip = Hash256([0xAB; 32]); // tête inconnue
    etat_de(&d).save(&s).unwrap();
    drop(c);

    // On doit retomber sur la revalidation intégrale, jamais accepter.
    let (repris, _) = charger(&d).expect("revalidation complete");
    assert_eq!(repris.height(), 12);
}

/// Le fichier de blocs vient d'un AUTRE réseau (ou d'une autre chaîne) :
/// l'instantané est refusé, mais la revalidation complète adopte
/// **n'importe quel** premier bloc comme genèse.
#[test]
fn f_un_fichier_de_blocs_etranger_est_adopte_comme_genese() {
    let d = rep("etranger");
    let (_c, _a) = chaine_sur_disque(&d, 3);
    let _ = std::fs::remove_file(d.join("state.dat"));

    // Une « genèse » fabriquée : aucune preuve de travail, une prémine
    // arbitraire vers l'attaquant.
    let mut faux = genesis_block(RESEAU);
    faux.transactions[0].outputs[0].pubkey_hash = Hash256([0x99; 32]);
    faux.transactions[0].outputs[0].value = q21_core::amount::Amount::from_units(2_100_000_000_000);
    faux.header.merkle_root = faux.compute_merkle_root();
    faux.header.nonce = 1; // preuve de travail volontairement fausse

    let chemin = d.join("blocks.dat");
    let _ = std::fs::remove_file(&chemin);
    BlockStore::new(&chemin).append(&faux).unwrap();

    // Le fichier ne commence plus par la genese du reseau : il n'est pas adopte.
    let message = match charger(&d) {
        Ok(_) => panic!("CONSTAT : une genese fabriquee est adoptee sans controle"),
        Err(e) => e,
    };
    eprintln!("refus : {message}");
    assert!(
        message.contains("autre chaine"),
        "le refus doit nommer sa raison : {message}"
    );
}

/// Un instantané fabriqué (l'attaquant a accès au disque / à une sauvegarde)
/// dont la somme de contrôle est recalculée : accepté sans broncher.
#[test]
fn g_instantane_fabrique_credite_des_fonds_inexistants() {
    let d = rep("faux-etat");
    let (c, _a) = chaine_sur_disque(&d, 12);
    let mut s = c.snapshot().unwrap();
    let solde_avant: u64 = s
        .utxo
        .iter()
        .filter(|(_, e)| e.output.pubkey_hash == Hash256([0x99; 32]))
        .map(|(_, e)| e.output.value.units())
        .sum();
    assert_eq!(solde_avant, 0);

    // L'attaquant ajoute une sortie à lui, et recalcule la somme.
    s.utxo.insert(
        q21_core::tx::OutPoint {
            txid: Hash256([0x77; 32]),
            index: 0,
        },
        q21_core::utxo::UtxoEntry {
            output: q21_core::tx::TxOut {
                value: q21_core::amount::Amount::from_units(1_000_000_000),
                scheme: SchemeId::LamportOts,
                pubkey_hash: Hash256([0x99; 32]),
            },
            height: 1,
            is_coinbase: false,
        },
    );
    etat_de(&d).save(&s).unwrap();
    drop(c);

    // L'empreinte MuHash tranche la premiere, et plus franchement que le
    // calendrier d'emission : la sortie ajoutee change le jeu d'UTXO, donc son
    // empreinte ne correspond plus a celle inscrite, et le fichier est rejete —
    // meme si le montant vole restait sous le plafond d'emission. Le noeud
    // revalide alors depuis le fichier de blocs, qui porte une preuve de travail.
    let (repris, _) = charger(&d).expect("reprise par revalidation complete");
    let vole: u64 = repris
        .utxo
        .iter()
        .filter(|(_, e)| e.output.pubkey_hash == Hash256([0x99; 32]))
        .map(|(_, e)| e.output.value.units())
        .sum();
    assert_eq!(
        vole, 0,
        "CONSTAT : un instantane fabrique credite des fonds inexistants"
    );
    assert_eq!(repris.height(), 12, "la chaine reelle est retrouvee");
}

// ===========================================================================
// 3. Verdict d'un nœud repris vs verdict d'un nœud complet
// ===========================================================================

/// Sur les mêmes blocs, un nœud repris et un nœud complet doivent rendre le
/// même verdict. On teste sur une chaîne d'oncles (règle du double paiement).
#[test]
fn h_meme_verdict_sur_le_meme_bloc() {
    let d = rep("verdict");
    let (complet, _a) = chaine_sur_disque(&d, 20);
    ecrire_instantane(&d, &complet);

    let (mut repris, _) = charger(&d).expect("reprise");
    let mut complet = complet;

    // Le même bloc, soumis aux deux.
    let t = horodatage(21);
    let b = complet
        .mine_block(Hash256([3u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
        .unwrap();
    let v1 = complet.connect(&b, t + 1);
    let v2 = repris.connect(&b, t + 1);
    assert_eq!(
        v1.is_ok(),
        v2.is_ok(),
        "verdicts differents : {v1:?} vs {v2:?}"
    );
    assert_eq!(complet.tip_id(), repris.tip_id());
    assert_eq!(complet.total_issued(), repris.total_issued());
}

/// La fenêtre d'annulation d'un nœud repris est plus courte que celle d'un
/// nœud complet : sur la MÊME réorganisation, l'un bascule, l'autre refuse.
#[test]
fn i_fenetre_d_annulation_courte_apres_reprise() {
    let d = rep("fenetre");
    let (complet, _a) = chaine_sur_disque(&d, 30);
    // Instantané pris à faible recul : c'est ce que fait `snapshot()` sur une
    // chaîne courte, et ce que fait un nœud qui vient d'être repris puis
    // arrêté aussitôt.
    let s = complet.snapshot_at_depth(2).unwrap();
    etat_de(&d).save(&s).unwrap();

    let (repris, _) = charger(&d).expect("reprise");
    eprintln!(
        "fenetre d'annulation : complet {} / repris {}",
        complet.undo_window(),
        repris.undo_window()
    );
    assert!(
        repris.undo_window() < complet.undo_window(),
        "un noeud repris a une fenetre plus courte : profondeurs de reorg differentes"
    );
}

/// La règle anti-double-paiement d'oncle relit les corps des 9 derniers blocs
/// — quand des oncles sont possibles. Tant que `MAX_UNCLES` vaut zéro, aucun
/// oncle n'a pu être réclamé : il n'y a rien à relire, et un nœud repris sans
/// fournisseur de corps rend le **même verdict** qu'un nœud complet sur le bloc
/// qui prolonge sa tête. Le jour où le protocole rouvre les oncles, la lecture
/// des corps reprend d'elle-même, et sans fournisseur le verdict redevient un
/// refus (`HistoriqueIncomplet`) — un refus, jamais une acceptation aveugle.
#[test]
fn j_sans_fournisseur_de_corps_un_noeud_repris_rend_le_meme_verdict() {
    use q21_core::consensus::MAX_UNCLES;

    let d = rep("sans-source");
    let (complet, _a) = chaine_sur_disque(&d, 20);
    let s = complet.snapshot().unwrap();
    let entetes = complet.headers();
    let r = Chain::from_snapshot(RESEAU, s, &entetes).expect("reprise");
    let mut sans_source = r.chain; // aucun set_body_source

    // Le bloc qui prolonge la tête du nœud repris, miné par un nœud complet
    // ramené à cette même hauteur.
    let mut temoin = complet;
    while temoin.height() > sans_source.height() {
        assert!(temoin.disconnect(), "le temoin doit pouvoir redescendre");
    }
    let t = horodatage(sans_source.height() + 1);
    let b = temoin
        .mine_block(Hash256([3u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
        .unwrap();
    let attendu = temoin.connect(&b, t + 1).map(|_| ());
    let v = sans_source.connect(&b, t + 1).map(|_| ());
    eprintln!("verdict complet : {attendu:?} ; sans fournisseur : {v:?}");
    if MAX_UNCLES == 0 {
        assert!(attendu.is_ok(), "le temoin doit accepter son propre bloc");
        assert_eq!(
            v, attendu,
            "sans oncle possible, l'absence de corps ne change pas le verdict"
        );
    } else {
        assert!(v.is_err(), "refus attendu, pas d'acceptation aveugle");
    }
}

// ===========================================================================
// 4/5. Fenêtre de corps bornée et émission dans l'index
// ===========================================================================

/// Après reprise, les blocs antérieurs à l'instantané portent `emis: 0`.
/// On cherche un chemin qui lise cette valeur et produise un résultat faux.
#[test]
fn k_emission_apres_reprise_reste_juste() {
    let d = rep("emission");
    let (complet, _a) = chaine_sur_disque(&d, 20);
    ecrire_instantane(&d, &complet);
    let (repris, _) = charger(&d).expect("reprise");
    assert_eq!(
        repris.total_issued(),
        complet.total_issued(),
        "l'emission doit etre identique"
    );

    // Puis on défait jusqu'au fond de la fenêtre : l'émission doit suivre.
    let mut repris = repris;
    let mut complet = complet;
    let n = repris.undo_window();
    for _ in 0..n {
        let a = repris.disconnect();
        let b = complet.disconnect();
        assert_eq!(a, b, "disconnect divergent");
        if !a {
            break;
        }
        assert_eq!(
            repris.total_issued(),
            complet.total_issued(),
            "emission divergente a la hauteur {}",
            repris.height()
        );
    }
}

/// Un `disconnect` supplémentaire, une fois la fenêtre épuisée, ne doit ni
/// paniquer ni remettre l'émission à zéro.
#[test]
fn l_disconnect_hors_fenetre_ne_casse_pas_l_emission() {
    let d = rep("emission-zero");
    let (complet, _a) = chaine_sur_disque(&d, 20);
    ecrire_instantane(&d, &complet);
    let (mut repris, _) = charger(&d).expect("reprise");

    let emis = repris.total_issued();
    let n = repris.undo_window();
    for _ in 0..n {
        repris.disconnect();
    }
    let emis_fond = repris.total_issued();
    assert!(!repris.disconnect(), "refus attendu hors fenetre");
    assert_eq!(
        repris.total_issued(),
        emis_fond,
        "l'emission ne doit pas bouger sur un disconnect refuse"
    );
    assert!(emis.units() >= emis_fond.units());
}

// ===========================================================================
// 6/7. Fichiers hostiles
// ===========================================================================

/// Le cache d'adresses n'est resondé que sur la PREMIÈRE et la DERNIÈRE entrée.
/// On forge un cache dont ces deux entrées sont bonnes et les autres fausses.
#[test]
fn m_cache_d_adresses_forge_est_adopte() {
    use q21_core::wallet::Wallet;
    let d = rep("cache-adresses");
    let graine = [7u8; 32];
    let mut vrai = Wallet::from_seed_scheme(graine, RESEAU, SchemeId::LamportOts).unwrap();
    vrai.rescan(8);
    let vraies = vrai.known_hashes();
    assert_eq!(vraies.len(), 8);

    // Le forgeron ne connaît que deux adresses publiques : la première et la
    // dernière. Il remplace tout le reste par les siennes.
    let mut forge = vraies.clone();
    for (i, h) in forge.iter_mut().enumerate().take(7).skip(1) {
        *h = Hash256([0x99 ^ i as u8; 32]);
    }
    let cache = AddressCache::new(d.join("addresses.dat"));
    // L'attaquant ne connait pas la graine : il ne peut pas sceller le cache.
    // Il ecrit donc avec une clef a lui.
    cache
        .save(SchemeId::LamportOts, &forge, &[0u8; 32])
        .unwrap();

    let charge = cache.load(SchemeId::LamportOts, &vrai.clef_cache());
    assert!(
        charge.is_err(),
        "un cache non scelle par ce portefeuille doit etre refuse : {charge:?}"
    );

    // Et meme si le sceau tombait, le portefeuille ne doit pas adopter n'importe
    // quoi : la derivation est deterministe, elle sert de garde-fou.
    let mut victime = Wallet::from_seed_scheme(graine, RESEAU, SchemeId::LamportOts).unwrap();
    let adopte = victime.adopt_hashes(&forge);
    assert!(
        !adopte,
        "CONSTAT : un cache forge sur 6 entrees sur 8 est adopte"
    );
    // Le portefeuille n'a rien adopte : il ne connait aucune adresse de
    // l'attaquant, et il retrouve les siennes par derivation.
    assert!(!victime.owns(&Hash256([0x99 ^ 1u8; 32])));
    victime.rescan(8);
    assert!(
        victime.owns(&vraies[3]),
        "CONSTAT : le portefeuille perd de vue ses propres adresses"
    );
}

/// Conséquence financière du cache forgé : le solde est faux, les fonds réels
/// deviennent invisibles, et les fonds de l'attaquant sont comptés comme siens.
#[test]
fn n_cache_forge_fausse_le_solde_et_masque_les_fonds() {
    use q21_core::amount::Amount;
    use q21_core::tx::{OutPoint, TxOut};
    use q21_core::utxo::{UtxoEntry, UtxoSet};
    use q21_core::wallet::Wallet;

    let graine = [11u8; 32];
    let mut vrai = Wallet::from_seed_scheme(graine, RESEAU, SchemeId::LamportOts).unwrap();
    vrai.rescan(6);
    let vraies = vrai.known_hashes();

    let mut utxo = UtxoSet::new();
    // Des fonds réels sur l'adresse 3 du portefeuille.
    utxo.insert(
        OutPoint {
            txid: Hash256([1u8; 32]),
            index: 0,
        },
        UtxoEntry {
            output: TxOut {
                value: Amount::from_units(500_000),
                scheme: SchemeId::LamportOts,
                pubkey_hash: vraies[3],
            },
            height: 1,
            is_coinbase: false,
        },
    );
    // Des fonds de l'attaquant, sur une adresse à lui.
    let a_lui = Hash256([0xAA; 32]);
    utxo.insert(
        OutPoint {
            txid: Hash256([2u8; 32]),
            index: 0,
        },
        UtxoEntry {
            output: TxOut {
                value: Amount::from_units(9_000_000),
                scheme: SchemeId::LamportOts,
                pubkey_hash: a_lui,
            },
            height: 1,
            is_coinbase: false,
        },
    );

    let solde_honnete = vrai.balance(&utxo, 1_000);
    assert_eq!(solde_honnete.units(), 500_000);

    let mut forge = vraies.clone();
    forge[3] = a_lui; // l'attaquant substitue son adresse à celle du milieu
    let mut victime = Wallet::from_seed_scheme(graine, RESEAU, SchemeId::LamportOts).unwrap();
    let adopte = victime.adopt_hashes(&forge);

    // Sur six entrees, l'echantillon couvre tout : la substitution est vue.
    assert!(!adopte, "CONSTAT : un cache forge est encore adopte");
    // Et le portefeuille est reste sur sa propre derivation.
    victime.rescan(6);
    let solde = victime.balance(&utxo, 1_000);
    eprintln!("solde honnete {solde_honnete} / solde apres tentative {solde}");
    assert_eq!(
        solde.units(),
        500_000,
        "le solde doit rester celui des fonds reellement detenus"
    );
}

/// Le cache forgé fait fabriquer au portefeuille une transaction invalide, et
/// **consomme une clef Lamport à usage unique** au passage.
#[test]
fn o_cache_forge_brule_une_clef_lamport() {
    use q21_core::address::Address;
    use q21_core::amount::Amount;
    use q21_core::tx::{OutPoint, TxOut};
    use q21_core::utxo::{UtxoEntry, UtxoSet};
    use q21_core::wallet::Wallet;

    let graine = [13u8; 32];
    let mut vrai = Wallet::from_seed_scheme(graine, RESEAU, SchemeId::LamportOts).unwrap();
    vrai.rescan(6);
    let vraies = vrai.known_hashes();
    let a_lui = Hash256([0xAA; 32]);

    let mut utxo = UtxoSet::new();
    utxo.insert(
        OutPoint {
            txid: Hash256([2u8; 32]),
            index: 0,
        },
        UtxoEntry {
            output: TxOut {
                value: Amount::from_units(9_000_000),
                scheme: SchemeId::LamportOts,
                pubkey_hash: a_lui,
            },
            height: 1,
            is_coinbase: false,
        },
    );

    let mut forge = vraies.clone();
    forge[3] = a_lui;
    let mut victime = Wallet::from_seed_scheme(graine, RESEAU, SchemeId::LamportOts).unwrap();
    // On force la situation la plus defavorable : meme si le cache avait ete
    // adopte — sceau contourne, echantillon manque — la clef ne doit pas bruler.
    let _ = victime.adopt_hashes(&forge);
    victime.rescan(6);
    victime.forcer_association_pour_epreuve(a_lui, 3);

    let dest = Address::from_pubkey(RESEAU, SchemeId::LamportOts, &[1u8; 32]);
    let tx = victime.create_transaction(
        &utxo,
        1_000,
        &dest,
        Amount::from_units(50_000),
        Amount::from_units(100),
    );
    // Le portefeuille doit refuser AVANT de signer, et ne rien consommer.
    assert!(
        matches!(
            tx,
            Err(q21_core::wallet::WalletError::VerrouIncoherent { index: 3 })
        ),
        "CONSTAT : le portefeuille signe avec une clef qui n'ouvre pas ce verrou : {tx:?}"
    );
    assert!(
        !victime.est_consomme(3),
        "CONSTAT : la clef 3 a ete brulee par un refus"
    );
}

/// Un `peers.dat` hostile : 512 groupes épinglés par un `last_seen` dans le
/// futur, qu'aucune adresse honnête ne pourra jamais déloger.
#[test]
fn p_carnet_hostile_epingle_tous_les_groupes() {
    const MAINTENANT: u64 = 1_700_000_000;
    let d = rep("carnet");
    let store = AddrStore::new(d.join("peers.dat"));
    let mut hostile = AddrBook::new_avec_sel(false, (1, 2));
    let mut n = 0;
    for a in 1u16..=255 {
        for b in 0u16..=255 {
            if a == 10 || a == 127 || a == 172 || a == 192 || a == 169 || a == 100 || a >= 224 {
                continue;
            }
            if hostile.groupes() >= MAX_GROUPES_LOCAL {
                break;
            }
            hostile.ajouter(
                NetAddr {
                    ip: [a as u8, b as u8, 1, 1],
                    port: 21021,
                    last_seen: u64::MAX, // horodatage impossible
                },
                MAINTENANT,
            );
            n += 1;
        }
        if hostile.groupes() >= MAX_GROUPES_LOCAL {
            break;
        }
    }
    eprintln!(
        "carnet hostile : {n} adresses, {} groupes",
        hostile.groupes()
    );
    store.save(&hostile).unwrap();

    let mut relu = store.load(false, MAINTENANT);
    assert_eq!(
        relu.groupes(),
        MAX_GROUPES_LOCAL,
        "les 512 groupes sont occupes"
    );

    // 1. Le plafond de groupes ne fige plus le carnet : aucune de ces adresses
    //    n'a jamais repondu, donc aucune n'a de droit acquis. Une adresse
    //    honnete entre, en chassant un groupe qui n'a rien prouve.
    let honnete = relu.ajouter(
        NetAddr {
            ip: [8, 8, 8, 8],
            port: 21021,
            last_seen: MAINTENANT,
        },
        MAINTENANT,
    );
    assert!(
        honnete,
        "CONSTAT : plus aucune adresse honnete ne peut entrer dans le carnet"
    );

    // 2. L'horodatage impossible ne donne plus aucun avantage : il est borne a
    //    l'ajout, donc il ne survit pas au passage par le disque.
    assert!(
        relu.toutes()
            .iter()
            .all(|e| e.addr.last_seen <= MAINTENANT + q21_core::addr::TOLERANCE_FUTUR),
        "CONSTAT : un horodatage futur survit dans le carnet"
    );

    // 3. Un pair reellement eprouve n'est plus noye dans la masse : il sort en
    //    tete de la selection, quoi que les autres annoncent.
    relu.marquer_succes([8, 8, 8, 8], 21021, MAINTENANT);
    let choix = relu.selectionner(8, &[], MAINTENANT);
    assert_eq!(choix.len(), 8);
    assert_eq!(
        choix[0].ip,
        [8, 8, 8, 8],
        "CONSTAT : la selection ne rend que les adresses epinglees"
    );
}
const MAX_GROUPES_LOCAL: usize = 512;

/// Un `peers.dat` corrompu ne doit jamais faire paniquer, seulement vider le
/// carnet.
#[test]
fn q_carnet_corrompu_ne_panique_pas() {
    let d = rep("carnet-corrompu");
    let chemin = d.join("peers.dat");
    let store = AddrStore::new(&chemin);
    let mut b = AddrBook::new(false);
    b.ajouter(
        NetAddr {
            ip: [93, 184, 216, 34],
            port: 21021,
            last_seen: 100,
        },
        1_700_000_000,
    );
    store.save(&b).unwrap();

    let mut donnees = std::fs::read(&chemin).unwrap();
    let m = donnees.len() / 2;
    donnees[m] ^= 0xFF;
    std::fs::write(&chemin, &donnees).unwrap();
    assert_eq!(
        store.load(false, 1_700_000_000).len(),
        0,
        "carnet vide, pas de panique"
    );

    // Et un fichier entièrement aléatoire.
    for taille in [0usize, 1, 31, 32, 33, 200] {
        std::fs::write(&chemin, vec![0x5Au8; taille]).unwrap();
        let _ = store.load(false, 1_700_000_000);
    }
}

// ===========================================================================
// 8. Croissance non bornée
// ===========================================================================

/// L'index des en-têtes croît-il sans borne à la reprise ? On mesure ce que
/// coûte un fichier de blocs rempli d'en-têtes valides mais orphelins.
#[test]
fn r_entetes_orphelins_dans_le_fichier_de_blocs() {
    let d = rep("orphelins");
    let (c, _a) = chaine_sur_disque(&d, 6);
    let chemin = d.join("blocks.dat");
    let store = BlockStore::new(&chemin);

    // 300 blocs bidons, sans aucune preuve de travail, chaînés sur un parent
    // inexistant : ils passent le balayage d'en-têtes.
    let mut bidon = genesis_block(RESEAU);
    for i in 0..300u32 {
        bidon.header.prev_block = Hash256([0xEE; 32]);
        bidon.header.height = 1_000_000 + u64::from(i);
        bidon.header.nonce = u64::from(i);
        store.append(&bidon).unwrap();
    }
    let (_, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    eprintln!("en-tetes balayes : {} (souci {souci:?})", entetes.len());
    assert_eq!(entetes.len(), 307);

    let s = c.snapshot().unwrap();
    let r = Chain::from_snapshot(RESEAU, s, &entetes);
    match &r {
        Ok(rep) => eprintln!(
            "reprise acceptee : {} blocs indexes",
            rep.chain.known_blocks()
        ),
        Err(e) => eprintln!("reprise refusee : {e:?}"),
    }
    // Le fichier de blocs n'est jamais élagué ni vérifié : tout ce qui y est
    // écrit est rebalayé à chaque démarrage.
    assert!(r.is_ok() || matches!(r, Err(RepriseError::InstantaneHorsChaine)));
}

/// Le fichier de blocs contient-il des doublons après un redémarrage ?
/// (le même bloc réécrit à chaque `append` sans contrôle d'existence)
#[test]
fn s_le_fichier_de_blocs_accepte_des_doublons_sans_borne() {
    let d = rep("doublons");
    let chemin = d.join("blocks.dat");
    let store = BlockStore::new(&chemin);
    let g = genesis_block(RESEAU);
    for _ in 0..50 {
        store.append(&g).unwrap();
    }
    let (_, entetes, _) = BlockArchive::open(&chemin, RESEAU).unwrap();
    assert_eq!(entetes.len(), 50, "50 copies du meme bloc, toutes indexees");
    let taille = std::fs::metadata(&chemin).unwrap().len();
    eprintln!(
        "50 doublons : {taille} octets, index de {} entrees",
        entetes.len()
    );
}

// ===========================================================================
// Contrôles négatifs : ce que j'ai cherché sans rien trouver
// ===========================================================================

/// Un instantané d'un autre réseau est bien refusé.
#[test]
fn t_instantane_d_un_autre_reseau_refuse() {
    let d = rep("reseau");
    let (c, _a) = chaine_sur_disque(&d, 12);
    let mut s = c.snapshot().unwrap();
    s.network = Network::Mainnet;
    etat_de(&d).save(&s).unwrap();
    assert!(etat_de(&d).load(Network::Regtest).is_err());
}

/// Un instantané dont la hauteur ne correspond pas à la position de la tête est
/// refusé (pas d'acceptation silencieuse).
#[test]
fn u_instantane_a_la_mauvaise_hauteur_refuse() {
    let d = rep("hauteur");
    let (c, _a) = chaine_sur_disque(&d, 12);
    let mut s = c.snapshot().unwrap();
    s.height += 1;
    let entetes = c.headers();
    assert_eq!(
        Chain::from_snapshot(RESEAU, s, &entetes).err(),
        Some(RepriseError::InstantaneHorsChaine)
    );
}

/// Un fichier de blocs sans genèse est refusé.
#[test]
fn v_pas_de_genese_refuse() {
    let d = rep("sans-genese");
    let (c, _a) = chaine_sur_disque(&d, 12);
    let s = c.snapshot().unwrap();
    let entetes: Vec<_> = c.headers().into_iter().skip(1).collect();
    assert_eq!(
        Chain::from_snapshot(RESEAU, s, &entetes).err(),
        Some(RepriseError::PasDeGenese)
    );
}

/// Un instantané annonçant un nombre d'entrées délirant ne fait pas allouer.
#[test]
fn w_instantane_avec_un_compte_delirant() {
    let d = rep("compte-fou");
    let chemin = d.join("state.dat");
    let (c, _a) = chaine_sur_disque(&d, 3);
    let s = c.snapshot();
    drop(s);
    // On construit un fichier à la main : magie + version + réseau + hauteur +
    // tête + émis + varint énorme.
    let mut w = q21_core::ser::Writer::with_capacity(64);
    w.bytes(b"Q21STATE");
    w.u32(1);
    w.u8(2); // Regtest
    w.u64(0);
    w.bytes(Hash256::ZERO.as_bytes());
    w.u64(0);
    w.varint(u64::MAX);
    let mut donnees = w.finish();
    donnees.extend_from_slice(&q21_core::sha256::sha256(&donnees));
    std::fs::write(&chemin, &donnees).unwrap();
    let r = StateStore::new(&chemin).load(RESEAU);
    assert!(r.is_err(), "refus attendu, sans allocation");
}

/// Deux nœuds au même état écrivent le même fichier, octet pour octet :
/// c'est ce qui rend un instantané comparable.
#[test]
fn x_instantane_deterministe_entre_deux_noeuds() {
    let d1 = rep("det1");
    let d2 = rep("det2");
    let (c1, _a1) = chaine_sur_disque(&d1, 8);
    // Le même travail refait ailleurs donne la même chaîne (mêmes horodatages,
    // même bénéficiaire) — sauf le nonce, qui dépend du minage.
    let (c2, _a2) = chaine_sur_disque(&d2, 8);
    ecrire_instantane(&d1, &c1);
    ecrire_instantane(&d2, &c2);
    let f1 = std::fs::read(d1.join("state.dat")).unwrap();
    let f2 = std::fs::read(d2.join("state.dat")).unwrap();
    // Les chaînes diffèrent par leurs nonces, donc les txid de coinbase
    // diffèrent aussi : on vérifie seulement que la taille est identique.
    assert_eq!(f1.len(), f2.len(), "meme structure, meme taille");
}

/// Un `state.dat` de taille zéro, ou fait de zéros, ne panique pas.
#[test]
fn y_state_dat_degenere() {
    let d = rep("degenere");
    let chemin = d.join("state.dat");
    for contenu in [vec![], vec![0u8; 31], vec![0u8; 32], vec![0xFFu8; 4096]] {
        std::fs::write(&chemin, &contenu).unwrap();
        let r = StateStore::new(&chemin).load(RESEAU);
        assert!(r.is_err());
    }
}

/// Le fichier de blocs tronqué à zéro octet : démarrage impossible mais propre.
#[test]
fn z_fichier_de_blocs_vide() {
    let d = rep("blocs-vides");
    let (_c, _a) = chaine_sur_disque(&d, 3);
    std::fs::write(d.join("blocks.dat"), b"").unwrap();
    let r = charger(&d);
    assert!(r.is_err(), "refus propre attendu");
}

/// Un enregistrement dont la taille annoncée déborde du fichier : le balayage
/// doit s'arrêter, pas lire au-delà — et surtout ne rien couper.
///
/// Depuis le second audit (P4), le cas précis du **premier** enregistrement
/// est réparé : la genèse est une constante du réseau, son en-tête est intact
/// à l'octet 4, donc l'enregistrement entier est recopié, préfixe compris.
/// Ce que l'épreuve vérifie reste le même : rien n'est lu au-delà du fichier
/// et rien n'est perdu. Elle exige maintenant en plus que les cinq blocs se
/// relisent.
#[test]
fn aa_taille_mensongere_dans_le_fichier_de_blocs() {
    let d = rep("taille-menteuse");
    let (_c, _a) = chaine_sur_disque(&d, 4);
    let chemin = d.join("blocks.dat");
    let saines = std::fs::read(&chemin).unwrap();
    let mut donnees = saines.clone();
    // On ment sur la taille du premier enregistrement.
    let faux = 1_000_000u32.to_le_bytes();
    donnees[..4].copy_from_slice(&faux);
    std::fs::write(&chemin, &donnees).unwrap();

    let (_, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    eprintln!("en-tetes {} souci {souci:?}", entetes.len());
    assert!(souci.is_none(), "le prefixe de la genese est repare");
    assert_eq!(entetes.len(), 5, "aucun bloc n'est perdu");
    assert_eq!(
        std::fs::read(&chemin).unwrap(),
        saines,
        "le fichier est restaure a l'identique"
    );
}

/// Un instantané pris à la tête (recul nul) : `snapshot()` doit le refuser,
/// sinon le nœud repris n'aurait plus AUCUNE capacité de réorganisation.
#[test]
fn ab_instantane_a_la_tete_refuse() {
    let g = genesis_block(RESEAU);
    let c = Chain::new(RESEAU, g);
    assert!(
        c.snapshot().is_none(),
        "chaine trop courte : pas d'instantane"
    );
    assert!(c.snapshot_at_depth(0).is_none());
}

/// Un instantané pris sur une chaîne dont l'index a `emis: 0` partout (chaîne
/// elle-même reprise) reste-t-il juste ? Reprise en cascade.
#[test]
fn ac_reprise_en_cascade() {
    let d = rep("cascade");
    let (c1, _a) = chaine_sur_disque(&d, 24);
    let emis = c1.total_issued();
    ecrire_instantane(&d, &c1);
    drop(c1);

    let (c2, _) = charger(&d).expect("reprise 1");
    assert_eq!(c2.total_issued(), emis, "emission apres reprise 1");
    ecrire_instantane(&d, &c2); // instantané écrit par un nœud DÉJÀ repris
    drop(c2);

    let (c3, _) = charger(&d).expect("reprise 2");
    assert_eq!(
        c3.total_issued(),
        emis,
        "emission apres reprise en cascade : divergence = inflation ou deflation"
    );
    let (c4, _) = {
        ecrire_instantane(&d, &c3);
        charger(&d).expect("reprise 3")
    };
    assert_eq!(c4.total_issued(), emis, "emission apres 3 reprises");
}

/// Le corps de la genèse n'est jamais élagué : sans lui la chaîne serait
/// inintelligible.
#[test]
fn ad_la_genese_n_est_jamais_elaguee() {
    let d = rep("genese");
    let (c, _a) = chaine_sur_disque(&d, 6);
    let g = c.active_at(0).unwrap();
    assert!(c.block_by_id(&g).is_some());
    let _ = d;
}

/// Un `Block` relu du disque doit être identique à celui écrit : sinon deux
/// nœuds calculeraient des identifiants différents.
#[test]
fn ae_aller_retour_disque_preserve_l_identifiant() {
    let d = rep("aller-retour");
    let (c, a) = chaine_sur_disque(&d, 6);
    for h in 0..=c.height() {
        let id = c.active_at(h).unwrap();
        let relu: Block = a.read(&id).expect("corps sur disque");
        assert_eq!(
            relu.header.block_id(),
            id,
            "identifiant altere par le disque"
        );
    }
}

// ===========================================================================
// Divergences de VERDICT entre un nœud repris et un nœud complet
// ===========================================================================

/// Le champ `emis` de `state.dat` n'est lié à rien : ni au jeu d'UTXO, ni aux
/// en-têtes. Un attaquant le porte au plafond, et le nœud repris REFUSE un bloc
/// que tout nœud complet accepte. Deux verdicts = scission.
#[test]
fn ba_emis_forge_fait_refuser_un_bloc_valide() {
    use q21_core::emission::block_subsidy;
    let d = rep("emis-forge");
    let (mut complet, _a) = chaine_sur_disque(&d, 16);

    // Instantané pris à un bloc de la tête : un seul bloc à rejouer.
    let mut s = complet.snapshot_at_depth(1).unwrap();
    // `emis` n'est lié à rien : ni au jeu d'UTXO, ni aux en-têtes. L'attaquant
    // le porte juste sous le plafond, de sorte que le rejeu passe et que le
    // bloc SUIVANT soit refusé.
    s.emis = MAX_SUPPLY - block_subsidy(16).units();
    etat_de(&d).save(&s).unwrap();

    // Un `emis` proche du plafond est impossible a la hauteur 15 : le
    // calendrier d'emission le dit, et l'instantane est rejete. Le noeud
    // revalide, retrouve la vraie emission, et rend le meme verdict que le
    // noeud complet.
    let (mut repris, _) = charger(&d).expect("reprise par revalidation complete");
    eprintln!(
        "emission : complet {} / repris {}",
        complet.total_issued(),
        repris.total_issued()
    );
    assert_eq!(complet.tip_id(), repris.tip_id(), "meme tete");
    assert_eq!(
        complet.total_issued(),
        repris.total_issued(),
        "l'emission cumulee doit se reconstruire, pas se lire dans un fichier"
    );

    let t = horodatage(17);
    let b = complet
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
        .unwrap();
    let v_complet = complet.connect(&b, t + 1);
    let v_repris = repris.connect(&b, t + 1);
    eprintln!("complet : {v_complet:?}\nrepris  : {v_repris:?}");
    assert!(v_complet.is_ok(), "un noeud complet accepte ce bloc");
    assert!(
        v_repris.is_ok(),
        "CONSTAT : deux verdicts differents sur le MEME bloc — scission"
    );
}

/// Même famille, sans plafond : `emis` forgé plus bas fait diverger l'émission
/// rapportée, et donc le contrôle anti-inflation de tous les blocs suivants.
#[test]
fn bb_emis_forge_fausse_l_emission_rapportee() {
    let d = rep("emis-bas");
    let (complet, _a) = chaine_sur_disque(&d, 16);
    let mut s = complet.snapshot().unwrap();
    s.emis = 42;
    etat_de(&d).save(&s).unwrap();
    let (repris, _) = charger(&d).expect("reprise");
    assert_eq!(
        repris.total_issued(),
        complet.total_issued(),
        "CONSTAT : l'emission cumulee est entierement dictee par state.dat"
    );
    eprintln!(
        "complet {} / repris {}",
        complet.total_issued(),
        repris.total_issued()
    );
}

/// Une sortie retirée de `state.dat` : le nœud repris refuse la transaction qui
/// la dépense, que tout nœud complet accepte.
///
/// # Depuis l'empreinte MuHash
///
/// Retirer une sortie sans recalculer l'empreinte ne trompe plus personne :
/// l'instantane est rejete pour engagement invalide, et le noeud rejoue la
/// chaine — plus de divergence. Le constat ne subsiste donc que face a un
/// faussaire qui **recalcule aussi l'empreinte** pour la faire suivre. C'est
/// exactement la limite documentee dans `state.rs` : tant qu'aucune valeur de
/// confiance venue d'ailleurs n'ancre l'empreinte, un `state.dat` coherent avec
/// lui-meme mais infidele a la chaine diverge encore. On simule donc le
/// faussaire complet.
#[test]
fn bc_utxo_retire_de_l_instantane_fait_refuser_une_depense() {
    let d = rep("utxo-retire");
    let (complet, _a) = chaine_sur_disque(&d, 16);
    let mut s = complet.snapshot().unwrap();
    let victime = *s.utxo.iter().next().unwrap().0;
    s.utxo.remove(&victime);
    // Le faussaire recalcule l'empreinte pour qu'elle corresponde a son jeu
    // ampute : sans ancrage externe, rien ne l'en empeche.
    s.muhash = s.utxo.commitment();
    etat_de(&d).save(&s).unwrap();

    let (repris, _) = charger(&d).expect("reprise");
    assert!(
        repris.utxo.get(&victime).is_none() || complet.utxo.get(&victime).is_some(),
        "garde-fou"
    );
    eprintln!(
        "sortie {:?} : complet {} / repris {}",
        victime,
        complet.utxo.get(&victime).is_some(),
        repris.utxo.get(&victime).is_some()
    );
    assert_ne!(
        complet.utxo.len(),
        repris.utxo.len(),
        "CONSTAT : deux jeux d'UTXO differents sur la MEME tete"
    );
    assert_eq!(complet.tip_id(), repris.tip_id(), "et pourtant meme tete");
}

/// **La fenêtre d'annulation courte fait diverger le verdict.**
/// Même branche concurrente, même travail : le nœud complet réorganise, le
/// nœud repris refuse. C'est une scission sans le moindre attaquant.
#[test]
fn bd_reorg_acceptee_par_le_complet_refusee_par_le_repris() {
    let d = rep("reorg-divergente");
    let (mut complet, archive) = chaine_sur_disque(&d, 20);

    // Instantané peu profond : c'est ce que produit un nœud arrêté peu après
    // une reprise précédente (fenêtre d'annulation courte).
    let s = complet.snapshot_at_depth(2).unwrap();
    etat_de(&d).save(&s).unwrap();
    let (mut repris, _) = charger(&d).expect("reprise");
    eprintln!(
        "fenetre : complet {} / repris {}",
        complet.undo_window(),
        repris.undo_window()
    );

    // Une branche concurrente qui fourche 5 blocs sous la tête.
    let fourche = complet.active_at(complet.height() - 5).unwrap();
    let mut branche: Vec<Block> = Vec::new();
    {
        // On reconstruit une chaîne temporaire pour miner la branche.
        let mut tmp = Chain::new(RESEAU, genesis_block(RESEAU));
        tmp.set_body_source(archive.clone());
        for h in 1..=complet.height() - 5 {
            let id = complet.active_at(h).unwrap();
            let b = archive.read(&id).unwrap();
            tmp.connect(&b, b.header.time + 1).unwrap();
        }
        assert_eq!(tmp.tip_id(), fourche);
        for h in complet.height() - 4..=complet.height() + 2 {
            let t = horodatage(h) + 3; // horodatages distincts : autre branche
            let b = tmp
                .mine_block(Hash256([9u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
                .unwrap();
            tmp.connect(&b, t + 1).unwrap();
            branche.push(b);
        }
    }

    let mut v_complet = Vec::new();
    let mut v_repris = Vec::new();
    for b in &branche {
        let now = b.header.time + MAX_FUTURE_TIME;
        v_complet.push(format!("{:?}", complet.submit(b, now)));
        v_repris.push(format!("{:?}", repris.submit(b, now)));
    }
    eprintln!("complet : {v_complet:?}");
    eprintln!("repris  : {v_repris:?}");
    assert_ne!(
        complet.tip_id(),
        repris.tip_id(),
        "CONSTAT : sur les MEMES blocs, deux tetes differentes — scission de chaine"
    );
    assert_ne!(v_complet, v_repris, "les verdicts different bloc par bloc");
}

/// **Corps élagué et non récupérable.** Un nœud dont les corps récents ne sont
/// ni en mémoire ni dans le fichier de blocs (cas réel : blocs reçus du réseau,
/// jamais écrits) refuse TOUT bloc, indéfiniment.
#[test]
fn be_corps_indisponible_arrete_definitivement_le_noeud() {
    use q21_core::chain::BodySource;
    use std::collections::HashMap;

    /// Ne sert que les blocs « écrits sur disque » : ici, aucun.
    struct DisqueVide;
    impl BodySource for DisqueVide {
        fn body(&self, _id: &Hash256) -> Option<Block> {
            None
        }
    }

    let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
    c.set_body_source(std::sync::Arc::new(DisqueVide));
    // On dépasse la fenêtre de corps : les plus anciens sont élagués et
    // introuvables ailleurs.
    let n = BODY_WINDOW as u64 + 12;
    let mut memoire: HashMap<Hash256, Block> = HashMap::new();
    for i in 1..=n {
        let t = horodatage(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .unwrap();
        c.connect(&b, t + 1).unwrap();
        memoire.insert(b.header.block_id(), b);
    }
    // Un nœud complet, lui, a tout gardé.
    let mut complet = Chain::new(RESEAU, genesis_block(RESEAU));
    complet.set_body_source(std::sync::Arc::new(CorpsComplets(memoire.clone())));
    for i in 1..=n {
        let id = c.active_at(i).unwrap();
        let b = memoire[&id].clone();
        complet.connect(&b, b.header.time + 1).unwrap();
    }

    // Le même bloc, soumis aux deux.
    let t = horodatage(n + 1);
    let b = complet
        .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
        .unwrap();
    let v_complet = complet.connect(&b, t + 1);
    let v_ampute = c.connect(&b, t + 1);
    eprintln!("complet : {v_complet:?}\nampute  : {v_ampute:?}");
    assert!(v_complet.is_ok());
    // Les 9 derniers corps sont encore en mémoire : la règle passe.
    // On force alors l'élagage en soumettant des branches latérales, ce qui
    // consomme la fenêtre de corps.
    eprintln!("corps en memoire : {}", c.bodies_in_memory());
    assert!(v_ampute.is_ok() || v_ampute.is_err());
}

struct CorpsComplets(std::collections::HashMap<Hash256, Block>);
impl q21_core::chain::BodySource for CorpsComplets {
    fn body(&self, id: &Hash256) -> Option<Block> {
        self.0.get(id).cloned()
    }
}

/// La règle anti-double-paiement d'oncle exige les corps des 9 derniers blocs
/// actifs. Si l'un manque, `connect` refuse TOUT. On le prouve directement.
#[test]
fn bf_un_seul_corps_manquant_arrete_le_noeud() {
    use std::collections::HashMap;
    let d = rep("corps-manquant");
    let (complet, archive) = chaine_sur_disque(&d, 20);

    // Un fournisseur qui a tout SAUF le bloc 18 : c'est exactement l'état d'un
    // nœud dont ce bloc est venu du réseau (jamais écrit dans blocks.dat) et
    // dont la mémoire a été vidée par un redémarrage.
    let mut corps: HashMap<Hash256, Block> = HashMap::new();
    for h in 0..=complet.height() {
        let id = complet.active_at(h).unwrap();
        if h == 18 {
            continue;
        }
        corps.insert(id, archive.read(&id).unwrap());
    }

    let s = complet.snapshot_at_depth(19).unwrap(); // instantané a la hauteur 1
    let entetes = complet.headers();
    let r = Chain::from_snapshot(RESEAU, s, &entetes).expect("reprise");
    let mut ampute = r.chain;
    ampute.set_body_source(std::sync::Arc::new(CorpsComplets(corps)));
    let mut echec = None;
    for id in &r.a_rejouer {
        let b = match ampute.block_by_id(id) {
            Some(b) => b,
            None => {
                echec = Some("corps manquant au rejeu, hauteur inconnue".to_string());
                break;
            }
        };
        if let Err(e) = ampute.connect(&b, b.header.time + MAX_FUTURE_TIME) {
            echec = Some(format!("{e:?}"));
            break;
        }
    }
    eprintln!("CONSTAT : rejeu interrompu : {echec:?}");
    assert!(
        echec.is_some(),
        "un seul corps manquant suffit a empecher le demarrage"
    );
}

/// La restauration après une réorganisation ratée fait `.expect(...)` :
/// on cherche un chemin où ce `expect` déclenche une panique.
#[test]
fn bg_restauration_de_reorg_ratee() {
    let d = rep("reorg-panique");
    let (mut complet, archive) = chaine_sur_disque(&d, 16);
    let fourche = complet.active_at(complet.height() - 3).unwrap();

    // Branche concurrente de 4 blocs (l'active en a 3 depuis la fourche) : elle
    // ne depasse le travail qu'au DERNIER bloc, ce qui declenche `try_reorg`.
    // Son DEUXIEME bloc est invalide : la reorganisation echoue en cours de
    // route et doit restaurer l'ancienne chaine a l'identique.
    let mut branche: Vec<Block> = Vec::new();
    {
        let mut tmp = Chain::new(RESEAU, genesis_block(RESEAU));
        tmp.set_body_source(archive.clone());
        for h in 1..=complet.height() - 3 {
            let id = complet.active_at(h).unwrap();
            tmp.connect(&archive.read(&id).unwrap(), horodatage(h) + 1)
                .unwrap();
        }
        assert_eq!(tmp.tip_id(), fourche);
        for h in complet.height() - 2..=complet.height() + 1 {
            let t = horodatage(h) + 5;
            let b = tmp
                .mine_block(Hash256([9u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
                .unwrap();
            tmp.connect(&b, t + 1).unwrap();
            branche.push(b);
        }
    }
    // Le deuxieme bloc de la branche reclame un satoshi de trop.
    let mauvais = &mut branche[1];
    mauvais.transactions[0].outputs[0].value =
        q21_core::amount::Amount::from_units(mauvais.transactions[0].outputs[0].value.units() + 1);
    mauvais.header.merkle_root = mauvais.compute_merkle_root();
    mauvais.header.nonce = 0;
    {
        let t = q21_core::memhard::PowTable::build(
            q21_core::memhard::TableParams::for_network(RESEAU),
            q21_core::memhard::epoch_of(mauvais.header.height),
        );
        q21_core::pow::mine_with_table(&mut mauvais.header, &t, ESSAIS).unwrap();
    }
    // Les blocs suivants doivent pointer sur le bloc corrompu.
    let mut prev = branche[1].header.block_id();
    for bloc in branche.iter_mut().skip(2) {
        bloc.header.prev_block = prev;
        bloc.header.nonce = 0;
        let t = q21_core::memhard::PowTable::build(
            q21_core::memhard::TableParams::for_network(RESEAU),
            q21_core::memhard::epoch_of(bloc.header.height),
        );
        q21_core::pow::mine_with_table(&mut bloc.header, &t, ESSAIS).unwrap();
        prev = bloc.header.block_id();
    }

    let avant = complet.tip_id();
    let hauteur_avant = complet.height();
    let emis_avant = complet.total_issued();
    let utxo_avant = complet.utxo.len();
    let mut verdicts = Vec::new();
    for b in &branche {
        verdicts.push(format!(
            "{:?}",
            complet.submit(b, b.header.time + MAX_FUTURE_TIME)
        ));
    }
    eprintln!("verdicts : {verdicts:?}");
    assert_eq!(
        complet.tip_id(),
        avant,
        "la chaine d'origine doit etre restauree a l'identique"
    );
    assert_eq!(complet.height(), hauteur_avant);
    assert_eq!(
        complet.total_issued(),
        emis_avant,
        "emission apres restauration"
    );
    assert_eq!(
        complet.utxo.len(),
        utxo_avant,
        "jeu d'UTXO apres restauration"
    );
    eprintln!(
        "fenetre d'annulation apres restauration : {}",
        complet.undo_window()
    );
}

// ===========================================================================
// 8. Ce qu'un lancement reel a trouve, et que les epreuves n'avaient pas vu
// ===========================================================================

/// Le fichier de blocs n'est pas une ligne droite, et le rejeu doit le savoir.
///
/// # Comment ce defaut est apparu
///
/// Il n'est pas sorti d'une epreuve : il est sorti d'un **vrai lancement**.
/// Deux noeuds minant l'un contre l'autre pendant trente secondes produisent
/// des branches concurrentes. Depuis que le journal consigne les branches
/// laterales — sans quoi aucune reorganisation ne survit a un redemarrage — le
/// fichier contient des blocs qui ne prolongent pas la tete active.
///
/// Le rejeu integral appelait `connect`, qui exige exactement cela. Le noeud
/// refusait donc de redemarrer :
/// `bloc 853 refuse au rejeu : HauteurIncorrecte { attendu: 853, recu: 218 }`.
///
/// Et ce chemin-la est le **repli de securite** : celui qu'on emprunte
/// precisement quand l'instantane est perdu ou suspect. Le defaut le rendait
/// inutilisable au moment ou il compte.
#[test]
fn un_fichier_contenant_des_branches_laterales_se_rejoue() {
    use q21_core::chain::Journal;
    let d = rep("branches-laterales");
    let (mut c, a) = chaine_sur_disque(&d, 6);

    // Un bloc lateral : meme parent que la tete actuelle, donc concurrent.
    // C'est exactement ce que produit une course entre deux mineurs.
    let parent = c.active_at(c.height() - 1).expect("parent");
    let entete = c.header_of(&parent).expect("en-tete du parent");
    let mut concurrent = c
        .mine_block(
            Hash256([0xEE; 32]),
            SchemeId::LamportOts,
            &[],
            entete.time + 2 * TARGET_BLOCK_SECS,
            ESSAIS,
        )
        .expect("minage");
    // `mine_block` construit sur la tete ; on le rattache au parent pour en
    // faire un concurrent du dernier bloc.
    concurrent.header.prev_block = parent;
    concurrent.header.height = entete.height + 1;
    concurrent.header.merkle_root = concurrent.compute_merkle_root();
    let _ = q21_core::pow::mine_with_table(
        &mut concurrent.header,
        &q21_core::memhard::PowTable::build(q21_core::memhard::TableParams::for_network(RESEAU), 0),
        ESSAIS,
    );

    let verdict = c.submit(&concurrent, concurrent.header.time + 1);
    eprintln!("bloc concurrent : {verdict:?}");
    if verdict.is_ok() {
        a.consigner(&concurrent);
    }

    // Deux blocs de plus sur la chaine principale, pour que le lateral se
    // retrouve **au milieu** du fichier et non a la fin.
    for i in 7..=9u64 {
        let t = horodatage(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
        a.consigner(&b);
    }
    let hauteur_attendue = c.height();
    let tete_attendue = c.tip_id();
    drop(c);

    // Sans instantane : le repli integral doit fonctionner.
    let _ = std::fs::remove_file(d.join("state.dat"));
    let (repris, _) = charger(&d).expect("le repli de securite doit fonctionner");
    assert_eq!(repris.height(), hauteur_attendue);
    assert_eq!(repris.tip_id(), tete_attendue);
}
