//! Regressions du second audit de persistance : un bit retourne dans un
//! prefixe de longueur du fichier de blocs ne coute plus ni bloc valide, ni
//! instantane, ni revalidation.
//!
//! Chaque epreuve manipule `blocks.dat` comme le ferait une carte SD fatiguee
//! ou un arret brutal, puis rejoue l'ouverture du binaire (`BlockArchive::open`)
//! et la reprise sur instantane (`Chain::from_snapshot`).

use q21_core::address::Network;
use q21_core::block::BlockHeader;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::state::StateStore;
use q21_core::store::{BlockArchive, BlockStore};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const RESEAU: Network = Network::Regtest;
const ESSAIS: u64 = 50_000_000;

fn rep(nom: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("q21-regr-audit2-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn horodatage(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

fn etat_de(d: &Path) -> StateStore {
    let clef = q21_core::state::clef_de_repertoire(d).unwrap();
    StateStore::new_scelle(d.join("state.dat"), clef)
}

/// Mine `n` blocs et les ecrit comme le binaire : `connect` puis `append`.
fn chaine_sur_disque(d: &Path, n: u64) -> (Chain, Arc<BlockArchive>) {
    let chemin = d.join("blocks.dat");
    let g = genesis_block(RESEAU);
    BlockStore::new(&chemin).append(&g).unwrap();
    let (archive, _, _) = BlockArchive::open(&chemin, RESEAU).unwrap();
    let archive = Arc::new(archive);
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

/// Positions (debut du prefixe de longueur) et longueurs de chaque
/// enregistrement, lues en suivant les prefixes tels qu'ils sont.
fn prefixes(chemin: &Path) -> Vec<(u64, u32)> {
    let brut = std::fs::read(chemin).unwrap();
    let mut v = Vec::new();
    let mut p = 0usize;
    while p + 4 <= brut.len() {
        let t = u32::from_le_bytes(brut[p..p + 4].try_into().unwrap());
        v.push((p as u64, t));
        p += 4 + t as usize;
    }
    v
}

fn retourner_un_bit(chemin: &Path, position: u64, masque: u8) {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(chemin)
        .unwrap();
    f.seek(SeekFrom::Start(position)).unwrap();
    let mut o = [0u8; 1];
    f.read_exact(&mut o).unwrap();
    f.seek(SeekFrom::Start(position)).unwrap();
    f.write_all(&[o[0] ^ masque]).unwrap();
}

/// Tous les blocs de la chaine se relisent depuis l'archive.
fn tout_se_relit(c: &Chain, archive: &BlockArchive, jusqu_a: u64) {
    for h in 0..=jusqu_a {
        let id = c.active_at(h).unwrap();
        assert!(archive.read(&id).is_some(), "le bloc {h} ne se relit plus");
    }
}

// ===========================================================================
// P1 — un bit dans un prefixe de longueur pres de la fin.
// ===========================================================================

/// Le defaut : la reparation de queue coupait jusqu'a `MAX_BLOCK_SIZE + 4`
/// octets apres le dernier enregistrement complet — onze blocs valides ici,
/// des milliers sur une vraie chaine — et l'instantane, pris sous la tete,
/// ne designait plus rien. Attendu desormais : le prefixe est reecrit, les
/// 61 en-tetes sont la, rien n'est coupe, l'instantane tient.
#[test]
fn un_bit_dans_un_prefixe_pres_de_la_fin_ne_coupe_aucun_bloc() {
    let d = rep("p1-prefixe-fin");
    let chemin = d.join("blocks.dat");
    let (c, archive) = chaine_sur_disque(&d, 60);
    let inst = c.snapshot_at_depth(5).unwrap();
    assert_eq!(inst.height, 55);
    etat_de(&d).save(&inst).unwrap();
    drop(archive);
    let taille_saine = std::fs::metadata(&chemin).unwrap().len();

    let enregs = prefixes(&chemin);
    assert_eq!(enregs.len(), 61);
    // Bit 20 (+1 Mio) dans le prefixe du bloc 50 : la longueur pointe au-dela
    // de la fin du fichier, comme une ecriture interrompue.
    let (pos50, _) = enregs[50];
    retourner_un_bit(&chemin, pos50 + 2, 0x10);

    let (archive, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    eprintln!("en-tetes : {}, souci : {:?}", entetes.len(), souci);
    assert_eq!(entetes.len(), 61, "aucun bloc valide ne doit etre perdu");
    assert!(souci.is_none(), "le prefixe repare, plus rien a signaler");
    assert_eq!(
        std::fs::metadata(&chemin).unwrap().len(),
        taille_saine,
        "rien n'a ete coupe"
    );
    assert!(
        !d.join("blocks.dat.coupe").exists(),
        "rien n'a ete jete, donc pas de copie"
    );
    assert_eq!(prefixes(&chemin), enregs, "le prefixe a retrouve sa valeur");
    tout_se_relit(&c, &archive, 60);

    // L'instantane (hauteur 55) est toujours sur la chaine visible.
    let r = Chain::from_snapshot(RESEAU, inst, &entetes).expect("reprise sur instantane");
    assert_eq!(r.a_rejouer.len(), 5, "il ne reste que 56..=60 a rejouer");
    drop(archive);

    // Une seconde ouverture ne trouve plus rien a reparer.
    let (_a, entetes2, souci2) = BlockArchive::open(&chemin, RESEAU).unwrap();
    assert_eq!(entetes2.len(), 61);
    assert!(souci2.is_none());
    let _ = std::fs::remove_dir_all(&d);
}

/// Un prefixe trop **court** sur le dernier enregistrement : le balayage
/// accepte le bloc avec une longueur fausse, puis lit n'importe quoi. Meme
/// remede : la longueur reelle est retrouvee en decodant le bloc.
#[test]
fn un_prefixe_trop_court_sur_le_dernier_bloc_est_reecrit() {
    let d = rep("p1-prefixe-court");
    let chemin = d.join("blocks.dat");
    let (c, archive) = chaine_sur_disque(&d, 30);
    drop(archive);
    let enregs = prefixes(&chemin);
    let (pos30, _) = enregs[30];
    // Bit 3 (-8) : la longueur annoncee est plus courte que le bloc.
    retourner_un_bit(&chemin, pos30, 0x08);

    let (archive, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    eprintln!("en-tetes : {}, souci : {:?}", entetes.len(), souci);
    assert_eq!(entetes.len(), 31);
    assert!(souci.is_none());
    assert_eq!(prefixes(&chemin), enregs);
    tout_se_relit(&c, &archive, 30);
    let _ = std::fs::remove_dir_all(&d);
}

/// Une ecriture reellement interrompue — le fichier s'arrete au milieu du
/// dernier bloc — reste reparee comme avant : le fragment est coupe, copie
/// gardee, les blocs complets restent.
#[test]
fn une_ecriture_reellement_interrompue_est_toujours_coupee() {
    let d = rep("p1-interrompue");
    let chemin = d.join("blocks.dat");
    let (c, archive) = chaine_sur_disque(&d, 60);
    drop(archive);
    let enregs = prefixes(&chemin);
    let (pos60, len60) = enregs[60];
    let fin_59 = pos60;
    // Le fichier s'arrete a la moitie du bloc 60.
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&chemin)
        .unwrap();
    f.set_len(pos60 + 4 + u64::from(len60) / 2).unwrap();
    drop(f);

    let (archive, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    eprintln!("en-tetes : {}, souci : {:?}", entetes.len(), souci);
    assert_eq!(entetes.len(), 60, "0..=59 restent");
    assert!(souci.is_none(), "la queue coupee, plus rien a signaler");
    assert_eq!(std::fs::metadata(&chemin).unwrap().len(), fin_59);
    assert!(
        d.join("blocks.dat.coupe").exists(),
        "le fragment est garde a cote"
    );
    tout_se_relit(&c, &archive, 59);
    let _ = std::fs::remove_dir_all(&d);
}

/// Les deux a la fois : un prefixe abime au bloc 50 **et** une ecriture
/// interrompue au bloc 60. Le prefixe est reecrit, seul le fragment final est
/// coupe.
#[test]
fn un_prefixe_abime_puis_une_ecriture_interrompue_se_reparent_tous_deux() {
    let d = rep("p1-les-deux");
    let chemin = d.join("blocks.dat");
    let (c, archive) = chaine_sur_disque(&d, 60);
    drop(archive);
    let enregs = prefixes(&chemin);
    let (pos60, len60) = enregs[60];
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&chemin)
        .unwrap();
    f.set_len(pos60 + 4 + u64::from(len60) / 2).unwrap();
    drop(f);
    let (pos50, _) = enregs[50];
    retourner_un_bit(&chemin, pos50 + 2, 0x10);

    let (archive, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    eprintln!("en-tetes : {}, souci : {:?}", entetes.len(), souci);
    assert_eq!(entetes.len(), 60);
    assert!(souci.is_none());
    assert_eq!(std::fs::metadata(&chemin).unwrap().len(), pos60);
    tout_se_relit(&c, &archive, 59);
    let _ = std::fs::remove_dir_all(&d);
}

/// Sur un fichier elague, le premier bloc de la fenetre n'a plus son parent
/// dans le fichier. Son prefixe abime doit quand meme se reparer : c'est le
/// successeur qui l'atteste.
#[test]
fn un_prefixe_abime_sur_le_premier_bloc_d_une_fenetre_elaguee_est_reecrit() {
    let d = rep("p1-elague");
    let chemin = d.join("blocks.dat");
    let (c, archive) = chaine_sur_disque(&d, 40);
    let bilan = archive
        .elaguer(|h| h.height == 0 || h.height >= 30)
        .unwrap();
    assert_eq!(bilan.conserves, 12);
    drop(archive);
    let enregs = prefixes(&chemin);
    assert_eq!(enregs.len(), 12);
    // L'enregistrement 1 est le bloc 30, dont le parent (29) a ete retire.
    let (pos1, _) = enregs[1];
    retourner_un_bit(&chemin, pos1 + 2, 0x10);

    let (archive, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    eprintln!("en-tetes : {}, souci : {:?}", entetes.len(), souci);
    assert_eq!(entetes.len(), 12);
    assert!(souci.is_none());
    for h in 30..=40 {
        assert!(archive.read(&c.active_at(h).unwrap()).is_some());
    }
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// P6 — un bit dans un prefixe AU MILIEU du fichier, sous l'instantane.
// ===========================================================================

/// Avant : le balayage s'arretait au bloc abime, l'instantane n'etait plus
/// sur la chaine visible (revalidation integrale), puis le corps illisible
/// faisait couper le fichier a 0..=19 et tout retelecharger. Desormais : le
/// prefixe est reecrit a l'ouverture, l'instantane tient, rien n'est a
/// refaire.
#[test]
fn un_bit_dans_un_prefixe_au_milieu_ne_coute_ni_revalidation_ni_coupe() {
    let d = rep("p6-milieu");
    let chemin = d.join("blocks.dat");
    let (c, archive) = chaine_sur_disque(&d, 40);
    let inst = c.snapshot_at_depth(5).unwrap();
    assert_eq!(inst.height, 35);
    etat_de(&d).save(&inst).unwrap();
    drop(archive);
    let taille_saine = std::fs::metadata(&chemin).unwrap().len();
    let enregs = prefixes(&chemin);
    let (pos20, _) = enregs[20];
    retourner_un_bit(&chemin, pos20, 0x08);

    let (archive, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    eprintln!("en-tetes : {}, souci : {:?}", entetes.len(), souci);
    assert_eq!(entetes.len(), 41);
    assert!(souci.is_none());
    assert_eq!(std::fs::metadata(&chemin).unwrap().len(), taille_saine);
    tout_se_relit(&c, &archive, 40);
    let r = Chain::from_snapshot(RESEAU, inst, &entetes).expect("reprise sur instantane");
    assert_eq!(r.a_rejouer.len(), 5);
    let _ = std::fs::remove_dir_all(&d);
}

/// Un bit dans le **corps** d'un bloc au milieu du fichier (pas dans le
/// prefixe, pas dans l'en-tete) : rien ne peut le reparer sans le reseau. Le
/// balayage ne voit rien, la lecture du corps echoue, le binaire coupe
/// l'archive a cette hauteur et le reseau refournit ; ce qui est ecrit
/// ensuite se relit. Un cout — revalidation et retelechargement — jamais une
/// perte. L'archive le dit a l'operateur, une fois, en nommant la cause.
#[test]
fn un_bit_dans_un_corps_au_milieu_coute_une_coupe_mais_rien_n_est_perdu() {
    let d = rep("p6-corps");
    let chemin = d.join("blocks.dat");
    let (c, archive) = chaine_sur_disque(&d, 40);
    drop(archive);
    let enregs = prefixes(&chemin);
    let (pos20, len20) = enregs[20];
    // Un bit dans la longueur de la coinbase du bloc 20 (juste apres le
    // compte de transactions) : le corps ne se decode plus. Un bit dans un
    // champ de valeur, lui, se decoderait et ne tomberait qu'a la validation
    // (racine de Merkle) — meme issue dans le binaire, par un autre chemin.
    retourner_un_bit(&chemin, pos20 + 4 + BlockHeader::SIZE as u64 + 1, 0x40);
    assert!(len20 > BlockHeader::SIZE as u32 + 2);

    let (archive, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    assert_eq!(entetes.len(), 41, "les en-tetes sont intacts");
    assert!(souci.is_none(), "le balayage ne voit rien : c'est normal");
    let id20 = c.active_at(20).unwrap();
    assert!(archive.read(&id20).is_none(), "le corps 20 ne se relit pas");
    assert!(
        archive.read(&id20).is_none(),
        "seconde lecture : meme reponse, sans second message"
    );
    // Le chemin du binaire : couper a partir de 20, puis le reseau refournit.
    let bilan = archive.elaguer(|h| h.height < 20).unwrap();
    assert_eq!(bilan.conserves, 20);
    for h in 20..=40 {
        archive.append(&c.block_at(h).unwrap()).unwrap();
    }
    drop(archive);
    let (archive, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    assert_eq!(entetes.len(), 41);
    assert!(souci.is_none());
    tout_se_relit(&c, &archive, 40);
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// P4 — un bit dans le prefixe de longueur de la GENESE.
// ===========================================================================

/// Avant : « en-tetes 1, BlocTropGros » (longueur reduite) ou « en-tetes 0,
/// FichierTronque » (longueur agrandie), et le noeud mourait en conseillant
/// `q21 init`. Attendu : la genese est recopiee, prefixe compris, et les 30
/// blocs qui suivent sont relus.
#[test]
fn un_bit_dans_le_prefixe_de_la_genese_est_repare() {
    let d = rep("p4-prefixe-genese");
    let chemin = d.join("blocks.dat");
    let (c, archive) = chaine_sur_disque(&d, 30);
    let inst = c.snapshot_at_depth(5).unwrap();
    etat_de(&d).save(&inst).unwrap();
    drop(archive);
    let sain = std::fs::read(&chemin).unwrap();

    for (masque, decalage, nom) in [
        (0x08u8, 0u64, "bit 3, longueur -8"),
        (0x10, 2, "bit 20, longueur +1 Mio"),
        (0x01, 0, "bit 0, longueur +1"),
        (0xff, 3, "octet de poids fort retourne"),
    ] {
        std::fs::write(&chemin, &sain).unwrap();
        retourner_un_bit(&chemin, decalage, masque);
        let (archive, entetes, souci) =
            BlockArchive::open(&chemin, RESEAU).unwrap_or_else(|e| panic!("{nom} : {e}"));
        eprintln!("{nom} : en-tetes {}, souci {:?}", entetes.len(), souci);
        assert_eq!(entetes.len(), 31, "{nom}");
        assert!(souci.is_none(), "{nom}");
        assert_eq!(
            std::fs::read(&chemin).unwrap(),
            sain,
            "{nom} : fichier restaure a l'identique"
        );
        tout_se_relit(&c, &archive, 30);
        let r = Chain::from_snapshot(RESEAU, inst.clone(), &entetes);
        assert!(r.is_ok(), "{nom} : l'instantane doit tenir");
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// Prefixe **et** en-tete de la genese abimes : la suite du fichier suffit
/// a la reconnaitre.
#[test]
fn prefixe_et_entete_de_la_genese_abimes_ensemble_sont_repares() {
    let d = rep("p4-prefixe-et-entete");
    let chemin = d.join("blocks.dat");
    let (c, archive) = chaine_sur_disque(&d, 10);
    drop(archive);
    let sain = std::fs::read(&chemin).unwrap();
    retourner_un_bit(&chemin, 1, 0x04);
    retourner_un_bit(&chemin, 4 + BlockHeader::SIZE as u64 - 1, 0x01);

    let (archive, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    assert_eq!(entetes.len(), 11);
    assert!(souci.is_none());
    assert_eq!(std::fs::read(&chemin).unwrap(), sain);
    tout_se_relit(&c, &archive, 10);
    let _ = std::fs::remove_dir_all(&d);
}

/// Un fichier qui n'est pas le notre — premier enregistrement etranger,
/// aucune suite qui s'enchaine sur notre genese — n'est pas « repare » : il
/// est refuse, comme avant.
#[test]
fn une_genese_etrangere_n_est_pas_ecrasee_par_la_reparation() {
    let d = rep("p4-etrangere");
    let chemin = d.join("blocks.dat");
    // Une chaine d'un autre reseau, ecrite dans le fichier.
    let g = genesis_block(Network::Testnet);
    let s = BlockStore::new(&chemin);
    s.append(&g).unwrap();
    let mut b = g.clone();
    b.header.height = 1;
    b.header.prev_block = g.header.block_id();
    s.append(&b).unwrap();
    let avant = std::fs::read(&chemin).unwrap();

    let r = BlockArchive::open(&chemin, RESEAU);
    assert!(
        matches!(r, Err(q21_core::store::StoreError::GeneseEtrangere { .. })),
        "attendu GeneseEtrangere"
    );
    assert_eq!(std::fs::read(&chemin).unwrap(), avant, "rien n'a ete ecrit");
    let _ = std::fs::remove_dir_all(&d);
}

/// Une queue de zeros — ce qu'un systeme de fichiers laisse apres une
/// coupure — se decode en « bloc » (en-tete nul, zero transaction) mais ne se
/// rattache a rien : elle est coupee, pas adoptee.
#[test]
fn une_queue_de_zeros_n_est_pas_prise_pour_un_bloc() {
    let d = rep("p1-zeros");
    let chemin = d.join("blocks.dat");
    let (_c, archive) = chaine_sur_disque(&d, 5);
    drop(archive);
    let sain = std::fs::metadata(&chemin).unwrap().len();
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&chemin)
            .unwrap();
        // Un prefixe plausible (300 octets), puis 1000 zeros : plus que le
        // prefixe n'annonce, moins qu'un bloc.
        f.write_all(&300u32.to_le_bytes()).unwrap();
        f.write_all(&vec![0u8; 1000]).unwrap();
    }
    // Le prefixe dit 300, il y a 1000 octets : ce n'est pas une troncature.
    // Le balayage voit un enregistrement de 300 zeros puis un prefixe nul ;
    // les 162 premiers zeros forment un « bloc » decodable, mais qui ne se
    // rattache a rien : le prefixe ne doit pas etre reecrit a 162.
    let avant = std::fs::read(&chemin).unwrap();
    let (_a, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    eprintln!("zeros : en-tetes {}, souci {:?}", entetes.len(), souci);
    assert!(souci.is_some(), "l'incident reste signale");
    assert_eq!(
        std::fs::read(&chemin).unwrap(),
        avant,
        "rien n'a ete reecrit"
    );
    // Et une vraie queue tronquee de zeros (prefixe qui deborde) est coupee.
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&chemin)
        .unwrap();
    f.set_len(sain).unwrap();
    drop(f);
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&chemin)
            .unwrap();
        f.write_all(&2000u32.to_le_bytes()).unwrap();
        f.write_all(&vec![0u8; 1000]).unwrap();
    }
    let (_a, entetes, souci) = BlockArchive::open(&chemin, RESEAU).unwrap();
    eprintln!(
        "zeros tronques : en-tetes {}, souci {:?}",
        entetes.len(),
        souci
    );
    assert_eq!(entetes.len(), 6);
    assert!(souci.is_none(), "la queue de zeros a ete coupee");
    assert_eq!(std::fs::metadata(&chemin).unwrap().len(), sain);
    let _ = std::fs::remove_dir_all(&d);
}
