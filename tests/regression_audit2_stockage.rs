//! Regressions du second audit de persistance : un bit retourne dans un
//! prefixe de longueur du fichier de blocs ne coute plus ni bloc valide, ni
//! instantane, ni revalidation (P1, P4, P6) ; un noeud elague ou adopte
//! redemarre quoi qu'il arrive a ses en-tetes, et se resynchronise (P2) ; un
//! instantane dont l'ecriture a echoue n'autorise aucun elagage (P3).
//!
//! Chaque epreuve manipule `blocks.dat`, `entetes.dat` ou `state.dat` comme le
//! ferait une carte SD fatiguee, un disque plein ou un arret brutal, puis
//! rejoue le demarrage du binaire — `BlockArchive::open`, puis
//! `q21_core::elagage::reprendre_la_chaine`, le chemin meme du binaire.

use q21_core::address::Network;
use q21_core::block::BlockHeader;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::net::Node;
use q21_core::sig::SchemeId;
use q21_core::state::StateStore;
use q21_core::store::{BlockArchive, BlockStore, HeaderStore};
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

// ===========================================================================
// P2 — un noeud elague ou adopte n'avait aucune voie de repli.
// ===========================================================================

/// Le demarrage du binaire, apres `BlockArchive::open` : le meme appel.
fn redemarrer(d: &Path) -> Result<(Arc<BlockArchive>, Chain), String> {
    let (archive, entetes, souci) =
        BlockArchive::open(d.join("blocks.dat"), RESEAU).map_err(|e| e.to_string())?;
    if let Some(s) = souci {
        eprintln!("avertissement : {s}");
    }
    let archive = Arc::new(archive);
    let magasin = HeaderStore::new(d.join("entetes.dat"));
    let chain =
        q21_core::elagage::reprendre_la_chaine(RESEAU, &archive, entetes, &magasin, &etat_de(d))?;
    Ok((archive, chain))
}

/// Un dossier elague : le magasin couvre `0..=magasin`, les corps sous
/// `premier_corps` sont retires, l'instantane est a `instantane`.
fn dossier_elague(
    d: &Path,
    n: u64,
    magasin: u64,
    premier_corps: u64,
    instantane: u64,
) -> (Chain, Arc<BlockArchive>) {
    let (c, archive) = chaine_sur_disque(d, n);
    HeaderStore::new(d.join("entetes.dat"))
        .append(&c.headers()[..=magasin as usize])
        .unwrap();
    let inst = c.snapshot_at_depth((n - instantane) as usize).unwrap();
    assert_eq!(inst.height, instantane);
    etat_de(d).save(&inst).unwrap();
    archive
        .elaguer(|h| h.height == 0 || h.height >= premier_corps)
        .unwrap();
    (c, archive)
}

/// Attend qu'une condition devienne vraie, sans bloquer indefiniment.
fn attendre(mut cond: impl FnMut() -> bool, secondes: u64) -> bool {
    let debut = std::time::Instant::now();
    while debut.elapsed() < std::time::Duration::from_secs(secondes) {
        if cond() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    cond()
}

/// Le noeud repare, branche sur son archive, rattrape un pair complet.
///
/// Un noeud complet sert la chaine `c` ; le noeud repris `chain` journalise
/// dans `archive`. A la sortie, le noeud repris est a la tete de `c`.
fn se_resynchronise_depuis_un_pair(c: Chain, chain: Chain, archive: Arc<BlockArchive>) {
    let cible = c.height();
    let tete = c.tip_id();
    let valeur = c.utxo.total_value();
    let complet = Node::new(RESEAU, c);
    let repris = Node::new(RESEAU, chain);
    repris.set_journal(archive);
    let addr = complet.listen("127.0.0.1:0").expect("ecoute");
    repris.connect(addr).expect("connexion");
    assert!(
        attendre(|| repris.height() == cible, 60),
        "le noeud repris est reste a la hauteur {} sur {cible}",
        repris.height()
    );
    assert_eq!(repris.tip_id(), tete, "les tetes doivent coincider");
    assert_eq!(
        repris.with_chain(|ch| ch.utxo.total_value()),
        valeur,
        "les jeux d'UTXO doivent coincider"
    );
    complet.shutdown();
    repris.shutdown();
}

/// Epreuve D. Avant : un bit dans le champ `time` de l'en-tete 15 de
/// `entetes.dat` rendait le magasin illisible (`EntetesMaillonRompu`), le
/// binaire refusait de demarrer et conseillait de repartir « dans un dossier
/// vide » — celui qui contient le portefeuille. Attendu : le magasin est
/// tronque a la derniere position saine, le noeud demarre a une hauteur au
/// plus egale a la hauteur saine, et un pair complet le ramene a la tete.
#[test]
fn d_un_bit_dans_entetes_dat_ne_condamne_plus_un_dossier_elague() {
    let d = rep("p2-d-entetes");
    let (c, archive) = dossier_elague(&d, 60, 40, 41, 50);
    drop(archive);
    let entetes = d.join("entetes.dat");
    let taille = std::fs::metadata(&entetes).unwrap().len();
    // Un bit dans le champ `time` de l'en-tete 15 : le maillon 16 ne
    // s'enchaine plus.
    let position = 12 + 15 * BlockHeader::SIZE as u64 + 4 + 32 * 4;
    assert!(position < taille);
    retourner_un_bit(&entetes, position, 0x01);

    let (archive, chain) = redemarrer(&d).expect("le noeud demarre");
    eprintln!("D : hauteur au redemarrage {}", chain.height());
    assert!(chain.height() <= 50, "au plus la hauteur saine");
    // Le magasin a ete tronque au premier maillon rompu : 0..=15 restent,
    // l'en-tete 15 lui-meme etant celui dont un bit a change (il s'enchaine
    // encore sur 14 ; c'est 16 qui ne s'enchaine plus sur lui).
    let magasin = HeaderStore::new(&entetes);
    let relus = magasin.load(RESEAU).unwrap();
    assert_eq!(relus.len(), 16);
    assert_eq!(
        std::fs::metadata(&entetes).unwrap().len(),
        12 + 16 * BlockHeader::SIZE as u64
    );
    assert!(
        archive.read(&c.active_at(0).unwrap()).is_some(),
        "la genese se relit"
    );

    let tete = c.tip_id();
    se_resynchronise_depuis_un_pair(c, chain, archive.clone());
    // Ce qui a ete resynchronise se relit au redemarrage suivant.
    drop(archive);
    let (_, chain2) = redemarrer(&d).expect("second demarrage");
    assert_eq!(chain2.height(), 60);
    assert_eq!(chain2.tip_id(), tete);
    // Et le magasin se complete depuis la chaine — l'en-tete 15 abime, que la
    // chaine dement, est retire et reecrit : le noeud elaguera de nouveau.
    let ajoutes = q21_core::elagage::completer_le_magasin(&chain2, &magasin, 50).unwrap();
    assert_eq!(ajoutes, 36, "15..=50 reecrits");
    let relus = magasin.load(RESEAU).unwrap();
    assert_eq!(relus.len(), 51);
    assert!(relus
        .iter()
        .all(|h| chain2.active_at(h.height) == Some(h.block_id())));
    let _ = std::fs::remove_dir_all(&d);
}

/// Epreuve H. Avant : magasin `0..=20`, instantane a 50, un bit dans le
/// nonce de l'en-tete du bloc 35 dans `blocks.dat` — entre le magasin et
/// l'instantane, la fenetre vitale d'un noeud elague. Le balayage ne voyait
/// rien, `from_snapshot` rendait `InstantaneHorsChaine`, le binaire refusait
/// de demarrer. Attendu : le noeud demarre (hauteur au plus 50), et le pair
/// complet le ramene a 60.
#[test]
fn h_un_bit_dans_un_entete_sous_l_instantane_ne_condamne_plus_un_noeud_elague() {
    let d = rep("p2-h-entete");
    let chemin = d.join("blocks.dat");
    let (c, archive) = dossier_elague(&d, 60, 20, 21, 50);
    drop(archive);
    // Le bloc 35 est le 15e enregistrement du fichier elague (genese, puis
    // 21..). Un bit dans son nonce : l'en-tete se decode, mais n'est plus lui.
    let enregs = prefixes(&chemin);
    let (pos35, _) = enregs[1 + (35 - 21)];
    retourner_un_bit(&chemin, pos35 + 4 + BlockHeader::SIZE as u64 - 1, 0x01);

    let (archive, chain) = redemarrer(&d).expect("le noeud demarre");
    eprintln!("H : hauteur au redemarrage {}", chain.height());
    assert!(chain.height() <= 50, "au plus la hauteur saine");
    assert!(
        archive.read(&c.active_at(0).unwrap()).is_some(),
        "la genese se relit"
    );

    se_resynchronise_depuis_un_pair(c, chain, archive.clone());
    drop(archive);
    let (_, chain2) = redemarrer(&d).expect("second demarrage");
    assert_eq!(chain2.height(), 60);
    let _ = std::fs::remove_dir_all(&d);
}

/// La fenetre AU-DESSUS de l'instantane : un bit dans la racine de Merkle de
/// l'en-tete 55 d'un dossier elague (magasin `0..=40`, instantane a 50). Le
/// rejeu s'arrete au dernier bloc sain, l'archive est coupee la, et le pair
/// refournit 55..=60 — le chemin du noeud complet, reutilise tel quel.
#[test]
fn un_en_tete_abime_au_dessus_de_l_instantane_coute_une_coupe_et_le_reseau_refournit() {
    let d = rep("p2-fenetre-haute");
    let chemin = d.join("blocks.dat");
    let (c, archive) = dossier_elague(&d, 60, 40, 41, 50);
    drop(archive);
    let enregs = prefixes(&chemin);
    let (pos55, _) = enregs[1 + (55 - 41)];
    // Octet 4 (prefixe) + 4 (version) + 32 (parent) : la racine de Merkle.
    retourner_un_bit(&chemin, pos55 + 4 + 4 + 32, 0x01);

    let (archive, chain) = redemarrer(&d).expect("le noeud demarre");
    eprintln!("fenetre haute : hauteur au redemarrage {}", chain.height());
    assert_eq!(chain.height(), 54, "le rejeu s'arrete au dernier bloc sain");
    assert_eq!(chain.tip_id(), c.active_at(54).unwrap());

    let tete = c.tip_id();
    se_resynchronise_depuis_un_pair(c, chain, archive.clone());
    drop(archive);
    let (_, chain2) = redemarrer(&d).expect("second demarrage");
    assert_eq!(chain2.height(), 60);
    assert_eq!(chain2.tip_id(), tete);
    let _ = std::fs::remove_dir_all(&d);
}

/// Un magasin qui n'en est pas un (magie fausse) : il est mis de cote sous
/// `entetes.dat.abime`, le noeud demarre sur ce que le fichier de blocs
/// permet, et le reseau refournit.
#[test]
fn un_magasin_d_en_tetes_inutilisable_est_mis_de_cote_et_le_noeud_demarre() {
    let d = rep("p2-magasin-magie");
    let (c, archive) = dossier_elague(&d, 60, 40, 41, 50);
    drop(archive);
    retourner_un_bit(&d.join("entetes.dat"), 0, 0xff);

    let (archive, chain) = redemarrer(&d).expect("le noeud demarre");
    assert!(chain.height() <= 50);
    assert!(
        d.join("entetes.dat.abime").exists(),
        "le magasin est mis de cote"
    );
    assert!(!d.join("entetes.dat").exists());
    se_resynchronise_depuis_un_pair(c, chain, archive.clone());
    drop(archive);
    let (_, chain2) = redemarrer(&d).expect("second demarrage");
    assert_eq!(chain2.height(), 60);
    let _ = std::fs::remove_dir_all(&d);
}

/// Le magasin est complete a chaque instantane, pas seulement a l'elagage :
/// la fenetre vitale (dernier elagage, instantane] n'existe plus. Ici, un
/// dossier elague dont le magasin s'arrete a 20 ; l'instantane a 50 vient
/// d'etre ecrit ; le magasin est complete jusqu'a 50 sans relire le fichier,
/// et un bit dans l'en-tete 35 de `blocks.dat` ne coute plus rien.
#[test]
fn le_magasin_complete_a_chaque_instantane_fait_disparaitre_la_fenetre_vitale() {
    let d = rep("p2-completion");
    let chemin = d.join("blocks.dat");
    let (c, archive) = dossier_elague(&d, 60, 20, 21, 50);
    let magasin = HeaderStore::new(d.join("entetes.dat"));
    assert_eq!(magasin.compte(), Some(21));
    let ajoutes = q21_core::elagage::completer_le_magasin(&c, &magasin, 50).unwrap();
    assert_eq!(ajoutes, 30);
    assert_eq!(magasin.compte(), Some(51));
    assert_eq!(magasin.dernier().map(|h| h.height), Some(50));
    // Rien a faire une seconde fois.
    assert_eq!(
        q21_core::elagage::completer_le_magasin(&c, &magasin, 50).unwrap(),
        0
    );
    drop(archive);

    let enregs = prefixes(&chemin);
    let (pos35, _) = enregs[1 + (35 - 21)];
    retourner_un_bit(&chemin, pos35 + 4 + BlockHeader::SIZE as u64 - 1, 0x01);
    let (_, chain) = redemarrer(&d).expect("le noeud demarre");
    assert_eq!(
        chain.height(),
        60,
        "l'instantane tient, le rejeu va jusqu'a la tete"
    );
    assert_eq!(chain.tip_id(), c.tip_id());
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// P3 — elaguer sur la foi d'un instantane qui n'a pas ete ecrit.
// ===========================================================================

/// Epreuve C. Avant : instantane sur le disque a 100, ecriture de celui a
/// 115 en echec (`state.tmp` est un dossier : le renommage echoue, comme un
/// disque plein ou un fichier tenu par un antivirus) ; l'elagage recevait
/// 115 de l'appelant et retirait 109 corps ; au redemarrage, 9 corps a
/// rejouer manquaient et l'archive etait ramenee a la genese. Attendu :
/// l'elagage relit la hauteur du disque (100), la trouve plus ancienne que
/// la fenetre, refuse et le dit, le fichier est intact ; une fois l'ecriture
/// reussie, il elague normalement et le redemarrage retrouve la tete.
#[test]
fn c_un_instantane_non_ecrit_n_autorise_aucun_elagage() {
    use q21_core::elagage::{elaguer, Politique};
    let d = rep("p3-c-instantane");
    let (c, archive) = chaine_sur_disque(&d, 120);
    let magasin = HeaderStore::new(d.join("entetes.dat"));
    let etat = etat_de(&d);
    let ancien = c.snapshot_at_depth(20).unwrap();
    assert_eq!(ancien.height, 100);
    etat.save(&ancien).unwrap();

    std::fs::create_dir_all(d.join("state.tmp")).unwrap();
    let nouveau = c.snapshot_at_depth(5).unwrap();
    assert_eq!(nouveau.height, 115);
    assert!(
        etat.save(&nouveau).is_err(),
        "l'ecriture de l'instantane echoue"
    );

    // Quinze corps conserves : plus que ce que la regle des oncles relit
    // (`MAX_UNCLE_AGE`), moins que ce qui separe l'ancien instantane de la
    // tete.
    let politique = Politique {
        corps_conserves: 15,
        pas: 1,
    };
    let mut derniere = 0;
    let avant = archive.len();
    let r = elaguer(
        &c,
        &archive,
        &magasin,
        &etat,
        RESEAU,
        politique,
        &mut derniere,
    );
    let message = r.as_ref().err().cloned().unwrap_or_default();
    eprintln!("C, ecriture en echec : {message}");
    assert!(
        message.contains("hauteur 100") && message.contains("plus ancien que la fenetre"),
        "l'elagage doit etre refuse en nommant la cause, obtenu {r:?}"
    );
    assert_eq!(archive.len(), avant, "aucun corps retire");
    assert!(!magasin.exists(), "rien n'a ete ecrit dans le magasin");
    assert_eq!(derniere, 0, "un refus ne compte pas comme un elagage");

    // L'ecriture reussit : l'elagage reprend son cours normal.
    std::fs::remove_dir_all(d.join("state.tmp")).unwrap();
    etat.save(&nouveau).unwrap();
    let bilan = elaguer(
        &c,
        &archive,
        &magasin,
        &etat,
        RESEAU,
        politique,
        &mut derniere,
    )
    .expect("elagage")
    .expect("il y avait a elaguer");
    eprintln!(
        "C, ecriture reussie : {} retires, {} conserves",
        bilan.retires, bilan.conserves
    );
    assert_eq!(bilan.conserves, 1 + 16); // genese + 105..=120
    assert_eq!(
        magasin.load(RESEAU).unwrap().last().map(|h| h.height),
        Some(115)
    );
    drop(archive);

    // Redemarrage : rien ne manque, la tete est retrouvee.
    let (_, chain) = redemarrer(&d).expect("le noeud redemarre");
    assert_eq!(chain.height(), 120, "aucune regression");
    assert_eq!(chain.tip_id(), c.tip_id());
    let _ = std::fs::remove_dir_all(&d);
}

/// Variante : `state.dat` lui-meme est devenu un dossier — plus aucun
/// instantane lisible sur le disque. L'elagage refuse aussi.
#[test]
fn un_instantane_illisible_sur_le_disque_n_autorise_aucun_elagage() {
    use q21_core::elagage::{elaguer, Politique};
    let d = rep("p3-illisible");
    let (c, archive) = chaine_sur_disque(&d, 120);
    let magasin = HeaderStore::new(d.join("entetes.dat"));
    let etat = etat_de(&d);
    std::fs::create_dir_all(d.join("state.dat")).unwrap();
    assert!(etat.save(&c.snapshot_at_depth(5).unwrap()).is_err());
    let politique = Politique {
        corps_conserves: 10,
        pas: 1,
    };
    let mut derniere = 0;
    let avant = archive.len();
    let r = elaguer(
        &c,
        &archive,
        &magasin,
        &etat,
        RESEAU,
        politique,
        &mut derniere,
    );
    let message = r.as_ref().err().cloned().unwrap_or_default();
    eprintln!("state.dat illisible : {message}");
    assert!(message.contains("illisible"), "obtenu {r:?}");
    assert_eq!(archive.len(), avant, "aucun corps retire");
    assert!(!magasin.exists());
    let _ = std::fs::remove_dir_all(&d);
}
