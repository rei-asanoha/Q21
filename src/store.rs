//! Stockage persistant.
//!
//! Un fichier en ajout seul : chaque bloc precede de sa longueur sur quatre
//! octets. Aucune base de donnees ne s'interpose entre le disque et le
//! consensus ; le fichier reste inspectable a la main.
//!
//! # Ce que la phase 7 a change
//!
//! Jusqu'ici, demarrer signifiait tout relire **et tout revalider** depuis la
//! genese. Sur quelques milliers de blocs c'etait instantane ; sur un million,
//! avec 660 us de preuve de travail par bloc et des signatures ML-DSA a
//! verifier, cela devenait des heures. Un noeud qu'on ne peut pas redemarrer
//! n'est pas un noeud.
//!
//! Deux ajouts suffisent a supprimer ce mur, sans rien deleguer a une
//! bibliotheque :
//!
//! - [`BlockStore::scan_headers`] parcourt le fichier en ne decodant que les
//!   160 octets d'en-tete de chaque enregistrement, et retient la position du
//!   corps. Reconstruire l'index d'une chaine ne coute plus qu'une lecture
//!   sequentielle.
//! - [`BlockStore::read_at`] relit un corps a la demande. Un noeud n'a donc plus
//!   a garder en memoire un million de blocs pour pouvoir en servir un seul.
//!
//! L'etat monetaire, lui, est persiste par [`crate::state`].

use crate::block::{Block, BlockHeader};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    BlocIllisible {
        index: u64,
    },
    /// Le fichier se termine au milieu d'un bloc : ecriture interrompue.
    FichierTronque {
        index: u64,
    },
    BlocTropGros {
        index: u64,
        taille: u32,
    },
    /// Le premier enregistrement n'est pas la genese de ce reseau.
    GeneseEtrangere {
        attendu: crate::hash::Hash256,
        vu: crate::hash::Hash256,
    },
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "erreur d'entree/sortie : {e}"),
            StoreError::BlocIllisible { index } => {
                write!(f, "bloc {index} illisible : fichier corrompu")
            }
            StoreError::FichierTronque { index } => write!(
                f,
                "fichier tronque au bloc {index} : ecriture interrompue, \
                 les blocs precedents restent valides"
            ),
            StoreError::BlocTropGros { index, taille } => {
                write!(f, "bloc {index} annonce {taille} octets : refuse")
            }
            StoreError::GeneseEtrangere { attendu, vu } => write!(
                f,
                "ce fichier de blocs commence par {vu}, alors que la genese de \
                 ce reseau est {attendu} : il appartient a une autre chaine et \
                 n'est pas adopte"
            ),
        }
    }
}

/// Borne de securite a la lecture : un fichier corrompu ne doit pas provoquer
/// une allocation delirante.
const MAX_BLOC_SERIALISE: u32 = 64 * 1024 * 1024;

/// Position d'un enregistrement dans le fichier.
///
/// `offset` designe le debut du **corps**, apres les quatre octets de longueur.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordRef {
    pub offset: u64,
    pub len: u32,
}

pub struct BlockStore {
    chemin: PathBuf,
}

impl BlockStore {
    pub fn new<P: AsRef<Path>>(chemin: P) -> BlockStore {
        BlockStore {
            chemin: chemin.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.chemin
    }

    pub fn exists(&self) -> bool {
        self.chemin.exists()
    }

    /// Ajoute un bloc a la fin du fichier et rend sa position.
    pub fn append(&self, block: &Block) -> Result<RecordRef, StoreError> {
        let donnees = block.encode();
        let mut fichier = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.chemin)?;
        let debut = fichier.metadata()?.len();
        {
            let mut f = BufWriter::new(&mut fichier);
            f.write_all(&(donnees.len() as u32).to_le_bytes())?;
            f.write_all(&donnees)?;
            f.flush()?;
        }
        Ok(RecordRef {
            offset: debut + 4,
            len: donnees.len() as u32,
        })
    }

    /// Parcourt le fichier en ne decodant que les en-tetes.
    ///
    /// L'en-tete occupe les [`BlockHeader::SIZE`] premiers octets de chaque
    /// enregistrement : on lit 4 + 160 octets, puis on saute le reste. Sur un
    /// million de blocs, cela remplace le decodage de plusieurs gigaoctets de
    /// transactions par une lecture sequentielle de quelques dizaines de
    /// megaoctets.
    ///
    /// Comme [`Self::load_all`], une troncature finale n'est pas fatale : ce qui
    /// precede reste exploitable, et l'incident est rendu a l'appelant.
    #[allow(clippy::type_complexity)]
    pub fn scan_headers(
        &self,
    ) -> Result<(Vec<(BlockHeader, RecordRef)>, Option<StoreError>), StoreError> {
        if !self.exists() {
            return Ok((Vec::new(), None));
        }
        let taille_fichier = std::fs::metadata(&self.chemin)?.len();
        let mut f = BufReader::new(File::open(&self.chemin)?);
        let mut v = Vec::new();
        let mut index = 0u64;
        let mut position = 0u64;

        loop {
            let mut entete = [0u8; 4];
            match f.read_exact(&mut entete) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(StoreError::Io(e)),
            }
            let taille = u32::from_le_bytes(entete);
            if taille < BlockHeader::SIZE as u32 || taille > MAX_BLOC_SERIALISE {
                return Ok((v, Some(StoreError::BlocTropGros { index, taille })));
            }

            let mut brut = [0u8; BlockHeader::SIZE];
            if f.read_exact(&mut brut).is_err() {
                return Ok((v, Some(StoreError::FichierTronque { index })));
            }
            let header = match BlockHeader::decode(&brut) {
                Ok(h) => h,
                Err(_) => return Ok((v, Some(StoreError::BlocIllisible { index }))),
            };

            let reste = i64::from(taille) - BlockHeader::SIZE as i64;
            if f.seek_relative(reste).is_err() {
                return Ok((v, Some(StoreError::FichierTronque { index })));
            }
            // `seek_relative` reussit au-dela de la fin : on verifie que le
            // corps existe reellement avant de declarer l'enregistrement bon.
            let fin = position + 4 + u64::from(taille);
            if fin > taille_fichier {
                return Ok((v, Some(StoreError::FichierTronque { index })));
            }

            v.push((
                header,
                RecordRef {
                    offset: position + 4,
                    len: taille,
                },
            ));
            position = fin;
            index += 1;
        }
        Ok((v, None))
    }

    /// Relit un bloc a une position connue.
    pub fn read_at(&self, r: RecordRef) -> Result<Block, StoreError> {
        if r.len == 0 || r.len > MAX_BLOC_SERIALISE {
            return Err(StoreError::BlocTropGros {
                index: r.offset,
                taille: r.len,
            });
        }
        let mut f = File::open(&self.chemin)?;
        f.seek(SeekFrom::Start(r.offset))?;
        let mut donnees = vec![0u8; r.len as usize];
        f.read_exact(&mut donnees)
            .map_err(|_| StoreError::FichierTronque { index: r.offset })?;
        Block::decode(&donnees).map_err(|_| StoreError::BlocIllisible { index: r.offset })
    }

    /// Relit tous les blocs, dans l'ordre.
    ///
    /// Une troncature en fin de fichier — coupure de courant pendant une
    /// ecriture — n'est pas une erreur fatale : les blocs complets qui
    /// precedent restent exploitables. Le detail est rendu a l'appelant, qui
    /// decide.
    pub fn load_all(&self) -> Result<(Vec<Block>, Option<StoreError>), StoreError> {
        if !self.exists() {
            return Ok((Vec::new(), None));
        }
        let mut f = BufReader::new(File::open(&self.chemin)?);
        let mut blocs = Vec::new();
        let mut index = 0u64;

        loop {
            let mut entete = [0u8; 4];
            match f.read_exact(&mut entete) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(StoreError::Io(e)),
            }
            let taille = u32::from_le_bytes(entete);
            if taille == 0 || taille > MAX_BLOC_SERIALISE {
                return Ok((blocs, Some(StoreError::BlocTropGros { index, taille })));
            }

            let mut donnees = vec![0u8; taille as usize];
            if f.read_exact(&mut donnees).is_err() {
                return Ok((blocs, Some(StoreError::FichierTronque { index })));
            }
            match Block::decode(&donnees) {
                Ok(b) => blocs.push(b),
                Err(_) => return Ok((blocs, Some(StoreError::BlocIllisible { index }))),
            }
            index += 1;
        }
        Ok((blocs, None))
    }

    pub fn remove(&self) -> Result<(), StoreError> {
        if self.exists() {
            std::fs::remove_file(&self.chemin)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Archive : magasin + index des positions
// ---------------------------------------------------------------------------

/// Le fichier de blocs, plus l'index de leurs positions.
///
/// # Le defaut que ce type corrige
///
/// La chaine n'a garde en memoire qu'une fenetre de corps depuis la phase 7 ;
/// tout le reste doit venir du disque. La premiere version construisait cet
/// index **une fois au demarrage**. Les blocs mines ou recus ensuite n'y
/// entraient jamais : des qu'ils sortaient de la fenetre memoire, le noeud ne
/// savait plus les servir.
///
/// Consequence observee en lancant deux vrais processus : un noeud rejoignant
/// une chaine en cours recevait des milliers de blocs, tous orphelins, et
/// restait indefiniment a la hauteur zero — parce que son pair ne pouvait plus
/// lui fournir les premiers blocs. Aucun test unitaire ne pouvait le voir : il
/// faut une chaine plus longue que la fenetre memoire, et deux processus.
///
/// L'index vit donc ici, et suit chaque ajout.
pub struct BlockArchive {
    store: BlockStore,
    positions: std::sync::Mutex<std::collections::HashMap<crate::hash::Hash256, RecordRef>>,
}

impl BlockArchive {
    /// Ouvre l'archive et balaie les en-tetes deja presents.
    ///
    /// Rend aussi les en-tetes lus, dont l'appelant a besoin pour reconstruire
    /// l'index de la chaine, et l'incident eventuel rencontre en fin de fichier.
    #[allow(clippy::type_complexity)]
    pub fn open<P: AsRef<Path>>(
        chemin: P,
        reseau: crate::address::Network,
    ) -> Result<(BlockArchive, Vec<BlockHeader>, Option<StoreError>), StoreError> {
        let store = BlockStore::new(chemin);
        let (entetes, souci) = store.scan_headers()?;

        // --- La racine, avant tout le reste.
        //
        // Un audit a depose dans le repertoire de donnees un fichier de blocs
        // fabrique : une fausse genese, sans preuve de travail, dont la coinbase
        // versait 21 millions a son auteur. Le noeud l'a adoptee comme racine et
        // a credite les fonds. Le premier bloc n'etait verifie par personne :
        // `Chain::new` prend son bloc de genese pour argent comptant, et le
        // rejeu ne commence qu'au bloc suivant.
        //
        // L'identifiant de la genese est une constante du reseau. On la compare
        // ici, une fois, a l'endroit ou toute chaine sur disque entre dans le
        // programme.
        if let Some((premier, _)) = entetes.first() {
            let attendu = crate::chain::genesis_id(reseau);
            let vu = premier.block_id();
            if vu != attendu {
                return Err(StoreError::GeneseEtrangere { attendu, vu });
            }
        }

        // --- Une queue abimee se coupe, elle ne se contourne pas.
        //
        // Une coupure de courant en pleine ecriture laisse un enregistrement a
        // moitie ecrit a la fin du fichier. Le balayage s'arrete la et signale
        // l'incident : les blocs precedents restent valides, et le noeud peut
        // repartir. C'etait deja le cas.
        //
        // Ce qui ne l'etait pas : les blocs suivants s'ecrivaient **apres** ces
        // octets abimes. Ils atteignaient le disque, servaient tant que le
        // processus vivait, et disparaissaient au redemarrage suivant — puisque
        // le balayage s'arretait toujours au meme endroit. Le fichier grossissait
        // en ne rendant plus rien. C'est la forme la plus perfide de perte de
        // donnees : silencieuse, et pire a chaque redemarrage.
        //
        // On ramene donc le fichier a la fin du dernier enregistrement complet.
        // Le bloc a moitie ecrit est perdu — il l'etait deja — et sera redemande
        // au reseau. Ce qui suit s'ecrira sur du terrain sain.
        // Trois garde-fous, et ils ne sont pas negociables — une reparation qui
        // se trompe efface des blocs :
        //
        // 1. **Seule une queue tronquee se repare.** Une taille mensongere ou un
        //    en-tete indechiffrable au milieu du fichier ne sont pas une
        //    ecriture interrompue : ce sont les traces d'autre chose, et les
        //    couper reviendrait a obeir a qui les a ecrites. Ces cas restent
        //    signales, et rien n'est touche.
        // 2. **Jamais jusqu'a zero.** Une premiere version coupait a la fin du
        //    dernier enregistrement valide, y compris quand il n'y en avait
        //    aucun : un mensonge sur la taille du **premier** enregistrement
        //    aurait donc efface tout le fichier. L'epreuve d'audit
        //    `aa_taille_mensongere` l'a vu ; la relecture, non.
        // 3. **Jamais plus qu'un bloc.** Ce qu'on jette doit avoir la taille
        //    d'une ecriture interrompue. Au-dela, on ne comprend plus ce qu'on
        //    voit, et on s'abstient.
        let mut souci = souci;
        if matches!(souci, Some(StoreError::FichierTronque { .. })) && !entetes.is_empty() {
            let fin = entetes
                .last()
                .map(|(_, r)| r.offset + r.len as u64)
                .unwrap_or(0);
            let taille = std::fs::metadata(store.path())
                .map(|m| m.len())
                .unwrap_or(0);
            let jete = taille.saturating_sub(fin);
            if fin > 0 && jete <= MAX_BLOC_SERIALISE as u64 + 4 {
                match std::fs::OpenOptions::new().write(true).open(store.path()) {
                    Ok(f) => match f.set_len(fin) {
                        Ok(()) => {
                            souci = None;
                            eprintln!(
                                "  fichier des blocs repare : {jete} octet(s) d'ecriture interrompue coupes"
                            );
                        }
                        Err(e) => eprintln!("avertissement : queue abimee non coupee ({e})"),
                    },
                    Err(e) => eprintln!("avertissement : queue abimee non coupee ({e})"),
                }
            }
        }

        let positions = entetes
            .iter()
            .map(|(h, r)| (h.block_id(), *r))
            .collect::<std::collections::HashMap<_, _>>();
        let seuls: Vec<BlockHeader> = entetes.into_iter().map(|(h, _)| h).collect();
        Ok((
            BlockArchive {
                store,
                positions: std::sync::Mutex::new(positions),
            },
            seuls,
            souci,
        ))
    }

    pub fn len(&self) -> usize {
        self.positions.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Ajoute un bloc et **enregistre sa position dans le meme geste**.
    ///
    /// Les deux ne doivent jamais etre separes : un bloc ecrit mais non indexe
    /// est un bloc que ce noeud ne saura plus servir.
    pub fn append(&self, block: &Block) -> Result<(), StoreError> {
        let r = self.store.append(block)?;
        if let Ok(mut g) = self.positions.lock() {
            g.insert(block.header.block_id(), r);
        }
        Ok(())
    }

    pub fn read(&self, id: &crate::hash::Hash256) -> Option<Block> {
        let r = *self.positions.lock().ok()?.get(id)?;
        self.store.read_at(r).ok()
    }

    pub fn store(&self) -> &BlockStore {
        &self.store
    }
}

impl crate::chain::Journal for BlockArchive {
    /// Ecrit le bloc s'il n'est pas deja dans le fichier.
    ///
    /// L'index des positions fait office de test d'appartenance : il est en
    /// memoire, donc la question ne coute pas une lecture disque.
    fn consigner(&self, bloc: &Block) {
        let id = bloc.header.block_id();
        if self
            .positions
            .lock()
            .map(|g| g.contains_key(&id))
            .unwrap_or(false)
        {
            return;
        }
        if let Err(e) = self.append(bloc) {
            eprintln!("avertissement : bloc {id} non ecrit sur disque : {e}");
        }
    }
}

impl crate::chain::BodySource for BlockArchive {
    fn body(&self, id: &crate::hash::Hash256) -> Option<Block> {
        self.read(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;
    use crate::chain::genesis_block;

    fn chemin_temporaire(nom: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("q21-test-{nom}-{}.dat", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Regtest et non Testnet : la genese y est bien moins couteuse a miner, et
    /// ce module ne teste pas la preuve de travail.
    fn bloc() -> Block {
        genesis_block(Network::Regtest)
    }

    #[test]
    fn un_magasin_absent_se_lit_comme_vide() {
        let s = BlockStore::new(chemin_temporaire("absent"));
        let (blocs, err) = s.load_all().unwrap();
        assert!(blocs.is_empty());
        assert!(err.is_none());
    }

    #[test]
    fn aller_retour_sur_plusieurs_blocs() {
        let p = chemin_temporaire("aller-retour");
        let s = BlockStore::new(&p);
        let b = bloc();
        s.append(&b).unwrap();
        s.append(&b).unwrap();
        s.append(&b).unwrap();

        let (relus, err) = s.load_all().unwrap();
        assert!(err.is_none());
        assert_eq!(relus.len(), 3);
        assert_eq!(relus[0], b);
        assert_eq!(relus[2], b);
        s.remove().unwrap();
    }

    #[test]
    fn une_troncature_conserve_les_blocs_complets() {
        let p = chemin_temporaire("tronque");
        let s = BlockStore::new(&p);
        s.append(&bloc()).unwrap();
        s.append(&bloc()).unwrap();

        // Simule une coupure de courant en pleine ecriture.
        let taille = std::fs::metadata(&p).unwrap().len();
        let f = OpenOptions::new().write(true).open(&p).unwrap();
        f.set_len(taille - 10).unwrap();
        drop(f);

        let (blocs, err) = s.load_all().unwrap();
        assert_eq!(blocs.len(), 1, "le premier bloc devait survivre");
        assert!(matches!(err, Some(StoreError::FichierTronque { index: 1 })));
        s.remove().unwrap();
    }

    /// Une queue abimee est **coupee**, pas contournee.
    ///
    /// # Le defaut, et pourquoi il etait pire a chaque redemarrage
    ///
    /// Une coupure de courant en pleine ecriture laisse un enregistrement a
    /// moitie ecrit en fin de fichier. Le balayage s'arretait la et signalait
    /// l'incident : correct. Mais les blocs suivants s'ecrivaient **apres** ces
    /// octets abimes. Ils atteignaient le disque, servaient tant que le
    /// processus vivait, et disparaissaient au redemarrage suivant — puisque le
    /// balayage s'arretait toujours au meme endroit. Le fichier grossissait en
    /// ne rendant plus rien : une perte de donnees silencieuse, et cumulative.
    #[test]
    fn une_queue_abimee_est_coupee_a_l_ouverture() {
        let p = chemin_temporaire("queue-abimee");
        let s = BlockStore::new(&p);
        let g = crate::chain::genesis_block(crate::address::Network::Regtest);
        s.append(&g).unwrap();
        let sain = std::fs::metadata(&p).unwrap().len();

        // Une ecriture interrompue : quelques octets d'un enregistrement suivant.
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&[0x40, 0x01, 0x00, 0x00, 0xaa, 0xbb]).unwrap();
        }
        assert!(std::fs::metadata(&p).unwrap().len() > sain);

        let (_a, entetes, souci) =
            BlockArchive::open(&p, crate::address::Network::Regtest).unwrap();
        assert_eq!(entetes.len(), 1, "le bloc complet doit survivre");
        assert!(
            souci.is_none(),
            "la queue ayant ete coupee, il n'y a plus d'incident a signaler"
        );
        assert_eq!(
            std::fs::metadata(&p).unwrap().len(),
            sain,
            "le fichier doit etre revenu a la fin du dernier enregistrement complet"
        );

        // Et surtout : ce qu'on ecrit ensuite est relu au redemarrage suivant.
        s.append(&g).unwrap();
        let (_a2, entetes2, souci2) =
            BlockArchive::open(&p, crate::address::Network::Regtest).unwrap();
        assert_eq!(
            entetes2.len(),
            2,
            "un bloc ecrit apres la reparation doit se relire"
        );
        assert!(souci2.is_none());
        s.remove().unwrap();
    }

    #[test]
    fn une_taille_delirante_est_refusee_sans_allouer() {
        let p = chemin_temporaire("taille-folle");
        {
            let mut f = File::create(&p).unwrap();
            f.write_all(&u32::MAX.to_le_bytes()).unwrap();
        }
        let s = BlockStore::new(&p);
        let (blocs, err) = s.load_all().unwrap();
        assert!(blocs.is_empty());
        assert!(matches!(err, Some(StoreError::BlocTropGros { .. })));
        s.remove().unwrap();
    }

    /// Le defaut que l'archive corrige, verrouille par un test.
    ///
    /// Un bloc ajoute **apres** l'ouverture doit rester servable. La version
    /// precedente construisait l'index une fois pour toutes : le bloc etait
    /// bien ecrit, mais introuvable des qu'il sortait de la fenetre memoire de
    /// la chaine. Un noeud rejoignant une chaine en cours restait alors
    /// indefiniment a la hauteur zero.
    #[test]
    fn un_bloc_ajoute_apres_l_ouverture_reste_servable() {
        let p = chemin_temporaire("archive");
        let store = BlockStore::new(&p);
        store.append(&bloc()).unwrap();

        let (archive, entetes, souci) = BlockArchive::open(&p, Network::Regtest).unwrap();
        assert!(souci.is_none());
        assert_eq!(entetes.len(), 1);
        assert_eq!(archive.len(), 1);

        // Un bloc different, ajoute apres coup.
        let mut nouveau = bloc();
        nouveau.header.nonce = 12_345;
        let id = nouveau.header.block_id();
        assert!(archive.read(&id).is_none(), "pas encore ecrit");

        archive.append(&nouveau).unwrap();
        assert_eq!(archive.len(), 2);
        assert_eq!(
            archive.read(&id).map(|b| b.header.nonce),
            Some(12_345),
            "un bloc ecrit doit etre relisible immediatement"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn une_archive_relue_retrouve_tous_ses_blocs() {
        let p = chemin_temporaire("archive-relue");
        {
            let (a, _, _) = BlockArchive::open(&p, Network::Regtest).unwrap();
            // Le premier enregistrement doit rester la vraie genese : une
            // archive qui commence ailleurs est desormais refusee.
            a.append(&bloc()).unwrap();
            for n in 1..5u64 {
                let mut b = bloc();
                b.header.nonce = n;
                a.append(&b).unwrap();
            }
        }
        let (a, entetes, souci) = BlockArchive::open(&p, Network::Regtest).unwrap();
        assert!(souci.is_none());
        assert_eq!(entetes.len(), 5);
        assert_eq!(a.read(&bloc().header.block_id()), Some(bloc()));
        for n in 1..5u64 {
            let mut b = bloc();
            b.header.nonce = n;
            assert_eq!(a.read(&b.header.block_id()), Some(b));
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn un_bloc_corrompu_est_signale() {
        let p = chemin_temporaire("corrompu");
        {
            let mut f = File::create(&p).unwrap();
            let charge = [0xffu8; 40];
            f.write_all(&(charge.len() as u32).to_le_bytes()).unwrap();
            f.write_all(&charge).unwrap();
        }
        let s = BlockStore::new(&p);
        let (_, err) = s.load_all().unwrap();
        assert!(matches!(err, Some(StoreError::BlocIllisible { index: 0 })));
        s.remove().unwrap();
    }
}
