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
    /// Le fichier d'en-tetes ne porte pas la magie attendue.
    EntetesMagie,
    /// Un en-tete ne s'enchaine pas sur le precedent : parent ou hauteur faux.
    EntetesMaillonRompu {
        index: u64,
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
            StoreError::EntetesMagie => {
                write!(f, "ce fichier n'est pas un magasin d'en-tetes Q21")
            }
            StoreError::EntetesMaillonRompu { index } => write!(
                f,
                "l'en-tete {index} ne s'enchaine pas sur le precedent : \
                 chaine d'en-tetes corrompue"
            ),
        }
    }
}

/// Borne de securite a la lecture : un fichier corrompu ne doit pas provoquer
/// une allocation delirante.
const MAX_BLOC_SERIALISE: u32 = 64 * 1024 * 1024;

/// Ou la queue coupee d'un fichier de blocs est conservee.
fn chemin_de_la_coupe(chemin: &Path) -> PathBuf {
    let mut nom = chemin.as_os_str().to_os_string();
    nom.push(".coupe");
    PathBuf::from(nom)
}

/// Copie `longueur` octets a partir de `depuis` dans le fichier de coupe,
/// avant qu'ils ne soient retires. Une copie precedente est ecrasee : elle
/// concernait une reparation deja passee.
fn copier_la_queue(chemin: &Path, depuis: u64, longueur: u64) -> std::io::Result<()> {
    let mut f = File::open(chemin)?;
    f.seek(SeekFrom::Start(depuis))?;
    let mut octets = Vec::with_capacity(longueur as usize);
    f.take(longueur).read_to_end(&mut octets)?;
    let mut sortie = File::create(chemin_de_la_coupe(chemin))?;
    sortie.write_all(&octets)?;
    sortie.sync_all()
}

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
        // Jusqu'au disque, comme les en-tetes et l'instantane : sans cela, une
        // coupure de courant pouvait perdre le dernier corps alors que son
        // en-tete, lui, avait ete force sur le disque — l'instantane se
        // retrouvait en avance sur le fichier de blocs. Un bloc toutes les
        // deux minutes : le cout est invisible.
        fichier.sync_all()?;
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

/// Ce qu'un elagage a fait.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Elagage {
    pub conserves: usize,
    pub retires: usize,
    pub octets_liberes: u64,
}

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
        Self::ouvrir(chemin.as_ref(), reseau, true)
    }

    /// `reparer_la_genese` n'est vrai qu'a la premiere tentative : une
    /// reparation qui ne changerait rien ne doit pas boucler.
    fn ouvrir(
        chemin: &Path,
        reseau: crate::address::Network,
        reparer_la_genese: bool,
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
        if let Some((premier, ref_premier)) = entetes.first() {
            let attendu = crate::chain::genesis_id(reseau);
            let vu = premier.block_id();
            if vu != attendu {
                // --- Une genese abimee n'est pas une genese etrangere.
                //
                // La genese est une constante du reseau, reecrite sans etat.
                // Si le **second** enregistrement s'enchaine sur la vraie
                // genese, le premier n'est pas celui d'une autre chaine : ce
                // sont quelques octets retournes sur la carte. Les ranger
                // comme « ancienne chaine » abandonnait toute l'histoire
                // locale pour un bit ; on recopie la genese canonique a sa
                // place, si elle y tient.
                let suivant_s_enchaine = entetes
                    .get(1)
                    .map(|(h, _)| h.prev_block == attendu)
                    .unwrap_or(false);
                let canonique = crate::chain::genesis_block(reseau).encode();
                if reparer_la_genese
                    && suivant_s_enchaine
                    && canonique.len() as u32 == ref_premier.len
                {
                    let mut f = OpenOptions::new().write(true).open(store.path())?;
                    f.seek(SeekFrom::Start(ref_premier.offset))?;
                    f.write_all(&canonique)?;
                    f.sync_all()?;
                    eprintln!(
                        "  fichier des blocs repare : l'enregistrement de la genese etait abime, \
                         la genese du reseau a ete recopiee a sa place"
                    );
                    // On relit : la suite du chargement doit voir le fichier tel
                    // qu'il est maintenant.
                    drop(f);
                    return Self::ouvrir(store.path(), reseau, false);
                }
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
        //    d'une ecriture interrompue — donc au plus un bloc du consensus,
        //    `MAX_BLOCK_SIZE`, et non la borne d'allocation de la lecture, qui
        //    en vaut seize. Un seul bit retourne dans un prefixe de longueur
        //    au milieu du fichier fait pointer un enregistrement au-dela de la
        //    fin, et se presente comme une queue tronquee : avec la borne
        //    large, la reparation effacait tout ce qui suivait — des dizaines
        //    de blocs valides — en annoncant une reparation reussie. Au-dela
        //    d'un bloc, on ne comprend plus ce qu'on voit, et on s'abstient.
        // 4. **Rien n'est jete sans copie.** Ce qui est coupe est d'abord
        //    ecrit a cote du fichier, dans `blocks.dat.coupe` : si la
        //    reparation s'est trompee, rien n'est perdu pour de bon.
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
            if fin > 0 && jete <= crate::consensus::MAX_BLOCK_SIZE as u64 + 4 {
                let copie = copier_la_queue(store.path(), fin, jete);
                match copie.and_then(|_| std::fs::OpenOptions::new().write(true).open(store.path())) {
                    Ok(f) => match f.set_len(fin) {
                        Ok(()) => {
                            souci = None;
                            eprintln!(
                                "  fichier des blocs repare : {jete} octet(s) d'ecriture interrompue coupes \
                                 (copie gardee dans {})",
                                chemin_de_la_coupe(store.path()).display()
                            );
                        }
                        Err(e) => eprintln!("avertissement : queue abimee non coupee ({e})"),
                    },
                    Err(e) => eprintln!("avertissement : queue abimee non coupee ({e})"),
                }
            } else if fin > 0 {
                eprintln!(
                    "avertissement : {jete} octet(s) au-dela du dernier enregistrement complet, \
                     plus qu'un bloc : ce n'est pas une ecriture interrompue, rien n'est coupe"
                );
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
    ///
    /// Le verrou des positions est pris **avant** l'ecriture : il serialise
    /// les ajouts avec l'elagage ([`Self::elaguer`]), qui reecrit le fichier.
    /// Sans cela, un bloc ecrit pendant la reecriture atterrirait dans
    /// l'ancien fichier, et sa position, dans l'index du nouveau.
    pub fn append(&self, block: &Block) -> Result<(), StoreError> {
        let mut g = self.positions.lock().unwrap_or_else(|e| e.into_inner());
        let r = self.store.append(block)?;
        g.insert(block.header.block_id(), r);
        Ok(())
    }

    /// Relit un bloc. Le verrou est tenu pendant la lecture, pour la meme
    /// raison que dans [`Self::append`] : une position lue avant un elagage ne
    /// designe plus rien apres.
    pub fn read(&self, id: &crate::hash::Hash256) -> Option<Block> {
        let g = self.positions.lock().ok()?;
        let r = *g.get(id)?;
        self.store.read_at(r).ok()
    }

    /// Reecrit le fichier en ne gardant que les blocs que `garder` retient.
    ///
    /// # Pourquoi
    ///
    /// Le fichier de blocs ne faisait que grossir. Un noeud qui ne mine que
    /// pour lui n'a pourtant besoin que de ce qu'il peut encore defaire (la
    /// fenetre de reorganisation) et de ce que son historique affiche : tout
    /// ce qui precede se resume dans l'instantane. Une carte SD de Raspberry
    /// ne tient pas dix ans de corps ; elle tient dix ans d'instantanes.
    ///
    /// # Ce qui est garanti
    ///
    /// - L'ordre des enregistrements est conserve, la genese reste le premier :
    ///   le controle de racine de [`Self::open`] continue de s'appliquer.
    /// - Le nouveau fichier est ecrit a cote, synchronise sur le disque, puis
    ///   renomme par-dessus l'ancien : a tout instant, le chemin designe un
    ///   fichier complet — l'ancien ou le nouveau, jamais un melange.
    /// - Le verrou des positions est tenu du debut a la fin : aucun ajout ni
    ///   aucune lecture ne s'intercale, et l'index est reconstruit avant que
    ///   quiconque le consulte.
    ///
    /// L'appelant est responsable de ce que `garder` retient : au minimum, la
    /// genese et tout ce que la chaine peut encore avoir a relire.
    pub fn elaguer(&self, garder: impl Fn(&BlockHeader) -> bool) -> Result<Elagage, StoreError> {
        let mut positions = self.positions.lock().unwrap_or_else(|e| e.into_inner());
        let chemin = self.store.path().to_path_buf();
        if !chemin.exists() {
            return Ok(Elagage::default());
        }
        let tmp = chemin.with_extension("elagage");
        let mut bilan = Elagage::default();
        let mut nouvelles: std::collections::HashMap<crate::hash::Hash256, RecordRef> =
            std::collections::HashMap::new();
        {
            let mut lecture = BufReader::new(File::open(&chemin)?);
            let sortie = File::create(&tmp)?;
            let mut ecriture = BufWriter::new(&sortie);
            let mut position_sortie = 0u64;
            loop {
                let mut prefixe = [0u8; 4];
                match lecture.read_exact(&mut prefixe) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(StoreError::Io(e)),
                }
                let taille = u32::from_le_bytes(prefixe);
                if taille < BlockHeader::SIZE as u32 || taille > MAX_BLOC_SERIALISE {
                    // Un enregistrement qu'on ne comprend pas : on s'arrete la,
                    // comme le balayage. Ce qui precede est sain.
                    break;
                }
                let mut brut = vec![0u8; taille as usize];
                if lecture.read_exact(&mut brut).is_err() {
                    break; // queue tronquee : coupee, comme a l'ouverture
                }
                let entete = match BlockHeader::decode(&brut[..BlockHeader::SIZE]) {
                    Ok(h) => h,
                    Err(_) => break,
                };
                if garder(&entete) {
                    ecriture.write_all(&prefixe)?;
                    ecriture.write_all(&brut)?;
                    nouvelles.insert(
                        entete.block_id(),
                        RecordRef {
                            offset: position_sortie + 4,
                            len: taille,
                        },
                    );
                    position_sortie += 4 + u64::from(taille);
                    bilan.conserves += 1;
                } else {
                    bilan.retires += 1;
                    bilan.octets_liberes += 4 + u64::from(taille);
                }
            }
            ecriture.flush()?;
            sortie.sync_all()?;
        }
        std::fs::rename(&tmp, &chemin)?;
        if let Some(parent) = chemin.parent() {
            if let Ok(d) = File::open(parent) {
                let _ = d.sync_all();
            }
        }
        *positions = nouvelles;
        Ok(bilan)
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

// ---------------------------------------------------------------------------
// Magasin d'en-tetes : la chaine d'en-tetes, sans les corps
// ---------------------------------------------------------------------------

/// Magie du fichier d'en-tetes.
const MAGIE_ENTETES: &[u8; 8] = b"Q21HDRS\0";
/// Version du format d'en-tetes.
const VERSION_ENTETES: u32 = 1;
/// Longueur du prefixe : magie (8) + version (4).
const PREFIXE_ENTETES: u64 = 12;

/// Magasin des en-tetes seuls, independant du fichier de blocs.
///
/// # Pourquoi il existe
///
/// Un noeud qui **adopte** un instantane repart a la hauteur H sans detenir les
/// blocs 1..H. Il lui faut pourtant leur chaine d'en-tetes : c'est elle qui
/// prouve que la tete porte une preuve de travail, et elle qui donne la
/// difficulte du prochain bloc. Le fichier de blocs ne peut pas la lui fournir —
/// il ne garde que les corps qu'il possede. Ce magasin la conserve a part.
///
/// Un noeud complet n'en a pas besoin : ses en-tetes se relisent du fichier de
/// blocs ([`BlockStore::scan_headers`]). Ce magasin ne sert donc qu'au noeud
/// repris sur instantane.
///
/// # Le format
///
/// Un prefixe (magie, version), puis des en-tetes de taille fixe
/// ([`BlockHeader::SIZE`]) mis bout a bout. Pas de prefixe de longueur par
/// enregistrement : un en-tete a toujours la meme taille. Une ecriture
/// interrompue laisse un enregistrement partiel en fin de fichier, coupe a la
/// relecture — comme pour le fichier de blocs.
///
/// # Ce qu'il verifie, et ce qu'il ne verifie pas
///
/// A la relecture : la magie, que le premier en-tete est bien la genese du
/// reseau, et que chaque en-tete s'enchaine sur le precedent (parent et hauteur).
/// Il **ne verifie pas** la preuve de travail : ce fichier local est cru, comme
/// l'est le fichier de blocs — qui peut reecrire le repertoire a deja gagne. La
/// preuve de travail des en-tetes **venus d'ailleurs** est verifiee a
/// l'adoption, avant qu'ils entrent ici.
pub struct HeaderStore {
    chemin: PathBuf,
}

impl HeaderStore {
    pub fn new<P: AsRef<Path>>(chemin: P) -> HeaderStore {
        HeaderStore {
            chemin: chemin.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.chemin
    }

    pub fn exists(&self) -> bool {
        self.chemin.exists()
    }

    /// Ajoute des en-tetes a la fin, en creant le fichier (avec son prefixe) au
    /// besoin. L'appelant garantit qu'ils s'enchainent sur ce qui precede ; la
    /// relecture le reverifie de toute facon.
    pub fn append(&self, entetes: &[BlockHeader]) -> Result<(), StoreError> {
        if entetes.is_empty() {
            return Ok(());
        }
        let neuf = !self.exists() || std::fs::metadata(&self.chemin)?.len() < PREFIXE_ENTETES;
        let mut fichier = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.chemin)?;
        {
            let mut f = BufWriter::new(&mut fichier);
            if neuf {
                f.write_all(MAGIE_ENTETES)?;
                f.write_all(&VERSION_ENTETES.to_le_bytes())?;
            }
            for h in entetes {
                f.write_all(&h.encode())?;
            }
            f.flush()?;
        }
        fichier.sync_all()?;
        Ok(())
    }

    /// Relit toute la chaine d'en-tetes.
    ///
    /// Verifie la magie, la genese, l'enchainement (parent et hauteur), et coupe
    /// une eventuelle queue partielle. Une rupture d'enchainement **au milieu**
    /// du fichier n'est pas une ecriture interrompue : elle est signalee, jamais
    /// coupee.
    pub fn load(&self, reseau: crate::address::Network) -> Result<Vec<BlockHeader>, StoreError> {
        if !self.exists() {
            return Ok(Vec::new());
        }
        let taille = std::fs::metadata(&self.chemin)?.len();
        if taille < PREFIXE_ENTETES {
            return Err(StoreError::EntetesMagie);
        }

        let mut f = BufReader::new(File::open(&self.chemin)?);
        let mut magie = [0u8; 8];
        f.read_exact(&mut magie)?;
        if &magie != MAGIE_ENTETES {
            return Err(StoreError::EntetesMagie);
        }
        let mut v = [0u8; 4];
        f.read_exact(&mut v)?;
        if u32::from_le_bytes(v) != VERSION_ENTETES {
            return Err(StoreError::EntetesMagie);
        }

        // Une queue partielle — ecriture interrompue — est coupee proprement.
        let corps = taille - PREFIXE_ENTETES;
        let taille_entete = BlockHeader::SIZE as u64;
        let n = corps / taille_entete;
        if corps % taille_entete != 0 {
            let propre = PREFIXE_ENTETES + n * taille_entete;
            if let Ok(fh) = OpenOptions::new().write(true).open(&self.chemin) {
                if fh.set_len(propre).is_ok() {
                    eprintln!(
                        "  magasin d'en-tetes repare : {} octet(s) d'ecriture interrompue coupes",
                        taille - propre
                    );
                }
            }
        }

        let mut entetes = Vec::with_capacity(n as usize);
        let mut brut = [0u8; BlockHeader::SIZE];
        for index in 0..n {
            if f.read_exact(&mut brut).is_err() {
                return Err(StoreError::FichierTronque { index });
            }
            let h = BlockHeader::decode(&brut).map_err(|_| StoreError::BlocIllisible { index })?;
            entetes.push(h);
        }

        // La genese, avant tout : un fichier d'en-tetes d'une autre chaine ne
        // doit pas etre adopte.
        if let Some(premier) = entetes.first() {
            let attendu = crate::chain::genesis_id(reseau);
            let vu = premier.block_id();
            if vu != attendu {
                return Err(StoreError::GeneseEtrangere { attendu, vu });
            }
        }
        // Puis l'enchainement : chaque en-tete pointe sur le precedent, hauteurs
        // contigues. Un maillon rompu est une corruption, pas une troncature.
        for i in 1..entetes.len() {
            if entetes[i].prev_block != entetes[i - 1].block_id()
                || entetes[i].height != entetes[i - 1].height + 1
            {
                return Err(StoreError::EntetesMaillonRompu { index: i as u64 });
            }
        }

        Ok(entetes)
    }

    pub fn remove(&self) -> Result<(), StoreError> {
        if self.exists() {
            std::fs::remove_file(&self.chemin)?;
        }
        Ok(())
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

    /// L'elagage garde ce qu'on lui dit de garder, dans l'ordre, la genese
    /// en tete ; ce qui reste se relit, se complete, et se rouvre.
    #[test]
    fn l_elagage_garde_la_genese_et_la_fenetre_et_le_fichier_se_rouvre() {
        let p = chemin_temporaire("elagage");
        let g = bloc();
        // Des « blocs » distincts : la genese modifiee dans son nonce et sa
        // hauteur. Ce module ne verifie pas la preuve de travail.
        let mut blocs = vec![g.clone()];
        for h in 1..=20u64 {
            let mut b = g.clone();
            b.header.height = h;
            b.header.nonce = 1000 + h;
            b.header.prev_block = blocs[(h - 1) as usize].header.block_id();
            blocs.push(b);
        }
        let (archive, _, _) = BlockArchive::open(&p, Network::Regtest).unwrap();
        for b in &blocs {
            archive.append(b).unwrap();
        }
        let avant = std::fs::metadata(&p).unwrap().len();

        // On ne garde que la genese et les blocs de hauteur >= 15.
        let bilan = archive
            .elaguer(|h| h.height == 0 || h.height >= 15)
            .unwrap();
        assert_eq!(bilan.conserves, 7);
        assert_eq!(bilan.retires, 14);
        assert!(bilan.octets_liberes > 0);
        assert!(std::fs::metadata(&p).unwrap().len() < avant);
        assert!(
            !p.with_extension("elagage").exists(),
            "pas de temporaire oublie"
        );

        // Ce qui est garde se relit ; ce qui est retire ne se lit plus.
        assert_eq!(
            archive.read(&blocs[0].header.block_id()),
            Some(blocs[0].clone())
        );
        assert_eq!(
            archive.read(&blocs[20].header.block_id()),
            Some(blocs[20].clone())
        );
        assert_eq!(
            archive.read(&blocs[15].header.block_id()),
            Some(blocs[15].clone())
        );
        assert_eq!(archive.read(&blocs[14].header.block_id()), None);
        assert_eq!(archive.len(), 7);

        // On peut continuer a ecrire apres.
        let mut suite = g.clone();
        suite.header.height = 21;
        suite.header.nonce = 1021;
        archive.append(&suite).unwrap();
        assert_eq!(archive.read(&suite.header.block_id()), Some(suite.clone()));

        // Et rouvrir : la genese est toujours la premiere, l'ordre est celui
        // des hauteurs, et rien n'est signale.
        let (rouverte, entetes, souci) = BlockArchive::open(&p, Network::Regtest).unwrap();
        assert!(souci.is_none());
        assert_eq!(entetes.len(), 8);
        assert_eq!(entetes[0].height, 0);
        assert_eq!(
            entetes.iter().map(|h| h.height).collect::<Vec<_>>(),
            vec![0, 15, 16, 17, 18, 19, 20, 21]
        );
        assert_eq!(
            rouverte.read(&blocs[18].header.block_id()),
            Some(blocs[18].clone())
        );
        let _ = std::fs::remove_file(&p);
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
        // Rien n'est jete sans copie : les six octets coupes sont a cote.
        let coupe = std::fs::read(chemin_de_la_coupe(&p)).expect("la copie de la queue coupee");
        assert_eq!(coupe, vec![0x40, 0x01, 0x00, 0x00, 0xaa, 0xbb]);
        let _ = std::fs::remove_file(chemin_de_la_coupe(&p));

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

    /// Une queue plus longue qu'un bloc n'est pas une ecriture interrompue :
    /// rien n'est coupe, et l'incident reste signale.
    #[test]
    fn une_queue_plus_longue_qu_un_bloc_n_est_pas_coupee() {
        let p = chemin_temporaire("queue-trop-longue");
        let s = BlockStore::new(&p);
        let g = crate::chain::genesis_block(crate::address::Network::Regtest);
        s.append(&g).unwrap();
        let sain = std::fs::metadata(&p).unwrap().len();
        {
            // Un prefixe de longueur qui promet un enregistrement geant, suivi
            // de plus d'un bloc d'octets : ce n'est pas une queue tronquee.
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&(MAX_BLOC_SERIALISE - 1).to_le_bytes()).unwrap();
            let bourrage = vec![0u8; crate::consensus::MAX_BLOCK_SIZE + 64];
            f.write_all(&bourrage).unwrap();
        }
        let (_a, entetes, souci) =
            BlockArchive::open(&p, crate::address::Network::Regtest).unwrap();
        assert_eq!(entetes.len(), 1);
        assert!(souci.is_some(), "l'incident doit rester signale");
        assert!(
            std::fs::metadata(&p).unwrap().len() > sain,
            "rien ne doit avoir ete coupe"
        );
        s.remove().unwrap();
    }

    /// Une genese dont un octet a ete retourne est recopiee, pas rangee comme
    /// une chaine etrangere.
    #[test]
    fn une_genese_abimee_est_recopiee() {
        use crate::address::Network::Regtest;
        let p = chemin_temporaire("genese-abimee");
        let s = BlockStore::new(&p);
        let g = crate::chain::genesis_block(Regtest);
        s.append(&g).unwrap();
        // Un second bloc qui s'enchaine sur la vraie genese.
        let c = crate::chain::Chain::new(Regtest, g.clone());
        let b = c
            .mine_block(
                crate::hash::Hash256([3u8; 32]),
                crate::sig::SchemeId::LamportOts,
                &[],
                g.header.time + 120,
                5_000_000,
            )
            .expect("minage");
        s.append(&b).unwrap();

        // Un octet retourne dans le nonce de la genese (dans le corps, pas
        // dans le prefixe de longueur).
        {
            let mut f = OpenOptions::new().read(true).write(true).open(&p).unwrap();
            let encode = g.encode();
            // Le nonce est a la fin de l'en-tete : on retourne l'octet 4 + 100.
            let position = 4 + (BlockHeader::SIZE as u64 - 1);
            f.seek(SeekFrom::Start(position)).unwrap();
            let mut octet = [0u8; 1];
            f.read_exact(&mut octet).unwrap();
            f.seek(SeekFrom::Start(position)).unwrap();
            f.write_all(&[octet[0] ^ 0x01]).unwrap();
            assert!(encode.len() > 4);
        }
        let (_a, entetes, souci) = BlockArchive::open(&p, Regtest).expect("reparation");
        assert!(souci.is_none());
        assert_eq!(entetes.len(), 2);
        assert_eq!(entetes[0].block_id(), crate::chain::genesis_id(Regtest));
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

    // -----------------------------------------------------------------------
    // Magasin d'en-tetes
    // -----------------------------------------------------------------------

    /// Chaine d'en-tetes structurellement liee : la vraie genese, puis des
    /// en-tetes qui pointent sur le precedent. La preuve de travail n'est pas
    /// valide — le magasin ne la verifie pas, c'est l'affaire de l'adoption.
    fn chaine_entetes(n: u64) -> Vec<BlockHeader> {
        let g = genesis_block(Network::Regtest).header;
        let mut v = vec![g];
        for i in 1..n {
            let mut h = g;
            h.height = i;
            h.nonce = i;
            h.prev_block = v[(i - 1) as usize].block_id();
            v.push(h);
        }
        v
    }

    #[test]
    fn un_magasin_d_entetes_absent_se_lit_comme_vide() {
        let s = HeaderStore::new(chemin_temporaire("hdr-absent"));
        assert!(s.load(Network::Regtest).unwrap().is_empty());
    }

    #[test]
    fn aller_retour_sur_la_chaine_d_entetes() {
        let p = chemin_temporaire("hdr-aller-retour");
        let s = HeaderStore::new(&p);
        let chaine = chaine_entetes(12);
        s.append(&chaine).unwrap();
        assert_eq!(s.load(Network::Regtest).unwrap(), chaine);
        s.remove().unwrap();
    }

    #[test]
    fn les_entetes_s_ajoutent_par_tranches() {
        let p = chemin_temporaire("hdr-tranches");
        let s = HeaderStore::new(&p);
        let chaine = chaine_entetes(10);
        s.append(&chaine[..4]).unwrap();
        s.append(&chaine[4..]).unwrap();
        assert_eq!(s.load(Network::Regtest).unwrap(), chaine);
        s.remove().unwrap();
    }

    #[test]
    fn une_queue_partielle_d_entete_est_coupee() {
        let p = chemin_temporaire("hdr-queue");
        let s = HeaderStore::new(&p);
        let chaine = chaine_entetes(6);
        s.append(&chaine).unwrap();
        // Une ecriture interrompue : la moitie d'un en-tete de plus.
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&[0xaa; BlockHeader::SIZE / 2]).unwrap();
        }
        assert_eq!(
            s.load(Network::Regtest).unwrap(),
            chaine,
            "la queue partielle doit etre coupee, la chaine complete relue"
        );
        s.remove().unwrap();
    }

    #[test]
    fn un_maillon_rompu_est_signale() {
        let p = chemin_temporaire("hdr-maillon");
        let s = HeaderStore::new(&p);
        let mut chaine = chaine_entetes(5);
        // On casse l'enchainement du troisieme en-tete.
        chaine[3].prev_block = crate::hash::Hash256([0x77; 32]);
        s.append(&chaine).unwrap();
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StoreError::EntetesMaillonRompu { index: 3 })
        ));
        s.remove().unwrap();
    }

    #[test]
    fn une_genese_etrangere_dans_les_entetes_est_refusee() {
        let p = chemin_temporaire("hdr-genese");
        let s = HeaderStore::new(&p);
        let mut chaine = chaine_entetes(3);
        // Le premier en-tete n'est plus la vraie genese.
        chaine[0].nonce = 999;
        // On refait pointer le second pour que seul le controle de genese morde.
        chaine[1].prev_block = chaine[0].block_id();
        s.append(&chaine).unwrap();
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StoreError::GeneseEtrangere { .. })
        ));
        s.remove().unwrap();
    }

    #[test]
    fn un_fichier_sans_magie_n_est_pas_un_magasin_d_entetes() {
        let p = chemin_temporaire("hdr-magie");
        std::fs::write(&p, b"ceci n'est pas un magasin d'en-tetes du tout").unwrap();
        let s = HeaderStore::new(&p);
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StoreError::EntetesMagie)
        ));
        s.remove().unwrap();
    }
}
