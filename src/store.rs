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

/// Lit au plus `longueur` octets a partir de `depuis` ; moins si le fichier
/// finit avant.
fn lire_a(chemin: &Path, depuis: u64, longueur: u64) -> std::io::Result<Vec<u8>> {
    let mut f = File::open(chemin)?;
    // On ne reserve que ce que le fichier peut fournir : la borne demandee
    // peut valoir des dizaines de mebioctets pour quelques centaines lus.
    let disponible = f.metadata()?.len().saturating_sub(depuis);
    f.seek(SeekFrom::Start(depuis))?;
    let mut octets = Vec::with_capacity(usize::try_from(longueur.min(disponible)).unwrap_or(0));
    f.take(longueur).read_to_end(&mut octets)?;
    Ok(octets)
}

/// Copie `longueur` octets a partir de `depuis` dans le fichier de coupe,
/// avant qu'ils ne soient retires. Une copie precedente est ecrasee : elle
/// concernait une reparation deja passee.
fn copier_la_queue(chemin: &Path, depuis: u64, longueur: u64) -> std::io::Result<()> {
    let octets = lire_a(chemin, depuis, longueur)?;
    let mut sortie = File::create(chemin_de_la_coupe(chemin))?;
    sortie.write_all(&octets)?;
    sortie.sync_all()
}

/// Combien de prefixes de longueur une ouverture accepte de reparer avant de
/// s'arreter et de laisser l'incident signale. Chaque reparation relance le
/// balayage entier ; une carte qui a retourne plus de bits que cela n'est
/// plus un support sur lequel reparer quoi que ce soit.
const MAX_REPARATIONS_DE_PREFIXE: u32 = 64;

/// Jusqu'ou remonter, depuis la fin, pour retrouver le dernier enregistrement
/// dont le corps se relit. Un prefixe trop court fait accepter au balayage un
/// ou deux enregistrements fantomes derriere lui, rarement plus ; au-dela, ce
/// n'est plus un prefixe abime.
const MAX_RECUL: usize = 64;

/// Un prefixe de longueur a reecrire.
struct PrefixeAReparer {
    /// Position des quatre octets du prefixe dans le fichier.
    position: u64,
    /// Index de l'enregistrement, tel que le balayage le compte.
    index: usize,
    /// Ce que le prefixe annonce.
    lu: u32,
    /// Ce que le bloc occupe reellement.
    reel: u32,
    hauteur: u64,
}

/// Le bloc complet qui commence `octets`, s'il y en a un **et** s'il se
/// rattache a ce fichier ; avec la longueur reelle de son enregistrement.
///
/// # Pourquoi deux conditions
///
/// Qu'un bloc se decode ne suffit pas : cent soixante-deux octets nuls sont
/// un bloc parfaitement decodable (en-tete nul, zero transaction, zero
/// oncle), et une queue de zeros est precisement ce qu'un systeme de fichiers
/// laisse apres une coupure de courant. On exige donc en plus que le bloc se
/// **rattache** : son parent est un enregistrement deja lu, ou l'enregistrement
/// qui le suit s'enchaine sur lui. Une ecriture interrompue ne satisfait ni
/// l'une ni l'autre ; un enregistrement au prefixe abime satisfait au moins
/// l'une des deux — y compris le premier bloc d'une fenetre elaguee, dont le
/// parent n'est plus dans le fichier mais dont le successeur y est.
///
/// Le reencodage doit rendre exactement les octets lus : l'encodage est
/// canonique, et c'est ce qui interdit d'accepter une longueur qui ne serait
/// pas celle que `append` a ecrite.
fn enregistrement_rattache(
    octets: &[u8],
    connus: &std::collections::HashSet<crate::hash::Hash256>,
) -> Option<(BlockHeader, usize)> {
    let (bloc, reel) = Block::decode_en_tete_de(octets).ok()?;
    if reel < BlockHeader::SIZE || reel > MAX_BLOC_SERIALISE as usize {
        return None;
    }
    if bloc.encode() != octets[..reel] {
        return None;
    }
    let id = bloc.header.block_id();
    let parent_connu = connus.contains(&bloc.header.prev_block);
    let suivant_s_enchaine = octets.len() >= reel + 4 + BlockHeader::SIZE && {
        let taille = u32::from_le_bytes([
            octets[reel],
            octets[reel + 1],
            octets[reel + 2],
            octets[reel + 3],
        ]);
        (BlockHeader::SIZE as u32..=MAX_BLOC_SERIALISE).contains(&taille)
            && BlockHeader::decode(&octets[reel + 4..reel + 4 + BlockHeader::SIZE])
                .map(|h| h.prev_block == id)
                .unwrap_or(false)
    };
    if parent_connu || suivant_s_enchaine {
        Some((bloc.header, reel))
    } else {
        None
    }
}

/// La genese est-elle reconnaissable en tete du fichier, malgre des octets
/// abimes ? Deux indices suffisent, chacun seul : l'en-tete a l'octet 4 est
/// celui de la genese (prefixe de longueur faux, contenu intact), ou
/// l'enregistrement place juste apres la longueur canonique s'enchaine sur
/// la genese (prefixe ou contenu faux, la suite du fichier est bien la
/// notre). Rend `false` si l'enregistrement est deja canonique : il n'y a
/// alors rien a recopier, et le mal est ailleurs.
fn la_genese_est_reconnaissable(
    chemin: &Path,
    canonique: &[u8],
    attendu: crate::hash::Hash256,
) -> std::io::Result<bool> {
    let l = canonique.len();
    let octets = lire_a(chemin, 0, (4 + l + 4 + BlockHeader::SIZE) as u64)?;
    if octets.len() >= 4 + l
        && octets[..4] == (l as u32).to_le_bytes()
        && octets[4..4 + l] == *canonique
    {
        return Ok(false);
    }
    let entete_intact = octets.len() >= 4 + BlockHeader::SIZE
        && BlockHeader::decode(&octets[4..4 + BlockHeader::SIZE])
            .map(|h| h.block_id() == attendu)
            .unwrap_or(false);
    let suivant_s_enchaine = octets.len() >= 4 + l + 4 + BlockHeader::SIZE
        && BlockHeader::decode(&octets[4 + l + 4..4 + l + 4 + BlockHeader::SIZE])
            .map(|h| h.prev_block == attendu)
            .unwrap_or(false);
    Ok(entete_intact || suivant_s_enchaine)
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
    /// Corps deja signales comme illisibles : un seul avertissement par bloc,
    /// pas un par lecture — un pair qui redemande le meme bloc ne doit pas
    /// remplir le journal.
    illisibles_signales: std::sync::Mutex<std::collections::HashSet<crate::hash::Hash256>>,
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
        Self::ouvrir(chemin.as_ref(), reseau, true, 0)
    }

    /// `reparer_la_genese` n'est vrai qu'a la premiere tentative : une
    /// reparation qui ne changerait rien ne doit pas boucler.
    /// `prefixes_repares` compte les prefixes de longueur deja reecrits par
    /// cette ouverture, pour la meme raison.
    fn ouvrir(
        chemin: &Path,
        reseau: crate::address::Network,
        reparer_la_genese: bool,
        prefixes_repares: u32,
    ) -> Result<(BlockArchive, Vec<BlockHeader>, Option<StoreError>), StoreError> {
        let store = BlockStore::new(chemin);
        let (entetes, souci) = store.scan_headers()?;
        let taille_fichier = if store.exists() {
            std::fs::metadata(store.path())?.len()
        } else {
            0
        };

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
        //
        // --- Une genese abimee n'est pas une genese etrangere.
        //
        // La genese est une constante du reseau, reecrite sans etat. Si
        // l'en-tete a l'octet 4 est le sien, ou si l'enregistrement qui suit
        // sa longueur canonique s'enchaine sur elle, le premier enregistrement
        // n'est pas celui d'une autre chaine : ce sont quelques octets
        // retournes sur la carte. Les ranger comme « ancienne chaine »
        // abandonnait toute l'histoire locale pour un bit. Une premiere
        // version ne recopiait que le **contenu**, a la longueur annoncee :
        // un bit dans le **prefixe de longueur** de la genese la laissait
        // hors d'atteinte — le balayage se desalignait ou ne rendait rien, et
        // le noeud mourait en conseillant `q21 init`. On recopie desormais
        // l'enregistrement entier, prefixe compris, quel que soit le prefixe
        // lu.
        let attendu = crate::chain::genesis_id(reseau);
        let canonique = crate::chain::genesis_block(reseau).encode();
        let premier_sain = entetes
            .first()
            .map(|(h, r)| h.block_id() == attendu && r.len as usize == canonique.len())
            .unwrap_or(false);
        if !premier_sain && taille_fichier > 0 {
            if reparer_la_genese && la_genese_est_reconnaissable(store.path(), &canonique, attendu)?
            {
                let mut f = OpenOptions::new().write(true).open(store.path())?;
                f.seek(SeekFrom::Start(0))?;
                f.write_all(&(canonique.len() as u32).to_le_bytes())?;
                f.write_all(&canonique)?;
                f.sync_all()?;
                eprintln!(
                    "  fichier des blocs repare : l'enregistrement de la genese etait abime \
                     (prefixe de longueur ou contenu), la genese du reseau a ete recopiee \
                     a sa place"
                );
                // On relit : la suite du chargement doit voir le fichier tel
                // qu'il est maintenant.
                drop(f);
                return Self::ouvrir(store.path(), reseau, false, prefixes_repares);
            }
            match entetes.first() {
                Some((premier, _)) if premier.block_id() != attendu => {
                    return Err(StoreError::GeneseEtrangere {
                        attendu,
                        vu: premier.block_id(),
                    });
                }
                // La genese est reconnue mais sa longueur annoncee est fausse
                // et la recopie a deja eu lieu : la reparation de prefixe
                // ci-dessous a le dernier mot.
                Some(_) => {}
                None => eprintln!(
                    "avertissement : le fichier des blocs ({taille_fichier} octet(s)) ne commence \
                     par aucun enregistrement lisible, et rien n'y ressemble a la genese de ce \
                     reseau : il est illisible ou n'est pas un fichier de blocs Q21 \
                     ({})",
                    souci.as_ref().map(|s| s.to_string()).unwrap_or_default()
                ),
            }
        }

        // --- Un prefixe de longueur abime se reecrit, il ne se coupe pas.
        //
        // Chaque enregistrement est precede de sa longueur sur quatre octets.
        // Un bit retourne la-dedans, et le balayage ne comprend plus la suite :
        // trop long, il pointe au-dela du fichier (« ecriture interrompue »)
        // ou au milieu de l'enregistrement suivant ; trop court, le balayage
        // accepte le bloc avec une longueur fausse puis lit n'importe quoi
        // derriere. Dans les deux cas, **tous les octets du bloc sont la**.
        //
        // La premiere version traitait le cas « trop long, pres de la fin »
        // comme une ecriture interrompue et coupait tout ce qui suivait le
        // dernier enregistrement complet — jusqu'a `MAX_BLOCK_SIZE` octets,
        // soit des milliers de blocs vides : un bit effacait trois semaines de
        // chaine en annoncant une reparation reussie, et l'instantane, pris
        // sous la tete, ne designait plus rien. Le cas « au milieu » coutait
        // une revalidation depuis la genese et le retelechargement de tout ce
        // qui suivait.
        //
        // Un bloc s'encode de facon canonique et se delimite lui-meme : on
        // retrouve sa longueur reelle en le decodant, et l'on exige qu'il se
        // rattache au fichier (parent connu, ou successeur qui s'enchaine).
        // Alors, et seulement alors, le prefixe est reecrit avec la longueur
        // reelle et le balayage est relance. Rien n'est coupe.
        let mut prefixe_abime = false;
        if souci.is_some() && !entetes.is_empty() {
            if let Some(p) = Self::prefixe_a_reparer(&store, &entetes, taille_fichier)? {
                if prefixes_repares < MAX_REPARATIONS_DE_PREFIXE {
                    let mut f = OpenOptions::new().write(true).open(store.path())?;
                    f.seek(SeekFrom::Start(p.position))?;
                    f.write_all(&p.reel.to_le_bytes())?;
                    f.sync_all()?;
                    drop(f);
                    eprintln!(
                        "  fichier des blocs repare : le prefixe de longueur de l'enregistrement {} \
                         (bloc de hauteur {}) annoncait {} octet(s) au lieu de {} ; il a ete \
                         reecrit, aucun bloc n'a ete coupe",
                        p.index, p.hauteur, p.lu, p.reel
                    );
                    return Self::ouvrir(
                        store.path(),
                        reseau,
                        reparer_la_genese,
                        prefixes_repares + 1,
                    );
                }
                // Le budget est epuise : on sait qu'un bloc complet suit, donc
                // on ne coupera rien, mais on ne relance plus le balayage.
                prefixe_abime = true;
                eprintln!(
                    "avertissement : plus de {MAX_REPARATIONS_DE_PREFIXE} prefixes de longueur \
                     abimes dans le fichier des blocs ; la reparation s'arrete a \
                     l'enregistrement {}, le reste n'est pas touche",
                    p.index
                );
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
        // 5. **Jamais un bloc complet.** La borne en octets du point 3 n'est
        //    pas une borne en blocs : quatre mebioctets, ce sont quinze mille
        //    blocs vides. Si un bloc complet qui se rattache au fichier
        //    commence apres le dernier enregistrement valide, ce n'est pas une
        //    ecriture interrompue mais un prefixe abime — traite plus haut,
        //    par reecriture. On n'arrive ici que s'il n'y en a pas : ce qui
        //    reste est bien un fragment.
        let mut souci = souci;
        if matches!(souci, Some(StoreError::FichierTronque { .. }))
            && !entetes.is_empty()
            && !prefixe_abime
        {
            let fin = entetes
                .last()
                .map(|(_, r)| r.offset + r.len as u64)
                .unwrap_or(0);
            let taille = taille_fichier;
            let jete = taille.saturating_sub(fin);
            if fin > 0 && jete <= crate::consensus::MAX_BLOCK_SIZE as u64 + 4 {
                let copie = copier_la_queue(store.path(), fin, jete);
                match copie.and_then(|_| std::fs::OpenOptions::new().write(true).open(store.path()))
                {
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
                illisibles_signales: std::sync::Mutex::new(std::collections::HashSet::new()),
            },
            seuls,
            souci,
        ))
    }

    /// Cherche, la ou le balayage s'est arrete, un prefixe de longueur dont
    /// la valeur ne correspond pas au bloc qu'il precede.
    ///
    /// # La methode
    ///
    /// On remonte depuis le dernier enregistrement accepte jusqu'au dernier
    /// dont le **corps** se relit : c'est le dernier point sur. Le suspect est
    /// l'enregistrement qui le suit — soit accepte par le balayage avec une
    /// longueur qui ne le laisse pas se relire (prefixe trop court, ou trop
    /// long mais encore dans le fichier), soit refuse par le balayage
    /// (prefixe qui pointe hors du fichier ou hors des bornes). Dans les deux
    /// cas, ses octets commencent juste apres le dernier corps sain, et
    /// [`enregistrement_rattache`] dit s'ils forment un bloc complet qui
    /// appartient a ce fichier, et combien d'octets il occupe.
    ///
    /// Ne fait rien — et ne laisse rien faire — si le prefixe lu est deja la
    /// longueur reelle : le mal est alors ailleurs, et ce n'est pas a cette
    /// fonction de l'inventer.
    fn prefixe_a_reparer(
        store: &BlockStore,
        entetes: &[(BlockHeader, RecordRef)],
        taille_fichier: u64,
    ) -> Result<Option<PrefixeAReparer>, StoreError> {
        // Le dernier enregistrement dont le corps se relit.
        let mut sains = entetes.len();
        let mut recul = 0usize;
        while sains > 0 && recul < MAX_RECUL {
            if store.read_at(entetes[sains - 1].1).is_ok() {
                break;
            }
            sains -= 1;
            recul += 1;
        }
        if recul >= MAX_RECUL {
            return Ok(None);
        }
        let connus: std::collections::HashSet<crate::hash::Hash256> =
            entetes[..sains].iter().map(|(h, _)| h.block_id()).collect();

        // Le suspect : la ou commencent ses octets, et ce que son prefixe dit.
        let (debut, lu) = if sains < entetes.len() {
            let r = entetes[sains].1;
            (r.offset, r.len)
        } else {
            let fin = entetes
                .last()
                .map(|(_, r)| r.offset + u64::from(r.len))
                .unwrap_or(0);
            if fin == 0 || taille_fichier < fin + 4 + BlockHeader::SIZE as u64 {
                return Ok(None);
            }
            let prefixe = lire_a(store.path(), fin, 4)?;
            if prefixe.len() < 4 {
                return Ok(None);
            }
            (
                fin + 4,
                u32::from_le_bytes([prefixe[0], prefixe[1], prefixe[2], prefixe[3]]),
            )
        };
        let octets = lire_a(
            store.path(),
            debut,
            u64::from(MAX_BLOC_SERIALISE) + 4 + BlockHeader::SIZE as u64,
        )?;
        let Some((entete, reel)) = enregistrement_rattache(&octets, &connus) else {
            return Ok(None);
        };
        if reel as u64 == u64::from(lu) {
            return Ok(None);
        }
        Ok(Some(PrefixeAReparer {
            position: debut - 4,
            index: sains,
            lu,
            reel: reel as u32,
            hauteur: entete.height,
        }))
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
    ///
    /// Un corps **indexe mais illisible** n'est pas un corps absent : ce sont
    /// des octets abimes au milieu du fichier. L'appelant ne voit qu'un
    /// `None` et dira « absent » ; on le precise ici, une fois par bloc, pour
    /// que l'operateur sache que c'est son disque, et que le bloc sera
    /// redemande au reseau — un cout, pas une perte.
    pub fn read(&self, id: &crate::hash::Hash256) -> Option<Block> {
        let g = self.positions.lock().ok()?;
        let r = *g.get(id)?;
        match self.store.read_at(r) {
            Ok(b) => Some(b),
            Err(e) => {
                let premiere_fois = self
                    .illisibles_signales
                    .lock()
                    .map(|mut s| s.insert(*id))
                    .unwrap_or(false);
                if premiere_fois {
                    let cause = match e {
                        StoreError::FichierTronque { .. } => "le fichier s'arrete avant sa fin",
                        StoreError::Io(_) => "erreur de lecture du disque",
                        _ => "ses octets ne forment plus un bloc",
                    };
                    eprintln!(
                        "avertissement : le corps du bloc {id} est indexe dans le fichier des \
                         blocs (position {}, {} octets) mais ne se relit pas : {cause}. Octets \
                         abimes sur le disque ; le bloc sera redemande au reseau",
                        r.offset, r.len
                    );
                }
                None
            }
        }
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

    /// Nombre d'en-tetes complets que le fichier contient, d'apres sa seule
    /// taille — sans le relire. `None` si le magasin n'existe pas ou n'a meme
    /// pas son prefixe.
    ///
    /// C'est ce que la boucle d'instantane consulte toutes les cinq minutes
    /// pour savoir jusqu'ou completer le magasin : relire tout le fichier —
    /// 160 octets par bloc, tout l'historique — a cette frequence userait
    /// une carte SD pour rien. La chaine relue au demarrage par [`Self::load`]
    /// garantit que les en-tetes comptes ici s'enchainent bien.
    pub fn compte(&self) -> Option<u64> {
        let taille = std::fs::metadata(&self.chemin).ok()?.len();
        if taille < PREFIXE_ENTETES {
            return None;
        }
        Some((taille - PREFIXE_ENTETES) / BlockHeader::SIZE as u64)
    }

    /// Le dernier en-tete complet du fichier, relu seul — sans parcourir le
    /// reste. `None` si le magasin est vide, absent, ou si cet en-tete ne se
    /// decode pas.
    pub fn dernier(&self) -> Option<BlockHeader> {
        let n = self.compte()?;
        if n == 0 {
            return None;
        }
        self.entete_a(n - 1)
    }

    /// L'en-tete a l'index `index` (l'index est aussi la hauteur, le magasin
    /// partant de la genese sans trou), relu seul. `None` s'il n'existe pas
    /// ou ne se decode pas.
    pub fn entete_a(&self, index: u64) -> Option<BlockHeader> {
        if index >= self.compte()? {
            return None;
        }
        let mut f = File::open(&self.chemin).ok()?;
        f.seek(SeekFrom::Start(
            PREFIXE_ENTETES + index * BlockHeader::SIZE as u64,
        ))
        .ok()?;
        let mut brut = [0u8; BlockHeader::SIZE];
        f.read_exact(&mut brut).ok()?;
        BlockHeader::decode(&brut).ok()
    }

    /// Ne garde que les `n` premiers en-tetes. Sert a retirer une queue que
    /// la chaine en memoire dement — un dernier en-tete abime qui s'enchaine
    /// encore sur son parent mais n'est plus lui-meme.
    pub fn tronquer(&self, n: u64) -> Result<(), StoreError> {
        let Some(actuel) = self.compte() else {
            return Ok(());
        };
        if n >= actuel {
            return Ok(());
        }
        let fh = OpenOptions::new().write(true).open(&self.chemin)?;
        fh.set_len(PREFIXE_ENTETES + n * BlockHeader::SIZE as u64)?;
        fh.sync_all()?;
        Ok(())
    }

    /// Relit toute la chaine d'en-tetes.
    ///
    /// Verifie la magie, la genese, l'enchainement (parent et hauteur), et coupe
    /// une eventuelle queue partielle.
    ///
    /// # Un en-tete illisible ou non chaine au milieu : on coupe, on ne refuse plus
    ///
    /// Une premiere version signalait toute rupture d'enchainement au milieu du
    /// fichier comme une corruption et refusait le magasin entier. Sur un noeud
    /// elague ou adopte, ce magasin est la **seule** source de la chaine
    /// d'en-tetes d'avant l'instantane : un seul bit retourne sur la carte SD
    /// — dans n'importe lequel des 160 octets de n'importe quel bloc de tout
    /// l'historique — rendait le dossier indemarrable, avec pour seul conseil
    /// de « resynchroniser dans un dossier vide ». C'est le defaut que ceci
    /// ferme : le fichier est tronque a la derniere position saine, l'operateur
    /// en est averti, et l'appelant repart de ce qui reste — le reseau
    /// refournira les en-tetes manquants, puisque la preuve de travail d'un
    /// en-tete recu du reseau est verifiee de toute facon.
    ///
    /// Tronquer plutot que garder le prefixe sain en memoire : le prochain
    /// `append` doit ecrire a la suite du dernier en-tete **sain**, pas apres
    /// les octets abimes. Si la troncature elle-meme echoue, l'ancienne erreur
    /// [`StoreError::EntetesMaillonRompu`] est rendue : rien n'est cru.
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

        // Chaque en-tete est decode, puis confronte au precedent, **au fil de
        // la lecture** : le premier qui ne se decode pas ou ne s'enchaine pas
        // marque la fin de ce qu'on peut croire. `None` = rien d'anormal.
        let mut entetes: Vec<BlockHeader> = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
        let mut brut = [0u8; BlockHeader::SIZE];
        let mut premier_douteux: Option<u64> = None;
        for index in 0..n {
            if f.read_exact(&mut brut).is_err() {
                premier_douteux = Some(index);
                break;
            }
            let Ok(h) = BlockHeader::decode(&brut) else {
                premier_douteux = Some(index);
                break;
            };
            if let Some(precedent) = entetes.last() {
                if h.prev_block != precedent.block_id() || h.height != precedent.height + 1 {
                    premier_douteux = Some(index);
                    break;
                }
            }
            entetes.push(h);
        }

        // La genese, avant tout : un fichier d'en-tetes d'une autre chaine ne
        // doit pas etre adopte.
        //
        // Mais une genese **abimee** n'est pas une genese etrangere. Elle est
        // une constante du reseau ; si l'en-tete qui suit s'enchaine sur la
        // vraie genese, le premier enregistrement n'est que quelques octets
        // retournes : on le recopie, comme le fait le fichier de blocs.
        let attendu = crate::chain::genesis_id(reseau);
        let genese_lue = entetes.first().map(|h| h.block_id());
        let genese_douteuse = match genese_lue {
            Some(vu) => vu != attendu,
            None => n >= 1, // le premier enregistrement ne se decode pas
        };
        if genese_douteuse {
            let etrangere = || match genese_lue {
                Some(vu) => StoreError::GeneseEtrangere { attendu, vu },
                None => StoreError::BlocIllisible { index: 0 },
            };
            if n < 2 {
                return Err(etrangere());
            }
            // Le second en-tete, relu directement : la boucle ci-dessus s'est
            // peut-etre arretee sur lui, puisqu'il ne s'enchaine pas sur la
            // fausse genese.
            let mut second = [0u8; BlockHeader::SIZE];
            let mut g = File::open(&self.chemin)?;
            g.seek(SeekFrom::Start(PREFIXE_ENTETES + taille_entete))?;
            let s = g
                .read_exact(&mut second)
                .ok()
                .and_then(|_| BlockHeader::decode(&second).ok());
            let chaine_sur_la_vraie = s.is_some_and(|s| s.prev_block == attendu && s.height == 1);
            if !chaine_sur_la_vraie {
                return Err(etrangere());
            }
            let canonique = crate::chain::genesis_block(reseau).header;
            let mut fh = OpenOptions::new().write(true).open(&self.chemin)?;
            fh.seek(SeekFrom::Start(PREFIXE_ENTETES))?;
            fh.write_all(&canonique.encode())?;
            fh.sync_all()?;
            eprintln!("  magasin d'en-tetes repare : en-tete de genese abime, recopie");
            // On relit tout : l'enchainement doit etre reverifie depuis la
            // vraie genese, et la troncature eventuelle se decide sur ce
            // fichier repare.
            return self.load(reseau);
        }

        // Puis la coupe : tout ce qui suit le premier en-tete douteux est
        // retire du fichier, et l'operateur le sait.
        if let Some(index) = premier_douteux {
            let propre = PREFIXE_ENTETES + index * taille_entete;
            let coupe = std::fs::metadata(&self.chemin)?
                .len()
                .saturating_sub(propre);
            let fh = OpenOptions::new().write(true).open(&self.chemin)?;
            if fh.set_len(propre).is_err() {
                return Err(StoreError::EntetesMaillonRompu { index });
            }
            let _ = fh.sync_all();
            eprintln!(
                "  magasin d'en-tetes repare : l'en-tete {index} est illisible ou ne \
                 s'enchaine pas sur le precedent ; {} en-tete(s) ({coupe} octets) \
                 retire(s) a partir de la hauteur {index}. Le reseau les refournira",
                n.saturating_sub(index)
            );
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
            f.write_all(&(MAX_BLOC_SERIALISE - 1).to_le_bytes())
                .unwrap();
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

    /// Un maillon rompu au milieu ne condamne plus le magasin : on coupe a la
    /// derniere position saine, et ce qui suit reviendra du reseau.
    #[test]
    fn un_maillon_rompu_est_coupe_a_la_derniere_position_saine() {
        let p = chemin_temporaire("hdr-maillon");
        let s = HeaderStore::new(&p);
        let mut chaine = chaine_entetes(5);
        // On casse l'enchainement du troisieme en-tete.
        chaine[3].prev_block = crate::hash::Hash256([0x77; 32]);
        s.append(&chaine).unwrap();
        let relus = s.load(Network::Regtest).expect("le magasin se repare");
        assert_eq!(relus, chaine[..3], "0..=2 sont sains, 3 et 4 sont retires");
        assert_eq!(
            std::fs::metadata(&p).unwrap().len(),
            PREFIXE_ENTETES + 3 * BlockHeader::SIZE as u64,
            "le fichier est tronque, pas seulement lu court"
        );
        // Et l'on peut ecrire a la suite : les en-tetes sains reviennent.
        let bonne = chaine_entetes(5);
        s.append(&bonne[3..]).unwrap();
        assert_eq!(s.load(Network::Regtest).unwrap(), bonne);
        s.remove().unwrap();
    }

    /// Un en-tete de genese abime n'est pas une genese etrangere : il est
    /// recopie depuis la constante du reseau, comme dans le fichier de blocs.
    #[test]
    fn une_genese_abimee_dans_le_magasin_est_recopiee() {
        let p = chemin_temporaire("hdr-genese-abimee");
        let s = HeaderStore::new(&p);
        let chaine = chaine_entetes(4);
        s.append(&chaine).unwrap();
        // Un bit dans le nonce de la genese : son identifiant change, le
        // second en-tete ne s'enchaine plus sur elle.
        {
            let mut f = OpenOptions::new().read(true).write(true).open(&p).unwrap();
            f.seek(SeekFrom::Start(
                PREFIXE_ENTETES + BlockHeader::SIZE as u64 - 1,
            ))
            .unwrap();
            let mut o = [0u8; 1];
            f.read_exact(&mut o).unwrap();
            f.seek(SeekFrom::Start(
                PREFIXE_ENTETES + BlockHeader::SIZE as u64 - 1,
            ))
            .unwrap();
            f.write_all(&[o[0] ^ 0x01]).unwrap();
        }
        assert_eq!(s.load(Network::Regtest).unwrap(), chaine);
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
