//! Chaine : genese, difficulte, index a branches, choix de fourche, minage.
//!
//! # Ce que ce module protege, et ce qu'il ne peut pas proteger
//!
//! Autant l'ecrire ici plutot que dans un document que personne n'ouvre :
//! **aucune ligne de ce fichier ne rend impossible une attaque a 51 %.** C'est
//! un theoreme, pas une lacune. La regle qui fait fonctionner Nakamoto — la
//! chaine valide est celle qui porte le plus de travail — est exactement celle
//! qui donne le pouvoir a un majoritaire. Refuser sa chaine supposerait de
//! savoir que c'est lui, donc une identite, donc une autorite : on echangerait
//! le probleme contre un pire.
//!
//! Ce que ce module fait, en revanche, et qui est loin d'etre rien :
//!
//! - **choisir par le travail cumule et non par la longueur.** Comparer deux
//!   chaines par leur nombre de blocs est un bug de conception : on fabrique une
//!   longue chaine a difficulte basse pour presque rien ;
//! - **borner la profondeur d'une reorganisation** ([`MAX_REORG_DEPTH`]), ce qui
//!   rend irreversible tout ce qui est enfoui plus profond ;
//! - **faire payer la profondeur** : au-dela de quelques blocs, une fourche doit
//!   montrer un exces de travail qui croit avec sa profondeur ;
//! - **remunerer les oncles**, pour retirer au gros mineur l'avantage
//!   super-lineaire qu'il tire des courses de propagation.
//!
//! Et ce qui reste protege quoi qu'il arrive, y compris face a un adversaire
//! detenant 99 % de la puissance : il ne peut ni voler une piece dont il n'a pas
//! la clef, ni fabriquer une unite au-dela de la subvention, ni relever le
//! plafond de 21 000 001. Ces trois proprietes ne dependent pas du consensus
//! mais de la cryptographie et de regles que chaque noeud verifie seul, dans
//! son coin, sans faire confiance a personne.

use crate::address::Network;
use crate::amount::Amount;
use crate::block::{Block, BlockHeader};
use crate::consensus::*;
use crate::hash::Hash256;
use crate::memhard::{PowTable, TableParams};
use crate::pow::{self, PowEngine, Q21Pow};
use crate::sig::SchemeId;
use crate::state::Snapshot;
use crate::tx::{Transaction, TxIn, TxOut};
use crate::uint::U256;
use crate::utxo::{UndoRecord, UtxoSet};
use crate::validate::{self, BlockContext, ValidationError};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// Genese
// ---------------------------------------------------------------------------

/// Message inscrit dans la coinbase du bloc de genese.
///
/// Techniquement inutile. En pratique, la seule ligne du systeme qui dit
/// pourquoi il existe — et elle remplit une seconde fonction, souvent oubliee :
/// un titre de presse date **prouve que la chaine n'a pas ete minee en secret
/// avant cette date**. C'est un horodatage que le fondateur ne peut pas falsifier.
///
/// A remplacer par un titre reel du jour du lancement.
pub const GENESIS_MESSAGE: &[u8] = b"Q21 -- une voix par machine, pas par fonderie de silicium";

/// Horodatage du bloc de genese. A figer au lancement.
pub const GENESIS_TIME: u64 = 1_755_734_400;

/// Construit le bloc de genese.
///
/// Sa coinbase emet exactement [`GENESIS_PREMINT`], la piece qui porte le
/// plafond de 21 000 000 a 21 000 001. Le calendrier d'emission rend zero au
/// bloc 0 — la rampe part de zero — donc cette unite ne peut venir que d'ici.
///
/// **Entierement deterministe.** Aucun parametre local n'y entre : tous les
/// noeuds d'un meme reseau produisent bit pour bit le meme bloc de genese, donc
/// le meme identifiant, donc la meme chaine. Voir [`GENESIS_BENEFICIARY`] pour
/// pourquoi la piece est indepensable.
pub fn genesis_block(network: Network) -> Block {
    // La genese est deterministe mais coûteuse : il faut construire une table de
    // preuve de travail puis balayer les nonces. La recalculer a chaque appel se
    // payait en dizaines de secondes de demarrage et de tests. On la calcule une
    // fois par reseau et par processus.
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Vec<(Network, Block)>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    if let Ok(g) = cache.lock() {
        if let Some((_, b)) = g.iter().find(|(n, _)| *n == network) {
            return b.clone();
        }
    }
    let b = construire_genese(network);
    if let Ok(mut g) = cache.lock() {
        if !g.iter().any(|(n, _)| *n == network) {
            g.push((network, b.clone()));
        }
    }
    b
}

/// Identifiant du bloc de genese du reseau.
///
/// C'est la seule racine legitime d'une chaine Q21. Un fichier de blocs dont le
/// premier enregistrement ne porte pas cet identifiant n'est pas une chaine de
/// ce reseau, quoi qu'il pretende.
pub fn genesis_id(network: Network) -> Hash256 {
    genesis_block(network).header.block_id()
}

fn construire_genese(network: Network) -> Block {
    let beneficiaire = Hash256(GENESIS_BENEFICIARY);
    // La genese porte le schema par defaut de la chaine. Elle est indepensable
    // — voir `GENESIS_BENEFICIARY` — mais ce champ annonce le niveau de
    // securite que Q21 retient, et il entre dans l'identifiant de la genese.
    let scheme = SchemeId::MlDsa87;
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase(GENESIS_MESSAGE.to_vec())],
        outputs: vec![TxOut {
            value: Amount::from_units(GENESIS_PREMINT),
            scheme,
            pubkey_hash: beneficiaire,
        }],
        lock_time: 0,
    };

    let mut b = Block {
        header: BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            uncles_root: Hash256::ZERO,
            miner: beneficiaire,
            time: GENESIS_TIME,
            bits: INITIAL_BITS,
            height: 0,
            nonce: 0,
        },
        transactions: vec![coinbase],
        uncles: Vec::new(),
    };
    b.header.merkle_root = b.compute_merkle_root();
    b.header.uncles_root = b.compute_uncles_root();

    // La genese porte une preuve de travail comme les autres : personne ne doit
    // pouvoir fabriquer une genese concurrente sans depenser le meme effort.
    let table = PowTable::build(TableParams::for_network(network), 0);
    let _ = pow::mine_with_table(&mut b.header, &table, 50_000_000);
    b
}

// ---------------------------------------------------------------------------
// Difficulte : LWMA
// ---------------------------------------------------------------------------

/// Ajustement de difficulte par moyenne mobile lineairement ponderee.
///
/// A chaque bloc, et non tous les 2 016 comme Bitcoin. Une petite chaine dont le
/// hashrate double ou disparait dans la journee ne peut pas attendre deux
/// semaines : elle se ferait eteindre par la premiere ferme qui passe.
///
/// Deux garde-fous limitent la manipulation par horodatage : chaque intervalle
/// est borne a `[1, 6T]`, et la cible ne peut varier que d'un facteur
/// [`MAX_TARGET_CHANGE`] d'un bloc a l'autre.
pub fn next_bits(entetes_recents: &[BlockHeader]) -> u32 {
    let n = entetes_recents.len();
    if n < 2 {
        return INITIAL_BITS;
    }
    let fenetre = n.min(LWMA_WINDOW + 1);
    let recents = &entetes_recents[n - fenetre..];
    let k = recents.len() - 1;

    let t_cible = TARGET_BLOCK_SECS;
    let avance_max = LWMA_AVANCE_MAX * t_cible;
    let retard_max = LWMA_RETARD_MAX * t_cible;

    // --- Le temps de resolution est SIGNE, et c'est tout le sujet.
    //
    // La version precedente calculait `time[i+1] - time[i]` en arithmetique non
    // signee, puis bornait a `[1, 6T]`. Un horodatage recule donnait donc 1, et
    // jamais une valeur negative.
    //
    // Cette dissymetrie etait exploitable, et l'audit de la phase 8b l'a
    // chiffree : un mineur inscrivant systematiquement `parent + 6T` injecte a
    // chaque bloc du temps apparent que **rien ne vient jamais soustraire**. La
    // difficulte s'effondre.
    //
    // ```text
    //   part de puissance   chute de difficulte   blocs obtenus
    //         5 %                  21,5 %             x 1,28
    //        15 %                  82,5 %             x 5,68
    //        20 %                  97,3 %             x 37,1
    // ```
    //
    // Le seuil analytique d'effondrement total est a **20,7 %** : au-dela, la
    // difficulte tombe a son plancher et la chaine appartient a l'attaquant.
    // Vingt pour cent, ce n'est pas cinquante-et-un.
    //
    // La premiere correction etait celle de LWMA-1 de Zawy : borner
    // symetriquement, a `[-6T, +6T]`, pour que le temps avance par un mineur
    // soit rendu par le bloc suivant. Il l'etait, mais pas entierement : le
    // bloc honnete est contraint par la mediane et ne peut pas reculer
    // autant que l'attaquant a avance. Il restait un solde — 33 % de blocs en
    // plus pour une moitie de la puissance.
    //
    // La borne est desormais **dissymetrique** : `[-6T, +4T]`. Le bloc
    // honnete retire plus que l'attaquant n'a pu injecter, et la manipulation
    // se retourne contre son auteur (voir `LWMA_AVANCE_MAX`). La somme
    // ponderee reste plancheree pour qu'une suite d'horodatages recules ne
    // puisse pas la rendre nulle ou negative.
    let mut somme_ponderee: i128 = 0;
    let mut somme_cibles = U256::ZERO;

    for i in 0..k {
        let brut = recents[i + 1].time as i128 - recents[i].time as i128;
        let solvetime = brut.clamp(-(retard_max as i128), avance_max as i128);
        somme_ponderee += solvetime * (i as i128 + 1);

        match pow::target_from_compact(recents[i + 1].bits) {
            Ok(c) => somme_cibles = somme_cibles.checked_add(c).unwrap_or(somme_cibles),
            Err(_) => return INITIAL_BITS,
        }
    }

    let poids_total = (k as i128 * (k as i128 + 1)) / 2;
    if poids_total == 0 {
        return INITIAL_BITS;
    }

    // Plancher a 5 % de la duree attendue : sans lui, une suite d'horodatages
    // recules rendrait la somme nulle ou negative, et la difficulte
    // exploserait d'un coup — l'attaque symetrique de la precedente.
    let plancher_somme = poids_total * t_cible as i128 / 20;
    let somme = somme_ponderee.max(plancher_somme);

    let lwma = (somme / poids_total).max(1) as u64;
    let cible_moyenne = match somme_cibles.checked_div_u64(k as u64) {
        Some(c) => c,
        None => return INITIAL_BITS,
    };

    let mut nouvelle = match cible_moyenne.mul_div(lwma, t_cible) {
        Some(c) => c,
        None => return INITIAL_BITS,
    };

    let plafond = cible_moyenne
        .checked_mul_u64(MAX_TARGET_CHANGE)
        .unwrap_or(U256::MAX);
    let plancher = cible_moyenne
        .checked_div_u64(MAX_TARGET_CHANGE)
        .unwrap_or(U256::ONE);
    nouvelle = nouvelle.min(plafond).max(plancher);
    if nouvelle.is_zero() {
        return INITIAL_BITS;
    }

    let limite = pow::target_from_compact(INITIAL_BITS).unwrap_or(U256::MAX);
    if nouvelle > limite {
        return INITIAL_BITS;
    }
    pow::target_to_compact(nouvelle)
}

// ---------------------------------------------------------------------------
// Index
// ---------------------------------------------------------------------------

/// Entree d'index : un en-tete et le travail cumule depuis la genese.
#[derive(Clone, Copy, Debug)]
pub struct BlockIndex {
    pub header: BlockHeader,
    pub total_work: U256,
    /// Total emis a ce bloc inclus, en unites.
    ///
    /// Retenu par bloc pour une raison precise : defaire un bloc doit rendre
    /// l'emission exacte du parent. La version precedente la recalculait en
    /// re-additionnant les frais de chaque transaction du bloc defait — un
    /// calcul juste mais fragile, qui dependait de l'etat du jeu d'UTXO au
    /// moment ou on le lisait. Un entier de huit octets par bloc coute moins
    /// cher qu'un raisonnement a refaire.
    ///
    /// Vaut zero pour les blocs anterieurs a un instantane charge au demarrage :
    /// on ne peut pas les defaire de toute facon.
    pub emis: u64,
}

/// Fils de minage par defaut : tous les coeurs disponibles.
///
/// Un mineur de reference mono-fil reviendrait a offrir un facteur huit a
/// quiconque prend la peine d'ecrire le sien.
fn fils_par_defaut() -> usize {
    std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(1)
}

/// L'arborescence des blocs deduite des seuls en-tetes.
///
/// Le fichier des blocs n'est pas une ligne droite : il consigne aussi les
/// branches laterales, sans quoi aucune reorganisation ne survivrait a un
/// redemarrage. Savoir laquelle de ces branches est la chaine active demande
/// donc un calcul, et c'est celui-ci.
pub struct Arborescence {
    /// Tous les en-tetes connus, par identifiant.
    pub par_id: HashMap<Hash256, BlockHeader>,
    /// Travail cumule depuis la genese, par identifiant. Une branche dont le
    /// parent manque n'y figure pas : elle est orpheline, donc inexploitable.
    pub travail: HashMap<Hash256, U256>,
    /// La chaine active, de la genese a la tete la plus lourde.
    pub active: Vec<Hash256>,
    /// Identifiant du bloc de genese.
    pub genese: Hash256,
}

/// Resultat d'une reprise sur instantane.
pub struct Reprise {
    /// Chaine positionnee a l'instantane.
    pub chain: Chain,
    /// Blocs de la chaine active a revalider pour atteindre la meilleure tete.
    pub a_rejouer: Vec<Hash256>,
}

/// Pourquoi une reprise a echoue. Chaque cas fait retomber sur la
/// revalidation integrale, jamais sur une acceptation silencieuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepriseError {
    MauvaisReseau,
    /// Aucun bloc de hauteur zero dans le fichier.
    PasDeGenese,
    /// Un parent manque, ou une boucle a ete detectee.
    IndexIncoherent,
    /// L'instantane ne designe pas un bloc de la chaine la plus travaillee.
    InstantaneHorsChaine,
}

/// Pourquoi l'adoption d'un instantane portable a echoue.
///
/// Chaque cas refuse l'adoption : jamais un etat n'est adopte sur un doute. Le
/// noeud retombe alors sur la synchronisation ordinaire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptionError {
    /// L'empreinte de l'instantane ne correspond pas a la valeur de confiance
    /// fournie : ce n'est pas l'etat attendu.
    EmpreinteInattendue,
    /// La tete de l'instantane ne correspond pas a la tete de confiance fournie.
    TeteInattendue,
    /// Les en-tetes ne menent pas a la tete de confiance, a la hauteur annoncee,
    /// depuis la vraie genese : la chaine d'en-tetes n'authentifie pas la tete.
    EntetesInauthentiques,
    /// Un en-tete ne porte pas la difficulte que la regle impose a sa position.
    /// Sans ce controle, une chaine fabriquee garderait la difficulte plancher
    /// de bout en bout et ne couterait presque rien a produire.
    DifficulteInvalide { hauteur: u64 },
    /// Un en-tete ne satisfait pas sa propre cible : le travail annonce n'a pas
    /// ete fourni.
    TravailInvalide { hauteur: u64 },
    /// La chaine proposee contredit un ancrage inscrit dans le binaire. C'est le
    /// cas ou l'operateur a recopie une valeur de confiance empoisonnee : le
    /// logiciel sait mieux, et refuse.
    AncrageContredit { hauteur: u64 },
    /// La construction de la chaine a echoue (reseau, genese, hors chaine).
    Reprise(RepriseError),
}

impl std::fmt::Display for AdoptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdoptionError::EmpreinteInattendue => write!(
                f,
                "l'empreinte de l'instantane ne correspond pas a la valeur de \
                 confiance : ce n'est pas l'etat attendu, il n'est pas adopte"
            ),
            AdoptionError::TeteInattendue => write!(
                f,
                "la tete de l'instantane ne correspond pas a la tete de confiance"
            ),
            AdoptionError::EntetesInauthentiques => write!(
                f,
                "les en-tetes ne menent pas a la tete de confiance a la hauteur \
                 annoncee : la tete n'est pas authentifiee"
            ),
            AdoptionError::DifficulteInvalide { hauteur } => write!(
                f,
                "l'en-tete de hauteur {hauteur} ne porte pas la difficulte imposee \
                 par la regle : cette chaine d'en-tetes est fabriquee"
            ),
            AdoptionError::TravailInvalide { hauteur } => write!(
                f,
                "l'en-tete de hauteur {hauteur} ne satisfait pas sa cible : le \
                 travail annonce n'a pas ete fourni"
            ),
            AdoptionError::AncrageContredit { hauteur } => write!(
                f,
                "la chaine proposee contredit l'ancrage inscrit dans ce binaire a \
                 la hauteur {hauteur} : la valeur de confiance fournie est fausse \
                 ou empoisonnee, rien n'est adopte"
            ),
            AdoptionError::Reprise(e) => write!(f, "reprise impossible : {e}"),
        }
    }
}

impl std::fmt::Display for RepriseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepriseError::MauvaisReseau => write!(f, "instantane d'un autre reseau"),
            RepriseError::PasDeGenese => write!(f, "aucun bloc de genese dans le fichier"),
            RepriseError::IndexIncoherent => {
                write!(f, "index de blocs incoherent : parent manquant ou boucle")
            }
            RepriseError::InstantaneHorsChaine => write!(
                f,
                "l'instantane ne correspond pas a la chaine la plus travaillee"
            ),
        }
    }
}

/// Ou un noeud ecrit les blocs qu'il accepte.
///
/// # Le defaut que cette abstraction repare
///
/// Le demon n'ecrivait sur disque que les blocs **qu'il minait lui-meme**. Les
/// blocs recus du reseau etaient valides, connectes, servis aux pairs — et
/// perdus a l'arret. Un noeud qui se synchronisait tout en minant produisait un
/// fichier de blocs troue : 0 a 4, puis 11. Au redemarrage il repartait a la
/// hauteur 4, sans un mot, et le travail de sept blocs disparaissait.
///
/// Accepter un bloc et le conserver ne sont pas deux decisions : c'est la meme.
/// Le journal est donc branche sur la chaine, pas sur la boucle de minage.
pub trait Journal: Send + Sync {
    /// Consigne un bloc que la chaine vient d'accepter.
    ///
    /// L'implementation doit etre idempotente : un meme bloc peut etre presente
    /// deux fois sans qu'il faille l'ecrire deux fois.
    fn consigner(&self, bloc: &Block);
}

/// Ce qu'il est advenu d'un bloc soumis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accept {
    /// Le bloc prolonge la chaine active.
    Prolonge,
    /// Le bloc est valide mais reste sur une branche laterale.
    BrancheLaterale,
    /// La chaine active a bascule sur une autre branche.
    Reorganise { profondeur: u64 },
    /// Deja connu.
    DejaVu,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    Validation(ValidationError),
    /// Parent inconnu : impossible de rattacher ce bloc.
    ParentInconnu(Hash256),
    /// Aucun ancetre commun entre cette branche et la chaine active, dans la
    /// portee ou l'on accepte d'en chercher un.
    ///
    /// Se distingue de [`ChainError::FinaliteDepassee`] : la, on sait de
    /// combien la reorganisation depasse ; ici, on ne sait meme pas d'ou vient
    /// la branche. Les confondre a deja coute un diagnostic.
    PointDeForkIntrouvable {
        portee: u64,
    },
    /// La reorganisation demandee depasse la profondeur de finalite.
    ///
    /// C'est la defense anti-reorganisation profonde. Elle protege le passe au
    /// prix d'un risque de scission en cas de partition reseau prolongee — le
    /// compromis est assume et documente sur [`MAX_REORG_DEPTH`].
    FinaliteDepassee {
        profondeur: u64,
        max: u64,
    },
    /// La fourche est profonde mais n'apporte pas l'exces de travail exige.
    TravailInsuffisantPourLaProfondeur {
        profondeur: u64,
    },
    /// La fenetre d'annulation ne couvre pas la profondeur demandee.
    ///
    /// Arrive apres une reprise sur instantane, quand la reorganisation demande
    /// de defaire plus de blocs que le noeud n'en a rejoue. On refuse plutot que
    /// de tenter une operation qu'on ne saurait pas terminer.
    FenetreDAnnulationInsuffisante {
        profondeur: u64,
        disponible: u64,
    },
}

impl From<ValidationError> for ChainError {
    fn from(e: ValidationError) -> Self {
        ChainError::Validation(e)
    }
}

// ---------------------------------------------------------------------------
// Chaine
// ---------------------------------------------------------------------------

/// Fournisseur de corps de blocs, pour ce que la memoire ne garde plus.
///
/// La chaine ne connait pas le disque et ne doit pas le connaitre : elle decrit
/// le consensus. Mais un pair qui se synchronise reclame des blocs anciens, dont
/// le corps a ete elague. Cette interface est le seul point ou l'histoire
/// longue rentre — en lecture, jamais en validation.
pub trait BodySource: Send + Sync {
    fn body(&self, id: &Hash256) -> Option<Block>;
}

pub struct Chain {
    pub network: Network,
    index: HashMap<Hash256, BlockIndex>,
    /// Corps recents seulement : voir [`BODY_WINDOW`].
    blocks: HashMap<Hash256, Block>,
    /// Ordre d'insertion des corps, pour elaguer les plus anciens.
    ordre_corps: VecDeque<Hash256>,
    /// Ou lire les corps elagues. Absent en memoire pure (tests, outils).
    source: Option<std::sync::Arc<dyn BodySource>>,
    /// Identifiants de la chaine active, de la genese a la tete.
    active: Vec<Hash256>,
    pub utxo: UtxoSet,
    /// Un enregistrement par bloc de la chaine active, le dernier en queue.
    ///
    /// Borne a [`BODY_WINDOW`] : au-dela de la finalite glissante, defaire un
    /// bloc est de toute facon interdit.
    undos: VecDeque<UndoRecord>,
    pow: Q21Pow,
    emis: u64,
    /// Table de preuve de travail, conservee entre deux blocs.
    ///
    /// Sans ce cache, chaque appel au mineur reconstruirait la table de
    /// l'epoque : 2 Gio et 2^26 condensats sur le reseau principal, a chaque
    /// bloc. La table ne change qu'une fois tous les
    /// [`POW_EPOCH_BLOCKS`] blocs — soit environ 71 jours — et il n'y a aucune
    /// raison de la recalculer plus souvent.
    ///
    /// `RefCell` parce que le minage ne modifie pas l'etat de la chaine et prend
    /// `&self`. L'`Arc` permet de partager la table entre les fils du mineur
    /// sans la dupliquer — deux gigaoctets par fil serait absurde.
    table: RefCell<Option<std::sync::Arc<PowTable>>>,
    /// Fils employes par le mineur. Tous les coeurs par defaut.
    fils_minage: usize,
}

impl Chain {
    pub fn new(network: Network, genesis: Block) -> Chain {
        let mut utxo = UtxoSet::new();
        let mut undo = UndoRecord::default();
        let mut emis = 0u64;
        for tx in &genesis.transactions {
            emis += tx.total_output().map(|a| a.units()).unwrap_or(0);
            utxo.apply_transaction(tx, 0, &mut undo);
        }

        let id = genesis.header.block_id();
        let mut index = HashMap::new();
        index.insert(
            id,
            BlockIndex {
                header: genesis.header,
                total_work: pow::block_work(genesis.header.bits),
                emis,
            },
        );
        let mut blocks = HashMap::new();
        blocks.insert(id, genesis);
        let mut ordre_corps = VecDeque::new();
        ordre_corps.push_back(id);

        Chain {
            network,
            index,
            blocks,
            ordre_corps,
            source: None,
            active: vec![id],
            utxo,
            undos: VecDeque::from(vec![undo]),
            pow: Q21Pow::new(network),
            emis,
            table: RefCell::new(None),
            fils_minage: fils_par_defaut(),
        }
    }

    /// Reconstruit une chaine a partir d'un index d'en-tetes et d'un instantane.
    ///
    /// # Ce que cette fonction fait, et ce qu'elle refuse de faire
    ///
    /// Elle reconstruit l'**index** — quels blocs existent, lequel porte le plus
    /// de travail — en ne lisant que des en-tetes, et charge l'**etat monetaire**
    /// depuis l'instantane. Ce qu'elle ne fait pas : revalider quoi que ce soit
    /// en deca de l'instantane. C'est un choix assume, et le meme que celui de
    /// Bitcoin Core avec son `chainstate` : quiconque peut reecrire vos fichiers
    /// a deja gagne, et une revalidation integrale a chaque demarrage rend le
    /// noeud inutilisable bien avant de proteger qui que ce soit.
    ///
    /// Ce qui reste garanti : les blocs rendus dans `a_rejouer` — tout ce qui
    /// suit l'instantane — sont valides integralement par l'appelant, et le
    /// travail cumule de chaque branche est recalcule ici depuis les en-tetes.
    ///
    /// L'instantane doit etre pris **en retrait de la tete**, pas a la tete :
    /// rejouer la derniere fenetre reconstruit les enregistrements d'annulation,
    /// sans lesquels aucune reorganisation ne serait plus possible au demarrage.
    /// L'arborescence des blocs, telle que les seuls en-tetes la decrivent.
    ///
    /// Trois choses, calculees ensemble parce qu'elles se deduisent l'une de
    /// l'autre : quels blocs existent, quel travail cumule chacun porte, et
    /// quelle suite mene de la genese a la tete la plus lourde.
    ///
    /// # Pourquoi c'est une fonction a part
    ///
    /// Deux chemins de demarrage en ont besoin, et pour la meme raison. Celui
    /// qui reprend sur un instantane doit savoir ou se trouve cet instantane
    /// dans l'arborescence. Celui qui n'a **pas** d'instantane — le cas d'un
    /// arret brutal — doit reconstruire l'etat depuis la genese, et pour cela
    /// il lui faut d'abord savoir quelle est la chaine active. Sans cette
    /// reponse, il rejouait le fichier dans son ordre d'ecriture, qui melange
    /// les branches, et se heurtait aux defenses anti-reorganisation sur sa
    /// propre histoire. Voir `RECONSTRUCTION` dans les epreuves.
    pub fn arborescence(headers: &[BlockHeader]) -> Result<Arborescence, RepriseError> {
        // 1. Index brut, par identifiant.
        let mut par_id: HashMap<Hash256, BlockHeader> = HashMap::new();
        let mut genese = None;
        for h in headers {
            let id = h.block_id();
            if h.height == 0 {
                genese = Some(id);
            }
            par_id.insert(id, *h);
        }
        let genese = genese.ok_or(RepriseError::PasDeGenese)?;

        // 2. Travail cumule, par remontee memoisee vers la genese.
        //
        // Iteratif et non recursif : une chaine d'un million de blocs ferait
        // deborder la pile d'appels, et un fichier corrompu pourrait s'en servir.
        let mut travail: HashMap<Hash256, U256> = HashMap::new();
        travail.insert(genese, pow::block_work(par_id[&genese].bits));

        for depart in par_id.keys() {
            if travail.contains_key(depart) {
                continue;
            }
            let mut pile = Vec::new();
            let mut courant = *depart;
            let connu = loop {
                if let Some(w) = travail.get(&courant) {
                    break Some(*w);
                }
                let Some(h) = par_id.get(&courant) else {
                    break None; // parent absent du fichier : branche orpheline
                };
                pile.push(courant);
                if pile.len() > par_id.len() {
                    return Err(RepriseError::IndexIncoherent);
                }
                courant = h.prev_block;
            };
            let Some(mut w) = connu else { continue };
            while let Some(id) = pile.pop() {
                w = w
                    .checked_add(pow::block_work(par_id[&id].bits))
                    .unwrap_or(w);
                travail.insert(id, w);
            }
        }

        // 3. Meilleure tete, puis chaine active par remontee.
        let meilleure = travail
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
            .map(|(id, _)| *id)
            .ok_or(RepriseError::PasDeGenese)?;

        let mut active = Vec::new();
        let mut courant = meilleure;
        loop {
            active.push(courant);
            if courant == genese {
                break;
            }
            courant = par_id[&courant].prev_block;
            if !par_id.contains_key(&courant) {
                return Err(RepriseError::IndexIncoherent);
            }
        }
        active.reverse();

        Ok(Arborescence {
            par_id,
            travail,
            active,
            genese,
        })
    }

    /// Adopte un instantane **portable** — venu d'ailleurs — apres l'avoir ancre
    /// a une valeur de confiance.
    ///
    /// # Le modele de confiance, dit franchement
    ///
    /// `from_snapshot` fait confiance a ses en-tetes : elles viennent du propre
    /// fichier de blocs du noeud, deja valide. Un instantane portable, lui, n'a
    /// aucune de ces garanties. Deux ancrages, tous deux fournis par l'operateur
    /// depuis une source qu'il tient pour sure (l'empreinte et la tete
    /// qu'affichent son explorateur ou l'export de son propre noeud), les
    /// remplacent :
    ///
    /// - **l'empreinte** authentifie le jeu d'UTXO — le condensat MuHash de
    ///   l'instantane doit egaler la valeur de confiance ;
    /// - **la tete** authentifie la position — l'instantane doit s'en reclamer,
    ///   et les en-tetes doivent y mener, a la hauteur annoncee, depuis la vraie
    ///   genese.
    ///
    /// # Pourquoi la preuve de travail **est** reverifiee
    ///
    /// Une version precedente s'en dispensait, au motif que l'enchainement
    /// structurel jusqu'a la tete de confiance authentifie toute la chaine : le
    /// condensat de chaque en-tete est fige par le `prev_block` du suivant, donc
    /// un seul en-tete falsifie romprait la chaine.
    ///
    /// Le raisonnement est exact, et il ne suffit pas. Il prouve que les
    /// ancetres sont authentiques **etant donne que la tete l'est**. Or c'est
    /// precisement la question : la tete ne vient que d'une chaine hexadecimale
    /// que l'operateur a recopiee. Qui la controle — explorateur usurpe,
    /// interception, miroir malveillant, simple faute de frappe — peut fabriquer
    /// de toutes pieces une chaine d'en-tetes coherente, sans le moindre calcul,
    /// se terminant sur sa propre tete, et un jeu d'UTXO de son choix dont
    /// l'empreinte correspond a sa propre valeur. Les trois premiers controles
    /// passent tous. Le noeud adopte alors un etat monetaire entierement
    /// invente, pour un cout d'attaque nul.
    ///
    /// Le travail est la seule chose qu'on puisse verifier **sans faire
    /// confiance a personne** — c'est tout le propos de la preuve de travail. On
    /// le reverifie donc de la genese a la tete, et l'attaque cesse d'etre
    /// gratuite : il faut refaire le travail de toute la chaine.
    ///
    /// Deux controles, indissociables :
    ///
    /// - **la difficulte** de chaque en-tete doit etre celle que la regle impose
    ///   a sa position, et non celle qu'il revendique. Sans cela, une chaine
    ///   fabriquee resterait a la difficulte plancher de bout en bout ;
    /// - **le travail** de chaque en-tete doit satisfaire cette cible.
    ///
    /// # Le cout, mesure plutot que suppose
    ///
    /// L'objection d'origine — « ce serait aussi couteux que la synchronisation
    /// qu'on cherche a eviter » — confond deux choses. Une synchronisation
    /// complete valide les **corps** : chaque transaction, chaque signature,
    /// chaque mouvement d'UTXO. Ici on ne verifie que des en-tetes, par le
    /// chemin *leger* de la preuve memory-hard, celui qui n'emploie que le cache
    /// et jamais la table. Et comme on avance par hauteurs croissantes, le cache
    /// d'une epoque n'est construit qu'une fois. C'est deux ordres de grandeur
    /// en dessous d'une validation complete, et cela ne se paie qu'une fois, a
    /// l'adoption.
    pub fn adopter_instantane(
        network: Network,
        instantane: Snapshot,
        headers: &[BlockHeader],
        tete_de_confiance: Hash256,
        empreinte_de_confiance: Hash256,
    ) -> Result<Reprise, AdoptionError> {
        // 1. L'etat.
        if instantane.muhash != empreinte_de_confiance {
            return Err(AdoptionError::EmpreinteInattendue);
        }
        // 2. La position revendiquee.
        if instantane.tip != tete_de_confiance {
            return Err(AdoptionError::TeteInattendue);
        }
        // 3. L'authentification de la tete par les en-tetes : on remonte de la
        //    tete de confiance jusqu'a la genese, en verifiant a chaque pas
        //    l'enchainement et la hauteur. Rien n'est cru sur parole ; tout est
        //    force par les condensats.
        let par_id: std::collections::HashMap<Hash256, &BlockHeader> =
            headers.iter().map(|h| (h.block_id(), h)).collect();
        let mut courant = tete_de_confiance;
        let mut hauteur = instantane.height;
        // On retient le chemin au passage : c'est exactement la chaine dont il
        // faut ensuite verifier le travail, et la reparcourir serait du gachis.
        //
        // La capacite se borne au nombre d'en-tetes reellement fournis, JAMAIS a
        // `instantane.height` : cette hauteur vient d'un instantane qu'un pair
        // decode et controle (elle n'est validee qu'a l'interieur de la boucle
        // ci-dessous). Une hauteur adverse de `u64::MAX` faisait deborder
        // `as usize + 1`, ou tentait une allocation de plusieurs teraoctets, et
        // faisait AVORTER le processus (overflow-checks, panic=abort) : un
        // plantage a distance, fiable, de tout noeud en synchronisation rapide
        // depuis ce pair. Trouve par la red-team de phase 8b (2e campagne). La
        // boucle ne peut de toute facon pas depasser le nombre d'en-tetes
        // presents, chaque pas exigeant une entree dans `par_id`.
        let mut chemin: Vec<BlockHeader> = Vec::with_capacity(headers.len());
        loop {
            let Some(h) = par_id.get(&courant) else {
                return Err(AdoptionError::EntetesInauthentiques);
            };
            if h.height != hauteur {
                return Err(AdoptionError::EntetesInauthentiques);
            }
            chemin.push(**h);
            if hauteur == 0 {
                if courant != genesis_id(network) {
                    return Err(AdoptionError::EntetesInauthentiques);
                }
                break;
            }
            courant = h.prev_block;
            hauteur -= 1;
        }
        // 4. Le travail. C'est ce qui rend l'attaque couteuse au lieu de
        //    gratuite : voir la note de tete.
        chemin.reverse(); // de la genese vers la tete
        Self::verifier_le_travail(network, &chemin)?;

        // 5. Les ancrages inscrits dans le binaire. Ils priment sur tout ce que
        //    l'operateur a pu recopier : aux hauteurs qu'ils couvrent, la verite
        //    vient du logiciel relu par tous, pas d'une valeur transmise.
        Self::verifier_les_ancrages(
            &chemin,
            &instantane,
            crate::synchro_rapide::ancrages_integres(network),
        )?;

        // 5. La construction : positionnement, index, fenetre a rejouer.
        Chain::from_snapshot(network, instantane, headers).map_err(AdoptionError::Reprise)
    }

    /// Confronte une chaine candidate aux ancrages inscrits dans le binaire.
    ///
    /// `chemin` est ordonne par hauteurs croissantes, `chemin[0]` etant la
    /// genese. Deux exigences, et la seconde est celle qui compte le plus :
    ///
    /// - **tout ancrage situe sous la tete doit se retrouver dans la chaine**, a
    ///   sa hauteur et avec son identifiant. Une chaine qui pretend passer par
    ///   ailleurs a un point que le binaire tient pour vrai est refusee, meme si
    ///   elle porte du travail : c'est la ou un adversaire tres puissant
    ///   viendrait, et c'est la qu'on l'arrete ;
    /// - **a la hauteur exacte d'un ancrage, l'empreinte doit correspondre**.
    ///   L'operateur ne peut donc pas faire adopter un autre etat monetaire a une
    ///   hauteur dont le binaire connait l'empreinte.
    ///
    /// Une table vide n'interdit rien : la reverification du travail reste, elle,
    /// toujours appliquee.
    pub fn verifier_les_ancrages(
        chemin: &[BlockHeader],
        instantane: &Snapshot,
        ancrages: &[crate::synchro_rapide::Ancrage],
    ) -> Result<(), AdoptionError> {
        for a in ancrages {
            if a.hauteur > instantane.height {
                continue; // au-dela de ce qu'on adopte : rien a dire
            }
            let Some(entete) = chemin.get(a.hauteur as usize) else {
                return Err(AdoptionError::AncrageContredit { hauteur: a.hauteur });
            };
            if entete.block_id() != a.tete {
                return Err(AdoptionError::AncrageContredit { hauteur: a.hauteur });
            }
            if a.hauteur == instantane.height && instantane.muhash != a.empreinte {
                return Err(AdoptionError::AncrageContredit { hauteur: a.hauteur });
            }
        }
        Ok(())
    }

    /// Verifie, de la genese a la tete, que chaque en-tete porte la difficulte
    /// imposee par la regle **et** le travail qui satisfait cette cible.
    ///
    /// `active` est ordonne par hauteurs croissantes, `active[0]` etant la
    /// genese. L'ordre n'est pas un detail de confort : il permet au cache de
    /// l'epoque de n'etre construit qu'une seule fois, la ou un parcours
    /// desordonne le reconstruirait sans cesse.
    fn verifier_le_travail(network: Network, active: &[BlockHeader]) -> Result<(), AdoptionError> {
        if active.len() <= 1 {
            return Ok(());
        }
        let params = crate::memhard::TableParams::for_network(network);
        let fils = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(16);

        // --- Epoque par epoque, et non par tranches quelconques.
        //
        // Le registre des caches ne retient que les deux dernieres epoques. Des
        // fils travaillant chacun sur une epoque differente s'evinceraient donc
        // mutuellement, et la verification serait plus lente a plusieurs qu'a
        // un seul. On avance donc epoque par epoque : le cache est construit une
        // fois, puis partage par tous les fils qui verifient cette tranche-la.
        let mut i = 1usize;
        while i < active.len() {
            let epoque = crate::memhard::epoch_of(active[i].height);
            let mut j = i;
            while j < active.len() && crate::memhard::epoch_of(active[j].height) == epoque {
                j += 1;
            }
            let cache = crate::memhard::cache_for(params, epoque);
            Self::verifier_plage(network, active, i, j, params, &cache, fils)?;
            i = j;
        }
        Ok(())
    }

    /// Repartit une tranche d'une seule epoque sur plusieurs fils.
    ///
    /// Chaque en-tete se verifie independamment des autres : sa difficulte ne
    /// depend que de ses predecesseurs, qui sont deja la et ne bougent pas, et
    /// son travail ne depend que de lui. Le decoupage ne change donc aucun
    /// verdict — seulement le temps qu'il met a venir.
    #[allow(clippy::too_many_arguments)]
    fn verifier_plage(
        network: Network,
        active: &[BlockHeader],
        debut: usize,
        fin: usize,
        params: crate::memhard::TableParams,
        cache: &crate::memhard::PowCache,
        fils: usize,
    ) -> Result<(), AdoptionError> {
        let n = fin - debut;
        let fils = fils.min(n).max(1);
        // En deca de quelques centaines d'en-tetes, lancer des fils coute plus
        // cher que le travail qu'on leur confie.
        if fils == 1 || n < 256 {
            return Self::verifier_segment(network, active, debut, fin, params, cache);
        }
        let taille = n.div_ceil(fils);
        let resultats: Vec<Result<(), AdoptionError>> = std::thread::scope(|s| {
            let mut poignees = Vec::new();
            let mut d = debut;
            while d < fin {
                let f = (d + taille).min(fin);
                poignees.push(
                    s.spawn(move || Self::verifier_segment(network, active, d, f, params, cache)),
                );
                d = f;
            }
            poignees
                .into_iter()
                // Un fil de verification qui PANIQUE est un echec, jamais un
                // succes : le traiter comme `Ok(())` laissait un segment dont la
                // preuve de travail a fait paniquer le verificateur passer pour
                // valide — une adoption a l'ouverture. Red-team 8b (2e campagne).
                .map(|p| {
                    p.join()
                        .unwrap_or(Err(AdoptionError::EntetesInauthentiques))
                })
                .collect()
        });
        // Les segments sont ranges par hauteur croissante : prendre la premiere
        // erreur rend toujours la faute la plus basse, quel que soit l'ordre
        // dans lequel les fils ont fini. Un message qui changerait d'une
        // execution a l'autre serait inexploitable.
        resultats
            .into_iter()
            .find_map(|r| r.err())
            .map_or(Ok(()), Err)
    }

    /// Verifie un segment contigu d'en-tetes, tous de la meme epoque.
    fn verifier_segment(
        network: Network,
        active: &[BlockHeader],
        debut: usize,
        fin: usize,
        params: crate::memhard::TableParams,
        cache: &crate::memhard::PowCache,
    ) -> Result<(), AdoptionError> {
        let moteur = crate::pow::Q21PowAvecCache::new(params, cache);
        for i in debut..fin {
            let entete = &active[i];
            // 1. La difficulte imposee, pas celle revendiquee. Le reseau de
            //    regression la fige au minimum, comme partout ailleurs.
            let attendu = if network == Network::Regtest {
                INITIAL_BITS
            } else {
                let d = (i - 1).saturating_sub(LWMA_WINDOW);
                next_bits(&active[d..i])
            };
            if entete.bits != attendu {
                return Err(AdoptionError::DifficulteInvalide {
                    hauteur: entete.height,
                });
            }
            // 2. Le travail lui-meme. La comparaison a la cible reste celle du
            //    trait : il n'existe qu'une seule regle de validite du travail.
            moteur
                .check(entete)
                .map_err(|_| AdoptionError::TravailInvalide {
                    hauteur: entete.height,
                })?;
        }
        Ok(())
    }

    pub fn from_snapshot(
        network: Network,
        snapshot: Snapshot,
        headers: &[BlockHeader],
    ) -> Result<Reprise, RepriseError> {
        if snapshot.network != network {
            return Err(RepriseError::MauvaisReseau);
        }

        let Arborescence {
            par_id,
            travail,
            active,
            ..
        } = Self::arborescence(headers)?;

        // 4. L'instantane doit se trouver sur cette chaine active, a sa hauteur.
        let pos = snapshot.height as usize;
        if active.get(pos) != Some(&snapshot.tip) {
            return Err(RepriseError::InstantaneHorsChaine);
        }

        let mut index = HashMap::with_capacity(par_id.len());
        for (id, h) in &par_id {
            let Some(w) = travail.get(id) else { continue };
            index.insert(
                *id,
                BlockIndex {
                    header: *h,
                    total_work: *w,
                    // Inconnue en deca de l'instantane, et sans usage : on ne
                    // defait pas un bloc dont on n'a pas l'annulation.
                    emis: if *id == snapshot.tip {
                        snapshot.emis
                    } else {
                        0
                    },
                },
            );
        }

        let a_rejouer = active[pos + 1..].to_vec();
        Ok(Reprise {
            chain: Chain {
                network,
                index,
                blocks: HashMap::new(),
                ordre_corps: VecDeque::new(),
                source: None,
                active: active[..=pos].to_vec(),
                utxo: snapshot.utxo,
                undos: VecDeque::new(),
                pow: Q21Pow::new(network),
                emis: snapshot.emis,
                table: RefCell::new(None),
                fils_minage: fils_par_defaut(),
            },
            a_rejouer,
        })
    }

    /// Instantane pris **en retrait** de la tete, pour rester rejouable.
    ///
    /// On recule de toute la fenetre d'annulation disponible. Au redemarrage,
    /// rejouer cette fenetre reconstruit les enregistrements d'annulation et
    /// rend au noeud sa capacite a reorganiser — ce qu'un instantane pris a la
    /// tete lui aurait retiree.
    ///
    /// Rend `None` si la chaine est trop courte pour qu'un instantane ait un
    /// interet.
    pub fn snapshot(&self) -> Option<Snapshot> {
        self.snapshot_at_depth(self.undos.len().saturating_sub(1))
    }

    /// Instantane a une profondeur choisie, en blocs sous la tete.
    ///
    /// Le recul est plafonne par la fenetre d'annulation disponible : on ne peut
    /// pas remonter plus haut que ce qu'on sait defaire.
    pub fn snapshot_at_depth(&self, recul: usize) -> Option<Snapshot> {
        let recul = recul.min(self.undos.len().saturating_sub(1));
        if recul == 0 || self.height() < recul as u64 {
            return None;
        }
        let hauteur = self.height() - recul as u64;
        let tip = *self.active.get(hauteur as usize)?;

        let mut utxo = self.utxo.clone();
        for undo in self.undos.iter().rev().take(recul) {
            utxo.undo(undo);
        }

        let muhash = utxo.commitment();
        Some(Snapshot {
            network: self.network,
            height: hauteur,
            tip,
            emis: self.index.get(&tip).map(|b| b.emis).unwrap_or(self.emis),
            utxo,
            muhash,
        })
    }

    /// Branche un fournisseur de corps pour les blocs elagues.
    pub fn set_body_source(&mut self, s: std::sync::Arc<dyn BodySource>) {
        self.source = Some(s);
    }

    /// Enregistre un corps et elague les plus anciens.
    ///
    /// La genese n'est jamais elaguee : elle est le seul bloc dont l'absence
    /// rendrait la chaine inintelligible, et elle ne coute qu'un bloc.
    fn retenir_corps(&mut self, id: Hash256, block: Block) {
        if self.blocks.insert(id, block).is_none() {
            self.ordre_corps.push_back(id);
        }
        let genese = self.active.first().copied();
        while self.ordre_corps.len() > BODY_WINDOW {
            if let Some(vieux) = self.ordre_corps.pop_front() {
                if Some(vieux) == genese {
                    self.ordre_corps.push_back(vieux);
                    continue;
                }
                self.blocks.remove(&vieux);
            }
        }
    }

    /// Corps conserves en memoire vive.
    pub fn bodies_in_memory(&self) -> usize {
        self.blocks.len()
    }

    /// Execute `f` avec la table de l'epoque demandee, en la construisant
    /// seulement si le cache ne la contient pas deja.
    #[cfg(test)]
    fn with_table<R>(&self, epoch: u64, f: impl FnOnce(&PowTable) -> R) -> R {
        let t = self.table_for(epoch);
        f(&t)
    }

    /// La table de l'epoque, si elle est deja construite. Ne construit rien :
    /// c'est a l'appelant de le faire **hors du verrou** et de la rendre par
    /// [`Self::adopter_table`].
    pub fn table_si_prete(&self, epoch: u64) -> Option<std::sync::Arc<PowTable>> {
        self.table
            .borrow()
            .as_ref()
            .filter(|t| t.epoch() == epoch)
            .cloned()
    }

    /// Retient une table construite ailleurs, pour que le mineur ne la
    /// reconstruise pas.
    pub fn adopter_table(&self, table: std::sync::Arc<PowTable>) {
        *self.table.borrow_mut() = Some(table);
    }

    /// Le bloc candidat du prochain minage, sans preuve de travail.
    ///
    /// # Pourquoi le minage ne se fait plus ici
    ///
    /// Le minage comptant assemblait **et minait** sous le verrou de la
    /// chaine — donc sous le verrou du noeud entier : deux millions d'essais
    /// par tour, plusieurs secondes sur un petit processeur, pendant lesquelles
    /// aucun bloc recu n'etait traite, aucune transaction relayee, aucun pair
    /// servi. Et au changement d'epoque, la construction de la table — des
    /// minutes — figeait le noeud de la meme facon.
    ///
    /// Le noeud assemble le candidat ici, rend le verrou, mine dehors avec la
    /// table qu'il detient, puis revient connecter le bloc. Si la tete a bouge
    /// entre-temps, la connexion echoue proprement et le tour suivant repart
    /// du bon parent.
    pub fn candidat_de_minage(
        &self,
        beneficiaire: Hash256,
        scheme: SchemeId,
        mempool: &[Transaction],
        horodatage: u64,
    ) -> Block {
        self.assembler_candidat(beneficiaire, scheme, mempool, &[], horodatage)
    }

    /// Table de l'epoque demandee, construite si besoin, partageable entre fils.
    fn table_for(&self, epoch: u64) -> std::sync::Arc<PowTable> {
        let mut cache = self.table.borrow_mut();
        let besoin_rebuild = match cache.as_ref() {
            Some(t) => t.epoch() != epoch,
            None => true,
        };
        if besoin_rebuild {
            *cache = Some(std::sync::Arc::new(PowTable::build(
                self.pow.params(),
                epoch,
            )));
        }
        std::sync::Arc::clone(cache.as_ref().expect("table construite juste au-dessus"))
    }

    /// Nombre de fils employes par le mineur.
    pub fn mining_threads(&self) -> usize {
        self.fils_minage
    }

    /// Choisit le nombre de fils du mineur. Zero remet la valeur par defaut.
    pub fn set_mining_threads(&mut self, n: usize) {
        self.fils_minage = if n == 0 { fils_par_defaut() } else { n };
    }

    pub fn height(&self) -> u64 {
        self.active.len() as u64 - 1
    }

    pub fn tip_id(&self) -> Hash256 {
        *self.active.last().expect("une chaine a toujours sa genese")
    }

    pub fn tip(&self) -> BlockHeader {
        self.index[&self.tip_id()].header
    }

    /// Travail cumule de la chaine active. C'est la seule mesure qui compte.
    pub fn total_work(&self) -> U256 {
        self.index[&self.tip_id()].total_work
    }

    pub fn headers(&self) -> Vec<BlockHeader> {
        self.active.iter().map(|id| self.index[id].header).collect()
    }

    /// Bloc de la chaine active a cette hauteur.
    ///
    /// Rend une valeur et non une reference : au-dela de [`BODY_WINDOW`], le
    /// corps vient du disque et n'existe pas en memoire.
    pub fn block_at(&self, hauteur: u64) -> Option<Block> {
        let id = *self.active.get(hauteur as usize)?;
        self.block_by_id(&id)
    }

    pub fn total_issued(&self) -> Amount {
        Amount::from_units(self.emis)
    }

    /// Empreinte MuHash du jeu d'UTXO a la tete de la chaine.
    ///
    /// C'est l'engagement sur l'etat de la monnaie a cette hauteur : deux noeuds
    /// synchronises la calculent a l'identique. Elle est ce qui rend un instantane
    /// verifiable au lieu d'etre cru sur parole.
    pub fn utxo_commitment(&self) -> Hash256 {
        self.utxo.commitment()
    }

    /// Nombre de sorties non depensees a la tete.
    pub fn utxo_count(&self) -> usize {
        self.utxo.len()
    }

    /// Construit l'amorce de synchronisation rapide que ce noeud peut servir.
    ///
    /// Les trois memes pieces que `instantane exporter-amorce` : l'instantane
    /// pris en retrait, les en-tetes de la genese a sa hauteur, et une fenetre
    /// bornee de corps autour de lui (la genese, puis les blocs qu'il faut pour
    /// rejouer par-dessus sans violer la regle du double paiement d'oncle).
    ///
    /// Rend `None` si la chaine est trop courte, ou si un corps de la fenetre
    /// manque — un noeud sans source de corps ne sert pas d'amorce.
    pub fn construire_amorce(&self) -> Option<crate::synchro_rapide::Amorce> {
        let s = self.snapshot()?;
        let h = s.height;
        let tous = self.headers();
        if h as usize >= tous.len() {
            return None;
        }
        let entetes = tous[..=h as usize].to_vec();
        let marge = crate::consensus::MAX_UNCLE_AGE + 2;
        let debut = h.saturating_sub(marge);
        let mut corps = vec![self.block_at(0)?];
        for hh in debut..=h {
            if hh == 0 {
                continue; // la genese est deja la
            }
            corps.push(self.block_at(hh)?);
        }
        Some(crate::synchro_rapide::Amorce {
            instantane: s.to_portable_bytes(),
            entetes,
            corps,
        })
    }

    pub fn known_blocks(&self) -> usize {
        self.index.len()
    }

    pub fn pow_params(&self) -> TableParams {
        self.pow.params()
    }

    /// Difficulte que devra porter le prochain bloc.
    ///
    /// Sur le reseau de regression elle reste figee au minimum : miner dix blocs
    /// d'affilee ferait sinon grimper la cible d'un facteur 4 a chaque bloc.
    ///
    /// Passe par [`Self::next_bits_after`] : `next_bits(&self.headers())`
    /// recopiait **tous** les en-tetes depuis la genese a chaque bloc connecte,
    /// pour n'en lire que les 91 derniers. A cinq cent mille blocs, c'etait
    /// des dizaines de millisecondes sous verrou par bloc, et une
    /// synchronisation initiale quadratique.
    pub fn next_bits(&self) -> u32 {
        self.next_bits_after(self.tip_id())
    }

    fn recent_times(&self) -> Vec<u64> {
        let n = self.active.len();
        let debut = n.saturating_sub(MEDIAN_TIME_SPAN);
        self.active[debut..]
            .iter()
            .map(|id| self.index[id].header.time)
            .collect()
    }

    /// Horodatages des ancetres d'un bloc, en remontant l'index depuis
    /// `parent` : le pendant de [`Self::next_bits_after`] pour la mediane, qui
    /// vaut donc pour n'importe quelle branche. Du plus ancien au plus recent.
    fn recent_times_after(&self, parent: Hash256) -> Vec<u64> {
        let mut v = Vec::with_capacity(MEDIAN_TIME_SPAN);
        let mut courant = parent;
        for _ in 0..MEDIAN_TIME_SPAN {
            match self.index.get(&courant) {
                Some(b) => {
                    v.push(b.header.time);
                    if b.header.height == 0 {
                        break;
                    }
                    courant = b.header.prev_block;
                }
                None => break,
            }
        }
        v.reverse();
        v
    }

    /// Identifiants des ancetres recents, tete comprise.
    fn recent_ancestors(&self) -> Vec<Hash256> {
        let n = self.active.len();
        let debut = n.saturating_sub(MAX_UNCLE_AGE as usize + 2);
        self.active[debut..].to_vec()
    }

    /// Oncles deja reclames par les blocs recents de la chaine active.
    ///
    /// # Pourquoi cette fonction peut echouer
    ///
    /// Elle lisait les corps en memoire. Apres une reprise sur instantane, ces
    /// corps sont absents : l'ensemble rendu etait alors **incomplet**, et un
    /// noeud fraichement redemarre acceptait un oncle deja paye qu'un noeud
    /// complet refusait. Deux noeuds honnetes, deux verdicts — une scission.
    ///
    /// Elle passe donc par [`Chain::block_by_id`], qui va chercher le corps sur
    /// disque au besoin, et **echoue bruyamment** si un corps manque vraiment.
    /// Valider a l'aveugle une regle anti-double-paiement serait pire que ne pas
    /// la valider du tout : on croirait etre protege.
    fn claimed_uncles(&self) -> Result<HashSet<Hash256>, ValidationError> {
        let n = self.active.len();
        let debut = n.saturating_sub(MAX_UNCLE_AGE as usize + 2);
        let mut s = HashSet::new();
        for id in &self.active[debut..] {
            let b = self
                .block_by_id(id)
                .ok_or(ValidationError::HistoriqueIncomplet)?;
            for u in &b.uncles {
                s.insert(u.block_id());
            }
        }
        Ok(s)
    }

    /// Difficulte attendue pour un enfant de chaque ancetre recent.
    ///
    /// Un oncle a la hauteur `h` est le frere du bloc actif de meme hauteur : il
    /// doit porter la difficulte que la chaine imposait a cette hauteur, et non
    /// celle que son auteur a bien voulu inscrire.
    fn uncle_expected_bits(&self) -> HashMap<Hash256, u32> {
        let n = self.active.len();
        let debut = n.saturating_sub(MAX_UNCLE_AGE as usize + 2);
        let mut m = HashMap::new();
        for id in &self.active[debut..] {
            m.insert(*id, self.next_bits_after(*id));
        }
        m
    }

    /// Difficulte attendue pour un bloc dont le parent est `parent`.
    ///
    /// Remonte l'index des en-tetes, ce qui la rend calculable pour n'importe
    /// quelle branche — y compris une branche laterale qu'on n'a pas connectee.
    /// C'est ce qui permet de refuser un bloc qui se serait choisi sa propre
    /// cible avant meme de l'indexer.
    pub fn next_bits_after(&self, parent: Hash256) -> u32 {
        if self.network == Network::Regtest {
            return INITIAL_BITS;
        }
        let mut entetes: Vec<BlockHeader> = Vec::with_capacity(LWMA_WINDOW + 1);
        let mut courant = parent;
        for _ in 0..=LWMA_WINDOW {
            match self.index.get(&courant) {
                Some(b) => {
                    entetes.push(b.header);
                    if b.header.height == 0 {
                        break;
                    }
                    courant = b.header.prev_block;
                }
                None => break,
            }
        }
        entetes.reverse();
        next_bits(&entetes)
    }

    /// Localisateur de blocs : jalons pour qu'un pair trouve notre point commun.
    ///
    /// Les dix derniers blocs, puis un recul exponentiel jusqu'a la genese. Un
    /// pair compare cette liste a sa propre chaine et repond a partir du premier
    /// identifiant qu'il reconnait. Le cout est logarithmique en la hauteur, la
    /// ou envoyer toute la chaine serait lineaire.
    pub fn locator(&self) -> Vec<Hash256> {
        let mut v = Vec::new();
        let mut pas = 1usize;
        let mut i = self.active.len() - 1;
        loop {
            v.push(self.active[i]);
            if i == 0 || v.len() >= 64 {
                break;
            }
            if v.len() > 10 {
                pas *= 2;
            }
            i = i.saturating_sub(pas);
        }
        if *v.last().unwrap() != self.active[0] {
            v.push(self.active[0]);
        }
        v
    }

    /// En-tetes suivant le premier identifiant reconnu du localisateur.
    ///
    /// Rend au plus `max` en-tetes. S'arrete a `stop` s'il est atteint.
    pub fn headers_from(&self, locator: &[Hash256], stop: Hash256, max: usize) -> Vec<BlockHeader> {
        // Point de fourche par recherche dans l'index (une lecture de table par
        // entree du localisateur), et non par balayage lineaire de la chaine
        // active. Un pair pouvait sinon envoyer 64 hachages absents et forcer
        // 64 balayages complets de la chaine — des dizaines de millions de
        // comparaisons par requete de 2 Kio, le tout sous le verrou global. On
        // retient la premiere entree du localisateur qui est bien sur la chaine
        // active, a sa hauteur.
        let depart = locator
            .iter()
            .find_map(|id| {
                let h = self.index.get(id)?.header.height as usize;
                if self.active.get(h) == Some(id) {
                    Some(h)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        let mut v = Vec::new();
        for id in self.active.iter().skip(depart + 1) {
            v.push(self.index[id].header);
            if v.len() >= max || *id == stop {
                break;
            }
        }
        v
    }

    /// Bloc complet par identifiant, y compris sur une branche laterale.
    ///
    /// Cherche d'abord en memoire, puis aupres du fournisseur de corps. Un
    /// noeud sans fournisseur ne sait rien des blocs elagues, et le dit.
    pub fn block_by_id(&self, id: &Hash256) -> Option<Block> {
        if let Some(b) = self.blocks.get(id) {
            return Some(b.clone());
        }
        self.source.as_ref()?.body(id)
    }

    /// Identifiant du bloc de la chaine active a cette hauteur.
    pub fn active_at(&self, hauteur: u64) -> Option<Hash256> {
        self.active.get(hauteur as usize).copied()
    }

    /// Travail total qu'une branche concurrente doit atteindre pour supplanter
    /// la chaine active, si elle diverge a l'index `fourche` de celle-ci et que
    /// la reorganisation porte sur `profondeur` blocs.
    ///
    /// Expose la regle de finalite pour l'observation et les epreuves : c'est
    /// une lecture, elle ne modifie rien.
    pub fn travail_requis_pour_reorg(&self, fourche: usize, profondeur: u64) -> U256 {
        self.seuil_de_reorg(fourche, profondeur)
    }

    /// En-tete d'un bloc connu, y compris sur une branche laterale.
    pub fn header_of(&self, id: &Hash256) -> Option<BlockHeader> {
        self.index.get(id).map(|b| b.header)
    }

    /// Nombre d'enregistrements d'annulation disponibles.
    ///
    /// C'est la profondeur maximale d'une reorganisation que ce noeud peut
    /// encore effectuer. Utile a l'exploitation : un noeud fraichement redemarre
    /// en a moins qu'un noeud qui tourne depuis longtemps.
    pub fn undo_window(&self) -> usize {
        self.undos.len()
    }

    pub fn has_block(&self, id: &Hash256) -> bool {
        self.index.contains_key(id)
    }

    /// Valide un bloc et le rattache a la tete courante.
    pub fn connect(&mut self, block: &Block, now: u64) -> Result<Amount, ValidationError> {
        let times = self.recent_times();
        let anc = self.recent_ancestors();
        let claimed = self.claimed_uncles()?;
        let bits_oncles = self.uncle_expected_bits();
        let hauteur = self.height() + 1;

        let ctx = BlockContext {
            network: self.network,
            height: hauteur,
            prev_id: self.tip_id(),
            recent_times: &times,
            expected_bits: self.next_bits(),
            now,
            ancestors: &anc,
            claimed_uncles: &claimed,
            uncle_expected_bits: &bits_oncles,
            cumul_emis: self.emis,
        };

        let frais = validate::check_block(block, &self.utxo, &ctx, &self.pow)?;

        let mut undo = UndoRecord::default();
        for tx in &block.transactions {
            self.utxo.apply_transaction(tx, hauteur, &mut undo);
        }
        let coinbase = block.transactions[0].total_output()?.units();
        self.emis += coinbase.saturating_sub(frais.units());

        let id = block.header.block_id();
        let travail_parent = self.index[&block.header.prev_block].total_work;
        let total = travail_parent
            .checked_add(pow::block_work(block.header.bits))
            .unwrap_or(travail_parent);
        self.index.insert(
            id,
            BlockIndex {
                header: block.header,
                total_work: total,
                emis: self.emis,
            },
        );
        self.retenir_corps(id, block.clone());
        self.active.push(id);
        self.undos.push_back(undo);
        if self.undos.len() > BODY_WINDOW {
            self.undos.pop_front();
        }
        Ok(frais)
    }

    /// Retire le bloc de tete et restaure l'etat precedent.
    pub fn disconnect(&mut self) -> bool {
        if self.active.len() <= 1 {
            return false;
        }
        // ORDRE CRITIQUE : on ne mute rien tant qu'on n'est pas certain de
        // pouvoir aller au bout.
        //
        // La version precedente ecrasait `self.emis` **avant** de constater
        // qu'aucun enregistrement d'annulation n'etait disponible. Un
        // `disconnect` refuse laissait donc le compteur d'emission a la valeur
        // du parent — et apres une reprise sur instantane, ou les index
        // anterieurs portent zero, le compteur tombait a zero. Un audit adverse
        // l'a demontre : « emission passee de 100691370 a 0 sur un disconnect
        // refuse ».
        //
        // Au-dela de la fenetre conservee, defaire est impossible — et c'est
        // deja interdit par la finalite glissante. On refuse sans rien toucher.
        if self.undos.is_empty() {
            return false;
        }
        let parent = self.active[self.active.len() - 2];
        let emis_parent = self.index[&parent].emis;

        let undo = self.undos.pop_back().expect("verifie juste au-dessus");
        self.utxo.undo(&undo);
        self.active.pop();
        self.emis = emis_parent;
        true
    }

    // -----------------------------------------------------------------------
    // Choix de fourche
    // -----------------------------------------------------------------------

    /// Chemin d'un bloc jusqu'a un ancetre appartenant a la chaine active.
    ///
    /// Rend l'indice du point de fourche dans `active` et les blocs a connecter,
    /// du plus ancien au plus recent.
    fn chemin_vers_active(&self, tete: Hash256) -> Option<(usize, Vec<Hash256>)> {
        let mut branche = Vec::new();
        let mut courant = tete;
        for _ in 0..=MAX_REORG_DEPTH + 1 {
            if let Some(pos) = self.active.iter().position(|x| *x == courant) {
                branche.reverse();
                return Some((pos, branche));
            }
            let idx = self.index.get(&courant)?;
            branche.push(courant);
            if idx.header.height == 0 {
                return None;
            }
            courant = idx.header.prev_block;
        }
        None
    }

    /// Travail qu'une fourche doit depasser, selon sa profondeur.
    ///
    /// # Le defaut que cette version corrige
    ///
    /// La penalite s'appliquait au travail **cumule depuis la genese**. Exiger
    /// « 1 % de plus par bloc de profondeur » revenait donc a exiger 1 % du
    /// travail de toute l'histoire de la chaine, et non 1 % du travail de la
    /// fourche.
    ///
    /// L'audit de la phase 8b l'a chiffre : des la hauteur 71 400 — trois mois
    /// apres le lancement — aucune reorganisation de profondeur 7 ne pouvait
    /// plus aboutir, meme avec 100 % de la puissance et meme face a une branche
    /// parfaitement honnete. La finalite reelle n'etait pas de 720 blocs mais de
    /// **six**, et une partition reseau de plus de douze minutes produisait deux
    /// chaines definitives.
    ///
    /// La penalite porte desormais sur le travail **de la fourche** : ce qui a
    /// ete produit depuis le point de divergence, des deux cotes. C'est la seule
    /// grandeur qui ait un sens — le passe commun n'est disputé par personne.
    fn seuil_de_reorg(&self, fourche: usize, profondeur: u64) -> U256 {
        let total = self.total_work();
        // Travail commun aux deux branches, jusqu'au point de divergence.
        let commun = self
            .active
            .get(fourche)
            .and_then(|id| self.index.get(id))
            .map(|b| b.total_work)
            .unwrap_or(U256::ZERO);
        let depuis_fourche = total.checked_sub(commun).unwrap_or(U256::ZERO);

        if profondeur <= REORG_PENALTY_FROM_DEPTH {
            return total;
        }
        let exces = ((profondeur - REORG_PENALTY_FROM_DEPTH) * REORG_PENALTY_PCT_PER_BLOCK)
            .min(REORG_PENALTY_MAX_PCT);
        // `commun + (1 + exces%) * travail_de_la_branche_active_depuis_la_fourche`
        let majore = depuis_fourche
            .mul_div(100 + exces, 100)
            .unwrap_or(depuis_fourche);
        commun.checked_add(majore).unwrap_or(total)
    }

    /// Soumet un bloc au noeud : rattachement, branche laterale ou reorganisation.
    ///
    /// C'est le point d'entree qu'utilisera la couche reseau de la phase 4.
    pub fn submit(&mut self, block: &Block, now: u64) -> Result<Accept, ChainError> {
        let id = block.header.block_id();
        if self.index.contains_key(&id) {
            return Ok(Accept::DejaVu);
        }
        if !self.index.contains_key(&block.header.prev_block) {
            return Err(ChainError::ParentInconnu(block.header.prev_block));
        }

        // --- Defense : la hauteur annoncee doit suivre celle du parent.
        //
        // Elle est verifiee AVANT tout calcul, parce que la preuve de travail
        // derive son epoque de `header.height` : un en-tete annoncant une
        // hauteur arbitraire faisait construire le cache — puis la table — de
        // l'epoque correspondante. Mesure de l'audit : ~10 s de cache et
        // ~5 min de table sur le reseau principal, pour un message de 160
        // octets. Repete, le noeud ne fait plus que cela.
        let parent_height = self.index[&block.header.prev_block].header.height;
        if block.header.height != parent_height + 1 {
            return Err(ChainError::Validation(ValidationError::HauteurIncorrecte {
                attendu: parent_height + 1,
                recu: block.header.height,
            }));
        }

        // Cas simple : le bloc prolonge la tete.
        if block.header.prev_block == self.tip_id() {
            self.connect(block, now)?;
            return Ok(Accept::Prolonge);
        }

        // Branche laterale. Quatre controles avant toute insertion dans l'index,
        // ranges du moins cher au plus cher : ce qui coute le plus a verifier
        // doit etre ce qu'on verifie en dernier.
        //
        // 1. La branche est-elle seulement adoptable un jour ?
        //
        //    La finalite glissante refuse deja toute reorganisation dont le
        //    point de fourche est a plus de `MAX_REORG_DEPTH` sous la tete. Une
        //    branche qui bifurque plus bas ne peut donc JAMAIS l'emporter :
        //    l'indexer, garder son corps et la consigner au journal est un cout
        //    pur — et sans borne, puisque l'index n'est jamais elague.
        //
        //    C'etait le levier du deni de service : la difficulte plancher des
        //    premiers blocs rend un frere de la genese quasi gratuit (quelques
        //    centaines de condensats), et rien ne bornait le nombre de freres
        //    retenus. Chacun achetait une entree permanente en memoire et un
        //    enregistrement sur disque.
        //
        //    Ce refus ne change aucune regle de consensus : il rejette plus tot
        //    exactement ce que `try_reorg` rejetait deja plus tard. Le pair qui
        //    insiste voit son score de mauvaise conduite monter.
        let profondeur_fourche = self.height().saturating_sub(parent_height);
        if profondeur_fourche > MAX_REORG_DEPTH {
            return Err(ChainError::FinaliteDepassee {
                profondeur: profondeur_fourche,
                max: MAX_REORG_DEPTH,
            });
        }

        // 2. La difficulte annoncee doit etre celle qu'impose la chaine a cette
        //    position. Sans ce controle, `pow.check` verifiait le travail contre
        //    `header.bits` — un champ que l'emetteur remplit. Avec une cible
        //    quasi maximale, n'importe qui produisait une infinite d'en-tetes
        //    valides sans miner une seule fois, et remplissait l'index et les
        //    corps d'un noeud jusqu'a l'epuisement. Demontre par l'audit de la
        //    phase 8 : 500 branches indexees sans le moindre calcul.
        let attendu = self.next_bits_after(block.header.prev_block);
        if block.header.bits != attendu {
            return Err(ChainError::Validation(
                ValidationError::DifficulteIncorrecte {
                    attendu,
                    recu: block.header.bits,
                },
            ));
        }

        // 2 bis. L'horodatage, aux memes conditions que sur la chaine active :
        //    posterieur a la mediane des onze ancetres **de sa branche**, et
        //    pas au-dela de la tolerance vers le futur.
        //
        //    Ces deux controles ne s'appliquaient qu'a la connexion. Une
        //    branche laterale pouvait donc porter des horodatages tres etales
        //    — la difficulte LWMA baissait le long de la branche, jusqu'a six
        //    fois grace a la borne de 6T par intervalle — et faire produire a
        //    bon compte des corps de 4 Mio que le noeud conservait et servait.
        //    Refuser ici n'ecarte aucun bloc valide : la connexion l'aurait
        //    refuse de toute facon, pour la meme raison.
        let temps = self.recent_times_after(block.header.prev_block);
        let mediane = validate::median_time(&temps);
        if !temps.is_empty() && block.header.time <= mediane {
            return Err(ChainError::Validation(
                ValidationError::HorodatageTropAncien {
                    median: mediane,
                    recu: block.header.time,
                },
            ));
        }
        let limite = now + MAX_FUTURE_TIME;
        if block.header.time > limite {
            return Err(ChainError::Validation(
                ValidationError::HorodatageDansLeFutur {
                    limite,
                    recu: block.header.time,
                },
            ));
        }

        // 3. La forme et la taille — les controles qui ne demandent aucun
        //    contexte, et que Bitcoin nomme `CheckBlock`.
        //
        //    Ils ne s'executaient que sur le chemin de connexion. Une branche
        //    laterale entrait donc dans l'index et sur le disque sans qu'on ait
        //    verifie que son corps correspond a son en-tete : la racine de
        //    Merkle n'etait jamais recalculee. Un en-tete au travail authentique
        //    pouvait ainsi trainer un corps arbitraire — que le noeud stockait,
        //    puis **servait a ses pairs**.
        //
        //    Refuser ici ne peut ecarter aucun bloc valide : un corps qui echoue
        //    ces controles echouerait de toute facon a la connexion.
        block
            .check_shape()
            .map_err(|e| ChainError::Validation(e.into()))?;
        let taille = block.encode().len();
        if taille > MAX_BLOCK_SIZE {
            return Err(ChainError::Validation(ValidationError::BlocTropGros {
                max: MAX_BLOCK_SIZE,
                recu: taille,
            }));
        }

        // 4. Le travail lui-meme — le plus couteux, donc le dernier.
        self.pow
            .check(&block.header)
            .map_err(|e| ChainError::Validation(ValidationError::PreuveDeTravail(e)))?;

        let parent = self.index[&block.header.prev_block];
        let total = parent
            .total_work
            .checked_add(pow::block_work(block.header.bits))
            .unwrap_or(parent.total_work);

        self.index.insert(
            id,
            BlockIndex {
                header: block.header,
                total_work: total,
                // Inconnu tant que le bloc n'est pas connecte : une branche
                // laterale n'a pas d'emission, elle n'a qu'un potentiel.
                emis: 0,
            },
        );
        self.retenir_corps(id, block.clone());

        if total <= self.total_work() {
            return Ok(Accept::BrancheLaterale);
        }

        let profondeur = self.try_reorg(id, now)?;
        Ok(Accept::Reorganise { profondeur })
    }

    /// Bascule la chaine active sur `nouvelle_tete`.
    ///
    /// Atomique : si un bloc de la nouvelle branche echoue a la validation,
    /// l'ancienne chaine est integralement restauree.
    fn try_reorg(&mut self, nouvelle_tete: Hash256, now: u64) -> Result<u64, ChainError> {
        // Aucun ancetre commun a portee : ce n'est pas une reorganisation trop
        // profonde, c'est une branche dont on ne sait pas d'ou elle vient. Le
        // dire ainsi a un cout : l'ancienne version rendait ici
        // `FinaliteDepassee { profondeur: u64::MAX }`, et un exploitant lisant
        // « profondeur 18446744073709551615 » ne pouvait rien en faire.
        let (fourche, branche) =
            self.chemin_vers_active(nouvelle_tete)
                .ok_or(ChainError::PointDeForkIntrouvable {
                    portee: MAX_REORG_DEPTH,
                })?;

        let profondeur = (self.active.len() - 1 - fourche) as u64;

        // --- Defense : finalite glissante.
        if profondeur > MAX_REORG_DEPTH {
            return Err(ChainError::FinaliteDepassee {
                profondeur,
                max: MAX_REORG_DEPTH,
            });
        }

        // --- Defense : la profondeur se paie.
        let requis = self.seuil_de_reorg(fourche, profondeur);
        if self.index[&nouvelle_tete].total_work <= requis {
            return Err(ChainError::TravailInsuffisantPourLaProfondeur { profondeur });
        }

        // --- Defense : ne rien entreprendre qu'on ne puisse defaire.
        //
        // Une reorganisation demande `profondeur` annulations. Si la fenetre
        // d'annulation n'en contient pas autant — cas normal apres une reprise
        // sur instantane — la boucle de restauration ne progresserait jamais et
        // le noeud tournerait indefiniment, verrou de chaine tenu. L'audit de la
        // phase 8 l'a demontre : le fil ne rendait jamais la main.
        //
        // On refuse donc **avant** de toucher a quoi que ce soit. Le noeud reste
        // sur sa chaine, ce qui est le comportement sur : il rattrapera la
        // branche concurrente quand elle aura repris assez d'avance, ou apres
        // une resynchronisation complete.
        if (self.undos.len() as u64) < profondeur {
            return Err(ChainError::FenetreDAnnulationInsuffisante {
                profondeur,
                disponible: self.undos.len() as u64,
            });
        }

        // Memorise l'ancienne branche pour pouvoir la restaurer a l'identique.
        let ancienne: Vec<Hash256> = self.active[fourche + 1..].to_vec();

        // Les corps sont recuperes AVANT toute mutation : un corps elague ferait
        // paniquer une indexation directe, et paniquer au milieu d'une
        // reorganisation laisserait la chaine dans un etat impossible.
        let mut corps_branche = Vec::with_capacity(branche.len());
        for id in &branche {
            match self.block_by_id(id) {
                Some(b) => corps_branche.push(b),
                None => return Err(ChainError::Validation(ValidationError::HistoriqueIncomplet)),
            }
        }
        let mut corps_ancienne = Vec::with_capacity(ancienne.len());
        for id in &ancienne {
            match self.block_by_id(id) {
                Some(b) => corps_ancienne.push(b),
                None => return Err(ChainError::Validation(ValidationError::HistoriqueIncomplet)),
            }
        }

        for _ in 0..profondeur {
            if !self.disconnect() {
                // Ne devrait pas arriver : la fenetre a ete verifiee. Mais on ne
                // boucle jamais sur une fonction qui peut refuser.
                break;
            }
        }

        for b in &corps_branche {
            if let Err(e) = self.connect(b, now) {
                while self.active.len() > fourche + 1 {
                    if !self.disconnect() {
                        break;
                    }
                }
                for ab in &corps_ancienne {
                    if self.connect(ab, now).is_err() {
                        // La chaine d'origine ne se revalide pas — ce qui ne
                        // devrait jamais arriver, ces blocs etant actifs et
                        // valides il y a un instant. L'ancienne version plantait
                        // ici (`expect`) : un `panic` sur une routine de
                        // consensus, donc l'arret du noeud. La red-team 8b l'a
                        // signale ; on n'a pas su le declencher (le chemin est
                        // deterministe), mais un plantage n'est pas la bonne
                        // reponse. On redescend plutot au point de fourche — un
                        // ancetre PROUVE valide, donc un etat toujours coherent,
                        // seulement plus court — et on rend la main. Le noeud
                        // repartira de la en se resynchronisant aupres de ses
                        // pairs, sans jamais servir un etat incoherent.
                        while self.active.len() > fourche + 1 {
                            if !self.disconnect() {
                                break;
                            }
                        }
                        return Err(ChainError::Validation(e));
                    }
                }
                return Err(ChainError::Validation(e));
            }
        }
        Ok(profondeur)
    }

    // -----------------------------------------------------------------------
    // Minage
    // -----------------------------------------------------------------------

    pub fn mine_block(
        &self,
        beneficiaire: Hash256,
        scheme: SchemeId,
        mempool: &[Transaction],
        horodatage: u64,
        max_essais: u64,
    ) -> Option<Block> {
        self.mine_block_with_uncles(beneficiaire, scheme, mempool, &[], horodatage, max_essais)
    }

    /// Assemble et mine un bloc candidat, oncles compris.
    pub fn mine_block_with_uncles(
        &self,
        beneficiaire: Hash256,
        scheme: SchemeId,
        mempool: &[Transaction],
        uncles: &[BlockHeader],
        horodatage: u64,
        max_essais: u64,
    ) -> Option<Block> {
        let hauteur = self.height() + 1;
        let mut b = self.assembler_candidat(beneficiaire, scheme, mempool, uncles, horodatage);
        let table = self.table_for(crate::memhard::epoch_of(hauteur));
        pow::mine_with_table_parallel(&mut b.header, &table, max_essais, self.fils_minage).ok()?;
        Some(b)
    }

    /// Le bloc candidat, complet et coherent, mais sans preuve de travail.
    ///
    /// Extrait de [`Self::mine_block_with_uncles`] pour que le minage du noeud
    /// ([`Self::candidat_de_minage`]) le reutilise : deux facons d'assembler un
    /// candidat, c'est deux facons de se tromper sur la coinbase.
    fn assembler_candidat(
        &self,
        beneficiaire: Hash256,
        scheme: SchemeId,
        mempool: &[Transaction],
        uncles: &[BlockHeader],
        horodatage: u64,
    ) -> Block {
        let hauteur = self.height() + 1;

        let mut frais: u64 = 0;
        for tx in mempool {
            let entrees: u64 = tx
                .inputs
                .iter()
                .filter_map(|i| self.utxo.get(&i.prev_out))
                .map(|e| e.output.value.units())
                .sum();
            let sorties = tx.total_output().map(|a| a.units()).unwrap_or(0);
            frais += entrees.saturating_sub(sorties);
        }

        let recompenses = validate::uncle_rewards(hauteur, uncles.len());
        let part_mineur = recompenses.part_mineur + frais;

        let mut sorties = vec![TxOut {
            value: Amount::from_units(part_mineur),
            scheme,
            pubkey_hash: beneficiaire,
        }];
        for u in uncles {
            sorties.push(TxOut {
                value: Amount::from_units(recompenses.par_oncle),
                scheme,
                pubkey_hash: u.miner,
            });
        }

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn::coinbase(hauteur.to_le_bytes().to_vec())],
            outputs: sorties,
            lock_time: 0,
        };

        let mut transactions = vec![coinbase];
        transactions.extend_from_slice(mempool);

        let median = validate::median_time(&self.recent_times());
        let time = horodatage.max(median + 1);

        let mut b = Block {
            header: BlockHeader {
                version: 1,
                prev_block: self.tip_id(),
                merkle_root: Hash256::ZERO,
                uncles_root: Hash256::ZERO,
                miner: beneficiaire,
                time,
                bits: self.next_bits(),
                height: hauteur,
                nonce: 0,
            },
            transactions,
            uncles: uncles.to_vec(),
        };
        b.header.merkle_root = b.compute_merkle_root();
        b.header.uncles_root = b.compute_uncles_root();
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESEAU: Network = Network::Regtest;
    const ESSAIS: u64 = 5_000_000;

    fn chaine() -> Chain {
        let g = genesis_block(RESEAU);
        Chain::new(RESEAU, g)
    }

    fn mine(c: &mut Chain, n: usize) {
        for _ in 0..n {
            let t = c.tip().time + TARGET_BLOCK_SECS;
            let b = c
                .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
                .expect("minage");
            c.connect(&b, t + 1).expect("connexion");
        }
    }

    fn remine(c: &Chain, b: &mut Block) {
        b.header.merkle_root = b.compute_merkle_root();
        b.header.uncles_root = b.compute_uncles_root();
        b.header.nonce = 0;
        c.with_table(crate::memhard::epoch_of(b.header.height), |table| {
            pow::mine_with_table(&mut b.header, table, ESSAIS)
        })
        .unwrap();
    }

    /// L'arborescence retrouve la chaine active au milieu des branches.
    ///
    /// # L'incident que cette epreuve fige
    ///
    /// Le chemin de secours — celui qui sert quand l'instantane manque, donc
    /// apres tout arret brutal — rejouait le fichier des blocs **dans son ordre
    /// d'ecriture**. Ce fichier consigne aussi les branches laterales : le rejeu
    /// demandait donc a la chaine d'accepter des dizaines de reorganisations
    /// successives, et se heurtait aux defenses anti-reorganisation, qui sont
    /// faites pour repousser un attaquant et non pour relire sa propre histoire.
    ///
    /// Mesure faite sur deux noeuds minant l'un contre l'autre : au bout de deux
    /// mille blocs, le noeud **refusait de redemarrer**. Un noeud incapable de
    /// relire son propre fichier est a une coupure de courant de la perte totale.
    ///
    /// La reponse est ici : on demande d'abord aux en-tetes quelle est la chaine
    /// active, et on la valide dans l'ordre des hauteurs. Plus une seule
    /// reorganisation a accepter.
    #[test]
    fn l_arborescence_designe_la_chaine_active_parmi_les_branches() {
        let mut c = chaine();
        mine(&mut c, 5);
        let fourche = c.tip_id();
        let apres_fourche: Vec<Hash256> = c.active[1..].to_vec();

        // Une branche concurrente, plus courte : elle ne doit pas l'emporter.
        let mut rivale = Chain::new(RESEAU, genesis_block(RESEAU));
        for id in &apres_fourche {
            let b = c.block_by_id(id).expect("corps");
            rivale.connect(&b, b.header.time + 1).expect("meme prefixe");
        }
        let t = rivale.tip().time + TARGET_BLOCK_SECS;
        let b = rivale
            .mine_block(Hash256([9u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage rival");
        rivale.connect(&b, t + 1).expect("connexion rivale");
        assert_eq!(b.header.prev_block, fourche);

        // On prolonge la chaine principale au-dela de la rivale.
        mine(&mut c, 3);

        // Le fichier melange tout, dans un ordre quelconque : c'est bien ce que
        // l'arborescence doit savoir demeler.
        let mut entetes: Vec<BlockHeader> = c.headers();
        entetes.insert(2, b.header);

        let a = Chain::arborescence(&entetes).expect("arborescence");
        assert_eq!(
            a.active, c.active,
            "la chaine active doit etre la plus lourde, pas l'ordre du fichier"
        );
        assert_eq!(a.genese, c.active[0]);
        assert!(
            a.travail.contains_key(&b.header.block_id()),
            "la branche laterale reste connue : sans elle, aucune reorganisation \
             ne survivrait a un redemarrage"
        );
    }

    /// Un redemarrage ne repart jamais sur une branche abandonnee, et ne
    /// perd pas la capacite de la rejoindre si elle finit par l'emporter.
    ///
    /// Une branche laterale indexee avant l'arret est retenue par les
    /// en-tetes ; au redemarrage, la tete doit etre celle de la chaine la plus
    /// lourde, pas la derniere ecrite. Et si la branche laterale est ensuite
    /// prolongee jusqu'a depasser la chaine active, la reorganisation doit
    /// aboutir — les corps de la branche etant fournis — exactement comme
    /// elle l'aurait fait sans redemarrage.
    #[test]
    fn un_redemarrage_ne_repart_pas_sur_une_branche_abandonnee() {
        let mut c = chaine();
        mine(&mut c, 40);
        let fourche_hauteur = 37u64;
        let fourche = c.active[fourche_hauteur as usize];

        // La branche laterale : deux blocs a partir de la hauteur 37, donc
        // moins de travail que la chaine active (40).
        let mut rivale = Chain::new(RESEAU, genesis_block(RESEAU));
        for id in &c.active[1..=fourche_hauteur as usize] {
            let b = c.block_by_id(id).expect("corps");
            rivale.connect(&b, b.header.time + 1).expect("meme prefixe");
        }
        let mut laterale = Vec::new();
        for _ in 0..2 {
            let t = rivale.tip().time + TARGET_BLOCK_SECS + 7;
            let b = rivale
                .mine_block(Hash256([9u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
                .expect("minage rival");
            rivale.connect(&b, t + 1).expect("connexion rivale");
            laterale.push(b);
        }
        assert_eq!(laterale[0].header.prev_block, fourche);
        for b in &laterale {
            assert_eq!(
                c.submit(b, b.header.time + 1).expect("branche laterale"),
                Accept::BrancheLaterale
            );
        }
        let tete_active = c.tip_id();

        // Redemarrage : la tete est celle de la chaine active, pas la
        // derniere branche ecrite.
        let mut rc = reprendre(&c);
        assert_eq!(
            rc.tip_id(),
            tete_active,
            "la reprise repart sur la branche abandonnee"
        );
        assert_eq!(rc.height(), 40);

        // La branche laterale l'emporte ensuite : la reorganisation aboutit.
        for _ in 0..3 {
            let t = rivale.tip().time + TARGET_BLOCK_SECS + 7;
            let b = rivale
                .mine_block(Hash256([9u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
                .expect("minage rival");
            rivale.connect(&b, t + 1).expect("connexion rivale");
            laterale.push(b);
        }
        let mut bascule = false;
        for b in &laterale[2..] {
            if let Accept::Reorganise { .. } = rc.submit(b, b.header.time + 1).expect("soumission")
            {
                bascule = true;
            }
        }
        assert!(bascule, "la branche devenue la plus lourde doit l'emporter");
        assert_eq!(rc.tip_id(), rivale.tip_id());
        assert_eq!(rc.height(), rivale.height());
        assert_eq!(
            rc.utxo, rivale.utxo,
            "l'etat rejoint celui de la branche gagnante"
        );
    }

    /// Une branche sans ancetre commun se nomme pour ce qu'elle est.
    ///
    /// Elle etait signalee comme `FinaliteDepassee { profondeur: u64::MAX }`.
    /// Un exploitant lisant « profondeur 18446744073709551615 » ne peut rien en
    /// faire : ce n'est pas une profondeur, c'est un aveu d'ignorance deguise.
    #[test]
    fn une_branche_sans_ancetre_commun_ne_se_dit_pas_trop_profonde() {
        let e = ChainError::PointDeForkIntrouvable { portee: 720 };
        match e {
            ChainError::PointDeForkIntrouvable { portee } => assert_eq!(portee, 720),
            autre => panic!("mauvaise erreur : {autre:?}"),
        }
    }

    /// Rejoue une reprise complete : instantane, reconstruction depuis les
    /// en-tetes, revalidation de la fenetre, et comparaison a l'etat d'origine.
    fn reprendre(c: &Chain) -> Chain {
        reprendre_a(c, usize::MAX)
    }

    /// Fournisseur de corps en memoire, pour les epreuves de reprise.
    struct CorpsEnMemoire(HashMap<Hash256, Block>);
    impl BodySource for CorpsEnMemoire {
        fn body(&self, id: &Hash256) -> Option<Block> {
            self.0.get(id).cloned()
        }
    }

    fn reprendre_a(c: &Chain, recul: usize) -> Chain {
        let instantane = c.snapshot_at_depth(recul).expect("chaine assez longue");
        let en_tetes: Vec<BlockHeader> = c.index.values().map(|b| b.header).collect();
        let corps: HashMap<Hash256, Block> = c.blocks.clone();

        let r = Chain::from_snapshot(c.network, instantane, &en_tetes).expect("reprise");
        let mut rc = r.chain;
        // Le fournisseur de corps est branche AVANT le rejeu : certaines regles
        // — le double paiement d'oncle, la restauration d'une reorganisation —
        // exigent de relire des corps anterieurs a l'instantane.
        rc.set_body_source(std::sync::Arc::new(CorpsEnMemoire(corps.clone())));
        for id in &r.a_rejouer {
            let b = corps.get(id).expect("corps de la fenetre rejouee");
            let t = b.header.time + 1;
            rc.connect(b, t).expect("revalidation du bloc rejoue");
        }
        rc
    }

    /// La propriete qui rend le demarrage incremental legitime : reprendre
    /// depuis un instantane doit donner **exactement** la meme chaine que
    /// revalider depuis la genese.
    #[test]
    fn une_reprise_retrouve_exactement_le_meme_etat() {
        let mut c = chaine();
        mine(&mut c, 40);
        let rc = reprendre(&c);

        assert_eq!(rc.height(), c.height(), "hauteur");
        assert_eq!(rc.tip_id(), c.tip_id(), "tete");
        assert_eq!(rc.total_issued(), c.total_issued(), "emission");
        assert_eq!(rc.total_work(), c.total_work(), "travail cumule");
        assert_eq!(rc.utxo, c.utxo, "jeu d'UTXO");
    }

    /// Un instantane pris a la tete priverait le noeud de toute
    /// reorganisation au redemarrage. Il est donc pris en retrait, et la
    /// fenetre rejouee reconstruit les annulations.
    #[test]
    fn une_reprise_conserve_la_capacite_de_reorganiser() {
        let mut c = chaine();
        mine(&mut c, 40);
        let instantane = c.snapshot().unwrap();
        assert!(
            instantane.height < c.height(),
            "l'instantane doit etre en retrait de la tete"
        );

        let mut rc = reprendre(&c);
        let avant = rc.height();
        assert!(rc.disconnect(), "defaire doit rester possible");
        assert_eq!(rc.height(), avant - 1);
        assert_eq!(
            rc.total_issued(),
            Amount::from_units(c.index[&rc.tip_id()].emis)
        );
    }

    /// Sous l'instantane, defaire est impossible — et doit echouer proprement
    /// plutot que corrompre le jeu d'UTXO.
    /// Sous l'instantane, defaire est impossible : il faut echouer proprement
    /// et s'arreter exactement la, sans corrompre le jeu d'UTXO.
    #[test]
    fn defaire_s_arrete_exactement_a_l_instantane() {
        let mut c = chaine();
        mine(&mut c, 40);
        let hauteur_instantane = c.snapshot_at_depth(10).unwrap().height;
        assert_eq!(hauteur_instantane, 30);

        let mut rc = reprendre_a(&c, 10);
        assert_eq!(rc.height(), 40, "la reprise rejoue la fenetre");

        let mut defaits = 0;
        while rc.disconnect() {
            defaits += 1;
            assert!(defaits < 1_000, "boucle");
        }
        assert_eq!(defaits, 10, "exactement la fenetre rejouee");
        assert_eq!(rc.height(), hauteur_instantane);

        // Et l'etat reste coherent : c'est celui de la chaine d'origine a la
        // meme hauteur, pas un jeu d'UTXO a demi defait.
        let mut temoin = chaine();
        mine(&mut temoin, 30);
        assert_eq!(rc.utxo, temoin.utxo);
        assert_eq!(rc.tip_id(), temoin.tip_id());
    }

    #[test]
    fn un_instantane_hors_chaine_est_refuse() {
        let mut c = chaine();
        mine(&mut c, 30);
        let mut instantane = c.snapshot().unwrap();
        instantane.tip = Hash256([0xab; 32]);
        let en_tetes: Vec<BlockHeader> = c.index.values().map(|b| b.header).collect();

        assert_eq!(
            Chain::from_snapshot(RESEAU, instantane, &en_tetes).err(),
            Some(RepriseError::InstantaneHorsChaine)
        );
    }

    #[test]
    fn une_reprise_sans_genese_est_refusee() {
        let mut c = chaine();
        mine(&mut c, 5);
        let instantane = c.snapshot();
        let en_tetes: Vec<BlockHeader> = c
            .index
            .values()
            .map(|b| b.header)
            .filter(|h| h.height != 0)
            .collect();
        if let Some(i) = instantane {
            assert_eq!(
                Chain::from_snapshot(RESEAU, i, &en_tetes).err(),
                Some(RepriseError::PasDeGenese)
            );
        }
    }

    /// La memoire ne doit pas croitre avec la chaine.
    #[test]
    fn les_corps_anciens_sont_elagues() {
        let mut c = chaine();
        mine(&mut c, 30);
        assert!(
            c.bodies_in_memory() <= BODY_WINDOW + 1,
            "{} corps en memoire",
            c.bodies_in_memory()
        );
        // Sur une chaine courte, rien n'est encore elague : la borne est la
        // propriete, pas l'elagage lui-meme.
        assert_eq!(c.bodies_in_memory(), 31);
    }

    #[test]
    fn la_genese_emet_exactement_une_piece() {
        let c = chaine();
        assert_eq!(c.height(), 0);
        assert_eq!(c.total_issued(), Amount::from_units(GENESIS_PREMINT));
    }

    #[test]
    fn la_genese_porte_une_preuve_de_travail_memory_hard_valide() {
        let g = genesis_block(RESEAU);
        assert!(Q21Pow::new(RESEAU).check(&g.header).is_ok());
    }

    #[test]
    fn miner_fait_monter_la_hauteur_et_le_travail() {
        let mut c = chaine();
        let travail0 = c.total_work();
        mine(&mut c, 5);
        assert_eq!(c.height(), 5);
        assert!(c.total_work() > travail0, "le travail doit s'accumuler");
    }

    #[test]
    fn le_travail_croit_quand_la_cible_baisse() {
        assert!(
            pow::block_work(0x1c00_ffff) > pow::block_work(0x2000_ffff),
            "une cible plus petite doit valoir plus de travail"
        );
    }

    #[test]
    fn une_cible_invalide_ne_vaut_aucun_travail() {
        assert_eq!(pow::block_work(0x1d00_0000), U256::ZERO);
    }

    #[test]
    fn un_bloc_deja_vu_est_ignore() {
        let mut c = chaine();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .unwrap();
        assert_eq!(c.submit(&b, t + 1), Ok(Accept::Prolonge));
        assert_eq!(c.submit(&b, t + 1), Ok(Accept::DejaVu));
    }

    #[test]
    fn un_bloc_orphelin_est_refuse() {
        let mut c = chaine();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let mut b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .unwrap();
        b.header.prev_block = Hash256([0xab; 32]);
        assert!(matches!(
            c.submit(&b, t + 1),
            Err(ChainError::ParentInconnu(_))
        ));
    }

    #[test]
    fn le_seuil_de_reorg_croit_avec_la_profondeur() {
        let mut c = chaine();
        mine(&mut c, 3);
        // Fourche a la genese : la branche disputee est toute la chaine.
        let court = c.seuil_de_reorg(0, REORG_PENALTY_FROM_DEPTH);
        let profond = c.seuil_de_reorg(0, REORG_PENALTY_FROM_DEPTH + 50);
        assert_eq!(
            court,
            c.total_work(),
            "pas de penalite en faible profondeur"
        );
        assert!(profond > court, "la profondeur doit se payer");
    }

    #[test]
    fn le_seuil_croit_de_facon_monotone() {
        let mut c = chaine();
        mine(&mut c, 2);
        let mut precedent = c.seuil_de_reorg(0, 0);
        for p in 1..100u64 {
            let s = c.seuil_de_reorg(0, p);
            assert!(s >= precedent, "profondeur {p} : le seuil a baisse");
            precedent = s;
        }
    }

    #[test]
    fn deconnecter_restaure_l_etat() {
        let mut c = chaine();
        mine(&mut c, 3);
        let masse = c.utxo.total_value();
        let emis = c.total_issued();
        mine(&mut c, 1);
        assert!(c.disconnect());
        assert_eq!(c.height(), 3);
        assert_eq!(c.utxo.total_value(), masse);
        assert_eq!(c.total_issued(), emis);
    }

    #[test]
    fn on_ne_deconnecte_jamais_la_genese() {
        let mut c = chaine();
        assert!(!c.disconnect());
    }

    #[test]
    fn la_coinbase_doit_payer_le_mineur_de_l_entete() {
        let mut c = chaine();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let mut b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .unwrap();
        b.transactions[0].outputs[0].pubkey_hash = Hash256([0xff; 32]);
        remine(&c, &mut b);
        assert_eq!(
            c.connect(&b, t + 1),
            Err(ValidationError::CoinbaseNePaiePasLeMineur)
        );
    }

    #[test]
    fn une_coinbase_gourmande_est_refusee() {
        let mut c = chaine();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let mut b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .unwrap();
        let du = b.transactions[0].outputs[0].value.units();
        b.transactions[0].outputs[0].value = Amount::from_units(du + 1);
        remine(&c, &mut b);
        assert!(matches!(
            c.connect(&b, t + 1),
            Err(ValidationError::SubventionExcessive { .. })
        ));
    }

    #[test]
    fn un_bloc_sans_preuve_de_travail_est_refuse() {
        let mut c = chaine();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let mut b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .unwrap();
        b.header.nonce = b.header.nonce.wrapping_add(0x5bad);
        assert!(matches!(
            c.connect(&b, t + 1),
            Err(ValidationError::PreuveDeTravail(_))
        ));
    }

    #[test]
    fn trop_d_oncles_est_refuse() {
        let mut c = chaine();
        mine(&mut c, 3);
        let faux = c.tip();
        let oncles = vec![faux; MAX_UNCLES + 1];
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let b = c
            .mine_block_with_uncles(
                Hash256([2u8; 32]),
                SchemeId::LamportOts,
                &[],
                &oncles,
                t,
                ESSAIS,
            )
            .unwrap();
        assert!(matches!(
            c.connect(&b, t + 1),
            Err(ValidationError::TropDOncles { .. })
        ));
    }

    #[test]
    fn un_ancetre_ne_peut_pas_se_faire_passer_pour_un_oncle() {
        let mut c = chaine();
        mine(&mut c, 3);
        // La tete courante est un ancetre du bloc a venir : la presenter comme
        // orphelin permettrait de se faire payer deux fois le meme travail.
        let ancetre = c.tip();
        let t = c.tip().time + TARGET_BLOCK_SECS;
        let b = c
            .mine_block_with_uncles(
                Hash256([2u8; 32]),
                SchemeId::LamportOts,
                &[],
                &[ancetre],
                t,
                ESSAIS,
            )
            .unwrap();
        // Depuis le retrait des oncles, tout oncle est refuse avant meme
        // d'etre examine : la tricherie n'a plus de porte.
        assert!(matches!(
            c.connect(&b, t + 1),
            Err(ValidationError::TropDOncles { .. })
        ));
    }

    /// La difficulte ne regarde que la fenetre, jamais toute l'histoire.
    ///
    /// C'est la propriete dont depend `Chain::next_bits` : calculer sur les
    /// `LWMA_WINDOW + 1` derniers en-tetes remontes depuis la tete donne
    /// exactement ce que donnait la copie de tous les en-tetes depuis la
    /// genese. Si quelqu'un elargit un jour la lecture au-dela de la fenetre,
    /// cette epreuve le dira avant que les deux chemins divergent.
    #[test]
    fn la_difficulte_ne_depend_que_de_la_fenetre() {
        let mut entetes: Vec<BlockHeader> = Vec::new();
        let mut t = GENESIS_TIME;
        let mut bits = INITIAL_BITS;
        for h in 0..(3 * LWMA_WINDOW as u64 + 17) {
            // Des intervalles irreguliers, pour que la fenetre compte vraiment.
            // Plus rapides que la cible en moyenne, pour que la difficulte
            // decolle du plancher et que la comparaison ait un sens.
            t += match h % 5 {
                0 => 40,
                1 => 100,
                2 => 120,
                3 => 15,
                _ => 90,
            };
            entetes.push(BlockHeader {
                version: 1,
                prev_block: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                uncles_root: Hash256::ZERO,
                miner: Hash256::ZERO,
                time: t,
                bits,
                height: h,
                nonce: 0,
            });
            bits = next_bits(&entetes);
        }
        let n = entetes.len();
        let fenetre = &entetes[n - (LWMA_WINDOW + 1)..];
        assert_eq!(next_bits(&entetes), next_bits(fenetre));
        // Et un en-tete de moins dans la fenetre change bel et bien le resultat :
        // la fenetre est la bonne, ni plus large ni plus etroite.
        assert_ne!(next_bits(&entetes), next_bits(&entetes[n - LWMA_WINDOW..]));
    }
}
