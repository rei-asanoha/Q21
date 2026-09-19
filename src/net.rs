//! Couche pair-a-pair.
//!
//! TCP nu, `std::net`, un fil par pair. Pas de bibliotheque reseau : sur du code
//! qui recoit des octets d'inconnus, chaque dependance est une surface d'attaque
//! qu'on n'a pas relue.
//!
//! # Le modele de fils, et pourquoi il ne peut pas se bloquer
//!
//! Un fil accepte les connexions entrantes, un fil lit chaque pair. L'etat
//! partage — chaine, mempool, table des pairs — vit derriere un unique verrou.
//!
//! La regle qui evite l'interblocage tient en une phrase : **on ne tient jamais
//! le verrou pendant une ecriture reseau.** Chaque gestionnaire calcule sous
//! verrou la liste des reponses a emettre, relache, puis emet. Un pair lent ne
//! peut donc pas geler le noeud entier en cessant de lire.
//!
//! # Ce que fait le relais compact ici
//!
//! Quand un bloc est accepte, on n'envoie pas cinq megaoctets a chaque pair : on
//! annonce le bloc compact, quelques kilooctets, et le pair ne redemande que ce
//! qui lui manque. C'est ce qui reduit la latence de propagation, donc le taux
//! d'orphelins, donc l'avantage super-lineaire des gros mineurs.

use crate::addr::AddrBook;
use crate::address::Network;
use crate::block::Block;
use crate::chain::{Accept, Chain};
use crate::compact::{CompactBlock, Reconstruction};
use crate::consensus::{NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_TESTNET};
use crate::hash::Hash256;
use crate::mempool::Mempool;
use crate::tx::Transaction;
use crate::wire::{
    InvItem, InvKind, Message, WireError, HEADER_LEN, MAX_PAYLOAD, MIN_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Score de bannissement au-dela duquel on coupe.
pub const BAN_THRESHOLD: u32 = 100;

/// Cout d'une trame illisible : un pair qui en envoie dix est coupe.
pub const MISCONDUCT_MALFORMED: u32 = 10;
/// Cout d'un bloc invalide : bien plus grave, c'est du travail gaspille.
pub const MISCONDUCT_BAD_BLOCK: u32 = 50;

/// Nombre maximal de pairs simultanes.
pub const MAX_PEERS: usize = 32;

/// Places que l'ecoute laisse toujours libres pour nos connexions sortantes.
///
/// Sans cette reserve, un flot d'entrantes remplissait les `MAX_PEERS` places
/// et le noeud ne pouvait plus appeler personne depuis son carnet — le
/// carnet anti-eclipse n'etait alors jamais consulte.
pub const PLACES_SORTANTES_RESERVEES: usize = 8;

/// Reconstructions de blocs compacts qu'un pair peut laisser en attente.
///
/// Sans borne, un pair annoncait des blocs compacts incomplets a la chaine
/// et ne repondait jamais a la demande des transactions manquantes : chaque
/// annonce restait en memoire, sans limite ni echeance. Une reconstruction en
/// vol par pair est ce que le protocole demande ; quatre laissent de la marge
/// a deux blocs trouves coup sur coup.
pub const RECONSTRUCTIONS_EN_ATTENTE_MAX: usize = 4;

/// Delai accorde a un pair pour livrer un corps de bloc qu'on lui a demande.
///
/// # Le defaut que ceci ferme
///
/// Les corps manquants etaient demandes au pair qui avait annonce les
/// en-tetes, et rien ne surveillait la reponse : un pair qui repondait aux
/// pings mais retenait les corps figeait la synchronisation pour toujours.
/// Passe ce delai, la demande est refaite a un autre pair et le retenteur
/// perd des points ; un noeud amorce par une unique adresse malveillante
/// finit au moins par la couper.
pub const DELAI_CORPS: Duration = Duration::from_secs(60);

/// Cout d'un corps demande et jamais livre. Deux suffisent a couper.
pub const MISCONDUCT_CORPS_RETENU: u32 = 50;

/// Corps de blocs qu'on accepte d'avoir demandes a un meme pair sans les
/// avoir encore recus.
///
/// # Le defaut que ceci ferme
///
/// La table des corps demandes n'avait pas de plafond : sa seule purge etait
/// temporelle, a [`DELAI_CORPS`]. Or les en-tetes qui font demander un corps
/// ne sont verifies qu'en **chainage**, pas en travail — les verifier en
/// travail sur deux mille en-tetes couterait plus que ce qu'on protege, la
/// preuve de Q21 etant a cout memoire. Fabriquer hors ligne une suite
/// d'en-tetes parfaitement chainee sur notre tete ne coute donc rien, et
/// chaque lot de deux mille faisait inscrire deux mille jetons de plus, sans
/// borne, pendant la minute que dure le delai de livraison.
///
/// La borne de surete de la synchronisation par en-tetes est donc ce plafond,
/// pas un controle de travail : quoi qu'un pair annonce, il ne nous fait
/// jamais demander plus de seize corps a la fois. Le reste attend dans une
/// file, elle-meme bornee ([`CORPS_EN_ATTENTE_MAX`]), et n'est demande qu'a
/// mesure que les corps arrivent. Seize suffisent a garder une liaison
/// occupee : un corps demande n'attend jamais le suivant pour partir.
pub const CORPS_EN_VOL_MAX: usize = 16;

/// Corps de blocs qu'un pair peut nous laisser a demander, en attendant qu'une
/// place en vol se libere.
///
/// Un lot d'en-tetes en contient au plus [`crate::wire::MAX_HEADERS`] ; la
/// file d'un pair est remplacee a chaque lot, et ne depasse donc jamais un
/// lot. Ce sont des identifiants, pas des en-tetes : soixante-quatre kibioctets
/// au plus par pair.
pub const CORPS_EN_ATTENTE_MAX: usize = crate::wire::MAX_HEADERS;

/// Annonces de blocs compacts non sollicitees qu'un pair peut pousser
/// d'emblee.
///
/// Un pair honnete n'annonce que ce qu'il vient d'accepter : quelques blocs
/// par minute au plus, et les corps que **nous** lui avons demandes ne sont pas
/// comptes ici. Huit laissent passer deux blocs trouves coup sur coup et une
/// petite reorganisation.
pub const CMPCT_SEAU_MAX: u64 = 8;

/// Debit soutenu d'annonces compactes non sollicitees accorde a un pair, par
/// seconde.
///
/// # Le defaut que ceci ferme
///
/// Une annonce compacte dont le parent est connu declenchait, **sous le verrou
/// global**, un balayage du reservoir avec un SipHash par transaction et une
/// allocation de la taille annoncee — jusqu'a soixante-cinq mille
/// emplacements — avant que la moindre verification ne la rejette. `tx` et
/// l'amorce avaient un seau ; les annonces compactes n'en avaient pas, et rien
/// ne sanctionnait un pair qui en poussait deux cents a la suite. Un bloc par
/// seconde en regime soutenu, c'est encore soixante fois la cadence du reseau.
pub const CMPCT_DEBIT_PAR_SEC: u64 = 1;

/// Cout d'une annonce compacte refusee : au-dela du seau, ou rejetee par la
/// reconstruction elle-meme (coinbase absente, indice hors du bloc, nombre
/// absurde de transactions — des formes que seul l'emetteur a pu produire).
/// Dix suffisent a couper, comme pour les trames illisibles.
pub const MISCONDUCT_CMPCT_REFUSE: u32 = 10;

/// Connexions entrantes admises depuis un meme groupe reseau (/16 en IPv4,
/// /64 en IPv6 — voir [`groupe_entrant`]).
///
/// Une seule adresse pouvait occuper les trente-deux places ; quatre par
/// groupe laissent une machine ou un petit reseau entrer plusieurs fois, sans
/// qu'une seule plage puisse fermer la porte aux autres.
pub const ENTRANTS_PAR_GROUPE: usize = 4;

/// Groupe reseau d'une connexion entrante, pour la diversite des places.
///
/// Deux familles, deux granularites : en IPv4 le `/16` du carnet, en IPv6 le
/// `/64` — c'est le prefixe qu'un hebergeur donne a une seule machine, donc
/// l'unite au-dessous de laquelle des adresses distinctes ne coutent rien.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupeReseau {
    V4([u8; 2]),
    V6([u8; 8]),
}

/// Groupe d'une adresse entrante, ou `None` si elle n'en a pas.
///
/// # Le defaut que ceci ferme
///
/// La diversite de groupe n'etait calculee que pour les adresses IPv4 : toute
/// connexion IPv6 tombait dans le cas « pas de groupe » et echappait a
/// [`ENTRANTS_PAR_GROUPE`]. Un seul `/64` — le lot de n'importe quel serveur
/// loue — pouvait alors occuper toutes les places entrantes, pour peu que le
/// noeud ecoute en IPv6. Le `/64` est la reponse : c'est l'equivalent admis
/// du `/16` v4.
///
/// Une adresse IPv4 presentee sous sa forme IPv6 (`::ffff:a.b.c.d`, ce que
/// donne une ecoute sur `[::]`) est rangee avec les IPv4 : la traiter comme un
/// `/64` mettrait tout l'Internet v4 dans un seul groupe.
///
/// La boucle locale n'est pas un groupe : plusieurs noeuds d'une meme machine
/// (regtest, epreuves) ne s'eclipsent pas entre eux.
pub fn groupe_entrant(adresse: SocketAddr) -> Option<GroupeReseau> {
    match adresse {
        SocketAddr::V4(a) if !a.ip().is_loopback() => {
            Some(GroupeReseau::V4(crate::addr::groupe(a.ip().octets())))
        }
        SocketAddr::V4(_) => None,
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) if v4.is_loopback() => None,
            Some(v4) => Some(GroupeReseau::V4(crate::addr::groupe(v4.octets()))),
            None if a.ip().is_loopback() => None,
            None => {
                let o = a.ip().octets();
                let mut prefixe = [0u8; 8];
                prefixe.copy_from_slice(&o[..8]);
                Some(GroupeReseau::V6(prefixe))
            }
        },
    }
}

/// Delai de lecture. Un pair muet finit par etre libere.
pub const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Silence apres lequel on demande au pair de se manifester.
///
/// Assez court pour qu'un portable qui se reveille retrouve le reseau en moins
/// d'une minute, assez long pour ne pas bavarder sur une liaison lente.
pub const PING_APRES: Duration = Duration::from_secs(45);

/// Silence apres lequel on considere le pair mort et on libere sa place.
///
/// Compte a partir de la derniere trame recue, pas du `Ping` envoye : un pair
/// qui repond a autre chose reste vivant.
pub const SILENCE_MAX: Duration = Duration::from_secs(100);

/// Delai maximal pour terminer la poignee de main.
///
/// Une connexion entrante qui ne s'est pas presentee — `Version` **puis**
/// `VerAck` — dans ce delai est fermee.
///
/// # Le defaut que ce delai ferme
///
/// Le seul controle de vie etait le silence depuis la derniere trame, et
/// **toute** trame rafraichit ce repere, y compris un `Ping` recu avant la
/// poignee de main (auquel on repond un `Pong` sans exiger la presentation).
/// Un attaquant pouvait donc ouvrir des connexions entrantes, envoyer un `Ping`
/// toutes les quarante secondes, et ne jamais se presenter : la connexion
/// restait « vivante » pour toujours, `handshaked` faux. Quelques groupes /16
/// suffisaient a occuper les vingt-quatre places entrantes et a fermer la porte
/// aux nouveaux venus honnetes — un deni de service sur l'accessibilite d'un
/// portier, trouve par la red-team de phase 8b. Une echeance de poignee de main
/// retire ces connexions inabouties, quelle que soit leur activite de surface.
pub const DELAI_POIGNEE_MAIN: Duration = Duration::from_secs(30);

/// Debit soutenu accorde a un pair pour le service d'amorce, en octets par
/// seconde.
pub const AMORCE_DEBIT_PAR_SEC: u64 = 2 * 1024 * 1024;

/// Reserve accordee d'emblee, en octets. Elle permet a un nouveau venu honnete
/// de demarrer sans attendre, tout en bornant ce qu'un pair peut extraire d'un
/// coup.
pub const AMORCE_SEAU_MAX: u64 = 8 * 1024 * 1024;

/// Cout d'une transaction invalide en soi — signature fausse, clef qui ne
/// correspond pas au verrou, forme incorrecte, valeur non conservee. Cinq
/// suffisent a couper : une transaction ainsi faite ne peut venir que d'un
/// pair qui la fabrique, jamais d'un relais honnete.
pub const MISCONDUCT_BAD_TX: u32 = 20;

/// Voir [`crate::validate::ValidationError::incapacite_locale`].
pub fn incapacite_locale(e: &crate::validate::ValidationError) -> Option<crate::sig::SchemeId> {
    e.incapacite_locale()
}

/// Le dit une fois par execution, pas a chaque bloc.
fn signaler_l_incapacite(schema: crate::sig::SchemeId) {
    static DEJA: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !DEJA.swap(true, Ordering::Relaxed) {
        eprintln!(
            "avertissement : un bloc porte des signatures {} que ce binaire ne sait pas \
             verifier (construit sans ML-DSA). Le pair n'est pas sanctionne et le bloc \
             n'est pas adopte. Reconstruisez : cargo build --release",
            schema.name()
        );
    }
}

/// Budget de verification qu'un pair peut consommer d'emblee, en signatures.
///
/// Le seau est desormais denomme en **verifications de signature**, pas en
/// transactions : c'est la verification qui coute, et une transaction en porte
/// autant que d'entrees. Le plafond couvre la plus grosse transaction valide
/// possible — bornee par le poids, de l'ordre de quelques centaines d'entrees —
/// de sorte qu'aucune transaction honnete ne soit jamais refusee faute de
/// budget : elle draine le seau, puis il se remplit. Voir le debit ci-dessous.
pub const TX_SEAU_MAX: u64 = 512;

/// En deca de ce nombre d'entrees, une transaction refusee faute de budget est
/// traitee comme un flot de messages (sanctionnable) ; au-dela, comme une seule
/// grosse demande possiblement honnete (differee sans sanction). Voir le bras
/// `Message::Tx`.
pub const SEUIL_FLOT_ENTREES: u64 = 16;

/// Debit soutenu de verifications de signature accorde a un pair, par seconde.
///
/// # Le defaut que ceci ferme, et sa vraie taille
///
/// Une transaction poussee coute au recepteur une verification de signature
/// post-quantique **par entree**, sous le verrou global. La note precedente
/// annoncait « seize millisecondes » par verification ML-DSA-87 ; la mesure
/// reelle (banc `sig`, machine du bac a sable) est de l'ordre de **0,33 ms** —
/// la note etait cinquante fois trop pessimiste. Le danger n'en disparait pas :
/// rien ne bornait le nombre d'entrees d'une transaction (seul le poids la
/// borne, ~271 entrees pour ML-DSA-87), et le budget se comptait en
/// transactions, pas en verifications. Une transaction a nombreuses entrees,
/// ou un flot de telles transactions, tenait donc le verrou bien au-dela de ce
/// qu'un jeton par transaction laissait croire — red-team 8b, seconde campagne.
///
/// Desormais le seau se debite a proportion des entrees. A ce debit, le travail
/// de verification qu'un pair peut imposer est borne a ~0,33 ms par unite, soit
/// une fraction negligeable d'un cœur, tandis qu'une transaction ordinaire (une
/// ou deux entrees) reste servie sans entrave.
pub const TX_DEBIT_PAR_SEC: u64 = 8;

/// Seau a jetons bornant ce qu'un pair peut se faire servir d'amorce.
///
/// # Le defaut que ceci ferme
///
/// Les autres bras de service comptent leurs octets ; celui de l'amorce ne
/// comptait rien. Un pair ayant passe la poignee de main pouvait donc demander
/// **la meme tranche** en boucle : chaque demande de neuf octets faisait copier
/// jusqu'a un mebioctet, **sous le verrou global** — celui qui sert aussi a
/// valider les blocs. Le rapport entre le cout de la demande et celui de la
/// reponse est ce qui definit un vecteur de deni de service.
///
/// Un debit soutenu de deux mebioctets par seconde laisse un nouveau venu
/// honnete telecharger son amorce sans gene — c'est une operation qu'il ne fait
/// qu'une fois — tout en ramenant l'abus a un filet.
///
/// # Pourquoi l'instant est un parametre
///
/// Une horloge cachee rend une regle de debit impossible a eprouver autrement
/// qu'en dormant, donc mal eprouvee. Ici l'appelant fournit l'instant : les
/// epreuves controlent le temps, et la regle se verifie exactement.
#[derive(Debug, Clone, Copy)]
pub struct SeauAmorce {
    jetons: u64,
    dernier: Instant,
}

impl SeauAmorce {
    pub fn new(maintenant: Instant) -> SeauAmorce {
        SeauAmorce {
            jetons: AMORCE_SEAU_MAX,
            dernier: maintenant,
        }
    }

    /// Autorise `octets` si le seau les contient, et les retire. Le seau se
    /// remplit d'abord au prorata du temps ecoule, sans jamais depasser sa
    /// contenance.
    pub fn autoriser(&mut self, octets: u64, maintenant: Instant) -> bool {
        self.autoriser_avec(octets, maintenant, AMORCE_SEAU_MAX, AMORCE_DEBIT_PAR_SEC)
    }

    /// Un seau de transactions : meme regle, en unites et non en octets.
    pub fn pour_transactions(maintenant: Instant) -> SeauAmorce {
        SeauAmorce {
            jetons: TX_SEAU_MAX,
            dernier: maintenant,
        }
    }

    /// Un seau d'annonces compactes : meme regle, en annonces non sollicitees.
    pub fn pour_annonces_compactes(maintenant: Instant) -> SeauAmorce {
        SeauAmorce {
            jetons: CMPCT_SEAU_MAX,
            dernier: maintenant,
        }
    }

    /// Autorise `cout` unites au titre d'un seau de contenance `max` et de
    /// debit `debit` par seconde.
    pub fn autoriser_avec(&mut self, cout: u64, maintenant: Instant, max: u64, debit: u64) -> bool {
        let ecoule = maintenant
            .saturating_duration_since(self.dernier)
            .as_millis() as u64;
        // Le remplissage se calcule en millisecondes : sous la milliseconde, on
        // ne credite rien et on ne deplace pas le repere, faute de quoi une
        // rafale de demandes tres rapprochees ne crediterait jamais rien.
        let gain = ecoule.saturating_mul(debit) / 1000;
        if gain > 0 {
            self.jetons = self.jetons.saturating_add(gain).min(max);
            self.dernier = maintenant;
        }
        let octets = cout;
        if self.jetons >= octets {
            self.jetons -= octets;
            true
        } else {
            false
        }
    }
}

/// Delai maximal d'une ecriture vers un pair.
///
/// Plus court que la lecture : un pair peut legitimement rester silencieux deux
/// minutes, il ne peut pas legitimement refuser d'accueillir ses octets pendant
/// trente secondes. Au-dela, la connexion tombe et la propagation continue sans
/// lui.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub fn magic_for(network: Network) -> [u8; 4] {
    match network {
        Network::Mainnet => NETWORK_MAGIC_MAINNET,
        _ => NETWORK_MAGIC_TESTNET,
    }
}

fn maintenant() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pair connecte.
struct Peer {
    addr: SocketAddr,
    sortie: Arc<Mutex<TcpStream>>,
    /// Vrai si **nous** avons initie cette connexion (sortante). Une connexion
    /// entrante est choisie par l'autre bout ; seules les sortantes sont
    /// choisies par nous, dans le carnet, avec sa diversite de groupes. Compter
    /// les entrantes dans la cible de pairs laisserait un attaquant remplir nos
    /// places depuis une seule IP et **supprimer tout appel sortant** : le
    /// carnet anti-eclipse ne serait alors jamais consulte. On les distingue.
    sortant: bool,
    /// Vrai des qu'un message `Version` valide a ete recu de ce pair. La
    /// poignee de main n'est complete (`handshaked`) qu'apres `Version` **puis**
    /// `VerAck` : un `VerAck` seul, sans `Version`, ne doit pas ouvrir l'acces
    /// aux messages couteux ni sauter le controle de nonce anti-boucle.
    version_recue: bool,
    /// Vrai des que **nous** avons envoye notre `Version` a ce pair — a la
    /// connexion pour une sortante, en reponse au sien pour une entrante. On
    /// ne se presente qu'une fois : voir le bras `Version`.
    version_envoyee: bool,
    handshaked: bool,
    ban_score: u32,
    /// Hauteur annoncee par le pair a la poignee de main.
    start_height: u64,
    /// Reconstructions de blocs compacts en attente de transactions.
    en_attente: HashMap<Hash256, (CompactBlock, Vec<u32>)>,
    /// Ce que ce pair peut encore se faire servir d'amorce. Voir [`SeauAmorce`].
    seau_amorce: SeauAmorce,
    /// Les transactions inedites que ce pair peut encore pousser. Voir
    /// [`TX_DEBIT_PAR_SEC`].
    seau_tx: SeauAmorce,
    /// Les annonces compactes non sollicitees que ce pair peut encore pousser.
    /// Voir [`CMPCT_DEBIT_PAR_SEC`].
    seau_cmpct: SeauAmorce,
    /// Corps de blocs demandes a ce pair, et quand. Voir [`DELAI_CORPS`].
    /// Jamais plus de [`CORPS_EN_VOL_MAX`] entrees : voir
    /// [`Peer::noter_corps_demande`].
    corps_demandes: HashMap<Hash256, Instant>,
    /// Corps que ce pair nous a fait connaitre et qu'on n'a pas encore
    /// demandes, faute de place en vol. Servis dans l'ordre de la chaine.
    /// Voir [`CORPS_EN_ATTENTE_MAX`].
    corps_a_demander: VecDeque<Hash256>,
    /// Le dernier lot d'en-tetes de ce pair etait plein : il en a d'autres, a
    /// redemander quand la file et les corps en vol seront ecoules.
    suite_attendue: bool,
    /// Instant de la derniere trame recue de ce pair.
    ///
    /// # Le defaut que ce champ repare
    ///
    /// La boucle de lecture pose un delai de 120 secondes sur la socket, et
    /// traitait son expiration ainsi :
    ///
    /// ```text
    ///     Err(e) if e.kind() == WouldBlock => continue,
    /// ```
    ///
    /// C'est-a-dire : elle recommencait a attendre, indefiniment. Un pair qui
    /// cesse d'emettre n'etait donc **jamais** retire. Le compte de pairs
    /// restait a un, et la boucle de maintien — qui ne reconnecte que s'il
    /// manque des pairs — n'avait rien a faire.
    ///
    /// Un portable dont on referme l'ecran produit exactement cela : la
    /// connexion meurt sans qu'aucun FIN ni RST n'arrive, et le noeud garde un
    /// pair fantome pour toujours. Trouve en refermant un MacBook — la chaine
    /// s'est arretee a la hauteur 442 et n'a plus jamais bouge.
    ///
    /// Sur un reseau public, c'est aussi une voie d'eclipse : ouvrir des
    /// connexions puis se taire suffit a occuper toutes les places.
    derniere_reception: Instant,
    /// Instant du dernier `Ping` envoye et resté sans reponse.
    ping_en_attente: Option<Instant>,
    /// Instant d'ouverture de la connexion, fige a la creation. Sert l'echeance
    /// de poignee de main : voir [`DELAI_POIGNEE_MAIN`]. A la difference de
    /// `derniere_reception`, aucune trame ne le repousse — une connexion qui ne
    /// se presente pas ne peut donc pas prolonger sa place en s'agitant.
    instant_connexion: Instant,
    /// Nombre d'en-tetes recus qui ne se rattachent a rien de connu.
    ///
    /// Compte les signes que ce pair est sur une autre chaine. Sans ce compteur,
    /// deux noeuds aux geneses differentes s'echangent indefiniment des blocs
    /// que ni l'un ni l'autre ne peut rattacher — defaut constate en lancant
    /// reellement deux noeuds, invisible en test unitaire parce que les deux y
    /// partageaient la meme genese.
    orphelins_consecutifs: u32,
}

impl Peer {
    /// Note un corps demande a ce pair, si la place en vol le permet.
    ///
    /// C'est l'unique porte d'entree de `corps_demandes` : quelle que soit la
    /// voie par laquelle un identifiant arrive — en-tetes, `inv`, redemande
    /// apres retention — la table ne depasse jamais [`CORPS_EN_VOL_MAX`].
    /// Rend vrai si le corps est en vol (nouvellement note, ou deja).
    fn noter_corps_demande(&mut self, h: Hash256, maintenant: Instant) -> bool {
        if self.corps_demandes.contains_key(&h) {
            return true;
        }
        if self.corps_demandes.len() >= CORPS_EN_VOL_MAX {
            return false;
        }
        self.corps_demandes.insert(h, maintenant);
        true
    }

    /// Range un corps a demander plus tard, si la file a de la place.
    fn mettre_en_attente(&mut self, h: Hash256) {
        if self.corps_a_demander.len() < CORPS_EN_ATTENTE_MAX {
            self.corps_a_demander.push_back(h);
        }
    }

    /// Fait avancer la synchronisation avec ce pair.
    ///
    /// Libere les places des corps arrives, remplit celles qui restent depuis
    /// la file d'attente, et — quand il n'y a plus rien ni en vol ni en
    /// attente — redemande des en-tetes si le pair en a annonce davantage.
    ///
    /// # Pourquoi la redemande d'en-tetes attend ce moment
    ///
    /// Elle partait auparavant des la reception d'un lot plein, avec un
    /// localisateur qui ne contenait encore aucun des blocs du lot : le pair
    /// repondait le meme lot une seconde fois. Ici elle part quand les corps
    /// sont arrives, avec un localisateur a jour, et demande ce qui suit.
    ///
    /// `apres_progres` dit si un bloc de ce pair vient d'etre accepte. Ce
    /// n'est qu'alors que la hauteur annoncee a la poignee de main autorise
    /// une redemande : sur un simple lot d'en-tetes tous connus, elle ferait
    /// tourner en boucle deux noeuds dont l'un tient l'autre pour une branche
    /// laterale. Un lot plein, lui, autorise toujours la suite — la suite est
    /// autre chose que ce lot, puisque le localisateur le contient desormais.
    fn poursuivre_synchro(
        &mut self,
        id: u64,
        chain: &Chain,
        envois: &mut Vec<Envoi>,
        maintenant: Instant,
        apres_progres: bool,
    ) {
        if !self.handshaked {
            return;
        }
        self.corps_demandes.retain(|h, _| !chain.has_block(h));
        let mut items = Vec::new();
        while self.corps_demandes.len() < CORPS_EN_VOL_MAX {
            let Some(h) = self.corps_a_demander.pop_front() else {
                break;
            };
            if chain.has_block(&h) || self.corps_demandes.contains_key(&h) {
                continue;
            }
            if self.noter_corps_demande(h, maintenant) {
                items.push(InvItem {
                    kind: InvKind::CompactBlock,
                    hash: h,
                });
            }
        }
        if !items.is_empty() {
            envois.push(Envoi {
                peer: id,
                message: Message::GetData(items),
            });
            return;
        }
        let epuise = self.corps_a_demander.is_empty() && self.corps_demandes.is_empty();
        let en_a_plus =
            self.suite_attendue || (apres_progres && self.start_height > chain.height());
        if epuise && en_a_plus {
            self.suite_attendue = false;
            envois.push(Envoi {
                peer: id,
                message: Message::GetHeaders {
                    locator: chain.locator(),
                    stop: Hash256::ZERO,
                },
            });
        }
    }
}

/// Etat partage du noeud.
struct Partage {
    chain: Chain,
    mempool: Mempool,
    /// Carnet d'adresses, range par groupe reseau.
    ///
    /// Vit sous le meme verrou que le reste : un pair qui annonce des adresses
    /// le fait dans le meme message que le reste de son trafic, et separer les
    /// verrous ferait gagner un temps qui n'existe pas contre un risque
    /// d'interblocage qui, lui, existe.
    carnet: AddrBook,
    peers: HashMap<u64, Peer>,
    network: Network,
    /// Nonce du noeud : sert a detecter une connexion a soi-meme.
    nonce: u64,
    /// Ou consigner les blocs acceptes. Absent en memoire pure (tests).
    journal: Option<Arc<dyn crate::chain::Journal>>,
    /// L'amorce de synchronisation rapide deja serialisee, gardee tant que la
    /// tete ne bouge pas. La reconstruire coute cher (instantane + empreinte) :
    /// on ne le fait qu'a la demande, et une seule fois par tete.
    amorce_cache: Option<AmorceCache>,
}

/// L'amorce servie, figee pour une tete donnee.
struct AmorceCache {
    tip: Hash256,
    octets: Vec<u8>,
    hauteur: u64,
    tete: Hash256,
    empreinte: Hash256,
}

/// Reconstruit l'amorce servie si la tete a bouge depuis la derniere fois.
///
/// Un client qui telecharge pendant que la tete avance recevra des tranches
/// d'une amorce differente de celle annoncee ; son controle d'empreinte le
/// detecte et il recommence. La coherence n'est donc jamais rompue en silence.
fn rafraichir_amorce(g: &mut Partage) {
    let tip = g.chain.tip_id();
    if g.amorce_cache.as_ref().map(|c| c.tip) == Some(tip) {
        return;
    }
    g.amorce_cache = g.chain.construire_amorce().map(|a| {
        let octets = a.encode();
        AmorceCache {
            tip,
            hauteur: a.hauteur_annoncee().unwrap_or(0),
            tete: a.tete_annoncee().unwrap_or(Hash256::ZERO),
            empreinte: a.empreinte_annoncee().unwrap_or(Hash256::ZERO),
            octets,
        }
    });
}

/// Items servis au maximum en reponse a un seul message.
///
/// Un pair honnete n'en demande jamais autant en une fois ; un pair hostile
/// n'obtiendra rien de plus.
const MAX_ITEMS_SERVIS: usize = 512;

/// Budget d'octets en sortie pour la reponse a un seul message.
///
/// C'est la borne qui transforme une amplification en simple requete. Fixee
/// sous le `MAX_PAYLOAD` du protocole : une reponse que le pair ne pourrait pas
/// lire ne serait qu'un gaspillage a sens unique.
const BUDGET_REPONSE_OCTETS: usize = 4 * 1024 * 1024;

/// Reponse a emettre apres liberation du verrou.
struct Envoi {
    peer: u64,
    message: Message,
}

#[derive(Clone)]
pub struct Node {
    partage: Arc<Mutex<Partage>>,
    magie: [u8; 4],
    prochain_id: Arc<AtomicU64>,
    arret: Arc<AtomicBool>,
    /// Compteurs d'observation, utiles aux tests et a l'exploitation.
    pub stats: Arc<Stats>,
}

#[derive(Default, Debug)]
pub struct Stats {
    pub blocs_recus: AtomicU64,
    pub blocs_acceptes: AtomicU64,
    pub tx_recues: AtomicU64,
    pub compacts_recus: AtomicU64,
    /// Blocs compacts reconstruits sans aucun aller-retour.
    pub compacts_sans_aller_retour: AtomicU64,
    /// Annonces compactes pour lesquelles une reconstruction a ete entamee —
    /// balayage du reservoir et allocation, sous le verrou. C'est la depense
    /// que le seau borne ; voir [`CMPCT_DEBIT_PAR_SEC`].
    pub compacts_reconstruits: AtomicU64,
    /// Annonces compactes refusees par le seau, sans reconstruction.
    pub compacts_refuses: AtomicU64,
    /// Annonces compactes dont l'en-tete a ete refuse **avant** toute
    /// reconstruction : hauteur, difficulte, horodatage ou travail faux. Rien
    /// n'a ete fouille ni alloue pour elles ; voir [`Chain::verifier_entete`].
    pub compacts_entete_refuse: AtomicU64,
    pub pairs_bannis: AtomicU64,
    /// Blocs dont on ignorait le parent au moment de leur arrivee.
    ///
    /// Doit rester proche de zero : la synchronisation stricte par en-tetes ne
    /// demande un corps qu'apres rattachement. Un compteur qui s'emballe
    /// signale une boucle de resynchronisation — exactement le defaut qui
    /// n'apparait qu'en lancant de vrais processus.
    pub blocs_orphelins: AtomicU64,
    /// Blocs refuses par la validation.
    pub blocs_invalides: AtomicU64,
}

impl Node {
    pub fn new(network: Network, chain: Chain) -> Node {
        let nonce = {
            // Source d'entropie sans dependance : l'horloge fine suffit pour
            // distinguer deux noeuds sur une meme machine.
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
                .unwrap_or(1);
            t.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1)
        };
        Node {
            partage: Arc::new(Mutex::new(Partage {
                chain,
                mempool: Mempool::new(),
                // Le bouclage n'a de sens que sur les reseaux de test, ou tout
                // tourne sur une seule machine.
                carnet: AddrBook::new(!matches!(network, Network::Mainnet)),
                peers: HashMap::new(),
                network,
                nonce,
                journal: None,
                amorce_cache: None,
            })),
            magie: magic_for(network),
            prochain_id: Arc::new(AtomicU64::new(1)),
            arret: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Stats::default()),
        }
    }

    /// Branche le journal ou consigner les blocs acceptes.
    ///
    /// A appeler **avant** de laisser entrer le moindre bloc : un bloc accepte
    /// sans journal est un bloc perdu au prochain arret.
    pub fn set_journal(&self, j: Arc<dyn crate::chain::Journal>) {
        self.partage.lock().unwrap().journal = Some(j);
    }

    pub fn height(&self) -> u64 {
        self.partage.lock().unwrap().chain.height()
    }

    // -----------------------------------------------------------------------
    // Carnet d'adresses
    // -----------------------------------------------------------------------

    /// Verse des adresses dans le carnet — amorcage ou rechargement du disque.
    pub fn seed_addresses(&self, v: &[crate::wire::NetAddr]) -> usize {
        let mut g = self.partage.lock().unwrap();
        let n = maintenant();
        v.iter().filter(|a| g.carnet.ajouter(**a, n)).count()
    }

    /// Adresses a essayer, toutes de groupes reseau distincts et distincts de
    /// ceux des pairs deja connectes.
    pub fn addresses_to_try(&self, combien: usize) -> Vec<crate::wire::NetAddr> {
        let g = self.partage.lock().unwrap();
        let deja: Vec<[u8; 4]> = g
            .peers
            .values()
            .filter_map(|p| match p.addr {
                SocketAddr::V4(a) => Some(a.ip().octets()),
                _ => None,
            })
            .collect();
        g.carnet.selectionner(combien, &deja, maintenant())
    }

    /// Groupes reseau distincts parmi les pairs connectes.
    ///
    /// C'est la mesure qui compte pour l'eclipse : dix pairs dans un seul groupe
    /// valent un seul pair.
    pub fn peer_groups(&self) -> usize {
        let g = self.partage.lock().unwrap();
        let s: std::collections::HashSet<[u8; 2]> = g
            .peers
            .values()
            .filter_map(|p| match p.addr {
                SocketAddr::V4(a) => Some(crate::addr::groupe(a.ip().octets())),
                _ => None,
            })
            .collect();
        s.len()
    }

    pub fn address_count(&self) -> usize {
        self.partage.lock().unwrap().carnet.len()
    }

    /// Copie du carnet, pour l'ecrire sur disque.
    pub fn address_entries(&self) -> Vec<crate::addr::Entree> {
        self.partage.lock().unwrap().carnet.toutes()
    }

    pub fn note_connect_success(&self, ip: [u8; 4], port: u16) {
        let mut g = self.partage.lock().unwrap();
        g.carnet.ajouter(
            crate::wire::NetAddr {
                ip,
                port,
                last_seen: maintenant(),
            },
            maintenant(),
        );
        g.carnet.marquer_succes(ip, port, maintenant());
    }

    pub fn note_connect_failure(&self, ip: [u8; 4], port: u16) {
        self.partage.lock().unwrap().carnet.marquer_echec(ip, port);
    }

    pub fn tip_id(&self) -> Hash256 {
        self.partage.lock().unwrap().chain.tip_id()
    }

    /// Plus haute hauteur annoncee par un pair dont la poignee de main est faite.
    ///
    /// C'est la seule mesure dont dispose un noeud pour savoir s'il est en
    /// retard. Elle vaut ce que valent les pairs : un noeud eclipse verra la
    /// hauteur que son adversaire lui montre. Le carnet d'adresses est ce qui
    /// rend cette situation couteuse a produire.
    pub fn hauteur_annoncee_max(&self) -> u64 {
        let g = self.partage.lock().unwrap();
        g.peers
            .values()
            .filter(|p| p.handshaked)
            .map(|p| p.start_height)
            .max()
            .unwrap_or(0)
    }

    pub fn peer_count(&self) -> usize {
        self.partage.lock().unwrap().peers.len()
    }

    /// Nombre de connexions **sortantes** — celles que nous avons initiees
    /// depuis le carnet. C'est ce compte, et non le total, que la boucle de
    /// maintien doit ramener a la cible : sinon un flot de connexions entrantes
    /// depuis une seule IP suffit a nous empecher d'aller chercher des pairs
    /// diversifies, et la defense anti-eclipse tombe.
    /// Une connexion entrante a-t-elle sa place ?
    ///
    /// Trois bornes : le total, la reserve des sortantes, et la part d'un
    /// meme groupe reseau — IPv4 et IPv6 confondus, voir [`groupe_entrant`].
    /// Voir [`PLACES_SORTANTES_RESERVEES`] et [`ENTRANTS_PAR_GROUPE`].
    ///
    /// Prend l'adresse plutot que le flux : la regle s'eprouve ainsi sur des
    /// adresses qu'une machine sans IPv6 ne saurait ouvrir.
    fn admettre_entrant(&self, adresse: Option<SocketAddr>) -> bool {
        let g = self.partage.lock().unwrap();
        let total = g.peers.len();
        if total >= MAX_PEERS {
            return false;
        }
        let entrants = g.peers.values().filter(|p| !p.sortant).count();
        if entrants + PLACES_SORTANTES_RESERVEES >= MAX_PEERS {
            return false;
        }
        if let Some(gr) = adresse.and_then(groupe_entrant) {
            let memes = g
                .peers
                .values()
                .filter(|p| !p.sortant)
                .filter(|p| groupe_entrant(p.addr) == Some(gr))
                .count();
            if memes >= ENTRANTS_PAR_GROUPE {
                return false;
            }
        }
        true
    }

    pub fn peer_count_sortants(&self) -> usize {
        self.partage
            .lock()
            .unwrap()
            .peers
            .values()
            .filter(|p| p.sortant)
            .count()
    }

    /// Coupe toutes les connexions, et rend leur nombre.
    ///
    /// Employe au reveil d'une machine mise en veille : apres quelques minutes
    /// d'arret, toutes les liaisons TCP sont mortes de toute facon — le
    /// routeur a oublie sa table de traduction, le pair d'en face a renonce.
    /// Attendre le delai de silence ferait perdre deux minutes de plus a
    /// quelqu'un qui vient simplement de rouvrir son portable.
    ///
    /// Se tromper ne coute qu'une reconnexion.
    pub fn couper_tous_les_pairs(&self) -> usize {
        let ids: Vec<u64> = self.partage.lock().unwrap().peers.keys().copied().collect();
        let n = ids.len();
        for id in ids {
            self.deconnecter(id);
        }
        n
    }

    /// Sommes-nous deja connectes a cette adresse ?
    ///
    /// Sert a ne pas ouvrir une seconde connexion vers une amorce qu'on
    /// reessaie periodiquement : deux liaisons vers le meme pair gaspillent une
    /// place et doublent le trafic sans rien apporter.
    pub fn est_connecte_a(&self, addr: SocketAddr) -> bool {
        self.partage
            .lock()
            .unwrap()
            .peers
            .values()
            .any(|p| p.addr == addr)
    }

    /// Interroge les pairs silencieux, et libere la place de ceux qui sont
    /// morts.
    ///
    /// # Pourquoi ce n'est pas la socket qui le dit
    ///
    /// Une connexion TCP peut survivre a la machine d'en face. Un portable dont
    /// on referme l'ecran, un cable debranche, un routeur qui oublie sa table :
    /// dans ces cas, aucun FIN ni RST n'arrive jamais. La socket reste ouverte,
    /// la lecture attend, et le noeud croit avoir un pair.
    ///
    /// Le seul signe fiable de vie est **une trame recue**. On demande donc au
    /// pair de se manifester apres un silence, et on libere sa place s'il ne le
    /// fait pas. C'est ce que fait Bitcoin, pour la meme raison.
    ///
    /// Rend le nombre de pairs coupes.
    pub fn entretenir_pairs(&self) -> usize {
        let maintenant = Instant::now();
        let mut a_pinger: Vec<(u64, Arc<Mutex<TcpStream>>)> = Vec::new();
        let mut morts: Vec<u64> = Vec::new();
        let magie = self.magie;
        let mut a_redemander: Vec<Envoi> = Vec::new();
        let nonce = {
            let mut g = self.partage.lock().unwrap();
            let Partage {
                ref chain,
                ref mut peers,
                ..
            } = *g;
            // --- Les corps demandes : livres, en attente, ou retenus ?
            let mut retenus: Vec<Hash256> = Vec::new();
            let mut retenteurs: Vec<u64> = Vec::new();
            for (id, p) in peers.iter_mut() {
                let mut en_retard = 0u32;
                p.corps_demandes.retain(|h, depuis| {
                    if chain.has_block(h) {
                        return false;
                    }
                    if maintenant.duration_since(*depuis) >= DELAI_CORPS {
                        en_retard += 1;
                        retenus.push(*h);
                        return false;
                    }
                    true
                });
                if en_retard > 0 {
                    retenteurs.push(*id);
                    p.ban_score += MISCONDUCT_CORPS_RETENU;
                    if p.ban_score >= BAN_THRESHOLD {
                        self.stats.pairs_bannis.fetch_add(1, Ordering::Relaxed);
                        morts.push(*id);
                    }
                }
            }
            if !retenus.is_empty() {
                // A un autre pair — presente, et pas celui qui retient. Par sa
                // file d'attente : la redemande obeit au meme plafond de corps
                // en vol que toute autre demande.
                let autre = peers
                    .iter()
                    .filter(|(id, p)| {
                        p.handshaked && !morts.contains(id) && !retenteurs.contains(id)
                    })
                    .map(|(id, _)| *id)
                    .next();
                if let Some(id) = autre {
                    if let Some(p) = peers.get_mut(&id) {
                        for h in retenus {
                            p.mettre_en_attente(h);
                        }
                        p.poursuivre_synchro(id, chain, &mut a_redemander, maintenant, false);
                    }
                }
            }
            for (id, p) in peers.iter_mut() {
                if morts.contains(id) {
                    continue;
                }
                let silence = maintenant.duration_since(p.derniere_reception);
                if silence >= SILENCE_MAX {
                    morts.push(*id);
                } else if !p.handshaked
                    && maintenant.duration_since(p.instant_connexion) >= DELAI_POIGNEE_MAIN
                {
                    // Poignee de main jamais terminee dans le delai : la place
                    // entrante ne doit pas rester squattee par une connexion qui
                    // ne fait que s'agiter. Voir DELAI_POIGNEE_MAIN.
                    morts.push(*id);
                } else if silence >= PING_APRES && p.ping_en_attente.is_none() {
                    p.ping_en_attente = Some(maintenant);
                    a_pinger.push((*id, p.sortie.clone()));
                }
            }
            g.nonce
        };
        for e in a_redemander {
            self.envoyer_a(e.peer, &e.message);
        }
        // L'ecriture se fait hors du verrou : une socket bouchee bloquerait
        // sinon tout le noeud pendant le delai d'ecriture.
        for (_, sortie) in a_pinger {
            let _ = ecrire(&sortie, &Message::Ping(nonce), magie);
        }
        let coupes = morts.len();
        for id in morts {
            // `deconnecter` ferme la socket des deux cotes : la boucle de
            // lecture, qui attendait, en sort avec une erreur et son fil meurt.
            self.deconnecter(id);
        }
        coupes
    }

    pub fn mempool_len(&self) -> usize {
        self.partage.lock().unwrap().mempool.len()
    }

    /// Execute `f` avec un acces exclusif a la chaine.
    pub fn with_chain<R>(&self, f: impl FnOnce(&mut Chain) -> R) -> R {
        let mut g = self.partage.lock().unwrap();
        f(&mut g.chain)
    }

    pub fn with_mempool<R>(&self, f: impl FnOnce(&mut Mempool) -> R) -> R {
        let mut g = self.partage.lock().unwrap();
        f(&mut g.mempool)
    }

    /// Execute `f` avec un acces exclusif a la chaine **et** au reservoir.
    ///
    /// Les deux vivent sous le meme verrou. Appeler `with_chain` a l'interieur
    /// de `with_mempool` — ou l'inverse — le prendrait deux fois et figerait le
    /// noeud sur place. Toute operation qui a besoin des deux passe par ici.
    pub fn with_chain_and_mempool<R>(&self, f: impl FnOnce(&mut Chain, &mut Mempool) -> R) -> R {
        let mut g = self.partage.lock().unwrap();
        let Partage {
            ref mut chain,
            ref mut mempool,
            ..
        } = *g;
        f(chain, mempool)
    }

    pub fn shutdown(&self) {
        self.arret.store(true, Ordering::Relaxed);
    }

    fn stoppe(&self) -> bool {
        self.arret.load(Ordering::Relaxed)
    }

    /// Ouvre un port d'ecoute et accepte les connexions en tache de fond.
    pub fn listen(&self, addr: &str) -> std::io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        let node = self.clone();
        std::thread::spawn(move || {
            for flux in listener.incoming() {
                if node.stoppe() {
                    break;
                }
                match flux {
                    Ok(s) => {
                        if !node.admettre_entrant(s.peer_addr().ok()) {
                            continue;
                        }
                        node.demarrer_pair(s, false);
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(local)
    }

    /// Se connecte a un pair et lance la poignee de main.
    pub fn connect(&self, addr: SocketAddr) -> std::io::Result<u64> {
        // Quatre secondes : assez pour une liaison lente, pas assez pour
        // qu'un lot d'adresses muettes tienne la boucle de maintien une
        // minute.
        let flux = TcpStream::connect_timeout(&addr, Duration::from_secs(4))?;
        Ok(self.demarrer_pair(flux, true))
    }

    fn demarrer_pair(&self, flux: TcpStream, sortant: bool) -> u64 {
        let _ = flux.set_read_timeout(Some(READ_TIMEOUT));
        // Sans delai d'ecriture, un pair qui n'accueille jamais ses octets
        // bloque indefiniment le fil qui lui ecrit — en tenant le mutex de son
        // flux. Comme les diffusions ecrivent vers tous les pairs, un seul pair
        // silencieux finissait par bloquer la propagation entiere.
        let _ = flux.set_write_timeout(Some(WRITE_TIMEOUT));
        let _ = flux.set_nodelay(true);
        let addr = flux
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        let lecture = match flux.try_clone() {
            Ok(f) => f,
            Err(_) => return 0,
        };

        let id = self.prochain_id.fetch_add(1, Ordering::Relaxed);
        let sortie = Arc::new(Mutex::new(flux));

        {
            let mut g = self.partage.lock().unwrap();
            g.peers.insert(
                id,
                Peer {
                    addr,
                    sortie: sortie.clone(),
                    sortant,
                    seau_amorce: SeauAmorce::new(Instant::now()),
                    seau_tx: SeauAmorce::pour_transactions(Instant::now()),
                    seau_cmpct: SeauAmorce::pour_annonces_compactes(Instant::now()),
                    corps_demandes: HashMap::new(),
                    corps_a_demander: VecDeque::new(),
                    suite_attendue: false,
                    version_recue: false,
                    version_envoyee: sortant,
                    handshaked: false,
                    ban_score: 0,
                    start_height: 0,
                    en_attente: HashMap::new(),
                    orphelins_consecutifs: 0,
                    derniere_reception: Instant::now(),
                    ping_en_attente: None,
                    instant_connexion: Instant::now(),
                },
            );
        }

        // Le connectant parle en premier.
        if sortant {
            let (nonce, hauteur) = {
                let g = self.partage.lock().unwrap();
                (g.nonce, g.chain.height())
            };
            let v = Message::Version {
                version: PROTOCOL_VERSION,
                timestamp: maintenant(),
                nonce,
                user_agent: "q21:0.3".into(),
                start_height: hauteur,
            };
            let _ = ecrire(&sortie, &v, self.magie);
        }

        let node = self.clone();
        std::thread::spawn(move || {
            node.boucle_lecture(id, lecture);
            node.deconnecter(id);
        });
        id
    }

    fn deconnecter(&self, id: u64) {
        let mut g = self.partage.lock().unwrap();
        if let Some(p) = g.peers.remove(&id) {
            let _ = p.sortie.lock().unwrap().shutdown(std::net::Shutdown::Both);
        }
    }

    /// Boucle de lecture d'un pair.
    ///
    /// Le tampon ne grandit jamais au-dela de la taille maximale d'une trame :
    /// c'est ce qui empeche un pair d'epuiser la memoire en annoncant une charge
    /// gigantesque puis en n'envoyant rien.
    fn boucle_lecture(&self, id: u64, mut flux: TcpStream) {
        let mut tampon: Vec<u8> = Vec::with_capacity(64 * 1024);
        let mut morceau = [0u8; 32 * 1024];

        loop {
            if self.stoppe() {
                return;
            }
            let n = match flux.read(&mut morceau) {
                Ok(0) => return,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => return,
            };
            tampon.extend_from_slice(&morceau[..n]);

            if tampon.len() > MAX_PAYLOAD + HEADER_LEN {
                self.sanctionner(id, MISCONDUCT_MALFORMED * 10);
                return;
            }

            loop {
                match Message::parse(&tampon, self.magie) {
                    Ok((msg, consomme)) => {
                        tampon.drain(..consomme);
                        if !self.traiter(id, msg) {
                            return;
                        }
                    }
                    Err(WireError::Incomplet) => break,
                    Err(_) => {
                        self.sanctionner(id, MISCONDUCT_MALFORMED);
                        // Un cadrage perdu ne se rattrape pas : on coupe.
                        return;
                    }
                }
            }
        }
    }

    /// Une transaction que seul son auteur a pu rendre invalide.
    fn transaction_invalide_en_soi(e: &crate::mempool::MempoolError) -> bool {
        use crate::mempool::MempoolError as M;
        use crate::validate::ValidationError as V;
        match e {
            // « Je ne sais pas verifier » n'est pas « tu mens » : voir
            // `incapacite_locale`.
            M::Validation(v) if incapacite_locale(v).is_some() => false,
            M::Validation(
                V::Signature(_)
                | V::ClefNeCorrespondPasAuVerrou
                | V::Transaction(_)
                | V::ValeurNonConservee { .. }
                | V::SchemaInterditSurCeReseau(_)
                | V::SortiePoussiere { .. },
            ) => true,
            _ => false,
        }
    }

    fn sanctionner(&self, id: u64, points: u32) -> bool {
        let mut g = self.partage.lock().unwrap();
        if let Some(p) = g.peers.get_mut(&id) {
            p.ban_score += points;
            if p.ban_score >= BAN_THRESHOLD {
                self.stats.pairs_bannis.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        true
    }

    /// Traite un message. Rend `false` s'il faut couper la connexion.
    fn traiter(&self, id: u64, msg: Message) -> bool {
        let mut envois: Vec<Envoi> = Vec::new();
        let mut couper = false;

        {
            let mut g = self.partage.lock().unwrap();
            // Une trame recue, quelle qu'elle soit, prouve que le pair est
            // vivant. C'est la seule preuve qui vaille : une socket ouverte n'en
            // est pas une, elle peut survivre a la machine d'en face.
            if let Some(p) = g.peers.get_mut(&id) {
                p.derniere_reception = Instant::now();
                p.ping_en_attente = None;
            }
            let magie_reseau = g.network;
            let nonce_local = g.nonce;
            // La poignee de main conditionne l'acces aux messages couteux.
            // Servir un `getdata` a une simple connexion TCP anonyme reduit le
            // cout d'une amplification a un `connect()`.
            let handshaked = g.peers.get(&id).map(|p| p.handshaked).unwrap_or(false);

            match msg {
                Message::Version {
                    version,
                    nonce,
                    start_height,
                    ..
                } => {
                    // Connexion a soi-meme : on coupe sans ceremonie. Un pair
                    // d'une autre epoque du protocole aussi : il ne validerait
                    // pas les memes regles, et chacun punirait l'autre pour
                    // des blocs que l'autre tient pour justes.
                    if nonce == nonce_local || version < MIN_PROTOCOL_VERSION {
                        couper = true;
                    } else {
                        let hauteur = g.chain.height();
                        if let Some(p) = g.peers.get_mut(&id) {
                            // --- Un `Version` par pair, et un seul en retour.
                            //
                            // Chaque `Version` recu faisait renvoyer un
                            // `Version`, y compris a celui qui nous l'avait
                            // envoye en reponse au notre : deux noeuds
                            // s'echangeaient donc `Version`/`VerAck`/
                            // `GetAddr`/`Addr` sans fin, des dizaines de
                            // milliers de trames par seconde, et chaque tour
                            // relancait une demande d'en-tetes. Le repondant
                            // se presente une fois, avant son `VerAck` pour
                            // que l'autre bout ait notre `Version` quand
                            // l'accuse lui parvient ; un doublon est ignore.
                            if !p.version_recue {
                                p.version_recue = true;
                                p.start_height = start_height;
                                if !p.version_envoyee {
                                    p.version_envoyee = true;
                                    envois.push(Envoi {
                                        peer: id,
                                        message: Message::Version {
                                            version: PROTOCOL_VERSION,
                                            timestamp: maintenant(),
                                            nonce: nonce_local,
                                            user_agent: "q21:0.3".into(),
                                            start_height: hauteur,
                                        },
                                    });
                                }
                                envois.push(Envoi {
                                    peer: id,
                                    message: Message::VerAck,
                                });
                            }
                        }
                    }
                }

                Message::VerAck => {
                    let (retard, locator) = {
                        let hauteur = g.chain.height();
                        let p = g.peers.get_mut(&id);
                        match p {
                            // Un `VerAck` ne complete la poignee de main que si
                            // un `Version` l'a precede. Sinon on l'ignore : pas
                            // d'acces aux messages couteux, et le controle de
                            // nonce (connexion a soi-meme) n'est pas contourne.
                            Some(p) if p.version_recue => {
                                p.handshaked = true;
                                (p.start_height > hauteur, g.chain.locator())
                            }
                            _ => (false, Vec::new()),
                        }
                    };
                    if retard {
                        envois.push(Envoi {
                            peer: id,
                            message: Message::GetHeaders {
                                locator,
                                stop: Hash256::ZERO,
                            },
                        });
                    }
                    // On demande son carnet a chaque nouveau pair. C'est le seul
                    // mecanisme de decouverte : sans lui, un noeud ne connait
                    // jamais que les adresses qu'on lui a donnees a la main.
                    envois.push(Envoi {
                        peer: id,
                        message: Message::GetAddr,
                    });
                }

                Message::Ping(n) => envois.push(Envoi {
                    peer: id,
                    message: Message::Pong(n),
                }),
                Message::Pong(_) => {}

                Message::GetHeaders { locator, stop } => {
                    // Comme tout service, la reponse aux en-tetes exige la
                    // poignee de main : la synchronisation ne demande jamais
                    // d'en-tetes avant elle (voir le bras VerAck), donc rien
                    // d'honnete n'est perdu, et une connexion anonyme ne peut
                    // plus declencher de travail de service.
                    if handshaked {
                        let h = g
                            .chain
                            .headers_from(&locator, stop, crate::wire::MAX_HEADERS);
                        if !h.is_empty() {
                            envois.push(Envoi {
                                peer: id,
                                message: Message::Headers(h),
                            });
                        }
                    }
                }

                Message::Headers(v) if v.is_empty() => {}

                Message::Headers(v) if !handshaked => {
                    // Meme regle que `getheaders` : la synchronisation ne
                    // recoit d'en-tetes qu'en reponse a sa propre demande, qui
                    // part apres la poignee de main (bras VerAck). Rien
                    // d'honnete n'est perdu, et une connexion anonyme ne fait
                    // plus hacher deux mille en-tetes ni demander un seul
                    // corps. Le message « pousse » franchissait la porte que
                    // le message « demande » gardait fermee.
                    let _ = v;
                }

                Message::Headers(v) => {
                    // --- Synchronisation par en-tetes, stricte en chainage.
                    //
                    // On ne demande **jamais** un corps de bloc avant d'avoir
                    // verifie que la suite d'en-tetes se rattache a la chaine
                    // qu'on connait deja. Sans ce controle, un pair sur une
                    // chaine incompatible fait telecharger indefiniment des
                    // blocs orphelins : c'est le defaut observe en lancant deux
                    // noeuds aux geneses differentes, 29 850 blocs recus pour
                    // une hauteur restee a zero.
                    //
                    // Stricte en chainage, pas en travail : la preuve de
                    // travail n'est pas verifiee ici — elle est a cout memoire,
                    // et la verifier sur deux mille en-tetes couterait plus que
                    // ce qu'elle protegerait. Une suite chainee sur notre tete
                    // se fabrique donc hors ligne, gratuitement. Ce qui borne
                    // ce qu'elle peut nous faire faire, c'est le plafond de
                    // corps en vol par pair (`CORPS_EN_VOL_MAX`) : le travail
                    // n'est verifie qu'a l'arrivee du corps, seize a la fois.
                    let rattache = g.chain.has_block(&v[0].prev_block);

                    let mut continu = rattache;
                    if continu {
                        for f in v.windows(2) {
                            if f[1].prev_block != f[0].block_id() {
                                continu = false;
                                break;
                            }
                        }
                    }

                    if !continu {
                        let incompatible = {
                            let p = g.peers.get_mut(&id);
                            match p {
                                Some(p) => {
                                    p.orphelins_consecutifs += 1;
                                    p.orphelins_consecutifs >= 3
                                }
                                None => true,
                            }
                        };
                        if incompatible {
                            // Ce pair n'est pas sur notre chaine. Insister
                            // couterait a tout le monde et ne menerait nulle part.
                            couper = true;
                        }
                    } else {
                        let Partage {
                            ref chain,
                            ref mut peers,
                            ..
                        } = *g;
                        if let Some(p) = peers.get_mut(&id) {
                            p.orphelins_consecutifs = 0;
                            // Le lot remplace la file : un pair ne repond des
                            // en-tetes qu'a notre demande, et on ne demande la
                            // suite qu'une fois la file ecoulee. C'est ce qui
                            // borne la file a un lot, quoi que le pair pousse.
                            p.corps_a_demander.clear();
                            p.corps_a_demander.extend(
                                v.iter()
                                    .map(|h| h.block_id())
                                    .filter(|bid| !chain.has_block(bid))
                                    .take(CORPS_EN_ATTENTE_MAX),
                            );
                            p.suite_attendue = v.len() >= crate::wire::MAX_HEADERS;
                            p.poursuivre_synchro(id, chain, &mut envois, Instant::now(), false);
                        }
                    }
                }

                Message::Inv(v) => {
                    let mut voulus = Vec::new();
                    let mut blocs = Vec::new();
                    for i in v {
                        match i.kind {
                            InvKind::Block | InvKind::CompactBlock => {
                                if !g.chain.has_block(&i.hash) {
                                    blocs.push(i.hash);
                                }
                            }
                            InvKind::Tx => {
                                if !g.mempool.contains(&i.hash) {
                                    voulus.push(i);
                                }
                            }
                        }
                    }
                    // Les blocs passent par le meme plafond que les en-tetes :
                    // ce qui n'a pas de place en vol attend dans la file, et
                    // un `inv` de cinquante mille identifiants n'inscrit rien
                    // de plus qu'un lot d'en-tetes.
                    if let Some(p) = g.peers.get_mut(&id) {
                        let maintenant = Instant::now();
                        for h in blocs {
                            if p.corps_demandes.contains_key(&h) {
                                continue;
                            }
                            if p.noter_corps_demande(h, maintenant) {
                                voulus.push(InvItem {
                                    kind: InvKind::CompactBlock,
                                    hash: h,
                                });
                            } else {
                                p.mettre_en_attente(h);
                            }
                        }
                    }
                    if !voulus.is_empty() {
                        envois.push(Envoi {
                            peer: id,
                            message: Message::GetData(voulus),
                        });
                    }
                }

                Message::GetData(v) => {
                    // --- Defense : amplification.
                    //
                    // Le handler d'origine servait chaque item tel quel, sans
                    // dedoublonner ni plafonner. Un pair envoyait 20 000 fois le
                    // meme hachage — 660 Kio de requete — et le noeud fabriquait
                    // 20 000 copies du bloc. Mesure de l'audit : 6,8 Mio en
                    // sortie, et pour les blocs compacts un recalcul complet des
                    // identifiants courts a chaque copie. Sur des blocs de 4 Mio,
                    // 80 Gio pour une requete de 660 Kio.
                    //
                    // Trois regles, et aucune n'est negociable : la poignee de
                    // main d'abord, un item servi au plus une fois, et un budget
                    // d'octets en sortie.
                    // On ne sert rien, mais on ne coupe pas : couper punirait une
                    // course benigne. Un pair legitime peut demander un bloc
                    // annonce avant que son `verack` nous soit parvenu, et
                    // rompre la connexion pour cela revient a s'infliger soi-meme
                    // une partition reseau. C'est ce qui s'est produit au premier
                    // essai reel : deux noeuds honnetes se coupaient
                    // immediatement, hauteur bloquee a zero.
                    let mut deja: HashSet<Hash256> = HashSet::new();
                    let mut budget = if handshaked { BUDGET_REPONSE_OCTETS } else { 0 };
                    for i in v.into_iter().take(MAX_ITEMS_SERVIS) {
                        if !deja.insert(i.hash) || budget == 0 {
                            continue;
                        }
                        match i.kind {
                            InvKind::Block => {
                                if let Some(b) = g.chain.block_by_id(&i.hash) {
                                    budget = budget.saturating_sub(b.encode().len());
                                    envois.push(Envoi {
                                        peer: id,
                                        message: Message::Block(Box::new(b)),
                                    });
                                }
                            }
                            InvKind::CompactBlock => {
                                if let Some(b) = g.chain.block_by_id(&i.hash) {
                                    let c = CompactBlock::from_block(&b, maintenant());
                                    budget = budget.saturating_sub(c.encode().len());
                                    envois.push(Envoi {
                                        peer: id,
                                        message: Message::CmpctBlock(Box::new(c)),
                                    });
                                }
                            }
                            InvKind::Tx => {
                                if let Some(t) = g.mempool.get(&i.hash) {
                                    budget = budget.saturating_sub(t.encode().len());
                                    envois.push(Envoi {
                                        peer: id,
                                        message: Message::Tx(Box::new(t.clone())),
                                    });
                                }
                            }
                        }
                    }
                }

                Message::Block(b) => {
                    // --- Defense : un bloc pousse par un inconnu.
                    //
                    // Tous les messages de service exigent la poignee de
                    // main ; un bloc pousse ne l'exigeait pas, et se faisait
                    // hacher, verifier et connecter sur une simple connexion
                    // TCP anonyme. Meme regle pour tous.
                    if handshaked {
                        self.stats.blocs_recus.fetch_add(1, Ordering::Relaxed);
                        couper = !Self::integrer(&mut g, &b, &self.stats, &mut envois, id);
                    }
                }

                Message::CmpctBlock(c) => {
                    self.stats.compacts_recus.fetch_add(1, Ordering::Relaxed);
                    let bid = c.header.block_id();
                    if g.chain.has_block(&bid) {
                        // Deja connu : rien a reconstruire. Mais si c'etait un
                        // corps demande a ce pair, sa place en vol se libere.
                        let Partage {
                            ref chain,
                            ref mut peers,
                            ..
                        } = *g;
                        if let Some(p) = peers.get_mut(&id) {
                            if p.corps_demandes.contains_key(&bid) {
                                p.poursuivre_synchro(id, chain, &mut envois, Instant::now(), true);
                            }
                        }
                    } else if !handshaked || !g.chain.has_block(&c.header.prev_block) {
                        // --- Defense : travail impose par un inconnu.
                        //
                        // Un bloc compact minimal fait environ 170 octets, et
                        // suffisait a declencher un clone integral du reservoir
                        // — jusqu'a 64 Mio — **sous le verrou global**, donc a
                        // serialiser tout le noeud. Repete, il le figeait.
                        //
                        // On refuse desormais avant toute depense : pas de
                        // poignee de main, ou un parent qu'on ne connait pas, et
                        // le message ne coute qu'une comparaison. Un bloc dont
                        // on ignore le parent ne serait de toute facon pas
                        // rattachable.
                    } else {
                        // --- Defense : le budget d'annonces du pair.
                        //
                        // Un corps que nous avons demande a ce pair n'est pas
                        // une annonce : il arrive parce qu'on l'a voulu, et le
                        // plafond de corps en vol borne deja ce qu'on veut.
                        // Tout le reste est une annonce spontanee, et un pair
                        // honnete n'en fait que quelques-unes par minute. Au-
                        // dela, on ne reconstruit pas — ni balayage, ni
                        // allocation — et l'insistance coute des points.
                        let sollicite = g
                            .peers
                            .get(&id)
                            .map(|p| p.corps_demandes.contains_key(&bid))
                            .unwrap_or(false);
                        let permis = sollicite
                            || g.peers
                                .get_mut(&id)
                                .map(|p| {
                                    p.seau_cmpct.autoriser_avec(
                                        1,
                                        Instant::now(),
                                        CMPCT_SEAU_MAX,
                                        CMPCT_DEBIT_PAR_SEC,
                                    )
                                })
                                .unwrap_or(false);
                        if !permis {
                            self.stats.compacts_refuses.fetch_add(1, Ordering::Relaxed);
                            if let Some(p) = g.peers.get_mut(&id) {
                                p.ban_score += MISCONDUCT_CMPCT_REFUSE;
                                if p.ban_score >= BAN_THRESHOLD {
                                    self.stats.pairs_bannis.fetch_add(1, Ordering::Relaxed);
                                    couper = true;
                                }
                            }
                        } else if let Err(e) = g.chain.verifier_entete(&c.header, maintenant()) {
                            // --- Defense : l'en-tete avant le corps (BIP 152).
                            //
                            // Le seau borne le NOMBRE d'annonces ; il ne dit
                            // rien de leur valeur. Une annonce dont l'en-tete
                            // ne porte pas le travail qu'impose sa position
                            // faisait tout de meme fouiller le reservoir et
                            // allouer la reconstruction, sous le verrou.
                            // Desormais : hauteur, finalite, difficulte,
                            // horodatage et travail sont verifies sur les
                            // 160 octets de l'en-tete, et rien d'autre n'est
                            // touche si l'un d'eux echoue. Ce sont les memes
                            // controles que la soumission du bloc entier
                            // appliquerait ; on ne fait que les avancer.
                            //
                            // Un en-tete faux ne vient que de celui qui l'a
                            // fabrique : meme sanction qu'un bloc invalide,
                            // et on ne redemande rien — son corps ne vaut
                            // pas mieux.
                            //
                            // Exception : ce que ce binaire ne sait pas
                            // lire n'est pas une faute du pair.
                            self.stats
                                .compacts_entete_refuse
                                .fetch_add(1, Ordering::Relaxed);
                            match e {
                                crate::chain::ChainError::Validation(v)
                                    if incapacite_locale(&v).is_some() =>
                                {
                                    signaler_l_incapacite(incapacite_locale(&v).expect("garde"));
                                }
                                _ => {
                                    self.stats.blocs_invalides.fetch_add(1, Ordering::Relaxed);
                                    if let Some(p) = g.peers.get_mut(&id) {
                                        p.ban_score += MISCONDUCT_BAD_BLOCK;
                                        if p.ban_score >= BAN_THRESHOLD {
                                            self.stats.pairs_bannis.fetch_add(1, Ordering::Relaxed);
                                            couper = true;
                                        }
                                    }
                                }
                            }
                        } else {
                            self.stats
                                .compacts_reconstruits
                                .fetch_add(1, Ordering::Relaxed);
                            let dispo = Self::reservoir_utile(&g.mempool, &c);
                            match Reconstruction::depuis(&c, &dispo) {
                                Ok(r) if r.is_complete() => {
                                    self.stats
                                        .compacts_sans_aller_retour
                                        .fetch_add(1, Ordering::Relaxed);
                                    match r.finish() {
                                        Ok(b) => {
                                            couper = !Self::integrer(
                                                &mut g,
                                                &b,
                                                &self.stats,
                                                &mut envois,
                                                id,
                                            );
                                        }
                                        Err(_) => {
                                            // Reconstruction plausible mais fausse :
                                            // on redemande le bloc entier.
                                            envois.push(Envoi {
                                                peer: id,
                                                message: Message::GetData(vec![InvItem {
                                                    kind: InvKind::Block,
                                                    hash: bid,
                                                }]),
                                            });
                                        }
                                    }
                                }
                                Ok(r) => {
                                    let indices = r.missing().to_vec();
                                    if let Some(p) = g.peers.get_mut(&id) {
                                        // Au-dela de la borne, la plus ancienne
                                        // cede la place : on ne garde jamais plus
                                        // que ce que le pair peut honnetement
                                        // avoir en vol.
                                        if p.en_attente.len() >= RECONSTRUCTIONS_EN_ATTENTE_MAX {
                                            let plus_ancienne = p
                                                .en_attente
                                                .iter()
                                                .min_by_key(|(_, (cb, _))| cb.header.height)
                                                .map(|(k, _)| *k);
                                            if let Some(k) = plus_ancienne {
                                                p.en_attente.remove(&k);
                                            }
                                        }
                                        p.en_attente.insert(bid, (*c.clone(), indices.clone()));
                                    }
                                    envois.push(Envoi {
                                        peer: id,
                                        message: Message::GetBlockTxn {
                                            block: bid,
                                            indices,
                                        },
                                    });
                                }
                                Err(_) => {
                                    // Rejetee avant meme de chercher les
                                    // transactions : coinbase absente, indice hors
                                    // du bloc, nombre absurde. Une annonce ainsi
                                    // faite ne vient que du pair qui l'a
                                    // fabriquee — a la difference d'une racine de
                                    // Merkle fausse, qui peut naitre d'une
                                    // collision d'identifiants courts. On redemande
                                    // le bloc entier, et le pair perd des points.
                                    if let Some(p) = g.peers.get_mut(&id) {
                                        p.ban_score += MISCONDUCT_CMPCT_REFUSE;
                                        if p.ban_score >= BAN_THRESHOLD {
                                            self.stats.pairs_bannis.fetch_add(1, Ordering::Relaxed);
                                            couper = true;
                                        }
                                    }
                                    envois.push(Envoi {
                                        peer: id,
                                        message: Message::GetData(vec![InvItem {
                                            kind: InvKind::Block,
                                            hash: bid,
                                        }]),
                                    });
                                }
                            }
                        }
                    }
                }

                Message::GetBlockTxn { block, indices } => {
                    // --- Defense : amplification.
                    //
                    // Sans dedoublonnage ni plafond, `indices: [0; 100_000]`
                    // faisait cloner cent mille fois la meme transaction dans
                    // une seule trame. Mesure de l'audit : 100 Kio de requete
                    // pour 15,5 Mio de reponse — une trame qui depassait meme le
                    // MAX_PAYLOAD du protocole, donc illisible par un pair
                    // honnete. Fabriquer une reponse que personne ne peut lire
                    // est la definition d'un vecteur de deni de service.
                    // Meme regle qu'au-dessus : on ne sert rien, on ne coupe pas.
                    let mut deja: HashSet<u32> = HashSet::new();
                    let uniques: Vec<u32> = indices
                        .into_iter()
                        .take(MAX_ITEMS_SERVIS)
                        .filter(|i| deja.insert(*i))
                        .collect();

                    // Le chargement du bloc (ouverture de fichier, lecture,
                    // clone) precedait la poignee de main : un pair anonyme
                    // faisait faire au noeud une lecture disque sous le verrou
                    // global pour zero octet servi. On l'exige d'abord.
                    if handshaked {
                        if let Some(b) = g.chain.block_by_id(&block) {
                            let mut txs = Vec::new();
                            let mut budget = if handshaked { BUDGET_REPONSE_OCTETS } else { 0 };
                            let mut valide = true;
                            for i in &uniques {
                                match b.transactions.get(*i as usize) {
                                    Some(t) => {
                                        let taille = t.encode().len();
                                        if taille > budget {
                                            break;
                                        }
                                        budget -= taille;
                                        txs.push(t.clone());
                                    }
                                    None => {
                                        valide = false;
                                        break;
                                    }
                                }
                            }
                            if valide && !txs.is_empty() {
                                envois.push(Envoi {
                                    peer: id,
                                    message: Message::BlockTxn { block, txs },
                                });
                            }
                        }
                    }
                }

                Message::BlockTxn { block, txs } => {
                    let attente = g
                        .peers
                        .get_mut(&id)
                        .and_then(|p| p.en_attente.remove(&block));
                    if let Some((c, _)) = attente {
                        let dispo = Self::reservoir_utile(&g.mempool, &c);
                        match Reconstruction::depuis(&c, &dispo).and_then(|r| r.complete(txs)) {
                            Ok(b) => {
                                couper = !Self::integrer(&mut g, &b, &self.stats, &mut envois, id);
                            }
                            Err(_) => {
                                envois.push(Envoi {
                                    peer: id,
                                    message: Message::GetData(vec![InvItem {
                                        kind: InvKind::Block,
                                        hash: block,
                                    }]),
                                });
                            }
                        }
                    }
                }

                Message::Tx(t) if !handshaked => {
                    // Une transaction poussee avant la poignee de main ne
                    // coute rien : elle n'est pas lue. Voir `Message::Block`.
                    let _ = t;
                }

                Message::Tx(t) => {
                    self.stats.tx_recues.fetch_add(1, Ordering::Relaxed);
                    // --- Defense : le budget du pair, debite AVANT tout calcul
                    // couteux, et A PROPORTION du travail de verification.
                    //
                    // # Les deux defauts que ce debit ferme
                    //
                    // 1. Rejeu (red-team 8b, 1re campagne). Pour savoir si une
                    //    transaction est inedite, il faut d'abord son identifiant
                    //    `t.txid()`, une empreinte de toute la transaction. En
                    //    rejouant une grosse transaction deja connue, un pair
                    //    forcait ce calcul a chaque message. On debite donc AVANT
                    //    l'empreinte.
                    // 2. Verification (red-team 8b, 2e campagne). Une transaction
                    //    coute une signature post-quantique PAR ENTREE, sous le
                    //    verrou global. Rien ne borne le nombre d'entrees (seul le
                    //    poids le fait, ~271), et l'ancien budget comptait une
                    //    unite PAR TRANSACTION : une transaction a nombreuses
                    //    entrees, ou un flot de telles, tenait le verrou bien
                    //    au-dela. On debite donc a proportion des entrees.
                    //
                    // Le cout est plafonne au seau : la plus grosse transaction
                    // valide draine le budget mais n'est jamais refusee. Au-dela
                    // du budget, on DIFFERE sans bannir — une consolidation a
                    // nombreuses entrees peut etre parfaitement honnete, et
                    // l'ancien bannissement sur depassement pouvait exclure un
                    // relais legitime (un pair ne decroit jamais son score). Le
                    // pair renverra quand son seau se remplit. Une transaction
                    // reellement invalide, elle, est toujours sanctionnee plus
                    // bas (`transaction_invalide_en_soi`).
                    let cout = (t.inputs.len() as u64).clamp(1, TX_SEAU_MAX);
                    let autorise = g
                        .peers
                        .get_mut(&id)
                        .map(|p| {
                            p.seau_tx.autoriser_avec(
                                cout,
                                Instant::now(),
                                TX_SEAU_MAX,
                                TX_DEBIT_PAR_SEC,
                            )
                        })
                        .unwrap_or(false);
                    if !autorise {
                        // Depassement de budget, deux cas distincts :
                        // - petite transaction : le pair envoie trop de MESSAGES,
                        //   c'est un flot. On sanctionne, comme toujours.
                        // - grosse transaction (nombreuses entrees) : un seul
                        //   message a demande beaucoup de travail d'un coup. Elle
                        //   peut etre honnete (consolidation). On DIFFERE sans
                        //   bannir — le pair renverra quand son seau se remplit —
                        //   car un score de ban ne decroit jamais et un relais
                        //   legitime finirait par etre exclu.
                        // Dans les deux cas : ni empreinte, ni verification. Le
                        // travail est borne parce qu'on s'arrete ici.
                        if cout <= SEUIL_FLOT_ENTREES {
                            if let Some(p) = g.peers.get_mut(&id) {
                                p.ban_score += MISCONDUCT_MALFORMED;
                                if p.ban_score >= BAN_THRESHOLD {
                                    self.stats.pairs_bannis.fetch_add(1, Ordering::Relaxed);
                                    couper = true;
                                }
                            }
                        }
                    } else {
                        let txid = t.txid();
                        let inedite = !g.mempool.contains(&txid);
                        let hauteur = g.chain.height();
                        // Sur une reference, jamais sur une copie : dupliquer le
                        // jeu d'UTXO a chaque transaction recue coutait des
                        // centaines de mebioctets par message sur une chaine
                        // reelle, sous le verrou global — un pair bavard suffisait
                        // a figer le noeud. Le reemprunt `&mut *g` separe les
                        // champs de la garde.
                        let partage = &mut *g;
                        let resultat = if inedite {
                            partage
                                .mempool
                                .accept(&t, &partage.chain.utxo, magie_reseau, hauteur)
                        } else {
                            // Deja connue : rien a revalider, rien a relayer.
                            Err(crate::mempool::MempoolError::DejaPresent)
                        };
                        match resultat {
                            Ok(txid) => {
                                let autres: Vec<u64> =
                                    g.peers.keys().copied().filter(|p| *p != id).collect();
                                for p in autres {
                                    envois.push(Envoi {
                                        peer: p,
                                        message: Message::Inv(vec![InvItem {
                                            kind: InvKind::Tx,
                                            hash: txid,
                                        }]),
                                    });
                                }
                            }
                            Err(e) => {
                                // Une transaction refusee n'est pas forcement une
                                // agression : elle peut etre deja connue, ou
                                // depasser une sortie qu'un bloc vient de
                                // consommer. Mais une signature fausse, une clef
                                // qui ne correspond pas au verrou, une forme
                                // incorrecte ou une valeur non conservee ne
                                // viennent que d'un pair qui l'a fabriquee.
                                if Self::transaction_invalide_en_soi(&e) {
                                    if let Some(p) = g.peers.get_mut(&id) {
                                        p.ban_score += MISCONDUCT_BAD_TX;
                                        if p.ban_score >= BAN_THRESHOLD {
                                            self.stats.pairs_bannis.fetch_add(1, Ordering::Relaxed);
                                            couper = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                Message::GetAddr if !handshaked => {
                    // Servir le carnet avant la poignee de main offrait a un
                    // scanner anonyme la totalite des adresses connues, et une
                    // amplification d'environ 600x (24 octets demandes, jusqu'a
                    // 16 Ko rendus) construite sous le verrou global — ce que le
                    // reste du code refuse deja (« rien n'est lu avant la poignee
                    // de main »). On aligne GetAddr sur GetHeaders. Red-team 8b.
                }

                Message::GetAddr => {
                    // Meme apres la poignee de main, la reponse est bornee par le
                    // seau : sa taille reelle est debitee, de sorte qu'une rafale
                    // de `getaddr` ne se transforme pas en amplification de bande
                    // passante sous le verrou.
                    let mut v = g.carnet.a_annoncer(crate::wire::MAX_ADDR);
                    if v.len() < crate::wire::MAX_ADDR {
                        for p in g.peers.values() {
                            if let SocketAddr::V4(a) = p.addr {
                                let n = crate::wire::NetAddr {
                                    ip: a.ip().octets(),
                                    port: a.port(),
                                    last_seen: maintenant(),
                                };
                                if !v.iter().any(|x| x.ip == n.ip && x.port == n.port) {
                                    v.push(n);
                                }
                            }
                            if v.len() >= crate::wire::MAX_ADDR {
                                break;
                            }
                        }
                    }
                    if !v.is_empty() {
                        // ~20 octets par adresse ; on debite la taille servie du
                        // seau d'amorce du pair. Au-dela du budget, on ne repond
                        // pas : le pair attend, le noeud ne s'epuise pas.
                        let cout = (v.len() as u64).saturating_mul(20);
                        let autorise = g
                            .peers
                            .get_mut(&id)
                            .map(|p| p.seau_amorce.autoriser(cout, Instant::now()))
                            .unwrap_or(false);
                        if autorise {
                            envois.push(Envoi {
                                peer: id,
                                message: Message::Addr(v),
                            });
                        }
                    }
                }

                Message::Addr(v) => {
                    // Les adresses arrivent d'un inconnu : le carnet applique
                    // ses propres regles — routabilite, plafond par groupe — et
                    // rien d'autre n'est fait de ce message. En particulier, on
                    // ne compose jamais une adresse parce qu'un pair l'a
                    // suggeree : c'est la boucle de maintenance qui decide.
                    let maintenant = maintenant();
                    for a in v.into_iter().take(crate::wire::MAX_ADDR) {
                        // Une adresse annoncee comme vue dans le futur serait un
                        // moyen de passer devant toutes les autres.
                        let mut a = a;
                        a.last_seen = a.last_seen.min(maintenant);
                        g.carnet.ajouter(a, maintenant);
                    }
                }
                Message::Reject { .. } => {}

                // --- Synchronisation rapide : servir une amorce.
                //
                // Comme tout message couteux, ces reponses exigent la poignee de
                // main : servir un jeu d'UTXO entier a une connexion anonyme
                // ramenerait une amplification au prix d'un `connect()`.
                Message::GetAmorce => {
                    if handshaked {
                        rafraichir_amorce(&mut g);
                        if let Some(c) = &g.amorce_cache {
                            envois.push(Envoi {
                                peer: id,
                                message: Message::AmorceInfo {
                                    hauteur: c.hauteur,
                                    tete: c.tete,
                                    empreinte: c.empreinte,
                                    taille: c.octets.len() as u64,
                                    tranches: crate::synchro_rapide::nombre_de_tranches(
                                        c.octets.len(),
                                    ),
                                },
                            });
                        }
                        // Pas d'amorce (chaine trop courte) : on ne repond rien.
                        // Le demandeur ira voir ailleurs.
                    }
                }
                Message::GetAmorceTranche { index } => {
                    if handshaked {
                        rafraichir_amorce(&mut g);
                        // On mesure d'abord, on copie ensuite : le seau doit
                        // etre consulte **avant** le mebioctet de copie, sinon
                        // il ne protegerait de rien.
                        let taille = g
                            .amorce_cache
                            .as_ref()
                            .map(|c| crate::synchro_rapide::tranche(&c.octets, index).len())
                            .unwrap_or(0);
                        let autorise = taille > 0
                            && g.peers
                                .get_mut(&id)
                                .map(|p| p.seau_amorce.autoriser(taille as u64, Instant::now()))
                                .unwrap_or(false);
                        if autorise {
                            if let Some(c) = &g.amorce_cache {
                                let tr = crate::synchro_rapide::tranche(&c.octets, index);
                                envois.push(Envoi {
                                    peer: id,
                                    message: Message::AmorceTranche {
                                        index,
                                        donnees: tr.to_vec(),
                                    },
                                });
                            }
                        }
                        // Au-dela du debit accorde, on ne sert rien et on ne
                        // coupe pas : un client honnete ralentit et reprend.
                    }
                }
                // Un serveur ne recoit pas de reponses d'amorce : on les ignore.
                Message::AmorceInfo { .. } | Message::AmorceTranche { .. } => {}
            }
        } // --- verrou relache ici, avant toute ecriture reseau ---

        for e in envois {
            let sortie = {
                let mut g = self.partage.lock().unwrap();
                // Un corps demande est note, pour qu'on sache s'il arrive —
                // dans la limite des places en vol, comme partout.
                if let Message::GetData(items) = &e.message {
                    let maintenant = Instant::now();
                    if let Some(p) = g.peers.get_mut(&e.peer) {
                        for i in items.iter().filter(|i| i.kind == InvKind::CompactBlock) {
                            p.noter_corps_demande(i.hash, maintenant);
                        }
                    }
                }
                g.peers.get(&e.peer).map(|p| p.sortie.clone())
            };
            if let Some(s) = sortie {
                let _ = ecrire(&s, &e.message, self.magie);
            }
        }

        !couper
    }

    /// Soumet un bloc a la chaine et prepare sa diffusion.
    ///
    /// Rend `false` si le pair merite d'etre coupe.
    /// Transactions du reservoir **effectivement utiles** a ce bloc compact.
    ///
    /// La version precedente clonait tout le reservoir a chaque annonce. Ici on
    /// ne retient que les transactions dont l'identifiant court figure dans
    /// l'annonce : le cout memoire devient celui d'un bloc, pas celui du
    /// reservoir. Le parcours reste lineaire, mais un parcours ne se compare pas
    /// a soixante-quatre megaoctets de copies.
    fn reservoir_utile(mempool: &Mempool, c: &CompactBlock) -> HashMap<Hash256, Transaction> {
        let (k0, k1) = crate::compact::short_id_key(&c.header, c.nonce);
        let vises: HashSet<u64> = c.short_ids.iter().copied().collect();
        let mut m = HashMap::with_capacity(vises.len());
        for t in mempool.txids() {
            if vises.contains(&crate::compact::short_id(k0, k1, &t)) {
                if let Some(tx) = mempool.get(&t) {
                    m.insert(t, tx.clone());
                }
            }
        }
        m
    }

    fn integrer(
        g: &mut Partage,
        b: &Block,
        stats: &Stats,
        envois: &mut Vec<Envoi>,
        source: u64,
    ) -> bool {
        let bid = b.header.block_id();
        if g.chain.has_block(&bid) {
            Self::corps_arrive(g, source, envois);
            return true;
        }
        match g.chain.submit(b, maintenant()) {
            Ok(Accept::Prolonge) | Ok(Accept::Reorganise { .. }) => {
                stats.blocs_acceptes.fetch_add(1, Ordering::Relaxed);
                // Un bloc accepte est un bloc conserve. Avant, seuls les blocs
                // que ce noeud minait lui-meme atteignaient le disque.
                if let Some(j) = &g.journal {
                    j.consigner(b);
                }
                g.mempool.on_block_connected(b);
                let hauteur = g.chain.height();
                // Meme regle qu'a la reception d'une transaction : le reservoir
                // lit le jeu d'UTXO en place, il ne le recopie pas.
                g.mempool.revalidate(&g.chain.utxo, g.network, hauteur);

                // Diffusion : annonce compacte, pas le bloc entier.
                //
                // Uniquement aux pairs dont la poignee de main est terminee.
                // Annoncer plus tot cree une course : le pair demande le bloc,
                // et sa requete nous parvient avant son `verack`.
                let autres: Vec<u64> = g
                    .peers
                    .iter()
                    .filter(|(p, e)| **p != source && e.handshaked)
                    .map(|(p, _)| *p)
                    .collect();
                for p in autres {
                    envois.push(Envoi {
                        peer: p,
                        message: Message::Inv(vec![InvItem {
                            kind: InvKind::CompactBlock,
                            hash: bid,
                        }]),
                    });
                }
                Self::corps_arrive(g, source, envois);
                true
            }
            Ok(Accept::BrancheLaterale) => {
                // Une branche laterale est du travail valide : si elle
                // l'emporte plus tard, il faudra ses corps. Ne pas les ecrire
                // rendait toute reorganisation impossible apres un redemarrage.
                if let Some(j) = &g.journal {
                    j.consigner(b);
                }
                Self::corps_arrive(g, source, envois);
                true
            }
            Ok(_) => {
                Self::corps_arrive(g, source, envois);
                true
            }
            Err(crate::chain::ChainError::ParentInconnu(_)) => {
                stats.blocs_orphelins.fetch_add(1, Ordering::Relaxed);
                // Un bloc dont on ignore le parent ne devrait plus arriver : la
                // synchronisation stricte par en-tetes ne demande un corps
                // qu'apres avoir verifie le rattachement. Redemander des
                // en-tetes ici recreerait la boucle infinie qu'on vient de
                // corriger. On ignore, sans punir : ce peut etre une course
                // benigne entre deux annonces.
                true
            }
            Err(crate::chain::ChainError::Validation(v)) if incapacite_locale(&v).is_some() => {
                // Le bloc n'est pas faux : c'est ce binaire qui ne sait pas
                // le lire. Le pair n'y est pour rien, on ne le sanctionne
                // pas ; on le dit une fois a l'operateur, et on ne compte pas
                // le bloc comme invalide — il ne l'est peut-etre pas.
                signaler_l_incapacite(incapacite_locale(&v).expect("garde"));
                true
            }
            Err(_) => {
                stats.blocs_invalides.fetch_add(1, Ordering::Relaxed);
                if let Some(p) = g.peers.get_mut(&source) {
                    p.ban_score += MISCONDUCT_BAD_BLOCK;
                    if p.ban_score >= BAN_THRESHOLD {
                        stats.pairs_bannis.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }
                }
                true
            }
        }
    }

    /// Un corps est arrive d'un pair : sa place en vol se libere, et la
    /// synchronisation avec ce pair reprend la ou elle en etait.
    ///
    /// C'est le pendant du plafond de corps en vol : sans cette reprise, une
    /// synchronisation s'arreterait apres les seize premiers corps.
    fn corps_arrive(g: &mut Partage, source: u64, envois: &mut Vec<Envoi>) {
        let Partage {
            ref chain,
            ref mut peers,
            ..
        } = *g;
        if let Some(p) = peers.get_mut(&source) {
            p.poursuivre_synchro(source, chain, envois, Instant::now(), true);
        }
    }

    /// Annonce un bloc qu'on vient de miner soi-meme.
    pub fn announce_block(&self, b: &Block) {
        let bid = b.header.block_id();
        let cibles: Vec<Arc<Mutex<TcpStream>>> = {
            let g = self.partage.lock().unwrap();
            // Seuls les pairs dont la poignee de main est achevee : annoncer
            // plus tot provoquerait une demande qui nous arriverait avant leur
            // `verack`, et qu'on ne saurait pas servir.
            g.peers
                .values()
                .filter(|p| p.handshaked)
                .map(|p| p.sortie.clone())
                .collect()
        };
        let m = Message::Inv(vec![InvItem {
            kind: InvKind::CompactBlock,
            hash: bid,
        }]);
        for s in cibles {
            let _ = ecrire(&s, &m, self.magie);
        }
    }

    /// Diffuse une transaction locale.
    /// Envoie un message a un pair, hors du verrou, en notant les corps
    /// demandes comme le fait `traiter`.
    fn envoyer_a(&self, id: u64, m: &Message) {
        let sortie = {
            let mut g = self.partage.lock().unwrap();
            if let Message::GetData(items) = m {
                let maintenant = Instant::now();
                if let Some(p) = g.peers.get_mut(&id) {
                    for i in items.iter().filter(|i| i.kind == InvKind::CompactBlock) {
                        p.noter_corps_demande(i.hash, maintenant);
                    }
                }
            }
            g.peers.get(&id).map(|p| p.sortie.clone())
        };
        if let Some(s) = sortie {
            let _ = ecrire(&s, m, self.magie);
        }
    }

    pub fn announce_tx(&self, txid: Hash256) {
        let cibles: Vec<Arc<Mutex<TcpStream>>> = {
            let g = self.partage.lock().unwrap();
            g.peers
                .values()
                .filter(|p| p.handshaked)
                .map(|p| p.sortie.clone())
                .collect()
        };
        let m = Message::Inv(vec![InvItem {
            kind: InvKind::Tx,
            hash: txid,
        }]);
        for s in cibles {
            let _ = ecrire(&s, &m, self.magie);
        }
    }
}

fn ecrire(flux: &Arc<Mutex<TcpStream>>, m: &Message, magie: [u8; 4]) -> std::io::Result<()> {
    let trame = m.frame(magie);
    let mut g = flux.lock().unwrap();
    g.write_all(&trame)?;
    g.flush()
}

#[cfg(test)]
mod tests {
    /// « Je ne sais pas verifier » n'est pas une faute du pair.
    ///
    /// Un bloc ou une transaction dont la signature releve d'un schema connu
    /// mais absent de cette compilation ne coute aucun point au pair. Une
    /// signature fausse, elle, en coute toujours : la distinction ne peut
    /// pas servir a inonder gratuitement.
    #[test]
    fn l_incapacite_locale_n_est_pas_une_faute_du_pair() {
        use crate::mempool::MempoolError as M;
        use crate::sig::{SchemeId, VerifyError};
        use crate::validate::ValidationError as V;
        let locale = V::Signature(VerifyError::SchemaNonDisponible(SchemeId::MlDsa87));
        let fausse = V::Signature(VerifyError::SignatureInvalide);
        assert_eq!(super::incapacite_locale(&locale), Some(SchemeId::MlDsa87));
        assert_eq!(super::incapacite_locale(&fausse), None);
        let (locale, fausse) = (M::Validation(locale), M::Validation(fausse));
        assert!(!super::Node::transaction_invalide_en_soi(&locale));
        assert!(super::Node::transaction_invalide_en_soi(&fausse));
    }

    /// ML-DSA est compile par defaut : `cargo build` nu donne un noeud qui
    /// sait verifier le reseau principal. Le noyau sans dependance reste
    /// accessible par `--no-default-features`, et il refuse alors de
    /// demarrer la ou il ne sait pas verifier.
    #[test]
    fn ml_dsa_est_compile_par_defaut() {
        let manifeste = include_str!("../Cargo.toml");
        assert!(
            manifeste.contains("default = [\"mldsa\"]"),
            "la feature mldsa doit etre dans les features par defaut"
        );
    }
    use super::*;
    use crate::chain::genesis_block;
    use crate::consensus::TARGET_BLOCK_SECS;
    use crate::sig::SchemeId;

    const RESEAU: Network = Network::Regtest;
    const ESSAIS: u64 = 5_000_000;

    fn noeud() -> Node {
        let g = genesis_block(RESEAU);
        Node::new(RESEAU, Chain::new(RESEAU, g))
    }

    /// Deux noeuds partant de la meme genese.
    fn paire() -> (Node, Node) {
        let g = genesis_block(RESEAU);
        (
            Node::new(RESEAU, Chain::new(RESEAU, g.clone())),
            Node::new(RESEAU, Chain::new(RESEAU, g)),
        )
    }

    fn miner(n: &Node, combien: usize) {
        for _ in 0..combien {
            let b = n.with_chain(|c| {
                let t = c.tip().time + TARGET_BLOCK_SECS;
                c.mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            });
            if let Some(b) = b {
                n.with_chain(|c| {
                    let t = b.header.time + 1;
                    c.connect(&b, t).expect("connexion locale")
                });
            }
        }
    }

    /// Attend qu'une condition devienne vraie, sans bloquer indefiniment.
    fn attendre(mut cond: impl FnMut() -> bool, secondes: u64) -> bool {
        let debut = std::time::Instant::now();
        while debut.elapsed() < Duration::from_secs(secondes) {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        cond()
    }

    /// La decouverte de pairs, de bout en bout : A connait des adresses, B se
    /// connecte a A, et B les apprend sans qu'on les lui ait donnees.
    #[test]
    fn un_pair_apprend_les_adresses_de_son_voisin() {
        let (a, b) = paire();
        // A a entendu parler de trois pairs, dans trois plages distinctes.
        let connues = [
            crate::wire::NetAddr {
                ip: [93, 184, 216, 34],
                port: 21021,
                last_seen: 1_000,
            },
            crate::wire::NetAddr {
                ip: [8, 8, 8, 8],
                port: 21021,
                last_seen: 1_000,
            },
            crate::wire::NetAddr {
                ip: [1, 1, 1, 1],
                port: 21021,
                last_seen: 1_000,
            },
        ];
        assert_eq!(a.seed_addresses(&connues), 3);
        assert_eq!(b.address_count(), 0);

        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        b.connect(addr).expect("connexion");

        assert!(
            attendre(|| b.address_count() >= 3, 10),
            "B n'a pas appris les adresses de A : {}",
            b.address_count()
        );

        // Et il ne proposera jamais deux adresses du meme groupe.
        let choix = b.addresses_to_try(10);
        let groupes: std::collections::HashSet<[u8; 2]> =
            choix.iter().map(|x| crate::addr::groupe(x.ip)).collect();
        assert_eq!(groupes.len(), choix.len());

        a.shutdown();
        b.shutdown();
    }

    /// Un pair malveillant qui annonce mille adresses d'une seule plage ne doit
    /// pas pouvoir occuper le carnet de son voisin.
    #[test]
    fn une_inondation_d_adresses_ne_remplit_pas_le_carnet() {
        let n = noeud();
        let mut flot = Vec::new();
        for i in 0..1_000u32 {
            flot.push(crate::wire::NetAddr {
                ip: [203, 0, (i >> 8) as u8, i as u8],
                port: 21021,
                last_seen: 1_000 + u64::from(i),
            });
        }
        n.seed_addresses(&flot);
        assert!(
            n.address_count() <= crate::addr::MAX_PAR_GROUPE,
            "{} adresses retenues",
            n.address_count()
        );
        assert_eq!(n.addresses_to_try(50).len(), 1);
    }

    #[test]
    fn un_noeud_ecoute_et_accepte_une_connexion() {
        let a = noeud();
        let b = noeud();
        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        b.connect(addr).expect("connexion");

        assert!(
            attendre(|| a.peer_count() == 1 && b.peer_count() == 1, 5),
            "les deux noeuds auraient du se voir"
        );
        a.shutdown();
        b.shutdown();
    }

    /// Une connexion entrante ne compte pas comme sortante. C'est l'invariant
    /// qui protege de l'eclipse : la boucle de maintien vise un nombre de pairs
    /// **sortants** (choisis dans le carnet, avec sa diversite de groupes) ; si
    /// une connexion entrante les comptait, un attaquant remplirait nos places
    /// depuis une seule IP et nous n'irions jamais chercher de pair diversifie.
    #[test]
    fn une_connexion_entrante_ne_compte_pas_comme_sortante() {
        let a = noeud();
        let b = noeud();
        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        b.connect(addr).expect("connexion");

        assert!(
            attendre(|| a.peer_count() == 1 && b.peer_count() == 1, 5),
            "les deux noeuds auraient du se voir"
        );

        // b a initie : c'est une sortante pour b. a l'a acceptee : une entrante
        // pour a, qui ne doit donc compter aucun pair sortant.
        assert_eq!(b.peer_count_sortants(), 1, "b a initie la connexion");
        assert_eq!(
            a.peer_count_sortants(),
            0,
            "a n'a fait qu'accepter : aucune sortante, sinon l'eclipse passe"
        );
        a.shutdown();
        b.shutdown();
    }

    /// Le seau borne ce qu'un pair extrait du service d'amorce.
    ///
    /// Le temps est fourni par l'epreuve, jamais lu d'une horloge : une regle de
    /// debit qu'on ne peut eprouver qu'en dormant est une regle mal eprouvee.
    #[test]
    fn le_seau_d_amorce_borne_le_debit() {
        let t0 = Instant::now();
        let mut seau = SeauAmorce::new(t0);

        // La reserve initiale se sert d'un coup, et pas un octet de plus.
        assert!(
            seau.autoriser(AMORCE_SEAU_MAX, t0),
            "la reserve initiale doit etre servie"
        );
        assert!(
            !seau.autoriser(1, t0),
            "au-dela de la reserve, plus rien n'est servi sans attendre"
        );

        // Une seconde ecoulee credite exactement le debit accorde.
        let t1 = t0 + Duration::from_secs(1);
        assert!(
            seau.autoriser(AMORCE_DEBIT_PAR_SEC, t1),
            "une seconde doit crediter le debit d'une seconde"
        );
        assert!(!seau.autoriser(1, t1), "et rien de plus");

        // Le seau ne deborde pas : une longue absence ne donne pas un credit
        // illimite, sinon il suffirait d'attendre pour tout reprendre d'un coup.
        let t2 = t1 + Duration::from_secs(3600);
        assert!(seau.autoriser(AMORCE_SEAU_MAX, t2), "la contenance est due");
        assert!(
            !seau.autoriser(1, t2),
            "mais jamais plus que la contenance, quelle que soit l'attente"
        );
    }

    /// Un nouveau venu honnete ne doit pas etre gene : telecharger une amorce
    /// entiere est une operation qu'il ne fait qu'une fois.
    #[test]
    fn le_seau_laisse_passer_un_telechargement_honnete() {
        let t0 = Instant::now();
        let mut seau = SeauAmorce::new(t0);
        let tranche = crate::synchro_rapide::TAILLE_TRANCHE as u64;

        // Une amorce de 64 Mio, demandee tranche par tranche au rythme ou le
        // reseau les livre : tout passe.
        let mut servies = 0u32;
        let mut t = t0;
        for _ in 0..64 {
            if seau.autoriser(tranche, t) {
                servies += 1;
            }
            // Un demi-seconde entre deux tranches : le debit reel d'un lien
            // ordinaire, largement sous la limite accordee.
            t += Duration::from_millis(500);
        }
        assert_eq!(servies, 64, "un telechargement honnete ne doit rien perdre");
    }

    /// L'abus, lui, est ramene au debit accorde : la boucle serree ne rapporte
    /// plus rien.
    #[test]
    fn le_seau_etrangle_une_boucle_serree() {
        let t0 = Instant::now();
        let mut seau = SeauAmorce::new(t0);
        let tranche = crate::synchro_rapide::TAILLE_TRANCHE as u64;

        // Mille demandes dans le meme instant, comme le ferait un attaquant.
        let mut servies = 0u32;
        for _ in 0..1_000 {
            if seau.autoriser(tranche, t0) {
                servies += 1;
            }
        }
        let plafond = (AMORCE_SEAU_MAX / tranche) as u32;
        assert_eq!(
            servies, plafond,
            "une boucle serree ne doit obtenir que la reserve, soit {plafond} tranches"
        );
        assert!(
            servies < 1_000,
            "sans le seau, les mille demandes auraient toutes ete servies"
        );
    }

    /// Un `VerAck` seul, sans `Version` prealable, ne doit pas completer la
    /// poignee de main : sinon un pair sauterait la negociation et le controle
    /// de nonce, et ouvrirait l'acces aux messages couteux avec une seule trame.
    #[test]
    fn un_verack_seul_ne_complete_pas_la_poignee() {
        use std::io::Write;
        let a = noeud();
        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        let magie = magic_for(RESEAU);

        let mut s = std::net::TcpStream::connect(addr).expect("connexion");
        s.write_all(&Message::VerAck.frame(magie)).unwrap();
        s.flush().unwrap();

        assert!(
            attendre(|| a.peer_count() == 1, 5),
            "la connexion TCP doit etre acceptee"
        );
        // Mais jamais marquee handshaked sur un verack orphelin.
        assert!(
            !attendre(
                || {
                    let g = a.partage.lock().unwrap();
                    g.peers.values().any(|p| p.handshaked)
                },
                2
            ),
            "un verack sans version ne doit pas completer la poignee de main"
        );
        a.shutdown();
    }

    /// Un pair d'une version anterieure du protocole est coupe a la poignee
    /// de main : il ne valide pas les memes regles, et l'echanger avec lui
    /// ne produirait que des refus mutuels.
    #[test]
    fn un_pair_d_une_version_anterieure_est_coupe_a_la_poignee() {
        use std::io::Write;
        let a = noeud();
        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        let magie = magic_for(RESEAU);

        let mut s = std::net::TcpStream::connect(addr).expect("connexion");
        let ancien = Message::Version {
            version: MIN_PROTOCOL_VERSION - 1,
            timestamp: maintenant(),
            nonce: 0x1234_5678,
            user_agent: "q21:0.1".into(),
            start_height: 0,
        };
        s.write_all(&ancien.frame(magie)).unwrap();
        s.flush().unwrap();

        // Le pair est accepte au niveau TCP puis coupe : il ne reste pas.
        assert!(
            attendre(|| a.peer_count() == 0, 5) && {
                std::thread::sleep(std::time::Duration::from_millis(300));
                a.peer_count() == 0
            },
            "un pair d'une version anterieure doit etre coupe"
        );
        assert!(
            !{
                let g = a.partage.lock().unwrap();
                g.peers.values().any(|p| p.handshaked)
            },
            "et jamais marque handshaked"
        );
        a.shutdown();
    }

    #[test]
    fn la_poignee_de_main_annonce_la_hauteur() {
        let (a, b) = paire();
        miner(&a, 3);
        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        b.connect(addr).expect("connexion");

        assert!(
            attendre(
                || {
                    let g = b.partage.lock().unwrap();
                    g.peers
                        .values()
                        .any(|p| p.handshaked && p.start_height == 3)
                },
                5
            ),
            "b aurait du apprendre que a est a la hauteur 3"
        );
        a.shutdown();
        b.shutdown();
    }

    /// Un pair muet finit par etre coupe, et sa place liberee.
    ///
    /// # Le defaut verrouille ici
    ///
    /// La boucle de lecture posait un delai de 120 secondes sur la socket et
    /// traitait son expiration par `continue` : elle recommencait a attendre,
    /// indefiniment. Un pair qui cesse d'emettre n'etait donc jamais retire.
    ///
    /// Consequence, observee sur un vrai portable : on referme l'ecran du
    /// MacBook, la connexion meurt sans qu'aucun FIN ni RST n'arrive, et le
    /// noeud garde un pair fantome. Le compte de pairs reste a un, la boucle de
    /// maintien — qui ne cherche que s'il manque des pairs — n'a rien a faire,
    /// et la chaine s'arrete a la hauteur ou elle en etait. Elle y est restee.
    ///
    /// Sur un reseau public, c'est aussi une voie d'eclipse : ouvrir des
    /// connexions puis se taire suffit a occuper toutes les places.
    ///
    /// L'epreuve ne peut pas attendre cent secondes : elle vieillit la derniere
    /// reception a la main, ce qui est exactement ce que le temps aurait fait.
    #[test]
    fn un_pair_muet_est_coupe_et_sa_place_liberee() {
        let (a, b) = paire();
        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        b.connect(addr).expect("connexion");
        assert!(attendre(|| b.peer_count() == 1, 20), "pas de pair");

        // Rien ne doit bouger tant que le pair parle.
        assert_eq!(b.entretenir_pairs(), 0, "un pair vivant a ete coupe");
        assert_eq!(b.peer_count(), 1);

        // Le temps passe, et plus rien n'arrive.
        {
            let mut g = b.partage.lock().unwrap();
            let ancien = Instant::now()
                .checked_sub(SILENCE_MAX + Duration::from_secs(5))
                .expect("horloge");
            for p in g.peers.values_mut() {
                p.derniere_reception = ancien;
            }
        }
        assert_eq!(b.entretenir_pairs(), 1, "le pair muet n'a pas ete coupe");
        assert_eq!(
            b.peer_count(),
            0,
            "la place du pair muet n'a pas ete liberee : le noeud croira \
             toujours avoir un pair, et ne cherchera personne"
        );

        // Et la place liberee se reprend : c'est tout l'objet de l'operation.
        b.connect(addr).expect("reconnexion");
        assert!(attendre(|| b.peer_count() == 1, 20), "pas de reconnexion");

        a.shutdown();
        b.shutdown();
    }

    /// Un silence plus court declenche un `Ping`, sans couper.
    ///
    /// Couper au premier silence serait aussi faux que ne jamais couper : une
    /// liaison lente, un pair occupe, et l'on se retrouve a rouvrir des
    /// connexions sans arret. On demande d'abord au pair de se manifester.
    #[test]
    fn un_silence_bref_interroge_le_pair_sans_le_couper() {
        let (a, b) = paire();
        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        b.connect(addr).expect("connexion");
        assert!(attendre(|| b.peer_count() == 1, 20), "pas de pair");

        {
            let mut g = b.partage.lock().unwrap();
            let ancien = Instant::now()
                .checked_sub(PING_APRES + Duration::from_secs(2))
                .expect("horloge");
            for p in g.peers.values_mut() {
                p.derniere_reception = ancien;
            }
        }
        assert_eq!(
            b.entretenir_pairs(),
            0,
            "un pair juste silencieux a ete coupe"
        );
        assert_eq!(b.peer_count(), 1);

        // Le pair repond : la reponse le remet en vie, et le prochain entretien
        // ne trouve plus rien a couper.
        assert!(
            attendre(
                || {
                    let g = b.partage.lock().unwrap();
                    g.peers
                        .values()
                        .all(|p| p.derniere_reception.elapsed() < PING_APRES)
                },
                20
            ),
            "le pair n'a pas repondu au Ping"
        );

        a.shutdown();
        b.shutdown();
    }

    /// Le test qui prouve que la phase 4 fonctionne.
    #[test]
    fn deux_noeuds_se_synchronisent_sur_tcp() {
        let (a, b) = paire();
        miner(&a, 12);
        assert_eq!(a.height(), 12);
        assert_eq!(b.height(), 0);

        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        b.connect(addr).expect("connexion");

        assert!(
            attendre(|| b.height() == 12, 30),
            "b est reste a la hauteur {}",
            b.height()
        );
        assert_eq!(b.tip_id(), a.tip_id(), "les tetes doivent coincider");
        assert_eq!(
            b.with_chain(|c| c.utxo.total_value()),
            a.with_chain(|c| c.utxo.total_value()),
            "les jeux d'UTXO doivent coincider"
        );
        // Preuve que les octets ont bien transite : sans cela, un test qui
        // passerait par accident ne prouverait rien.
        //
        // Le compteur regarde les blocs **compacts** : depuis que la
        // synchronisation par en-tetes demande des annonces compactes plutot que
        // des corps entiers, plus aucun message `block` ne circule en rattrapage.
        // C'est le comportement voulu, et cette assertion le verrouille.
        let compacts = b.stats.compacts_recus.load(Ordering::Relaxed);
        assert!(
            compacts >= 12,
            "seulement {compacts} annonces compactes recues sur le fil"
        );
        assert!(
            b.stats.blocs_acceptes.load(Ordering::Relaxed) >= 12,
            "blocs recus mais non acceptes"
        );
        // Un noeud vierge n'a rien en mempool : chaque bloc a donc exige un
        // aller-retour. Le gain du relais compact se mesure en regime etabli,
        // pas au rattrapage initial.
        assert_eq!(
            b.stats.compacts_sans_aller_retour.load(Ordering::Relaxed),
            12,
            "les blocs sans transaction se reconstruisent sans aller-retour"
        );
        a.shutdown();
        b.shutdown();
    }

    /// Le plafond de corps en vol ne doit pas arreter la synchronisation.
    ///
    /// Avec seize corps en vol au plus par pair, un rattrapage de plus de
    /// seize blocs ne tient que si chaque corps recu fait demander le suivant.
    /// Trois plafonds et demi : assez pour traverser plusieurs vagues, et pour
    /// que la redemande d'en-tetes a file ecoulee soit exercee aussi.
    #[test]
    fn la_synchro_se_poursuit_au_dela_des_corps_en_vol() {
        let (a, b) = paire();
        let cible = CORPS_EN_VOL_MAX * 3 + CORPS_EN_VOL_MAX / 2;
        miner(&a, cible);
        assert_eq!(a.height(), cible as u64);

        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        b.connect(addr).expect("connexion");

        assert!(
            attendre(|| b.height() == cible as u64, 30),
            "b est reste a la hauteur {} sur {cible} : la synchronisation \
             s'est arretee au plafond de corps en vol",
            b.height()
        );
        assert_eq!(b.tip_id(), a.tip_id(), "les tetes doivent coincider");
        // Et jamais plus que le plafond en vol vers ce pair.
        let en_vol = {
            let g = b.partage.lock().unwrap();
            g.peers
                .values()
                .map(|p| p.corps_demandes.len())
                .max()
                .unwrap_or(0)
        };
        assert!(en_vol <= CORPS_EN_VOL_MAX, "{en_vol} corps en vol");
        a.shutdown();
        b.shutdown();
    }

    /// Un pair factice, pour eprouver l'admission sur des adresses qu'une
    /// machine sans IPv6 ne peut pas ouvrir. La socket est reelle — un
    /// `Peer` en tient une — mais l'adresse est celle qu'on veut.
    fn pair_factice(n: &Node, id: u64, addr: SocketAddr, sortant: bool) {
        let ecoute = TcpListener::bind("127.0.0.1:0").expect("ecoute");
        let flux = TcpStream::connect(ecoute.local_addr().unwrap()).expect("socket");
        let mut g = n.partage.lock().unwrap();
        g.peers.insert(
            id,
            Peer {
                addr,
                sortie: Arc::new(Mutex::new(flux)),
                sortant,
                seau_amorce: SeauAmorce::new(Instant::now()),
                seau_tx: SeauAmorce::pour_transactions(Instant::now()),
                seau_cmpct: SeauAmorce::pour_annonces_compactes(Instant::now()),
                corps_demandes: HashMap::new(),
                corps_a_demander: VecDeque::new(),
                suite_attendue: false,
                version_recue: false,
                version_envoyee: sortant,
                handshaked: false,
                ban_score: 0,
                start_height: 0,
                en_attente: HashMap::new(),
                orphelins_consecutifs: 0,
                derniere_reception: Instant::now(),
                ping_en_attente: None,
                instant_connexion: Instant::now(),
            },
        );
    }

    /// La diversite de groupe s'applique aussi aux entrants IPv6.
    ///
    /// Le plafond par groupe n'etait calcule que pour l'IPv4 : un seul `/64`
    /// pouvait occuper toutes les places entrantes d'un noeud ecoutant en
    /// IPv6. Le bac a sable n'ouvre pas de socket IPv6 : on eprouve la regle
    /// d'admission sur des pairs a l'adresse choisie.
    #[test]
    fn l_admission_borne_aussi_les_entrants_ipv6() {
        let a = noeud();
        let meme_64 =
            |k: u16| -> SocketAddr { format!("[2001:db8:1:2::{k:x}]:21021").parse().unwrap() };
        for k in 0..ENTRANTS_PAR_GROUPE as u16 {
            assert!(
                a.admettre_entrant(Some(meme_64(k + 1))),
                "la {}e connexion du /64 doit passer",
                k + 1
            );
            pair_factice(&a, 100 + u64::from(k), meme_64(k + 1), false);
        }
        assert!(
            !a.admettre_entrant(Some(meme_64(0x99))),
            "un /64 entier doit etre borne a {ENTRANTS_PAR_GROUPE} entrants, \
             comme un /16 en IPv4"
        );
        // Un autre /64 du meme /48 est un autre groupe.
        let autre_64: SocketAddr = "[2001:db8:1:3::1]:21021".parse().unwrap();
        assert!(
            a.admettre_entrant(Some(autre_64)),
            "un autre /64 doit rester admis"
        );
        // Une IPv4 presentee en IPv6 compte avec les IPv4 de son /16, pas dans
        // un /64 commun a tout l'Internet v4.
        for k in 0..ENTRANTS_PAR_GROUPE as u16 {
            let v4: SocketAddr = format!("203.0.113.{}:21021", k + 1).parse().unwrap();
            pair_factice(&a, 200 + u64::from(k), v4, false);
        }
        let mappee: SocketAddr = "[::ffff:203.0.113.77]:21021".parse().unwrap();
        assert!(
            !a.admettre_entrant(Some(mappee)),
            "une IPv4 mappee doit etre comptee dans son /16"
        );
        let mappee_ailleurs: SocketAddr = "[::ffff:198.51.100.1]:21021".parse().unwrap();
        assert!(
            a.admettre_entrant(Some(mappee_ailleurs)),
            "une IPv4 mappee d'un autre /16 doit passer"
        );
        // Et la boucle locale reste hors groupe, en v6 comme en v4.
        assert_eq!(groupe_entrant("[::1]:1".parse().unwrap()), None);
        a.shutdown();
    }

    #[test]
    fn un_bloc_mine_apres_connexion_se_propage() {
        let (a, b) = paire();
        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        b.connect(addr).expect("connexion");
        assert!(attendre(|| a.peer_count() == 1 && b.peer_count() == 1, 5));

        miner(&a, 1);
        let bloc = a.with_chain(|c| c.block_by_id(&c.tip_id())).unwrap();
        a.announce_block(&bloc);

        assert!(
            attendre(|| b.height() == 1, 20),
            "le bloc annonce n'a pas ete recupere"
        );
        assert_eq!(b.tip_id(), a.tip_id());
        // La propagation doit etre passee par le relais compact.
        assert!(
            b.stats.compacts_recus.load(Ordering::Relaxed) > 0,
            "le bloc aurait du transiter en compact"
        );
        a.shutdown();
        b.shutdown();
    }

    #[test]
    fn un_noeud_refuse_de_se_connecter_a_lui_meme() {
        let a = noeud();
        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        a.connect(addr).expect("connexion");
        // La detection de nonce doit finir par fermer les deux cotes.
        assert!(
            attendre(|| a.peer_count() <= 1, 10),
            "la connexion a soi-meme n'a pas ete coupee"
        );
        a.shutdown();
    }

    #[test]
    fn des_octets_aleatoires_ne_font_pas_tomber_le_noeud() {
        let a = noeud();
        let addr = a.listen("127.0.0.1:0").expect("ecoute");

        for graine in 0..20u64 {
            if let Ok(mut s) = TcpStream::connect(addr) {
                let mut brut = vec![0u8; 256];
                let mut g = graine
                    .wrapping_mul(2_862_933_555_777_941_757)
                    .wrapping_add(3);
                for o in brut.iter_mut() {
                    g = g.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    *o = (g >> 33) as u8;
                }
                let _ = s.write_all(&brut);
            }
        }

        // Le noeud doit rester vivant et repondre normalement ensuite.
        let b = noeud();
        b.connect(addr).expect("connexion apres agression");
        assert!(
            attendre(|| b.peer_count() == 1, 10),
            "le noeud a cesse de repondre apres des octets aleatoires"
        );
        a.shutdown();
        b.shutdown();
    }
}

#[cfg(test)]
mod tests_chaines_incompatibles {
    use super::tests_util::*;
    use super::*;
    use crate::block::BlockHeader;

    /// Le defaut trouve en lancant deux vrais noeuds, transforme en test.
    ///
    /// Deux geneses differentes : les pairs doivent le constater et se separer,
    /// au lieu de s'echanger des blocs orphelins jusqu'a epuisement.
    #[test]
    fn deux_noeuds_aux_geneses_differentes_se_separent() {
        let a = noeud_avec_genese(7);
        let b = noeud_avec_genese(99);
        assert_ne!(a.tip_id(), b.tip_id(), "les geneses doivent differer");

        miner_local(&a, 5);
        let addr = a.listen("127.0.0.1:0").expect("ecoute");
        b.connect(addr).expect("connexion");

        // Le noeud b ne doit ni progresser ni s'acharner.
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(
            b.height(),
            0,
            "b n'aurait pas du adopter une chaine etrangere"
        );
        assert!(
            b.stats.blocs_recus.load(Ordering::Relaxed) < 50,
            "b a telecharge {} blocs orphelins : la boucle infinie est revenue",
            b.stats.blocs_recus.load(Ordering::Relaxed)
        );
        a.shutdown();
        b.shutdown();
    }

    #[test]
    fn des_entetes_qui_ne_se_suivent_pas_sont_refuses() {
        let a = noeud_avec_genese(1);
        let mut faux = BlockHeader {
            version: 1,
            prev_block: a.tip_id(),
            merkle_root: Hash256([1u8; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([2u8; 32]),
            time: 1,
            bits: crate::consensus::INITIAL_BITS,
            height: 1,
            nonce: 0,
        };
        let premier = faux;
        // Le second ne pointe pas sur le premier : la suite est rompue.
        faux.prev_block = Hash256([0xaa; 32]);
        faux.height = 2;

        let avant = a.stats.blocs_recus.load(Ordering::Relaxed);
        let _ = a.traiter(999, Message::Headers(vec![premier, faux]));
        assert_eq!(
            a.stats.blocs_recus.load(Ordering::Relaxed),
            avant,
            "aucun corps ne doit etre demande sur une suite rompue"
        );
        a.shutdown();
    }
}

#[cfg(test)]
mod tests_util {
    use super::*;
    use crate::chain::genesis_block;
    use crate::consensus::TARGET_BLOCK_SECS;
    use crate::sig::SchemeId;

    pub const RESEAU: Network = Network::Regtest;

    /// Noeud dont la genese est artificiellement distincte.
    ///
    /// La genese reelle est deterministe par reseau — c'est justement le
    /// correctif. Pour simuler deux chaines incompatibles, on decale son
    /// horodatage.
    pub fn noeud_avec_genese(decalage: u64) -> Node {
        let mut g = genesis_block(RESEAU);
        g.header.time += decalage;
        g.header.nonce = 0;
        let table =
            crate::memhard::PowTable::build(crate::memhard::TableParams::for_network(RESEAU), 0);
        let _ = crate::pow::mine_with_table(&mut g.header, &table, 5_000_000);
        Node::new(RESEAU, Chain::new(RESEAU, g))
    }

    pub fn miner_local(n: &Node, combien: usize) {
        for _ in 0..combien {
            let b = n.with_chain(|c| {
                let t = c.tip().time + TARGET_BLOCK_SECS;
                c.mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
            });
            if let Some(b) = b {
                n.with_chain(|c| {
                    let t = b.header.time + 1;
                    let _ = c.connect(&b, t);
                });
            }
        }
    }
}
