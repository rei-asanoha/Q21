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
    InvItem, InvKind, Message, WireError, HEADER_LEN, MAX_PAYLOAD, PROTOCOL_VERSION,
};
use std::collections::{HashMap, HashSet};
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

/// Debit soutenu accorde a un pair pour le service d'amorce, en octets par
/// seconde.
pub const AMORCE_DEBIT_PAR_SEC: u64 = 2 * 1024 * 1024;

/// Reserve accordee d'emblee, en octets. Elle permet a un nouveau venu honnete
/// de demarrer sans attendre, tout en bornant ce qu'un pair peut extraire d'un
/// coup.
pub const AMORCE_SEAU_MAX: u64 = 8 * 1024 * 1024;

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
        let ecoule = maintenant
            .saturating_duration_since(self.dernier)
            .as_millis() as u64;
        // Le remplissage se calcule en millisecondes : sous la milliseconde, on
        // ne credite rien et on ne deplace pas le repere, faute de quoi une
        // rafale de demandes tres rapprochees ne crediterait jamais rien.
        let gain = ecoule.saturating_mul(AMORCE_DEBIT_PAR_SEC) / 1000;
        if gain > 0 {
            self.jetons = self.jetons.saturating_add(gain).min(AMORCE_SEAU_MAX);
            self.dernier = maintenant;
        }
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
    handshaked: bool,
    ban_score: u32,
    /// Hauteur annoncee par le pair a la poignee de main.
    start_height: u64,
    /// Reconstructions de blocs compacts en attente de transactions.
    en_attente: HashMap<Hash256, (CompactBlock, Vec<u32>)>,
    /// Ce que ce pair peut encore se faire servir d'amorce. Voir [`SeauAmorce`].
    seau_amorce: SeauAmorce,
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
    /// Nombre d'en-tetes recus qui ne se rattachent a rien de connu.
    ///
    /// Compte les signes que ce pair est sur une autre chaine. Sans ce compteur,
    /// deux noeuds aux geneses differentes s'echangent indefiniment des blocs
    /// que ni l'un ni l'autre ne peut rattacher — defaut constate en lancant
    /// reellement deux noeuds, invisible en test unitaire parce que les deux y
    /// partageaient la meme genese.
    orphelins_consecutifs: u32,
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
        let nonce = {
            let mut g = self.partage.lock().unwrap();
            for (id, p) in g.peers.iter_mut() {
                let silence = maintenant.duration_since(p.derniere_reception);
                if silence >= SILENCE_MAX {
                    morts.push(*id);
                } else if silence >= PING_APRES && p.ping_en_attente.is_none() {
                    p.ping_en_attente = Some(maintenant);
                    a_pinger.push((*id, p.sortie.clone()));
                }
            }
            g.nonce
        };
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
                        if node.peer_count() >= MAX_PEERS {
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
        let flux = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
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
                    version_recue: false,
                    handshaked: false,
                    ban_score: 0,
                    start_height: 0,
                    en_attente: HashMap::new(),
                    orphelins_consecutifs: 0,
                    derniere_reception: Instant::now(),
                    ping_en_attente: None,
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
                user_agent: "q21:0.1".into(),
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
                    nonce,
                    start_height,
                    ..
                } => {
                    // Connexion a soi-meme : on coupe sans ceremonie.
                    if nonce == nonce_local {
                        couper = true;
                    } else if let Some(p) = g.peers.get_mut(&id) {
                        p.version_recue = true;
                        p.start_height = start_height;
                        envois.push(Envoi {
                            peer: id,
                            message: Message::VerAck,
                        });
                    }
                    if !couper {
                        let hauteur = g.chain.height();
                        // Le repondant se presente a son tour.
                        envois.push(Envoi {
                            peer: id,
                            message: Message::Version {
                                version: PROTOCOL_VERSION,
                                timestamp: maintenant(),
                                nonce: nonce_local,
                                user_agent: "q21:0.1".into(),
                                start_height: hauteur,
                            },
                        });
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

                Message::Headers(v) => {
                    // --- Synchronisation par en-tetes, version stricte.
                    //
                    // On ne demande **jamais** un corps de bloc avant d'avoir
                    // verifie que la suite d'en-tetes se rattache a la chaine
                    // qu'on connait deja. Sans ce controle, un pair sur une
                    // chaine incompatible fait telecharger indefiniment des
                    // blocs orphelins : c'est le defaut observe en lancant deux
                    // noeuds aux geneses differentes, 29 850 blocs recus pour
                    // une hauteur restee a zero.
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
                        if let Some(p) = g.peers.get_mut(&id) {
                            p.orphelins_consecutifs = 0;
                        }
                        let manquants: Vec<InvItem> = v
                            .iter()
                            .map(|h| h.block_id())
                            .filter(|bid| !g.chain.has_block(bid))
                            .map(|hash| InvItem {
                                kind: InvKind::CompactBlock,
                                hash,
                            })
                            .collect();
                        if !manquants.is_empty() {
                            envois.push(Envoi {
                                peer: id,
                                message: Message::GetData(manquants),
                            });
                        }
                        if v.len() >= crate::wire::MAX_HEADERS {
                            envois.push(Envoi {
                                peer: id,
                                message: Message::GetHeaders {
                                    locator: g.chain.locator(),
                                    stop: Hash256::ZERO,
                                },
                            });
                        }
                    }
                }

                Message::Inv(v) => {
                    let mut voulus = Vec::new();
                    for i in v {
                        match i.kind {
                            InvKind::Block | InvKind::CompactBlock => {
                                if !g.chain.has_block(&i.hash) {
                                    voulus.push(InvItem {
                                        kind: InvKind::CompactBlock,
                                        hash: i.hash,
                                    });
                                }
                            }
                            InvKind::Tx => {
                                if !g.mempool.contains(&i.hash) {
                                    voulus.push(i);
                                }
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
                    self.stats.blocs_recus.fetch_add(1, Ordering::Relaxed);
                    couper = !Self::integrer(&mut g, &b, &self.stats, &mut envois, id);
                }

                Message::CmpctBlock(c) => {
                    self.stats.compacts_recus.fetch_add(1, Ordering::Relaxed);
                    let bid = c.header.block_id();
                    if g.chain.has_block(&bid) {
                        // Deja connu : rien a faire.
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

                Message::Tx(t) => {
                    self.stats.tx_recues.fetch_add(1, Ordering::Relaxed);
                    let hauteur = g.chain.height();
                    // Sur une reference, jamais sur une copie : dupliquer le jeu
                    // d'UTXO a chaque transaction recue coutait des centaines de
                    // mebioctets par message sur une chaine reelle, sous le
                    // verrou global — un pair bavard suffisait a figer le noeud.
                    // Le reemprunt `&mut *g` separe les champs de la garde.
                    let partage = &mut *g;
                    match partage
                        .mempool
                        .accept(&t, &partage.chain.utxo, magie_reseau, hauteur)
                    {
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
                        Err(_) => {
                            // Une transaction refusee n'est pas forcement une
                            // agression : elle peut simplement etre deja connue.
                        }
                    }
                }

                Message::GetAddr => {
                    // Le carnet d'abord — il est reparti sur les groupes — puis
                    // les pairs en cours, qui sont par construction joignables.
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
                        envois.push(Envoi {
                            peer: id,
                            message: Message::Addr(v),
                        });
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
                let g = self.partage.lock().unwrap();
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
                true
            }
            Ok(Accept::BrancheLaterale) => {
                // Une branche laterale est du travail valide : si elle
                // l'emporte plus tard, il faudra ses corps. Ne pas les ecrire
                // rendait toute reorganisation impossible apres un redemarrage.
                if let Some(j) = &g.journal {
                    j.consigner(b);
                }
                true
            }
            Ok(_) => true,
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
