//! Serveur HTTP/1.1 minimal.
//!
//! Juste assez pour servir une API JSON-RPC et une page d'exploration. Ecrit
//! ici, sans dependance, pour la meme raison que le reste.
//!
//! # La decision de securite qui compte
//!
//! Un port RPC ouvert est un acces au noeud. Un port RPC ouvert **sur une
//! interface publique** est une perte de fonds : il suffit d'un scan pour le
//! trouver. Cette histoire s'est deja jouee — des milliers de noeuds Ethereum et
//! Docker ont ete vides parce qu'un port d'administration ecoutait sur
//! `0.0.0.0` par defaut.
//!
//! Deux garde-fous, appliques a la liaison et non au premier appel :
//!
//! - **le bouclage local est le defaut.** `127.0.0.1` sert le noeud a la machine
//!   qui l'heberge, et a personne d'autre ;
//! - **ecouter ailleurs exige un jeton.** Sans jeton, [`serve`] refuse de se
//!   lier a une adresse non locale, et le refus arrive au demarrage, pas en
//!   pleine nuit quand le port a deja ete trouve.
//!
//! Le jeton est compare en **temps constant** : une comparaison naive laisse
//! fuir sa longueur et son prefixe par le temps de reponse.

use std::collections::BTreeMap;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Taille maximale d'un corps de requete.
pub const MAX_BODY: usize = 1024 * 1024;
/// Longueur maximale d'une ligne d'en-tete.
pub const MAX_LINE: usize = 8 * 1024;
/// Nombre maximal d'en-tetes.
pub const MAX_HEADERS: usize = 64;

pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Duree maximale d'une requete complete, lecture comprise.
///
/// `READ_TIMEOUT` porte sur **chaque** lecture : un octet toutes les vingt
/// secondes maintenait donc une connexion — et son fil — indefiniment. C'est
/// l'attaque Slowloris, vieille de quinze ans et toujours efficace contre qui
/// ne borne que les lectures individuelles.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Connexions traitees simultanement.
///
/// `serve` lancait un fil systeme par connexion, sans compteur ni file. Quelques
/// milliers de connexions ouvertes suffisaient a epuiser la memoire du
/// processus. Au-dela de ce plafond, la connexion est refusee immediatement :
/// un refus franc vaut mieux qu'un fil de plus.
pub const MAX_CONNEXIONS: usize = 64;

/// Duree de validite d'un jeton d'amorcage qui n'a pas encore servi.
///
/// Il ne vit que le temps d'ouvrir une page. Dix minutes couvrent le cas de
/// celui qui recopie l'adresse a la main depuis le terminal ; au-dela, ce qui
/// traine dans la ligne de commande d'un navigateur n'ouvre plus rien.
pub const AMORCE_VALIDITE: Duration = Duration::from_secs(10 * 60);

/// Chemin de l'echange du jeton d'amorcage contre le jeton de session.
pub const CHEMIN_SESSION: &str = "/session";

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    /// L'adresse du client, telle que le serveur peut la connaitre.
    ///
    /// Celle de la connexion TCP — sauf derriere le mandataire local, ou c'est
    /// la premiere adresse de `X-Forwarded-For`. Voir [`adresse_client`]. Elle
    /// sert a ce que le budget d'un client ne soit pas celui de tous.
    pub client: Option<IpAddr>,
}

/// L'adresse du client d'une requete.
///
/// # Pourquoi l'en-tete n'est cru que depuis la boucle locale
///
/// En mode public, le noeud n'ecoute que sur la boucle locale et c'est le
/// mandataire qui lui parle : toutes les connexions viennent de `127.0.0.1`,
/// et sans l'en-tete `X-Forwarded-For` que le mandataire pose, tous les
/// visiteurs seraient un seul et meme client. On lit donc la **premiere**
/// adresse de cet en-tete — celle du client, le mandataire ayant efface ce
/// qu'il aurait pu recevoir avant de poser la sienne.
///
/// Un `X-Forwarded-For` qui arrive d'ailleurs que de la boucle locale n'est
/// pas celui du mandataire : c'est un client qui l'ecrit lui-meme. Le croire
/// laisserait ce client choisir son identite, donc son budget, et en changer a
/// chaque requete. On garde alors l'adresse de la connexion, et rien d'autre.
///
/// Une valeur illisible ne fait pas echouer la requete : on retombe sur
/// l'adresse de la connexion, et le client est traite avec le mandataire.
pub fn adresse_client(pair: Option<IpAddr>, headers: &BTreeMap<String, String>) -> Option<IpAddr> {
    let pair = pair?;
    if !pair.is_loopback() {
        return Some(pair);
    }
    let Some(transmis) = headers.get("x-forwarded-for") else {
        return Some(pair);
    };
    let premier = transmis.split(',').next().unwrap_or("").trim();
    match premier.parse::<IpAddr>() {
        Ok(ip) => Some(ip),
        Err(_) => Some(pair),
    }
}

/// Un jeton d'amorcage : echange **une seule fois** contre le jeton de session.
///
/// # Ce que cela ferme
///
/// Le lanceur ouvre le navigateur sur une adresse dont le fragment porte un
/// secret. Cette adresse est passee au lanceur en **argument de ligne de
/// commande** — lisible par tout compte de la machine dans `/proc/<pid>/cmdline`
/// sous Linux, par `ps` sous macOS — et elle y reste tant que le processus du
/// navigateur vit. Sous Linux, la garde de `/proc/net/tcp` refuse les autres
/// comptes ; ailleurs, ce secret etait la seule barriere, et il valait pour
/// toute la session.
///
/// Le fragment ne porte donc plus le jeton de session. Il porte ce jeton-ci,
/// court, que la page echange au premier chargement contre le vrai jeton par
/// un `POST` — puis il est detruit. Ce qui traine ensuite dans `argv` ne vaut
/// plus rien. Un autre compte qui l'aurait lu avant la page ne gagne qu'une
/// course d'une seconde ; s'il la gagne, la page legitime echoue a s'ouvrir et
/// le dit, au lieu de fonctionner a cote d'un intrus silencieux.
struct Amorce {
    secret: String,
    nee: std::time::Instant,
}

/// Une amorce configuree, consommee ou non. `None` a l'interieur : deja servie.
type AmorcePartagee = Arc<std::sync::Mutex<Option<Amorce>>>;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: String,
    /// Jeton a usage unique du script en ligne de cette page.
    ///
    /// Voir [`Response::html`] : il remplace `'unsafe-inline'` dans la
    /// politique de securite du contenu.
    pub nonce: Option<String>,
}

impl Response {
    pub fn json(body: String) -> Response {
        Response {
            status: 200,
            content_type: "application/json; charset=utf-8".into(),
            body,
            nonce: None,
        }
    }

    /// Une page, et le jeton qui autorise son seul script.
    ///
    /// # Ce que cela ferme
    ///
    /// La politique de securite du contenu disait `script-src 'unsafe-inline'`.
    /// Elle autorisait donc **n'importe quel** script en ligne — dont un script
    /// qu'un attaquant serait parvenu a faire ecrire dans la page. Tant qu'aucun
    /// texte libre ne traverse le nœud, ce trou reste theorique ; un audit l'a
    /// verifie champ par champ. Mais une politique n'a d'interet que si elle
    /// tient encore le jour ou l'on ajoute un champ sans y penser.
    ///
    /// Chaque reponse porte donc un jeton tire au hasard, inscrit sur la balise
    /// `<script>` **et** dans l'en-tete. Le navigateur n'execute alors que ce
    /// script-la : un script injecte n'a pas le jeton, et ne s'execute pas.
    /// Deux pages servies coup sur coup n'ont pas le meme jeton, donc il ne se
    /// devine pas.
    ///
    /// # Pourquoi l'echec est ferme
    ///
    /// Sans alea sur, on ne fabrique pas un jeton previsible : la page part
    /// alors avec une politique qui interdit **tout** script, et elle ne
    /// fonctionne pas. C'est le bon echec — un generateur d'alea en panne est
    /// un probleme bien plus grave qu'une page inerte, et ce nœud ne devrait de
    /// toute facon pas manipuler de clefs dans cet etat.
    pub fn html(body: String) -> Response {
        let mut brut = [0u8; 16];
        let nonce = match crate::rng::remplir(&mut brut) {
            Ok(()) => Some(brut.iter().map(|o| format!("{o:02x}")).collect::<String>()),
            Err(_) => None,
        };
        let body = match &nonce {
            Some(n) => body.replacen("<script>", &format!("<script nonce=\"{n}\">"), 1),
            None => body,
        };
        Response {
            status: 200,
            content_type: "text/html; charset=utf-8".into(),
            body,
            nonce,
        }
    }
    pub fn text(status: u16, body: &str) -> Response {
        Response {
            status,
            content_type: "text/plain; charset=utf-8".into(),
            body: body.into(),
            nonce: None,
        }
    }
    pub fn not_found() -> Response {
        Response::text(404, "introuvable")
    }
}

#[derive(Debug)]
pub enum HttpError {
    Io(std::io::Error),
    /// Liaison a une interface non locale sans jeton d'acces.
    ExpositionSansJeton(SocketAddr),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Io(e) => write!(f, "erreur reseau : {e}"),
            HttpError::ExpositionSansJeton(a) => write!(
                f,
                "refus d'ecouter sur {a} sans jeton : un port RPC accessible depuis \
                 l'exterieur donne acces au noeud. Utilisez 127.0.0.1, ou fournissez \
                 un jeton d'acces."
            ),
        }
    }
}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        HttpError::Io(e)
    }
}

/// Comparaison en temps constant.
///
/// Une comparaison naive s'arrete au premier octet different : le temps de
/// reponse revele alors le prefixe correct, et un jeton se devine octet par
/// octet. Ici le temps ne depend que des longueurs.
fn egal_temps_constant(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub struct ServerHandle {
    pub addr: SocketAddr,
    arret: Arc<AtomicBool>,
}

impl ServerHandle {
    pub fn shutdown(&self) {
        self.arret.store(true, Ordering::Relaxed);
    }
}

/// Demarre le serveur en tache de fond.
///
/// `token` protege l'acces. Il est **obligatoire** pour toute adresse d'ecoute
/// qui n'est pas une adresse de bouclage.
pub fn serve<F>(adresse: &str, token: Option<String>, handler: F) -> Result<ServerHandle, HttpError>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    serve_avec_public(adresse, token, &[], handler)
}

/// Comme [`serve`], mais avec une liste de chemins servis **sans jeton**.
///
/// # Pourquoi cette liste existe, et pourquoi elle est explicite
///
/// L'explorateur demande son jeton a l'utilisateur puis l'envoie en
/// `Authorization`. Encore faut-il que la page ait pu se charger : exiger le
/// jeton pour la page elle-meme donnait un `401` en texte brut, sans moyen de
/// le saisir. Le noeud etait protege et inutilisable.
///
/// Cette liste ne doit contenir que des ressources **statiques**, qui ne
/// portent aucune donnee : la coquille HTML de l'explorateur, rien d'autre.
/// Elle est passee par l'appelant, nommee chemin par chemin, et vide par
/// defaut — la valeur sure est celle qu'on obtient en ne faisant rien.
pub fn serve_avec_public<F>(
    adresse: &str,
    token: Option<String>,
    chemins_publics: &'static [&'static str],
    handler: F,
) -> Result<ServerHandle, HttpError>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    serve_complet(adresse, token, chemins_publics, None, None, handler)
}

/// Comme [`serve_avec_public`], avec un jeton d'amorcage a usage unique.
///
/// `amorce` est ce que le lanceur met dans l'adresse ouverte par le navigateur.
/// La page l'echange contre `token` par un `POST` sur [`CHEMIN_SESSION`], une
/// seule fois et dans les [`AMORCE_VALIDITE`] ; voir [`Amorce`] pour ce que
/// cela ferme. `token` reste le seul jeton qui ouvre quoi que ce soit d'autre.
pub fn serve_avec_amorce<F>(
    adresse: &str,
    token: String,
    amorce: String,
    chemins_publics: &'static [&'static str],
    handler: F,
) -> Result<ServerHandle, HttpError>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    serve_complet(
        adresse,
        Some(token),
        chemins_publics,
        None,
        Some(amorce),
        handler,
    )
}

/// Comme [`serve_avec_public`], mais pour un service **destine a etre public**.
///
/// # Pourquoi ce mode existe, et pourquoi il est separe
///
/// La garde de ce serveur refuse toute requete dont l'en-tete `Host` n'est pas
/// locale. C'est la bonne regle pour un portefeuille : le RPC ecoute sur la
/// boucle locale, et le navigateur de l'utilisateur y est aussi — sans cette
/// garde, une page hostile ouverte dans un onglet quelconque atteindrait les
/// fonds par reliaison DNS.
///
/// Un explorateur public est l'exact oppose : on l'expose **exprès**, derriere
/// un nom de domaine, et les navigateurs qui l'atteignent enverront ce nom en
/// `Host` et en `Origin`. La garde les refuserait tous.
///
/// On aurait pu reecrire ces en-tetes dans le mandataire. Ce serait desactiver
/// un controle de securite par un artifice de configuration, sans que le
/// programme sache qu'il est expose. On declare donc le nom au serveur, qui
/// l'accepte pour lui seul et garde toutes ses autres regles.
///
/// **L'appelant doit garantir qu'aucune methode de portefeuille n'est servie
/// sur ce port.** C'est verifie a l'appel, dans le binaire.
pub fn serve_public_web<F>(
    adresse: &str,
    hote_public: String,
    handler: F,
) -> Result<ServerHandle, HttpError>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    serve_complet(adresse, None, &[], Some(hote_public), None, handler)
}

fn serve_complet<F>(
    adresse: &str,
    token: Option<String>,
    chemins_publics: &'static [&'static str],
    hote_public: Option<String>,
    amorce: Option<String>,
    handler: F,
) -> Result<ServerHandle, HttpError>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    let listener = TcpListener::bind(adresse)?;
    let local = listener.local_addr()?;

    let bouclage = match local.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    // --- Le mode public se met derriere un mandataire, jamais devant.
    //
    // Il n'a pas de jeton : c'est un explorateur, fait pour etre lu par
    // n'importe qui. Mais ce serveur traite une connexion par fil, soixante-
    // quatre au plus : expose directement, il tombe sous une poignee de
    // connexions ouvertes et jamais terminees — l'attaque Slowloris, qu'un
    // audit d'intrusion a reproduite ici en deux lignes.
    //
    // Le mandataire, lui, est fait pour ca. On exige donc que ce mode ecoute
    // sur la boucle locale, et le refus est ici plutot que dans une note de
    // documentation que personne ne relit.
    if !bouclage && hote_public.is_some() {
        return Err(HttpError::ExpositionSansJeton(local));
    }
    if !bouclage && token.is_none() {
        return Err(HttpError::ExpositionSansJeton(local));
    }

    let hote = Arc::new(hote_public);
    let arret = Arc::new(AtomicBool::new(false));
    let arret_fil = arret.clone();
    let handler = Arc::new(handler);
    let token = Arc::new(token);
    let amorce: Option<AmorcePartagee> = amorce.map(|secret| {
        Arc::new(std::sync::Mutex::new(Some(Amorce {
            secret,
            nee: std::time::Instant::now(),
        })))
    });
    // Compteur de connexions en cours : sans lui, une connexion valait un fil
    // systeme, sans plafond.
    let en_cours = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    std::thread::spawn(move || {
        for flux in listener.incoming() {
            if arret_fil.load(Ordering::Relaxed) {
                break;
            }
            let mut flux = match flux {
                Ok(f) => f,
                Err(_) => break,
            };
            // --- Defense : un autre compte de la meme machine.
            //
            // L'adresse ouverte par le navigateur est passee au lanceur en
            // argument de ligne de commande, que tout compte de la machine
            // peut lire dans `/proc/<pid>/cmdline`. Le jeton d'amorcage a
            // usage unique (voir `Amorce`) rend cette lecture inutile apres
            // la premiere ouverture ; cette garde-ci ferme aussi la course
            // d'avant. Sur Linux, on demande au noyau **qui** tient l'autre
            // bout de la connexion locale, et on refuse tout compte autre que
            // le notre. Le mode public, servi par un mandataire sous un autre
            // compte, n'est pas concerne : il n'a pas de portefeuille.
            if hote.is_none() {
                if let Err(raison) = autre_compte_admis(&flux) {
                    let _ = flux.set_write_timeout(Some(Duration::from_secs(2)));
                    let _ = ecrire_reponse(&mut flux, &Response::text(403, raison));
                    let _ = flux.shutdown(std::net::Shutdown::Both);
                    continue;
                }
            }
            if en_cours.load(Ordering::Relaxed) >= MAX_CONNEXIONS {
                // Refus franc, sans fil : le client sait a quoi s'en tenir et le
                // noeud ne paie rien.
                let _ = flux.set_write_timeout(Some(Duration::from_secs(2)));
                let _ = ecrire_reponse(
                    &mut flux,
                    &Response::text(503, "trop de connexions simultanees"),
                );
                let _ = flux.shutdown(std::net::Shutdown::Both);
                continue;
            }
            let h = handler.clone();
            let t = token.clone();
            let c = en_cours.clone();
            let pubs = chemins_publics;
            let hp = hote.clone();
            let am = amorce.clone();
            c.fetch_add(1, Ordering::Relaxed);
            let lance = std::thread::Builder::new().spawn(move || {
                // Le delai de lecture ne doit pas pouvoir survivre a l'echeance
                // globale : sinon une seule lecture bloquee la depasserait avant
                // meme qu'on la consulte.
                let _ = flux.set_read_timeout(Some(REQUEST_TIMEOUT));
                let _ = flux.set_write_timeout(Some(READ_TIMEOUT));
                traiter_connexion(
                    flux,
                    &*h,
                    t.as_ref().as_deref(),
                    pubs,
                    hp.as_deref(),
                    am.as_ref(),
                );
                c.fetch_sub(1, Ordering::Relaxed);
            });
            if lance.is_err() {
                en_cours.fetch_sub(1, Ordering::Relaxed);
            }
        }
    });

    Ok(ServerHandle { addr: local, arret })
}

/// Ce que le noyau sait du compte qui tient l'autre bout d'une connexion.
#[derive(Debug, PartialEq, Eq)]
enum Proprietaire {
    /// Le compte designe par la table des sockets.
    Compte(u32),
    /// La table a ete lue, et la connexion n'y figure pas.
    Absent,
    /// Aucune table lisible : autre systeme, ou `/proc` inaccessible.
    Inconnu,
}

/// La connexion locale vient-elle de notre propre compte ?
///
/// # Ferme quand on sait, ouvert seulement quand on ne peut pas savoir
///
/// Trois reponses, et trois verdicts distincts :
///
/// - le noyau designe un compte : on l'admet s'il est le notre, et lui seul ;
/// - la table des sockets se lit mais **ne contient pas** cette connexion :
///   on refuse. La premiere version admettait ce cas, par crainte de fermer
///   la porte par erreur. Mais une connexion de bouclage que la table du
///   noyau ne liste pas n'a pas d'explication legitime — les deux bouts sont
///   dans le meme espace de noms reseau que nous —, et un « je ne trouve
///   pas » qui vaut « entrez » est une garde qu'un defaut d'analyse suffit a
///   desarmer sans qu'aucune epreuve le voie ;
/// - aucune table n'est lisible — macOS, Windows, un `/proc` masque : on
///   admet, parce qu'il n'y a rien a lire et que refuser rendrait le
///   portefeuille inutilisable. Sur ces systemes, le jeton d'amorcage a usage
///   unique est la barriere, et le lanceur le dit.
///
/// Une connexion qui ne vient pas de la boucle locale n'est pas concernee :
/// ce n'est pas un autre compte de cette machine, et c'est le jeton qui la
/// garde.
fn autre_compte_admis(flux: &TcpStream) -> Result<(), &'static str> {
    let (Ok(local), Ok(distant)) = (flux.local_addr(), flux.peer_addr()) else {
        return Ok(());
    };
    if !distant.ip().is_loopback() {
        return Ok(());
    }
    verdict(proprietaire_de_la_connexion(local, distant))
}

/// Le verdict de la garde, separe de la lecture pour etre eprouve seul.
fn verdict(p: Proprietaire) -> Result<(), &'static str> {
    match p {
        Proprietaire::Compte(uid) if uid == compte_courant() => Ok(()),
        Proprietaire::Compte(_) => {
            Err("connexion depuis un autre compte de cette machine : refusee")
        }
        Proprietaire::Absent => {
            Err("connexion locale que le noyau n'attribue a aucun compte : refusee")
        }
        Proprietaire::Inconnu => Ok(()),
    }
}

#[cfg(target_os = "linux")]
fn compte_courant() -> u32 {
    // Sur : `geteuid` ne peut pas echouer.
    unsafe { libc::geteuid() }
}

#[cfg(not(target_os = "linux"))]
fn compte_courant() -> u32 {
    0
}

/// Le compte qui possede la socket cliente d'une connexion locale, d'apres
/// `/proc/net/tcp` et `/proc/net/tcp6`.
///
/// Chaque ligne y decrit une socket : son adresse locale, son adresse
/// distante et son proprietaire. La socket **cliente** de notre connexion a
/// pour adresse locale `distant` (ce que nous voyons comme pair) et pour
/// adresse distante `local` (notre port d'ecoute).
#[cfg(target_os = "linux")]
fn proprietaire_de_la_connexion(local: SocketAddr, distant: SocketAddr) -> Proprietaire {
    let fichier = if distant.is_ipv4() {
        "/proc/net/tcp"
    } else {
        "/proc/net/tcp6"
    };
    match std::fs::read_to_string(fichier) {
        Ok(contenu) => proprietaire_dans(&contenu, local, distant),
        Err(_) => Proprietaire::Inconnu,
    }
}

/// Cherche la socket cliente dans le contenu d'une table `/proc/net/tcp*`.
///
/// Separe de la lecture du fichier pour que l'epreuve puisse presenter une
/// table qui ne contient pas la connexion — ce qu'on ne peut pas provoquer
/// avec une vraie socket.
#[cfg(target_os = "linux")]
fn proprietaire_dans(contenu: &str, local: SocketAddr, distant: SocketAddr) -> Proprietaire {
    fn hex_de(a: &SocketAddr) -> Option<String> {
        match a {
            SocketAddr::V4(v) => {
                let o = v.ip().octets();
                // Le noyau ecrit chaque mot de 32 bits en petit-boutiste.
                Some(format!(
                    "{:02X}{:02X}{:02X}{:02X}:{:04X}",
                    o[3],
                    o[2],
                    o[1],
                    o[0],
                    v.port()
                ))
            }
            SocketAddr::V6(v) => {
                let o = v.ip().octets();
                let mut s = String::with_capacity(32);
                for mot in o.chunks(4) {
                    for b in mot.iter().rev() {
                        s.push_str(&format!("{b:02X}"));
                    }
                }
                Some(format!("{s}:{:04X}", v.port()))
            }
        }
    }
    let (Some(cherche_local), Some(cherche_distant)) = (hex_de(&distant), hex_de(&local)) else {
        return Proprietaire::Inconnu;
    };
    for ligne in contenu.lines().skip(1) {
        let mut champs = ligne.split_whitespace();
        let (Some(_sl), Some(adr_locale), Some(adr_distante)) =
            (champs.next(), champs.next(), champs.next())
        else {
            continue;
        };
        if adr_locale != cherche_local || adr_distante != cherche_distant {
            continue;
        }
        // st tx_queue:rx_queue tr:tm->when retrnsmt uid ...
        return match champs.nth(4).and_then(|u| u.parse().ok()) {
            Some(uid) => Proprietaire::Compte(uid),
            // La ligne est la mais son compte est illisible : la table etait
            // lisible et n'attribue cette connexion a personne. On refuse,
            // comme pour une ligne absente — la garde ne s'ouvre pas sur un
            // defaut d'analyse.
            None => Proprietaire::Absent,
        };
    }
    Proprietaire::Absent
}

#[cfg(not(target_os = "linux"))]
fn proprietaire_de_la_connexion(_local: SocketAddr, _distant: SocketAddr) -> Proprietaire {
    Proprietaire::Inconnu
}

#[cfg(all(test, target_os = "linux"))]
mod compte_local {
    use super::*;

    /// Le noyau designe bien notre compte pour une connexion que nous ouvrons
    /// nous-memes, en IPv4 comme en IPv6.
    #[test]
    fn la_connexion_locale_est_attribuee_a_notre_compte() {
        for ecoute in ["127.0.0.1:0", "[::1]:0"] {
            let Ok(l) = TcpListener::bind(ecoute) else {
                continue;
            };
            let adr = l.local_addr().unwrap();
            let client = TcpStream::connect(adr).unwrap();
            let (serveur, _) = l.accept().unwrap();
            let uid = proprietaire_de_la_connexion(
                serveur.local_addr().unwrap(),
                serveur.peer_addr().unwrap(),
            );
            assert_eq!(uid, Proprietaire::Compte(compte_courant()), "sur {ecoute}");
            assert!(autre_compte_admis(&serveur).is_ok());
            drop(client);
        }
    }

    /// Une connexion locale que la table du noyau ne liste pas est refusee.
    ///
    /// La garde admettait ce cas : « on ne trouve pas » valait « entrez ».
    /// Une table lisible qui ne contient pas la connexion n'a pas
    /// d'explication legitime, et une garde qui s'ouvre sur un defaut
    /// d'analyse n'en est pas une.
    #[test]
    fn une_connexion_locale_absente_de_proc_est_refusee() {
        let local: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let distant: SocketAddr = "127.0.0.1:2".parse().unwrap();
        // Le vrai fichier, avec un 4-uplet qui n'y est pas.
        assert_eq!(
            proprietaire_de_la_connexion(local, distant),
            Proprietaire::Absent
        );
        assert!(verdict(Proprietaire::Absent).is_err());

        // Une table fabriquee : l'en-tete seul, puis une ligne d'une autre
        // connexion, puis la bonne ligne avec un autre compte, puis le notre.
        let entete = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        let autre = "   0: 0100007F:0003 0100007F:0001 01 00000000:00000000 00:00000000 00000000  1000        0 0 1 0 100 0 0 10 0\n";
        let bonne = |uid: u32| {
            format!(
            "   1: 0100007F:0002 0100007F:0001 01 00000000:00000000 00:00000000 00000000  {uid}        0 0 1 0 100 0 0 10 0\n"
        )
        };
        assert_eq!(
            proprietaire_dans(entete, local, distant),
            Proprietaire::Absent
        );
        assert_eq!(
            proprietaire_dans(&format!("{entete}{autre}"), local, distant),
            Proprietaire::Absent
        );
        let etranger = compte_courant().wrapping_add(1);
        assert_eq!(
            proprietaire_dans(
                &format!("{entete}{autre}{}", bonne(etranger)),
                local,
                distant
            ),
            Proprietaire::Compte(etranger)
        );
        assert!(verdict(Proprietaire::Compte(etranger)).is_err());
        assert_eq!(
            proprietaire_dans(
                &format!("{entete}{}", bonne(compte_courant())),
                local,
                distant
            ),
            Proprietaire::Compte(compte_courant())
        );
        assert!(verdict(Proprietaire::Compte(compte_courant())).is_ok());
        // Sans table du tout, on ne sait pas : c'est le seul cas ouvert.
        assert!(verdict(Proprietaire::Inconnu).is_ok());
    }
}

fn traiter_connexion<F>(
    mut flux: TcpStream,
    handler: &F,
    token: Option<&str>,
    chemins_publics: &[&str],
    hote_public: Option<&str>,
    amorce: Option<&AmorcePartagee>,
) where
    F: Fn(Request) -> Response,
{
    // Echeance globale : la somme des lectures d'une requete est bornee, pas
    // seulement chaque lecture prise a part.
    let echeance = std::time::Instant::now() + REQUEST_TIMEOUT;
    let pair = flux.peer_addr().ok().map(|a| a.ip());
    let reponse = match lire_requete(&flux, echeance) {
        Ok(mut req) => {
            req.client = adresse_client(pair, &req.headers);
            let libre = chemins_publics.contains(&req.path.as_str());
            // Une coquille statique demandee en GET est une page vide de
            // donnees et sans effet. Elle seule tolere qu'on y arrive depuis un
            // autre port de la boucle locale — voir `garde_navigateur`.
            let coquille = libre && req.method == "GET";
            match garde_navigateur(&req, coquille, hote_public) {
                Some(raison) => Response::text(403, raison),
                // L'echange d'amorce est servi ici, avant le jeton : c'est
                // lui qui le donne. Il passe la garde du navigateur comme
                // tout POST, et n'est jamais un chemin public.
                None if req.method == "POST" && req.path == CHEMIN_SESSION && amorce.is_some() => {
                    echanger_amorce(&req, token, amorce)
                }
                None => {
                    if let Some(attendu) = token.filter(|_| !libre) {
                        if !autorise(&req, attendu) {
                            Response::text(401, "jeton d'acces manquant ou invalide")
                        } else {
                            handler(req)
                        }
                    } else {
                        handler(req)
                    }
                }
            }
        }
        Err(msg) => Response::text(400, msg),
    };
    let _ = ecrire_reponse(&mut flux, &reponse);
    let _ = flux.shutdown(std::net::Shutdown::Both);
}

/// Echange le jeton d'amorcage contre le jeton de session, une seule fois.
///
/// L'amorce arrive en `Authorization: Bearer`, comme un jeton — c'est ce que
/// la page sait envoyer. Elle est retiree de sa case **avant** que la reponse
/// parte : deux echanges concurrents ne peuvent pas reussir tous les deux, la
/// case est sous verrou. Une amorce perimee est retiree de meme, sans avoir
/// servi. Tout refus a la meme forme : un `401` sans detail, parce que dire
/// « deja servie » a qui ne devrait pas la connaitre reviendrait a lui
/// confirmer qu'elle a existe.
fn echanger_amorce(
    req: &Request,
    token: Option<&str>,
    amorce: Option<&AmorcePartagee>,
) -> Response {
    let refus = || Response::text(401, "jeton d'amorcage invalide, deja servi ou perime");
    let (Some(token), Some(case)) = (token, amorce) else {
        return refus();
    };
    let Some(presente) = req
        .headers
        .get("authorization")
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
    else {
        return refus();
    };
    let Ok(mut garde) = case.lock() else {
        return refus();
    };
    let Some(a) = garde.as_ref() else {
        return refus();
    };
    if a.nee.elapsed() > AMORCE_VALIDITE {
        *garde = None;
        return refus();
    }
    if !egal_temps_constant(&presente, &a.secret) {
        return refus();
    }
    *garde = None;
    Response::json(
        crate::json::Json::obj()
            .set("jeton", crate::json::Json::str(token))
            .build()
            .encode(),
    )
}

/// Refuse ce qu'un navigateur ne devrait jamais pouvoir envoyer ici.
///
/// # L'attaque
///
/// Le RPC ecoute sur la boucle locale, ce qui donne un faux sentiment de
/// securite : **le navigateur de l'utilisateur, lui, est sur la boucle
/// locale**. Une page hostile ouverte dans un onglet quelconque peut donc
/// emettre une requete vers `http://127.0.0.1:PORT/rpc`.
///
/// Un audit l'a demontre de trois facons :
///
/// - en JavaScript, une requete « simple » au sens CORS — donc sans pre-vol —
///   atteignait le portefeuille ;
/// - **sans aucun JavaScript** : un `<form enctype="text/plain">` produit un
///   corps `nom=valeur`, et en placant le JSON dans le *nom* on obtient un
///   document JSON-RPC valide. Un clic suffisait ;
/// - par reliaison DNS : un nom qui resout d'abord vers l'attaquant puis vers
///   127.0.0.1 rend la page hostile **de meme origine**. Elle lit alors les
///   reponses, et pas seulement les emet a l'aveugle.
///
/// # Les quatre verrous
///
/// Chacun ferme une des voies. Ils sont independants : aucun ne rattrape la
/// defaillance d'un autre, et c'est voulu.
///
/// # L'exception, et pourquoi elle ne perce pas le mur
///
/// `coquille` vaut vrai pour un **GET sur un chemin declare public** : la page
/// de l'explorateur, celle du portefeuille, celle de l'installation. Ces
/// documents ne portent aucune donnee et ne declenchent aucune action ; les
/// obtenir n'apprend rien a personne.
///
/// Dans ce cas seul, le verrou 3 accepte aussi `same-site`. Le besoin est
/// concret : la page d'installation ecoute sur un port, le nœud sur un autre,
/// et passer de l'une a l'autre est une navigation `same-site` que le verrou
/// refusait — le portefeuille s'ouvrait sur « requete inter-sites : refusee ».
///
/// Ce que l'exception ne donne pas :
///
/// - **`same-site` sur `127.0.0.1` ne peut venir que de `127.0.0.1`.** Le site
///   d'un hote IP est cette IP elle-meme ; la page d'un attaquant distant reste
///   `cross-site`, donc refusee.
/// - Un nom de domaine qui resoudrait vers la boucle locale — la reliaison DNS —
///   bute d'abord sur le verrou 1, qui lit `Host`.
/// - `/rpc` n'est jamais public, donc jamais une coquille : rien de ce qui
///   deplace des fonds n'est concerne.
/// - Un POST n'est jamais une coquille, meme sur un chemin public.
fn garde_navigateur(
    req: &Request,
    coquille: bool,
    hote_public: Option<&str>,
) -> Option<&'static str> {
    // 1. `Host` : seule la boucle locale est un hote legitime — ou le nom que
    //    l'exploitant a **declare** pour un service public. Un autre nom de
    //    domaine signale une reliaison DNS.
    match req.headers.get("host") {
        Some(host) if !hote_local(host) && !hote_declare(host, hote_public) => {
            return Some(
                "en-tete Host inattendue : ce service ne repond qu'a 127.0.0.1, [::1] ou localhost",
            )
        }
        Some(_) => {}
        // Absente, elle ne prouve rien — mais un service publie ne repond que
        // sous le nom qu'on lui a donne, et une requete anonyme n'a pas ce nom.
        // En local on reste tolerant : la garde y protege d'un navigateur, qui
        // envoie toujours cet en-tete.
        None if hote_public.is_some() => {
            return Some("en-tete Host absente : ce service publie ne repond que sous son nom")
        }
        None => {}
    }

    // 2. `Origin` / `Referer` : une page web n'a rien a faire ici. Presents et
    //    non locaux, ils designent une origine tierce — sauf, la encore, le nom
    //    declare : la page de l'explorateur public est servie depuis lui, et
    //    ses appels en portent l'origine.
    for cle in ["origin", "referer"] {
        if let Some(v) = req.headers.get(cle) {
            if !origine_locale(v) && !origine_declaree(v, hote_public) {
                return Some("requete emise depuis une autre origine : refusee");
            }
        }
    }

    // 3. `Sec-Fetch-Site` : les navigateurs recents l'ajoutent d'office et une
    //    page ne peut pas le falsifier — c'est un en-tete interdit au script.
    if let Some(v) = req.headers.get("sec-fetch-site") {
        let admis = v == "same-origin" || v == "none" || (coquille && v == "same-site");
        if !admis {
            return Some("requete inter-sites : refusee");
        }
    }

    // 4. `Content-Type` : exiger `application/json` interdit la requete
    //    « simple ». Le navigateur devra faire un pre-vol, que ce service ne
    //    satisfait pas — donc la requete ne partira jamais.
    if req.method == "POST" {
        let ct = req
            .headers
            .get("content-type")
            .map(|s| {
                s.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        if ct != "application/json" {
            return Some("content-type: application/json requis");
        }
    }
    None
}

/// L'hote declare par l'exploitant pour un service public, port compris ou non.
///
/// La comparaison est insensible a la casse — un nom de domaine l'est — et
/// exacte sur le reste : `example.org.evil.example` ne doit pas passer pour
/// `example.org`, et c'est le genre de sous-chaine qui trompe une comparaison
/// paresseuse.
fn hote_declare(host: &str, declare: Option<&str>) -> bool {
    let Some(d) = declare else { return false };
    let nu = match host.rsplit_once(':') {
        // Un seul deux-points et un port numerique : c'est un port.
        Some((avant, apres))
            if !avant.contains(':') && apres.chars().all(|c| c.is_ascii_digit()) =>
        {
            avant
        }
        _ => host,
    };
    nu.eq_ignore_ascii_case(d)
}

/// Une origine servie par l'hote declare.
///
/// On exige `https` : le service public est derriere un mandataire qui termine
/// le chiffrement, et une origine en clair signalerait autre chose.
fn origine_declaree(valeur: &str, declare: Option<&str>) -> bool {
    let Some(d) = declare else { return false };
    let Some(reste) = valeur.strip_prefix("https://") else {
        return false;
    };
    // Le referent porte un chemin ; l'origine non. On coupe au premier `/`.
    let hote = reste.split('/').next().unwrap_or("");
    hote_declare(hote, Some(d))
}

/// Un hote qui designe cette machine, et rien d'autre.
fn hote_local(host: &str) -> bool {
    // Isoler l'hote du port. Trois formes possibles, et une seule facon de ne
    // pas se tromper : traiter la forme entre crochets a part, puis ne couper
    // sur `:` que s'il n'y en a qu'un — au-dela, c'est une adresse IPv6 nue.
    let nu = if let Some(reste) = host.strip_prefix('[') {
        match reste.split_once(']') {
            // Apres le crochet fermant, seul un port est admis. `[::1].evil.example`
            // n'est pas une adresse entre crochets, c'est un nom qui en porte le
            // costume.
            Some((interieur, apres)) if apres.is_empty() || apres.starts_with(':') => interieur,
            _ => return false,
        }
    } else if host.matches(':').count() == 1 {
        host.split_once(':').map(|(h, _)| h).unwrap_or(host)
    } else {
        host
    };

    // --- Une adresse, pas un prefixe de texte.
    //
    // La premiere version de ce controle testait `nu.starts_with("127.")`.
    // C'etait faux, et faux de la pire maniere : `127.0.0.1.evil.example` est un
    // nom de domaine qu'on enregistre en cinq minutes, et il satisfaisait le
    // test. Il franchissait alors les **quatre** verrous d'un coup — apres
    // reliaison, l'origine de la page hostile devient
    // `http://127.0.0.1.evil.example:PORT`, donc `origine_locale` l'accepte pour
    // la meme raison, `Sec-Fetch-Site` vaut `same-origin`, et une requete de
    // meme origine n'a pas de pre-vol, donc elle pose le bon `Content-Type`.
    // La reliaison DNS etait entierement rouverte.
    //
    // Un nom d'hote n'est du bouclage que s'il **est** une adresse de bouclage,
    // ou le mot `localhost`. On analyse, on ne compare plus des prefixes.
    if nu.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(v4) = nu.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Ok(v6) = nu.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback();
    }
    false
}

/// Une origine `http://127.0.0.1:PORT` ou equivalente.
fn origine_locale(v: &str) -> bool {
    let sans_schema = v
        .strip_prefix("http://")
        .or_else(|| v.strip_prefix("https://"))
        .unwrap_or(v);
    // Un `Referer` porte un chemin : on ne garde que l'autorite.
    let autorite = sans_schema.split('/').next().unwrap_or("");
    hote_local(autorite)
}

fn autorise(req: &Request, attendu: &str) -> bool {
    if let Some(a) = req.headers.get("authorization") {
        if let Some(v) = a.strip_prefix("Bearer ") {
            if egal_temps_constant(v.trim(), attendu) {
                return true;
            }
        }
    }
    // Le jeton ne voyage plus dans l'URL.
    //
    // Il y etait accepte, et l'explorateur le recommandait. Une URL finit dans
    // l'historique du navigateur, dans les journaux de tout mandataire, et dans
    // l'en-tete `Referer` de la premiere ressource externe chargee. Un secret
    // qui voyage dans une URL n'est plus un secret.
    false
}

fn lire_requete(flux: &TcpStream, echeance: std::time::Instant) -> Result<Request, &'static str> {
    let mut lecteur = BufReader::new(flux);
    let expire = |e: std::time::Instant| -> Result<(), &'static str> {
        if std::time::Instant::now() >= e {
            Err("requete trop lente")
        } else {
            Ok(())
        }
    };

    let mut ligne = String::new();
    lire_ligne(&mut lecteur, &mut ligne, echeance)?;
    let mut morceaux = ligne.split_whitespace();
    let method = morceaux.next().ok_or("ligne de requete vide")?.to_string();
    let cible = morceaux.next().ok_or("cible absente")?.to_string();

    let (chemin, requete) = match cible.split_once('?') {
        Some((c, q)) => (c.to_string(), q.to_string()),
        None => (cible, String::new()),
    };

    let mut query = BTreeMap::new();
    for paire in requete.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = paire.split_once('=').unwrap_or((paire, ""));
        query.insert(decoder_url(k), decoder_url(v));
    }

    let mut headers = BTreeMap::new();
    // --- Depasser la limite est un refus, jamais un silence.
    //
    // Cette boucle s'arretait a `MAX_HEADERS` **sans rien dire**, et la lecture
    // du corps reprenait la ou elle en etait : les en-tetes en trop devenaient
    // silencieusement le debut du corps. Aucune fuite ne s'ensuivait tant que
    // les connexions se ferment apres chaque reponse — mais une requete dont
    // le decoupage depend de l'emetteur est exactement le terrain de la
    // contrebande de requetes, et c'est le genre de tolerance qui devient une
    // faille le jour ou l'on ajoute la reutilisation des connexions.
    //
    // Un audit d'intrusion l'a releve avant cette mise en ligne. On refuse.
    let mut fin_des_entetes = false;
    for _ in 0..MAX_HEADERS {
        let mut l = String::new();
        lire_ligne(&mut lecteur, &mut l, echeance)?;
        let l = l.trim_end();
        if l.is_empty() {
            fin_des_entetes = true;
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            let clef = k.trim().to_ascii_lowercase();
            // --- Un `Host` en double n'est jamais une maladresse.
            //
            // La table conserve la derniere valeur : `Host: evil.example` suivi
            // de `Host: explorateur.example.org` passait donc la garde, alors que le
            // premier `Host` est celui qu'un intermediaire aura lu. Deux
            // machines qui ne lisent pas la meme valeur pour le meme champ,
            // c'est la definition de la contrebande de requetes.
            //
            // Aucun navigateur n'en envoie deux, et la norme l'interdit. On
            // refuse plutot que de choisir.
            if clef == "host" && headers.contains_key("host") {
                return Err("en-tete Host en double");
            }
            headers.insert(clef, v.trim().to_string());
        }
        expire(echeance)?;
    }
    if !fin_des_entetes {
        return Err("trop d'en-tetes");
    }

    let taille: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if taille > MAX_BODY {
        return Err("corps de requete trop grand");
    }

    // --- Le tampon est rempli, pas pre-alloue.
    //
    // `vec![0u8; taille]` reservait un mebioctet sur la seule foi d'un
    // `Content-Length` que l'attaquant ecrit, puis attendait des octets qui ne
    // venaient jamais. Chaque connexion coutait donc un mebioctet de tas et un
    // fil, pour zero octet envoye. On lit par morceaux : ce qui est alloue est
    // ce qui est arrive.
    let mut brut: Vec<u8> = Vec::new();
    if taille > 0 {
        let mut tampon = [0u8; 16 * 1024];
        while brut.len() < taille {
            expire(echeance)?;
            let voulu = (taille - brut.len()).min(tampon.len());
            match lecteur.read(&mut tampon[..voulu]) {
                Ok(0) => return Err("corps de requete incomplet"),
                Ok(n) => brut.extend_from_slice(&tampon[..n]),
                Err(_) => return Err("corps de requete incomplet"),
            }
        }
    }
    let body = String::from_utf8_lossy(&brut).into_owned();

    Ok(Request {
        method,
        path: chemin,
        query,
        headers,
        body,
        // Pose par l'appelant, qui seul connait la connexion.
        client: None,
    })
}

/// Lit une ligne, sans jamais depasser l'echeance.
///
/// # Pourquoi l'echeance descend jusqu'ici
///
/// L'echeance globale etait verifiee **entre** les lignes seulement. Or cette
/// boucle lit octet par octet, et seul le delai de lecture de trente secondes
/// s'appliquait a chacun. Un octet toutes les vingt-cinq secondes a l'interieur
/// d'une **seule** en-tete — jusqu'a `MAX_LINE`, soit 8 Kio — tenait donc une
/// connexion, et son fil, pendant des dizaines d'heures. Avec le plafond de
/// soixante-quatre connexions, autant de connexions de ce type suffisaient a
/// fermer le service pour un cout derisoire.
///
/// C'est Slowloris, et une echeance qui ne descend pas jusqu'a la lecture n'est
/// pas une echeance.
fn lire_ligne(
    lecteur: &mut BufReader<&TcpStream>,
    sortie: &mut String,
    echeance: std::time::Instant,
) -> Result<(), &'static str> {
    sortie.clear();
    let mut total = 0usize;
    loop {
        if std::time::Instant::now() >= echeance {
            return Err("requete trop lente");
        }
        let mut octet = [0u8; 1];
        match lecteur.read(&mut octet) {
            Ok(0) => return Err("connexion fermee"),
            Ok(_) => {}
            Err(_) => return Err("lecture impossible"),
        }
        total += 1;
        if total > MAX_LINE {
            return Err("ligne d'en-tete trop longue");
        }
        if octet[0] == b'\n' {
            return Ok(());
        }
        sortie.push(octet[0] as char);
    }
}

fn decoder_url(s: &str) -> String {
    let octets: Vec<u8> = s.bytes().collect();
    let mut out = Vec::with_capacity(octets.len());
    let mut i = 0;
    while i < octets.len() {
        match octets[i] {
            b'%' if i + 2 < octets.len() => {
                let h = |c: u8| (c as char).to_digit(16);
                match (h(octets[i + 1]), h(octets[i + 2])) {
                    (Some(a), Some(b)) => {
                        out.push((a * 16 + b) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(octets[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// La politique de securite du contenu de cette reponse.
///
/// `script-src` change selon la reponse : le jeton de la page quand il y en a
/// une, et l'interdiction pure sinon. Une reponse JSON ou un message d'erreur
/// n'ont aucun script a executer, et le dire coute une ligne.
///
/// `style-src` garde `'unsafe-inline'` : les pages emploient des attributs
/// `style`, qu'un jeton ne couvre pas — c'est une limite de la norme, pas un
/// choix. Le risque est sans commune mesure : une feuille de style injectee ne
/// s'execute pas.
fn politique(r: &Response) -> String {
    let scripts = match &r.nonce {
        Some(n) => format!("'nonce-{n}'"),
        None => "'none'".to_string(),
    };
    format!(
        "default-src 'none'; script-src {scripts}; style-src 'unsafe-inline'; \
         connect-src 'self'; base-uri 'none'; form-action 'self'; \
         frame-ancestors 'none'"
    )
}

fn ecrire_reponse(flux: &mut TcpStream, r: &Response) -> std::io::Result<()> {
    let texte = match r.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
    let entete = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Cache-Control: no-store\r\n\
         Content-Security-Policy: {}\r\n\
         \r\n",
        r.status,
        texte,
        r.content_type,
        r.body.len(),
        politique(r)
    );
    flux.write_all(entete.as_bytes())?;
    flux.write_all(r.body.as_bytes())?;
    flux.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Client HTTP minimal, uniquement pour les tests.
    ///
    /// Ferme le sens ecriture apres l'envoi. Sans cela, une requete tronquee
    /// laisse le serveur attendre la suite jusqu'au delai de lecture, et la
    /// suite de tests met des minutes la ou elle devrait mettre des
    /// millisecondes — defaut constate a la premiere execution.
    fn requete(addr: SocketAddr, brut: &str) -> String {
        let mut s = TcpStream::connect(addr).expect("connexion");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(brut.as_bytes()).expect("envoi");
        let _ = s.shutdown(std::net::Shutdown::Write);
        let mut reponse = String::new();
        let _ = s.read_to_string(&mut reponse);
        reponse
    }

    fn get(addr: SocketAddr, chemin: &str) -> String {
        requete(
            addr,
            &format!("GET {chemin} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
        )
    }

    fn post(addr: SocketAddr, chemin: &str, corps: &str) -> String {
        requete(
            addr,
            &format!(
                "POST {chemin} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{corps}",
                corps.len()
            ),
        )
    }

    fn echo() -> impl Fn(Request) -> Response + Send + Sync + 'static {
        |r: Request| {
            Response::text(
                200,
                &format!("{} {} q={:?} body={}", r.method, r.path, r.query, r.body),
            )
        }
    }

    #[test]
    fn une_requete_get_est_servie() {
        let h = serve("127.0.0.1:0", None, echo()).expect("demarrage");
        let r = get(h.addr, "/etat");
        assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
        assert!(r.contains("GET /etat"), "{r}");
        h.shutdown();
    }

    #[test]
    fn les_parametres_de_requete_sont_decodes() {
        let h = serve("127.0.0.1:0", None, echo()).expect("demarrage");
        let r = get(h.addr, "/x?a=1&b=deux%20mots&c=a+b");
        assert!(r.contains("deux mots"), "{r}");
        assert!(r.contains("a b"), "{r}");
        h.shutdown();
    }

    #[test]
    fn un_corps_post_est_lu_entierement() {
        let h = serve("127.0.0.1:0", None, echo()).expect("demarrage");
        let corps = r#"{"jsonrpc":"2.0","method":"getinfo","id":1}"#;
        let r = post(h.addr, "/rpc", corps);
        assert!(r.contains("getinfo"), "{r}");
        h.shutdown();
    }

    #[test]
    fn une_page_hostile_n_atteint_pas_le_rpc() {
        let h = serve("127.0.0.1:0", None, echo()).expect("demarrage");
        let corps = r#"{"jsonrpc":"2.0","method":"getinfo","id":1}"#;

        // 1. Le formulaire sans JavaScript : `enctype="text/plain"`.
        let r = requete(
            h.addr,
            &format!(
                "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Content-Type: text/plain\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{corps}",
                corps.len()
            ),
        );
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");

        // 2. Une origine tierce.
        let r = requete(
            h.addr,
            &format!(
                "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Origin: http://mechant.example\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{corps}",
                corps.len()
            ),
        );
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");

        // 3. La marque que le navigateur pose lui-meme.
        let r = requete(
            h.addr,
            &format!(
                "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Sec-Fetch-Site: cross-site\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{corps}",
                corps.len()
            ),
        );
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        h.shutdown();
    }

    /// Le mode public accepte le nom declare, et lui seul.
    ///
    /// # Ce que ce mode desarme, et ce qu'il ne desarme pas
    ///
    /// La garde refuse tout `Host` non local : c'est la defense contre la
    /// reliaison DNS, celle qui empeche une page hostile d'atteindre un
    /// portefeuille par la boucle locale. Un explorateur public, lui, est
    /// expose **exprès** : les navigateurs qui l'atteignent enverront son nom
    /// de domaine, et la garde les refuserait tous.
    ///
    /// On declare donc ce nom au serveur. Tout le reste tient : un autre nom
    /// est refuse, une origine tierce est refusee, et le `Content-Type` reste
    /// exige. Et le binaire refuse de combiner ce mode avec un portefeuille.
    #[test]
    fn le_mode_public_n_accepte_que_le_nom_declare() {
        let h = serve_public_web("127.0.0.1:0", "explorateur.example.org".to_string(), echo())
            .expect("demarrage");

        let avec = |entetes: &str| {
            requete(
                h.addr,
                &format!(
                    "POST /rpc HTTP/1.1\r\n{entetes}\
                     Content-Type: application/json\r\nContent-Length: 2\r\n\
                     Connection: close\r\n\r\n{{}}"
                ),
            )
        };

        // 1. Le nom declare passe, avec ou sans port, quelle que soit la casse.
        for hote in [
            "explorateur.example.org",
            "explorateur.example.org:443",
            "Explorateur.Example.Org",
        ] {
            let r = avec(&format!("Host: {hote}\r\n"));
            assert!(r.starts_with("HTTP/1.1 200"), "{hote} doit passer : {r}");
        }

        // 2. La boucle locale reste admise : le mandataire parle en local.
        let r = avec("Host: 127.0.0.1\r\n");
        assert!(
            r.starts_with("HTTP/1.1 200"),
            "le mandataire local doit passer : {r}"
        );

        // 3. Un autre nom est refuse. Et surtout : un nom qui **contient** le
        //    notre ne passe pas. `explorateur.example.org.evil.example` est le
        //    genre de chaine qui trompe une comparaison paresseuse.
        for hote in [
            "evil.example",
            "explorateur.example.org.evil.example",
            "example.org",
        ] {
            let r = avec(&format!("Host: {hote}\r\n"));
            assert!(
                r.starts_with("HTTP/1.1 403"),
                "{hote} doit etre refuse : {r}"
            );
        }

        // 4. L'origine declaree passe — la page de l'explorateur est servie par
        //    ce nom — mais une origine tierce reste refusee.
        let r = avec("Host: explorateur.example.org\r\nOrigin: https://explorateur.example.org\r\n");
        assert!(
            r.starts_with("HTTP/1.1 200"),
            "l'origine declaree doit passer : {r}"
        );
        let r = avec("Host: explorateur.example.org\r\nOrigin: https://evil.example\r\n");
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "une origine tierce doit etre refusee : {r}"
        );
        // En clair, non : le service public est derriere un mandataire qui
        // termine le chiffrement.
        let r = avec("Host: explorateur.example.org\r\nOrigin: http://explorateur.example.org\r\n");
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "une origine en clair doit etre refusee : {r}"
        );

        h.shutdown();
    }

    /// Un `Host` en double est refuse, quel que soit l'ordre.
    ///
    /// La table des en-tetes conserve la derniere valeur. `Host: evil.example`
    /// suivi de `Host: explorateur.example.org` passait donc la garde, alors qu'un
    /// intermediaire aurait lu le premier. Deux machines qui ne lisent pas la
    /// meme valeur pour le meme champ, c'est la definition de la contrebande de
    /// requetes. Releve par l'audit d'intrusion avant la mise en ligne.
    #[test]
    fn un_host_en_double_est_refuse_dans_les_deux_ordres() {
        let h = serve_public_web("127.0.0.1:0", "explorateur.example.org".to_string(), echo())
            .expect("demarrage");
        for (a, b) in [
            ("evil.example", "explorateur.example.org"),
            ("explorateur.example.org", "evil.example"),
        ] {
            let r = requete(
                h.addr,
                &format!(
                    "POST /rpc HTTP/1.1\r\nHost: {a}\r\nHost: {b}\r\n\
                     Content-Type: application/json\r\nContent-Length: 2\r\n\
                     Connection: close\r\n\r\n{{}}"
                ),
            );
            assert!(
                r.starts_with("HTTP/1.1 400"),
                "Host double ({a}, {b}) doit etre refuse : {r}"
            );
        }
        h.shutdown();
    }

    /// Un service publie ne repond que sous son nom : sans `Host`, il refuse.
    #[test]
    fn le_mode_public_exige_un_host() {
        let h = serve_public_web("127.0.0.1:0", "explorateur.example.org".to_string(), echo())
            .expect("demarrage");
        let r = requete(
            h.addr,
            "POST /rpc HTTP/1.1\r\nContent-Type: application/json\r\n\
             Content-Length: 2\r\nConnection: close\r\n\r\n{}",
        );
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "sans Host, refus attendu : {r}"
        );
        h.shutdown();
    }

    /// Le mode public refuse d'ecouter ailleurs que sur la boucle locale.
    ///
    /// Ce serveur traite une connexion par fil, soixante-quatre au plus :
    /// expose directement, il tombe sous une poignee de connexions ouvertes et
    /// jamais terminees. L'audit l'a reproduit en deux lignes — deux cents
    /// connexions muettes, et le service repondait 503 a tout le monde. Le
    /// mandataire est fait pour ca ; le refus est ici plutot que dans une note.
    #[test]
    fn le_mode_public_refuse_d_ecouter_hors_de_la_boucle_locale() {
        let r = serve_public_web("0.0.0.0:0", "explorateur.example.org".to_string(), echo());
        assert!(
            matches!(r, Err(HttpError::ExpositionSansJeton(_))),
            "un mode public expose directement doit etre refuse"
        );
    }

    /// Au-dela de la limite, les en-tetes ne deviennent pas le corps.
    ///
    /// La boucle s'arretait a `MAX_HEADERS` sans rien dire, et la lecture du
    /// corps reprenait la ou elle en etait : les en-tetes en trop devenaient
    /// silencieusement le debut du corps. Une requete dont le decoupage depend
    /// de l'emetteur est le terrain de la contrebande de requetes.
    #[test]
    fn trop_d_en_tetes_est_un_refus_pas_un_reinterpretation() {
        let h = serve("127.0.0.1:0", None, echo()).expect("demarrage");
        let bourrage: String = (0..MAX_HEADERS + 10)
            .map(|i| format!("X-{i}: v\r\n"))
            .collect();
        let r = requete(
            h.addr,
            &format!("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n{bourrage}Connection: close\r\n\r\n"),
        );
        assert!(
            r.starts_with("HTTP/1.1 400"),
            "l'exces doit etre refuse : {r}"
        );
        h.shutdown();
    }

    /// Le mode public n'assouplit pas le `Content-Type`.
    #[test]
    fn le_mode_public_exige_toujours_du_json() {
        let h = serve_public_web("127.0.0.1:0", "explorateur.example.org".to_string(), echo())
            .expect("demarrage");
        let r = requete(
            h.addr,
            "POST /rpc HTTP/1.1\r\nHost: explorateur.example.org\r\n\
             Content-Type: text/plain\r\nContent-Length: 2\r\n\
             Connection: close\r\n\r\n{}",
        );
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "un POST non-JSON doit etre refuse : {r}"
        );
        h.shutdown();
    }

    /// L'exception `same-site` ne vaut que pour une coquille demandee en GET.
    ///
    /// Elle existe parce que la page d'installation et le nœud vivent sur deux
    /// ports, et que passer de l'une a l'autre est une navigation `same-site`.
    /// Ces quatre epreuves disent ou elle s'arrete.
    #[test]
    fn same_site_n_est_admis_que_sur_une_coquille_en_lecture() {
        let h =
            serve_avec_public("127.0.0.1:0", None, &["/portefeuille"], echo()).expect("demarrage");

        let avec = |methode: &str, chemin: &str, site: &str| {
            requete(
                h.addr,
                &format!(
                    "{methode} {chemin} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                     Sec-Fetch-Site: {site}\r\n\
                     Content-Type: application/json\r\nContent-Length: 2\r\n\
                     Connection: close\r\n\r\n{{}}"
                ),
            )
        };

        // 1. Le cas voulu : arriver sur la page du portefeuille depuis la page
        //    d'installation, qui est sur un autre port.
        let r = avec("GET", "/portefeuille", "same-site");
        assert!(
            r.starts_with("HTTP/1.1 200"),
            "la coquille doit passer : {r}"
        );

        // 2. Le meme assouplissement ne s'etend pas au RPC, qui n'est pas
        //    public. C'est lui qui deplace des fonds.
        let r = avec("POST", "/rpc", "same-site");
        assert!(r.starts_with("HTTP/1.1 403"), "le RPC doit refuser : {r}");

        // 3. Ni a un POST sur le chemin public lui-meme : une coquille se lit,
        //    elle ne s'ecrit pas.
        let r = avec("POST", "/portefeuille", "same-site");
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "un POST n'est pas une coquille : {r}"
        );

        // 4. Et `cross-site` reste refuse partout : c'est la marque que pose le
        //    navigateur quand la page vient d'ailleurs que de cette machine.
        let r = avec("GET", "/portefeuille", "cross-site");
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "cross-site doit refuser : {r}"
        );

        h.shutdown();
    }

    /// Un nom d'hote n'est du bouclage que s'il **est** une adresse de bouclage.
    ///
    /// Le controle a d'abord teste `starts_with("127.")`. Un audit a montre que
    /// `127.0.0.1.evil.example` — un nom de domaine, pas une adresse — passait,
    /// et rouvrait entierement la reliaison DNS.
    #[test]
    fn un_nom_qui_ressemble_a_du_bouclage_n_en_est_pas() {
        for bon in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.0.0.1:8080",
            "127.1.2.3",
            "[::1]",
            "[::1]:8080",
        ] {
            assert!(hote_local(bon), "{bon} devrait etre reconnu local");
        }
        for mauvais in [
            "127.0.0.1.evil.example",
            "127.0.0.1.evil.example:8080",
            "localhost.evil.example",
            "127-0-0-1.evil.example",
            "evil.example",
            "1270.0.0.1",
            "127.0.0.1x",
            "[::1].evil.example",
        ] {
            assert!(
                !hote_local(mauvais),
                "{mauvais} ne doit pas passer pour local"
            );
            assert!(
                !origine_locale(&format!("http://{mauvais}")),
                "origine http://{mauvais} ne doit pas passer pour locale"
            );
        }
    }

    /// Reliaison DNS : un nom qui finit par pointer vers 127.0.0.1 rend la page
    /// hostile de meme origine. L'en-tete `Host` le trahit.
    #[test]
    fn un_host_etranger_est_refuse() {
        let h = serve("127.0.0.1:0", None, echo()).expect("demarrage");
        let r = requete(
            h.addr,
            "GET /etat HTTP/1.1\r\nHost: rebind.mechant.example\r\nConnection: close\r\n\r\n",
        );
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        h.shutdown();
    }

    /// Le jeton ne doit plus ouvrir quoi que ce soit depuis l'URL.
    #[test]
    fn le_jeton_ne_passe_plus_par_l_url() {
        let h = serve("127.0.0.1:0", Some("secret".into()), echo()).expect("demarrage");
        let r = get(h.addr, "/etat?token=secret");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");

        let r = requete(
            h.addr,
            "GET /etat HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Authorization: Bearer secret\r\nConnection: close\r\n\r\n",
        );
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        h.shutdown();
    }

    /// Le garde-fou le plus important de ce fichier.
    #[test]
    fn ecouter_hors_bouclage_sans_jeton_est_refuse() {
        let r = serve("0.0.0.0:0", None, echo());
        assert!(
            matches!(r, Err(HttpError::ExpositionSansJeton(_))),
            "un port RPC public sans jeton doit etre refuse au demarrage"
        );
    }

    #[test]
    fn ecouter_hors_bouclage_avec_jeton_est_permis() {
        let h = serve("0.0.0.0:0", Some("secret".into()), echo());
        assert!(h.is_ok());
        if let Ok(h) = h {
            h.shutdown();
        }
    }

    #[test]
    fn le_jeton_est_exige_quand_il_est_configure() {
        let h = serve("127.0.0.1:0", Some("s3cret".into()), echo()).expect("demarrage");

        assert!(get(h.addr, "/x").starts_with("HTTP/1.1 401"));
        assert!(get(h.addr, "/x?token=faux").starts_with("HTTP/1.1 401"));
        // Le jeton dans l'URL n'ouvre plus rien, meme juste : voir
        // `le_jeton_ne_passe_plus_par_l_url`.
        assert!(get(h.addr, "/x?token=s3cret").starts_with("HTTP/1.1 401"));

        let avec_entete = requete(
            h.addr,
            "GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Authorization: Bearer s3cret\r\nConnection: close\r\n\r\n",
        );
        assert!(avec_entete.starts_with("HTTP/1.1 200"), "{avec_entete}");
        h.shutdown();
    }

    #[test]
    fn la_comparaison_de_jeton_est_a_temps_constant() {
        assert!(egal_temps_constant("abc", "abc"));
        assert!(!egal_temps_constant("abc", "abd"));
        assert!(!egal_temps_constant("abc", "abcd"));
        assert!(!egal_temps_constant("", "a"));
        assert!(egal_temps_constant("", ""));
    }

    #[test]
    fn un_corps_trop_grand_est_refuse() {
        let h = serve("127.0.0.1:0", None, echo()).expect("demarrage");
        let r = requete(
            h.addr,
            &format!(
                "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_BODY + 1
            ),
        );
        assert!(r.starts_with("HTTP/1.1 400"), "{r}");
        h.shutdown();
    }

    #[test]
    fn une_ligne_d_entete_interminable_est_coupee() {
        let h = serve("127.0.0.1:0", None, echo()).expect("demarrage");
        let mut brut = String::from("GET /x HTTP/1.1\r\nX: ");
        brut.push_str(&"a".repeat(MAX_LINE + 100));
        brut.push_str("\r\n\r\n");
        let r = requete(h.addr, &brut);
        assert!(r.starts_with("HTTP/1.1 400"), "{r}");
        h.shutdown();
    }

    #[test]
    fn des_octets_aleatoires_ne_font_pas_tomber_le_serveur() {
        let h = serve("127.0.0.1:0", None, echo()).expect("demarrage");
        let mut g = 0x1234_5678u64;
        for _ in 0..20 {
            g = g.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let mut s = String::new();
            for i in 0..((g % 100) as usize) {
                s.push((((g >> (i % 40)) % 94) as u8 + 33) as char);
            }
            let _ = requete(h.addr, &s);
        }
        // Le serveur doit encore repondre normalement.
        assert!(get(h.addr, "/vivant").starts_with("HTTP/1.1 200"));
        h.shutdown();
    }

    #[test]
    fn l_entete_anti_sniffing_est_present() {
        let h = serve("127.0.0.1:0", None, echo()).expect("demarrage");
        let r = get(h.addr, "/x");
        assert!(r.contains("X-Content-Type-Options: nosniff"), "{r}");
        h.shutdown();
    }

    /// Page d'essai : un seul script en ligne, comme les pages reelles.
    fn page() -> impl Fn(Request) -> Response + Send + Sync + 'static {
        |_r: Request| Response::html("<!doctype html><body><script>1;</script>".into())
    }

    /// Extrait la valeur du jeton porte par la politique de securite.
    fn jeton_de_l_entete(reponse: &str) -> Option<String> {
        let d = reponse.find("script-src 'nonce-")? + "script-src 'nonce-".len();
        let f = d + reponse[d..].find('\'')?;
        Some(reponse[d..f].to_string())
    }

    #[test]
    fn le_script_en_ligne_n_est_plus_autorise_globalement() {
        let h = serve("127.0.0.1:0", None, page()).expect("demarrage");
        let r = get(h.addr, "/p");
        let ligne = r
            .lines()
            .find(|l| l.starts_with("Content-Security-Policy:"))
            .unwrap_or("")
            .to_string();
        let scripts = ligne
            .split("script-src ")
            .nth(1)
            .and_then(|s| s.split(';').next())
            .unwrap_or("")
            .to_string();
        assert!(
            !scripts.contains("unsafe-inline"),
            "la politique autorise encore n'importe quel script en ligne : {ligne}"
        );
        assert!(ligne.contains("default-src 'none'"), "{ligne}");
        assert!(ligne.contains("frame-ancestors 'none'"), "{ligne}");
        h.shutdown();
    }

    #[test]
    fn le_jeton_de_l_entete_est_celui_de_la_page() {
        let h = serve("127.0.0.1:0", None, page()).expect("demarrage");
        let r = get(h.addr, "/p");
        let jeton = jeton_de_l_entete(&r).expect("jeton dans l'en-tete");
        assert_eq!(jeton.len(), 32, "jeton trop court : {jeton}");
        assert!(jeton.chars().all(|c| c.is_ascii_hexdigit()), "{jeton}");
        assert!(
            r.contains(&format!("<script nonce=\"{jeton}\">")),
            "la balise ne porte pas le jeton de l'en-tete : {r}"
        );
        h.shutdown();
    }

    #[test]
    fn deux_pages_servies_n_ont_pas_le_meme_jeton() {
        let h = serve("127.0.0.1:0", None, page()).expect("demarrage");
        let a = jeton_de_l_entete(&get(h.addr, "/p")).expect("jeton a");
        let b = jeton_de_l_entete(&get(h.addr, "/p")).expect("jeton b");
        assert_ne!(a, b, "un jeton previsible n'en est pas un");
        h.shutdown();
    }

    /// Un script injecte n'a pas le jeton : il reste inerte.
    ///
    /// La page ne porte qu'un seul `<script>`, celui qu'on a ecrit. Une balise
    /// arrivee par un autre chemin ne peut pas porter le jeton, tire apres
    /// coup et different a chaque reponse.
    #[test]
    fn un_second_script_ne_recoit_pas_le_jeton() {
        let h = serve("127.0.0.1:0", None, |_r: Request| {
            Response::html("<script>bon()</script><script>injecte()</script>".into())
        })
        .expect("demarrage");
        let r = get(h.addr, "/p");
        let jeton = jeton_de_l_entete(&r).expect("jeton");
        assert!(
            r.contains(&format!("<script nonce=\"{jeton}\">bon()")),
            "{r}"
        );
        assert!(r.contains("<script>injecte()"), "{r}");
        h.shutdown();
    }

    #[test]
    fn une_reponse_json_n_autorise_aucun_script() {
        let h = serve("127.0.0.1:0", None, |_r: Request| {
            Response::json("{\"ok\":true}".into())
        })
        .expect("demarrage");
        let r = get(h.addr, "/j");
        assert!(r.contains("script-src 'none'"), "{r}");
        assert!(!r.contains("nonce-"), "{r}");
        h.shutdown();
    }

    /// L'adresse du client vient de la connexion — sauf derriere le
    /// mandataire local, ou elle vient de `X-Forwarded-For`. Un
    /// `X-Forwarded-For` qui n'arrive pas de la boucle locale est un client
    /// qui se deguise : il est ignore.
    #[test]
    fn l_adresse_du_client_ne_se_forge_pas() {
        let bouclage: IpAddr = "127.0.0.1".parse().unwrap();
        let lointain: IpAddr = "203.0.113.9".parse().unwrap();
        let visiteur: IpAddr = "198.51.100.7".parse().unwrap();
        let mut h = BTreeMap::new();

        // Sans en-tete : l'adresse de la connexion, quelle qu'elle soit.
        assert_eq!(adresse_client(Some(bouclage), &h), Some(bouclage));
        assert_eq!(adresse_client(Some(lointain), &h), Some(lointain));
        assert_eq!(adresse_client(None, &h), None);

        // Depuis la boucle locale, l'en-tete est celui du mandataire : on lit
        // la premiere adresse, meme si une chaine suit.
        h.insert("x-forwarded-for".into(), "198.51.100.7, 10.0.0.1".into());
        assert_eq!(adresse_client(Some(bouclage), &h), Some(visiteur));

        // Depuis ailleurs, le meme en-tete est une forgerie : ignore.
        assert_eq!(adresse_client(Some(lointain), &h), Some(lointain));

        // Illisible : on retombe sur la connexion, sans echouer.
        h.insert("x-forwarded-for".into(), "pas-une-adresse".into());
        assert_eq!(adresse_client(Some(bouclage), &h), Some(bouclage));
    }

    /// Le serveur pose `client` sur la requete qu'il transmet, d'apres la
    /// connexion et l'en-tete du mandataire — et l'en-tete n'est lu que sur
    /// une connexion locale, ce qui est le cas de toutes celles d'ici.
    #[test]
    fn la_requete_transmise_porte_l_adresse_du_client() {
        let h = serve("127.0.0.1:0", None, |r: Request| {
            Response::text(200, &format!("client={:?}", r.client))
        })
        .expect("demarrage");
        let r = get(h.addr, "/x");
        assert!(r.contains("client=Some(127.0.0.1)"), "{r}");
        let r = requete(
            h.addr,
            "GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-For: 198.51.100.7\r\n\
             Connection: close\r\n\r\n",
        );
        assert!(r.contains("client=Some(198.51.100.7)"), "{r}");
        h.shutdown();
    }

    /// Le jeton d'amorcage s'echange une fois, puis ne vaut plus rien.
    ///
    /// C'est ce qui ferme A2 hors Linux : ce qui traine dans la ligne de
    /// commande du navigateur est l'amorce, pas le jeton de session, et
    /// apres la premiere ouverture elle n'ouvre plus rien — ni le RPC, ni un
    /// second echange.
    #[test]
    fn le_jeton_d_amorcage_ne_sert_qu_une_fois() {
        let h = serve_avec_amorce(
            "127.0.0.1:0",
            "jeton-de-session".into(),
            "am0rce".into(),
            &["/portefeuille"],
            echo(),
        )
        .expect("demarrage");
        let bearer = |methode: &str, chemin: &str, secret: &str| {
            requete(
                h.addr,
                &format!(
                    "{methode} {chemin} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                     Content-Type: application/json\r\nContent-Length: 0\r\n\
                     Authorization: Bearer {secret}\r\nConnection: close\r\n\r\n"
                ),
            )
        };

        // 1. L'amorce n'ouvre rien d'autre que l'echange.
        let r = bearer("POST", "/rpc", "am0rce");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");

        // 2. Une amorce fausse n'obtient rien.
        let r = bearer("POST", CHEMIN_SESSION, "am0rcf");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");

        // 3. L'echange rend le jeton de session, une fois.
        let r = bearer("POST", CHEMIN_SESSION, "am0rce");
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        assert!(r.contains(r#"{"jeton":"jeton-de-session"}"#), "{r}");

        // 4. Ce qui etait dans argv ne vaut plus rien : ni un second echange,
        //    ni le RPC.
        let r = bearer("POST", CHEMIN_SESSION, "am0rce");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");
        let r = bearer("POST", "/rpc", "am0rce");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");

        // 5. Le jeton de session, lui, ouvre le RPC — et n'est pas une amorce.
        let r = bearer("POST", "/rpc", "jeton-de-session");
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        let r = bearer("POST", CHEMIN_SESSION, "jeton-de-session");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");

        // 6. L'echange est un POST JSON comme un autre : la garde du
        //    navigateur s'y applique.
        let r = requete(
            h.addr,
            &format!(
                "POST {CHEMIN_SESSION} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Origin: http://mechant.example\r\nContent-Type: application/json\r\n\
                 Content-Length: 0\r\nAuthorization: Bearer am0rce\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        h.shutdown();
    }

    /// Sans amorce configuree, le chemin d'echange n'existe pas : il tombe
    /// sur le jeton, puis sur le routeur, comme n'importe quel chemin.
    #[test]
    fn sans_amorce_le_chemin_d_echange_n_est_qu_un_chemin() {
        let h = serve("127.0.0.1:0", Some("s".into()), echo()).expect("demarrage");
        let r = post(h.addr, CHEMIN_SESSION, "{}");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");
        h.shutdown();
    }
}
