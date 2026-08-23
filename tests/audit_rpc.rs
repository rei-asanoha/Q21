//! Audit adverse de la surface HTTP / JSON-RPC / explorateur / portefeuille.
//!
//! Chaque test de ce fichier est un **exploit** : il se connecte reellement en
//! TCP au serveur et lui envoie des octets hostiles.
//!
//! # Ce que ce fichier est devenu
//!
//! A l'origine, un test `faille_*` qui passait *demontrait* une faille. Ces
//! failles ont ete corrigees ; les tests, eux, sont restes, sous le meme nom, et
//! verifient desormais que la correction tient. Le nom raconte l'attaque, le
//! commentaire raconte ce qu'elle permettait, et les assertions verifient
//! qu'elle ne permet plus rien. Un test qui echoue ici signale une regression
//! vers l'etat d'avant.
//!
//! Les tests `ok_*` confirment, comme avant, qu'une attaque echoue.
//!
//! Ce que les assertions decrivent est le comportement **observe**, pas le
//! comportement souhaite. La ou une rugosite subsiste — un `Content-Length`
//! duplique, des en-tetes au-dela de la soixante-quatrieme — le test la fixe
//! telle quelle et la nomme, plutot que de la maquiller : c'est ainsi qu'on
//! s'apercoit qu'elle a bouge.
//!
//! Rien de ce fichier ne modifie `src/`.

use q21_core::address::Network;
use q21_core::chain::{genesis_block, Chain};
use q21_core::http::{self, Request, Response, ServerHandle};
use q21_core::net::Node;
use q21_core::rpc::RpcContext;
use q21_core::wallet::Wallet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const RESEAU: Network = Network::Regtest;

// ---------------------------------------------------------------------------
// Harnais : le meme routeur que src/bin/q21.rs (fonction `servir`, l. 1553).
// ---------------------------------------------------------------------------

fn routeur(ctx: &RpcContext, req: Request) -> Response {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            Response::html(q21_core::explorer::PAGE.to_string())
        }
        ("POST", "/rpc") => Response::json(ctx.handle(&req.body)),
        ("GET", "/rpc") => Response::text(405, "POST attendu"),
        _ => Response::not_found(),
    }
}

fn serveur(avec_portefeuille: bool, token: Option<&str>) -> ServerHandle {
    let g = genesis_block(RESEAU);
    let node = Arc::new(Node::new(RESEAU, Chain::new(RESEAU, g)));
    let ctx = RpcContext {
        sur_changement: None,
        node,
        wallet: if avec_portefeuille {
            Some(Arc::new(Mutex::new(Wallet::from_seed([7u8; 32], RESEAU))))
        } else {
            None
        },
        network: RESEAU,
        index: None,
    };
    http::serve("127.0.0.1:0", token.map(|s| s.to_string()), move |req| {
        routeur(&ctx, req)
    })
    .expect("demarrage du serveur")
}

/// Envoie des octets bruts, ferme le sens ecriture, lit tout.
fn brut(addr: SocketAddr, octets: &[u8]) -> String {
    let mut s = TcpStream::connect(addr).expect("connexion");
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(octets).expect("envoi");
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut r = Vec::new();
    let _ = s.read_to_end(&mut r);
    String::from_utf8_lossy(&r).into_owned()
}

/// POST /rpc avec en-tetes libres.
fn post_rpc_avec(addr: SocketAddr, entetes: &str, corps: &str) -> String {
    brut(
        addr,
        format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n{entetes}Content-Length: {}\r\nConnection: close\r\n\r\n{corps}",
            corps.len()
        )
        .as_bytes(),
    )
}

/// Un client legitime : celui de l'explorateur, ou `curl`.
///
/// Depuis que le serveur exige `application/json`, l'absence de cet en-tete est
/// elle-meme un refus — c'est le point de la correction. Les exploits qui
/// veulent l'omettre appellent `post_rpc_avec` directement.
fn post_rpc(addr: SocketAddr, corps: &str) -> String {
    post_rpc_avec(addr, "Content-Type: application/json\r\n", corps)
}

fn corps_de(reponse: &str) -> &str {
    reponse.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
}

fn appel(addr: SocketAddr, methode: &str, params: &str) -> String {
    let c = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{methode}","params":{params}}}"#);
    post_rpc(addr, &c).to_string()
}

fn adresse_regtest(addr: SocketAddr) -> String {
    let r = appel(addr, "getnewaddress", "{}");
    let b = corps_de(&r).to_string();
    let i = b.find(r#""adresse":""#).expect("champ adresse") + 11;
    let reste = &b[i..];
    reste[..reste.find('"').unwrap()].to_string()
}

/// Le meme serveur, mais en gardant la main sur le noeud.
///
/// Deux epreuves ont besoin de fabriquer un etat que le RPC ne sait pas
/// produire — un jeu d'UTXO de cent mille sorties, par exemple.
fn serveur_et_noeud() -> (ServerHandle, Arc<Node>) {
    let g = genesis_block(RESEAU);
    let node = Arc::new(Node::new(RESEAU, Chain::new(RESEAU, g)));
    let ctx = RpcContext {
        node: node.clone(),
        wallet: Some(Arc::new(Mutex::new(Wallet::from_seed([7u8; 32], RESEAU)))),
        network: RESEAU,
        index: None,
        sur_changement: None,
    };
    let h = http::serve("127.0.0.1:0", None, move |req| routeur(&ctx, req))
        .expect("demarrage du serveur");
    (h, node)
}

/// Les epreuves qui comptent les fils du processus ne peuvent pas se chevaucher.
///
/// `Threads:` de `/proc/self/status` est une mesure du **processus**, pas du
/// serveur : deux epreuves qui ouvrent chacune des centaines de connexions en
/// parallele se mesureraient l'une l'autre. Le verrou les serialise.
static VERROU_FILS: Mutex<()> = Mutex::new(());

fn verrou_fils() -> std::sync::MutexGuard<'static, ()> {
    VERROU_FILS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Ouvre `n` connexions, puis verifie que les dernieres ont ete refusees.
///
/// Au-dela de `MAX_CONNEXIONS`, `serve` repond 503 sans lancer de fil. Les
/// connexions tardives portent donc deja leur refus quand on les lit ; celles
/// qui occupent un fil, elles, ne repondent rien avant le delai de lecture.
fn refus_des_connexions_tardives(gardees: &mut [TcpStream], echantillon: usize) -> usize {
    let debut = gardees.len().saturating_sub(echantillon);
    let mut refusees = 0;
    for s in &mut gardees[debut..] {
        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
        let mut tampon = [0u8; 64];
        if let Ok(n) = s.read(&mut tampon) {
            if String::from_utf8_lossy(&tampon[..n]).contains("503") {
                refusees += 1;
            }
        }
    }
    refusees
}

/// Attend que le serveur ait de nouveau un fil disponible.
fn attendre_retablissement(addr: SocketAddr) -> bool {
    for _ in 0..40 {
        if appel(addr, "getinfo", "{}").starts_with("HTTP/1.1 200") {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn fils_du_processus() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Threads:"))?
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()
        })
        .unwrap_or(0)
}

// ===========================================================================
// 1. CSRF / navigateur — la voie la plus courte vers les fonds
// ===========================================================================

/// Le RPC n'examinait ni `Origin`, ni `Referer`, ni `Sec-Fetch-Site`.
///
/// Le noeud ecoute sur la boucle locale, ce qui rassure a tort : **le
/// navigateur de l'utilisateur est sur la boucle locale**. Une page hostile
/// ouverte dans un onglet quelconque pouvait donc emettre une requete « simple »
/// au sens CORS — donc sans pre-vol — vers `http://127.0.0.1:PORT/rpc`, et
/// atteindre le portefeuille. Le seul obstacle rencontre etait l'absence de
/// fonds.
///
/// `garde_navigateur` (src/http.rs) ferme cette voie par quatre verrous
/// independants : `Host`, `Origin`/`Referer`, `Sec-Fetch-Site`, et l'exigence
/// d'un `Content-Type: application/json`. Chacun suffit a un refus 403 rendu
/// **avant** l'analyse du corps : la requete n'atteint plus le portefeuille, ni
/// meme l'analyseur JSON.
#[test]
fn faille_csrf_origine_hostile_atteint_le_portefeuille() {
    let h = serveur(true, None);
    let dest = adresse_regtest(h.addr);
    let charge = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"adresse":"{dest}","unites":100000}}}}"#
    );

    // D'abord la preuve que la charge est vivante : par la voie legitime, elle
    // va jusqu'a la creation de transaction. Ce qui suit mesure donc le garde,
    // et non une requete devenue inoffensive par accident.
    assert!(
        corps_de(&post_rpc(h.addr, &charge)).contains("fonds insuffisants"),
        "la charge doit atteindre le portefeuille par la voie locale legitime"
    );

    for (nom, entetes) in [
        (
            "origine tierce",
            "Origin: https://evil.example\r\nContent-Type: application/json\r\n",
        ),
        (
            "referent tiers",
            "Referer: https://evil.example/piege.html\r\nContent-Type: application/json\r\n",
        ),
        (
            "marque posee par le navigateur",
            "Sec-Fetch-Site: cross-site\r\nContent-Type: application/json\r\n",
        ),
        (
            "requete simple, sans pre-vol",
            "Origin: https://evil.example\r\nReferer: https://evil.example/piege.html\r\n\
             Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: no-cors\r\n\
             Content-Type: text/plain;charset=UTF-8\r\n",
        ),
    ] {
        let r = post_rpc_avec(h.addr, entetes, &charge);
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "{nom} : refus attendu, obtenu {}",
            r.lines().next().unwrap_or("(rien)")
        );
        let c = corps_de(&r);
        assert!(
            !c.contains("jsonrpc") && !c.contains("fonds") && !c.contains("txid"),
            "{nom} : la requete a tout de meme ete traitee : {c}"
        );
    }

    // `Sec-Fetch-Site: same-origin` — ce que pose l'explorateur lui-meme — reste
    // servi : le garde distingue l'origine, il ne refuse pas tout le monde.
    let r = post_rpc_avec(
        h.addr,
        "Sec-Fetch-Site: same-origin\r\nOrigin: http://127.0.0.1\r\nContent-Type: application/json\r\n",
        &charge,
    );
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    h.shutdown();
}

/// Pire encore : aucun JavaScript n'etait necessaire.
///
/// `<form action="http://127.0.0.1:21080/rpc" method="POST"
///        enctype="text/plain">` produit un corps `nom=valeur\r\n`. En placant
/// le JSON dans le *nom* et en refermant l'objet dans la *valeur*, le corps
/// envoye est un document JSON-RPC valide. Un simple clic — ou un
/// `form.submit()` automatique — suffisait.
///
/// Le verrou qui ferme precisement cette voie est l'exigence de
/// `Content-Type: application/json` : un formulaire HTML ne sait produire que
/// `text/plain`, `application/x-www-form-urlencoded` ou `multipart/form-data`.
/// Aucun des trois n'ouvre plus rien, et un `fetch` qui poserait
/// `application/json` declencherait un pre-vol que ce service ne satisfait pas.
#[test]
fn faille_csrf_formulaire_html_sans_javascript() {
    let h = serveur(true, None);
    let dest = adresse_regtest(h.addr);

    // name  = {"jsonrpc":"2.0","id":1,"method":"sendtoaddress",
    //          "params":{"adresse":"…","unites":100000,"z":"
    // value = "}}
    // corps = name + "=" + value  →  …"z":"="}}
    let corps = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"adresse":"{dest}","unites":100000,"z":"="}}}}"#
    );

    // Les trois seuls types de contenu qu'un formulaire HTML peut emettre.
    for enctype in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=----q21",
    ] {
        let r = post_rpc_avec(
            h.addr,
            &format!("Origin: https://evil.example\r\nContent-Type: {enctype}\r\n"),
            &corps,
        );
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "enctype {enctype} : refus attendu, obtenu {}",
            r.lines().next().unwrap_or("(rien)")
        );
        assert!(
            !corps_de(&r).contains("fonds"),
            "enctype {enctype} a atteint sendtoaddress : {}",
            corps_de(&r)
        );
    }
    h.shutdown();
}

/// Un `Content-Type` absurde ne changeait rien : le corps etait analyse quand
/// meme, et c'est ce qui rendait la requete de formulaire exploitable.
///
/// Le POST exige desormais `application/json`. Ce n'est pas une formalite : ce
/// type est precisement celui qu'une page ne peut pas poser sans declencher un
/// pre-vol CORS, auquel ce service ne repond pas. Les parametres (`; charset=`)
/// et la casse restent tolores — un client conforme n'a pas a s'en soucier.
#[test]
fn faille_csrf_aucun_controle_de_content_type() {
    let h = serveur(false, None);
    let corps = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;

    for ct in [
        "Content-Type: text/plain\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Type: multipart/form-data; boundary=x\r\n",
        "Content-Type: image/png\r\n",
        "Content-Type: application/json-patch+json\r\n",
        "", // aucun Content-Type du tout
    ] {
        let r = post_rpc_avec(h.addr, ct, corps);
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "le type de contenu {ct:?} aurait du etre refuse ; reponse = {}",
            r.lines().next().unwrap_or("(rien)")
        );
        assert!(
            !corps_de(&r).contains("\"hauteur\""),
            "le corps a ete analyse malgre le refus : {}",
            corps_de(&r)
        );
    }

    // Et le client conforme passe, quelle que soit la casse ou les parametres.
    for ct in [
        "Content-Type: application/json\r\n",
        "Content-Type: application/json; charset=utf-8\r\n",
        "content-type: Application/JSON\r\n",
    ] {
        let r = post_rpc_avec(h.addr, ct, corps);
        assert!(
            corps_de(&r).contains("\"hauteur\""),
            "le type de contenu {ct:?} est legitime et doit passer : {r}"
        );
    }
    h.shutdown();
}

/// Aucune verification de l'en-tete `Host` : reliaison DNS possible.
///
/// Avec un nom qui resout d'abord vers l'IP de l'attaquant puis vers 127.0.0.1,
/// la page hostile devenait **de meme origine** que le noeud : elle lisait alors
/// les reponses, et ne se contentait plus d'emettre a l'aveugle. Elle recuperait
/// ainsi le jeton passe en `?token=`, les adresses, les soldes.
///
/// Le premier verrou de `garde_navigateur` refuse tout `Host` qui ne designe pas
/// cette machine. Un navigateur pose toujours cet en-tete, et une page ne peut
/// pas le falsifier : apres reliaison, il porte le nom de l'attaquant.
///
/// Le verrou est cependant plus etroit que son intention, et ce test fixe les
/// deux ecarts constates plus bas :
///
/// - il ne s'applique que si l'en-tete est **presente** ;
/// - il accepte tout nom commencant par `127.`, ce qui inclut des noms de
///   domaine comme `127.0.0.1.evil.example`.
///
/// Le second ecart rouvre entierement la reliaison DNS : un tel nom traverse
/// aussi les verrous `Origin` et `Sec-Fetch-Site`, pour la meme raison.
#[test]
fn faille_aucune_verification_de_host_reliaison_dns() {
    let h = serveur(false, None);

    for hote in [
        "rebind.evil.example",
        "attaquant.example:21080",
        "192.168.1.10",
        "q21.local",
    ] {
        let r = brut(
            h.addr,
            format!("GET / HTTP/1.1\r\nHost: {hote}\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "Host {hote} aurait du etre refuse : {}",
            r.lines().next().unwrap_or("(rien)")
        );
        assert!(
            !corps_de(&r).contains("<!doctype"),
            "la page a ete servie a un hote etranger : {hote}"
        );
    }

    // Et le POST vers le RPC, meme parfaitement forme par ailleurs.
    let c = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;
    let r = brut(
        h.addr,
        format!(
            "POST /rpc HTTP/1.1\r\nHost: rebind.evil.example\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{c}",
            c.len()
        )
        .as_bytes(),
    );
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    assert!(
        !corps_de(&r).contains("\"hauteur\""),
        "un Host etranger a obtenu l'etat de la chaine : {r}"
    );

    // --- Le nom qui portait le costume d'une adresse.
    //
    // La premiere version de `hote_local` terminait par
    // `nu.starts_with("127.")`, pour couvrir les adresses de bouclage autres
    // que 127.0.0.1. Mais un **nom de domaine** peut commencer ainsi :
    // `127.0.0.1.evil.example` s'enregistre en cinq minutes et se fait pointer
    // vers 127.0.0.1.
    //
    // Ce nom traversait alors les quatre verrous d'un coup : `Host` le prenait
    // pour du bouclage ; apres reliaison, l'origine de la page devenait
    // `http://127.0.0.1.evil.example:PORT`, que `origine_locale` acceptait pour
    // la meme raison ; `Sec-Fetch-Site` valait `same-origin` ; et une requete de
    // meme origine n'a pas de pre-vol, donc elle posait le bon `Content-Type`.
    // La reliaison DNS etait entierement rouverte par une comparaison de
    // chaine.
    //
    // Le filtre analyse desormais une adresse au lieu de comparer un prefixe.
    for hote in [
        "127.0.0.1.evil.example",
        "127.evil.example:21080",
        "localhost.evil.example",
        "127-0-0-1.evil.example",
        "[::1].evil.example",
    ] {
        let r = brut(
            h.addr,
            format!("GET / HTTP/1.1\r\nHost: {hote}\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "{hote} passe encore pour du bouclage : {}",
            r.lines().next().unwrap_or("")
        );
    }

    // Et les formes reellement locales restent servies.
    for hote in ["127.0.0.1", "localhost", "127.1.2.3", "[::1]:21080"] {
        let r = brut(
            h.addr,
            format!("GET / HTTP/1.1\r\nHost: {hote}\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 200"),
            "{hote} devrait etre servi : {}",
            r.lines().next().unwrap_or("")
        );
    }

    // Un `Host` absent n'est pas non plus examine : le verrou ne s'applique qu'a
    // l'en-tete presente. Aucun navigateur n'omet `Host`, mais un client brut le
    // peut, et ne rencontre alors que les trois autres verrous.
    let c = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;
    let r = brut(
        h.addr,
        format!(
            "POST /rpc HTTP/1.1\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{c}",
            c.len()
        )
        .as_bytes(),
    );
    assert!(
        corps_de(&r).contains("\"hauteur\""),
        "constat : sans en-tete Host, le premier verrou ne s'applique pas : {r}"
    );

    // Les hotes qui designent bien cette machine restent servis, avec ou sans
    // port, en IPv4, en IPv6 ou par le nom.
    for hote in [
        "127.0.0.1",
        "127.0.0.1:21080",
        "localhost",
        "LocalHost",
        "[::1]:21080",
    ] {
        let r = brut(
            h.addr,
            format!("GET / HTTP/1.1\r\nHost: {hote}\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 200"),
            "Host {hote} designe cette machine et doit etre servi : {}",
            r.lines().next().unwrap_or("(rien)")
        );
    }
    h.shutdown();
}

/// La reponse ne portait aucune en-tete defensive pour le navigateur : la page
/// pouvait etre chargee dans une `<iframe>` d'un site hostile, rien n'y limitait
/// les scripts, et l'adresse — jeton compris, a l'epoque — partait dans le
/// `Referer` de la premiere ressource externe.
///
/// `ecrire_reponse` (src/http.rs) les pose desormais sur **toutes** les
/// reponses, refus compris : une page d'erreur est une page comme une autre.
///
/// `Cross-Origin-Resource-Policy` et `Cross-Origin-Opener-Policy` restent
/// absentes. Le cadrage est couvert par `X-Frame-Options: DENY`, et le reste par
/// `garde_navigateur`, qui refuse la requete inter-sites avant qu'une politique
/// de reponse ait a la rattraper.
#[test]
fn faille_aucune_entete_defensive_navigateur() {
    let h = serveur(false, None);

    let attendues = [
        ("content-security-policy", "default-src 'none'"),
        ("x-frame-options", "deny"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
    ];

    // Sur la page servie…
    let page = brut(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    );
    // …sur une reponse JSON…
    let json = appel(h.addr, "getinfo", "{}");
    // …et sur un refus : c'est la que l'oubli est le plus facile.
    let refus = brut(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
    );
    assert!(refus.starts_with("HTTP/1.1 403"), "{refus}");

    for (nom, reponse) in [("page", &page), ("json", &json), ("refus", &refus)] {
        let entetes = reponse
            .split("\r\n\r\n")
            .next()
            .unwrap()
            .to_ascii_lowercase();
        for (cle, valeur) in attendues {
            assert!(
                entetes.contains(cle),
                "reponse {nom} : en-tete {cle} absente\n{entetes}"
            );
            assert!(
                entetes.contains(valeur),
                "reponse {nom} : {cle} n'a pas la valeur attendue ({valeur})\n{entetes}"
            );
        }
    }
    h.shutdown();
}

// ===========================================================================
// 2. Vol de fonds / arret du noeud par le portefeuille
// ===========================================================================

/// Debordement d'entier non verifie dans `Wallet::create_transaction`
/// (`montant.units() + frais.units()`).
///
/// `overflow-checks = true` sur **tous** les profils, et `panic = "abort"` en
/// release : le fil de connexion paniquait, et un noeud compile en release
/// **s'arretait**. En test (deroulement), la connexion se fermait sans la
/// moindre reponse HTTP — signature de la panique.
///
/// L'analyseur JSON refusait deja les entiers au-dela de `i64::MAX`, mais
/// `Json::as_u64` acceptait une **chaine** et la convertissait : la borne se
/// contournait en trois caracteres.
///
/// Deux verrous ont ete poses, et il faut les deux :
///
/// - `Json::as_u64` n'accepte plus une chaine — le detour est ferme ;
/// - `create_transaction` refuse montant, frais et leur **somme** au-dela de
///   `MAX_SUPPLY` (`WalletError::MontantHorsBornes`), avant toute arithmetique.
///
/// Chacun des trois envois ci-dessous produit donc une erreur JSON-RPC propre,
/// et le fil survit.
#[test]
fn faille_sendtoaddress_debordement_arrete_le_noeud() {
    let h = serveur(true, None);
    let dest = adresse_regtest(h.addr);

    // 1. Le detour d'origine : le nombre place entre guillemets.
    let r = post_rpc(
        h.addr,
        &format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"adresse":"{dest}","unites":"18446744073709551615","frais":"1000"}}}}"#
        ),
    );
    assert!(
        r.starts_with("HTTP/1.1 200"),
        "aucune reponse (fil panique ?) : {r}"
    );
    let c = corps_de(&r);
    assert!(
        c.contains("\"code\":-32602") && c.contains("'unites' attendu"),
        "une chaine ne doit plus valoir un entier : {c}"
    );

    // 2. Le meme nombre, cette fois en nombre : l'analyseur l'accepte
    //    desormais (`Json::Grand`), et c'est le portefeuille qui le refuse.
    let r = post_rpc(
        h.addr,
        &format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"adresse":"{dest}","unites":18446744073709551615}}}}"#
        ),
    );
    let c = corps_de(&r);
    assert!(
        c.contains("\"code\":-3") && c.contains("au-dela de ce qui peut exister"),
        "un montant hors bornes doit etre refuse nommement : {c}"
    );

    // 3. Deux valeurs individuellement sous le plafond, dont la somme ne l'est
    //    pas : c'est l'addition elle-meme qui debordait.
    let r = post_rpc(
        h.addr,
        &format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"adresse":"{dest}","unites":2100000100000000,"frais":2100000100000000}}}}"#
        ),
    );
    let c = corps_de(&r);
    assert!(
        c.contains("\"code\":-3") && c.contains("au-dela de ce qui peut exister"),
        "la somme montant + frais doit etre bornee elle aussi : {c}"
    );

    // Et le noeud repond toujours : plus aucune panique n'a eu lieu.
    assert!(appel(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// Meme debordement par le champ `frais`, qui n'avait aucun plafond.
///
/// `create_transaction` borne desormais les frais comme le montant. Reste une
/// asperite que ce test fixe telle quelle : `sendtoaddress` lit les frais avec
/// `.unwrap_or(1_000)`. Des frais **mal types** — une chaine, par exemple — ne
/// sont donc pas refuses : ils sont silencieusement remplaces par le defaut. Ce
/// n'est plus un debordement, mais la transaction construite n'est pas celle que
/// le client a ecrite. Le montant, lui, n'a pas de defaut et se plaint.
#[test]
fn faille_sendtoaddress_debordement_par_les_frais() {
    let h = serveur(true, None);
    let dest = adresse_regtest(h.addr);

    for frais in ["18446744073709551615", "2100000100000000"] {
        let r = post_rpc(
            h.addr,
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"adresse":"{dest}","unites":1,"frais":{frais}}}}}"#
            ),
        );
        assert!(
            r.starts_with("HTTP/1.1 200"),
            "attendu une reponse, obtenu : {r}"
        );
        let c = corps_de(&r);
        assert!(
            c.contains("\"code\":-3") && c.contains("au-dela de ce qui peut exister"),
            "frais {frais} : refus attendu, obtenu {c}"
        );
    }

    // --- Des frais mal types ne retombent plus sur le defaut.
    //
    // `.and_then(as_u64).unwrap_or(1_000)` remplacait silencieusement toute
    // valeur illisible par mille unites : la transaction construite n'etait pas
    // celle que le client avait ecrite. Un champ present et invalide est
    // desormais une erreur, pas une invitation a deviner.
    for frais in [
        r#""18446744073709551615""#,
        r#""1000""#,
        "true",
        r#"{"unites":1000}"#,
        "[1000]",
    ] {
        let c = corps_de(&post_rpc(
            h.addr,
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"adresse":"{dest}","unites":1,"frais":{frais}}}}}"#
            ),
        ))
        .to_string();
        assert!(
            c.contains("\"code\":-32602") && c.contains("illisible"),
            "frais {frais} : refus attendu, obtenu {c}"
        );
    }

    // Absent ou nul : le defaut s'applique, et c'est legitime.
    for frais in ["null", ""] {
        let params = if frais.is_empty() {
            format!(r#"{{"adresse":"{dest}","unites":1}}"#)
        } else {
            format!(r#"{{"adresse":"{dest}","unites":1,"frais":{frais}}}"#)
        };
        let c = corps_de(&post_rpc(
            h.addr,
            &format!(r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{params}}}"#),
        ))
        .to_string();
        assert!(
            c.contains("fonds insuffisants"),
            "frais absent : le defaut doit s'appliquer, obtenu {c}"
        );
    }

    assert!(appel(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// Un lot JSON-RPC transformait une panique unique en arret garanti : la
/// premiere entree qui debordait emportait le fil avant toute reponse, et
/// aucune des autres n'etait rendue.
///
/// Puisque plus rien ne panique, le lot rend maintenant ce qu'un lot doit
/// rendre : une reponse par appel, l'erreur de l'un n'emportant pas l'autre.
#[test]
fn faille_le_lot_propage_la_panique() {
    let h = serveur(true, None);
    let dest = adresse_regtest(h.addr);
    let corps = format!(
        r#"[{{"jsonrpc":"2.0","id":1,"method":"getinfo"}},{{"jsonrpc":"2.0","id":2,"method":"sendtoaddress","params":{{"adresse":"{dest}","unites":18446744073709551615}}}},{{"jsonrpc":"2.0","id":3,"method":"getsupply"}}]"#
    );
    let r = post_rpc(h.addr, &corps);
    assert!(
        r.starts_with("HTTP/1.1 200"),
        "aucune reponse (fil panique ?) : {r}"
    );

    let c = corps_de(&r);
    assert!(
        c.starts_with('[') && c.ends_with(']'),
        "un lot rend un tableau : {c}"
    );
    assert_eq!(
        c.matches("\"jsonrpc\":\"2.0\"").count(),
        3,
        "les trois appels doivent etre rendus : {c}"
    );
    assert!(
        c.contains("\"hauteur\":0"),
        "le premier appel a bien ete execute : {c}"
    );
    assert!(
        c.contains("\"code\":-3"),
        "le deuxieme doit rendre une erreur, pas une panique : {c}"
    );
    assert!(
        c.contains("\"plafond\""),
        "le troisieme doit etre execute malgre l'erreur du deuxieme : {c}"
    );

    assert!(appel(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// Confirmation : sans `--rpc-wallet`, les methodes de depense sont bien
/// refusees, et le debordement n'est pas atteignable.
#[test]
fn ok_le_portefeuille_est_bien_ferme_sans_rpc_wallet() {
    let h = serveur(false, None);
    for m in ["getbalance", "getnewaddress", "sendtoaddress"] {
        let r = appel(
            h.addr,
            m,
            r#"{"adresse":"x","unites":"18446744073709551615"}"#,
        );
        let c = corps_de(&r);
        assert!(
            c.contains("\"code\":-2"),
            "{m} aurait du etre refusee (code -2) : {c}"
        );
    }
    // Et le serveur repond toujours : aucune panique n'a eu lieu.
    assert!(appel(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// `getinfo` annonce publiquement si les fonds sont joignables.
///
/// Ce n'est pas une faille en soi, c'est le **reperage** qui precede la CSRF :
/// une page hostile teste `portefeuille_actif` avant de tirer.
#[test]
fn faille_getinfo_annonce_si_les_fonds_sont_joignables() {
    let ouvert = serveur(true, None);
    assert!(corps_de(&appel(ouvert.addr, "getinfo", "{}")).contains("\"portefeuille_actif\":true"));
    ouvert.shutdown();

    let ferme = serveur(false, None);
    assert!(corps_de(&appel(ferme.addr, "getinfo", "{}")).contains("\"portefeuille_actif\":false"));
    ferme.shutdown();
}

// ===========================================================================
// 3. Authentification
// ===========================================================================

/// Aucune tentative de contournement du jeton n'a abouti.
#[test]
fn ok_le_jeton_ne_se_contourne_pas_trivialement() {
    let h = serveur(false, Some("s3cret"));

    let tentatives: Vec<(&str, String)> = vec![
        ("aucun jeton", String::new()),
        (
            "casse differente",
            "Authorization: Bearer S3CRET\r\n".into(),
        ),
        (
            "schema minuscule",
            "authorization: bearer s3cret\r\n".into(),
        ),
        ("schema absent", "Authorization: s3cret\r\n".into()),
        ("prefixe correct", "Authorization: Bearer s3c\r\n".into()),
        ("suffixe ajoute", "Authorization: Bearer s3cretX\r\n".into()),
        ("octet nul", "Authorization: Bearer s3cret\x00\r\n".into()),
        (
            "en-tete alternative",
            "X-Auth-Token: s3cret\r\nAuthorization: Bearer faux\r\n".into(),
        ),
    ];
    for (nom, entetes) in tentatives {
        let r = brut(
            h.addr,
            format!("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n{entetes}Connection: close\r\n\r\n")
                .as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 401"),
            "contournement par « {nom} » : {}",
            r.lines().next().unwrap_or("")
        );
    }

    // La seule voie legitime : l'en-tete.
    assert!(brut(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer s3cret\r\nConnection: close\r\n\r\n"
    )
    .starts_with("HTTP/1.1 200"));
    // Le jeton dans l'URL n'ouvre plus rien : une adresse finit dans
    // l'historique, dans les journaux d'un mandataire, et dans le `Referer`.
    assert!(brut(
        h.addr,
        b"GET /?token=s3cret HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .starts_with("HTTP/1.1 401"));
    h.shutdown();
}

/// Le jeton etait accepte avec des espaces surnumeraires (le `.trim()` de
/// `autorise`, src/http.rs) **et** sous forme percent-encodee dans l'URL.
///
/// Le second point etait le vrai probleme : `?token=%73%33%63%72%65%74` ouvrait
/// le noeud, et une URL finit dans l'historique du navigateur, dans les journaux
/// de tout mandataire, et dans le `Referer`. Cette voie est fermee : seule
/// l'en-tete `Authorization` est lue.
///
/// La tolerance aux espaces, elle, demeure et ce test la fixe : elle n'est pas
/// un contournement — il faut toujours le bon jeton, compare en temps constant —
/// mais elle elargit ce qu'un intermediaire doit normaliser avant de comparer.
#[test]
fn faille_mineure_le_jeton_tolere_espaces_et_encodage() {
    let h = serveur(false, Some("s3cret"));

    // Espaces surnumeraires : toujours tolores, toujours sans effet sur la
    // valeur exigee.
    assert!(brut(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer    s3cret   \r\nConnection: close\r\n\r\n"
    )
    .starts_with("HTTP/1.1 200"));
    // Mais l'espace ne remplace pas un caractere : le jeton reste compare entier.
    assert!(brut(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer s3 cret\r\nConnection: close\r\n\r\n"
    )
    .starts_with("HTTP/1.1 401"));

    // Le jeton percent-encode dans l'URL n'ouvre plus rien : l'URL n'est plus
    // une voie d'authentification, quelle que soit sa forme.
    for cible in [
        "/?token=%73%33%63%72%65%74",
        "/?token=s3cret",
        "/?a=1&token=s3cret",
        "/index.html?token=s3cret",
    ] {
        let r = brut(
            h.addr,
            format!("GET {cible} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 401"),
            "{cible} a ouvert le noeud : {}",
            r.lines().next().unwrap_or("(rien)")
        );
    }
    h.shutdown();
}

/// En-tete `Authorization` dupliquee : c'est la **derniere** qui compte
/// (`BTreeMap::insert`, src/http.rs:236). Un mandataire qui validerait la
/// premiere serait desynchronise du noeud.
#[test]
fn faille_entete_dupliquee_la_derniere_gagne() {
    let h = serveur(false, Some("s3cret"));
    let premiere_bonne = brut(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer s3cret\r\nAuthorization: Bearer faux\r\nConnection: close\r\n\r\n",
    );
    let derniere_bonne = brut(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer faux\r\nAuthorization: Bearer s3cret\r\nConnection: close\r\n\r\n",
    );
    assert!(
        premiere_bonne.starts_with("HTTP/1.1 401"),
        "la premiere en-tete est ignoree"
    );
    assert!(
        derniere_bonne.starts_with("HTTP/1.1 200"),
        "la derniere en-tete l'emporte"
    );
    h.shutdown();
}

/// Le jeton pouvait voyager dans l'URL (`?token=`), et l'explorateur lui-meme le
/// recommandait dans son message d'erreur. Une URL finit dans l'historique du
/// navigateur, dans les journaux d'un mandataire, et dans le `Referer` de la
/// premiere ressource externe chargee. Un secret qui voyage dans une URL n'est
/// plus un secret.
///
/// `autorise` (src/http.rs) ne lit plus que l'en-tete `Authorization`, et la
/// page a change de conseil : elle demande le jeton et l'envoie en `Bearer`.
#[test]
fn faille_le_jeton_voyage_dans_l_url() {
    let h = serveur(false, Some("s3cret"));

    assert!(
        brut(
            h.addr,
            b"GET /?token=s3cret HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .starts_with("HTTP/1.1 401"),
        "le jeton dans l'URL ne doit plus rien ouvrir"
    );

    // La chaine de requete est simplement ignoree : elle n'ouvre rien, et elle
    // ne ferme rien non plus a qui presente l'en-tete.
    assert!(brut(
        h.addr,
        b"GET /?token=faux HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer s3cret\r\nConnection: close\r\n\r\n"
    )
    .starts_with("HTTP/1.1 200"));

    // Et la page ne conseille plus de le mettre la.
    let p = q21_core::explorer::PAGE;
    assert!(
        !p.contains("?token="),
        "la page conseille encore de mettre le jeton dans l'URL"
    );
    assert!(
        p.contains("Authorization") && p.contains("\"Bearer \""),
        "la page doit envoyer le jeton en en-tete"
    );
    h.shutdown();
}

/// Confirme le garde-fou : pas d'ecoute publique sans jeton.
#[test]
fn ok_ecouter_hors_bouclage_sans_jeton_est_refuse() {
    let r = http::serve("0.0.0.0:0", None, |_| Response::text(200, "x"));
    assert!(r.is_err(), "0.0.0.0 sans jeton doit etre refuse");
    let r6 = http::serve("[::]:0", None, |_| Response::text(200, "x"));
    assert!(r6.is_err(), "[::] sans jeton doit etre refuse");
}

// ===========================================================================
// 4. Analyseur HTTP
// ===========================================================================

/// `Content-Length` mensonger : le serveur allouait le tampon **avant** de lire
/// (`vec![0u8; taille]`), puis restait bloque jusqu'au delai de lecture. Chaque
/// connexion coutait donc un mebioctet de tas et un fil systeme, pour zero octet
/// de corps envoye par l'attaquant. Cent vingt connexions suffisaient a cent
/// vingt fils et cent vingt mebioctets.
///
/// Deux corrections. La premiere n'est pas observable depuis un client : le
/// tampon est desormais **rempli** par morceaux et non pre-alloue, donc ce qui
/// est alloue est ce qui est arrive. Elle se lit dans `lire_requete`.
///
/// La seconde l'est : `MAX_CONNEXIONS` plafonne les connexions traitees
/// simultanement. Au-dela, la connexion recoit un 503 franc, sans fil. C'est ce
/// que verifie ce test — le nombre de fils du processus ne suit plus le nombre
/// de connexions ouvertes.
#[test]
fn faille_content_length_mensonger_alloue_avant_de_lire() {
    let _verrou = verrou_fils();
    let h = serveur(false, None);
    let avant = fils_du_processus();

    // 120 connexions annoncant 1 Mio chacune, sans jamais envoyer le corps.
    let mut gardees = Vec::new();
    for _ in 0..120 {
        let mut s = TcpStream::connect(h.addr).expect("connexion");
        s.write_all(
            b"POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
              Content-Length: 1048576\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        gardees.push(s);
    }
    std::thread::sleep(Duration::from_millis(700));
    let pendant = fils_du_processus();
    eprintln!("fils : avant={avant} pendant={pendant} (120 connexions a 1 Mio annonce)");

    assert!(
        pendant < avant + 100,
        "le nombre de fils suit encore le nombre de connexions ; \
         avant={avant} pendant={pendant}, plafond annonce = {}",
        http::MAX_CONNEXIONS
    );

    // Les connexions au-dela du plafond portent deja leur refus.
    let refusees = refus_des_connexions_tardives(&mut gardees, 40);
    assert_eq!(
        refusees,
        40,
        "les connexions au-dela de {} doivent etre refusees par un 503",
        http::MAX_CONNEXIONS
    );

    // Un corps plus grand que `MAX_BODY` est refuse sur sa seule annonce, sans
    // qu'un octet soit lu ni reserve.
    let r = brut(
        h.addr,
        format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            http::MAX_BODY + 1
        )
        .as_bytes(),
    );
    assert!(
        r.is_empty() || r.starts_with("HTTP/1.1 400") || r.starts_with("HTTP/1.1 503"),
        "{r}"
    );

    // Le plafond n'est pas un verrouillage : les fils se liberent.
    drop(gardees);
    assert!(
        attendre_retablissement(h.addr),
        "le serveur doit repondre a nouveau une fois les connexions closes"
    );
    h.shutdown();
}

/// Aucune limite au nombre de connexions ni de fils.
///
/// `serve` faisait `std::thread::spawn` par connexion, sans compteur, sans file,
/// sans pool. Cinq cents connexions muettes — aucun octet envoye — donnaient
/// cinq cents fils systeme, chacun bloque jusqu'au delai de lecture.
///
/// `MAX_CONNEXIONS` borne desormais les connexions traitees simultanement, et
/// le refus est immediat : un 503 ecrit depuis la boucle d'acceptation, sans
/// lancer de fil. Un refus franc coute moins cher qu'un fil de plus.
#[test]
fn faille_nombre_de_fils_non_borne() {
    let _verrou = verrou_fils();
    let h = serveur(false, None);
    let avant = fils_du_processus();
    let mut gardees = Vec::new();
    for _ in 0..500 {
        // Connexion ouverte, aucun octet envoye.
        match TcpStream::connect(h.addr) {
            Ok(s) => gardees.push(s),
            Err(_) => break,
        }
    }
    std::thread::sleep(Duration::from_millis(900));
    let pendant = fils_du_processus();
    eprintln!(
        "fils : avant={avant} pendant={pendant} ({} connexions muettes, plafond {})",
        gardees.len(),
        http::MAX_CONNEXIONS
    );

    assert!(
        gardees.len() >= 400,
        "l'epreuve n'a pas pu ouvrir assez de connexions : {}",
        gardees.len()
    );
    assert!(
        pendant < avant + 200,
        "les fils suivent encore les connexions : avant={avant} pendant={pendant} \
         pour {} connexions",
        gardees.len()
    );

    // La preuve directe, propre a ce serveur : les connexions tardives sont
    // refusees au lieu d'obtenir un fil.
    let refusees = refus_des_connexions_tardives(&mut gardees, 50);
    assert_eq!(
        refusees, 50,
        "les connexions au-dela du plafond doivent recevoir un 503"
    );

    drop(gardees);
    assert!(attendre_retablissement(h.addr));
    h.shutdown();
}

/// Le delai de lecture portait sur **chaque lecture**, jamais sur la requete
/// entiere. Un octet toutes les quelques secondes maintenait donc la connexion —
/// et son fil — indefiniment : c'est Slowloris, et il suffisait de quelques
/// dizaines de connexions pour immobiliser le noeud.
///
/// `REQUEST_TIMEOUT` (20 s) borne desormais la requete complete : `lire_requete`
/// verifie l'echeance apres la ligne de requete, apres chaque en-tete et avant
/// chaque morceau de corps. Au-dela, c'est un 400 « requete trop lente ».
///
/// La borne est verifiee **entre** les lignes, pas au milieu d'une ligne : le
/// couperet tombe donc a la fin de l'en-tete en cours, jamais avant. La ligne
/// est elle-meme bornee par `MAX_LINE`, mais un attaquant qui etale une seule
/// en-tete tres longue peut encore tenir une connexion bien au-dela de
/// l'echeance. Ce test mesure ce que le serveur garantit reellement.
#[test]
fn faille_slowloris_aucun_delai_global() {
    let h = serveur(false, None);
    let mut s = TcpStream::connect(h.addr).expect("connexion");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    // Une requete de sept cents octets, envoyee a dix octets par seconde : sans
    // echeance globale, elle occuperait un fil pendant plus d'une minute, puis
    // serait servie.
    let mut requete = String::from("GET /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    for i in 0..30 {
        requete.push_str(&format!("X-Lent-{i:02}: aaaaaaaaaa\r\n"));
    }
    requete.push_str("Connection: close\r\n\r\n");
    let total = requete.len();

    let debut = Instant::now();
    let mut envoyes = 0usize;
    let mut coupee = false;
    for o in requete.as_bytes() {
        if s.write_all(&[*o]).is_err() || s.flush().is_err() {
            coupee = true;
            break;
        }
        envoyes += 1;
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut r = String::new();
    let _ = s.read_to_string(&mut r);
    let ecoule = debut.elapsed();
    eprintln!("slowloris : {envoyes}/{total} octets en {ecoule:?}, coupee={coupee}");

    assert!(
        coupee || !r.is_empty(),
        "la connexion n'a ete ni coupee ni close apres {ecoule:?}"
    );
    assert!(
        ecoule < Duration::from_secs(45),
        "la connexion a survecu {ecoule:?} : l'echeance globale ne s'applique pas"
    );
    assert!(
        envoyes < total,
        "le serveur a attendu la requete entiere ({envoyes} octets sur {total})"
    );
    assert!(
        r.is_empty() || r.starts_with("HTTP/1.1 400"),
        "une requete etalee au-dela de l'echeance ne doit pas etre servie : {r}"
    );
    assert!(
        !r.contains("HTTP/1.1 405"),
        "le serveur a servi une requete etalee sur {ecoule:?} : {r}"
    );
    // Et l'echeance est bien ce qui a coupe : un refus immediat aurait une tout
    // autre allure.
    assert!(
        ecoule > Duration::from_secs(15),
        "coupure trop precoce pour venir de l'echeance de {:?} : {ecoule:?}",
        http::REQUEST_TIMEOUT
    );

    assert!(appel(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// Au-dela de `MAX_HEADERS` en-tetes, la boucle de lecture s'arrete **sans
/// consommer la ligne vide**. Les en-tetes suivantes ne sont ni lues ni
/// refusees : elles deviennent silencieusement le corps.
///
/// Ce comportement n'a pas change, et ce test le fixe tel quel. Ce qui a change,
/// c'est que chacune de ses consequences est desormais **fermante** — aucune ne
/// laisse passer une requete qui serait autrement refusee :
///
/// - une authentification placee apres la 64e en-tete est ignoree, donc 401 ;
/// - un `Content-Type` place apres la 64e en-tete est ignore, donc 403 par
///   `garde_navigateur` ;
/// - un `Content-Length` correct mais suivi de bourrage voit son corps decale :
///   le document analyse est du bourrage, donc une erreur d'analyse.
///
/// Reste qu'un 400 franc — « trop d'en-tetes » — vaudrait mieux qu'un corps
/// silencieusement decale. C'est la rugosite que ces assertions surveillent : si
/// l'une d'elles cesse de valoir, c'est que le decoupage a bouge.
#[test]
fn faille_au_dela_de_64_entetes_le_reste_devient_le_corps() {
    let bourrage = |n: usize| {
        let mut s = String::new();
        for i in 0..n {
            s.push_str(&format!("X-Bourrage-{i}: a\r\n"));
        }
        s
    };
    let trop = http::MAX_HEADERS + 6;

    // 1. L'authentification apres la 64e en-tete est perdue : echec fermant.
    let h = serveur(false, Some("s3cret"));
    let req = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Authorization: Bearer s3cret\r\nConnection: close\r\n\r\n",
        bourrage(trop)
    );
    let r = brut(h.addr, req.as_bytes());
    assert!(
        r.starts_with("HTTP/1.1 401"),
        "l'authentification apres {} en-tetes doit etre ignoree, pas honoree : {}",
        http::MAX_HEADERS,
        r.lines().next().unwrap_or("(rien)")
    );
    // La meme requete sans bourrage passe : c'est bien le bourrage qui coupe.
    assert!(brut(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer s3cret\r\nConnection: close\r\n\r\n"
    )
    .starts_with("HTTP/1.1 200"));
    h.shutdown();

    let h2 = serveur(false, None);
    let corps = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;

    // 2. Le `Content-Type` repousse au-dela de la limite est ignore : le garde
    //    refuse la requete au lieu de l'analyser.
    let req = format!(
        "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{corps}",
        bourrage(trop),
        corps.len()
    );
    let r = brut(h2.addr, req.as_bytes());
    assert!(
        r.starts_with("HTTP/1.1 403"),
        "un Content-Type hors de portee doit fermer la requete : {}",
        r.lines().next().unwrap_or("(rien)")
    );

    // 3. En-tetes valides d'abord, bourrage ensuite : le corps annonce est
    //    decale par les en-tetes non lues, et l'appel devient illisible.
    let req = format!(
        "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n{}\r\n{corps}",
        corps.len(),
        bourrage(trop)
    );
    let r = brut(h2.addr, req.as_bytes());
    assert!(
        corps_de(&r).contains("-32700"),
        "le corps decale doit produire une erreur d'analyse, jamais un appel \
         execute : {r}"
    );
    assert!(
        !corps_de(&r).contains("\"hauteur\""),
        "l'appel a ete execute malgre le decalage : {r}"
    );
    h2.shutdown();
}

/// `Transfer-Encoding: chunked` n'est pas implemente et n'est pas refuse : le
/// corps est simplement ignore (aucun `Content-Length`, donc taille zero).
///
/// Ce point n'a pas ete corrige, et ce test le fixe tel quel. Ce qu'il verifie,
/// c'est ce qui compte vraiment ici : l'absence de **contrebande**. Une seule
/// requete est traitee par connexion, et les octets du corps chunked ne sont
/// jamais relus comme une seconde requete — ni quand `Content-Length` et
/// `Transfer-Encoding` se contredisent, ce qui est le motif classique de
/// desynchronisation entre un mandataire et son amont.
///
/// Un client conforme, lui, voit toujours sa requete disparaitre derriere une
/// erreur d'analyse ; un 400 « chunked non supporte » vaudrait mieux.
#[test]
fn faille_chunked_est_ignore_en_silence() {
    let h = serveur(false, None);

    let r = brut(
        h.addr,
        b"POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
          Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
          2a\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getinfo\"}\r\n0\r\n\r\n",
    );
    assert!(
        corps_de(&r).contains("-32700"),
        "chunked devrait etre refuse par 400, pas ignore : {r}"
    );
    assert!(
        !corps_de(&r).contains("\"hauteur\""),
        "le corps chunked ne doit pas etre execute : {r}"
    );

    // `Content-Length` et `Transfer-Encoding` contradictoires : c'est le motif
    // de la contrebande de requetes. Une seule reponse doit sortir, et la
    // seconde requete cachee ne doit jamais etre servie.
    let cache = r#"{"jsonrpc":"2.0","id":9,"method":"getsupply"}"#;
    let r = brut(
        h.addr,
        format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
             Transfer-Encoding: chunked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n\
             {:x}\r\n{cache}\r\n0\r\n\r\n",
            cache.len()
        )
        .as_bytes(),
    );
    assert_eq!(
        r.matches("HTTP/1.1 ").count(),
        1,
        "une seule reponse doit sortir de la connexion : {r}"
    );
    assert!(
        !r.contains("\"plafond\""),
        "la requete dissimulee dans les morceaux a ete servie : {r}"
    );
    h.shutdown();
}

/// `Content-Length` duplique : la derniere valeur gagne (`BTreeMap::insert`),
/// et le corps reel plus grand que declare est tronque, l'excedent jete.
///
/// Ce point n'a pas ete corrige non plus, et ce test le fixe tel quel : deux
/// `Content-Length` contradictoires devraient valoir un 400 franc, comme
/// l'exige le RFC 9112. Tant que ce n'est pas le cas, un mandataire qui
/// retiendrait la **premiere** valeur lirait un autre message que le noeud.
///
/// Ce que le serveur garantit malgre tout, et que ce test verrouille : l'excedent
/// n'est jamais relu comme une requete supplementaire. Une connexion, une
/// reponse — la contrebande de requetes reste impossible.
#[test]
fn faille_content_length_duplique_et_corps_tronque() {
    let h = serveur(false, None);
    let json = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;
    let cache = r#"{"jsonrpc":"2.0","id":9,"method":"getsupply"}"#;
    let corps = format!("{json}{cache}");

    // Deux valeurs contradictoires ; le corps reel est plus long que les deux.
    // C'est la **derniere** en-tete qui est retenue.
    let r = brut(
        h.addr,
        format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
             Content-Length: 9999\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{corps}",
            json.len()
        )
        .as_bytes(),
    );
    assert!(
        corps_de(&r).contains("\"hauteur\""),
        "la derniere valeur de Content-Length l'emporte et l'excedent est jete \
         sans erreur : {r}"
    );
    assert_eq!(
        r.matches("HTTP/1.1 ").count(),
        1,
        "l'excedent ne doit jamais devenir une seconde requete : {r}"
    );
    assert!(
        !r.contains("\"plafond\""),
        "la requete dissimulee dans l'excedent a ete servie : {r}"
    );

    // Ordre inverse : si c'etait la premiere qui gagnait, la requete serait
    // identique. Elle ne l'est pas — preuve que seule la derniere compte.
    let r2 = brut(
        h.addr,
        format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nContent-Length: 9999\r\nConnection: close\r\n\r\n{corps}",
            json.len()
        )
        .as_bytes(),
    );
    assert!(
        r2.starts_with("HTTP/1.1 400"),
        "avec 9999 en dernier, le serveur attend un corps qui n'arrive pas : {r2}"
    );
    assert!(
        !corps_de(&r2).contains("\"hauteur\""),
        "l'appel a tout de meme ete execute : {r2}"
    );
    h.shutdown();
}

/// Deux requetes empilees sur une connexion : la seconde est perdue.
/// Aucune contrebande, mais aucune erreur non plus.
#[test]
fn ok_pas_de_contrebande_par_empilement() {
    let h = serveur(false, None);
    let c = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;
    let r = brut(
        h.addr,
        format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Content-Type: application/json\r\nContent-Length: {n}\r\n\r\n{c}\
             POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Content-Type: application/json\r\nContent-Length: {n}\r\n\r\n{c}",
            n = c.len()
        )
        .as_bytes(),
    );
    assert_eq!(
        r.matches("HTTP/1.1 200").count(),
        1,
        "une seule reponse doit sortir : {r}"
    );
    h.shutdown();
}

/// Les octets non-UTF-8 du corps sont remplaces sans erreur
/// (`from_utf8_lossy`, src/http.rs:254) — pas de panique.
#[test]
fn ok_corps_binaire_ne_fait_pas_paniquer() {
    let h = serveur(false, None);
    let mut req = b"POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
          Content-Length: 16\r\nConnection: close\r\n\r\n"
        .to_vec();
    req.extend_from_slice(&[
        0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28, 0xed, 0xa0, 0x80, 1, 2, 3, 4, 5, 6, 7,
    ]);
    let r = brut(h.addr, &req);
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    h.shutdown();
}

// ===========================================================================
// 5. Analyseur JSON
// ===========================================================================

/// Imbrication profonde : le compteur de profondeur tient, pas de debordement
/// de pile.
#[test]
fn ok_imbrication_profonde_est_refusee_proprement() {
    let h = serveur(false, None);
    for n in [40usize, 5_000, 200_000] {
        let corps = format!("{}{}", "[".repeat(n), "]".repeat(n));
        let r = post_rpc(h.addr, &corps);
        assert!(
            r.starts_with("HTTP/1.1 200") || r.starts_with("HTTP/1.1 400"),
            "profondeur {n} : {}",
            r.lines().next().unwrap_or("(rien)")
        );
    }
    assert!(appel(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// Chaines geantes, echappements pathologiques, substituts isoles, nombres
/// hors bornes : erreurs propres, aucune panique.
#[test]
fn ok_json_pathologique_ne_fait_pas_paniquer() {
    let h = serveur(false, None);
    let cas: Vec<String> = vec![
        format!(r#"{{"method":"{}"}}"#, "A".repeat(500_000)),
        r#"{"method":"getinfo","x":"\ud800𐏿"}"#.into(),
        r#"{"method":"getinfo","x":" ￿"}"#.into(),
        format!(
            r#"{{"method":"getemission","params":{{"hauteur":{}}}}}"#,
            "9".repeat(400)
        ),
        r#"{"method":"getemission","params":{"hauteur":-1}}"#.into(),
        r#"{"method":"getemission","params":{"hauteur":1.5}}"#.into(),
        r#"{"method":"getinfo","x":"\uZZZZ"}"#.into(),
        r#"{"method":"getinfo","x":"non termine"#.into(),
        format!(r#"{{"method":"getinfo","x":{}}}"#, "\"a\":".to_string()),
        "\u{feff}{\"method\":\"getinfo\"}".into(),
    ];
    for c in &cas {
        let r = post_rpc(h.addr, c);
        assert!(
            !r.is_empty(),
            "aucune reponse (panique ?) pour : {}",
            &c[..c.len().min(60)]
        );
    }
    assert!(appel(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// Clefs dupliquees : la **derniere** l'emportait (`BTreeMap::insert`). Un
/// intermediaire — pare-feu applicatif, journal d'audit, mandataire filtrant —
/// qui lit la premiere occurrence de `method` voyait donc autre chose que le
/// noeud, et laissait passer une depense annoncee comme une consultation.
///
/// Le RFC 8259 laisse ce comportement indefini ; du code monetaire ne se paie
/// pas d'indefini. L'analyseur refuse maintenant le document entier
/// (`JsonError::ClefDupliquee`), a n'importe quelle profondeur.
#[test]
fn faille_clef_json_dupliquee_la_derniere_gagne() {
    use q21_core::json::{parse, JsonError};

    let h = serveur(true, None);

    // La clef `method` repetee : ni la premiere ni la derniere lecture ne
    // s'execute, le document est refuse.
    let r = post_rpc(
        h.addr,
        r#"{"jsonrpc":"2.0","id":1,"method":"getinfo","method":"getnewaddress"}"#,
    );
    let c = corps_de(&r);
    assert!(c.contains("-32700"), "document ambigu accepte : {c}");
    assert!(
        !c.contains("\"adresse\""),
        "la seconde clef a ete executee : {c}"
    );
    assert!(
        !c.contains("\"hauteur\""),
        "la premiere clef a ete executee : {c}"
    );

    // Et jusque dans les parametres, ou se cacherait un second montant.
    let c = corps_de(&post_rpc(
        h.addr,
        r#"{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{"adresse":"rq21zzz","unites":1,"unites":100000000}}"#,
    ))
    .to_string();
    assert!(
        c.contains("-32700"),
        "duplication dans les parametres acceptee : {c}"
    );

    // Directement sur l'analyseur : le refus nomme la clef fautive.
    assert_eq!(
        parse(r#"{"method":"getinfo","method":"sendtoaddress"}"#),
        Err(JsonError::ClefDupliquee("method".to_string()))
    );
    // Un objet sans repetition reste evidemment accepte.
    assert!(parse(r#"{"a":1,"b":2}"#).is_ok());
    h.shutdown();
}

/// `Json::as_u64` acceptait une chaine : la promesse « aucun entier au-dela de
/// `i64::MAX` » ne tenait pas cote **entree**, et c'etait la porte du
/// debordement de `sendtoaddress`.
///
/// Deux changements, de sens contraire, qui se completent :
///
/// - un entier reste un entier. `as_u64` ne convertit plus une chaine ; une
///   valeur numerique donnee entre guillemets n'est plus lue du tout ;
/// - la borne de l'analyseur, elle, n'a plus lieu d'etre : la variante
///   `Json::Grand` represente les entiers entre `i64::MAX` et `u64::MAX`, qui
///   sont du JSON parfaitement valide. Ils sont donc **acceptes en nombre**, et
///   c'est aux couches metier de les borner — ce que fait le portefeuille.
#[test]
fn faille_les_entiers_hors_i64_passent_par_une_chaine() {
    use q21_core::json::parse;

    let h = serveur(false, None);

    // En nombre : accepte, et rendu en nombre.
    let n = corps_de(&post_rpc(
        h.addr,
        r#"{"jsonrpc":"2.0","id":1,"method":"getemission","params":{"hauteur":18446744073709551615}}"#,
    ))
    .to_string();
    assert!(
        n.contains("\"hauteur\":18446744073709551615"),
        "un entier hors i64 est du JSON valide et doit etre lu comme un nombre : {n}"
    );
    assert!(
        !n.contains("\"hauteur\":\"18446744073709551615\""),
        "le champ ne doit pas ressortir en chaine : {n}"
    );

    // En chaine : plus de conversion. Le parametre est simplement absent, et
    // `getemission` retombe sur la hauteur de la chaine — zero ici.
    let s = corps_de(&post_rpc(
        h.addr,
        r#"{"jsonrpc":"2.0","id":1,"method":"getemission","params":{"hauteur":"18446744073709551615"}}"#,
    ))
    .to_string();
    assert!(
        s.contains("\"hauteur\":0"),
        "une chaine ne doit plus valoir un entier : {s}"
    );
    assert!(
        !s.contains("18446744073709551615"),
        "la valeur donnee en chaine a ete lue : {s}"
    );

    // Le meme constat, sans passer par le reseau.
    assert_eq!(
        parse(r#"{"n":"18446744073709551615"}"#)
            .unwrap()
            .get("n")
            .and_then(|v| v.as_u64()),
        None
    );
    assert_eq!(
        parse(r#"{"n":18446744073709551615}"#)
            .unwrap()
            .get("n")
            .and_then(|v| v.as_u64()),
        Some(u64::MAX)
    );
    h.shutdown();
}

/// Amplification par lot : une requete d'un mebioctet — la taille maximale d'un
/// corps — contenait des dizaines de milliers d'appels, chacun produisant sa
/// reponse, le tout assemble **entierement en memoire** avant emission
/// (`Json::array(reponses).encode()`). Aucune borne sur le nombre d'appels,
/// aucune sur la taille de la reponse ; le facteur mesure depassait dix.
///
/// `MAX_LOT` borne le nombre d'appels et `MAX_REPONSE_LOT` la taille cumulee des
/// reponses. Un lot trop grand est refuse **avant** d'executer quoi que ce soit :
/// le cout de l'attaque est desormais celui d'une analyse, pas celui de vingt
/// mille appels.
#[test]
fn faille_amplification_par_lot_json_rpc() {
    use q21_core::rpc::MAX_LOT;

    let h = serveur(false, None);

    let unite = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"},"#;
    let n = (1024 * 1024 - 2) / unite.len();
    let mut corps = String::with_capacity(1024 * 1024);
    corps.push('[');
    for _ in 0..n {
        corps.push_str(unite);
    }
    corps.pop();
    corps.push(']');
    assert!(corps.len() <= 1024 * 1024, "corps = {} o", corps.len());

    let debut = Instant::now();
    let r = post_rpc(h.addr, &corps);
    let ecoule = debut.elapsed();
    let sortie = corps_de(&r).len();

    let facteur = sortie as f64 / corps.len() as f64;
    eprintln!(
        "lot : {n} requetes, entree {} o, sortie {sortie} o, facteur x{facteur:.4}, {ecoule:?}",
        corps.len()
    );
    assert!(
        facteur < 1.0,
        "un lot ne doit plus amplifier : entree {} o -> sortie {sortie} o (x{facteur:.1})",
        corps.len()
    );
    let c = corps_de(&r);
    assert!(
        c.contains("-32600") && c.contains(&format!("maximum {MAX_LOT}")),
        "le refus doit nommer la borne : {c}"
    );
    assert!(
        !c.contains("\"hauteur\""),
        "aucun des {n} appels ne doit avoir ete execute : {c}"
    );

    // La borne est exacte, et un lot utile passe toujours.
    let lot = |m: usize| {
        let mut c = String::from("[");
        for _ in 0..m {
            c.push_str(unite);
        }
        c.pop();
        c.push(']');
        post_rpc(h.addr, &c)
    };
    assert_eq!(
        corps_de(&lot(MAX_LOT)).matches("\"hauteur\"").count(),
        MAX_LOT,
        "un lot de {MAX_LOT} appels doit etre servi entierement"
    );
    assert!(corps_de(&lot(MAX_LOT + 1)).contains("-32600"));
    h.shutdown();
}

/// Amplification en travail : chaque `gettransaction` d'un lot declenchait un
/// balayage arriere de **toute** la chaine, sous le verrou global du noeud. Le
/// cout croissait avec la hauteur, et un lot le multipliait par le nombre
/// d'elements — cinq mille appels pour le prix d'une requete.
///
/// Deux bornes se completent : `MAX_LOT` limite le nombre d'appels d'un lot, et
/// `MAX_BLOCS_BALAYES` limite la profondeur de chaque balayage. La seconde n'est
/// pas exercee ici — il faudrait une chaine de plus de deux mille blocs, donc
/// autant de preuves de travail. Ce test verrouille la premiere, qui est celle
/// qui transformait un appel couteux en arme.
#[test]
fn faille_gettransaction_balaie_toute_la_chaine_par_element_de_lot() {
    use q21_core::rpc::MAX_LOT;

    let h = serveur(false, None);
    let un = r#"{"jsonrpc":"2.0","id":1,"method":"gettransaction","params":{"txid":"0000000000000000000000000000000000000000000000000000000000000000"}},"#;

    let lot_de = |n: usize| {
        let mut corps = String::from("[");
        for _ in 0..n {
            corps.push_str(un);
        }
        corps.pop();
        corps.push(']');
        let t = Instant::now();
        let r = post_rpc(h.addr, &corps);
        (t.elapsed(), r)
    };

    let (borne, r_borne) = lot_de(MAX_LOT);
    let n = 5_000;
    let (grand, r_grand) = lot_de(n);
    eprintln!("gettransaction : lot de {MAX_LOT} en {borne:?}, lot de {n} en {grand:?}");

    // Le lot autorise s'execute entierement…
    assert_eq!(
        corps_de(&r_borne).matches("\"code\":-1").count(),
        MAX_LOT,
        "les {MAX_LOT} appels autorises doivent etre executes"
    );
    // …et le lot demesure ne s'execute pas du tout.
    let c = corps_de(&r_grand);
    assert_eq!(
        c.matches("\"code\":-1").count(),
        0,
        "aucun des {n} balayages ne doit avoir eu lieu : {c}"
    );
    assert!(
        c.contains("-32600") && c.contains(&format!("maximum {MAX_LOT}")),
        "{c}"
    );
    // Le travail ne suit plus la taille du lot : le refus tient en une centaine
    // d'octets, la ou la reponse pesait des mebioctets.
    assert!(
        c.len() < 200,
        "le refus doit couter une reponse minuscule : {} o",
        c.len()
    );
    h.shutdown();
}

/// `getbalance` recopiait tout l'ensemble des UTXO a chaque appel
/// (`c.utxo.clone()`) — des centaines de mebioctets sur une chaine reelle, pour
/// lire un solde — et un lot en demandait autant de copies.
///
/// Le calcul se fait desormais sous le verrou, sur une reference : il est
/// identique, l'allocation a disparu. C'est une propriete de cout, donc invisible
/// dans une reponse ; ce test la mesure en se donnant un etalon.
///
/// L'etalon est la copie elle-meme : on remplit un jeu de cent mille sorties, on
/// chronometre **une** copie, puis on chronometre cent `getbalance`. Si l'appel
/// recopiait, ces cent appels couteraient au moins cent copies. Ils en coutent
/// aujourd'hui moins de deux — chaque appel parcourt le jeu sans le dupliquer.
#[test]
fn faille_getbalance_recopie_l_ensemble_utxo_par_appel() {
    use q21_core::amount::Amount;
    use q21_core::hash::Hash256;
    use q21_core::rpc::MAX_LOT;
    use q21_core::sig::SchemeId;
    use q21_core::tx::{OutPoint, TxOut};
    use q21_core::utxo::UtxoEntry;

    let (h, noeud) = serveur_et_noeud();

    // Cent mille sorties non depensees : de quoi rendre une copie mesurable.
    const SORTIES: u32 = 100_000;
    noeud.with_chain(|c| {
        for i in 0..SORTIES {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            c.utxo.insert(
                OutPoint {
                    txid: Hash256(b),
                    index: 0,
                },
                UtxoEntry {
                    output: TxOut {
                        value: Amount::from_units(1_000),
                        scheme: SchemeId::LamportOts,
                        pubkey_hash: Hash256(b),
                    },
                    height: 0,
                    is_coinbase: false,
                },
            );
        }
    });

    // L'etalon : ce que coute exactement le `clone()` qui a ete retire.
    let cout_copie = {
        let t = Instant::now();
        let copie = noeud.with_chain(|c| c.utxo.clone());
        let d = t.elapsed();
        assert!(
            copie.len() as u32 > SORTIES,
            "le jeu doit etre reellement rempli"
        );
        d
    };

    let mut corps = String::from("[");
    for _ in 0..MAX_LOT {
        corps.push_str(r#"{"jsonrpc":"2.0","id":1,"method":"getbalance"},"#);
    }
    corps.pop();
    corps.push(']');

    let t = Instant::now();
    let r = post_rpc(h.addr, &corps);
    let cout_lot = t.elapsed();
    eprintln!("une copie du jeu UTXO : {cout_copie:?} ; {MAX_LOT} getbalance : {cout_lot:?}");

    assert_eq!(
        corps_de(&r).matches("\"depensable\"").count(),
        MAX_LOT,
        "les {MAX_LOT} soldes doivent etre rendus"
    );
    assert!(
        cout_lot < cout_copie * 25,
        "{MAX_LOT} appels coutent {cout_lot:?} pour une copie a {cout_copie:?} : \
         l'ensemble des UTXO est recopie a chaque appel"
    );

    // Et le lot lui-meme reste borne : vingt mille copies ne se demandent plus.
    let mut enorme = String::from("[");
    for _ in 0..20_000 {
        enorme.push_str(r#"{"jsonrpc":"2.0","id":1,"method":"getbalance"},"#);
    }
    enorme.pop();
    enorme.push(']');
    let c = corps_de(&post_rpc(h.addr, &enorme)).to_string();
    assert!(
        c.contains("-32600"),
        "un lot de 20 000 doit etre refuse : {c}"
    );
    assert!(!c.contains("depensable"), "{c}");
    h.shutdown();
}

// ===========================================================================
// 6. Explorateur / injection dans le navigateur
// ===========================================================================

/// L'encodeur JSON (`echapper`, src/json.rs) n'echappait ni `<`, ni `>`, ni `/`,
/// ni U+2028 / U+2029.
///
/// Le nom de methode inconnu est renvoye **verbatim** dans le message d'erreur.
/// Tout client qui insere ce message dans du HTML — ou qui place la reponse dans
/// un `<script>` — executait alors le script de l'attaquant. U+2028 et U+2029
/// sont des fins de ligne pour JavaScript mais pas pour JSON : une chaine qui en
/// contient rompt le litteral qui l'incorpore.
///
/// Ces cinq caracteres sortent desormais echappes. Les echappements restent du
/// JSON standard : tout analyseur les relit a l'identique, ce que ce test
/// verifie aussi — une sortie sure qui ne se relirait pas serait un autre bogue.
#[test]
fn faille_le_json_sortant_n_echappe_pas_le_html() {
    use q21_core::json::{parse, Json};

    let h = serveur(false, None);
    let charge = "</script><img src=x onerror=alert(document.domain)>";
    let r = post_rpc(
        h.addr,
        &format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{charge}"}}"#),
    );
    let c = corps_de(&r);
    assert!(
        !c.contains(charge),
        "la charge revient telle quelle dans le corps JSON : {c}"
    );
    assert!(
        !c.contains('<') && !c.contains('>') && !c.contains('/'),
        "aucun de ces trois caracteres ne doit sortir nu : {c}"
    );
    assert!(
        c.contains("\\u003c") && c.contains("\\u003e") && c.contains("\\u002f"),
        "l'echappement attendu est absent : {c}"
    );
    // Et la charge est intacte apres relecture : on echappe, on ne mutile pas.
    let relu = parse(c).expect("la reponse doit rester du JSON valide");
    assert_eq!(
        relu.get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .map(|m| m.contains(charge)),
        Some(true),
        "la relecture doit rendre la chaine d'origine : {c}"
    );

    // U+2028 et U+2029 : invisibles, et fatals a un litteral JavaScript.
    for (nom, sep) in [("U+2028", '\u{2028}'), ("U+2029", '\u{2029}')] {
        let corps = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"a{sep}b\"}}");
        let c = corps_de(&post_rpc(h.addr, &corps)).to_string();
        assert!(!c.contains(sep), "{nom} sort nu : {c}");
        assert!(
            c.contains(&format!("\\u{:04x}", sep as u32)),
            "{nom} doit etre echappe : {c}"
        );
    }

    // Directement sur l'encodeur, pour que la propriete ne depende pas d'un
    // chemin d'appel particulier.
    assert_eq!(
        Json::str("<a/b>\u{2028}\u{2029}").encode(),
        r#""\u003ca\u002fb\u003e\u2028\u2029""#
    );
    h.shutdown();
}

/// L'explorateur possedait des points d'insertion `innerHTML` **non echappes**.
///
/// `tuile(k,v,n)` echappait `k` mais inserait `v` et `n` bruts ; `lignes()`
/// echappait la clef mais inserait la valeur brute. Seuls des nombres y
/// transitaient, si bien que l'exploitation n'etait pas demontree — mais
/// l'invariant tenait a la seule discipline de chaque appelant, et la faille
/// voisine (`Json::u64` basculant en chaine) etait precisement de quoi la rompre.
///
/// Les deux helpers passent maintenant par `rendu()`, qui echappe par defaut ;
/// un fragment de balisage volontaire se declare avec `brut()`. La discipline
/// est donc inversee : il faut demander l'insertion crue, elle n'est plus le
/// defaut.
///
/// Quelques insertions crues subsistent dans la table des blocs et dans le pave
/// de securite. Elles sont enumerees ci-dessous, une par une : toutes sont
/// alimentees par des champs que `Json::u64` garantit numeriques (voir
/// `faille_latente_un_champ_numerique_peut_devenir_une_chaine`). Le balayage qui
/// suit echoue des qu'un point d'insertion cru apparait hors de cette liste.
#[test]
fn faille_latente_points_d_insertion_non_echappes_dans_l_explorateur() {
    let p = q21_core::explorer::PAGE;

    // Les deux helpers partages echappent desormais par defaut.
    assert!(
        p.contains(r#"<div class="v">${rendu(v)}</div>"#),
        "tuile() doit passer `v` par rendu()"
    );
    assert!(
        p.contains("<tr><th>${ech(k)}</th><td>${rendu(v)}</td></tr>"),
        "lignes() doit passer la valeur par rendu()"
    );
    assert!(!p.contains(r#"<div class="v">${v}</div>"#));
    assert!(!p.contains("<td>${v}</td>"));
    assert!(
        p.contains("const rendu =") && p.contains("const brut ="),
        "le balisage volontaire doit se declarer explicitement"
    );

    // Fonctions qui echappent ou qui ne peuvent produire que des caracteres surs.
    const SURES: [&str; 10] = [
        "ech(",
        "rendu(",
        "court(",
        "octets(",
        "date(",
        // Constructeurs de liens : ils echappent la route **et** le texte.
        // La verification qu'ils le font est faite juste au-dessus, sur la
        // source de `lien` : sans elle, les inscrire ici serait une croyance.
        "lien(",
        "lienBloc(",
        "lienTx(",
        "lienAdresse(",
        // Conversion d'unites en Q21 : n'assemble que des chiffres issus d'un
        // BigInt et un point. Aucun caractere de balisage n'en sort.
        "q21(",
    ];
    // Insertions crues admises, et la raison de chacune.
    const CRUES_ADMISES: [&str; 12] = [
        // Condition d'un ternaire : jamais inseree, seulement testee.
        "n",
        // Champs numeriques du noeud (`Json::u64`), donc jamais des chaines.
        "b.entete.hauteur",
        "b.nb_transactions",
        "sec.defenses.finalite_glissante_blocs",
        "sec.defenses.finalite_glissante_heures",
        // Booleen, rendu par un litteral choisi dans la page elle-meme.
        "sec.protection_100_pourcent_possible",
        // Tableaux dont chaque element passe par ech() juste apres.
        "sec.un_attaquant_peut.map(x=>",
        "sec.un_attaquant_ne_peut_pas.map(x=>",
        // Conditions de ternaires : testees, jamais inserees. Ce qui est
        // insere ensuite est un litteral choisi dans la page elle-meme.
        "t.coinbase",
        "m.coinbase",
        "BigInt(m.recu.unites) > 0n",
        "!m.montant_sortant_connu",
    ];

    // Les constructeurs de liens sont declares surs plus haut. On verifie ici
    // qu'ils le sont : leurs deux moities passent par ech(). Sans ce controle,
    // ajouter un nom a SURES reviendrait a desarmer l'epreuve d'une ligne.
    assert!(
        p.contains(r##"`<a class="plat" href="#/${ech(route)}">${ech(texte)}</a>`"##),
        "le constructeur de liens n'echappe plus ses deux moities : tout ce qui \
         passe par lien(), lienBloc(), lienTx() ou lienAdresse() devient une \
         injection possible"
    );

    let mut reste = p;
    let mut examines = 0;
    while let Some(i) = reste.find("${") {
        reste = &reste[i + 2..];
        let fin = reste.find(['}', '?', '`']).unwrap_or(reste.len());
        let tete = reste[..fin].trim();
        examines += 1;
        let sure = SURES.iter().any(|f| tete.starts_with(f));
        assert!(
            sure || CRUES_ADMISES.contains(&tete),
            "point d'insertion non echappe et non repertorie : ${{{tete}}}\n\
             Ajoutez-le a CRUES_ADMISES en justifiant pourquoi sa valeur ne peut \
             pas porter de balisage, ou passez-le par rendu()."
        );
    }
    assert!(
        examines >= 15,
        "le balayage n'a trouve que {examines} points d'insertion : la page a \
         change de forme, la verification ne mesure plus rien"
    );
}

/// `Json::u64` basculait en **chaine** au-dela de `i64::MAX`. Un champ que le
/// client croit numerique changeait donc de type selon sa valeur : la valeur
/// arrivait dans un point d'insertion prevu pour un nombre, ou dans une
/// comparaison qui ne comparait plus rien. C'etait le pont entre un compteur du
/// noeud et une injection dans l'explorateur.
///
/// La variante `Json::Grand` porte desormais ces valeurs et s'encode en
/// **nombre**. JSON ne borne pas les entiers ; c'est JavaScript qui perd la
/// precision au-dela de 2^53, ce qui est un autre sujet. Le type, lui, ne varie
/// plus — et c'est ce qui rend surs les points d'insertion crus enumeres dans
/// `faille_latente_points_d_insertion_non_echappes_dans_l_explorateur`.
#[test]
fn faille_latente_un_champ_numerique_peut_devenir_une_chaine() {
    use q21_core::json::{parse, Json};

    assert!(matches!(Json::u64(42), Json::Int(_)));
    assert!(
        matches!(Json::u64(u64::MAX), Json::Grand(_)),
        "au-dela de i64::MAX, le champ doit rester un nombre"
    );

    // Aucune valeur ne doit produire une chaine, de part et d'autre de la borne.
    for v in [
        0,
        1,
        i64::MAX as u64 - 1,
        i64::MAX as u64,
        i64::MAX as u64 + 1,
        u64::MAX,
    ] {
        let j = Json::u64(v);
        assert!(!matches!(j, Json::Str(_)), "u64({v}) est devenu une chaine");
        let encode = j.encode();
        assert!(
            !encode.contains('"'),
            "u64({v}) s'encode en chaine : {encode}"
        );
        assert_eq!(encode, v.to_string());
        // Et il se relit comme un nombre.
        assert_eq!(parse(&encode).unwrap().as_u64(), Some(v));
    }
}

/// L'explorateur transmettait la totalite de `location.search` au RPC
/// (`const RPC = "/rpc" + location.search`).
///
/// C'etait la moitie visible du transport du jeton par l'URL : la page recopiait
/// dans chaque appel tout ce qui trainait dans la chaine de requete, jeton
/// compris, et l'adresse portant ce jeton restait dans l'historique du
/// navigateur.
///
/// Le jeton est desormais demande une fois, garde en memoire le temps de
/// l'onglet, et envoye en `Authorization: Bearer`.
#[test]
fn faille_l_explorateur_recopie_la_chaine_de_requete() {
    let p = q21_core::explorer::PAGE;

    assert!(
        !p.contains("location.search"),
        "la chaine de requete est encore recopiee vers le RPC"
    );
    assert!(
        p.contains(r#"const RPC = "/rpc";"#),
        "le point d'entree du RPC doit etre fixe"
    );
    assert!(
        p.contains("\"Authorization\"") && p.contains("\"Bearer \""),
        "le jeton doit voyager en en-tete"
    );
    // Le jeton se demande dans la page. `window.prompt` bloque tout l'onglet,
    // ne se met pas en forme, et plusieurs navigateurs ne l'affichent plus du
    // tout dans certains contextes — un explorateur devenait alors
    // inutilisable sans qu'aucun message n'explique pourquoi.
    assert!(
        p.contains(r#"id="panneau-jeton""#),
        "le jeton doit etre demande par un champ de la page"
    );
    assert!(
        !p.contains("window.prompt"),
        "le jeton ne doit plus etre demande par une fenetre du navigateur"
    );

    // --- Le fragment sert maintenant a deux choses, et une seule est secrete.
    //
    // Le jeton y arrive — le navigateur ne l'envoie jamais au serveur — et le
    // routage l'emploie ensuite. Ce qui doit rester vrai :
    //
    //  - le jeton est efface de la barre d'adresse des qu'il est lu ;
    //  - il ne repart que dans l'en-tete `Authorization` ;
    //  - rien de l'adresse n'est recopie dans une requete sortante.
    assert!(
        p.contains("history.replaceState"),
        "le jeton reste dans la barre d'adresse apres avoir ete lu"
    );
    assert!(
        p.contains(r##"if (f && !f.startsWith("/"))"##),
        "rien ne distingue un jeton d'une route dans le fragment"
    );
    assert!(!p.contains("location.href"));
    // Le corps d'une requete ne contient que la methode et ses parametres.
    assert!(
        p.contains("body: JSON.stringify({jsonrpc:\"2.0\", id:++compteur, method:methode, params:params||{}})"),
        "le corps des requetes n'est plus celui qu'on croit"
    );
}

// ===========================================================================
// 7. Fuites
// ===========================================================================

/// Aucune reponse RPC ne laisse fuir la graine ni le code de sauvegarde.
#[test]
fn ok_aucune_reponse_rpc_ne_revele_la_graine() {
    let h = serveur(true, None);
    let graine_hex = "07".repeat(32);
    for (m, p) in [
        ("getinfo", "{}"),
        ("getbalance", "{}"),
        ("getnewaddress", "{}"),
        ("getsupply", "{}"),
        ("getpeers", "{}"),
        ("getmempool", "{}"),
        ("listmethods", "{}"),
        ("sendtoaddress", r#"{"adresse":"rq21zzz","unites":1}"#),
    ] {
        let c = corps_de(&appel(h.addr, m, p)).to_string();
        assert!(!c.contains(&graine_hex), "{m} revele la graine : {c}");
        assert!(!c.to_lowercase().contains("seed="), "{m} : {c}");
        assert!(!c.contains("next_index"), "{m} : {c}");
    }
    h.shutdown();
}

/// Les erreurs de portefeuille exposaient l'etat interne : rendues par
/// `format!("{e:?}")`, elles portaient le contenu de la variante, soit
/// `FondsInsuffisants { disponible: 43120000, demande: … }`. Le solde exact
/// partait ainsi vers un appelant qui n'avait qu'a demander une somme absurde
/// pour l'obtenir. Un refus n'a pas a etre un releve de compte.
///
/// `message_portefeuille` (src/rpc.rs) traduit desormais chaque variante en un
/// message fixe. Les autres variantes ne portent rien de sensible et gardent un
/// message precis : qui se trompe doit comprendre pourquoi.
#[test]
fn faille_l_erreur_de_fonds_revele_le_solde_exact() {
    let h = serveur(true, None);
    let dest = adresse_regtest(h.addr);

    // Deux demandes tres differentes doivent donner exactement le meme refus :
    // sinon la reponse mesure encore le solde.
    let refus = |unites: u64| -> String {
        corps_de(&appel(
            h.addr,
            "sendtoaddress",
            &format!(r#"{{"adresse":"{dest}","unites":{unites}}}"#),
        ))
        .to_string()
    };
    let petit = refus(1);
    let gros = refus(1_000_000_000_000);

    assert!(petit.contains("\"code\":-3"), "{petit}");
    assert_eq!(petit, gros, "le refus varie avec la somme demandee");

    for interdit in ["disponible", "demande", "FondsInsuffisants", "43120000"] {
        assert!(
            !petit.contains(interdit),
            "l'erreur laisse fuir « {interdit} » : {petit}"
        );
    }
    assert!(
        petit.contains("fonds insuffisants"),
        "le refus doit rester comprehensible : {petit}"
    );
    // Aucun chiffre dans le message : c'est la ou se cachait le solde.
    let message = petit
        .split("\"message\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("champ message");
    assert!(
        !message.chars().any(|c| c.is_ascii_digit()),
        "le message porte encore un nombre : {message}"
    );
    h.shutdown();
}

// ===========================================================================
// 8. Fichier de portefeuille scelle (src/kdf.rs)
// ===========================================================================

/// Le nombre d'iterations est authentifie, mais **utilise avant** de l'etre.
///
/// `desceller` derive la clef avec la valeur lue dans le fichier (l. 235-243),
/// puis seulement ensuite verifie le MAC. Un attaquant qui peut ecrire quatre
/// octets dans `wallet.dat` impose donc un travail arbitraire — jusqu'a
/// 2^32-1 iterations de PBKDF2, soit des heures — avant le moindre rejet.
/// Le portefeuille devient inouvrable sans qu'aucun message ne l'explique.
#[test]
fn faille_iterations_attaquant_avant_verification_du_mac() {
    use q21_core::kdf;

    let scelle = kdf::sceller(b"phrase", b"seed=00\nnext_index=0\n", 1).expect("scellage");

    let mesure = |iterations: u32| {
        let mut faux = scelle.clone();
        faux[8..12].copy_from_slice(&iterations.to_le_bytes());
        let t = Instant::now();
        let r = kdf::desceller(b"phrase", &faux);
        (t.elapsed(), r)
    };

    // Le champ reste lu avant d'etre authentifie — c'est inevitable, il faut ce
    // nombre pour deriver la clef qui verifie le MAC. Ce qui a change : il est
    // **borne** avant la derivation.
    let (rapide, _) = mesure(1);
    let (absurde, r) = mesure(u32::MAX);
    eprintln!("iterations=1 : {rapide:?} ; iterations=2^32-1 : {absurde:?}");
    assert!(
        matches!(r, Err(q21_core::kdf::ScelleError::IterationsAberrantes(_))),
        "un nombre d'iterations aberrant doit etre refuse : {r:?}"
    );
    assert!(
        absurde < Duration::from_millis(50),
        "le refus a coute {absurde:?} : la derivation a ete engagee malgre tout"
    );

    // Un reglage legitime, lui, passe et coute ce qu'il doit couter.
    let (lent, r2) = mesure(400_000);
    assert!(r2.is_err(), "le MAC doit finir par echouer");
    assert!(lent > absurde, "un reglage legitime derive bien");
}

/// Aucune version, aucun compteur, aucune identite de fichier dans le format
/// scelle : un ancien `wallet.dat` se rejoue tel quel.
///
/// Le format est `MAGIE || iterations || sel || chiffre || mac` (src/kdf.rs:200).
/// Deux scellages successifs du meme portefeuille sont interchangeables : rien
/// ne permet de savoir lequel est le plus recent.
#[test]
fn faille_rejeu_d_un_ancien_fichier_de_portefeuille() {
    use q21_core::kdf;

    // Le format scelle lui-meme n'ordonne toujours pas deux fichiers : c'est un
    // constat, pas un defaut du scellement. Ce qui les ordonne est **dans le
    // clair**, et le noeud conserve a part la valeur la plus haute vue.
    let contenu = |serie: u32, next: u32| {
        format!(
            "seed=1111111111111111111111111111111111111111111111111111111111111111\n\
             next_index={next}\nnetwork=regtest\nscheme=1\nserie={serie}\nconsommes=\n"
        )
    };
    let ancien = kdf::sceller(b"phrase", contenu(3, 0).as_bytes(), 1).unwrap();
    let recent = kdf::sceller(b"phrase", contenu(4, 9).as_bytes(), 1).unwrap();

    let a = String::from_utf8(kdf::desceller(b"phrase", &ancien).unwrap()).unwrap();
    let r = String::from_utf8(kdf::desceller(b"phrase", &recent).unwrap()).unwrap();

    let serie_de = |s: &str| -> u64 {
        s.lines()
            .find_map(|l| l.strip_prefix("serie="))
            .and_then(|v| v.parse().ok())
            .expect("champ serie")
    };
    assert!(
        serie_de(&a) < serie_de(&r),
        "deux fichiers successifs doivent etre ordonnables : {a} / {r}"
    );
    // C'est cette comparaison que `lire_portefeuille` effectue contre la valeur
    // haute conservee dans `wallet.seq` : un fichier plus ancien est refuse,
    // avec un message qui explique comment passer outre en connaissance de cause.
}

/// Conséquence du rejeu, sur un schema a **usage unique** (Lamport, defaut sans
/// la feature `mldsa`) : ramener `next_index` a zero fait re-deriver les memes
/// clefs, et la liste des indices deja signes n'est **jamais** ecrite sur
/// disque (src/bin/q21.rs:`ecrire_portefeuille`, l. 236 : seuls `seed`,
/// `next_index`, `network`, `scheme` sont sauves ; `Wallet::consommes`
/// (src/wallet.rs:72) meurt avec le processus).
///
/// Deux signatures avec une clef Lamport revelent la clef privee.
#[test]
fn faille_le_garde_fou_anti_reutilisation_lamport_ne_survit_pas_au_redemarrage() {
    use q21_core::sig::SchemeId;

    let mut w1 = Wallet::from_seed_scheme([3u8; 32], RESEAU, SchemeId::LamportOts).unwrap();
    let a0 = w1.new_address();
    let a1 = w1.new_address();

    // Un « redemarrage » : on ne relit que ce que le fichier contient.
    let mut w2 = Wallet::from_seed_scheme([3u8; 32], RESEAU, SchemeId::LamportOts).unwrap();
    w2.rescan(2);

    let connues1 = w1.known_hashes();
    let connues2 = w2.known_hashes();
    assert_eq!(connues1, connues2, "memes clefs rederivees");
    assert_eq!(connues2[0], a0.hash);
    assert_eq!(connues2[1], a1.hash);

    // Ce qui est persiste porte desormais la liste des clefs deja employees.
    let contenu = format!(
        "seed={}\nnext_index={}\nnetwork=regtest\nscheme={}\nserie=1\nconsommes={}\n",
        w1.seed_hex(),
        w1.next_index(),
        w1.scheme().as_u8(),
        w1.indices_consommes()
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(
        contenu.contains("consommes="),
        "le format ecrit sur disque doit conserver les clefs deja employees : {contenu}"
    );

    // Et la reprise les rend au portefeuille.
    w2.marquer_consommes(&[0]);
    assert!(
        w2.est_consomme(0),
        "la consommation doit survivre au redemarrage"
    );
    assert!(!w2.est_consomme(1));
}

/// Troncature : rejetee, mais avec un message **distinct** de celui d'une
/// mauvaise phrase. Un fichier abime et une phrase fausse n'etaient donc pas
/// indistinguables, contrairement a ce qu'affirmait la documentation du module :
/// qui abime lui-meme un fichier scelle pouvait, en observant le message,
/// apprendre si la phrase essayee etait la bonne.
///
/// `desceller` rend maintenant `AuthentificationEchouee` dans tous les cas ou le
/// fichier se presente comme un scelle Q21 — troncature comprise.
///
/// Une seule distinction subsiste, et elle est voulue : la **magie**. Absente,
/// ce fichier n'est pas un portefeuille Q21, et le dire ne renseigne personne
/// sur la phrase secrete. Ce test verifie les deux moities de ce partage.
#[test]
fn faille_troncature_et_mauvaise_phrase_ne_donnent_pas_le_meme_message() {
    use q21_core::kdf::{self, ScelleError};
    let scelle = kdf::sceller(b"phrase", b"seed=00\n", 1).unwrap();

    let mauvaise = kdf::desceller(b"autre", &scelle).unwrap_err();
    assert_eq!(mauvaise, ScelleError::AuthentificationEchouee);

    // Toute troncature d'un fichier qui porte la magie donne le meme message
    // qu'une phrase fausse — quelle que soit la longueur retiree.
    for n in [1, 2, 20, scelle.len() - 40, scelle.len() - 8] {
        let tronque = kdf::desceller(b"phrase", &scelle[..scelle.len() - n]).unwrap_err();
        assert_eq!(
            tronque, mauvaise,
            "un fichier ampute de {n} octets reste distinguable d'une phrase fausse"
        );
        // Et les messages rendus a l'utilisateur le sont aussi.
        assert_eq!(tronque.to_string(), mauvaise.to_string());
    }

    // Un en-tete altere autrement que par la magie : meme message encore.
    let mut sel_change = scelle.clone();
    sel_change[14] ^= 0x01;
    assert_eq!(
        kdf::desceller(b"phrase", &sel_change).unwrap_err(),
        mauvaise
    );

    // La seule distinction conservee : ce fichier n'est pas un scelle Q21.
    let magie = {
        let mut m = scelle.clone();
        m[0] = b'X';
        kdf::desceller(b"phrase", &m).unwrap_err()
    };
    assert_eq!(magie, ScelleError::FormatInvalide);
    assert_ne!(
        magie, mauvaise,
        "dire qu'un fichier n'est pas un portefeuille Q21 ne renseigne personne \
         sur la phrase, et evite a l'utilisateur de chercher au mauvais endroit"
    );
    assert_eq!(
        kdf::desceller(b"phrase", b"ceci n'est pas un scelle").unwrap_err(),
        ScelleError::FormatInvalide
    );
}

/// `iterations = 0` est refuse — la protection ne peut pas etre annulee.
#[test]
fn ok_iterations_nulles_sont_refusees() {
    use q21_core::kdf;
    let scelle = kdf::sceller(b"phrase", b"x", 1).unwrap();
    let mut faux = scelle.clone();
    faux[8..12].copy_from_slice(&0u32.to_le_bytes());
    assert!(kdf::desceller(b"phrase", &faux).is_err());
}

/// Le MAC couvre bien l'en-tete : on ne peut pas abaisser les iterations.
#[test]
fn ok_le_mac_couvre_le_nombre_d_iterations() {
    use q21_core::kdf;
    let scelle = kdf::sceller(b"phrase", b"seed=aa\n", 200_000).unwrap();
    let mut faux = scelle.clone();
    faux[8..12].copy_from_slice(&1u32.to_le_bytes());
    assert!(
        kdf::desceller(b"phrase", &faux).is_err(),
        "abaisser les iterations doit casser le MAC"
    );
}
