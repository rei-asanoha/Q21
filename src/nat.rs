//! Ouverture automatique du port dans la box.
//!
//! # Pourquoi ce module existe
//!
//! Derriere une box internet, un portefeuille sort vers le reseau mais rien
//! n'entre : la box bloque, c'est son role. Le reseau prenait alors la forme
//! d'une etoile dont le seul point d'entree public etait le centre — et qui
//! coupe le centre coupe tout le monde. Pour que le reseau se passe d'un
//! centre, il faut qu'une partie des portefeuilles soient joignables. Ce module
//! demande a la box d'ouvrir le port du noeud, sans rien exiger de
//! l'utilisateur.
//!
//! # Deux protocoles, dans cet ordre
//!
//! - **NAT-PMP** (RFC 6886) : un aller-retour UDP vers la box. Simple, rapide,
//!   present sur les box Apple et beaucoup d'autres.
//! - **UPnP IGD** : une decouverte par multidiffusion, puis une requete SOAP.
//!   Plus bavard, mais le plus repandu sur les box grand public.
//!
//! Aucune dependance : la bibliotheque standard suffit pour de l'UDP, du TCP,
//! et le peu de HTTP et de XML que ces protocoles demandent. C'est la regle du
//! projet, et c'est aussi une surface d'attaque en moins.
//!
//! # Ce qu'on ne croit pas sur parole
//!
//! La box est un appareil du reseau local, et un reseau local peut heberger un
//! appareil hostile qui se fait passer pour elle. Ce module borne donc chaque
//! lecture, fixe chaque delai, n'accepte une description que depuis une adresse
//! privee, et ne tient une adresse externe pour bonne que si elle est publique.
//! Une adresse privee ou de CGNAT rendue par la box signifie une seconde box
//! devant elle : le port est ouvert pour rien, et on ne l'annonce pas.
//!
//! # Ce que ce module ne garantit pas
//!
//! Une ouverture reussie ne prouve pas que le noeud est joignable de
//! l'exterieur : un pare-feu en amont, ou un operateur qui partage une adresse
//! entre plusieurs clients, peuvent encore bloquer. Le programme dit donc
//! « ouverture demandee a la box : reussie », jamais « joignable » — ce serait
//! promettre ce qu'on ne peut pas verifier d'ici.

use std::fmt;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::Duration;

/// Bail demande a la box, en secondes. Deux heures : renouvele a mi-vie par
/// l'appelant, il survit a une absence prolongee de renouvellement sans
/// s'eterniser si le programme meurt sans retirer l'ouverture.
pub const BAIL_SECONDES: u32 = 7200;

/// Taille maximale d'une reponse HTTP lue d'un appareil du reseau local.
const MAX_REPONSE_HTTP: usize = 64 * 1024;

/// Delai de connexion et de lecture vers la box, en HTTP.
const DELAI_HTTP: Duration = Duration::from_secs(3);

/// Port NAT-PMP, fixe par la RFC 6886.
const PORT_NATPMP: u16 = 5351;

/// Adresse de multidiffusion SSDP, fixee par UPnP.
const SSDP_ADRESSE: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Methode {
    NatPmp,
    Upnp,
}

impl fmt::Display for Methode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Methode::NatPmp => write!(f, "NAT-PMP"),
            Methode::Upnp => write!(f, "UPnP"),
        }
    }
}

/// Une ouverture obtenue de la box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ouverture {
    pub methode: Methode,
    /// L'adresse que la box dit presenter a internet.
    pub adresse_externe: Ipv4Addr,
    /// Le port ouvert cote internet. Egal au port demande, sauf si la box en a
    /// attribue un autre (NAT-PMP le permet).
    pub port_externe: u16,
    /// Le bail accorde, en secondes. Zero = permanent (certaines box UPnP ne
    /// savent faire que cela).
    pub bail_secondes: u32,
    /// Ce qu'il faut pour retirer l'ouverture (UPnP) : l'URL de controle et le
    /// type de service. Vide pour NAT-PMP, qui retire par un bail nul.
    controle: Option<(String, String)>,
    /// La passerelle qui a repondu (NAT-PMP), pour le retrait.
    passerelle: Option<Ipv4Addr>,
}

#[derive(Debug)]
pub enum NatError {
    /// Aucune des deux methodes n'a abouti : la box ne repond pas, ou refuse.
    AucuneMethode { natpmp: String, upnp: String },
    /// L'adresse rendue par la box n'est pas publique : il y a une seconde box
    /// devant, l'ouverture ne sert a rien.
    AdresseNonPublique(Ipv4Addr),
}

impl fmt::Display for NatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NatError::AucuneMethode { natpmp, upnp } => write!(
                f,
                "la box n'a pas ouvert le port (NAT-PMP : {natpmp} ; UPnP : {upnp})"
            ),
            NatError::AdresseNonPublique(ip) => write!(
                f,
                "la box rend l'adresse {ip}, qui n'est pas publique : une seconde box \
                 ou un operateur partage l'adresse en amont, le port ouvert ne sert a rien"
            ),
        }
    }
}

impl std::error::Error for NatError {}

/// Demande a la box d'ouvrir `port` en TCP, vers cette machine.
///
/// Essaie NAT-PMP, puis UPnP. Rend l'ouverture obtenue, dont l'adresse externe
/// a ete verifiee publique.
pub fn ouvrir(port: u16) -> Result<Ouverture, NatError> {
    let erreur_natpmp = match natpmp_ouvrir(port) {
        Ok(o) => return verifier_publique(o),
        Err(e) => e,
    };
    let erreur_upnp = match upnp_ouvrir(port) {
        Ok(o) => return verifier_publique(o),
        Err(e) => e,
    };
    Err(NatError::AucuneMethode {
        natpmp: erreur_natpmp,
        upnp: erreur_upnp,
    })
}

/// Renouvelle une ouverture existante. Meme chemin que l'ouverture initiale,
/// par la meme methode : la box remet le bail a zero.
pub fn renouveler(o: &Ouverture, port: u16) -> Result<Ouverture, NatError> {
    let r = match o.methode {
        Methode::NatPmp => natpmp_ouvrir(port),
        Methode::Upnp => upnp_ouvrir(port),
    };
    match r {
        Ok(n) => verifier_publique(n),
        // Si la methode d'origine ne repond plus, on repart de zero.
        Err(_) => ouvrir(port),
    }
}

/// Retire l'ouverture. Sans garantie : la box peut avoir redemarre, ou refuser.
/// Un echec ici n'a pas de consequence — un bail non renouvele expire seul.
pub fn fermer(o: &Ouverture, port: u16) {
    match o.methode {
        Methode::NatPmp => {
            if let Some(gw) = o.passerelle {
                // Bail nul = retrait, par la RFC 6886.
                let _ = natpmp_requete_mappage(gw, port, 0, 0);
            }
        }
        Methode::Upnp => {
            if let Some((url, service)) = &o.controle {
                let args = format!(
                    "<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort>\
                     <NewProtocol>TCP</NewProtocol>",
                    o.port_externe
                );
                let _ = upnp_soap(url, service, "DeletePortMapping", &args);
            }
        }
    }
}

fn verifier_publique(o: Ouverture) -> Result<Ouverture, NatError> {
    if !adresse_publique(o.adresse_externe) {
        return Err(NatError::AdresseNonPublique(o.adresse_externe));
    }
    Ok(o)
}

/// Une adresse IPv4 que le reste d'internet peut joindre.
///
/// Refuse les plages privees, le CGNAT (100.64/10), le bouclage, le lien
/// local, la multidiffusion, et les non-specifiees. C'est le critere qui
/// decide si l'ouverture merite d'etre annoncee aux autres noeuds.
pub fn adresse_publique(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    let privee =
        o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168);
    let cgnat = o[0] == 100 && (64..=127).contains(&o[1]);
    let lien_local = o[0] == 169 && o[1] == 254;
    !(privee
        || cgnat
        || lien_local
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || o[0] == 0
        || o[0] >= 240)
}

// ---------------------------------------------------------------------------
// Adresse locale et passerelle
// ---------------------------------------------------------------------------

/// L'adresse IPv4 de cette machine sur son reseau local.
///
/// Astuce classique : « connecter » une socket UDP vers une adresse publique
/// n'envoie aucun paquet, mais force le systeme a choisir l'interface de
/// sortie, dont on lit l'adresse.
pub fn ip_locale() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect((Ipv4Addr::new(1, 1, 1, 1), 53)).ok()?;
    match s.local_addr().ok()? {
        std::net::SocketAddr::V4(a) => Some(*a.ip()),
        _ => None,
    }
}

/// Les adresses ou la box est probablement, dans l'ordre d'essai.
///
/// Sous Linux, la route par defaut du noyau donne la reponse exacte. Ailleurs,
/// et en repli, on tente les conventions des box grand public : le `.1` et le
/// `.254` du reseau local. NAT-PMP ne repond qu'a la bonne adresse, une
/// mauvaise ne coute qu'un delai court.
pub fn passerelles_candidates(ip_locale: Option<Ipv4Addr>) -> Vec<Ipv4Addr> {
    let mut v: Vec<Ipv4Addr> = Vec::new();
    if let Some(gw) = passerelle_systeme() {
        v.push(gw);
    }
    if let Some(ip) = ip_locale {
        let o = ip.octets();
        for dernier in [1u8, 254] {
            let c = Ipv4Addr::new(o[0], o[1], o[2], dernier);
            if c != ip && !v.contains(&c) {
                v.push(c);
            }
        }
    }
    v
}

#[cfg(target_os = "linux")]
fn passerelle_systeme() -> Option<Ipv4Addr> {
    let contenu = std::fs::read_to_string("/proc/net/route").ok()?;
    passerelle_depuis_table_de_routage(&contenu)
}

#[cfg(not(target_os = "linux"))]
fn passerelle_systeme() -> Option<Ipv4Addr> {
    None
}

/// Lit la passerelle de la route par defaut dans le format de
/// `/proc/net/route` : colonnes separees par des blancs, destination et
/// passerelle en hexadecimal petit-boutiste.
///
/// Propre a Linux (seul `passerelle_systeme` de Linux l'appelle), plus les
/// epreuves qui la verifient. Ailleurs, `/proc/net/route` n'existe pas.
#[cfg(any(target_os = "linux", test))]
fn passerelle_depuis_table_de_routage(contenu: &str) -> Option<Ipv4Addr> {
    for ligne in contenu.lines().skip(1) {
        let mut cols = ligne.split_whitespace();
        let _iface = cols.next()?;
        let dest = cols.next()?;
        let gw = cols.next()?;
        if dest != "00000000" {
            continue;
        }
        let n = u32::from_str_radix(gw, 16).ok()?;
        let b = n.to_le_bytes();
        let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
        if !ip.is_unspecified() {
            return Some(ip);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// NAT-PMP (RFC 6886)
// ---------------------------------------------------------------------------

fn natpmp_ouvrir(port: u16) -> Result<Ouverture, String> {
    let locale = ip_locale();
    let candidates = passerelles_candidates(locale);
    if candidates.is_empty() {
        return Err("aucune passerelle candidate".into());
    }
    let mut derniere = String::from("aucune reponse");
    for gw in candidates {
        let externe = match natpmp_requete_adresse(gw) {
            Ok(ip) => ip,
            Err(e) => {
                derniere = format!("{gw} : {e}");
                continue;
            }
        };
        let (port_externe, bail) = natpmp_requete_mappage(gw, port, port, BAIL_SECONDES)
            .map_err(|e| format!("{gw} : {e}"))?;
        return Ok(Ouverture {
            methode: Methode::NatPmp,
            adresse_externe: externe,
            port_externe,
            bail_secondes: bail,
            controle: None,
            passerelle: Some(gw),
        });
    }
    Err(derniere)
}

/// Requete « adresse externe » : deux octets, reponse de douze.
fn natpmp_requete_adresse(gw: Ipv4Addr) -> Result<Ipv4Addr, String> {
    let reponse = natpmp_echange(gw, &[0u8, 0u8], 12)?;
    natpmp_decoder_adresse(&reponse)
}

/// Requete de mappage TCP. Rend (port externe accorde, bail accorde).
fn natpmp_requete_mappage(
    gw: Ipv4Addr,
    port_interne: u16,
    port_externe_souhaite: u16,
    bail: u32,
) -> Result<(u16, u32), String> {
    let mut req = [0u8; 12];
    req[1] = 2; // opcode 2 = TCP
    req[4..6].copy_from_slice(&port_interne.to_be_bytes());
    req[6..8].copy_from_slice(&port_externe_souhaite.to_be_bytes());
    req[8..12].copy_from_slice(&bail.to_be_bytes());
    let reponse = natpmp_echange(gw, &req, 16)?;
    natpmp_decoder_mappage(&reponse, port_interne)
}

/// Envoie `req` et attend une reponse d'au moins `min` octets, avec les
/// retransmissions de la RFC (250 ms, 500 ms, 1 s). Trois essais : assez pour
/// une box presente, court pour une box absente.
fn natpmp_echange(gw: Ipv4Addr, req: &[u8], min: usize) -> Result<Vec<u8>, String> {
    let s = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    s.connect(SocketAddrV4::new(gw, PORT_NATPMP))
        .map_err(|e| e.to_string())?;
    let mut attente = Duration::from_millis(250);
    for _ in 0..3 {
        s.send(req).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(attente))
            .map_err(|e| e.to_string())?;
        let mut buf = [0u8; 64];
        match s.recv(&mut buf) {
            Ok(n) if n >= min => return Ok(buf[..n].to_vec()),
            Ok(_) => return Err("reponse trop courte".into()),
            Err(_) => attente *= 2,
        }
    }
    Err("pas de reponse NAT-PMP".into())
}

fn natpmp_code(code: u16) -> String {
    match code {
        0 => "succes".into(),
        1 => "version non prise en charge".into(),
        2 => "refuse par la box (NAT-PMP desactive ?)".into(),
        3 => "la box n'a pas d'adresse externe (pas de connexion ?)".into(),
        4 => "la box n'a plus de place".into(),
        5 => "operation non prise en charge".into(),
        n => format!("code {n}"),
    }
}

fn natpmp_decoder_adresse(r: &[u8]) -> Result<Ipv4Addr, String> {
    if r.len() < 12 {
        return Err("reponse trop courte".into());
    }
    if r[0] != 0 || r[1] != 128 {
        return Err("reponse inattendue".into());
    }
    let code = u16::from_be_bytes([r[2], r[3]]);
    if code != 0 {
        return Err(natpmp_code(code));
    }
    Ok(Ipv4Addr::new(r[8], r[9], r[10], r[11]))
}

fn natpmp_decoder_mappage(r: &[u8], port_interne: u16) -> Result<(u16, u32), String> {
    if r.len() < 16 {
        return Err("reponse trop courte".into());
    }
    if r[0] != 0 || r[1] != 130 {
        return Err("reponse inattendue".into());
    }
    let code = u16::from_be_bytes([r[2], r[3]]);
    if code != 0 {
        return Err(natpmp_code(code));
    }
    let interne = u16::from_be_bytes([r[8], r[9]]);
    if interne != port_interne {
        return Err("la box repond pour un autre port".into());
    }
    let externe = u16::from_be_bytes([r[10], r[11]]);
    let bail = u32::from_be_bytes([r[12], r[13], r[14], r[15]]);
    Ok((externe, bail))
}

// ---------------------------------------------------------------------------
// UPnP IGD : decouverte SSDP, description, SOAP
// ---------------------------------------------------------------------------

fn upnp_ouvrir(port: u16) -> Result<Ouverture, String> {
    let locale = ip_locale().ok_or("adresse locale introuvable")?;
    let location = ssdp_decouvrir().ok_or("aucune box UPnP ne repond")?;
    // La description vient obligatoirement d'une adresse privee : une box est
    // sur le reseau local. Une URL vers une adresse publique serait un appareil
    // qui nous envoie ailleurs — on refuse.
    let (hote, _port, _chemin) = decouper_url(&location).ok_or("URL de description invalide")?;
    let ip_desc: Ipv4Addr = hote
        .parse()
        .map_err(|_| "hote de description non numerique")?;
    if adresse_publique(ip_desc) {
        return Err("la description UPnP vient d'une adresse publique : refuse".into());
    }
    let corps = http_get(&location)?;
    let (controle, service) = upnp_extraire_controle(&corps, &location)
        .ok_or("service WANIPConnection introuvable dans la description")?;

    // Certaines box n'acceptent que des baux permanents (erreur 725) : on
    // retombe alors sur zero.
    let mut bail = BAIL_SECONDES;
    let mut derniere = String::new();
    for essai in 0..2 {
        let args = format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort>\
             <NewProtocol>TCP</NewProtocol><NewInternalPort>{port}</NewInternalPort>\
             <NewInternalClient>{locale}</NewInternalClient><NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>Q21</NewPortMappingDescription>\
             <NewLeaseDuration>{bail}</NewLeaseDuration>"
        );
        match upnp_soap(&controle, &service, "AddPortMapping", &args) {
            Ok(_) => break,
            Err(e) => {
                derniere = e;
                if essai == 0 && derniere.contains("725") {
                    bail = 0;
                    continue;
                }
                return Err(format!("AddPortMapping : {derniere}"));
            }
        }
    }
    let _ = derniere;
    let rep = upnp_soap(&controle, &service, "GetExternalIPAddress", "")?;
    let externe = extraire_balise(&rep, "NewExternalIPAddress")
        .and_then(|s| s.trim().parse::<Ipv4Addr>().ok())
        .ok_or("adresse externe absente de la reponse UPnP")?;
    Ok(Ouverture {
        methode: Methode::Upnp,
        adresse_externe: externe,
        port_externe: port,
        bail_secondes: bail,
        controle: Some((controle, service)),
        passerelle: None,
    })
}

/// Decouverte SSDP : une question en multidiffusion, la premiere reponse qui
/// annonce une passerelle. Rend l'URL de description (en-tete `LOCATION`).
fn ssdp_decouvrir() -> Option<String> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.set_multicast_ttl_v4(2).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(2500))).ok()?;
    for st in [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    ] {
        let req = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_ADRESSE}:{SSDP_PORT}\r\nMAN: \"ssdp:discover\"\r\n\
             MX: 2\r\nST: {st}\r\n\r\n"
        );
        let _ = s.send_to(req.as_bytes(), SocketAddrV4::new(SSDP_ADRESSE, SSDP_PORT));
    }
    let mut buf = [0u8; 2048];
    // Plusieurs appareils peuvent repondre : on prend la premiere reponse qui
    // porte un LOCATION, sans attendre les autres au-dela du delai.
    for _ in 0..8 {
        match s.recv_from(&mut buf) {
            Ok((n, _)) => {
                let texte = String::from_utf8_lossy(&buf[..n]);
                if let Some(loc) = ssdp_extraire_location(&texte) {
                    return Some(loc);
                }
            }
            Err(_) => break,
        }
    }
    None
}

/// L'en-tete `LOCATION` d'une reponse SSDP, insensible a la casse du nom.
fn ssdp_extraire_location(reponse: &str) -> Option<String> {
    for ligne in reponse.lines() {
        if let Some((nom, valeur)) = ligne.split_once(':') {
            if nom.trim().eq_ignore_ascii_case("location") {
                let v = valeur.trim();
                if v.starts_with("http://") {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Dans la description XML, le service de connexion WAN et son URL de controle.
///
/// Prefere `WANIPConnection:2`, puis `:1`, puis `WANPPPConnection:1`. Une URL de
/// controle relative est resolue contre `URLBase` si present, sinon contre
/// l'origine de la description. Pas d'analyseur XML : on cherche les balises,
/// ce qui suffit a un document dont on ne lit que deux champs.
fn upnp_extraire_controle(xml: &str, location: &str) -> Option<(String, String)> {
    let base = extraire_balise(xml, "URLBase")
        .map(|b| b.trim().trim_end_matches('/').to_string())
        .filter(|b| b.starts_with("http://"))
        .or_else(|| origine_url(location))?;
    let preferes = [
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    ];
    for voulu in preferes {
        let mut reste = xml;
        while let Some(debut) = reste.find("<service>") {
            let apres = &reste[debut..];
            let fin = match apres.find("</service>") {
                Some(f) => f,
                None => break,
            };
            let bloc = &apres[..fin];
            if extraire_balise(bloc, "serviceType").map(|s| s.trim() == voulu) == Some(true) {
                if let Some(url) = extraire_balise(bloc, "controlURL") {
                    let url = url.trim();
                    let complete = if url.starts_with("http://") {
                        url.to_string()
                    } else if url.starts_with('/') {
                        format!("{base}{url}")
                    } else {
                        format!("{base}/{url}")
                    };
                    return Some((complete, voulu.to_string()));
                }
            }
            reste = &apres[fin + "</service>".len()..];
        }
    }
    None
}

/// Le contenu de la premiere balise `<nom>...</nom>`.
fn extraire_balise(texte: &str, nom: &str) -> Option<String> {
    let ouvre = format!("<{nom}>");
    let ferme = format!("</{nom}>");
    let d = texte.find(&ouvre)? + ouvre.len();
    let f = texte[d..].find(&ferme)? + d;
    Some(texte[d..f].to_string())
}

/// Envoie une action SOAP a l'URL de controle. Rend le corps de la reponse, ou
/// une erreur qui contient le code de faute UPnP quand il y en a un.
fn upnp_soap(url: &str, service: &str, action: &str, args: &str) -> Result<String, String> {
    let corps = format!(
        "<?xml version=\"1.0\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{action} xmlns:u=\"{service}\">{args}</u:{action}></s:Body></s:Envelope>"
    );
    let (hote, port, chemin) = decouper_url(url).ok_or("URL de controle invalide")?;
    let entete = format!(
        "POST {chemin} HTTP/1.1\r\nHOST: {hote}:{port}\r\n\
         CONTENT-TYPE: text/xml; charset=\"utf-8\"\r\n\
         SOAPACTION: \"{service}#{action}\"\r\nCONTENT-LENGTH: {}\r\nCONNECTION: close\r\n\r\n",
        corps.len()
    );
    let mut requete = entete.into_bytes();
    requete.extend_from_slice(corps.as_bytes());
    let (statut, reponse) = http_echange(&hote, port, &requete)?;
    if statut == 200 {
        return Ok(reponse);
    }
    // Une faute SOAP porte un code UPnP dans <errorCode>. On le remonte pour
    // que l'appelant reconnaisse le 725 « baux permanents seulement ».
    if let Some(code) = extraire_balise(&reponse, "errorCode") {
        return Err(format!("erreur UPnP {} (HTTP {statut})", code.trim()));
    }
    Err(format!("HTTP {statut}"))
}

/// Recupere un document par HTTP GET, en bornant sa taille.
fn http_get(url: &str) -> Result<String, String> {
    let (hote, port, chemin) = decouper_url(url).ok_or("URL invalide")?;
    let requete =
        format!("GET {chemin} HTTP/1.1\r\nHOST: {hote}:{port}\r\nCONNECTION: close\r\n\r\n");
    let (statut, corps) = http_echange(&hote, port, requete.as_bytes())?;
    if statut != 200 {
        return Err(format!("HTTP {statut}"));
    }
    Ok(corps)
}

/// Un aller-retour HTTP brut vers un appareil du reseau local. Rend (statut,
/// corps). Delais fixes, corps borne : on ne fait jamais confiance a la taille
/// annoncee, on plafonne la lecture reelle.
fn http_echange(hote: &str, port: u16, requete: &[u8]) -> Result<(u16, String), String> {
    let flux = TcpStream::connect_timeout(
        &SocketAddrV4::new(hote.parse().map_err(|_| "hote non numerique")?, port).into(),
        DELAI_HTTP,
    )
    .map_err(|e| e.to_string())?;
    flux.set_read_timeout(Some(DELAI_HTTP)).ok();
    flux.set_write_timeout(Some(DELAI_HTTP)).ok();
    let mut flux = flux;
    flux.write_all(requete).map_err(|e| e.to_string())?;

    let mut brut = Vec::new();
    let mut tampon = [0u8; 4096];
    loop {
        match flux.read(&mut tampon) {
            Ok(0) => break,
            Ok(n) => {
                brut.extend_from_slice(&tampon[..n]);
                if brut.len() > MAX_REPONSE_HTTP {
                    brut.truncate(MAX_REPONSE_HTTP);
                    break;
                }
            }
            Err(_) => break,
        }
    }
    decouper_reponse_http(&brut)
}

/// Separe le statut et le corps d'une reponse HTTP. `\r\n\r\n` marque la fin des
/// en-tetes ; on n'interprete pas les en-tetes, seulement le code de statut.
fn decouper_reponse_http(brut: &[u8]) -> Result<(u16, String), String> {
    let texte = String::from_utf8_lossy(brut);
    let premiere = texte.lines().next().ok_or("reponse vide")?;
    // « HTTP/1.1 200 OK » : le code est le deuxieme mot.
    let statut = premiere
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("ligne de statut illisible")?;
    let corps = match texte.find("\r\n\r\n") {
        Some(i) => texte[i + 4..].to_string(),
        None => String::new(),
    };
    Ok((statut, corps))
}

/// Decoupe une URL `http://hote:port/chemin` en ses trois morceaux. Le port
/// vaut 80 par defaut, le chemin `/` par defaut.
fn decouper_url(url: &str) -> Option<(String, u16, String)> {
    let reste = url.strip_prefix("http://")?;
    let (autorite, chemin) = match reste.find('/') {
        Some(i) => (&reste[..i], &reste[i..]),
        None => (reste, "/"),
    };
    let (hote, port) = match autorite.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (autorite.to_string(), 80u16),
    };
    if hote.is_empty() {
        return None;
    }
    Some((hote, port, chemin.to_string()))
}

/// L'origine `http://hote:port` d'une URL, sans le chemin.
fn origine_url(url: &str) -> Option<String> {
    let (hote, port, _) = decouper_url(url)?;
    Some(format!("http://{hote}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn une_adresse_privee_ou_cgnat_n_est_pas_publique() {
        for ip in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 4, 5),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1), // CGNAT
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(240, 0, 0, 1),
        ] {
            assert!(!adresse_publique(ip), "{ip} ne doit pas etre publique");
        }
    }

    #[test]
    fn une_vraie_adresse_publique_est_reconnue() {
        for ip in [
            Ipv4Addr::new(92, 222, 86, 135), // le portier OVH
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(203, 0, 113, 7),
        ] {
            assert!(adresse_publique(ip), "{ip} doit etre publique");
        }
    }

    #[test]
    fn la_passerelle_se_lit_dans_la_table_de_routage() {
        // Ligne de route par defaut : destination 00000000, passerelle
        // 0101A8C0 = 192.168.1.1 en petit-boutiste.
        let table = "Iface\tDestination\tGateway\tFlags\n\
                     eth0\t00000000\t0101A8C0\t0003\n\
                     eth0\t0001A8C0\t00000000\t0001\n";
        assert_eq!(
            passerelle_depuis_table_de_routage(table),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn sans_route_par_defaut_pas_de_passerelle() {
        let table = "Iface\tDestination\tGateway\tFlags\n\
                     eth0\t0001A8C0\t00000000\t0001\n";
        assert_eq!(passerelle_depuis_table_de_routage(table), None);
    }

    #[test]
    fn les_candidates_couvrent_1_et_254_du_reseau_local() {
        let c = passerelles_candidates(Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert!(c.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(c.contains(&Ipv4Addr::new(192, 168, 1, 254)));
    }

    #[test]
    fn le_mappage_natpmp_se_decode() {
        // Reponse de mappage : version 0, op 130, code 0, port interne 21121,
        // port externe 21121, bail 7200.
        let mut r = [0u8; 16];
        r[1] = 130;
        r[8..10].copy_from_slice(&21121u16.to_be_bytes());
        r[10..12].copy_from_slice(&21121u16.to_be_bytes());
        r[12..16].copy_from_slice(&7200u32.to_be_bytes());
        assert_eq!(natpmp_decoder_mappage(&r, 21121), Ok((21121, 7200)));
    }

    #[test]
    fn un_code_d_erreur_natpmp_est_remonte() {
        let mut r = [0u8; 16];
        r[1] = 130;
        r[2..4].copy_from_slice(&2u16.to_be_bytes()); // refuse
        assert!(natpmp_decoder_mappage(&r, 21121).is_err());
    }

    #[test]
    fn l_adresse_externe_natpmp_se_decode() {
        let mut r = [0u8; 12];
        r[1] = 128;
        r[8..12].copy_from_slice(&[92, 222, 86, 135]);
        assert_eq!(
            natpmp_decoder_adresse(&r),
            Ok(Ipv4Addr::new(92, 222, 86, 135))
        );
    }

    #[test]
    fn le_location_ssdp_se_lit_quelle_que_soit_la_casse() {
        let rep = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n\
                   Location: http://192.168.1.1:5000/desc.xml\r\nST: upnp:rootdevice\r\n\r\n";
        assert_eq!(
            ssdp_extraire_location(rep).as_deref(),
            Some("http://192.168.1.1:5000/desc.xml")
        );
    }

    #[test]
    fn une_url_se_decoupe() {
        assert_eq!(
            decouper_url("http://192.168.1.1:5000/ctl/IPConn"),
            Some(("192.168.1.1".into(), 5000, "/ctl/IPConn".into()))
        );
        assert_eq!(
            decouper_url("http://10.0.0.1/desc"),
            Some(("10.0.0.1".into(), 80, "/desc".into()))
        );
        assert_eq!(decouper_url("ftp://x/y"), None);
    }

    #[test]
    fn le_service_de_controle_se_trouve_dans_la_description() {
        let xml = "<root><URLBase>http://192.168.1.1:5000/</URLBase><device><serviceList>\
            <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
            <controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>";
        let (url, service) =
            upnp_extraire_controle(xml, "http://192.168.1.1:5000/desc.xml").unwrap();
        assert_eq!(url, "http://192.168.1.1:5000/ctl/IPConn");
        assert_eq!(service, "urn:schemas-upnp-org:service:WANIPConnection:1");
    }

    #[test]
    fn le_statut_http_et_le_corps_se_separent() {
        let brut =
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/xml\r\n\r\n<e>725</e>";
        let (statut, corps) = decouper_reponse_http(brut).unwrap();
        assert_eq!(statut, 500);
        assert_eq!(corps, "<e>725</e>");
    }
}
