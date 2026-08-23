//! Amorcage : par ou l'on entre dans un reseau.
//!
//! # Le probleme
//!
//! Un noeud qui vient de naitre ne connait personne. Il a la genese — elle est
//! deterministe, il l'a calculee lui-meme — mais aucune adresse ou frapper.
//!
//! Ce module rassemble les trois facons d'en obtenir une, et le peu de code
//! qu'elles demandent : le port par defaut de chaque reseau, la liste integree
//! au binaire, le fichier de l'exploitant, et la resolution des noms.
//!
//! # Ce que l'amorcage ne decide pas
//!
//! Il decide **a qui vous parlez en premier**, pas ce que vous croyez. Un pair,
//! quel qu'il soit, ne peut vous faire accepter que des blocs valides
//! prolongeant votre propre genese et portant la preuve de travail. Il peut
//! vous cacher des choses ; il ne peut pas vous en inventer.
//!
//! La defense contre le fait d'etre isole — l'eclipse — n'est pas la confiance
//! dans l'amorcage : c'est le carnet, ses seaux par groupe reseau /16 et son
//! sel propre a chaque noeud. Voir `net::addr`.

use crate::address::Network;
use std::path::Path;

/// Port P2P par defaut de chaque reseau.
///
/// Un port fixe par reseau evite d'avoir a l'ecrire dans chaque marche a
/// suivre, et rend une adresse d'amorcage recopiable telle quelle. Les trois
/// sont distincts : brancher par erreur un noeud d'essai sur le port du reseau
/// principal doit echouer par « connexion refusee », pas par une poignee de
/// main qui part et se fait bannir.
pub fn port_par_defaut(n: Network) -> u16 {
    match n {
        Network::Mainnet => 21021,
        Network::Testnet => 21121,
        Network::Regtest => 21221,
    }
}

/// Noeuds d'amorcage integres au binaire, par reseau.
///
/// # Pourquoi des noms et pas des adresses
///
/// Une adresse IP change : le serveur est remplace, l'hebergeur reattribue, le
/// fournisseur renumerote. Un binaire distribue ne se met pas a jour pour
/// autant, et un reseau dont les points d'entree sont morts est un reseau que
/// personne ne peut plus rejoindre.
///
/// Un nom se repointe en une minute, sans rien redistribuer.
///
/// # Ce que cela ne donne pas comme pouvoir
///
/// Celui qui tient ces noms decide **a qui vous parlez en premier**, pas ce que
/// vous croyez. Un pair, quel qu'il soit, ne peut vous faire accepter que des
/// blocs valides prolongeant la genese que vous avez ecrite vous-meme, et
/// portant la preuve de travail. Il peut vous cacher des choses ; il ne peut
/// pas vous en inventer.
///
/// La defense contre le fait d'etre isole — l'eclipse — n'est pas la confiance
/// dans l'amorcage, c'est le carnet : voir `net::addr`, ses seaux par groupe
/// /16 et son sel propre a chaque noeud.
///
/// La liste est vide tant que le reseau d'essai n'est pas ouvert. Annoncer des
/// noms qui ne repondent pas serait pire que rien : chaque demarrage attendrait
/// une reponse qui ne vient pas.
pub fn amorces_integrees(n: Network) -> &'static [&'static str] {
    match n {
        Network::Mainnet => &[],
        Network::Testnet => &[],
        Network::Regtest => &[],
    }
}

/// Amorces lues dans le dossier de donnees, une par ligne.
///
/// C'est ce qui permet d'ouvrir un reseau sans rien recompiler : l'exploitant
/// depose `amorces.txt`, chacun y ajoute ce qu'il veut. Les lignes vides et
/// celles commencant par `#` sont ignorees.
pub fn amorces_du_dossier(datadir: &Path) -> Vec<String> {
    let chemin = datadir.join("amorces.txt");
    let Ok(contenu) = std::fs::read_to_string(&chemin) else {
        return Vec::new();
    };
    contenu
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// Resout `hote:port`, ou `hote` seul avec le port par defaut du reseau.
///
/// # Le defaut que cela repare
///
/// Le noeud faisait `"1.2.3.4:5678".parse::<SocketAddr>()`, qui n'accepte
/// qu'une adresse litterale. Un nom — le seul point d'entree durable d'un
/// reseau public — donnait « adresse illisible » sans autre explication.
///
/// Un nom peut rendre plusieurs adresses ; on les prend toutes. C'est ce qui
/// fait qu'un point d'amorcage peut etre redonde derriere un seul nom.
pub fn resoudre(cible: &str, reseau: Network) -> Result<Vec<std::net::SocketAddr>, String> {
    use std::net::ToSocketAddrs;
    // Une adresse IPv6 litterale porte ses crochets : `[::1]:21121`. Sans eux,
    // les deux-points de l'adresse se confondent avec celui du port.
    let avec_port = if cible.contains(':') && !cible.ends_with(']') {
        cible.to_string()
    } else {
        format!("{cible}:{}", port_par_defaut(reseau))
    };
    let adresses: Vec<_> = avec_port
        .to_socket_addrs()
        .map_err(|e| format!("{cible} : {e}"))?
        .collect();
    if adresses.is_empty() {
        return Err(format!("{cible} : aucune adresse"));
    }
    Ok(adresses)
}

/// Interprete `--listen` : un numero de port seul, ou une adresse complete.
///
/// `--listen 21121` ecoute sur toutes les interfaces, ce qu'un noeud public
/// veut ; `--listen 127.0.0.1:21121` reste chez soi. Ecrire le premier est bien
/// plus court que `0.0.0.0:21121`, et c'est ce qu'on tape le plus souvent sur
/// un serveur.
pub fn adresse_d_ecoute(brut: &str, reseau: Network) -> String {
    // Le vide se traite en premier. `"".chars().all(...)` rend **vrai** — un
    // ensemble vide satisfait tout — et l'ordre inverse produisait donc
    // `0.0.0.0:`, une adresse sans port que le systeme refuse. C'est l'epreuve
    // de ce module qui l'a trouve, pas la relecture.
    if brut.is_empty() {
        format!("0.0.0.0:{}", port_par_defaut(reseau))
    } else if brut.chars().all(|c| c.is_ascii_digit()) {
        format!("0.0.0.0:{brut}")
    } else {
        brut.to_string()
    }
}

/// Lit une liste d'amorces. Les lignes vides et les commentaires sont ignores.
///
/// Separee de la lecture du fichier pour pouvoir etre eprouvee : le format est
/// ce que l'exploitant tape a la main, donc l'endroit ou une tolerance mal
/// placee se paie.
pub fn lire_amorces(contenu: &str) -> Vec<String> {
    contenu
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trois reseaux, trois ports. Les confondre doit echouer par « connexion
    /// refusee », pas par une poignee de main qui part et se fait bannir.
    #[test]
    fn les_trois_reseaux_ont_des_ports_distincts() {
        let p = [
            port_par_defaut(Network::Mainnet),
            port_par_defaut(Network::Testnet),
            port_par_defaut(Network::Regtest),
        ];
        assert_eq!(p.len(), 3);
        assert_ne!(p[0], p[1]);
        assert_ne!(p[1], p[2]);
        assert_ne!(p[0], p[2]);
        // Hors des plages reservees et des ports privilegies.
        for x in p {
            assert!(x > 1024, "port privilegie : {x}");
        }
    }

    /// `--listen 21121` ecoute partout ; une adresse complete est respectee.
    ///
    /// C'est ce qu'on tape sur un serveur, et la forme courte doit faire ce
    /// qu'on attend d'elle — sans quoi on ecrit `0.0.0.0:` a la main, et un
    /// jour on l'oublie.
    #[test]
    fn un_numero_de_port_seul_ecoute_partout() {
        assert_eq!(adresse_d_ecoute("21121", Network::Testnet), "0.0.0.0:21121");
        assert_eq!(
            adresse_d_ecoute("127.0.0.1:9", Network::Testnet),
            "127.0.0.1:9"
        );
        assert_eq!(
            adresse_d_ecoute("", Network::Testnet),
            format!("0.0.0.0:{}", port_par_defaut(Network::Testnet))
        );
    }

    /// Un nom sans port prend celui du reseau.
    #[test]
    fn un_nom_sans_port_prend_celui_du_reseau() {
        let a = resoudre("localhost", Network::Testnet).expect("localhost doit se resoudre");
        assert!(!a.is_empty());
        assert!(a
            .iter()
            .all(|s| s.port() == port_par_defaut(Network::Testnet)));
    }

    /// Un port explicite l'emporte.
    #[test]
    fn un_port_explicite_l_emporte() {
        let a = resoudre("127.0.0.1:12345", Network::Testnet).expect("adresse litterale");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].port(), 12345);
    }

    /// Une adresse IPv6 litterale garde ses crochets, et son port.
    ///
    /// Sans traitement particulier, les deux-points de l'adresse se confondent
    /// avec celui du port : `::1` deviendrait un nom d'hote suivi du port `1`.
    #[test]
    fn une_adresse_ipv6_ne_se_confond_pas_avec_un_port() {
        let a = resoudre("[::1]:12345", Network::Testnet).expect("IPv6 litterale");
        assert_eq!(a[0].port(), 12345);
        assert!(a[0].is_ipv6());
    }

    /// Un nom qui n'existe pas rend une erreur lisible, pas une panique.
    #[test]
    fn un_nom_introuvable_rend_une_erreur() {
        let r = resoudre("q21-ce-nom-n-existe-pas.invalid", Network::Testnet);
        assert!(r.is_err());
        let m = r.unwrap_err();
        assert!(
            m.contains("q21-ce-nom-n-existe-pas.invalid"),
            "l'erreur doit nommer ce qui a echoue : {m}"
        );
    }

    /// Le format du fichier d'amorces.
    #[test]
    fn les_commentaires_et_les_vides_sont_ignores() {
        let v = lire_amorces(
            "# les amorces du reseau d'essai\n\
             \n   \n\
             amorce1.exemple.fr\n\
             \t amorce2.exemple.fr:21121 \n\
             # une ligne mise de cote\n",
        );
        assert_eq!(v, vec!["amorce1.exemple.fr", "amorce2.exemple.fr:21121"]);
    }

    /// La liste integree est vide tant que le reseau n'est pas ouvert.
    ///
    /// Annoncer des noms qui ne repondent pas serait pire que rien : chaque
    /// demarrage attendrait une reponse qui ne vient jamais. Cette epreuve
    /// tombera le jour ou l'on ouvrira le reseau — c'est voulu, elle rappellera
    /// qu'il faut alors verifier que les noms repondent vraiment.
    #[test]
    fn aucune_amorce_n_est_annoncee_avant_l_ouverture() {
        for r in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert!(
                amorces_integrees(r).is_empty(),
                "des amorces sont annoncees pour {r:?} : verifiez qu'elles repondent"
            );
        }
    }
}
