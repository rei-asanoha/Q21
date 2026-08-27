//! `q21` — noeud et portefeuille en ligne de commande.
//!
//! Noeud local mono-machine : pas encore de reseau pair-a-pair, ce sera la
//! phase 4. On peut deja initialiser une chaine, miner, consulter un solde,
//! envoyer des fonds et inspecter les blocs.

use q21_core::addr::AddrStore;
use q21_core::address::{Address, Network};
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain};
use q21_core::consensus::*;
use q21_core::emission;
use q21_core::pow;
use q21_core::sig::SchemeId;
use q21_core::state::{AddressCache, StateStore};
use q21_core::store::BlockArchive;
use q21_core::tx::Transaction;
use q21_core::wallet::Wallet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const AIDE: &str = "\
q21 — noeud et portefeuille du protocole Q21 (phase 2)

USAGE
    q21 [--datadir <chemin>] [--phrase-fichier <chemin>] <commande> [arguments]

COMMANDES
    init [regtest|testnet] [lamport|mldsa65|mldsa87]
                            Cree une chaine et un portefeuille
                            (schema par defaut : mldsa87 si compile, sinon lamport)
    restore <code> [reseau] [schema]
                            Restaure un portefeuille depuis son code de
                            sauvegarde Bech32m
    info                     Etat de la chaine
    address                  Produit une adresse de reception neuve
    balance                  Solde depensable du portefeuille
    mine [n]                 Mine n blocs (defaut : 1)
    send <adresse> <montant> Envoie des fonds (le montant est en Q21)
    block <hauteur>          Detaille un bloc
    utxo                     Resume du jeu de sorties non depensees
    emission [annee]         Courbe d'emission theorique
    wallet [options]         Ouvre le portefeuille dans le navigateur
                             --port <n>           port d'ecoute (defaut : libre)
                             --sans-navigateur    n'ouvre pas le navigateur,
                                                  affiche l'adresse
    node [options]           Lance un noeud reseau
                             --reseau <nom>       testnet ou regtest. Permet de
                                                  demarrer SANS portefeuille :
                                                  la genese est ecrite seule et
                                                  aucune clef n'est gardee
                             --listen <port>      accepte les connexions. Un
                                                  numero seul ecoute partout ;
                                                  une adresse complete cible une
                                                  interface
                             --amorce <hote>      point d'entree. Un nom suffit,
                                                  le port du reseau est pris par
                                                  defaut. Repetable
                             --sans-amorces       n'employer que ce que la ligne
                                                  de commande donne
                             --connect <ip:port>  synonyme d'--amorce
                             --index-adresses     index de recherche (voir
                                                  EXPLORATEUR.md)
                             --mine               mine en continu
                             --rpc <ip:port>      API JSON-RPC + explorateur web
                             --rpc-token <jeton>  exige un jeton (obligatoire
                                                  hors bouclage local)
                             --rpc-wallet         active les methodes de
                                                  portefeuille (elles peuvent
                                                  deplacer des fonds)
                             --seconds <n>        s'arrete apres n secondes
                             --fils <n>           fils de minage (defaut : tous
                                                  les coeurs)
                             --pairs <n>          connexions sortantes visees
                                                  (defaut : 8, toutes de groupes
                                                  reseau distincts)
    pow [regtest|testnet|mainnet]
                            Banc de mesure de la preuve de travail.
                            `mainnet` construit la vraie table de 2 Gio et
                            trace la courbe du compromis temps-memoire.
    explorateur              Explorateur de chaine dans le navigateur.
                            Recherche par hauteur, bloc, transaction ou adresse.
                            L'index d'adresses est actif : la recherche
                            d'adresse est alors complete, et non bornee.
                            --sans-index         s'en passer
                            --port <n>           imposer le port
                            --sans-navigateur    ne rien ouvrir
    genese [reseau]          Identifiant du bloc de genese, et le port du reseau.
                            A verifier avant de rejoindre : deux noeuds qui n'ont
                            pas la meme genese ne sont pas sur la meme chaine.
    securite                 Ce qui est protege, et ce qui ne l'est pas
    help                     Cette aide

EXEMPLE
    q21 init regtest
    q21 mine 205

    # rejoindre un reseau d'essai, sans portefeuille
    q21 genese testnet
    q21 --datadir n node --reseau testnet --amorce amorce.exemple.fr

    # deux noeuds qui se synchronisent, dans deux terminaux
    q21 --datadir a node --listen 127.0.0.1:21021 --mine
    q21 --datadir b node --connect 127.0.0.1:21021

    # explorateur local, dans un navigateur : http://127.0.0.1:21080
    q21 --datadir a node --rpc 127.0.0.1:21080 --mine
    q21 balance
    q21 address
    q21 send rq21... 1.5

AVERTISSEMENT
    Code de recherche, non audite. La preuve de travail est memory-hard mais
    n'a recu aucune cryptanalyse externe. Les signatures ML-DSA reposent sur le
    crate `ml-dsa` de RustCrypto, lui-meme non audite formellement.
    Lancez `q21 securite` pour ce qui est protege et ce qui ne l'est pas.
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut datadir = PathBuf::from("q21-data");
    let mut reste: Vec<String> = Vec::new();

    let mut phrase_option: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--datadir" && i + 1 < args.len() {
            datadir = PathBuf::from(&args[i + 1]);
            i += 2;
        } else if args[i] == "--phrase-fichier" && i + 1 < args.len() {
            phrase_option = Some(args[i + 1].clone());
            i += 2;
        } else {
            reste.push(args[i].clone());
            i += 1;
        }
    }

    // Une phrase fournie par fichier ou par variable d'environnement vaut pour
    // toute la commande.
    //
    // La variable etait consultee trop tard : le controle de terminal ajoute
    // pour ne plus creer de portefeuille sans protection s'executait avant
    // elle, et refusait alors une commande parfaitement legitime — celle qu'on
    // emploie precisement quand il n'y a pas de terminal.
    match phrase_secrete(phrase_option.as_deref(), false) {
        Ok(Some(p)) => retenir_phrase(Some(p)),
        Ok(None) => {}
        Err(e) => {
            eprintln!("erreur : {e}");
            std::process::exit(1);
        }
    }

    // --- Le double-clic qui n'ouvrait rien.
    //
    // Lance sans argument, ce programme affichait son aide et rendait la main.
    // Sous Windows, un double-clic ouvre alors une fenetre qui se referme dans
    // la demi-seconde : rien n'est lisible, et l'utilisateur conclut — a juste
    // titre — que le logiciel ne fonctionne pas. C'est arrive au premier a
    // l'essayer, apres avoir suivi la procedure jusqu'au bout.
    //
    // Un programme lance depuis un terminal a recu une commande ; un programme
    // double-clique n'en a aucune. La distinction est donc nette, et la reponse
    // evidente : sans argument, c'est le portefeuille qu'on veut.
    //
    // Le repli reste l'aide, mais suivie d'une pause : une fenetre qui se
    // referme avant qu'on ait pu lire n'a jamais rien appris a personne.
    // --- Un seul q21 a la fois sur un dossier de donnees.
    //
    // Rien ne l'empechait, et le cas est banal : le portefeuille tourne dans sa
    // fenetre, on lance `q21 mine` dans une autre pour confirmer une
    // transaction. Deux processus ecrivent alors le meme `wallet.dat`, le meme
    // `blocks.dat` et le meme `wallet.seq`. Le portefeuille en ressort avec un
    // numero de serie incoherent, et refuse de s'ouvrir au demarrage suivant en
    // annoncant une restauration depuis une sauvegarde ancienne.
    //
    // Les commandes qui ne touchent pas au repertoire — l'aide, la courbe
    // d'emission, la note de securite — ne le verrouillent pas : refuser
    // `q21 help` parce qu'un portefeuille tourne serait absurde.
    let commande_lue = reste.first().map(|s| s.as_str()).unwrap_or("help");
    let sans_repertoire = matches!(
        commande_lue,
        "emission" | "securite" | "genese" | "genesis" | "help" | "--help" | "-h"
    );
    let _verrou = if sans_repertoire {
        None
    } else {
        match q21_core::verrou::prendre(&datadir) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("erreur : {e}");
                if q21_core::prompt::entree_interactive() {
                    println!();
                    println!("  Appuyez sur Entree pour fermer.");
                    let mut _l = String::new();
                    let _ = std::io::stdin().read_line(&mut _l);
                }
                std::process::exit(1);
            }
        }
    };

    let sans_argument = reste.is_empty();
    if sans_argument {
        println!("Q21 — portefeuille");
        println!();
        println!("  Lance sans commande : ouverture du portefeuille.");
        println!("  Pour la liste des commandes : q21 help");
        println!();
        let r = cmd_wallet(&datadir, &[]);
        if let Err(e) = r {
            eprintln!("erreur : {e}");
            if q21_core::prompt::entree_interactive() {
                println!();
                println!("  Appuyez sur Entree pour fermer.");
                let mut _l = String::new();
                let _ = std::io::stdin().read_line(&mut _l);
            }
            std::process::exit(1);
        }
        return;
    }

    let commande = reste.first().map(|s| s.as_str()).unwrap_or("help");
    let r = match commande {
        "init" => cmd_init(
            &datadir,
            reste.get(1).map(|s| s.as_str()),
            reste.get(2).map(|s| s.as_str()),
            phrase_option.as_deref(),
        ),
        "restore" => cmd_restore(
            &datadir,
            reste.get(1).map(|s| s.as_str()),
            reste.get(2).map(|s| s.as_str()),
            reste.get(3).map(|s| s.as_str()),
            phrase_option.as_deref(),
        ),
        "info" => cmd_info(&datadir),
        "address" => cmd_address(&datadir),
        "balance" => cmd_balance(&datadir),
        "mine" => cmd_mine(&datadir, reste.get(1).map(|s| s.as_str())),
        "send" => cmd_send(&datadir, reste.get(1), reste.get(2)),
        "block" => cmd_block(&datadir, reste.get(1).map(|s| s.as_str())),
        "utxo" => cmd_utxo(&datadir),
        "emission" => cmd_emission(reste.get(1).map(|s| s.as_str())),
        "node" => cmd_node(&datadir, &reste[1..]),
        "wallet" | "portefeuille" => cmd_wallet(&datadir, &reste[1..]),
        "explorateur" | "explorer" => cmd_explorateur(&datadir, &reste[1..]),
        "pow" => cmd_pow(
            &datadir,
            reste.get(1).map(|s| s.as_str()),
            reste.iter().any(|a| a == "--sans-table"),
        ),
        "genese" | "genesis" => cmd_genese(reste.get(1).map(|s| s.as_str())),
        "securite" => cmd_securite(),
        "help" | "--help" | "-h" => {
            print!("{AIDE}");
            Ok(())
        }
        autre => Err(format!("commande inconnue : {autre}\n\n{AIDE}")),
    };

    if let Err(e) = r {
        eprintln!("erreur : {e}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Etat sur disque
// ---------------------------------------------------------------------------

struct Etat {
    chain: Chain,
    wallet: Wallet,
    /// Ce noeud tourne sans fichier de portefeuille.
    ///
    /// Le portefeuille en memoire n'est alors qu'une coquille : il n'est jamais
    /// ecrit, aucune de ses adresses n'est distribuee, et les methodes qui
    /// deplacent des fonds ne sont pas servies. C'est ce que doit etre un noeud
    /// d'amorcage — un serveur qui redemarre seul apres une coupure ne peut pas
    /// attendre qu'un humain tape une phrase secrete, et n'a aucune raison de
    /// garder des clefs.
    sans_portefeuille: bool,
    /// Le fichier de blocs **et** l'index de leurs positions. Les deux ensemble,
    /// jamais l'un sans l'autre : un bloc ecrit mais non indexe est un bloc que
    /// ce noeud ne saura plus servir a ses pairs.
    archive: std::sync::Arc<BlockArchive>,
    datadir: PathBuf,
}

fn chemin_portefeuille(d: &Path) -> PathBuf {
    d.join("wallet.dat")
}
fn chemin_blocs(d: &Path) -> PathBuf {
    d.join("blocks.dat")
}

/// Phrase secrete du portefeuille, telle que l'utilisateur l'a fournie.
///
/// Trois sources, dans cet ordre : l'option explicite, un fichier, la variable
/// d'environnement. La saisie interactive n'intervient qu'en dernier recours,
/// et seulement si un terminal est disponible.
fn phrase_secrete(
    depuis_fichier: Option<&str>,
    interactif: bool,
) -> Result<Option<String>, String> {
    if let Some(chemin) = depuis_fichier {
        let brut = std::fs::read_to_string(chemin)
            .map_err(|e| format!("phrase secrete illisible dans {chemin} : {e}"))?;
        let p = brut.trim_end_matches(['\n', '\r']).to_string();
        if p.is_empty() {
            return Err(format!("le fichier {chemin} est vide"));
        }
        return Ok(Some(p));
    }
    if let Ok(p) = std::env::var("Q21_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(Some(p));
        }
    }
    if !interactif {
        return Ok(None);
    }
    let (p, masque) = q21_core::prompt::lire_phrase("Phrase secrete du portefeuille : ")
        .map_err(|e| e.to_string())?;
    if !masque {
        eprintln!("  avertissement : l'echo du terminal n'a pas pu etre coupe.");
    }
    Ok(if p.is_empty() { None } else { Some(p) })
}

/// Restreint le fichier a son proprietaire.
///
/// Sans cela, `wallet.dat` etait ecrit avec les droits par defaut — souvent
/// lisible par tout le monde sur une machine partagee. Chiffrer un fichier que
/// n'importe qui peut copier ne protege que contre la paresse.
fn restreindre_acces(chemin: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = chemin;
    }
}

/// Numero de serie du fichier de portefeuille, conserve a part.
///
/// # Le rejeu qu'il empeche
///
/// Le format scelle ne portait ni version, ni compteur : deux scellages
/// successifs du meme portefeuille etaient interchangeables. Remettre en place
/// une copie anterieure de `wallet.dat` ramenait `next_index` en arriere **et**
/// effacait la liste des clefs deja employees. Sur un schema a usage unique,
/// cela signifie re-signer avec une clef Lamport deja revelee : la clef privee
/// devient publique.
///
/// Le compteur croit a chaque ecriture et sa valeur haute est conservee dans un
/// fichier distinct. Un `wallet.dat` plus ancien que ce qu'on a deja vu est
/// refuse, avec un message qui dit quoi faire.
fn chemin_reservoir(d: &Path) -> PathBuf {
    d.join("mempool.dat")
}

fn chemin_serie(d: &Path) -> PathBuf {
    d.join("wallet.seq")
}

/// Nom d'un reseau tel qu'on l'ecrit en ligne de commande.
fn nom_de_reseau(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

fn reseau_depuis_nom(s: &str) -> Result<Network, String> {
    match s {
        "regtest" => Ok(Network::Regtest),
        "testnet" => Ok(Network::Testnet),
        "mainnet" => Err("le reseau principal n'existe pas : le protocole n'est pas \
                          pret, et le dire serait mentir."
            .into()),
        autre => Err(format!(
            "reseau inconnu : {autre}. Attendu : regtest ou testnet."
        )),
    }
}

fn chemin_index(d: &Path) -> PathBuf {
    d.join("index.dat")
}

fn serie_connue(d: &Path) -> u64 {
    std::fs::read_to_string(chemin_serie(d))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn enregistrer_serie(d: &Path, serie: u64) {
    let chemin = chemin_serie(d);
    let tmp = chemin.with_extension("tmp");
    if std::fs::write(&tmp, serie.to_string()).is_ok() && std::fs::rename(&tmp, &chemin).is_ok() {
        restreindre_acces(&chemin);
    }
}

/// Un seul fil ecrit le portefeuille a la fois.
///
/// # Le defaut que ce verrou repare
///
/// `ecrire_portefeuille` lit le numero de serie, scelle le contenu, ecrit
/// `wallet.dat`, puis ecrit `wallet.seq`. Le scellement coute six cent mille
/// iterations de PBKDF2 : plusieurs centaines de millisecondes pendant
/// lesquelles le numero de serie lu au depart vieillit.
///
/// Deux ecritures concurrentes — le fil du RPC apres une depense, le fil
/// principal a l'arret — s'entrelacent alors ainsi :
///
/// ```text
///   fil A  lit seq=5, serie=6, commence a sceller ......................
///   fil B  lit seq=5, serie=6, scelle, ecrit wallet(6), ecrit seq=6
///   fil B  lit seq=6, serie=7, scelle, ecrit wallet(7), ecrit seq=7
///   fil A  ..... termine et ecrit wallet(6)   <-- ecrase la version 7
/// ```
///
/// Il reste un `wallet.seq` a 7 et un `wallet.dat` a 6. Au demarrage suivant,
/// la protection anti-rejeu fait exactement ce qu'on lui demande : elle refuse
/// d'ouvrir le portefeuille en annoncant une restauration depuis une
/// sauvegarde ancienne. Le portefeuille est intact, mais l'utilisateur lit
/// qu'il a peut-etre revele ses clefs a usage unique.
///
/// Le verrou couvre la totalite de la sequence : lecture de la serie,
/// scellement, ecriture des deux fichiers. Entre processus, c'est le verrou de
/// repertoire de `q21_core::verrou` qui s'en charge.
static VERROU_ECRITURE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn ecrire_portefeuille(d: &Path, w: &Wallet) -> Result<(), String> {
    // Un fil qui panique en tenant ce verrou empoisonne le mutex. On reprend
    // quand meme : la donnee protegee est le disque, pas une structure en
    // memoire qu'une panique aurait pu laisser a moitie modifiee.
    let _serialise = VERROU_ECRITURE.lock().unwrap_or_else(|e| e.into_inner());
    let reseau = match w.network() {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    };
    let serie = serie_connue(d).saturating_add(1);
    // Les indices deja employes font partie du portefeuille au meme titre que
    // la graine : les perdre coute une clef privee.
    let consommes: Vec<String> = w
        .indices_consommes()
        .iter()
        .map(|i| i.to_string())
        .collect();
    let contenu = format!(
        "seed={}\nnext_index={}\nnetwork={}\nscheme={}\nserie={}\nverifie_jusqu_a={}\nconsommes={}\n",
        w.seed_hex(),
        w.next_index(),
        reseau,
        w.scheme().as_u8(),
        serie,
        w.verifie_jusqu_a(),
        consommes.join(",")
    );
    // Le portefeuille est scelle si une phrase secrete est connue de cette
    // session. La graine ne doit jamais toucher le disque en clair quand
    // l'utilisateur a demande le contraire.
    let chemin = chemin_portefeuille(d);
    let octets = match phrase_courante() {
        Some(phrase) => q21_core::kdf::sceller(
            phrase.as_bytes(),
            contenu.as_bytes(),
            q21_core::kdf::ITERATIONS_DEFAUT,
        )
        .map_err(|e| e.to_string())?,
        None => contenu.into_bytes(),
    };
    // --- L'ecriture passe par un fichier temporaire, puis un renommage.
    //
    // `std::fs::write` tronque le fichier existant **avant** d'ecrire le
    // nouveau contenu. Une coupure entre les deux — plus de place, batterie a
    // plat, arret brutal — laissait un `wallet.dat` vide ou incomplet, c'est-a-
    // dire une graine perdue. Le renommage, lui, est atomique : le fichier
    // contient l'ancienne version ou la nouvelle, jamais un melange.
    //
    // `wallet.seq` avait deja cette precaution ; le fichier qui porte les fonds
    // ne l'avait pas.
    let tmp = chemin.with_extension("tmp");
    std::fs::write(&tmp, &octets).map_err(|e| e.to_string())?;
    restreindre_acces(&tmp);
    std::fs::rename(&tmp, &chemin).map_err(|e| e.to_string())?;
    restreindre_acces(&chemin);
    // La marque de serie n'est posee qu'apres l'ecriture reussie : sinon une
    // coupure entre les deux rendrait le portefeuille reel « trop ancien ».
    enregistrer_serie(d, serie);

    // Le cache d'adresses suit le portefeuille. Son echec n'est pas fatal : on
    // y perd du temps de demarrage, jamais des fonds.
    if let Err(e) =
        AddressCache::new(chemin_adresses(d)).save(w.scheme(), &w.known_hashes(), &w.clef_cache())
    {
        eprintln!("avertissement : cache d'adresses non ecrit : {e}");
    }
    Ok(())
}

/// Phrase secrete retenue pour la duree du processus.
///
/// Elle sert a rouvrir le portefeuille **et** a le refermer apres chaque
/// modification. La demander deux fois par commande serait une invitation a
/// choisir une phrase courte.
///
/// # Pourquoi ce n'est plus un `OnceLock`
///
/// Ce fut un `OnceLock`, et cela tenait tant que la phrase etait tapee dans un
/// terminal : elle arrivait une fois, avant tout le reste, et une phrase fausse
/// terminait le programme. Des lors qu'elle se saisit dans une page —
/// `installation.rs` —, l'utilisateur peut se tromper et recommencer. Un
/// `OnceLock` aurait garde la premiere valeur pour toujours : le deuxieme essai,
/// meme juste, aurait echoue avec le message du premier. Le defaut aurait ete
/// invisible en epreuve et permanent a l'usage.
///
/// La valeur exterieure distingue « personne n'a encore rien dit » de « on sait
/// qu'il n'y a pas de phrase », qui ne sont pas la meme chose : la seconde
/// autorise a ecrire un portefeuille en clair, la premiere non.
static PHRASE: std::sync::Mutex<Option<Option<String>>> = std::sync::Mutex::new(None);

fn phrase_courante() -> Option<String> {
    PHRASE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .flatten()
}

fn retenir_phrase(p: Option<String>) {
    *PHRASE.lock().unwrap_or_else(|e| e.into_inner()) = Some(p);
}

/// Oublie la phrase retenue, sans decider qu'il n'y en a pas.
///
/// Sert au seul cas ou une phrase s'est revelee fausse : on revient a l'etat
/// « rien n'a ete dit », et non a l'etat « il n'y a pas de phrase », qui
/// autoriserait a ecrire une graine en clair.
fn oublier_phrase() {
    *PHRASE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

fn lire_portefeuille(d: &Path) -> Result<Wallet, String> {
    let brut = std::fs::read(chemin_portefeuille(d))
        .map_err(|_| "aucun portefeuille ici. Lancez `q21 init` d'abord.".to_string())?;

    // Un portefeuille scelle se reconnait a sa magie. On ne devine jamais : soit
    // le fichier annonce qu'il est chiffre, soit il ne l'est pas.
    let contenu = if brut.starts_with(b"Q21SCEL1") {
        let phrase = match phrase_courante() {
            Some(p) => p,
            None => {
                let p = phrase_secrete(None, true)?
                    .ok_or("ce portefeuille est chiffre : une phrase secrete est necessaire")?;
                retenir_phrase(Some(p.clone()));
                p
            }
        };
        let clair =
            q21_core::kdf::desceller(phrase.as_bytes(), &brut).map_err(|e| e.to_string())?;
        String::from_utf8(clair).map_err(|_| "portefeuille illisible apres dechiffrement")?
    } else {
        retenir_phrase(None);
        String::from_utf8(brut).map_err(|_| "portefeuille illisible")?
    };

    let mut seed = None;
    let mut next_index = 0u32;
    let mut serie = 0u64;
    let mut consommes: Vec<u32> = Vec::new();
    let mut verifie_jusqu_a = 0u64;
    let mut reseau = Network::Regtest;
    // Absent des portefeuilles ecrits avant l'arrivee de ML-DSA : on retombe
    // sur Lamport, qui est ce qu'ils contenaient.
    let mut scheme = SchemeId::LamportOts;
    for ligne in contenu.lines() {
        let (clef, valeur) = match ligne.split_once('=') {
            Some(p) => p,
            None => continue,
        };
        match clef {
            "seed" => seed = Wallet::seed_from_hex(valeur),
            "next_index" => next_index = valeur.parse().unwrap_or(0),
            "serie" => serie = valeur.parse().unwrap_or(0),
            "verifie_jusqu_a" => verifie_jusqu_a = valeur.parse().unwrap_or(0),
            "consommes" => {
                consommes = valeur
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse().ok())
                    .collect()
            }
            "scheme" => {
                scheme = valeur
                    .parse::<u8>()
                    .ok()
                    .and_then(SchemeId::from_u8)
                    .ok_or_else(|| format!("portefeuille illisible : schema inconnu ({valeur})"))?
            }
            "network" => {
                reseau = match valeur {
                    "mainnet" => Network::Mainnet,
                    "testnet" => Network::Testnet,
                    _ => Network::Regtest,
                }
            }
            _ => {}
        }
    }

    let seed = seed.ok_or("portefeuille illisible : graine absente ou malformee")?;

    // --- Rejeu d'un fichier anterieur.
    //
    // Un `wallet.dat` remis en place depuis une sauvegarde ramene `next_index`
    // en arriere et efface les indices deja employes. Sur Lamport, re-signer
    // avec une clef deja revelee publie la clef privee. On refuse, et on dit
    // comment sortir de la situation — jamais un refus muet sur un portefeuille.
    let attendue = serie_connue(d);
    if serie < attendue {
        return Err(format!(
            "ce portefeuille porte le numero de serie {serie}, alors que ce\n             repertoire en a deja vu un plus recent ({attendue}).\n             C'est la signature d'une restauration depuis une sauvegarde ancienne.\n             Reutiliser un tel fichier ferait re-signer avec des clefs a usage\n             unique deja employees, ce qui revele leur clef privee.\n\n             Si cette restauration est voulue et que vous savez qu'aucune clef\n             n'a servi depuis, effacez {}.",
            chemin_serie(d).display()
        ));
    }

    let cache = AddressCache::new(chemin_adresses(d));
    let mut w = Wallet::from_seed_scheme(seed, reseau, scheme).map_err(|_| {
        format!(
            "ce portefeuille est en {}, que ce binaire ne sait pas manipuler.\n             Recompilez avec `cargo build --release --features mldsa`.",
            scheme.name()
        )
    })?;
    // Retrouve les adresses deja distribuees. Le cache evite de rederiver
    // chaque clef ; il est resonde par le portefeuille avant d'etre adopte, et
    // toute anomalie fait retomber sur la derivation complete.
    let clef_cache = w.clef_cache();
    let adopte = match cache.load(scheme, &clef_cache) {
        Ok(h) if h.len() as u32 >= next_index => w.adopt_hashes(&h[..next_index as usize]),
        Ok(_) => false,
        Err(e) => {
            if cache.exists() {
                eprintln!("avertissement : cache d'adresses ignore ({e})");
            }
            false
        }
    };
    w.marquer_consommes(&consommes);
    w.noter_verification(verifie_jusqu_a);
    if !adopte {
        w.rescan(next_index);
        if next_index > 0 {
            let _ = cache.save(scheme, &w.known_hashes(), &clef_cache);
        }
    }
    Ok(w)
}

fn chemin_etat(d: &Path) -> PathBuf {
    d.join("state.dat")
}

fn chemin_adresses(d: &Path) -> PathBuf {
    d.join("addresses.dat")
}

fn chemin_pairs(d: &Path) -> PathBuf {
    d.join("peers.dat")
}

/// Ecrit un instantane de l'etat monetaire, si la chaine est assez longue.
///
/// L'echec n'est jamais fatal : un instantane absent coute un demarrage lent,
/// pas une chaine perdue.
fn ecrire_instantane(datadir: &Path, chain: &Chain) {
    let clef = match q21_core::state::clef_de_repertoire(datadir) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("avertissement : instantane non ecrit ({e})");
            return;
        }
    };
    if let Some(i) = chain.snapshot() {
        if let Err(e) = StateStore::new_scelle(chemin_etat(datadir), clef).save(&i) {
            eprintln!("avertissement : instantane non ecrit : {e}");
        }
    }
}

fn charger(datadir: &Path) -> Result<Etat, String> {
    charger_avec(datadir, None)
}

/// Charge l'etat du repertoire.
///
/// `reseau_impose` sert au noeud sans portefeuille : c'est alors la seule
/// source de la reponse « quelle chaine ce repertoire contient-il ». Avec un
/// portefeuille, la reponse vient de lui, et un desaccord est une erreur — pas
/// quelque chose qu'on tranche en silence.
fn charger_avec(datadir: &Path, reseau_impose: Option<Network>) -> Result<Etat, String> {
    let chrono = std::env::var("Q21_CHRONO").is_ok();
    let t0 = std::time::Instant::now();

    let a_un_portefeuille = chemin_portefeuille(datadir).exists();
    let (mut wallet, sans_portefeuille) = if a_un_portefeuille {
        (lire_portefeuille(datadir)?, false)
    } else {
        match reseau_impose {
            Some(n) => {
                // Coquille : jamais ecrite, jamais distribuee. Sa graine ne
                // garde rien, et le minage est refuse plus haut precisement
                // pour qu'aucune piece n'atterrisse sur une clef qui mourra
                // avec le processus.
                (Wallet::from_seed([0u8; 32], n), true)
            }
            None => {
                return Err(
                    "aucun portefeuille ici.\n\n                       Pour en creer un :        q21 init testnet\n                       Pour un noeud sans portefeuille : q21 node --reseau testnet"
                        .into(),
                )
            }
        }
    };
    if chrono {
        eprintln!("[chrono] portefeuille {:.2} s", t0.elapsed().as_secs_f64());
    }
    let reseau = wallet.network();
    if let Some(n) = reseau_impose {
        if n != reseau {
            return Err(format!(
                "ce dossier contient une chaine {reseau:?}, et vous demandez {n:?}.\n                   Employez un autre dossier : q21 --datadir <autre> node --reseau {}",
                nom_de_reseau(n)
            ));
        }
    }

    // 1. Balayage des en-tetes : une lecture sequentielle, aucun corps decode.
    //
    // Un dossier vide n'est pas une erreur quand on sait de quel reseau il
    // s'agit : la genese est deterministe, chacun peut donc l'ecrire lui-meme.
    // C'est ce qui permet a quelqu'un de rejoindre le reseau sans recevoir de
    // fichier de personne — et donc sans avoir a faire confiance a personne
    // pour la racine de la chaine.
    if reseau_impose.is_some() && !chemin_blocs(datadir).exists() {
        std::fs::create_dir_all(datadir).map_err(|e| e.to_string())?;
        let genese = genesis_block(reseau);
        q21_core::store::BlockStore::new(chemin_blocs(datadir))
            .append(&genese)
            .map_err(|e| e.to_string())?;
        println!("  genese ecrite : {}", genese.header.block_id());
    }

    let (archive, seuls_entetes, souci) =
        BlockArchive::open(chemin_blocs(datadir), reseau).map_err(|e| e.to_string())?;
    if seuls_entetes.is_empty() {
        return Err("aucun bloc. Lancez `q21 init` d'abord.".into());
    }
    if let Some(s) = souci {
        eprintln!("avertissement : {s}");
    }
    if chrono {
        eprintln!(
            "[chrono] balayage en-tetes {:.2} s",
            t0.elapsed().as_secs_f64()
        );
    }
    let archive = std::sync::Arc::new(archive);

    // 2. Reprise sur instantane, si l'on en a un et qu'il est coherent.
    // Le sceau du repertoire : un instantane venu d'ailleurs ne sera pas adopte.
    let clef = q21_core::state::clef_de_repertoire(datadir).map_err(|e| e.to_string())?;
    let etat = StateStore::new_scelle(chemin_etat(datadir), clef);
    let reprise = match etat.load(reseau) {
        Ok(i) => match Chain::from_snapshot(reseau, i, &seuls_entetes) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("avertissement : instantane inutilisable ({e}) — revalidation complete");
                None
            }
        },
        Err(e) if etat.exists() => {
            eprintln!("avertissement : {e}");
            None
        }
        Err(_) => None,
    };

    let mut chain = match reprise {
        Some(r) => {
            let mut c = r.chain;
            // Le fournisseur de corps est branche AVANT le rejeu : la regle du
            // double paiement d'oncle relit les corps anterieurs a l'instantane,
            // et valider sans eux serait valider a l'aveugle.
            c.set_body_source(archive.clone());
            // 3a. Seule la fenetre qui suit l'instantane est revalidee — c'est
            // ce qui reconstruit les enregistrements d'annulation, donc la
            // capacite a reorganiser.
            for id in &r.a_rejouer {
                let b = archive.read(id).ok_or("corps manquant au rejeu")?;
                let now = b.header.time + MAX_FUTURE_TIME;
                c.connect(&b, now)
                    .map_err(|e| format!("bloc {} refuse au rejeu : {e:?}", b.header.height))?;
            }
            c
        }
        None => {
            // 3b. Sans instantane exploitable, on revalide tout. Lent, et sûr.
            //
            // --- Le fichier n'est pas une ligne droite.
            //
            // Ce rejeu appelait `connect`, qui exige que chaque bloc prolonge la
            // tete active. C'etait vrai tant que seuls les blocs de la chaine
            // active atteignaient le disque. Depuis que le journal consigne
            // **aussi** les branches laterales — sans quoi aucune reorganisation
            // ne survit a un redemarrage — le fichier contient des blocs qui ne
            // prolongent rien.
            //
            // Un vrai lancement l'a montre sans ambiguite : deux noeuds minant
            // l'un contre l'autre produisent des branches concurrentes, et le
            // noeud refusait de redemarrer avec
            // `HauteurIncorrecte { attendu: 853, recu: 218 }`. Le repli de
            // securite — celui qui doit fonctionner quand l'instantane est
            // perdu — ne fonctionnait plus du tout.
            //
            // `submit` accepte ce que `connect` refuse : branche laterale,
            // reorganisation, bloc deja vu. L'ordre du fichier est celui de
            // l'acceptation, donc un parent y precede toujours ses enfants.
            let (blocs, _) = archive.store().load_all().map_err(|e| e.to_string())?;
            let mut c = Chain::new(reseau, blocs[0].clone());
            c.set_body_source(archive.clone());
            for (i, b) in blocs.iter().enumerate().skip(1) {
                let now = b.header.time + MAX_FUTURE_TIME;
                c.submit(b, now)
                    .map_err(|e| format!("bloc {i} refuse au rejeu : {e:?}"))?;
            }
            c
        }
    };

    if chrono {
        eprintln!("[chrono] chaine prete {:.2} s", t0.elapsed().as_secs_f64());
    }
    chain.set_body_source(archive.clone());

    // --- Clefs a usage unique : la chaine a le dernier mot.
    //
    // Un fichier de portefeuille peut etre remplace par une version anterieure ;
    // la chaine, non. Si ce portefeuille annonce des adresses distribuees mais
    // aucune clef consommee, l'etat est suspect — restauration depuis un code
    // de sauvegarde, sauvegarde ancienne, fichier perdu. Sur un schema a usage
    // unique, repartir d'une ardoise vierge revient a publier une clef privee au
    // premier paiement.
    //
    // On balaie alors la chaine pour retrouver les signatures deja emises. C'est
    // couteux, et c'est exactement pour cela qu'on ne le fait pas a chaque
    // demarrage — seulement quand l'ardoise est vierge alors qu'elle ne devrait
    // pas l'etre.
    if wallet.scheme().est_a_usage_unique()
        && wallet.next_index() > 0
        && wallet.verifie_jusqu_a() < chain.height()
    {
        eprintln!(
            "verification des clefs a usage unique : aucune consommation connue \n             pour {} adresse(s) distribuee(s). Balayage de la chaine...",
            wallet.next_index()
        );
        let mut trouves = 0usize;
        for h in 1..=chain.height() {
            if let Some(id) = chain.active_at(h) {
                if let Some(b) = archive.read(&id) {
                    trouves += wallet.noter_depenses(&b);
                }
            }
        }
        if trouves > 0 {
            eprintln!(
                "             {trouves} clef(s) deja employee(s) retrouvee(s) dans la chaine : \n             elles ne resserviront pas."
            );
        } else {
            eprintln!("             aucune signature de ce portefeuille dans la chaine.");
        }
        // Le balayage est note : il ne recommencera qu'a partir d'ici. Sans
        // cela, un portefeuille qui ne depense jamais relisait toute la chaine
        // a chaque commande — un cout qui croit avec la hauteur, paye pour rien.
        wallet.noter_verification(chain.height());
        if !sans_portefeuille {
            let _ = ecrire_portefeuille(datadir, &wallet);
        }
    }

    // --- La restauration retrouve ses adresses, ou elle ne restaure rien.
    //
    // Un portefeuille ne reconnait que les adresses qu'il a derivees. Restaure
    // depuis son code de sauvegarde, il n'en a derive aucune : il affichait donc
    // un solde de **zero** sur une chaine qui contenait ses fonds, et la
    // promesse « ce code suffit a tout retrouver » etait fausse. L'essai qui l'a
    // montre tient en trois commandes : creer, miner, restaurer ailleurs.
    //
    // On applique la regle de l'ecart : deriver par fenetres de deux cents
    // indices tant qu'on trouve quelque chose, s'arreter quand une fenetre
    // entiere ne trouve rien.
    //
    // Le declencheur est etroit a dessein. Un portefeuille qui a deja distribue
    // des adresses connait son etat ; refaire la decouverte a chaque demarrage
    // couterait une generation de clef ML-DSA par indice, pour rien. On ne la
    // tente donc que si le portefeuille est presque vierge alors que la chaine,
    // elle, a une histoire.
    let a_decouvrir = !sans_portefeuille
        && chain.height() > 0
        && wallet.next_index() <= 1
        && !chain.utxo.is_empty();
    if a_decouvrir {
        let avant = wallet.next_index();
        let trouvees = {
            let u = &chain.utxo;
            wallet.decouvrir(|h| u.connait(h))
        };
        if trouvees > 0 {
            println!(
                "  restauration : {trouvees} sortie(s) retrouvee(s) sur la chaine, \n               {} adresse(s) rederivee(s)",
                wallet.next_index().saturating_sub(avant)
            );
            let _ = ecrire_portefeuille(datadir, &wallet);
        }
    }

    Ok(Etat {
        chain,
        wallet,
        archive,
        datadir: datadir.to_path_buf(),
        sans_portefeuille,
    })
}

fn maintenant() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Analyse un montant en Q21 sans jamais passer par un flottant.
fn parse_montant(s: &str) -> Result<Amount, String> {
    let (entier, frac) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    if frac.len() > DECIMALS as usize {
        return Err(format!("au plus {DECIMALS} decimales"));
    }
    let e: u64 = entier
        .parse()
        .map_err(|_| format!("montant invalide : {s}"))?;
    let mut f: u64 = 0;
    if !frac.is_empty() {
        f = frac
            .parse()
            .map_err(|_| format!("partie decimale invalide : {frac}"))?;
        for _ in frac.len()..DECIMALS as usize {
            f *= 10;
        }
    }
    e.checked_mul(UNITS_PER_COIN)
        .and_then(|v| v.checked_add(f))
        .map(Amount::from_units)
        .ok_or_else(|| "montant hors limites".into())
}

// ---------------------------------------------------------------------------
// Commandes
// ---------------------------------------------------------------------------

/// Traduit le nom d'un schema donne en ligne de commande.
///
/// Refuse explicitement ce qui n'est pas compile : mieux vaut echouer ici que
/// deriver des adresses que ce binaire ne saura jamais depenser.
fn schema_depuis_nom(nom: &str) -> Result<SchemeId, String> {
    let s = match nom {
        "lamport" => SchemeId::LamportOts,
        "mldsa65" => SchemeId::MlDsa65,
        "mldsa87" => SchemeId::MlDsa87,
        autre => {
            return Err(format!(
                "schema inconnu : {autre}\n  attendus : lamport, mldsa65, mldsa87"
            ))
        }
    };
    if !s.disponible() {
        return Err(format!(
            "{} n'est pas compile dans ce binaire.\n  Recompilez avec `cargo build --release --features mldsa`.",
            s.name()
        ));
    }
    Ok(s)
}

/// Restaure un portefeuille depuis son code de sauvegarde.
///
/// La contrepartie du code Bech32m : un code qu'on ne peut pas rejouer ne sert
/// a rien. La chaine, elle, se resynchronisera depuis le reseau ; seules les
/// clefs se restaurent ici.
fn cmd_restore(
    datadir: &Path,
    code: Option<&str>,
    reseau: Option<&str>,
    schema: Option<&str>,
    phrase_fichier: Option<&str>,
) -> Result<(), String> {
    let code = code.ok_or("usage : q21 restore <code-de-sauvegarde> [reseau] [schema]")?;
    let reseau_choisi = match reseau.unwrap_or("regtest") {
        "regtest" => Network::Regtest,
        "testnet" => Network::Testnet,
        autre => return Err(format!("reseau inconnu : {autre}")),
    };
    let graine = Wallet::seed_from_backup(code, reseau_choisi).map_err(|e| match e {
        q21_core::wallet::WalletError::SauvegardeAutreReseau => {
            "ce code de sauvegarde appartient a un autre reseau".to_string()
        }
        _ => "code de sauvegarde illisible : la somme de controle ne correspond pas.\n                Verifiez la recopie — l'alphabet Bech32 ne contient ni 1, ni b, ni i, ni o."
            .to_string(),
    })?;
    cmd_init_avec(datadir, reseau, schema, phrase_fichier, Some(graine))
}

fn cmd_init(
    datadir: &Path,
    reseau: Option<&str>,
    schema: Option<&str>,
    phrase_fichier: Option<&str>,
) -> Result<(), String> {
    cmd_init_avec(datadir, reseau, schema, phrase_fichier, None)
}

/// Cree la chaine et le portefeuille dans un dossier neuf.
///
/// C'est le cœur de `init` et de `restore`, extrait pour que la page
/// d'installation puisse l'appeler sans passer par un terminal. La fonction
/// n'imprime rien et ne demande rien : la phrase secrete doit deja etre
/// etablie — c'est [`ecrire_portefeuille`] qui l'emploie pour sceller.
///
/// L'ordre compte, et il est le meme que dans la version en ligne de commande :
/// le portefeuille n'est ecrit qu'apres la genese, de sorte qu'un dossier ne
/// puisse jamais contenir une graine sans la chaine qui va avec.
fn ecrire_chaine_neuve(
    datadir: &Path,
    reseau: Network,
    schema: SchemeId,
    graine_fournie: Option<[u8; 32]>,
) -> Result<(Wallet, q21_core::address::Address, q21_core::block::Block), String> {
    let mut wallet = match graine_fournie {
        Some(g) => Wallet::from_seed_scheme(g, reseau, schema)
            .map_err(|_| format!("schema indisponible : {}", schema.name()))?,
        None => Wallet::generate_scheme(reseau, schema).map_err(|e| match e {
            q21_core::wallet::WalletError::AleaIndisponible => {
                "le generateur d'alea du systeme est inaccessible : aucune clef n'a ete creee. \
                 Mieux vaut aucun portefeuille qu'un portefeuille previsible."
                    .to_string()
            }
            _ => format!("schema indisponible : {}", schema.name()),
        })?,
    };
    let beneficiaire = wallet.new_address();
    let genesis = genesis_block(reseau);

    let store = q21_core::store::BlockStore::new(chemin_blocs(datadir));
    store.append(&genesis).map_err(|e| e.to_string())?;
    ecrire_portefeuille(datadir, &wallet)?;
    Ok((wallet, beneficiaire, genesis))
}

fn cmd_init_avec(
    datadir: &Path,
    reseau: Option<&str>,
    schema: Option<&str>,
    phrase_fichier: Option<&str>,
    graine_fournie: Option<[u8; 32]>,
) -> Result<(), String> {
    let reseau = match reseau.unwrap_or("regtest") {
        "regtest" => Network::Regtest,
        "testnet" => Network::Testnet,
        "mainnet" => {
            return Err(
                "le reseau principal n'existe pas : le protocole n'est pas pret, \
                        et le dire serait mentir."
                    .into(),
            )
        }
        autre => return Err(format!("reseau inconnu : {autre}")),
    };

    if chemin_blocs(datadir).exists() {
        return Err(format!(
            "une chaine existe deja dans {}. Supprimez le dossier pour repartir de zero.",
            datadir.display()
        ));
    }
    std::fs::create_dir_all(datadir).map_err(|e| e.to_string())?;

    // Par defaut, le meilleur schema que ce binaire sache manipuler.
    let schema = match schema {
        Some(n) => schema_depuis_nom(n)?,
        // Le niveau maximal que la norme definit, parce qu'il ne coute rien :
        // quinze millisecondes de plus par bloc plein, sur une cible de cent
        // vingt secondes. Voir la documentation de `SchemeId::MlDsa87`.
        None if SchemeId::MlDsa87.disponible() => SchemeId::MlDsa87,
        None => SchemeId::LamportOts,
    };
    if !schema.allowed_on(reseau) {
        return Err(format!(
            "{} n'est pas autorise sur ce reseau.",
            schema.name()
        ));
    }

    // La phrase secrete est etablie AVANT de creer quoi que ce soit : un
    // portefeuille ecrit en clair puis chiffre aurait laisse une trace en clair
    // sur le disque, et un fichier efface n'est pas un fichier detruit.
    if phrase_fichier.is_none() && phrase_courante().is_none() {
        // --- Un choix qui n'a pas ete fait n'est pas un choix.
        //
        // Sans terminal — application double-cliquee, tache planifiee, canal
        // redirige — `read_line` rend une ligne vide immediatement. Le
        // programme comprenait « pas de phrase secrete » alors que personne
        // n'avait rien choisi, et creait un portefeuille dont la graine partait
        // en clair sur le disque.
        //
        // On refuse, et on dit comment faire autrement. Les deux voies
        // proposees fonctionnent sans terminal.
        if !q21_core::prompt::entree_interactive() {
            return Err(
                "aucun terminal pour demander une phrase secrete.\n\n                   Creer un portefeuille sans protection ecrirait la graine en clair\n                   sur le disque, et ce n'est pas une decision a prendre a votre place.\n\n                   Deux facons de fournir la phrase sans terminal :\n\n                       q21 --phrase-fichier <chemin> init testnet\n                       Q21_PASSPHRASE='...' q21 init testnet\n\n                   Et si vous voulez reellement un portefeuille sans protection —\n                   sur un reseau de test, par exemple — lancez cette commande depuis\n                   un terminal et laissez la phrase vide."
                    .to_string(),
            );
        }
        let saisie = q21_core::prompt::lire_phrase_confirmee(
            "Phrase secrete du portefeuille (vide = aucune protection) : ",
        )
        .unwrap_or(None);
        retenir_phrase(saisie);
    }
    if phrase_courante().is_none() {
        println!();
        println!("  ATTENTION : aucune phrase secrete.");
        println!("  La graine sera ecrite EN CLAIR dans wallet.dat. Quiconque lira ce");
        println!("  fichier — sauvegarde, disque revendu, dossier partage — detiendra");
        println!("  definitivement les fonds.");
        println!();
    }

    let (wallet, beneficiaire, genesis) = ecrire_chaine_neuve(datadir, reseau, schema, graine_fournie)?;

    println!();
    println!("  Chaine initialisee dans {}", datadir.display());
    println!("  Reseau            {reseau:?}");
    println!("  Schema            {}", schema.name());
    println!("  Genese            {}", genesis.header.block_id());
    println!(
        "  Message           {}",
        String::from_utf8_lossy(&genesis.transactions[0].inputs[0].witness.signature)
    );
    println!(
        "  Piece de genese   {} Q21",
        Amount::from_units(GENESIS_PREMINT)
    );
    println!("  Beneficiaire      {beneficiaire}");
    println!();
    println!("  CODE DE SAUVEGARDE");
    println!();
    println!("    {}", wallet.backup_code());
    println!();
    println!("  Recopiez-le sur papier, hors de cette machine. Il est le seul moyen");
    println!("  de retrouver les fonds si le fichier disparait — et il porte une");
    println!("  somme de controle : une faute de frappe sera detectee, pas subie.");
    println!();
    println!(
        "  La piece de genese est une coinbase : elle devient depensable\n  \
         apres {COINBASE_MATURITY} blocs. Lancez `q21 mine {}`.",
        COINBASE_MATURITY + 1
    );
    Ok(())
}

fn cmd_info(datadir: &Path) -> Result<(), String> {
    let e = charger(datadir)?;
    let tip = e.chain.tip();
    let cible = pow::target_from_compact(tip.bits).map_err(|x| format!("{x:?}"))?;

    println!("Chaine");
    println!("  Reseau            {:?}", e.chain.network);
    println!("  Hauteur           {}", e.chain.height());
    println!("  Tete              {}", e.chain.tip_id());
    println!(
        "  Horodatage        {} ({})",
        tip.time,
        if tip.time > maintenant() {
            "futur"
        } else {
            "passe"
        }
    );
    println!("  Difficulte        {:#010x}", tip.bits);
    println!("  Cible             {}", hex_court(&cible.to_be_bytes()));
    println!(
        "  Travail cumule    {}",
        format_travail(e.chain.total_work())
    );
    println!("  Blocs connus      {}", e.chain.known_blocks());
    println!();
    println!("Monnaie");
    println!("  Emis              {} Q21", e.chain.total_issued());
    println!("  Dans les UTXO     {} Q21", e.chain.utxo.total_value());
    println!("  Plafond           {} Q21", Amount::from_units(MAX_SUPPLY));
    println!(
        "  Part emise        {:.6} %",
        100.0 * e.chain.total_issued().units() as f64 / MAX_SUPPLY as f64
    );
    println!(
        "  Prochain bloc     {} Q21",
        emission::block_subsidy(e.chain.height() + 1)
    );
    println!();
    println!("Portefeuille");
    println!(
        "  Solde depensable  {} Q21",
        e.wallet.balance(&e.chain.utxo, e.chain.height())
    );
    println!("  Adresses derivees {}", e.wallet.next_index());
    println!("  Sorties suivies   {}", e.chain.utxo.len());
    Ok(())
}

fn cmd_address(datadir: &Path) -> Result<(), String> {
    let mut e = charger(datadir)?;
    let a = e.wallet.new_address();
    ecrire_portefeuille(&e.datadir, &e.wallet)?;
    println!("{a}");
    println!();
    println!("Schema : {}", a.scheme.name());
    if a.scheme.est_a_usage_unique() {
        println!(
            "Adresse a usage unique : Lamport revele la clef privee si elle signe\n\
             deux fois. Chaque `q21 address` en produit une neuve, et c'est\n\
             obligatoire, pas une precaution de confidentialite."
        );
    } else {
        println!(
            "Adresse reutilisable : ML-DSA signe autant de fois qu'on veut sans\n\
             affaiblir la clef. Chaque `q21 address` en produit tout de meme une\n\
             neuve — par confidentialite, cette fois, et non par necessite."
        );
    }
    Ok(())
}

fn cmd_balance(datadir: &Path) -> Result<(), String> {
    let e = charger(datadir)?;
    let h = e.chain.height();
    let solde = e.wallet.balance(&e.chain.utxo, h);
    let sorties = e.wallet.spendable(&e.chain.utxo, h);

    println!("{solde} Q21 depensables ({} sorties)", sorties.len());

    // Ce qui existe mais n'est pas encore mûr.
    let mut immature = 0u64;
    for (_, entree) in e.chain.utxo.iter() {
        if entree.is_coinbase
            && h < entree.height + COINBASE_MATURITY
            && e.wallet.owns(&entree.output.pubkey_hash)
        {
            immature += entree.output.value.units();
        }
    }
    if immature > 0 {
        println!(
            "{} Q21 encore immatures ({COINBASE_MATURITY} blocs de maturite)",
            Amount::from_units(immature)
        );
    }
    Ok(())
}

fn cmd_mine(datadir: &Path, n: Option<&str>) -> Result<(), String> {
    let n: u64 = n.unwrap_or("1").parse().map_err(|_| "nombre invalide")?;
    let mut e = charger(datadir)?;

    // --- Les transactions en attente entrent dans les blocs qu'on mine.
    //
    // `q21 mine` ignorait le reservoir et minait des blocs vides. Une
    // transaction envoyee puis suivie d'un `mine` restait donc en attente
    // indefiniment, alors que la commande semblait faite pour la confirmer.
    // C'est exactement l'enchainement qu'a suivi le premier utilisateur.
    let mut reservoir = q21_core::mempool::Mempool::new();
    let magasin = q21_core::state::clef_de_repertoire(datadir)
        .ok()
        .map(|clef| q21_core::state::MempoolStore::new(chemin_reservoir(datadir), clef));
    if let Some(m) = &magasin {
        if m.exists() {
            if let Ok(attente) = m.load() {
                let hauteur = e.chain.height();
                let mut reprises = 0usize;
                for tx in &attente {
                    if reservoir
                        .accept(tx, &e.chain.utxo, e.chain.network, hauteur)
                        .is_ok()
                    {
                        reprises += 1;
                    }
                }
                if reprises > 0 {
                    println!("reservoir : {reprises} transaction(s) a confirmer");
                }
            }
        }
    }

    let debut = std::time::Instant::now();
    let mut total_essais = 0u64;

    for i in 0..n {
        let addr = e.wallet.new_address();
        // Le schema du beneficiaire doit etre celui de son adresse, sinon
        // l'empreinte inscrite dans la sortie ne correspondra a aucune clef et
        // la piece sera perdue.
        let schema = addr.scheme;
        let t = maintenant().max(e.chain.tip().time + 1);

        let selection = reservoir.select_for_block(q21_core::consensus::POIDS_BLOC_CIBLE);
        let bloc = e
            .chain
            .mine_block(addr.hash, schema, &selection, t, 200_000_000)
            .ok_or_else(|| format!("aucun nonce trouve pour le bloc {}", e.chain.height() + 1))?;
        total_essais += bloc.header.nonce;

        // Horloge de validation.
        //
        // Un horodatage ne peut pas depasser l'heure courante de plus de
        // MAX_FUTURE_TIME. Comme le reseau de test mine bien plus vite qu'une
        // seconde par bloc, une rafale butait sur cette borne au bout de
        // ~7 200 blocs — ce qui rendait impossible toute epreuve sur une
        // chaine longue.
        //
        // Sur Regtest **uniquement**, on valide contre une horloge simulee qui
        // suit le bloc. C'est l'equivalent du `setmocktime` de Bitcoin Core, et
        // c'est cantonne au reseau qui n'a aucune valeur : sur testnet comme
        // sur le reseau principal, la borne s'applique telle quelle.
        let horloge = if e.chain.network == Network::Regtest {
            bloc.header.time + 1
        } else {
            maintenant()
        };

        e.chain
            .connect(&bloc, horloge)
            .map_err(|x| format!("bloc refuse par notre propre validateur : {x:?}"))?;
        e.archive.append(&bloc).map_err(|x| x.to_string())?;
        reservoir.on_block_connected(&bloc);

        let recompense = bloc.transactions[0].outputs[0].value;
        // Au-dela de quelques centaines de blocs, une ligne par bloc noie la
        // sortie sans rien apprendre a personne.
        let bavard = n <= 200 || i + 1 == n || (i + 1) % 1_000 == 0;
        if bavard {
            println!(
                "bloc {:>6}  {}  +{} Q21",
                bloc.header.height,
                hex_court(bloc.header.block_id().as_bytes()),
                recompense
            );
        }

        if i + 1 == n {
            ecrire_portefeuille(&e.datadir, &e.wallet)?;
        }
    }
    ecrire_instantane(&e.datadir, &e.chain);

    // Ce qui reste en attente est reecrit ; ce qui vient d'etre confirme
    // disparait. Laisser le fichier tel quel ferait ressusciter au prochain
    // demarrage des transactions deja dans un bloc.
    if let Some(m) = &magasin {
        let restantes = reservoir.transactions_ordonnees();
        if restantes.is_empty() {
            let _ = m.remove();
        } else if let Err(x) = m.save(&restantes) {
            eprintln!("avertissement : reservoir non reecrit : {x}");
        }
    }

    let secondes = debut.elapsed().as_secs_f64();
    println!();
    println!(
        "{n} bloc(s) en {secondes:.2} s — {:.0} condensats/s",
        total_essais as f64 / secondes.max(0.001)
    );
    println!("Hauteur : {}", e.chain.height());
    println!("Emis    : {} Q21", e.chain.total_issued());
    Ok(())
}

fn cmd_send(
    datadir: &Path,
    adresse: Option<&String>,
    montant: Option<&String>,
) -> Result<(), String> {
    let adresse = adresse.ok_or("usage : q21 send <adresse> <montant>")?;
    let montant = montant.ok_or("usage : q21 send <adresse> <montant>")?;
    let mut e = charger(datadir)?;

    let dest = Address::parse_on(adresse, e.chain.network)
        .map_err(|x| format!("adresse invalide : {x:?}"))?;
    let valeur = parse_montant(montant)?;
    let frais = Amount::from_units(1_000);

    let tx = e
        .wallet
        .create_transaction(&e.chain.utxo, e.chain.height(), &dest, valeur, frais)
        .map_err(|x| match x {
            q21_core::wallet::WalletError::FondsInsuffisants {
                disponible,
                demande,
            } => format!(
                "fonds insuffisants : {} Q21 disponibles, {} Q21 demandes",
                Amount::from_units(disponible),
                Amount::from_units(demande)
            ),
            autre => format!("{autre:?}"),
        })?;

    println!("Transaction  {}", tx.txid());
    println!("  vers       {dest}");
    println!("  montant    {valeur} Q21");
    println!("  frais      {frais} Q21");
    println!("  entrees    {}", tx.inputs.len());
    println!("  taille     {} octets", tx.encode().len());
    println!(
        "  dont temoin {} octets ({} %)",
        tx.encode().len() - tx.encode_without_witness().len(),
        100 * (tx.encode().len() - tx.encode_without_witness().len()) / tx.encode().len().max(1)
    );

    // Pas encore de mempool en phase 2 : la transaction part directement dans un
    // bloc que l'on mine sur-le-champ.
    println!();
    println!("Minage du bloc qui la contient...");
    let addr = e.wallet.new_address();
    let t = maintenant().max(e.chain.tip().time + 1);
    let mempool: Vec<Transaction> = vec![tx];

    let bloc = e
        .chain
        .mine_block(addr.hash, addr.scheme, &mempool, t, 200_000_000)
        .ok_or("aucun nonce trouve")?;

    let frais_percus = e
        .chain
        .connect(&bloc, maintenant())
        .map_err(|x| format!("bloc refuse : {x:?}"))?;
    e.archive.append(&bloc).map_err(|x| x.to_string())?;
    ecrire_portefeuille(&e.datadir, &e.wallet)?;
    ecrire_instantane(&e.datadir, &e.chain);

    println!(
        "bloc {} mine — frais percus par le mineur : {} Q21",
        bloc.header.height, frais_percus
    );
    println!(
        "Solde restant : {} Q21",
        e.wallet.balance(&e.chain.utxo, e.chain.height())
    );
    Ok(())
}

fn cmd_block(datadir: &Path, hauteur: Option<&str>) -> Result<(), String> {
    let h: u64 = hauteur
        .ok_or("usage : q21 block <hauteur>")?
        .parse()
        .map_err(|_| "hauteur invalide")?;
    let e = charger(datadir)?;
    // Par la chaine, qui sait aller chercher un corps elague dans l'archive.
    let b = e
        .chain
        .block_at(h)
        .ok_or_else(|| format!("hauteur {h} inconnue (tete : {})", e.chain.height()))?;
    let b = &b;

    println!("Bloc {h}");
    println!("  Identifiant   {}", b.header.block_id());
    println!("  Parent        {}", b.header.prev_block);
    println!("  Merkle        {}", b.header.merkle_root);
    println!("  Horodatage    {}", b.header.time);
    println!("  Difficulte    {:#010x}", b.header.bits);
    println!("  Nonce         {}", b.header.nonce);
    println!("  Oncles        {}", b.uncles.len());
    println!("  Taille        {} octets", b.encode().len());
    println!("  Subvention    {} Q21", emission::block_subsidy(h));
    println!();
    println!("  {} transaction(s)", b.transactions.len());
    for (i, t) in b.transactions.iter().enumerate() {
        let etiquette = if t.is_coinbase() {
            "coinbase"
        } else {
            "depense "
        };
        println!(
            "    {i:>3} {etiquette} {}  {} entree(s) -> {} sortie(s)  {} Q21",
            hex_court(t.txid().as_bytes()),
            t.inputs.len(),
            t.outputs.len(),
            t.total_output().map(|a| a.to_string()).unwrap_or_default()
        );
    }
    Ok(())
}

fn cmd_utxo(datadir: &Path) -> Result<(), String> {
    let e = charger(datadir)?;
    let h = e.chain.height();
    let mut a_nous = 0u64;
    let mut immature = 0u64;
    let mut n_nous = 0usize;

    for (_, entree) in e.chain.utxo.iter() {
        if e.wallet.owns(&entree.output.pubkey_hash) {
            n_nous += 1;
            if entree.is_coinbase && h < entree.height + COINBASE_MATURITY {
                immature += entree.output.value.units();
            } else {
                a_nous += entree.output.value.units();
            }
        }
    }

    println!("Jeu d'UTXO");
    println!("  Sorties totales   {}", e.chain.utxo.len());
    println!("  Valeur totale     {} Q21", e.chain.utxo.total_value());
    println!("  A nous            {n_nous} sorties");
    println!("  Depensable        {} Q21", Amount::from_units(a_nous));
    println!("  Immature          {} Q21", Amount::from_units(immature));
    println!();
    println!(
        "  Controle anti-inflation : {}",
        if e.chain.utxo.total_value().units() <= MAX_SUPPLY {
            "masse sous le plafond, OK"
        } else {
            "PLAFOND FRANCHI — bug de consensus"
        }
    );
    Ok(())
}

fn cmd_emission(annee: Option<&str>) -> Result<(), String> {
    if let Some(a) = annee {
        let a: u64 = a.parse().map_err(|_| "annee invalide")?;
        let h = BLOCKS_PER_YEAR * a;
        println!("An {a} (bloc {h})");
        println!("  Recompense    {} Q21", emission::block_subsidy(h));
        println!("  Emis cumule   {} Q21", emission::cumulative_emission(h));
        println!("  Offre totale  {} Q21", emission::total_supply_at(h));
        println!(
            "  Part du plafond {:.4} %",
            100.0 * emission::total_supply_at(h).units() as f64 / MAX_SUPPLY as f64
        );
        return Ok(());
    }

    println!("Courbe d'emission — plafond {} Q21", MAX_SUPPLY_COINS);
    println!();
    println!("  An    Recompense/bloc        Emis cumule     % plafond");
    for a in [1u64, 2, 4, 8, 12, 16, 20, 30, 45, 60, 100] {
        let h = BLOCKS_PER_YEAR * a;
        let cumul = emission::total_supply_at(h);
        println!(
            "  {a:>3}    {:>14}    {:>15}    {:>6.2} %",
            emission::block_subsidy(h).to_string(),
            cumul.to_string(),
            100.0 * cumul.units() as f64 / MAX_SUPPLY as f64
        );
    }
    println!();
    println!("La courbe est asymptotique : elle approche le plafond sans l'atteindre.");
    Ok(())
}

/// Affiche un travail cumule de facon lisible.
///
/// Un travail se compte en tentatives esperees. Tant qu'il tient dans 64 bits on
/// l'ecrit en clair ; au-dela on donne son ordre de grandeur en bits, parce
/// qu'aligner soixante-dix chiffres n'aide personne.
fn format_travail(w: q21_core::uint::U256) -> String {
    let b = w.to_be_bytes();
    if b[..24] == [0u8; 24] {
        let mut bas = [0u8; 8];
        bas.copy_from_slice(&b[24..]);
        format!("{} tentatives esperees", u64::from_be_bytes(bas))
    } else {
        format!("~2^{} tentatives esperees", w.bits())
    }
}

fn hex_court(b: &[u8]) -> String {
    let h: String = b.iter().take(8).map(|x| format!("{x:02x}")).collect();
    format!("{h}...")
}

fn cmd_pow(datadir: &Path, reseau_demande: Option<&str>, sans_table: bool) -> Result<(), String> {
    use q21_core::consensus as k;
    use q21_core::memhard::{self, PartialTable, PowTable, TableParams};
    use std::io::Write;

    let reseau = match reseau_demande {
        Some("regtest") => Network::Regtest,
        Some("testnet") => Network::Testnet,
        Some("mainnet") => Network::Mainnet,
        Some(autre) => return Err(format!("reseau inconnu : {autre}")),
        None => lire_portefeuille(datadir)
            .map(|w| w.network())
            .unwrap_or(Network::Regtest),
    };
    let params = TableParams::for_network(reseau);
    let n = memhard::table_size(params, 0);
    let c = memhard::cache_size(params, 0);
    let mio = |elements: u64| elements as f64 * 32.0 / 1024.0 / 1024.0;

    println!("Preuve de travail memory-hard a deux niveaux — reseau {reseau:?}");
    println!();
    println!(
        "  Cache  (niveau 1)   {c} elements   {:>9.1} Mio   detenu par tout noeud",
        mio(u64::from(c))
    );
    println!(
        "  Table  (niveau 2)   {n} elements   {:>9.1} Mio   detenue par les mineurs",
        mio(u64::from(n))
    );
    println!("  Acces par tentative {}", k::POW_K);
    println!(
        "  Acces cache/element {}   (penalite theorique du refus de table)",
        k::POW_J
    );
    println!(
        "  Croissance          +{} % toutes les {} blocs",
        k::POW_TABLE_GROWTH_PCT,
        k::POW_EPOCH_BLOCKS
    );
    println!();

    let entete = q21_core::block::BlockHeader {
        version: 1,
        prev_block: q21_core::hash::Hash256::ZERO,
        merkle_root: q21_core::hash::Hash256([3u8; 32]),
        uncles_root: q21_core::hash::Hash256::ZERO,
        miner: q21_core::hash::Hash256([4u8; 32]),
        time: 1_755_000_000,
        bits: k::INITIAL_BITS,
        height: 1,
        nonce: 0,
    };

    print!("  Construction du cache... ");
    let _ = std::io::stdout().flush();
    let t0 = std::time::Instant::now();
    let cache = memhard::cache_for(params, 0);
    println!("{:.2} s", t0.elapsed().as_secs_f64());

    if sans_table {
        // Mode noeud : on ne mesure que ce que coute la verification, sans
        // jamais materialiser les 2 Gio du mineur.
        let sans = debit_rapide(std::time::Duration::from_secs(3), |i| {
            let mut h = entete;
            h.nonce = i;
            std::hint::black_box(memhard::hash_verify_avec_cache(&h, params, &cache));
        });
        println!();
        println!(
            "  Verification    {sans:>12.0} blocs/s   ({:.0} us par bloc)",
            1e6 / sans.max(1e-9)
        );
        println!(
            "  Rattrapage      {:>12.0} s pour 10 ans de chaine ({} blocs)",
            (10.0 * 365.25 * 86400.0 / k::TARGET_BLOCK_SECS as f64) / sans.max(1e-9),
            (10.0 * 365.25 * 86400.0 / k::TARGET_BLOCK_SECS as f64) as u64
        );
        return Ok(());
    }

    print!("  Construction de la table... ");
    let _ = std::io::stdout().flush();
    let t0 = std::time::Instant::now();
    let table = PowTable::build_avec_cache(&cache, params, 0);
    println!("{:.1} s", t0.elapsed().as_secs_f64());

    /// Mesure a budget de temps constant.
    ///
    /// Un nombre d'essais fixe est inutilisable ici : entre la strategie la plus
    /// rapide et la plus lente il y a deux ordres de grandeur, et l'une des deux
    /// finirait soit en microsecondes soit en heures.
    fn debit(budget: std::time::Duration, essai: impl FnMut(u64)) -> f64 {
        debit_rapide(budget, essai)
    }

    fn debit_rapide(budget: std::time::Duration, mut essai: impl FnMut(u64)) -> f64 {
        let t0 = std::time::Instant::now();
        let mut n = 0u64;
        loop {
            for _ in 0..16 {
                essai(n);
                n += 1;
            }
            if t0.elapsed() >= budget {
                break;
            }
        }
        n as f64 / t0.elapsed().as_secs_f64()
    }

    let budget = std::time::Duration::from_secs(3);

    let avec = debit(budget, |i| {
        let mut h = entete;
        h.nonce = i;
        std::hint::black_box(memhard::hash_mining(&h, &table));
    });
    let sans = debit(budget, |i| {
        let mut h = entete;
        h.nonce = i;
        std::hint::black_box(memhard::hash_verify_avec_cache(&h, params, &cache));
    });

    println!();
    println!("  Avec table      {avec:>12.0} tentatives/s");
    println!("  Sans table      {sans:>12.0} tentatives/s");
    println!("  Avantage table  {:>12.1} x", avec / sans.max(1e-9));

    // -----------------------------------------------------------------------
    // Courbe du compromis temps-memoire
    // -----------------------------------------------------------------------
    //
    // Le rapport ci-dessus compare deux extremes qu'aucun concepteur de circuit
    // ne choisit. La vraie question est : que coute une tentative quand on ne
    // detient qu'une fraction de la table ? On reutilise la table deja
    // construite et on se contente d'en ignorer la fin — c'est exactement ce
    // que ferait un mineur ayant achete moins de memoire.
    println!();
    println!("  Compromis temps-memoire");
    println!("  fraction    memoire        tentatives/s   cout relatif");
    println!("  --------------------------------------------------------");

    let mut partielle = PartialTable::depuis_table(table, cache.clone());
    let fractions: &[(u32, u32)] = &[(1, 1), (1, 2), (1, 4), (1, 8), (1, 16), (1, 64), (0, 1)];
    let mut reference = 0.0f64;

    for &(num, den) in fractions {
        partielle.restreindre(num, den);
        let d = debit(budget, |i| {
            let mut h = entete;
            h.nonce = i;
            std::hint::black_box(memhard::hash_mining_partial(&h, &partielle));
        });
        if num == 1 && den == 1 {
            reference = d;
        }
        println!(
            "  {:<10} {:>8.0} Mio  {:>12.0}   {:>8.1} x",
            format!("{num}/{den}"),
            partielle.memory_bytes() as f64 / 1024.0 / 1024.0,
            d,
            reference / d.max(1e-9)
        );
    }

    println!();
    println!("  Lecture");
    println!();
    println!("  Le cout relatif de la derniere ligne est le facteur qu'un circuit");
    println!("  sans table doit compenser. Il ne se compense pas seulement par du");
    println!(
        "  calcul : refuser la table multiplie par {} le nombre d'acces",
        k::POW_J
    );
    println!("  memoire, donc la bande passante — que le silicium ne fabrique pas.");
    println!();
    println!("  Le detail de la mesure et son verdict sont dans PHASE6.md.");
    Ok(())
}

/// Identifiant du bloc de genese, pour verification avant de rejoindre.
///
/// # Pourquoi cette commande existe
///
/// Rejoindre un reseau, c'est decider a quelle chaine on croit. Cette decision
/// se prend une fois, et elle tient a un seul nombre : l'identifiant du bloc de
/// genese. Deux noeuds qui ne l'ont pas en commun ne se parleront jamais
/// utilement — et il vaut mieux le constater en trois secondes qu'apres une
/// heure de synchronisation qui n'aboutit pas.
///
/// La genese de Q21 n'est distribuee par personne : elle est **deterministe**.
/// Chacun la calcule chez lui a partir du code, et compare. Il n'y a donc rien
/// a telecharger, et personne a croire — c'est exactement la propriete qu'on
/// veut pour la racine d'une chaine.
fn cmd_genese(reseau: Option<&str>) -> Result<(), String> {
    let reseaux: Vec<Network> = match reseau {
        Some(n) => vec![reseau_depuis_nom(n)?],
        None => vec![Network::Regtest, Network::Testnet],
    };
    println!("Genese");
    println!();
    for r in reseaux {
        let g = genesis_block(r);
        println!("  {}", nom_de_reseau(r));
        println!("    identifiant   {}", g.header.block_id());
        println!("    horodatage    {}", g.header.time);
        println!("    difficulte    {:#010x}", g.header.bits);
        println!(
            "    message       {}",
            String::from_utf8_lossy(&g.transactions[0].inputs[0].witness.signature)
        );
        println!("    port P2P      {}", q21_core::amorce::port_par_defaut(r));
        let amorces = q21_core::amorce::amorces_integrees(r);
        if amorces.is_empty() {
            println!("    amorces       aucune (reseau non ouvert)");
        } else {
            println!("    amorces       {}", amorces.join(", "));
        }
        println!();
    }
    println!("  Cette valeur ne vient d'aucun serveur : elle se recalcule a partir du");
    println!("  code. Si la votre differe de celle de quelqu'un d'autre, vous n'etes");
    println!("  pas sur la meme chaine — et aucune synchronisation n'y changera rien.");
    Ok(())
}

fn cmd_securite() -> Result<(), String> {
    use q21_core::consensus as k;
    println!("Attaque a 51 % — ce que Q21 protege, et ce qu'il ne protege pas");
    println!();
    println!("IMPOSSIBLE A EMPECHER, ET C'EST UN THEOREME");
    println!();
    println!("  Le consensus definit la chaine valide comme celle qui porte le plus");
    println!("  de travail. Un adversaire majoritaire en produit plus que tous les");
    println!("  autres reunis, par definition. Refuser sa chaine supposerait de");
    println!("  savoir que c'est lui : une identite, donc une autorite, donc la fin");
    println!("  du caractere sans permission.");
    println!();
    println!("  Quiconque vend une immunite au 51 % vend une autorite deguisee.");
    println!();
    println!("CE QU'UN ATTAQUANT A 51 % PEUT FAIRE");
    println!();
    println!("  - reorganiser les blocs recents, donc annuler ses propres paiements");
    println!("  - refuser d'inclure certaines transactions (censure)");
    println!();
    println!("CE QU'IL NE PEUT PAS FAIRE, MEME AVEC 99 % DE LA PUISSANCE");
    println!();
    println!("  - voler une piece dont il n'a pas la clef");
    println!("      protege par la signature, pas par le consensus");
    println!("  - fabriquer une seule unite au-dela de la subvention");
    println!("      chaque noeud verifie la coinbase, seul, sans faire confiance");
    println!("  - relever le plafond de 21 000 001");
    println!("  - changer une regle : ses blocs sont rejetes et il mine une chaine");
    println!("      que personne ne regarde");
    println!();
    println!("CE QUE Q21 AJOUTE POUR EN LIMITER LA PORTEE");
    println!();
    println!("  - choix par travail cumule, jamais par longueur de chaine");
    println!(
        "  - finalite glissante : aucune reorganisation au-dela de {} blocs ({} h)",
        k::MAX_REORG_DEPTH,
        k::MAX_REORG_DEPTH * k::TARGET_BLOCK_SECS / 3600
    );
    println!(
        "  - au-dela de {} blocs de profondeur, une fourche doit montrer +{} %",
        k::REORG_PENALTY_FROM_DEPTH,
        k::REORG_PENALTY_PCT_PER_BLOCK
    );
    println!("      de travail par bloc supplementaire");
    println!("  - preuve de travail memory-hard : aucun marche de location de");
    println!("      puissance n'existe pour un algorithme neuf, et c'est la vraie");
    println!("      protection d'une petite chaine a ses debuts");
    println!("  - recompenses d'oncles : le gros mineur perd son avantage");
    println!("      super-lineaire dans les courses de propagation");
    println!();
    println!("LE COUT DE LA FINALITE GLISSANTE, DIT FRANCHEMENT");
    println!();
    println!("  Elle ne supprime pas l'attaque, elle en change la nature. Une");
    println!(
        "  partition reseau durant plus de {} blocs produit deux chaines qui ne",
        k::MAX_REORG_DEPTH
    );
    println!("  se reconcilieront jamais seules. On echange un risque de reecriture");
    println!("  silencieuse contre un risque de scission visible. Une scission se");
    println!("  diagnostique et se repare ; une reecriture profonde vole des gens");
    println!("  sans bruit.");
    Ok(())
}

fn cmd_node(datadir: &Path, args: &[String]) -> Result<(), String> {
    use q21_core::net::Node;
    use std::sync::atomic::Ordering;

    let mut ecoute: Option<String> = None;
    let mut vers: Vec<String> = Vec::new();
    let mut mine = false;
    let mut duree = 0u64;
    let mut rpc: Option<String> = None;
    let mut rpc_token: Option<String> = None;
    let mut rpc_wallet = false;
    let mut fils: usize = 0;
    let mut cible_pairs: usize = 8;
    let mut silencieux = false;
    let mut index_adresses = false;
    let mut reseau_impose: Option<Network> = None;
    let mut sans_amorces = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" if i + 1 < args.len() => {
                ecoute = Some(args[i + 1].clone());
                i += 2;
            }
            "--connect" | "--amorce" if i + 1 < args.len() => {
                vers.push(args[i + 1].clone());
                i += 2;
            }
            // Un noeud public ne veut pas des amorces integrees : il **est**
            // l'amorce. Sans cela, deux points d'entree d'un meme reseau
            // passeraient leur temps a se rappeler l'un l'autre.
            "--sans-amorces" => {
                sans_amorces = true;
                i += 1;
            }
            "--rpc" if i + 1 < args.len() => {
                rpc = Some(args[i + 1].clone());
                i += 2;
            }
            "--rpc-token" if i + 1 < args.len() => {
                rpc_token = Some(args[i + 1].clone());
                i += 2;
            }
            "--rpc-wallet" => {
                rpc_wallet = true;
                i += 1;
            }
            "--mine" => {
                mine = true;
                i += 1;
            }
            // Le rapport d'etat toutes les deux secondes est precieux quand on
            // fait tourner un noeud, et nuisible dans un portefeuille : il
            // noyait l'adresse a ouvrir sous des dizaines de lignes identiques,
            // au point qu'un utilisateur a cru que rien ne se passait.
            "--silencieux" => {
                silencieux = true;
                i += 1;
            }
            "--seconds" if i + 1 < args.len() => {
                duree = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "--fils" if i + 1 < args.len() => {
                fils = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "--pairs" if i + 1 < args.len() => {
                cible_pairs = args[i + 1].parse().unwrap_or(8);
                i += 2;
            }
            // L'index d'adresses se paie en disque et en ecriture a chaque
            // bloc. Un noeud qui valide la chaine et garde un portefeuille n'en
            // a aucun besoin : il ne cherche que ses propres adresses, et il
            // sait lesquelles. Voir `q21_core::index`.
            "--index-adresses" => {
                index_adresses = true;
                i += 1;
            }
            // Un noeud d'amorcage n'a pas de portefeuille : il faut donc lui
            // dire de quelle chaine il s'agit. Avec un portefeuille, c'est lui
            // qui porte la reponse et cette option devient un controle.
            "--reseau" if i + 1 < args.len() => {
                reseau_impose = Some(reseau_depuis_nom(&args[i + 1])?);
                i += 2;
            }
            autre => return Err(format!("option inconnue : {autre}")),
        }
    }

    // Le gestionnaire d'arret est installe avant toute chose : un Ctrl-C
    // pendant le chargement doit deja etre entendu.
    if !q21_core::arret::installer() {
        eprintln!(
            "avertissement : le systeme a refuse le gestionnaire d'arret.\n               Un Ctrl-C tuera le processus sans ecrire l'instantane ni le reservoir."
        );
    }

    let mut etat = charger_avec(datadir, reseau_impose)?;
    let sans_portefeuille = etat.sans_portefeuille;

    // --- Ce qu'un noeud sans portefeuille ne fait pas.
    //
    // Miner sur une coquille enverrait la subvention a une clef derivee d'une
    // graine qui n'est ecrite nulle part : la piece serait creee, valide, et
    // perdue au premier redemarrage. Mieux vaut refuser bruyamment que produire
    // de la monnaie que personne ne pourra jamais depenser.
    if sans_portefeuille {
        if mine {
            return Err("--mine demande un portefeuille : sans lui, la subvention \
                        irait a une clef qui mourra avec le processus.\n                          Creez-en un (q21 init testnet), ou retirez --mine."
                .into());
        }
        if rpc_wallet {
            return Err("--rpc-wallet demande un portefeuille.".into());
        }
        println!("  sans portefeuille : aucune methode de portefeuille servie");
    }
    let reseau = etat.chain.network;
    let hauteur_depart = etat.chain.height();
    etat.chain.set_mining_threads(fils);
    let fils_effectifs = etat.chain.mining_threads();
    let node = std::sync::Arc::new(Node::new(reseau, etat.chain));
    let wallet = std::sync::Arc::new(std::sync::Mutex::new(etat.wallet));
    let archive = etat.archive.clone();
    // Le journal est branche avant qu'un seul bloc puisse entrer : tout bloc
    // accepte — y compris ceux recus du reseau, et ceux des branches laterales —
    // est ecrit sur disque au moment ou il est accepte.
    node.set_journal(archive.clone());

    // --- L'index d'adresses, si on l'a demande.
    //
    // Invariant tenu ici, et il est volontairement grossier : **l'index colle
    // exactement au sommet de la chaine, ou bien il est reconstruit depuis
    // zero**. Rien entre les deux.
    //
    // La raison tient a la table des proprietaires de sorties, qui repond a
    // « a qui appartenait la sortie que cette entree depense ». Elle se reprend
    // de l'ensemble UTXO du noeud, lequel ne connait que les sorties **encore
    // vivantes**. Si l'index accusait un retard de quelques blocs, les sorties
    // creees avant ce retard et depensees pendant lui auraient disparu de
    // l'UTXO : les depenses correspondantes seraient attribuees a personne, et
    // l'ecran d'une adresse montrerait ses receptions sans ses envois.
    //
    // Tenir une table qui survive au retard demanderait de journaliser aussi
    // les sorties consommees, donc plus de disque et une nouvelle facon de se
    // tromper. Reconstruire coute le prix d'un balayage — celui que le
    // portefeuille paie deja — et ne peut pas mentir.
    let index = if index_adresses {
        let mut i = q21_core::index::Index::ouvrir(&chemin_index(datadir));
        let (hauteur, id_sommet) = node.with_chain(|c| (c.height(), c.active_at(c.height())));
        let colle = !i.est_vide() && i.hauteur() == hauteur && i.identifiant(hauteur) == id_sommet;
        if colle {
            node.with_chain(|c| i.amorcer(&c.utxo));
            println!("  index d'adresses : {} bloc(s) repris", i.blocs_indexes());
        } else {
            if !i.est_vide() {
                println!("  index d'adresses : desynchronise, reconstruction");
            }
            i.effacer();
            let debut = std::time::Instant::now();
            node.with_chain(|c| {
                for h in 0..=c.height() {
                    if let Some(b) = c.block_at(h) {
                        if let Err(e) = i.indexer(&b) {
                            eprintln!("avertissement : {e}");
                            break;
                        }
                    }
                }
            });
            println!(
                "  index d'adresses : {} bloc(s), {} adresse(s), en {:.2} s",
                i.blocs_indexes(),
                i.adresses_connues(),
                debut.elapsed().as_secs_f64()
            );
        }
        Some(std::sync::Arc::new(std::sync::Mutex::new(i)))
    } else {
        None
    };

    // --- Le reservoir de la session precedente.
    //
    // Chaque transaction repasse par `accept`, qui la revalide contre la chaine
    // telle qu'elle est **maintenant**. La chaine a pu avancer pendant l'arret :
    // certaines sont deja confirmees, d'autres sont devenues impossibles. Un
    // reservoir relu n'est jamais cru sur parole.
    if let Ok(clef) = q21_core::state::clef_de_repertoire(datadir) {
        let magasin = q21_core::state::MempoolStore::new(chemin_reservoir(datadir), clef);
        if magasin.exists() {
            match magasin.load() {
                Ok(attente) => {
                    let mut reprises = 0usize;
                    let total = attente.len();
                    for tx in &attente {
                        let ok = node.with_chain_and_mempool(|c, m| {
                            m.accept(tx, &c.utxo, reseau, c.height()).is_ok()
                        });
                        if ok {
                            reprises += 1;
                        }
                    }
                    if total > 0 {
                        println!("  reservoir : {reprises} transaction(s) reprise(s) sur {total}");
                    }
                }
                Err(e) => eprintln!("avertissement : reservoir ignore ({e})"),
            }
        }
    }

    if !silencieux {
        println!("Noeud Q21 — reseau {reseau:?}, hauteur {hauteur_depart}");
    }

    if let Some(a) = &ecoute {
        let local = node
            .listen(&q21_core::amorce::adresse_d_ecoute(a, reseau))
            .map_err(|e| format!("ecoute impossible : {e}"))?;
        println!("  ecoute sur {local}");
    }
    // --- Ce vers quoi on tente de sortir.
    //
    // Trois sources, dans cet ordre : ce que la ligne de commande demande, le
    // fichier `amorces.txt` du dossier, puis la liste integree au binaire. Les
    // deux premieres l'emportent, parce qu'elles viennent de l'exploitant et
    // que la troisieme vient de moi.
    let mut cibles: Vec<String> = vers.clone();
    if !sans_amorces {
        cibles.extend(q21_core::amorce::amorces_du_dossier(datadir));
        cibles.extend(
            q21_core::amorce::amorces_integrees(reseau)
                .iter()
                .map(|s| s.to_string()),
        );
    }
    cibles.dedup();
    if cibles.is_empty() && ecoute.is_none() {
        println!(
            "  aucune amorce : ce noeud ne cherchera personne. Donnez-lui\n               --amorce <hote> ou un fichier amorces.txt dans {}",
            datadir.display()
        );
    }
    for a in &cibles {
        match q21_core::amorce::resoudre(a, reseau) {
            Ok(adresses) => {
                // Un nom peut rendre plusieurs adresses. On s'arrete a la
                // premiere qui repond : les autres serviront si celle-ci tombe,
                // et le carnet les aura retenues.
                let mut ouverte = false;
                for sa in &adresses {
                    match node.connect(*sa) {
                        Ok(_) => {
                            println!("  connexion vers {a} ({sa})");
                            ouverte = true;
                            break;
                        }
                        Err(e) => eprintln!("  echec vers {a} ({sa}) : {e}"),
                    }
                }
                if !ouverte && adresses.len() > 1 {
                    eprintln!("  {a} : aucune des {} adresses n'a repondu", adresses.len());
                }
            }
            Err(e) => eprintln!("  amorce illisible : {e}"),
        }
    }
    // Carnet d'adresses : ce qui a ete appris lors des sessions precedentes.
    let carnet = AddrStore::new(chemin_pairs(datadir));
    let appris: Vec<q21_core::wire::NetAddr> = carnet
        .load(reseau != Network::Mainnet, maintenant())
        .toutes()
        .iter()
        .map(|e| e.addr)
        .collect();
    if !appris.is_empty() {
        let n = node.seed_addresses(&appris);
        println!("  carnet : {n} adresses rechargees");
    }
    // L'interrupteur du minage. Il part de la valeur du drapeau `--mine`, mais
    // ne s'y arrete plus : l'interface peut l'allumer et l'eteindre sans qu'on
    // relance quoi que ce soit. Le drapeau devient une preference de depart.
    let minage = std::sync::Arc::new(q21_core::minage::Minage::new(mine));
    // Beneficiaire courant du minage. `None` signifie « il en faut un neuf ».
    let mut beneficiaire_minage: Option<(q21_core::hash::Hash256, SchemeId)> = None;
    // Hauteur a laquelle la derniere tentative de decouverte a eu lieu.
    let mut derniere_decouverte: u64 = 0;
    if mine {
        println!("  minage actif sur {fils_effectifs} fil(s)");
    }

    // --- Le RPC ne sort pas de la machine sans qu'on l'ait dit deux fois.
    //
    // Le controle d'en-tete `Host` refuse deja toute requete qui ne se presente
    // pas comme locale, et le jeton garde chaque methode. Mais lier le service a
    // une interface publique reste une decision qu'on peut prendre par
    // distraction — en recopiant l'adresse d'ecoute P2P, par exemple — et ses
    // consequences ne se voient pas : le service repond, simplement il repond a
    // tout le monde.
    //
    // Sur un serveur d'amorcage, le P2P doit etre joignable et le RPC non. Les
    // deux options se ressemblent trop pour qu'on laisse la confusion passer en
    // silence.
    if let Some(adresse) = &rpc {
        let local = adresse.starts_with("127.")
            || adresse.starts_with("localhost:")
            || adresse.starts_with("[::1]");
        if !local {
            if rpc_token.is_none() {
                return Err(format!(
                    "refus : --rpc {adresse} sort de la boucle locale et aucun jeton \n                       n'est fourni. Toute machine qui vous atteint pourrait interroger\n                       ce noeud.\n\n                       Restez local :   --rpc 127.0.0.1:21080\n                       Ou exigez un jeton : --rpc-token <secret>"
                ));
            }
            eprintln!(
                "AVERTISSEMENT : le RPC ecoute sur {adresse}, hors de la boucle locale.\n\
                 \x20              Le controle d'en-tete Host refusera les requetes qui ne se\n\
                 \x20              presentent pas comme locales, mais le service est joignable.\n\
                 \x20              Un noeud d'amorcage n'a aucune raison d'exposer son RPC."
            );
        }
    }

    let _serveur = if let Some(adresse) = &rpc {
        // Toute operation qui modifie le portefeuille est ecrite sur disque
        // immediatement. Une depense qui ne serait consignee qu'en memoire
        // disparaitrait au prochain arret — et sur un schema a usage unique,
        // la clef correspondante resservirait.
        let dossier = datadir.to_path_buf();
        let ctx = q21_core::rpc::RpcContext {
            node: node.clone(),
            wallet: if rpc_wallet {
                Some(wallet.clone())
            } else {
                None
            },
            network: reseau,
            index: index.clone(),
            // Le nœud sans portefeuille ne recoit pas l'interrupteur : il n'a
            // nulle part ou verser une subvention, et le refus est plus honnete
            // qu'un bouton qui ne ferait rien.
            minage: if sans_portefeuille {
                None
            } else {
                Some(minage.clone())
            },
            sur_changement: if sans_portefeuille {
                None
            } else {
                Some(std::sync::Arc::new(move |w: &Wallet| {
                    if let Err(e) = ecrire_portefeuille(&dossier, w) {
                        eprintln!("ALERTE : portefeuille non enregistre apres modification : {e}");
                    }
                }))
            },
        };
        // La coquille de l'explorateur est servie sans jeton : elle ne porte
        // aucune donnee, et c'est elle qui demande le jeton a l'utilisateur.
        // Toute methode RPC, elle, reste derriere l'authentification.
        // Les deux coquilles statiques. Elles ne portent aucune donnee : c'est
        // le JavaScript qui interroge le RPC, et le RPC exige le jeton.
        const PUBLICS: &[&str] = &["/", "/index.html", "/portefeuille", "/portefeuille.html"];
        let h =
            q21_core::http::serve_avec_public(adresse, rpc_token.clone(), PUBLICS, move |req| {
                servir(&ctx, req)
            })
            .map_err(|e| e.to_string())?;

        // En mode silencieux, le lanceur a deja tout dit : repeter l'adresse et
        // les avertissements ne ferait que rallonger ce que l'utilisateur doit
        // lire pour trouver le lien.
        if !silencieux {
            println!("  RPC et explorateur sur http://{}", h.addr);
            if rpc_wallet {
                println!("  ATTENTION : methodes de portefeuille actives sur ce port.");
            } else {
                println!("  Portefeuille desactive (--rpc-wallet pour l'activer).");
            }
            if rpc_token.is_some() {
                // --- Ce message proposait le jeton dans l'adresse.
                //
                // `?token=...` a cesse d'ouvrir quoi que ce soit — une adresse
                // finit dans l'historique du navigateur, dans les journaux d'un
                // mandataire et dans l'en-tete `Referer` — mais ce conseil-la
                // survivait a la correction, et invitait donc a faire
                // exactement ce qu'on venait d'interdire.
                println!("  Jeton exige. Les pages le demandent a l'ouverture.");
            }
        }
        Some(h)
    } else {
        None
    };

    if !silencieux {
        println!("  Ctrl-C pour arreter");
        println!();
    }

    let debut = std::time::Instant::now();
    let mut dernier_rapport = std::time::Instant::now();
    let mut derniere_hauteur = node.height();
    let mut dernier_tour = std::time::Instant::now();
    let mut derniere_recherche = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(60))
        .unwrap_or_else(std::time::Instant::now);

    loop {
        if duree > 0 && debut.elapsed().as_secs() >= duree {
            break;
        }
        // Ctrl-C : on sort de la boucle plutot que de se faire tuer sur place.
        // Tout ce que ce noeud doit ecrire — reservoir, instantane, carnet,
        // portefeuille — se trouve apres cette boucle, et n'etait jamais
        // atteint.
        if q21_core::arret::demande() {
            if !silencieux {
                println!();
            }
            println!("  Arret demande. Ecriture en cours...");
            break;
        }

        // Maintien des connexions sortantes.
        //
        // Le carnet ne rend que des adresses de groupes reseau distincts, et
        // distincts de ceux deja connectes : c'est ce qui empeche un adversaire
        // detenant une seule plage d'occuper toutes les places. Voir `addr`.
        // --- La machine s'est-elle endormie ?
        //
        // Cette boucle tourne toutes les deux cents millisecondes. Un tour qui
        // dure une minute ne peut pas etre du travail : la machine a ete mise
        // en veille, et pendant ce temps toutes ses liaisons TCP sont mortes —
        // le routeur a oublie sa table, le pair d'en face a renonce.
        //
        // Attendre le delai de silence ferait perdre deux minutes de plus a
        // quelqu'un qui vient simplement de rouvrir son portable. On coupe donc
        // tout de suite, et on redemande les amorces au tour suivant. Se
        // tromper ne coute qu'une reconnexion.
        if dernier_tour.elapsed() >= std::time::Duration::from_secs(60) {
            let n = node.couper_tous_les_pairs();
            if n > 0 {
                println!("  reveil apres veille : {n} liaison(s) coupee(s), on recommence");
            }
            derniere_recherche = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(60))
                .unwrap_or_else(std::time::Instant::now);
        }
        dernier_tour = std::time::Instant::now();

        if derniere_recherche.elapsed().as_secs() >= 15 {
            derniere_recherche = std::time::Instant::now();

            // --- D'abord, liberer les places occupees par des pairs morts.
            //
            // Une connexion TCP peut survivre a la machine d'en face : un
            // portable dont on referme l'ecran ne dit rien en partant. Sans ce
            // menage, le noeud croit avoir un pair, ne cherche donc personne, et
            // reste bloque a la hauteur ou il en etait. C'est arrive sur un
            // vrai MacBook : hauteur 442, plus rien pendant que l'autre machine
            // continuait a miner.
            let coupes = node.entretenir_pairs();
            if coupes > 0 && !silencieux {
                println!("  {coupes} pair(s) silencieux coupe(s)");
            }

            let manquants = cible_pairs.saturating_sub(node.peer_count());
            if manquants > 0 {
                // --- Les amorces explicites d'abord.
                //
                // Elles ne sont pas dans le carnet tant qu'aucune poignee de
                // main n'a abouti — et c'est precisement quand rien n'aboutit
                // qu'on en a besoin. Ce que l'utilisateur a ecrit en ligne de
                // commande doit etre reessaye tant qu'il manque des pairs.
                for a in &cibles {
                    if let Ok(adresses) = q21_core::amorce::resoudre(a, reseau) {
                        for sa in adresses {
                            if node.est_connecte_a(sa) {
                                continue;
                            }
                            if node.connect(sa).is_ok() {
                                if !silencieux {
                                    println!("  reconnexion vers {a} ({sa})");
                                }
                                break;
                            }
                        }
                    }
                }
                // --- Puis le carnet, pour les places restantes.
                let manquants = cible_pairs.saturating_sub(node.peer_count());
                for a in node.addresses_to_try(manquants) {
                    let sa = std::net::SocketAddr::from((a.ip, a.port));
                    match node.connect(sa) {
                        Ok(_) => node.note_connect_success(a.ip, a.port),
                        Err(_) => node.note_connect_failure(a.ip, a.port),
                    }
                }
            }
        }

        if minage.actif() {
            // --- Une adresse par bloc trouve, et non par tentative.
            //
            // Cette ligne derivait une adresse neuve **a chaque tour de
            // boucle**. Mesure faite sur le reseau d'essai : six secondes de
            // minage avaient consomme 149 indices pour 102 blocs. Le
            // portefeuille gonflait sans raison, la liste des adresses devenait
            // illisible, et le cache d'adresses etait reecrit vingt fois par
            // seconde. Sur un schema a usage unique — Lamport, encore accepte en
            // regtest — c'aurait ete pire qu'un gaspillage.
            //
            // On garde donc le beneficiaire tant qu'aucun bloc n'est sorti. Une
            // adresse par recompense reste la bonne granularite : elle evite de
            // relier publiquement toutes ses recompenses entre elles.
            //
            // La derivation reste hors du verrou de la chaine : tenir deux
            // verrous a la fois est le plus court chemin vers l'interblocage.
            if beneficiaire_minage.is_none() {
                let mut w = wallet.lock().map_err(|_| "portefeuille verrouille")?;
                let a = w.new_address();
                beneficiaire_minage = Some((a.hash, a.scheme));
            }
            let (beneficiaire, schema) = beneficiaire_minage.expect("derive juste au-dessus");
            // Les transactions du mempool entrent dans le bloc, dans l'ordre
            // topologique impose par la selection.
            let selection = node.with_mempool(|m| m.select_for_block(2_000_000));
            // La variante comptante : le debit affiche a l'ecran doit etre une
            // mesure, pas une estimation tiree du plafond d'essais.
            let (bloc, essais) = node.with_chain(|c| {
                let t = maintenant().max(c.tip().time + 1);
                c.mine_block_comptant(beneficiaire, schema, &selection, t, 2_000_000)
            });
            minage.compter(essais);
            if let Some(b) = bloc {
                let ok = node.with_chain(|c| c.connect(&b, maintenant()).is_ok());
                if ok {
                    minage.bloc_trouve();
                    // La recompense est encaissee : l'adresse a servi, la
                    // suivante en aura une autre.
                    beneficiaire_minage = None;
                    node.with_mempool(|m| m.on_block_connected(&b));
                    // L'ecriture passe par le journal, comme pour tout bloc
                    // accepte : une seule voie vers le disque, donc un seul
                    // endroit ou l'oublier.
                    q21_core::chain::Journal::consigner(archive.as_ref(), &b);
                    node.announce_block(&b);
                }
            }
        } else {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        // --- La decouverte d'adresses, retentee tant qu'elle a un sens.
        //
        // Le declencheur du chargement ne couvre qu'un cas : celui ou la chaine
        // est deja la. Sur une machine neuve, l'ordre est inverse — on restaure,
        // *puis* on se synchronise — et la decouverte n'aurait jamais lieu. Le
        // porteur verrait zero pendant que ses fonds arrivent sous ses yeux.
        //
        // On retente donc, mais rarement : la condition `next_index <= 1` cesse
        // d'etre vraie des la premiere trouvaille, et le compteur de hauteur
        // evite de rederiver deux cents clefs ML-DSA a chaque bloc recu.
        if !sans_portefeuille {
            let h = node.height();
            if h > derniere_decouverte + 20 {
                derniere_decouverte = h;
                let vierge = {
                    let w = wallet.lock().map_err(|_| "portefeuille verrouille")?;
                    w.next_index() <= 1
                };
                if vierge {
                    let trouvees = node.with_chain(|c| {
                        let u = &c.utxo;
                        if u.is_empty() {
                            return 0;
                        }
                        let mut w = match wallet.lock() {
                            Ok(w) => w,
                            Err(_) => return 0,
                        };
                        w.decouvrir(|e| u.connait(e))
                    });
                    if trouvees > 0 {
                        let w = wallet.lock().map_err(|_| "portefeuille verrouille")?;
                        println!(
                            "  restauration : {trouvees} sortie(s) retrouvee(s), {} adresse(s) rederivee(s)",
                            w.next_index()
                        );
                        let _ = ecrire_portefeuille(datadir, &w);
                    }
                }
            }
        }

        // --- L'index suit la chaine.
        //
        // Il n'est pas branche dans le noeud lui-meme : un index est un
        // confort, et le chemin d'acceptation des blocs est ce qu'il y a de
        // plus sensible dans ce programme. On l'observe de l'exterieur, au
        // rythme de la boucle, sans rien pouvoir casser du consensus.
        if let Some(index) = &index {
            if let Ok(mut i) = index.lock() {
                suivre_index(&mut i, &node);
            }
        }

        if !silencieux && dernier_rapport.elapsed().as_secs() >= 2 {
            let h = node.height();
            let s = &node.stats;
            println!(
                "hauteur {h} (+{})  pairs {} ({} groupes, carnet {})  mempool {}  \
                 blocs recus {}  compacts {} dont {} sans aller-retour  \
                 orphelins {}  invalides {}",
                h.saturating_sub(derniere_hauteur),
                node.peer_count(),
                node.peer_groups(),
                node.address_count(),
                node.mempool_len(),
                s.blocs_recus.load(Ordering::Relaxed),
                s.compacts_recus.load(Ordering::Relaxed),
                s.compacts_sans_aller_retour.load(Ordering::Relaxed),
                s.blocs_orphelins.load(Ordering::Relaxed),
                s.blocs_invalides.load(Ordering::Relaxed),
            );
            derniere_hauteur = h;
            dernier_rapport = std::time::Instant::now();
        }
    }

    node.shutdown();
    if !sans_portefeuille {
        if let Ok(w) = wallet.lock() {
            let _ = ecrire_portefeuille(datadir, &w);
        }
    }
    // Le carnet survit a l'arret : sans cela, chaque redemarrage repartirait de
    // l'amorcage, ce qui donne a quiconque controle ce point d'amorcage un
    // pouvoir qu'il ne devrait pas avoir.
    // Les entrees sont ecrites telles quelles : les echecs et la date du dernier
    // succes font partie de ce que ce noeud a constate lui-meme, et c'est
    // precisement ce qui permet de distinguer un pair reel d'une adresse
    // simplement annoncee. Les reconstruire a zero revenait a tout oublier.
    if let Err(e) = carnet.save_entrees(&node.address_entries()) {
        eprintln!("avertissement : carnet non ecrit : {e}");
    }
    // --- Le reservoir survit a l'arret.
    //
    // Une transaction envoyee y patiente qu'un mineur la prenne. Elle n'etait
    // ecrite nulle part : arreter le logiciel avant qu'elle soit minee
    // l'effacait, sans un mot. Un premier utilisateur l'a vecu — envoi, arret
    // pour lancer le minage, transaction disparue.
    //
    // Sur un reseau peuple, un pair l'aurait relayee et gardee. C'est donc le
    // noeud isole — celui d'un portefeuille de bureau — qui payait ce defaut.
    if let Ok(clef) = q21_core::state::clef_de_repertoire(datadir) {
        let attente = node.with_mempool(|m| m.transactions_ordonnees());
        let magasin = q21_core::state::MempoolStore::new(chemin_reservoir(datadir), clef);
        if attente.is_empty() {
            // Un reservoir vide efface le fichier : le laisser ferait ressusciter
            // au prochain demarrage des transactions deja confirmees.
            let _ = magasin.remove();
        } else if let Err(e) = magasin.save(&attente) {
            eprintln!("avertissement : reservoir non ecrit : {e}");
        } else {
            println!("  {} transaction(s) en attente conservee(s)", attente.len());
        }
    }
    // L'instantane est ecrit a l'arret, pas a chaque bloc : c'est une economie
    // de demarrage, pas une donnee dont la perte couterait quoi que ce soit.
    node.with_chain(|c| ecrire_instantane(datadir, c));
    println!();
    println!("Arret. Hauteur finale : {}", node.height());
    // Sur Windows, le gestionnaire de console attend ce signal avant de laisser
    // le systeme tuer le processus.
    q21_core::arret::arret_termine();
    Ok(())
}

/// Routeur HTTP du noeud.
///
/// Deux chemins seulement : la page d'exploration et l'API. Tout le reste rend
/// 404 — une surface reduite est une surface qu'on peut relire.
fn servir(
    ctx: &q21_core::rpc::RpcContext,
    req: q21_core::http::Request,
) -> q21_core::http::Response {
    use q21_core::http::Response;
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            Response::html(q21_core::explorer::PAGE.to_string())
        }
        // Le portefeuille, sur son propre chemin. Les deux pages parlent au
        // meme noeud ; seule celle-ci demande les methodes qui deplacent des
        // fonds, et elles restent desactivees sans `--rpc-wallet`.
        ("GET", "/portefeuille") | ("GET", "/portefeuille.html") => {
            Response::html(q21_core::wallet_ui::PAGE.to_string())
        }
        ("POST", "/rpc") => Response::json(ctx.handle(&req.body)),
        ("GET", "/rpc") => Response::text(
            405,
            "L'API JSON-RPC attend une requete POST. Exemple :\n\n  \
             curl -s -X POST http://127.0.0.1:21080/rpc \\\n    \
             -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getinfo\"}'\n",
        ),
        _ => Response::not_found(),
    }
}

// ===========================================================================
// Le portefeuille de bureau
// ===========================================================================

/// Lance le portefeuille : un noeud complet, une page locale, et le navigateur.
///
/// # Pourquoi un noeud complet, et pas un client leger
///
/// Un client leger demande a un serveur ce que contient la chaine. C'est-a-dire
/// qu'il **fait confiance a quelqu'un** pour connaitre son propre solde. Q21 n'a
/// d'ailleurs aucun protocole de client leger, et en concevoir un introduirait
/// un modele de confiance qui n'existe pas aujourd'hui.
///
/// Ici, le portefeuille **est** un noeud : il valide chaque bloc lui-meme. Ce
/// que la page affiche, cette machine l'a verifie.
///
/// # Le jeton, et pourquoi il voyage dans le fragment
///
/// L'interface a besoin d'un jeton pour parler au RPC. Le mettre dans la
/// requete — `?token=...` — le ferait entrer dans l'historique du navigateur,
/// dans les journaux de tout mandataire, et dans l'en-tete `Referer` de la
/// premiere ressource externe chargee. Un secret qui voyage dans une adresse
/// n'est plus un secret, et c'est une faille que l'audit de la phase 8b a
/// relevee puis fermee.
///
/// Le **fragment** — ce qui suit le `#` — n'est jamais envoye au serveur. Le
/// navigateur le garde pour lui. La page le lit, l'efface aussitot de la barre
/// d'adresse, et l'envoie ensuite en `Authorization`. Il ne laisse donc aucune
/// trace ailleurs que dans la memoire de l'onglet.
fn cmd_wallet(datadir: &Path, args: &[String]) -> Result<(), String> {
    let mut port: u16 = 0;
    let mut sans_navigateur = false;
    let mut reste: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" if i + 1 < args.len() => {
                port = args[i + 1]
                    .parse()
                    .map_err(|_| "port illisible".to_string())?;
                i += 2;
            }
            "--sans-navigateur" => {
                sans_navigateur = true;
                i += 1;
            }
            autre => {
                reste.push(autre.to_string());
                i += 1;
            }
        }
    }

    println!("Portefeuille Q21");
    println!();

    // 1. Un port libre pour le nœud, si l'on n'en impose pas un.
    //
    // Il est tire **avant** l'installation : la page d'installation doit savoir
    // vers ou renvoyer le navigateur quand elle a fini, et elle ne peut pas le
    // demander a un serveur qui n'existe pas encore.
    let port = if port != 0 {
        port
    } else {
        std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("aucun port disponible : {e}"))?
            .local_addr()
            .map_err(|e| e.to_string())?
            .port()
    };

    // 2. Le jeton de la session. Trente-deux octets tires du generateur du
    //    systeme : il n'est pas devinable, et il ne sert que le temps de cette
    //    execution. Le meme sert a l'installation et au nœud — c'est un secret
    //    de session, pas un secret par serveur.
    let brut: [u8; 32] = q21_core::rng::octets()
        .map_err(|_| "generateur d'alea du systeme inaccessible".to_string())?;
    let jeton: String = brut.iter().map(|o| format!("{o:02x}")).collect();

    // 3. L'installation, si le portefeuille n'existe pas encore ou s'il est
    //    scelle et qu'aucune phrase n'a ete fournie autrement.
    //
    // C'est ce qui remplace les deux commandes de terminal d'avant : `init`
    // pour creer, puis la question « Phrase secrete du portefeuille : » posee
    // sur une ligne nue. Les deux se font maintenant dans des ecrans.
    let phrase_deja_fournie = std::env::var("Q21_PASSPHRASE").is_ok_and(|p| !p.is_empty());
    let existe = chemin_portefeuille(datadir).exists();
    let scelle = existe
        && q21_core::kdf::est_scelle(
            &std::fs::read(chemin_portefeuille(datadir)).unwrap_or_default(),
        );
    let installation_necessaire = !existe || (scelle && !phrase_deja_fournie);

    if installation_necessaire {
        installer(datadir, &jeton, port, sans_navigateur, existe && scelle)?;
    }

    // 4. Le portefeuille se lit maintenant sans rien demander : ou bien
    //    l'installation vient de retenir la phrase, ou bien elle etait deja
    //    connue, ou bien le fichier n'est pas scelle.
    lire_portefeuille(datadir)?;

    let adresse = format!("127.0.0.1:{port}");
    let url = format!("http://{adresse}/portefeuille#{jeton}");

    println!();

    // --- L'adresse est toujours affichee.
    //
    // Elle ne l'etait que si l'on renoncait a ouvrir le navigateur. Quand
    // l'ouverture echouait — un systeme sans navigateur par defaut, une session
    // distante, une politique d'entreprise — il ne restait rien a l'ecran, et
    // aucun moyen d'entrer.
    //
    // La montrer ne coute rien : elle s'affiche sur la machine de son
    // proprietaire, dans une fenetre qu'il a ouverte. Ce qu'on refuse, c'est
    // qu'elle parte ailleurs — dans un historique de navigateur, dans les
    // journaux d'un mandataire. Sur son propre ecran, elle est a sa place.
    println!("  Si le navigateur ne s'ouvre pas, ouvrez cette adresse :");
    println!();
    println!("      {url}");
    println!();
    println!("  Le jeton est apres le « # ». Il n'est jamais envoye au serveur");
    println!("  dans l'adresse : le navigateur le garde, la page le lit, puis");
    println!("  l'efface de la barre d'adresse.");
    println!();

    // Le navigateur est deja ouvert si l'installation vient de le faire : la
    // page d'installation renvoie elle-meme vers le portefeuille. En rouvrir un
    // second laisserait deux onglets, dont un mort.
    if !sans_navigateur && !installation_necessaire {
        // Le navigateur s'ouvre une fois le serveur pret. On sonde le port
        // plutot que d'attendre une duree fixe : une duree fixe est toujours
        // trop courte sur une machine chargee et trop longue ailleurs.
        let a = adresse.clone();
        let u = url.clone();
        std::thread::spawn(move || {
            for _ in 0..100 {
                if std::net::TcpStream::connect(&a).is_ok() {
                    if let Err(e) = ouvrir_navigateur(&u) {
                        eprintln!("  Le navigateur n'a pas pu etre ouvert ({e}).");
                        eprintln!("  Ouvrez l'adresse ci-dessus a la main.");
                    }
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            eprintln!("  Le serveur n'a pas repondu. Ouvrez l'adresse ci-dessus a la main.");
        });
    }
    println!("  Le meme nœud sert aussi l'explorateur de la chaine, sur le meme");
    println!("  port : lien en bas de la page, ou http://{adresse}/");
    println!();
    println!("  Cette fenetre fait tourner le portefeuille. Laissez-la ouverte.");
    println!();

    // --- Comment arreter.
    //
    // Ce paragraphe ne disait qu'une chose : « Ctrl-C pour arreter ». C'est
    // exact, et c'etait insuffisant. Sur Windows, un Ctrl-C recu pendant un
    // fichier `.bat` fait poser par l'interpreteur sa propre question —
    // « Terminer le programme de commandes (O/N) ? » — a laquelle les deux
    // reponses ferment la fenetre. Le premier utilisateur l'a lue comme une
    // panne, et a cesse d'oser arreter son portefeuille.
    //
    // On donne donc d'abord la voie qui ne pose aucune question : le bouton.
    println!("  Pour arreter, au choix :");
    println!("    - le bouton « Fermer le portefeuille », onglet Informations ;");
    println!("    - fermer cette fenetre ;");
    println!("    - Ctrl-C ici. Windows demande alors « Terminer le programme");
    println!("      de commandes (O/N) ? » : repondez O. Ce n'est pas une erreur,");
    println!("      tout est deja enregistre quand cette question s'affiche.");
    println!();

    // 5. Le noeud, avec les methodes de portefeuille et le jeton.
    let mut arguments = vec![
        "--rpc".to_string(),
        adresse,
        "--rpc-wallet".to_string(),
        "--rpc-token".to_string(),
        jeton,
        // Pas de rapport d'etat : dans un portefeuille il noie la seule
        // information utile, l'adresse a ouvrir.
        "--silencieux".to_string(),
    ];
    arguments.extend(reste);
    cmd_node(datadir, &arguments)
}

// ===========================================================================
// L'installation, dans des ecrans
// ===========================================================================

/// Cree ou ouvre le portefeuille depuis une page, puis rend la main.
///
/// Le serveur vit le temps de l'echange et meurt ensuite : le nœud demarre
/// apres, sur **son propre port**. Voir l'en-tete de `q21_core::installation`
/// pour ce que ce choix coute et ce qu'il evite.
///
/// La fonction bloque jusqu'a ce que la page dise avoir fini. Quand elle rend
/// la main, le portefeuille existe sur le disque et la phrase secrete est
/// retenue pour la duree du processus.
fn installer(
    datadir: &Path,
    jeton: &str,
    port_noeud: u16,
    sans_navigateur: bool,
    scelle: bool,
) -> Result<(), String> {
    use q21_core::http::Response;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // Le cas ou une chaine existe sans portefeuille : c'est le dossier d'un
    // nœud lance avec `--sans-portefeuille`. Y greffer un portefeuille neuf
    // ecrirait une seconde genese sur la premiere. On refuse, en le disant.
    if !scelle && chemin_blocs(datadir).exists() && !chemin_portefeuille(datadir).exists() {
        return Err(format!(
            "le dossier {} contient une chaine mais aucun portefeuille.\n\n  \
             C'est le dossier d'un nœud sans portefeuille. Prenez-en un autre :\n\n      \
             q21 --datadir <un-dossier-neuf> wallet",
            datadir.display()
        ));
    }

    let fini = Arc::new(AtomicBool::new(false));
    let datadir = datadir.to_path_buf();
    let fini_h = fini.clone();

    // Le reseau du portefeuille de bureau est le reseau d'essai. C'est le seul
    // qui existe, et proposer un choix a une seule reponse est une facon de
    // faire hesiter sans rien offrir. `regtest` reste accessible en ligne de
    // commande, ou vont ceux qui en ont besoin.
    let reseau = Network::Testnet;

    let repondre = move |req: q21_core::http::Request| -> Response {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/bienvenue") => Response::html(q21_core::installation::PAGE.to_string()),
            ("POST", "/installation") => {
                let r = traiter_installation(&datadir, reseau, port_noeud, &req.body, &fini_h);
                Response::json(r.encode())
            }
            _ => Response::not_found(),
        }
    };

    // La coquille HTML est servie sans jeton — sinon la page ne pourrait meme
    // pas se charger pour en demander un. Elle ne porte aucune donnee : c'est
    // la meme regle que pour l'explorateur, et la liste reste nommee chemin par
    // chemin.
    let serveur = q21_core::http::serve_avec_public("127.0.0.1:0", Some(jeton.to_string()), &["/bienvenue"], repondre)
        .map_err(|e| format!("le serveur d'installation n'a pas demarre : {e:?}"))?;
    let url = format!("http://127.0.0.1:{}/bienvenue#{jeton}", serveur.addr.port());

    if scelle {
        println!("  Ce portefeuille est protege par une phrase secrete.");
    } else {
        println!("  Aucun portefeuille ici : on va en creer un.");
    }
    println!();
    println!("  Si le navigateur ne s'ouvre pas, ouvrez cette adresse :");
    println!();
    println!("      {url}");
    println!();

    if !sans_navigateur {
        if let Err(e) = ouvrir_navigateur(&url) {
            eprintln!("  Le navigateur n'a pas pu etre ouvert ({e}).");
            eprintln!("  Ouvrez l'adresse ci-dessus a la main.");
        }
    }

    // On attend que la page dise avoir fini. Sans limite de temps : c'est un
    // humain qui recopie un code de sauvegarde sur du papier, et lui imposer un
    // chronometre serait exactement la mauvaise idee.
    while !fini.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(120));
    }

    // Ce serveur ne meurt pas tout de suite : la page l'interroge encore pour
    // savoir quand le nœud ecoute — elle ne peut pas le demander au nœud
    // lui-meme, qui est sur une autre origine. Un guetteur attend donc que le
    // nœud soit debout, laisse a la page le temps de s'en apercevoir, puis
    // ferme la porte. Laisser un second serveur ouvert pour toute la duree du
    // programme serait de la surface d'attaque sans usage.
    std::thread::spawn(move || {
        let cible = std::net::SocketAddr::from(([127, 0, 0, 1], port_noeud));
        for _ in 0..600 {
            if std::net::TcpStream::connect_timeout(&cible, std::time::Duration::from_millis(200))
                .is_ok()
            {
                std::thread::sleep(std::time::Duration::from_millis(1500));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        serveur.shutdown();
    });
    Ok(())
}

/// Le corps des quatre methodes de l'installation.
///
/// Rend toujours un objet JSON. Une erreur est un champ `erreur` portant une
/// phrase destinee a etre lue par quelqu'un, pas un code.
fn traiter_installation(
    datadir: &Path,
    reseau: Network,
    port_noeud: u16,
    corps: &str,
    fini: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> q21_core::json::Json {
    use q21_core::json::Json;

    let erreur = |m: &str| Json::obj().set("erreur", Json::str(m)).build();

    let requete = match q21_core::json::parse(corps) {
        Ok(j) => j,
        Err(_) => return erreur("requete illisible"),
    };
    let methode = requete.get("methode").and_then(|j| j.as_str()).unwrap_or("");
    let params = requete.get("params");
    let texte = |clef: &str| -> Option<String> {
        params
            .and_then(|p| p.get(clef))
            .and_then(|j| j.as_str())
            .map(|s| s.to_string())
    };

    match methode {
        "etat" => {
            let brut = std::fs::read(chemin_portefeuille(datadir)).unwrap_or_default();
            let quoi = if brut.is_empty() {
                "absent"
            } else if q21_core::kdf::est_scelle(&brut) {
                "scelle"
            } else {
                "clair"
            };
            Json::obj()
                .set("portefeuille", Json::str(quoi))
                .set("reseau", Json::str(nom_de_reseau(reseau)))
                .set("port_noeud", Json::u64(port_noeud as u64))
                .build()
        }

        "creer" => {
            if chemin_portefeuille(datadir).exists() {
                return erreur("un portefeuille existe deja dans ce dossier");
            }
            // Un code fourni : c'est une restauration. La graine vient de la
            // feuille de papier, pas du generateur.
            let graine = match texte("code") {
                Some(code) if !code.trim().is_empty() => {
                    match Wallet::seed_from_backup(code.trim(), reseau) {
                        Ok(g) => Some(g),
                        Err(q21_core::wallet::WalletError::SauvegardeAutreReseau) => {
                            return erreur("ce code de sauvegarde appartient a un autre reseau")
                        }
                        Err(_) => {
                            return erreur(
                                "code de sauvegarde illisible : la somme de controle ne \
                                 correspond pas. Verifiez la recopie — l'alphabet employe ne \
                                 contient ni 1, ni b, ni i, ni o.",
                            )
                        }
                    }
                }
                _ => None,
            };

            // La phrase est etablie AVANT toute ecriture : `ecrire_portefeuille`
            // la lit pour sceller, et un portefeuille ecrit en clair puis
            // chiffre aurait laisse une trace en clair sur le disque.
            match texte("phrase") {
                Some(p) if !p.is_empty() => retenir_phrase(Some(p)),
                // Chaine vide : le choix « sans protection », fait sciemment
                // dans la page, derriere une case a cocher qui l'explique.
                Some(_) => retenir_phrase(None),
                None => return erreur("aucune phrase transmise"),
            }

            let schema = if SchemeId::MlDsa87.disponible() {
                SchemeId::MlDsa87
            } else {
                SchemeId::LamportOts
            };
            if std::fs::create_dir_all(datadir).is_err() {
                oublier_phrase();
                return erreur("le dossier de donnees n'a pas pu etre cree");
            }
            match ecrire_chaine_neuve(datadir, reseau, schema, graine) {
                Ok((w, adresse, _)) => Json::obj()
                    .set("code", Json::str(w.backup_code()))
                    .set("adresse", Json::str(adresse.to_string()))
                    .build(),
                Err(e) => {
                    oublier_phrase();
                    erreur(&e)
                }
            }
        }

        "ouvrir" => {
            let phrase = match texte("phrase") {
                Some(p) => p,
                None => return erreur("aucune phrase transmise"),
            };
            retenir_phrase(Some(phrase));
            match lire_portefeuille(datadir) {
                Ok(mut w) => {
                    let adresse = w.new_address().to_string();
                    Json::obj().set("adresse", Json::str(adresse)).build()
                }
                Err(_) => {
                    // On revient a « rien n'a ete dit », et non a « il n'y a pas
                    // de phrase » : la seconde autoriserait une ecriture en
                    // clair au prochain enregistrement.
                    oublier_phrase();
                    erreur("Phrase secrete incorrecte. Reessayez.")
                }
            }
        }

        // « J'ai fini » : la page a tout ce qu'il lui faut, le nœud peut
        // demarrer. On ne coupe pas ce serveur pour autant — la page a encore
        // besoin de lui pour savoir quand aller voir ailleurs.
        "commencer" => {
            fini.store(true, std::sync::atomic::Ordering::Relaxed);
            Json::obj().set("ok", Json::Bool(true)).build()
        }

        // « Le nœud ecoute-t-il ? » La page ne peut pas le demander elle-meme :
        // le nœud est sur une autre origine, et le navigateur refuse d'en lire
        // la reponse. Ce serveur-ci, lui, n'a pas de politique de meme origine
        // a respecter : il ouvre une connexion et dit ce qu'il a vu.
        "noeud" => {
            let pret = std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], port_noeud)),
                std::time::Duration::from_millis(200),
            )
            .is_ok();
            Json::obj().set("pret", Json::Bool(pret)).build()
        }

        _ => erreur("methode inconnue"),
    }
}

/// Ouvre une adresse dans le navigateur par defaut du systeme.
///
/// Aucune bibliotheque : trois commandes, une par systeme. C'est exactement ce
/// que font les bibliotheques qu'on aurait pu importer, et cela evite d'ajouter
/// une dependance a un logiciel qui garde des clefs privees.
fn ouvrir_navigateur(url: &str) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    let mut c = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else if cfg!(target_os = "windows") {
        // `start` est une commande interne de l'interpreteur, d'ou `cmd /C`.
        // Le premier argument vide est le titre de fenetre : sans lui, `start`
        // prend l'adresse pour un titre et n'ouvre rien.
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    c.stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    Ok(())
}

/// Amene l'index au niveau de la chaine.
///
/// Trois cas, et un seul comportement pour les deux mauvais :
///
/// - **rien a faire** : l'index est deja au sommet, et sur le meme bloc ;
/// - **extension** : la chaine a avance, l'index suit bloc par bloc. Les
///   sorties que ces blocs depensent sont soit anterieures et encore vivantes —
///   donc connues de la table des proprietaires — soit creees par eux-memes ;
/// - **divergence** : une reorganisation a change le passe. L'index est
///   reconstruit depuis zero.
///
/// Reconstruire sur reorganisation est plus brutal que necessaire : on
/// pourrait ne retirer que la branche abandonnee. Mais la table des
/// proprietaires devrait alors etre ramenee a son etat d'avant la fourche, ce
/// qui demande de journaliser les sorties consommees. Une reorganisation est
/// rare ; une attribution d'adresse fausse ne se voit pas. Entre les deux, on
/// choisit ce qui ne peut pas mentir.
fn suivre_index(index: &mut q21_core::index::Index, node: &std::sync::Arc<q21_core::net::Node>) {
    let hauteur = node.height();
    if !index.est_vide() && index.hauteur() == hauteur {
        return;
    }
    let divergence = !index.est_vide() && {
        let h = index.hauteur();
        node.with_chain(|c| c.active_at(h)) != index.identifiant(h)
    };
    if divergence {
        eprintln!("  index d'adresses : reorganisation detectee, reconstruction");
        index.effacer();
    }
    let depart = if index.est_vide() {
        0
    } else {
        index.hauteur() + 1
    };
    node.with_chain(|c| {
        for h in depart..=c.height() {
            if let Some(b) = c.block_at(h) {
                if let Err(e) = index.indexer(&b) {
                    eprintln!("avertissement : {e}");
                    return;
                }
            }
        }
    });
}

/// Ouvre l'explorateur de chaine dans le navigateur.
///
/// # Pourquoi une commande a part
///
/// L'explorateur est deja servi par `q21 wallet` : meme processus, meme port,
/// meme jeton, a la racine plutot que sur `/portefeuille`. Qui a un
/// portefeuille ouvert n'a rien a lancer de plus, et le verrou de repertoire
/// interdirait de toute facon un second programme sur le meme dossier.
///
/// Cette commande sert l'autre cas : consulter la chaine **sans** ouvrir de
/// portefeuille. Les methodes qui deplacent des fonds ne sont alors pas
/// exposees du tout — pas desactivees par un reglage, absentes.
///
/// # L'index est actif par defaut, ici seulement
///
/// Un explorateur sans index d'adresses ne repond qu'a moitie : la recherche
/// d'adresse s'arrete au bout de deux mille blocs et l'annonce. Le noeud, lui,
/// garde son defaut — voir `q21_core::index` pour la raison.
fn cmd_explorateur(datadir: &Path, args: &[String]) -> Result<(), String> {
    let mut port: u16 = 0;
    let mut sans_navigateur = false;
    let mut index = true;
    let mut reste: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" if i + 1 < args.len() => {
                port = args[i + 1]
                    .parse()
                    .map_err(|_| "port illisible".to_string())?;
                i += 2;
            }
            "--sans-navigateur" => {
                sans_navigateur = true;
                i += 1;
            }
            "--sans-index" => {
                index = false;
                i += 1;
            }
            autre => {
                reste.push(autre.to_string());
                i += 1;
            }
        }
    }

    println!("Explorateur Q21");
    println!();

    // Le reseau se lit dans le portefeuille : c'est lui qui dit quelle chaine
    // ce repertoire contient. Un explorateur n'a pas besoin de son contenu,
    // mais il a besoin de cette reponse — et le fichier est scelle d'un seul
    // tenant. D'ou la phrase secrete, meme ici.
    if q21_core::kdf::est_scelle(&std::fs::read(chemin_portefeuille(datadir)).unwrap_or_default())
        && !std::env::var("Q21_PASSPHRASE").is_ok_and(|p| !p.is_empty())
    {
        println!("  Ce dossier contient un portefeuille protege par une phrase secrete.");
        println!("  L'explorateur n'y touche pas : il a seulement besoin d'y lire");
        println!("  de quel reseau il s'agit. Tapez la phrase, puis Entree.");
        println!();
    }
    lire_portefeuille(datadir)?;

    let port = if port != 0 {
        port
    } else {
        std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("aucun port disponible : {e}"))?
            .local_addr()
            .map_err(|e| e.to_string())?
            .port()
    };

    let brut: [u8; 32] = q21_core::rng::octets()
        .map_err(|_| "generateur d'alea du systeme inaccessible".to_string())?;
    let jeton: String = brut.iter().map(|o| format!("{o:02x}")).collect();
    let adresse = format!("127.0.0.1:{port}");
    let url = format!("http://{adresse}/#{jeton}");

    println!();
    println!("  Si le navigateur ne s'ouvre pas, ouvrez cette adresse :");
    println!();
    println!("      {url}");
    println!();
    println!("  Aucune methode de portefeuille n'est servie par ce processus.");
    println!();

    if !sans_navigateur {
        let a = adresse.clone();
        let u = url.clone();
        std::thread::spawn(move || {
            for _ in 0..200 {
                if std::net::TcpStream::connect(&a).is_ok() {
                    if let Err(e) = ouvrir_navigateur(&u) {
                        eprintln!("  Le navigateur n'a pas pu etre ouvert ({e}).");
                    }
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
    }
    println!("  Cette fenetre fait tourner l'explorateur. Laissez-la ouverte.");
    println!("  Fermez-la pour arreter.");
    println!();

    let mut arguments = vec![
        "--rpc".to_string(),
        adresse,
        "--rpc-token".to_string(),
        jeton,
    ];
    if index {
        arguments.push("--index-adresses".to_string());
    }
    arguments.push("--silencieux".to_string());
    arguments.extend(reste);
    cmd_node(datadir, &arguments)
}
