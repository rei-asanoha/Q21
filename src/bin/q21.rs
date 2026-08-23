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
                             --listen <ip:port>   accepte les connexions
                             --connect <ip:port>  se connecte a un pair
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
    securite                 Ce qui est protege, et ce qui ne l'est pas
    help                     Cette aide

EXEMPLE
    q21 init regtest
    q21 mine 205

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
        "pow" => cmd_pow(
            &datadir,
            reste.get(1).map(|s| s.as_str()),
            reste.iter().any(|a| a == "--sans-table"),
        ),
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
fn chemin_serie(d: &Path) -> PathBuf {
    d.join("wallet.seq")
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

fn ecrire_portefeuille(d: &Path, w: &Wallet) -> Result<(), String> {
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
    match phrase_courante() {
        Some(phrase) => {
            let scelle = q21_core::kdf::sceller(
                phrase.as_bytes(),
                contenu.as_bytes(),
                q21_core::kdf::ITERATIONS_DEFAUT,
            )
            .map_err(|e| e.to_string())?;
            std::fs::write(&chemin, scelle).map_err(|e| e.to_string())?;
        }
        None => std::fs::write(&chemin, contenu).map_err(|e| e.to_string())?,
    }
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
static PHRASE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

fn phrase_courante() -> Option<String> {
    PHRASE.get().cloned().flatten()
}

fn retenir_phrase(p: Option<String>) {
    let _ = PHRASE.set(p);
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
    let chrono = std::env::var("Q21_CHRONO").is_ok();
    let t0 = std::time::Instant::now();
    let mut wallet = lire_portefeuille(datadir)?;
    if chrono {
        eprintln!("[chrono] portefeuille {:.2} s", t0.elapsed().as_secs_f64());
    }
    let reseau = wallet.network();
    // 1. Balayage des en-tetes : une lecture sequentielle, aucun corps decode.
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
        let _ = ecrire_portefeuille(datadir, &wallet);
    }

    Ok(Etat {
        chain,
        wallet,
        archive,
        datadir: datadir.to_path_buf(),
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

    println!("Minage du bloc de genese...");
    let genesis = genesis_block(reseau);

    let store = q21_core::store::BlockStore::new(chemin_blocs(datadir));
    store.append(&genesis).map_err(|e| e.to_string())?;
    ecrire_portefeuille(datadir, &wallet)?;

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

    let debut = std::time::Instant::now();
    let mut total_essais = 0u64;

    for i in 0..n {
        let addr = e.wallet.new_address();
        // Le schema du beneficiaire doit etre celui de son adresse, sinon
        // l'empreinte inscrite dans la sortie ne correspondra a aucune clef et
        // la piece sera perdue.
        let schema = addr.scheme;
        let t = maintenant().max(e.chain.tip().time + 1);

        let bloc = e
            .chain
            .mine_block(addr.hash, schema, &[], t, 200_000_000)
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

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" if i + 1 < args.len() => {
                ecoute = Some(args[i + 1].clone());
                i += 2;
            }
            "--connect" if i + 1 < args.len() => {
                vers.push(args[i + 1].clone());
                i += 2;
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
            autre => return Err(format!("option inconnue : {autre}")),
        }
    }

    let mut etat = charger(datadir)?;
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

    println!("Noeud Q21 — reseau {reseau:?}, hauteur {hauteur_depart}");

    if let Some(a) = &ecoute {
        let local = node
            .listen(a)
            .map_err(|e| format!("ecoute impossible : {e}"))?;
        println!("  ecoute sur {local}");
    }
    for a in &vers {
        match a.parse() {
            Ok(sa) => match node.connect(sa) {
                Ok(_) => println!("  connexion vers {a}"),
                Err(e) => eprintln!("  echec vers {a} : {e}"),
            },
            Err(_) => eprintln!("  adresse illisible : {a}"),
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
    if mine {
        println!("  minage actif sur {fils_effectifs} fil(s)");
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
            sur_changement: Some(std::sync::Arc::new(move |w: &Wallet| {
                if let Err(e) = ecrire_portefeuille(&dossier, w) {
                    eprintln!("ALERTE : portefeuille non enregistre apres modification : {e}");
                }
            })),
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

        println!("  RPC et explorateur sur http://{}", h.addr);
        if rpc_wallet {
            println!("  ATTENTION : methodes de portefeuille actives sur ce port.");
        } else {
            println!("  Portefeuille desactive (--rpc-wallet pour l'activer).");
        }
        if let Some(t) = &rpc_token {
            println!("  Jeton exige. Explorateur : http://{}/?token={t}", h.addr);
        }
        Some(h)
    } else {
        None
    };

    println!("  Ctrl-C pour arreter");
    println!();

    let debut = std::time::Instant::now();
    let mut dernier_rapport = std::time::Instant::now();
    let mut derniere_hauteur = node.height();
    let mut derniere_recherche = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(60))
        .unwrap_or_else(std::time::Instant::now);

    loop {
        if duree > 0 && debut.elapsed().as_secs() >= duree {
            break;
        }

        // Maintien des connexions sortantes.
        //
        // Le carnet ne rend que des adresses de groupes reseau distincts, et
        // distincts de ceux deja connectes : c'est ce qui empeche un adversaire
        // detenant une seule plage d'occuper toutes les places. Voir `addr`.
        if derniere_recherche.elapsed().as_secs() >= 15 {
            derniere_recherche = std::time::Instant::now();
            let manquants = cible_pairs.saturating_sub(node.peer_count());
            if manquants > 0 {
                for a in node.addresses_to_try(manquants) {
                    let sa = std::net::SocketAddr::from((a.ip, a.port));
                    match node.connect(sa) {
                        Ok(_) => node.note_connect_success(a.ip, a.port),
                        Err(_) => node.note_connect_failure(a.ip, a.port),
                    }
                }
            }
        }

        if mine {
            // L'adresse du mineur se derive hors du verrou de la chaine : tenir
            // deux verrous a la fois est le plus court chemin vers l'interblocage.
            let (beneficiaire, schema) = {
                let mut w = wallet.lock().map_err(|_| "portefeuille verrouille")?;
                let a = w.new_address();
                (a.hash, a.scheme)
            };
            // Les transactions du mempool entrent dans le bloc, dans l'ordre
            // topologique impose par la selection.
            let selection = node.with_mempool(|m| m.select_for_block(2_000_000));
            let bloc = node.with_chain(|c| {
                let t = maintenant().max(c.tip().time + 1);
                c.mine_block(beneficiaire, schema, &selection, t, 2_000_000)
            });
            if let Some(b) = bloc {
                let ok = node.with_chain(|c| c.connect(&b, maintenant()).is_ok());
                if ok {
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

        if dernier_rapport.elapsed().as_secs() >= 2 {
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
    if let Ok(w) = wallet.lock() {
        let _ = ecrire_portefeuille(datadir, &w);
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
    // L'instantane est ecrit a l'arret, pas a chaque bloc : c'est une economie
    // de demarrage, pas une donnee dont la perte couterait quoi que ce soit.
    node.with_chain(|c| ecrire_instantane(datadir, c));
    println!();
    println!("Arret. Hauteur finale : {}", node.height());
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

    // 1. Le portefeuille doit exister. On ne le cree pas en silence : creer un
    //    portefeuille est un acte qui produit un code de sauvegarde, et ce code
    //    doit etre lu par un humain, pas defiler dans une fenetre qui se ferme.
    if !chemin_portefeuille(datadir).exists() {
        return Err(format!(
            "aucun portefeuille dans {}.\n\n  \
             Creez-en un d'abord :\n\n      \
             q21 --datadir {} init testnet\n\n  \
             Cette commande affiche un code de sauvegarde. Recopiez-le sur papier\n  \
             avant d'aller plus loin : c'est le seul moyen de retrouver vos fonds\n  \
             si ce fichier disparait.",
            datadir.display(),
            datadir.display()
        ));
    }

    // 2. Un port libre, si l'on n'en impose pas un.
    let port = if port != 0 {
        port
    } else {
        std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("aucun port disponible : {e}"))?
            .local_addr()
            .map_err(|e| e.to_string())?
            .port()
    };

    // 3. Un jeton tire du generateur du systeme. Trente-deux octets : il n'est
    //    pas devinable, et il ne sert que le temps de cette execution.
    let brut: [u8; 32] = q21_core::rng::octets()
        .map_err(|_| "generateur d'alea du systeme inaccessible".to_string())?;
    let jeton: String = brut.iter().map(|o| format!("{o:02x}")).collect();

    let adresse = format!("127.0.0.1:{port}");
    let url = format!("http://{adresse}/portefeuille#{jeton}");

    println!("Portefeuille Q21");
    println!("  interface   http://{adresse}/portefeuille");
    println!("  explorateur http://{adresse}/");
    println!();
    if sans_navigateur {
        println!("  Ouvrez cette adresse dans votre navigateur :");
        println!();
        println!("      {url}");
        println!();
        println!("  Le jeton est apres le « # ». Il n'est jamais envoye au serveur");
        println!("  dans l'adresse : le navigateur le garde, la page le lit, puis");
        println!("  l'efface de la barre d'adresse.");
    } else {
        // 4. Le navigateur s'ouvre une fois le serveur pret. On sonde le port
        //    plutot que d'attendre une duree fixe : une duree fixe est toujours
        //    trop courte sur une machine chargee et trop longue ailleurs.
        let a = adresse.clone();
        let u = url.clone();
        std::thread::spawn(move || {
            for _ in 0..100 {
                if std::net::TcpStream::connect(&a).is_ok() {
                    if let Err(e) = ouvrir_navigateur(&u) {
                        eprintln!("  Le navigateur n'a pas pu etre ouvert ({e}).");
                        eprintln!("  Ouvrez cette adresse a la main :\n\n      {u}\n");
                    }
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            eprintln!("  Le serveur n'a pas repondu. Ouvrez a la main :\n\n      {u}\n");
        });
    }
    println!();
    println!("  Ctrl-C pour arreter.");
    println!();

    // 5. Le noeud, avec les methodes de portefeuille et le jeton.
    let mut arguments = vec![
        "--rpc".to_string(),
        adresse,
        "--rpc-wallet".to_string(),
        "--rpc-token".to_string(),
        jeton,
    ];
    arguments.extend(reste);
    cmd_node(datadir, &arguments)
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
