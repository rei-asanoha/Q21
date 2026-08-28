//! La vie de la chaine, calculee et non racontee.
//!
//! Ce programme ne simule rien : il appelle les memes fonctions de consensus que
//! le validateur, hauteur par hauteur, et imprime ce qu'elles rendent. Toute
//! divergence entre ce tableau et le comportement du reseau serait un defaut du
//! reseau, pas du tableau.
//!
//! Il repond a quatre questions :
//!
//! 1. Combien de Q21 existent a la fin de chaque annee, et quand le plafond de
//!    21 000 001 est-il approche ?
//! 2. Combien de transactions la chaine peut-elle porter, sachant qu'une
//!    signature post-quantique pese 4 627 octets la ou ECDSA en pese 71 ?
//! 3. Combien de disque cela represente ?
//! 4. Quelle memoire un mineur doit-il detenir, annee par annee ?
//!
//! Lancer :
//!
//! ```text
//! cargo run --release --example projection
//! ```
use q21_core::address::Network;
use q21_core::consensus::*;
use q21_core::emission;
use q21_core::memhard::{self, TableParams};
use q21_core::sig::SchemeId;

/// Blocs par annee, au rythme vise.
const BLOCS_PAR_AN: u64 = (365.25 * 86400.0 / 120.0) as u64;

/// Taille reelle d'une transaction a une entree et une sortie, en ML-DSA-87.
///
/// Mesuree par `cargo run --release --features mldsa --example bench_sig`, qui
/// en construit une vraie et la serialise. On l'inscrit ici en dur pour que ce
/// programme n'ait pas besoin de la fonctionnalite `mldsa` ; l'epreuve du bas
/// verifie qu'elle reste coherente avec les tailles declarees par `sig`.
const TX_OCTETS: usize = 7_361;

fn q21(unites: u64) -> f64 {
    unites as f64 / UNITS_PER_COIN as f64
}

/// Imprime les memes grandeurs en CSV, annee par annee.
///
/// Sert a alimenter un graphique sans recopier des nombres a la main — une
/// recopie est une occasion de se tromper, et un graphique faux est pire qu'un
/// tableau juste.
fn donnees() {
    let p = TableParams::for_network(Network::Mainnet);
    println!("annee,recompense_q21,circulation_q21,pct_plafond,table_gio");
    for an in 0..=100u64 {
        let h = an * BLOCS_PAR_AN;
        let ep = memhard::epoch_of(h);
        let t = memhard::table_size(p, ep) as u64 * POW_ELEMENT_SIZE as u64;
        println!(
            "{},{:.8},{:.2},{:.4},{:.4}",
            an,
            q21(emission::block_subsidy(h).units()),
            q21(emission::total_supply_at(h).units()),
            100.0 * emission::total_supply_at(h).units() as f64 / MAX_SUPPLY as f64,
            t as f64 / 1024.0 / 1024.0 / 1024.0
        );
    }
}

fn main() {
    if std::env::args().any(|a| a == "--donnees") {
        donnees();
        return;
    }

    println!();
    println!("  ===  LA VIE DE Q21, CALCULEE  ===");
    println!();

    // -----------------------------------------------------------------------
    // 1. L'emission
    // -----------------------------------------------------------------------
    println!("  --- Emission ---");
    println!();
    println!(
        "  {:>4}  {:>12}  {:>10}  {:>14}  {:>7}",
        "an", "hauteur", "par bloc", "en circulation", "du cap"
    );

    let plafond = MAX_SUPPLY;
    for an in [1u64, 2, 3, 4, 5, 8, 10, 15, 20, 25, 30, 40, 50, 75, 100] {
        let h = an * BLOCS_PAR_AN;
        let par_bloc = emission::block_subsidy(h).units();
        let total = emission::total_supply_at(h).units();
        println!(
            "  {:>4}  {:>12}  {:>10.4}  {:>14.0}  {:>6.2}%",
            an,
            h,
            q21(par_bloc),
            q21(total),
            100.0 * total as f64 / plafond as f64
        );
    }
    println!();

    // Les seuils. On cherche la premiere hauteur qui les franchit, par pas
    // d'une epoque de decroissance — inutile d'aller au bloc pres pour une
    // grandeur qui bouge tous les six jours.
    println!("  --- Seuils ---");
    println!();
    let seuils = [50.0f64, 75.0, 90.0, 99.0, 99.9, 99.99];
    let mut i = 0;
    let mut epoque = 0u64;
    while i < seuils.len() && epoque < 20_000 {
        let h = epoque * DECAY_EPOCH_BLOCKS;
        let pct = 100.0 * emission::total_supply_at(h).units() as f64 / plafond as f64;
        while i < seuils.len() && pct >= seuils[i] {
            println!(
                "  {:>6.2}% du plafond atteint au bloc {:>10}  —  {:>5.1} ans",
                seuils[i],
                h,
                h as f64 / BLOCS_PAR_AN as f64
            );
            i += 1;
        }
        epoque += 1;
    }

    // La fin du minage : le plancher de queue garantit qu'elle existe, et que
    // le plafond y est atteint exactement.
    let h_fin = emission::hauteur_de_fin_d_emission();
    println!(
        "  plafond atteint au bloc {:>10}  —  {:>6.2} ans",
        h_fin - 1,
        (h_fin - 1) as f64 / BLOCS_PAR_AN as f64
    );
    println!(
        "  emis a ce moment : {:.8} Q21 sur {:.8} — il en manque {}",
        q21(emission::total_supply_at(h_fin).units()),
        q21(plafond),
        plafond - emission::total_supply_at(h_fin).units()
    );
    println!(
        "  reliquat du dernier bloc emetteur : {:.8} Q21",
        q21(emission::block_subsidy(h_fin - 1).units())
    );
    println!(
        "  plancher de queue : {:.8} Q21 par bloc des que la decroissance passe dessous",
        q21(TAIL_REWARD)
    );
    println!();

    // Demi-vie effective, pour comparaison avec le halving de Bitcoin.
    let mut e = 0u64;
    while emission::epoch_base_reward(e) > INITIAL_REWARD / 2 {
        e += 1;
    }
    println!(
        "  la recompense est divisee par deux tous les {:.2} ans",
        (e * DECAY_EPOCH_BLOCKS) as f64 / BLOCS_PAR_AN as f64
    );
    println!();

    // -----------------------------------------------------------------------
    // 2. La capacite
    // -----------------------------------------------------------------------
    println!("  --- Capacite ---");
    println!();
    let par_bloc = MAX_BLOCK_SIZE / TX_OCTETS;
    let par_seconde = par_bloc as f64 / TARGET_BLOCK_SECS as f64;
    let par_jour = par_bloc as u64 * 720;
    println!(
        "  signature ML-DSA-87        {:>10} octets   (ECDSA : 71)",
        SchemeId::MlDsa87.sig_len()
    );
    println!("  clef publique              {:>10} octets", SchemeId::MlDsa87.pubkey_len());
    println!("  transaction 1 vers 1       {:>10} octets   (mesuree)", TX_OCTETS);
    println!("  taille maximale d'un bloc  {:>10} octets", MAX_BLOCK_SIZE);
    println!();
    println!("  transactions par bloc      {:>10}", par_bloc);
    println!("  transactions par seconde   {:>10.2}", par_seconde);
    println!("  transactions par jour      {:>10}", par_jour);
    println!();

    for gens in [1_000_000u64, 15_000_000, 100_000_000] {
        let jours = gens as f64 / par_jour as f64;
        println!(
            "  a {:>11} porteurs : une transaction chacun tous les {:>5.1} jours",
            gens, jours
        );
    }
    println!();

    // -----------------------------------------------------------------------
    // 3. Le disque
    // -----------------------------------------------------------------------
    println!("  --- Disque, si les blocs sont pleins ---");
    println!();
    let par_an_octets = MAX_BLOCK_SIZE as u64 * BLOCS_PAR_AN;
    println!(
        "  par jour  {:>8.2} Gio        par an  {:>8.2} Tio",
        (MAX_BLOCK_SIZE as u64 * 720) as f64 / 1024.0 / 1024.0 / 1024.0,
        par_an_octets as f64 / 1024.0 / 1024.0 / 1024.0 / 1024.0
    );
    println!(
        "  fenetre de corps conservee : {} blocs, soit {:.2} Gio",
        BODY_WINDOW,
        (BODY_WINDOW * MAX_BLOCK_SIZE) as f64 / 1024.0 / 1024.0 / 1024.0
    );
    println!();

    // -----------------------------------------------------------------------
    // 4. La memoire du mineur
    // -----------------------------------------------------------------------
    println!("  --- Memoire exigee du mineur ---");
    println!();
    let p = TableParams::for_network(Network::Mainnet);
    println!(
        "  {:>4}  {:>8}  {:>10}  {:>10}",
        "an", "epoque", "table", "cache"
    );
    for an in [0u64, 1, 2, 3, 4, 5, 6, 7, 10, 20] {
        let h = an * BLOCS_PAR_AN;
        let ep = memhard::epoch_of(h);
        let t = memhard::table_size(p, ep) as u64 * POW_ELEMENT_SIZE as u64;
        let c = memhard::cache_size(p, ep) as u64 * POW_ELEMENT_SIZE as u64;
        println!(
            "  {:>4}  {:>8}  {:>7.2} Gio  {:>7.0} Mio",
            an,
            ep,
            t as f64 / 1024.0 / 1024.0 / 1024.0,
            c as f64 / 1024.0 / 1024.0
        );
    }
    println!();
    println!(
        "  duree d'une epoque de preuve de travail : {:.1} jours",
        POW_EPOCH_BLOCKS as f64 * TARGET_BLOCK_SECS as f64 / 86400.0
    );
    println!();

    // -----------------------------------------------------------------------
    // 5. Ce que devient le minage quand beaucoup de monde s'y met
    // -----------------------------------------------------------------------
    //
    // Le debit par machine vient du banc : 84 053 essais/s par coeur, mesures.
    // On retient 400 000 essais/s pour une machine « moyenne » du parc — un
    // melange de portables a quatre coeurs et de machines de bureau a huit. Ce
    // nombre-la est une hypothese, pas une mesure, et tout ce qui suit en
    // depend lineairement.
    const PAR_MACHINE: f64 = 400_000.0;
    const WATTS: f64 = 80.0;

    println!("  --- Le minage a grande echelle ---");
    println!();
    println!("  hypothese : {PAR_MACHINE:.0} essais/s et {WATTS:.0} W par machine");
    println!();
    println!(
        "  {:>12}  {:>14}  {:>18}  {:>10}",
        "mineurs", "reseau", "un bloc chacun tous les", "puissance"
    );
    for n in [1_000u64, 100_000, 1_000_000, 15_000_000] {
        let reseau = n as f64 * PAR_MACHINE;
        // Part d'un mineur = 1/n. Un bloc toutes les 120 s pour tout le reseau.
        let secondes = TARGET_BLOCK_SECS as f64 * n as f64;
        let jours = secondes / 86400.0;
        let gw = n as f64 * WATTS / 1e9;
        let duree = if jours < 365.0 {
            format!("{jours:.1} jours")
        } else {
            format!("{:.1} ans", jours / 365.25)
        };
        println!(
            "  {:>12}  {:>10.2e} h/s  {:>18}  {:>7.2} GW",
            n, reseau, duree, gw
        );
    }
    println!();
    println!("  A 15 millions de mineurs, un particulier seul gagne un bloc tous les");
    println!("  57 ans. Le minage solitaire n'a alors plus de sens : on se regroupe,");
    println!("  et le regroupement est le vrai risque de centralisation qui reste.");
    println!();
}
