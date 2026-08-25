//! Ce que coute reellement le minage, sur les parametres du reseau principal.
//!
//! Ce banc existe parce que la question « faut-il une machine chere pour miner
//! du Q21 ? » ne se repond pas par une opinion. Il mesure quatre choses, sur la
//! machine ou on le lance :
//!
//! - le temps de construction du cache (ce que paie **tout** noeud, meme celui
//!   qui ne mine pas) ;
//! - le temps de construction de la table (ce que paie le mineur, une fois par
//!   epoque, soit environ tous les 71 jours) ;
//! - le debit de minage, en essais par seconde ;
//! - le temps de verification d'un en-tete, qui est ce que paie un noeud pour
//!   chaque bloc recu.
//!
//! Lancer :
//!
//! ```text
//! cargo run --release --example banc_minage
//! ```
//!
//! La machine a besoin d'environ 2,2 Gio de memoire libre : la table du reseau
//! principal en occupe 2 a elle seule. C'est voulu, et c'est le sujet meme de la
//! mesure.
use q21_core::address::Network;
use q21_core::block::BlockHeader;
use q21_core::hash::Hash256;
use q21_core::memhard::{self, PowCache, PowTable, TableParams};
use std::sync::Arc;
use std::time::Instant;

fn gio(octets: usize) -> f64 {
    octets as f64 / (1024.0 * 1024.0 * 1024.0)
}

fn mio(octets: usize) -> f64 {
    octets as f64 / (1024.0 * 1024.0)
}

fn main() {
    let params = TableParams::for_network(Network::Mainnet);
    let epoque = 0;
    let fils = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    println!();
    println!("  Banc de minage Q21 — parametres du reseau principal, epoque 0");
    println!("  Coeurs vus par le programme : {fils}");
    println!();

    // --- Niveau 1 : le cache -------------------------------------------------
    let t = Instant::now();
    let cache = Arc::new(PowCache::build(params, epoque));
    let temps_cache = t.elapsed();
    println!(
        "  Cache   {:>8.0} Mio   construit en {:>6.1} s",
        mio(cache.memory_bytes()),
        temps_cache.as_secs_f64()
    );

    // --- Niveau 2 : la table -------------------------------------------------
    let t = Instant::now();
    let table = Arc::new(PowTable::build_avec_cache(&cache, params, epoque));
    let temps_table = t.elapsed();
    println!(
        "  Table   {:>8.2} Gio   construite en {:>6.1} s",
        gio(table.memory_bytes()),
        temps_table.as_secs_f64()
    );
    println!();

    // --- Debit de minage -----------------------------------------------------
    //
    // On ne passe pas par `mine_with_table_parallel` : il s'arrete des que la
    // cible est atteinte, et une cible impossible le fait sortir sans rien
    // calculer. Un premier jet de ce banc affichait ainsi 30 milliards
    // d'essais par seconde — c'etait la mesure d'une boucle qui n'avait pas
    // tourne. On compte donc les condensats un par un, ce qui est exactement
    // le travail d'un essai.
    let mut en_tete = BlockHeader {
        version: 1,
        prev_block: Hash256([7u8; 32]),
        merkle_root: Hash256([9u8; 32]),
        uncles_root: Hash256([0u8; 32]),
        miner: Hash256([3u8; 32]),
        time: 1_700_000_000,
        bits: 0x1d00_ffff,
        height: 1,
        nonce: 0,
    };

    // Un fil, d'abord : c'est le debit par coeur.
    let essais: u64 = 200_000;
    let t = Instant::now();
    for i in 0..essais {
        en_tete.nonce = i;
        std::hint::black_box(memhard::hash_mining(&en_tete, &table));
    }
    let temps = t.elapsed().as_secs_f64();
    let par_coeur = essais as f64 / temps;
    println!(
        "  Minage  {:>8.0} essais/s par coeur  ({} essais en {:.1} s)",
        par_coeur, essais, temps
    );

    // Puis sur tous les coeurs, parce que c'est ce qu'un mineur emploie.
    let t = Instant::now();
    let mut mains = Vec::new();
    for f in 0..fils {
        let table = Arc::clone(&table);
        let mut h = en_tete;
        mains.push(std::thread::spawn(move || {
            for i in 0..essais {
                h.nonce = (f as u64) << 40 | i;
                std::hint::black_box(memhard::hash_mining(&h, &table));
            }
        }));
    }
    for m in mains {
        let _ = m.join();
    }
    let temps = t.elapsed().as_secs_f64();
    let debit = (essais * fils as u64) as f64 / temps;
    println!("  Minage  {:>8.0} essais/s sur {} coeur(s)", debit, fils);

    // --- Verification --------------------------------------------------------
    //
    // Ce que paie un noeud qui ne mine pas : un seul acces a la table, refait
    // depuis le cache. C'est le prix de la correction a deux niveaux.
    let n = 200;
    let t = Instant::now();
    for i in 0..n {
        en_tete.nonce = i;
        let _ = memhard::hash_verify_avec_cache(&en_tete, params, &cache);
    }
    let par_verif = t.elapsed().as_secs_f64() / n as f64;
    println!("  Verif   {:>8.0} us par en-tete", par_verif * 1e6);
    println!();

    // --- Ce que cela veut dire ----------------------------------------------
    //
    // Un bloc toutes les 120 secondes. Si le reseau entier avait la puissance
    // de cette machine, il faudrait `debit * 120` essais pour en trouver un.
    println!(
        "  A ce debit, cette machine fait {:.0} essais entre deux blocs (120 s).",
        debit * 120.0
    );
    println!(
        "  Le cache se reconstruit tous les {} blocs, soit environ {:.0} jours.",
        q21_core::consensus::POW_EPOCH_BLOCKS,
        q21_core::consensus::POW_EPOCH_BLOCKS as f64 * 120.0 / 86400.0
    );
    println!();
}
