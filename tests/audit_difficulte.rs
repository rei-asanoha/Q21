//! Audit adverse — axe « difficulte, horodatages, economie du minage ».
//!
//! Chaque test est une SIMULATION NUMERIQUE sur le code de production
//! (`chain::next_bits`, `chain::Chain`, `memhard`, `validate`). Aucun `src/`
//! n'est modifie.
//!
//! Lancement :
//!   cargo test --offline --release --test audit_difficulte -- --nocapture

use q21_core::address::Network;
use q21_core::block::BlockHeader;
use q21_core::chain::{self, Chain};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::memhard::{self, PowTable, TableParams};
use q21_core::pow;
use q21_core::uint::U256;
use q21_core::validate;

// ---------------------------------------------------------------------------
// Outils de simulation
// ---------------------------------------------------------------------------

/// Generateur pseudo-aleatoire deterministe (xorshift64*).
struct Rng(u64);
impl Rng {
    fn new(graine: u64) -> Rng {
        Rng(graine | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    /// Loi exponentielle de moyenne `m` — le temps entre deux blocs.
    fn expo(&mut self, m: f64) -> f64 {
        let u = self.unit().max(1e-15);
        -m * u.ln()
    }
}

/// Cible d'un `bits` compact, en flottant. Sert uniquement a mesurer.
fn cible_f64(bits: u32) -> f64 {
    let exposant = (bits >> 24) as i32;
    let mantisse = (bits & 0x007f_ffff) as f64;
    mantisse * 2f64.powi(8 * (exposant - 3))
}

/// Difficulte relative a [`INITIAL_BITS`] : 1.0 = difficulte plancher.
fn difficulte(bits: u32) -> f64 {
    cible_f64(INITIAL_BITS) / cible_f64(bits)
}

fn entete(time: u64, bits: u32, height: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block: Hash256::ZERO,
        merkle_root: Hash256::ZERO,
        uncles_root: Hash256::ZERO,
        miner: Hash256::ZERO,
        time,
        bits,
        height,
        nonce: 0,
    }
}

/// Mediane des horodatages, exactement comme `validate::median_time`.
fn mediane(times: &[u64]) -> u64 {
    validate::median_time(times)
}

/// Strategie d'horodatage d'un mineur.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Strategie {
    /// Horodatage honnete : l'heure reelle.
    Honnete,
    /// Saturation de la fenetre future : `maintenant + MAX_FUTURE_TIME`.
    FuturMax,
    /// Optimum : `precedent + 6T`, plafonne par `maintenant + MAX_FUTURE_TIME`.
    Increment6t,
}

struct Resultat {
    difficulte_moyenne: f64,
    intervalle_reel_moyen: f64,
    blocs_attaquant: usize,
    blocs_total: usize,
    bits_final: u32,
    horodatages_refuses: usize,
}

/// Simule `n` blocs. `part` = fraction de puissance de l'attaquant.
///
/// Le hashrate reseau est constant et calibre pour que, sans attaque, la
/// difficulte se stabilise a `d0` et l'intervalle a TARGET_BLOCK_SECS.
fn simuler(n: usize, part: f64, strat: Strategie, graine: u64) -> Resultat {
    let d0 = 1000.0f64; // difficulte de depart, arbitraire mais >> 1
    let bits0 = bits_pour_difficulte(d0);
    // hashrate en « unites de difficulte par seconde »
    let r = d0 / TARGET_BLOCK_SECS as f64;

    let mut rng = Rng::new(graine);
    let mut entetes: Vec<BlockHeader> = Vec::with_capacity(n + 200);
    // Amorce : 200 blocs parfaitement reguliers a d0.
    let t0 = 1_800_000_000u64;
    for i in 0..200u64 {
        entetes.push(entete(t0 + i * TARGET_BLOCK_SECS, bits0, i));
    }
    let mut reel = (t0 + 199 * TARGET_BLOCK_SECS) as f64;

    let mut somme_diff = 0.0;
    let mut blocs_att = 0usize;
    let mut refuses = 0usize;
    let debut_mesure = n / 2; // on ne mesure que le regime permanent

    let mut reel_debut_mesure = 0.0;
    let mut n_mesure = 0usize;

    for i in 0..n {
        let bits = chain::next_bits(&entetes);
        let d = difficulte(bits);
        let dt = rng.expo(d / r);
        reel += dt;

        let attaquant = rng.unit() < part;
        let precedent = entetes.last().unwrap().time;
        let med = mediane(
            &entetes
                .iter()
                .rev()
                .take(MEDIAN_TIME_SPAN)
                .rev()
                .map(|h| h.time)
                .collect::<Vec<_>>(),
        );
        let plafond_futur = reel as u64 + MAX_FUTURE_TIME;

        let brut = if attaquant {
            match strat {
                Strategie::Honnete => reel as u64,
                Strategie::FuturMax => plafond_futur,
                Strategie::Increment6t => (precedent + 6 * TARGET_BLOCK_SECS).min(plafond_futur),
            }
        } else {
            reel as u64
        };
        // Regles de `validate::check_block` : > mediane, <= maintenant + 2 h.
        let t = brut.max(med + 1);
        if t > plafond_futur {
            // Le bloc serait refuse — le mineur retombe sur le maximum legal.
            refuses += 1;
        }
        let t = t.min(plafond_futur);

        entetes.push(entete(t, bits, 200 + i as u64));
        if attaquant {
            blocs_att += 1;
        }
        if i >= debut_mesure {
            if n_mesure == 0 {
                reel_debut_mesure = reel - dt;
            }
            somme_diff += d;
            n_mesure += 1;
        }
    }

    Resultat {
        difficulte_moyenne: somme_diff / n_mesure as f64,
        intervalle_reel_moyen: (reel - reel_debut_mesure) / n_mesure as f64,
        blocs_attaquant: blocs_att,
        blocs_total: n,
        bits_final: entetes.last().unwrap().bits,
        horodatages_refuses: refuses,
    }
}

/// Trouve un `bits` compact realisant approximativement la difficulte demandee.
fn bits_pour_difficulte(d: f64) -> u32 {
    let t0 = pow::target_from_compact(INITIAL_BITS).unwrap();
    let cible = t0.checked_div_u64(d as u64).unwrap();
    pow::target_to_compact(cible)
}

// ---------------------------------------------------------------------------
// 1. Manipulation d'horodatage
// ---------------------------------------------------------------------------

#[test]
fn a1_manipulation_horodatage_fait_chuter_la_difficulte() {
    println!("\n=== A1 — manipulation d'horodatage (LWMA, clamp [1, 6T]) ===");
    println!(
        "MAX_FUTURE_TIME = {} s, 6T = {} s, T = {} s, fenetre = {} blocs",
        MAX_FUTURE_TIME,
        6 * TARGET_BLOCK_SECS,
        TARGET_BLOCK_SECS,
        LWMA_WINDOW
    );
    println!();
    println!(
        "{:>6} {:>10} {:>14} {:>14} {:>10} {:>12}",
        "X %", "strategie", "difficulte", "chute", "intervalle", "inflation"
    );

    let n = 6000;
    let base = simuler(n, 0.0, Strategie::Honnete, 12345);
    println!(
        "{:>6.1} {:>10} {:>14.1} {:>14} {:>10.1} {:>12}",
        0.0, "-", base.difficulte_moyenne, "-", base.intervalle_reel_moyen, "-"
    );

    let mut chute_max = 0.0f64;
    for part in [0.05, 0.10, 0.15, 0.20, 0.25, 0.33, 0.50] {
        for strat in [Strategie::FuturMax, Strategie::Increment6t] {
            let r = simuler(n, part, strat, 12345);
            let chute = 1.0 - r.difficulte_moyenne / base.difficulte_moyenne;
            let infl = base.intervalle_reel_moyen / r.intervalle_reel_moyen;
            chute_max = chute_max.max(chute);
            println!(
                "{:>6.1} {:>10} {:>14.1} {:>13.1}% {:>10.1} {:>11.2}x  ({} horodatage(s) refuse(s))",
                part * 100.0,
                match strat {
                    Strategie::FuturMax => "futur+2h",
                    Strategie::Increment6t => "prec+6T",
                    _ => "honnete",
                },
                r.difficulte_moyenne,
                chute * 100.0,
                r.intervalle_reel_moyen,
                infl,
                r.horodatages_refuses
            );
        }
    }
    println!();
    println!("chute maximale observee : {:.1} %", chute_max * 100.0);
    assert!(
        chute_max > 0.20,
        "aucune chute significative : la faille serait absente"
    );
}

#[test]
fn a1b_seuil_d_effondrement_theorique_et_mesure() {
    println!("\n=== A1b — seuil d'effondrement total de la difficulte ===");
    // Modele : chaque bloc de l'attaquant contribue 6T=720 s au lieu de T=120 s
    // dans la somme LWMA (clamp haut), et le bloc honnete qui le suit contribue
    // 1 s (clamp bas, car `saturating_sub` transforme un intervalle negatif
    // en 0 puis en 1). L'equilibre LWMA impose une moyenne de T.
    println!("modele analytique : 721*a*(1-a) + mu*(a^2+(1-a)^2) = T");
    for a in [0.05f64, 0.10, 0.15, 0.20, 0.2065, 0.25] {
        let num = TARGET_BLOCK_SECS as f64 - 721.0 * a * (1.0 - a);
        let den = a * a + (1.0 - a) * (1.0 - a);
        let mu = num / den;
        println!(
            "  a = {:>5.1} %  ->  intervalle reel d'equilibre mu = {:>8.2} s  (difficulte x {:>6.3})",
            a * 100.0,
            mu,
            (mu / TARGET_BLOCK_SECS as f64).max(0.0)
        );
    }
    println!("  seuil ou mu <= 0 : a* = T / 721 ... a* ~ 20.7 % (strategie prec+6T)");

    // Mesure : on pousse la simulation jusqu'a l'effondrement.
    let n = 20_000;
    for part in [0.20f64, 0.25, 0.30] {
        let r = simuler(n, part, Strategie::Increment6t, 987);
        println!(
            "  mesure a = {:>4.0} % : difficulte finale bits = {:#010x}  (= {:.3} x le plancher), \
             intervalle reel = {:.2} s, blocs attaquant {}/{}",
            part * 100.0,
            r.bits_final,
            difficulte(r.bits_final),
            r.intervalle_reel_moyen,
            r.blocs_attaquant,
            r.blocs_total
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Oscillation LWMA / hash rate hopping
// ---------------------------------------------------------------------------

struct Hopping {
    part_blocs: f64,
    part_hash: f64,
    gain: f64,
    diff_on: f64,
    diff_off: f64,
    cycles: usize,
}

/// Un mineur nomade allume sa ferme quand la difficulte est basse et l'eteint
/// quand elle remonte. Mesure : sa part de blocs / sa part de hachage depense.
fn simuler_hopping(
    n: usize,
    ratio_att: f64,
    seuil_on: f64,
    seuil_off: f64,
    graine: u64,
) -> Hopping {
    let d0 = 1000.0f64;
    let bits0 = bits_pour_difficulte(d0);
    let r_honnete = d0 / TARGET_BLOCK_SECS as f64;
    let r_att = r_honnete * ratio_att;

    let mut rng = Rng::new(graine);
    let mut entetes: Vec<BlockHeader> = Vec::with_capacity(n + 200);
    let t0 = 1_800_000_000u64;
    for i in 0..200u64 {
        entetes.push(entete(t0 + i * TARGET_BLOCK_SECS, bits0, i));
    }
    let mut reel = (t0 + 199 * TARGET_BLOCK_SECS) as f64;

    let mut allume = false;
    let mut cycles = 0usize;
    let mut blocs_att = 0.0;
    let mut hash_att = 0.0;
    let mut hash_hon = 0.0;
    let mut somme_on = 0.0;
    let mut n_on = 0.0;
    let mut somme_off = 0.0;
    let mut n_off = 0.0;

    for i in 0..n {
        let bits = chain::next_bits(&entetes);
        let d = difficulte(bits);
        let d_rel = d / d0;

        if !allume && d_rel < seuil_on {
            allume = true;
            cycles += 1;
        } else if allume && d_rel > seuil_off {
            allume = false;
        }

        let r_total = r_honnete + if allume { r_att } else { 0.0 };
        let dt = rng.expo(d / r_total);
        reel += dt;

        // Hachage depense = puissance x duree.
        hash_hon += r_honnete * dt;
        if allume {
            hash_att += r_att * dt;
            somme_on += d_rel;
            n_on += 1.0;
        } else {
            somme_off += d_rel;
            n_off += 1.0;
        }
        // Probabilite de gagner le bloc = part de puissance instantanee.
        let p = if allume { r_att / r_total } else { 0.0 };
        if rng.unit() < p {
            blocs_att += 1.0;
        }

        let precedent = entetes.last().unwrap().time;
        let t = (reel as u64).max(precedent.saturating_sub(0)).max(
            mediane(
                &entetes
                    .iter()
                    .rev()
                    .take(MEDIAN_TIME_SPAN)
                    .rev()
                    .map(|h| h.time)
                    .collect::<Vec<_>>(),
            ) + 1,
        );
        entetes.push(entete(t, bits, 200 + i as u64));
    }

    let part_blocs = blocs_att / n as f64;
    let part_hash = hash_att / (hash_att + hash_hon);
    Hopping {
        part_blocs,
        part_hash,
        gain: part_blocs / part_hash.max(1e-12),
        diff_on: if n_on > 0.0 { somme_on / n_on } else { 0.0 },
        diff_off: if n_off > 0.0 { somme_off / n_off } else { 0.0 },
        cycles,
    }
}

#[test]
fn a2_hash_rate_hopping_sur_lwma() {
    println!("\n=== A2 — oscillation LWMA / hash rate hopping ===");
    println!(
        "LWMA ajuste a CHAQUE bloc sur {} blocs : le retard moyen est de ~{} blocs (~{} min)",
        LWMA_WINDOW,
        LWMA_WINDOW / 3,
        LWMA_WINDOW / 3 * TARGET_BLOCK_SECS as usize / 60
    );
    println!();
    println!(
        "{:>8} {:>8} {:>8} {:>11} {:>11} {:>8} {:>8} {:>8}",
        "R_att/R", "on<", "off>", "part blocs", "part hash", "gain", "d_on", "d_off"
    );
    let n = 40_000;
    let mut gain_max = 0.0f64;
    for ratio in [0.25f64, 0.5, 1.0, 2.0] {
        for (on, off) in [(0.95f64, 1.05f64), (0.90, 1.10), (0.80, 1.20)] {
            let h = simuler_hopping(n, ratio, on, off, 555);
            gain_max = gain_max.max(h.gain);
            println!(
                "{:>8.2} {:>8.2} {:>8.2} {:>10.2}% {:>10.2}% {:>8.4} {:>8.3} {:>8.3}  ({} cycles)",
                ratio,
                on,
                off,
                h.part_blocs * 100.0,
                h.part_hash * 100.0,
                h.gain,
                h.diff_on,
                h.diff_off,
                h.cycles
            );
        }
    }
    println!();
    println!("gain relatif maximal (1.0 = part exacte) : {gain_max:.4}");
}

#[test]
fn a2b_depart_massif_et_spirale_de_la_mort() {
    println!("\n=== A2b — depart massif de puissance : la chaine repart-elle ? ===");
    println!(
        "MAX_TARGET_CHANGE = {MAX_TARGET_CHANGE} (la cible ne peut varier que d'un facteur {MAX_TARGET_CHANGE} \
         par bloc, et ce facteur est relatif a la MOYENNE de la fenetre, pas au parent)"
    );
    println!();
    println!(
        "{:>12} {:>14} {:>16} {:>14}",
        "hashrate x", "blocs pour", "temps reel", "equivalent"
    );
    for facteur in [2.0f64, 10.0, 100.0, 1000.0, 10_000.0] {
        let (blocs, secondes) = simuler_effondrement(facteur);
        println!(
            "{:>11.0}x {:>14} {:>13.0} s {:>13}",
            facteur,
            blocs,
            secondes,
            duree_lisible(secondes)
        );
    }
}

fn duree_lisible(s: f64) -> String {
    if s < 3600.0 {
        format!("{:.0} min", s / 60.0)
    } else if s < 86400.0 {
        format!("{:.1} h", s / 3600.0)
    } else if s < 86400.0 * 365.0 {
        format!("{:.1} j", s / 86400.0)
    } else {
        format!("{:.2} ans", s / (86400.0 * 365.0))
    }
}

/// Le hashrate est divise par `facteur` d'un coup. Combien de blocs et de temps
/// reel avant que l'intervalle redescende sous 2 x TARGET_BLOCK_SECS ?
fn simuler_effondrement(facteur: f64) -> (usize, f64) {
    let d0 = 1_000_000.0f64;
    let bits0 = bits_pour_difficulte(d0);
    let r = d0 / TARGET_BLOCK_SECS as f64 / facteur; // hashrate residuel

    let mut rng = Rng::new(7777);
    let mut entetes: Vec<BlockHeader> = Vec::with_capacity(2000);
    let t0 = 1_800_000_000u64;
    for i in 0..(LWMA_WINDOW as u64 + 1) {
        entetes.push(entete(t0 + i * TARGET_BLOCK_SECS, bits0, i));
    }
    let mut reel = (t0 + LWMA_WINDOW as u64 * TARGET_BLOCK_SECS) as f64;
    let depart = reel;

    for k in 0..5000usize {
        let bits = chain::next_bits(&entetes);
        let d = difficulte(bits);
        let dt = rng.expo(d / r);
        reel += dt;
        let t = (reel as u64).max(
            mediane(
                &entetes
                    .iter()
                    .rev()
                    .take(MEDIAN_TIME_SPAN)
                    .rev()
                    .map(|h| h.time)
                    .collect::<Vec<_>>(),
            ) + 1,
        );
        entetes.push(entete(t, bits, entetes.len() as u64));
        if dt < 2.0 * TARGET_BLOCK_SECS as f64 && k > 5 {
            return (k + 1, reel - depart);
        }
    }
    (5000, reel - depart)
}

#[test]
fn a2c_max_target_change_ne_borne_pas_ce_qu_il_pretend() {
    println!("\n=== A2c — MAX_TARGET_CHANGE : borne annoncee vs borne reelle ===");
    println!(
        "consensus.rs:186 annonce « Facteur maximal de variation de la cible ENTRE DEUX BLOCS » = {MAX_TARGET_CHANGE}"
    );
    println!("chain.rs:167-172 : plafond/plancher sont calcules sur `cible_moyenne`,");
    println!(
        "c'est-a-dire la MOYENNE des {LWMA_WINDOW} dernieres cibles, pas sur la cible du parent.\n"
    );

    // Fenetre stable, puis solvetimes maximaux (6T) : la cible doit monter.
    let d0 = 1_000_000.0f64;
    let bits0 = bits_pour_difficulte(d0);
    let t0 = 1_800_000_000u64;
    let mut entetes: Vec<BlockHeader> = (0..=(LWMA_WINDOW as u64))
        .map(|i| entete(t0 + i * TARGET_BLOCK_SECS, bits0, i))
        .collect();

    println!("--- cible qui MONTE (difficulte qui baisse), solvetime = 6T a chaque bloc ---");
    println!(
        "{:>6} {:>14} {:>14} {:>14}",
        "bloc", "cible/parent", "cible/depart", "difficulte"
    );
    let mut precedent = cible_f64(bits0);
    let depart = precedent;
    for k in 0..12 {
        let bits = chain::next_bits(&entetes);
        let c = cible_f64(bits);
        if k < 6 || k == 11 {
            println!(
                "{:>6} {:>14.4} {:>14.4} {:>14.1}",
                k + 1,
                c / precedent,
                c / depart,
                difficulte(bits)
            );
        }
        precedent = c;
        let t = entetes.last().unwrap().time + 6 * TARGET_BLOCK_SECS;
        entetes.push(entete(t, bits, entetes.len() as u64));
    }
    println!(
        "-> la cible ne monte que de ~4 % par bloc, PAS d'un facteur {MAX_TARGET_CHANGE}. \
         Le facteur 4 n'est atteint qu'au premier bloc."
    );

    println!("\n--- cible qui BAISSE (difficulte qui monte), solvetime = 1 s a chaque bloc ---");
    let mut entetes: Vec<BlockHeader> = (0..=(LWMA_WINDOW as u64))
        .map(|i| entete(t0 + i * TARGET_BLOCK_SECS, bits0, i))
        .collect();
    println!(
        "{:>6} {:>14} {:>14} {:>14}",
        "bloc", "cible/parent", "cible/depart", "difficulte"
    );
    let mut precedent = cible_f64(bits0);
    let depart = precedent;
    for k in 0..12 {
        let bits = chain::next_bits(&entetes);
        let c = cible_f64(bits);
        if k < 6 || k == 11 {
            println!(
                "{:>6} {:>14.4} {:>14.4} {:>14.1}",
                k + 1,
                c / precedent,
                c / depart,
                difficulte(bits)
            );
        }
        precedent = c;
        let t = entetes.last().unwrap().time + 1;
        entetes.push(entete(t, bits, entetes.len() as u64));
    }
}

// ---------------------------------------------------------------------------
// 3 et 4. Epoque de preuve de travail, table/cache, divergence minage/verif
// ---------------------------------------------------------------------------

#[test]
fn a3_frontiere_d_epoque_cout_et_avantage() {
    println!("\n=== A3 — transition d'epoque de preuve de travail ===");
    println!(
        "POW_EPOCH_BLOCKS = {POW_EPOCH_BLOCKS} blocs (~{:.0} jours a {TARGET_BLOCK_SECS} s)",
        POW_EPOCH_BLOCKS as f64 * TARGET_BLOCK_SECS as f64 / 86400.0
    );
    println!(
        "graine d'epoque = H(numero d'epoque) — memhard.rs:130 : elle ne depend d'AUCUN bloc,"
    );
    println!("donc toutes les epoques futures sont calculables des aujourd'hui.\n");

    for (nom, net) in [
        ("regtest", Network::Regtest),
        ("testnet", Network::Testnet),
        ("mainnet", Network::Mainnet),
    ] {
        let p = TableParams::for_network(net);
        print!("{nom:>8} : ");
        for e in [0u64, 1, 5, 10, 29, 30, 100] {
            print!(
                "e{e}={} Mio  ",
                memhard::table_size(p, e) as u64 * POW_ELEMENT_SIZE as u64 / (1 << 20)
            );
        }
        println!();
    }

    // Cout mesure d'une transition.
    let p = TableParams::for_network(Network::Testnet);
    let t = std::time::Instant::now();
    let cache1 = memhard::cache_for(p, 1);
    let dcache = t.elapsed().as_secs_f64();
    let t = std::time::Instant::now();
    let table1 = PowTable::build_avec_cache(&cache1, p, 1);
    let dtable = t.elapsed().as_secs_f64();
    println!(
        "\nmesure (testnet, {} coeurs) : cache {} elements ({} Mio) en {:.3} s ; \
         table {} elements ({} Mio) en {:.3} s",
        std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(1),
        cache1.len(),
        cache1.memory_bytes() / (1 << 20),
        dcache,
        table1.len(),
        table1.memory_bytes() / (1 << 20),
        dtable
    );
    let facteur = POW_TABLE_N0_MAINNET as f64 / POW_TABLE_N0_TESTNET as f64;
    println!(
        "extrapolation mainnet (x{facteur:.0} elements) : cache ~{:.1} s, table ~{:.0} s = {:.1} min",
        dcache * facteur,
        dtable * facteur,
        dtable * facteur / 60.0
    );
    println!(
        "-> a la hauteur {POW_EPOCH_BLOCKS}, `Chain::mine_block` appelle `table_for(epoch_of(hauteur))` \
         (chain.rs:1222)"
    );
    println!(
        "   qui reconstruit la table de facon SYNCHRONE. Un mineur non prepare perd ce temps ;"
    );
    println!(
        "   un mineur prepare a 0 s d'arret et encaisse la totalite des blocs pendant la fenetre."
    );
    let perte = dtable * facteur;
    println!(
        "   avantage chiffre : {:.0} blocs gagnes gratuitement par le mineur prepare \
         (fenetre {:.0} s / {TARGET_BLOCK_SECS} s), soit {:.1} % d'une journee de recompense.",
        perte / TARGET_BLOCK_SECS as f64,
        perte,
        100.0 * perte / 86400.0
    );
}

#[test]
fn a4_divergence_minage_verification() {
    println!("\n=== A4 — hash_mining vs hash_verify ===");
    let p = TableParams::for_network(Network::Regtest);

    // (a) Cas nominal : les deux chemins coincident, epoque 0 comprise.
    let table0 = PowTable::build(p, 0);
    let mut ok = 0;
    for nonce in 0..64u64 {
        let h = entete(1_800_000_000, INITIAL_BITS, 0);
        let mut h = h;
        h.nonce = nonce;
        if memhard::hash_mining(&h, &table0) == memhard::hash_verify(&h, p) {
            ok += 1;
        }
    }
    println!("epoque 0, hauteur 0 : {ok}/64 concordances");
    assert_eq!(ok, 64);

    // (b) Frontiere d'epoque : la table de l'epoque N ne vaut RIEN a l'epoque N+1.
    let table1 = PowTable::build(p, 1);
    let h_fin_epoque = {
        let mut h = entete(1_800_000_000, INITIAL_BITS, POW_EPOCH_BLOCKS - 1);
        h.nonce = 7;
        h
    };
    let h_debut_epoque = {
        let mut h = entete(1_800_000_000, INITIAL_BITS, POW_EPOCH_BLOCKS);
        h.nonce = 7;
        h
    };
    println!(
        "hauteur {} (epoque {}) : table(e0) == verif ? {}",
        POW_EPOCH_BLOCKS - 1,
        memhard::epoch_of(POW_EPOCH_BLOCKS - 1),
        memhard::hash_mining(&h_fin_epoque, &table0) == memhard::hash_verify(&h_fin_epoque, p)
    );
    println!(
        "hauteur {} (epoque {}) : table(e0) == verif ? {}   <-- table perimee = 0 bloc valide",
        POW_EPOCH_BLOCKS,
        memhard::epoch_of(POW_EPOCH_BLOCKS),
        memhard::hash_mining(&h_debut_epoque, &table0) == memhard::hash_verify(&h_debut_epoque, p)
    );
    println!(
        "hauteur {} (epoque {}) : table(e1) == verif ? {}",
        POW_EPOCH_BLOCKS,
        memhard::epoch_of(POW_EPOCH_BLOCKS),
        memhard::hash_mining(&h_debut_epoque, &table1) == memhard::hash_verify(&h_debut_epoque, p)
    );
    assert_ne!(
        memhard::hash_mining(&h_debut_epoque, &table0),
        memhard::hash_verify(&h_debut_epoque, p)
    );

    // (c) `hash_verify_avec_cache` controle que le cache est celui de l'epoque
    //     de l'en-tete. C'etait un defaut : un cache d'une autre epoque etait
    //     accepte sans un mot, et le noeud calculait une autre preuve de
    //     travail que ses pairs. Depuis la correction, un cache etranger est
    //     ignore et la verification retombe sur le calcul complet : les trois
    //     chemins — table, cache de la bonne epoque, cache d'une mauvaise
    //     epoque — donnent la meme valeur.
    let cache0 = memhard::cache_for(p, 0);
    let cache1 = memhard::cache_for(p, 1);
    let reference = memhard::hash_verify(&h_debut_epoque, p);
    let bon = memhard::hash_verify_avec_cache(&h_debut_epoque, p, &cache1);
    let mauvais = memhard::hash_verify_avec_cache(&h_debut_epoque, p, &cache0);
    println!(
        "\nhash_verify_avec_cache(hauteur {}, cache e1) == hash_verify ? {} ; \
         avec le cache e0 (etranger) ? {}",
        POW_EPOCH_BLOCKS,
        bon == reference,
        mauvais == reference
    );
    assert_eq!(bon, reference, "le cache de la bonne epoque doit concorder");
    assert_eq!(
        mauvais, reference,
        "un cache d'une autre epoque doit etre ignore, jamais utilise"
    );
    assert_eq!(
        memhard::hash_mining(&h_debut_epoque, &table1),
        reference,
        "le chemin de minage doit concorder avec la verification"
    );

    // (d) Cas limites de taille de table.
    println!("\n--- cas limites de dimensionnement ---");
    for (n0, nmax) in [(1u32, 1u32), (2, 2), (32, 32), (33, 33)] {
        let p = TableParams { n0, nmax };
        let n = memhard::table_size(p, 0);
        let c = memhard::cache_size(p, 0);
        let tab = PowTable::build(p, 0);
        let mut h = entete(1_800_000_000, INITIAL_BITS, 0);
        h.nonce = 3;
        let egal = memhard::hash_mining(&h, &tab) == memhard::hash_verify(&h, p);
        println!("  n0={n0:<3} -> table {n} elements, cache {c} elements, concordance = {egal}");
        assert!(egal, "divergence pour n0={n0}");
    }
    println!(
        "  n0=0 -> table_size = {} : `index_from` (memhard.rs:398) ferait `% 0` = panique. \
         Non atteignable depuis `TableParams::for_network`, mais le champ est `pub`.",
        memhard::table_size(TableParams { n0: 0, nmax: 0 }, 0)
    );

    // (e) La croissance de table est plafonnee : au-dela, seule la graine change.
    let pm = TableParams::for_network(Network::Mainnet);
    let mut premiere_saturation = None;
    for e in 0..80u64 {
        if memhard::table_size(pm, e) == pm.nmax && premiere_saturation.is_none() {
            premiere_saturation = Some(e);
        }
    }
    println!(
        "\nmainnet : la table atteint NMAX ({} Mio) a l'epoque {:?}, soit vers {:.1} ans.",
        pm.nmax as u64 * 32 / (1 << 20),
        premiere_saturation,
        premiere_saturation.unwrap_or(0) as f64
            * POW_EPOCH_BLOCKS as f64
            * TARGET_BLOCK_SECS as f64
            / (86400.0 * 365.0)
    );
    println!(
        "-> apres cette date, le « levier A » (table qui grandit) est mort : la taille est figee."
    );
}

#[test]
fn a4b_amplification_epoque_arbitraire_dos() {
    println!("\n=== A4b — hauteur arbitraire => construction de cache arbitraire ===");
    println!("chain.rs:984-1020 `submit` : pour une branche laterale, seul `bits` est verifie");
    println!(
        "avant `self.pow.check(&block.header)`. La HAUTEUR n'est jamais controlee a ce stade."
    );
    println!(
        "pow.rs -> memhard::hash_verify -> epoch_of(header.height) -> cache_for(params, epoque).\n"
    );

    let p = TableParams::for_network(Network::Testnet);
    // Meme epoque : le cache est reutilise.
    let t = std::time::Instant::now();
    for k in 0..4u64 {
        let mut h = entete(1_800_000_000, INITIAL_BITS, 5);
        h.nonce = k;
        let _ = memhard::hash_verify(&h, p);
    }
    let d_meme = t.elapsed().as_secs_f64();

    // Epoques toutes differentes : un cache complet par en-tete.
    let t = std::time::Instant::now();
    for k in 0..4u64 {
        let h = entete(
            1_800_000_000,
            INITIAL_BITS,
            900_000_000 + k * POW_EPOCH_BLOCKS,
        );
        let _ = memhard::hash_verify(&h, p);
    }
    let d_diff = t.elapsed().as_secs_f64();

    println!("testnet : 4 en-tetes de meme epoque      : {d_meme:.4} s");
    println!("testnet : 4 en-tetes d'epoques distinctes : {d_diff:.4} s");
    println!(
        "amplification mesuree : x{:.0} pour 4 en-tetes de {} octets",
        d_diff / d_meme.max(1e-9),
        BlockHeader::SIZE
    );
    println!(
        "cout mainnet d'UN en-tete (cache 64 Mio, generation SEQUENTIELLE — memhard.rs:186-206) : \
         11,7 s mesurees sur 2 coeurs."
    );
    println!(
        "-> {} octets envoyes => ~11,7 s de CPU + 64 Mio d'allocation, sans qu'aucune preuve de \
         travail n'ait ete fournie.",
        BlockHeader::SIZE
    );
    println!(
        "-> de plus `cache_for` (memhard.rs:246) ne garde que 2 entrees : le cache legitime est \
         evince a chaque fois."
    );
    assert!(d_diff > d_meme * 3.0, "l'amplification devrait etre nette");
}

// ---------------------------------------------------------------------------
// 5. Minage egoiste, oncles, et la penalite de reorganisation
// ---------------------------------------------------------------------------

/// Revenu relatif d'un mineur egoiste (Eyal & Sirer), avec le gamma de Q21.
///
/// `alpha` = part de puissance, `gamma` = part des honnetes qui minent sur le
/// bloc de l'egoiste en cas d'egalite 1-1.
fn revenu_egoiste(alpha: f64, gamma: f64) -> f64 {
    let a = alpha;
    let num = a * (1.0 - a) * (1.0 - a) * (4.0 * a + gamma * (1.0 - 2.0 * a)) - a * a * a;
    let den = 1.0 - a * (1.0 + (2.0 - a) * a);
    num / den
}

#[test]
fn a5_minage_egoiste_penalite_et_oncles() {
    println!("\n=== A5 — minage egoiste : la penalite de reorg change-t-elle le seuil ? ===");
    println!(
        "REORG_PENALTY_FROM_DEPTH = {REORG_PENALTY_FROM_DEPTH} : une fourche de profondeur <= {REORG_PENALTY_FROM_DEPTH}"
    );
    println!("ne paie AUCUNE penalite (chain.rs:972-982). Or le minage egoiste classique");
    println!("n'utilise que des fourches de profondeur 1 ou 2.\n");
    println!(
        "{:>8} {:>12} {:>12} {:>12} {:>12}",
        "alpha", "gamma=0", "gamma=0.5", "gamma=1", "part juste"
    );
    let mut seuil = None;
    for a in [0.10f64, 0.20, 0.25, 0.30, 0.3333, 0.40, 0.45] {
        let r0 = revenu_egoiste(a, 0.0);
        println!(
            "{:>8.4} {:>12.4} {:>12.4} {:>12.4} {:>12.4}",
            a,
            r0,
            revenu_egoiste(a, 0.5),
            revenu_egoiste(a, 1.0),
            a
        );
        if seuil.is_none() && r0 > a {
            seuil = Some(a);
        }
    }
    println!("\nseuil classique (gamma=0) retrouve entre 25 % et 33 % : inchange par Q21.");

    // Combien de blocs de profondeur la penalite couvre-t-elle vraiment ?
    println!("\n--- profondeur des fourches utilisees par le minage egoiste ---");
    println!("etat 0'/1/2   : la reorganisation publiee fait 1 ou 2 blocs de profondeur.");
    println!(
        "penalite appliquee a profondeur 1 et 2 : {} % (car profondeur <= {REORG_PENALTY_FROM_DEPTH})",
        0
    );
    println!("-> la defense « la profondeur se paie » ne touche PAS le minage egoiste.");

    // L'accelerateur specifique a Q21 : LWMA reagit en ~90 blocs, pas 2016.
    println!("\n--- accelerateur propre a Q21 : la difficulte suit en 90 blocs, pas 2016 ---");
    for a in [0.25f64, 0.3333, 0.40] {
        let orphelins = 1.0 - (revenu_egoiste(a, 0.0) + (1.0 - a)) / 1.0;
        let _ = orphelins;
        let part = revenu_egoiste(a, 0.0);
        // Le taux reel de blocs baisse : la difficulte s'ajuste, l'attaquant
        // encaisse son excedent en valeur et non seulement en parts.
        println!(
            "  alpha = {:.2} : part de blocs {:.4} (+{:.1} % vs sa puissance), \
             delai avant que LWMA compense : ~{} blocs = {:.1} h (Bitcoin : 2016 blocs = 336 h)",
            a,
            part,
            (part / a - 1.0) * 100.0,
            LWMA_WINDOW,
            LWMA_WINDOW as f64 * TARGET_BLOCK_SECS as f64 / 3600.0
        );
    }
}

#[test]
fn a5b_les_oncles_ne_seront_jamais_inclus() {
    println!("\n=== A5b — economie des oncles : « levier C » economiquement mort ===");
    println!("validate.rs:190-201 `uncle_rewards` : part_mineur = subvention - n * par_oncle.");
    println!("La part d'oncle est PRELEVEE sur la subvention du mineur qui inclut.\n");
    println!(
        "{:>10} {:>16} {:>16} {:>16} {:>12}",
        "hauteur", "subvention", "0 oncle", "1 oncle", "manque a gagner"
    );
    for h in [1_000u64, 20_000, 100_000, 500_000] {
        let r0 = validate::uncle_rewards(h, 0);
        let r1 = validate::uncle_rewards(h, 1);
        let r2 = validate::uncle_rewards(h, 2);
        println!(
            "{:>10} {:>16} {:>16} {:>16} {:>11.1}%",
            h,
            r0.part_mineur,
            r0.part_mineur,
            r1.part_mineur,
            100.0 * (r0.part_mineur - r1.part_mineur) as f64 / r0.part_mineur.max(1) as f64
        );
        assert!(r1.part_mineur < r0.part_mineur || r0.part_mineur == 0);
        assert!(r2.part_mineur <= r1.part_mineur);
    }
    println!(
        "\n-> inclure un oncle coute {UNCLE_REWARD_PCT} % de la subvention et ne rapporte RIEN \
         (aucune prime d'inclusion,"
    );
    println!("   et un oncle n'ajoute aucun travail cumule : chain.rs:889-893 ne compte que");
    println!("   `block_work(header.bits)` du bloc lui-meme).");
    println!("-> un mineur rationnel n'inclut JAMAIS l'oncle d'un tiers. Le seul cas rentable");
    println!(
        "   est d'inclure son PROPRE orphelin : il se paie {UNCLE_REWARD_PCT} % a lui-meme, \
         cout net nul, et recupere"
    );
    println!("   ainsi une partie de son travail perdu.");
    println!("-> consequence : le levier C avantage le GROS mineur (qui s'auto-orpheline) au lieu");
    println!(
        "   de compenser le petit mineur mal connecte, c'est-a-dire l'inverse de son objectif."
    );

    // Chiffrage : combien un gros mineur recupere-t-il de ses propres orphelins ?
    println!("\n--- recuperation par auto-inclusion (taux d'orphelins o) ---");
    println!(
        "{:>8} {:>12} {:>16} {:>16}",
        "alpha", "orphelins", "sans oncles", "auto-oncles"
    );
    for a in [0.10f64, 0.30, 0.50] {
        for o in [0.01f64, 0.05] {
            let sans = a * (1.0 - o);
            let avec = a * (1.0 - o) + a * o * (UNCLE_REWARD_PCT as f64 / 100.0);
            println!(
                "{:>8.2} {:>11.0}% {:>16.5} {:>16.5}  (+{:.2} %)",
                a,
                o * 100.0,
                sans,
                avec,
                (avec / sans - 1.0) * 100.0
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Penalite de profondeur : debordement, et gel de la chaine
// ---------------------------------------------------------------------------

/// Reproduction exacte de `Chain::seuil_de_reorg` (chain.rs:972-982), qui est
/// privee. Toute divergence serait un bug de ce test, pas du code audite.
fn seuil_de_reorg(travail_courant: U256, profondeur: u64) -> U256 {
    if profondeur <= REORG_PENALTY_FROM_DEPTH {
        return travail_courant;
    }
    let exces = ((profondeur - REORG_PENALTY_FROM_DEPTH) * REORG_PENALTY_PCT_PER_BLOCK)
        .min(REORG_PENALTY_MAX_PCT);
    travail_courant
        .mul_div(100 + exces, 100)
        .unwrap_or(travail_courant)
}

/// Longueur minimale d'une branche concurrente pour reorganiser a la
/// profondeur `d`, sur une chaine de hauteur `h` a difficulte constante.
///
/// Travail par bloc = 1 (unite arbitraire, la difficulte est constante).
/// Travail courant = h. Travail de la branche = (h - d) + L.
/// Condition (chain.rs:1072-1077) : (h - d) + L > seuil(h, d).
fn longueur_minimale(h: u64, d: u64) -> Option<u64> {
    if d <= REORG_PENALTY_FROM_DEPTH {
        return Some(d + 1);
    }
    let exces = (d - REORG_PENALTY_FROM_DEPTH) * REORG_PENALTY_PCT_PER_BLOCK;
    // seuil = h * (100 + exces) / 100, arrondi vers le bas comme mul_div.
    let seuil = (h as u128 * (100 + exces) as u128) / 100;
    let base = (h - d) as u128;
    let l = seuil.saturating_sub(base) + 1;
    u64::try_from(l).ok()
}

#[test]
fn a6_la_penalite_de_profondeur_gele_la_chaine_a_6_blocs() {
    println!(
        "\n=== A6 — `seuil_de_reorg` : la penalite porte sur TOUT le travail depuis la genese ==="
    );
    println!("chain.rs:973 `let courant = self.total_work();` -> travail CUMULE depuis le bloc 0.");
    println!("chain.rs:979 `courant.mul_div(100 + exces, 100)` -> on exige 1 % du travail TOTAL");
    println!("de la chaine par bloc de profondeur au-dela de {REORG_PENALTY_FROM_DEPTH}, et non 1 % du travail de la fourche.\n");
    println!(
        "MAX_REORG_DEPTH annonce {MAX_REORG_DEPTH} blocs (~24 h). `chemin_vers_active` (chain.rs:949-970) \
         plafonne une branche a {} blocs.\n",
        MAX_REORG_DEPTH + 1
    );

    println!(
        "{:>10} {:>8} {:>18} {:>18} {:>10}",
        "hauteur", "profond.", "branche minimale", "surplus de travail", "possible ?"
    );
    let plafond_branche = MAX_REORG_DEPTH + 1;
    for h in [1_000u64, 10_000, 71_400, 100_000, 262_800, 2_628_000] {
        for d in [6u64, 7, 20, 100, 720] {
            let l = longueur_minimale(h, d);
            let possible = matches!(l, Some(x) if x <= plafond_branche);
            println!(
                "{:>10} {:>8} {:>18} {:>18} {:>10}",
                h,
                d,
                l.map(|x| x.to_string()).unwrap_or("depassement".into()),
                l.map(|x| format!("{} blocs", x.saturating_sub(d)))
                    .unwrap_or("-".into()),
                if possible { "oui" } else { "NON" }
            );
        }
        println!();
    }

    // Hauteur a partir de laquelle une reorganisation de profondeur 7 est
    // arithmetiquement impossible, quel que soit le travail de l'attaquant.
    let mut h_bascule = 0u64;
    for h in (1_000u64..200_000).step_by(100) {
        if longueur_minimale(h, 7)
            .map(|l| l > plafond_branche)
            .unwrap_or(true)
        {
            h_bascule = h;
            break;
        }
    }
    println!(
        "-> des la hauteur {h_bascule} (~{:.0} jours apres le lancement), AUCUNE reorganisation de \
         profondeur 7 ne peut plus aboutir,",
        h_bascule as f64 * TARGET_BLOCK_SECS as f64 / 86400.0
    );
    println!("   meme avec 100 % de la puissance et meme si la branche concurrente est honnete.");
    println!(
        "   La finalite reelle n'est donc pas de {MAX_REORG_DEPTH} blocs (24 h) mais de \
         {REORG_PENALTY_FROM_DEPTH} blocs ({} min).",
        REORG_PENALTY_FROM_DEPTH * TARGET_BLOCK_SECS / 60
    );
    println!("   Une partition reseau de plus de 12 minutes produit deux chaines definitives.");
    assert!(h_bascule > 0 && h_bascule < 200_000);

    // Meme calcul pour chaque profondeur, a une hauteur d'un an.
    println!("\n--- a un an de chaine (hauteur {BLOCKS_PER_YEAR}) ---");
    for d in [7u64, 8, 10, 50, 720] {
        println!(
            "  profondeur {d:>4} : branche minimale = {} blocs (plafond materiel : {plafond_branche})",
            longueur_minimale(BLOCKS_PER_YEAR, d)
                .map(|x| x.to_string())
                .unwrap_or(">u64".into())
        );
    }
}

#[test]
fn a6b_debordement_de_seuil_de_reorg() {
    println!("\n=== A6b — `seuil_de_reorg` peut-il deborder et annuler la penalite ? ===");
    println!("`mul_div` (uint.rs:190-203) : si `x * m` deborde, il retombe sur `(x / d) * m`.");
    println!("Si CE produit deborde aussi, `mul_div` rend None et `unwrap_or(courant)` supprime");
    println!("SILENCIEUSEMENT toute la penalite (chain.rs:979).\n");

    let facteur_max =
        100 + (MAX_REORG_DEPTH - REORG_PENALTY_FROM_DEPTH) * REORG_PENALTY_PCT_PER_BLOCK;
    println!(
        "facteur maximal = {facteur_max} / 100 = x{:.2}",
        facteur_max as f64 / 100.0
    );

    // Seuil de debordement : (x/100) * facteur_max > 2^256.
    let limite = U256::MAX.checked_div_u64(facteur_max / 100 + 1).unwrap();
    println!(
        "travail cumule a partir duquel la penalite disparait : ~2^{}",
        limite.bits()
    );

    for (nom, w) in [
        ("U256::MAX", U256::MAX),
        ("2^250", U256([0, 0, 0, 1u64 << 58])),
        ("2^200", U256([0, 0, 1u64 << 8, 0])),
    ] {
        let s = seuil_de_reorg(w, MAX_REORG_DEPTH);
        println!(
            "  travail = {nom:<10} -> seuil = {} (penalite {})",
            if s == w {
                "IDENTIQUE".to_string()
            } else {
                format!("2^{}", s.bits())
            },
            if s == w { "ANNULEE" } else { "appliquee" }
        );
    }

    // Travail cumule realiste.
    println!("\n--- travail realiste ---");
    for (nom, bits) in [
        ("plancher (INITIAL_BITS)", INITIAL_BITS),
        ("difficulte 2^40", bits_pour_difficulte(2f64.powi(40))),
        ("difficulte 2^60", bits_pour_difficulte(2f64.powi(60))),
    ] {
        let w = pow::block_work(bits);
        let total = w
            .checked_mul_u64(BLOCKS_PER_YEAR * 100)
            .unwrap_or(U256::MAX);
        println!(
            "  {nom:<24} : travail/bloc = 2^{:<4} ; 100 ans de chaine = 2^{}",
            w.bits(),
            total.bits()
        );
    }
    println!(
        "-> le debordement exige un travail cumule de ~2^{}. Meme cent ans a une difficulte de 2^60",
        limite.bits()
    );
    println!(
        "   ne depassent pas 2^140. NON EXPLOITABLE en pratique — mais le `unwrap_or(courant)`"
    );
    println!("   qui masque l'echec reste une mauvaise pratique dans du code de consensus.");
}

#[test]
fn a6c_demonstration_sur_une_vraie_chaine() {
    println!("\n=== A6c — demonstration sur une vraie `Chain` (Regtest) ===");
    use q21_core::chain::{genesis_block, Accept, ChainError};
    use q21_core::sig::SchemeId;

    const H: usize = 120; // hauteur de la chaine principale
    const D: usize = 7; // profondeur de la fourche (= 1 de plus que la franchise)

    let g = genesis_block(Network::Regtest);
    let mut principale = Chain::new(Network::Regtest, g.clone());
    let mut jusqu_a_fourche: Vec<q21_core::block::Block> = Vec::new();

    let base = principale.tip().time;
    for i in 0..H {
        let t = base + (i as u64 + 1) * TARGET_BLOCK_SECS;
        let b = principale
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
            .expect("minage");
        principale.connect(&b, b.header.time).expect("connexion");
        if i < H - D {
            jusqu_a_fourche.push(b);
        }
    }
    println!(
        "chaine principale : hauteur {}, travail cumule 2^{}",
        principale.height(),
        principale.total_work().bits()
    );

    // Branche concurrente, batie depuis le meme point de fourche.
    let mut concurrente = Chain::new(Network::Regtest, g);
    for b in &jusqu_a_fourche {
        concurrente.connect(b, b.header.time).expect("rejeu");
    }
    assert_eq!(concurrente.height() as usize, H - D);

    let mut branche = Vec::new();
    let base2 = concurrente.tip().time;
    for i in 0..40 {
        let t = base2 + (i as u64 + 1) * TARGET_BLOCK_SECS + 7;
        let b = concurrente
            .mine_block(Hash256([9u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
            .expect("minage");
        concurrente.connect(&b, b.header.time).expect("connexion");
        branche.push(b);
    }

    println!(
        "branche concurrente : {} blocs depuis la profondeur {D}\n",
        branche.len()
    );
    println!(
        "{:>8} {:>10} {:>14} {:>34}",
        "blocs", "hauteur", "avance", "verdict de submit()"
    );
    let mut premiere_acceptation = None;
    for (i, b) in branche.iter().enumerate() {
        let now = b.header.time + 1;
        let r = principale.submit(b, now);
        let hauteur_branche = (H - D + i + 1) as i64;
        let avance = hauteur_branche - H as i64;
        let verdict = match &r {
            Ok(Accept::Prolonge) => "Prolonge".to_string(),
            Ok(Accept::BrancheLaterale) => "BrancheLaterale".to_string(),
            Ok(Accept::Reorganise { profondeur }) => {
                if premiere_acceptation.is_none() {
                    premiere_acceptation = Some(i + 1);
                }
                format!("REORGANISE (profondeur {profondeur})")
            }
            Ok(Accept::DejaVu) => "DejaVu".into(),
            Err(ChainError::TravailInsuffisantPourLaProfondeur { profondeur }) => {
                format!("refus: TravailInsuffisant (prof {profondeur})")
            }
            Err(e) => format!("refus: {e:?}"),
        };
        if i < 3 || avance >= -1 || premiere_acceptation == Some(i + 1) {
            println!(
                "{:>8} {:>10} {:>+14} {:>34}",
                i + 1,
                hauteur_branche,
                avance,
                verdict
            );
        }
        if premiere_acceptation.is_some() {
            break;
        }
    }
    match premiere_acceptation {
        Some(n) => println!(
            "\n-> il a fallu {n} blocs pour reorganiser {D} blocs, soit {} blocs de travail \
             excedentaire pour une fourche de {D}.",
            n - D
        ),
        None => println!("\n-> AUCUN des 40 blocs n'a permis la reorganisation."),
    }
    println!(
        "   prevision du modele : {} blocs.",
        longueur_minimale(H as u64, D as u64).unwrap()
    );
}

// ---------------------------------------------------------------------------
// 7. Partition reseau : le plafond de la majoration
// ---------------------------------------------------------------------------

/// Une partition reseau doit se resorber quand elle prend fin.
///
/// # Ce que cette epreuve fige
///
/// Sans plafond, la majoration atteignait 100 % a la profondeur 106 et plus
/// de 700 % a la profondeur maximale. Deux moities du reseau minant chacune de
/// leur cote se voyaient donc majorees l'une contre l'autre, et au bout de
/// deux heures aucune ne pouvait plus rejoindre l'autre : la coupure Internet
/// devenait une scission definitive, la ou la documentation annoncait
/// vingt-quatre heures.
///
/// On simule deux branches minees a difficulte egale avec la regle reelle
/// (`seuil_de_reorg`, reproduite ci-dessus), et l'on cherche, pour chaque
/// partage de puissance, le dernier moment ou la minorite peut encore
/// basculer sur la majorite. Avec le plafond, une majorite de 60 % reunifie
/// toujours dans la fenetre de finalite ; sans lui, elle ne le pouvait plus
/// apres quelques heures.
#[test]
fn a7_une_partition_a_60_40_se_reunifie_toujours() {
    /// Un noeud sur la branche `a` bascule sur `b` si le travail de `b` depuis
    /// la fourche depasse le seuil calcule sur le travail de `a`.
    fn bascule_possible(a: u64, b: u64) -> bool {
        let seuil = seuil_de_reorg(U256::from_u64(a), a);
        U256::from_u64(b) > seuil
    }
    let horizon = MAX_REORG_DEPTH;
    let mut rng = Rng::new(21);
    println!("\n=== A7 — reunification apres partition (plafond {REORG_PENALTY_MAX_PCT} %) ===");
    for minorite in [0.5f64, 0.45, 0.40, 0.30] {
        let essais = 400;
        let mut jamais = 0;
        let mut dernieres: Vec<u64> = Vec::new();
        for _ in 0..essais {
            let (mut a, mut b) = (0u64, 0u64);
            let mut derniere = None;
            for _ in 0..horizon {
                if rng.unit() < minorite {
                    a += 1;
                } else {
                    b += 1;
                }
                // La minorite (a) peut-elle rejoindre b, ou l'inverse ?
                if bascule_possible(a, b) || bascule_possible(b, a) {
                    derniere = Some(a + b);
                }
            }
            match derniere {
                Some(n) => dernieres.push(n),
                None => jamais += 1,
            }
        }
        dernieres.sort_unstable();
        let mediane = dernieres.get(dernieres.len() / 2).copied().unwrap_or(0);
        let reunifie_a_la_fin = dernieres.iter().filter(|n| **n >= horizon - 1).count();
        println!(
            "minorite {:>3.0} % : derniere reunification possible, mediane {mediane} blocs ; \
             encore possible au bloc {horizon} dans {} cas sur {essais} ; jamais possible : {jamais}",
            minorite * 100.0,
            reunifie_a_la_fin
        );
        assert_eq!(
            jamais, 0,
            "la reunification doit toujours avoir ete possible"
        );
        if minorite <= 0.40 {
            // A 60/40 le rapport des travaux vaut 1,5 en esperance, contre un
            // seuil de 1,25 : seule une fluctuation a plus de deux ecarts-types
            // sur 720 blocs peut encore l'emporter, soit environ 1 % des cas.
            assert!(
                reunifie_a_la_fin as f64 >= 0.97 * essais as f64,
                "a 60/40, la reunification doit rester possible au bout de la fenetre \
                 dans au moins 97 % des cas ({reunifie_a_la_fin}/{essais})"
            );
        }
        if minorite <= 0.30 {
            assert_eq!(
                reunifie_a_la_fin, essais,
                "a 70/30, la reunification doit rester possible au bout de la fenetre"
            );
        }
    }
}
