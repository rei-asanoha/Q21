//! Audit adverse — axe « reservoir de transactions et epuisement de ressources ».
//!
//! Chaque test correspond a une faille candidate. Il mesure, il n'argumente pas.

use q21_core::amount::Amount;
use q21_core::consensus::WITNESS_DISCOUNT;
use q21_core::hash::Hash256;
use q21_core::lamport;
use q21_core::mempool::{Mempool, MempoolError, MEMPOOL_MAX_BYTES, MIN_FEE_RATE};
use q21_core::sig::{self, SchemeId};
use q21_core::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use q21_core::utxo::{UtxoEntry, UtxoSet};
use q21_core::Network;

use std::time::Instant;

const RESEAU: Network = Network::Regtest;
const GRAINE: [u8; 32] = [0x5a; 32];

// ---------------------------------------------------------------------------
// Outillage : fabriquer des transactions signees a volonte, sans miner.
// ---------------------------------------------------------------------------

/// Clef Lamport n° `i` et son empreinte de verrou.
fn clef(i: u32) -> (lamport::SecretKey, Vec<u8>, Hash256) {
    let sk = lamport::SecretKey::from_seed(GRAINE, i);
    let pk = sk.public_key();
    let h = sig::pubkey_hash(SchemeId::LamportOts, &pk);
    (sk, pk, h)
}

/// Jeu d'UTXO synthetique : `n` sorties de `valeur` unites, chacune verrouillee
/// par une clef Lamport distincte. Rend aussi la liste des points de sortie.
fn utxo_synthetique(n: u32, valeur: u64, depart: u32) -> (UtxoSet, Vec<(OutPoint, u32)>) {
    let mut u = UtxoSet::new();
    let mut v = Vec::new();
    for i in 0..n {
        let idx = depart + i;
        let (_, _, h) = clef(idx);
        let o = OutPoint {
            txid: Hash256([(idx % 251) as u8; 32]),
            index: idx,
        };
        u.insert(
            o,
            UtxoEntry {
                output: TxOut {
                    value: Amount::from_units(valeur),
                    scheme: SchemeId::LamportOts,
                    pubkey_hash: h,
                },
                height: 1,
                is_coinbase: false,
            },
        );
        v.push((o, idx));
    }
    (u, v)
}

/// Construit et signe une transaction depensant `entrees` vers `sorties`.
fn tx_signee(entrees: &[(OutPoint, u32)], sorties: Vec<TxOut>, lock_time: u64) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: entrees
            .iter()
            .map(|(o, _)| TxIn {
                prev_out: *o,
                witness: Witness::default(),
                sequence: 0xffff_ffff,
            })
            .collect(),
        outputs: sorties,
        lock_time,
    };
    // Le sighash ne couvre pas les temoins : on peut signer apres coup.
    for (i, (_, idx)) in entrees.iter().enumerate() {
        let (sk, pk, _) = clef(*idx);
        let m = tx.sighash(i as u32);
        tx.inputs[i].witness = Witness {
            pubkey: pk,
            signature: sk.sign(&m),
        };
    }
    tx
}

fn sortie(valeur: u64, h: Hash256) -> TxOut {
    TxOut {
        value: Amount::from_units(valeur),
        scheme: SchemeId::LamportOts,
        pubkey_hash: h,
    }
}

/// Empreinte quelconque, sans clef derriere (destinataire brule).
fn puits(n: u8) -> Hash256 {
    Hash256([n; 32])
}

fn rss_kio() -> u64 {
    let s = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages: u64 = s
        .split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    pages * 4
}

// ---------------------------------------------------------------------------
// 1. Cout de verification asymetrique : l'ordre des rejets
// ---------------------------------------------------------------------------

/// Une transaction a frais nuls est-elle rejetee avant ou apres les signatures ?
#[test]
fn t01_le_filtre_de_frais_passe_apres_la_verification_des_signatures() {
    const K: u32 = 40;
    let (u, ops) = utxo_synthetique(K, 1_000, 0);

    // Frais nuls : la somme des sorties egale la somme des entrees.
    let tx = tx_signee(&ops, vec![sortie(K as u64 * 1_000, puits(0xaa))], 0);
    let taille = tx.encode().len();

    let mut m = Mempool::new();
    let t0 = Instant::now();
    let r = m.accept(&tx, &u, RESEAU, 10);
    let cher = t0.elapsed();

    // Meme transaction, mais une clef publique qui ne correspond pas au verrou :
    // rejet AVANT toute verification cryptographique.
    let mut tx2 = tx.clone();
    for e in &mut tx2.inputs {
        e.witness.pubkey[0] ^= 0xff;
    }
    let mut m2 = Mempool::new();
    let t1 = Instant::now();
    let r2 = m2.accept(&tx2, &u, RESEAU, 10);
    let bon_marche = t1.elapsed();

    println!("--- t01 : ordre des rejets ---");
    println!("  transaction : {K} entrees, {taille} octets serialises");
    println!("  rejet a frais nuls      : {r:?} en {cher:?}");
    println!("  rejet clef non conforme : {r2:?} en {bon_marche:?}");
    println!(
        "  rapport de cout : x{:.1}",
        cher.as_secs_f64() / bon_marche.as_secs_f64().max(1e-9)
    );
    println!(
        "  cout CPU par octet recu (rejet a frais nuls) : {:.3} us/Kio",
        cher.as_secs_f64() * 1e6 / (taille as f64 / 1024.0)
    );

    assert!(
        matches!(r, Err(MempoolError::TauxDeFraisTropBas { .. })),
        "attendu : rejet pour frais insuffisants APRES les signatures, obtenu {r:?}"
    );
    assert!(
        cher > bon_marche * 4,
        "le rejet a frais nuls doit couter bien plus cher : {cher:?} vs {bon_marche:?}"
    );
}

/// Cout de la verification ML-DSA-65 reelle, et amplification par octet recu.
#[cfg(feature = "mldsa")]
#[test]
fn t02_cout_mldsa_reel_et_amplification() {
    use q21_core::sig::verify;

    // Un couple clef/signature ML-DSA-65 authentique, via le portefeuille.
    let mut w = q21_core::Wallet::from_seed_scheme(GRAINE, RESEAU, SchemeId::MlDsa65).unwrap();
    let a = w.new_address();
    // On fabrique une transaction reelle pour obtenir une vraie signature.
    let mut u = UtxoSet::new();
    let o = OutPoint {
        txid: Hash256([9u8; 32]),
        index: 0,
    };
    u.insert(
        o,
        UtxoEntry {
            output: TxOut {
                value: Amount::from_units(1_000_000),
                scheme: SchemeId::MlDsa65,
                pubkey_hash: a.hash,
            },
            height: 1,
            is_coinbase: false,
        },
    );
    let mut dest =
        q21_core::Wallet::from_seed_scheme([0x77; 32], RESEAU, SchemeId::MlDsa65).unwrap();
    let da = dest.new_address();
    let tx = w
        .create_transaction(
            &u,
            10,
            &da,
            Amount::from_units(1_000),
            Amount::from_units(100),
        )
        .expect("construction");

    let pk = tx.inputs[0].witness.pubkey.clone();
    let sg = tx.inputs[0].witness.signature.clone();
    let msg = tx.sighash(0);
    assert!(verify(SchemeId::MlDsa65, &pk, &msg, &sg).is_ok());

    const N: u32 = 200;
    let t0 = Instant::now();
    for _ in 0..N {
        let _ = verify(SchemeId::MlDsa65, &pk, &msg, &sg);
    }
    let par_verif = t0.elapsed().as_secs_f64() / N as f64;

    // Une signature invalide coute-t-elle aussi cher ? (pire cas pour le noeud)
    let mut faux = sg.clone();
    faux[100] ^= 0x01;
    let t1 = Instant::now();
    for _ in 0..N {
        let _ = verify(SchemeId::MlDsa65, &pk, &msg, &faux);
    }
    let par_verif_fausse = t1.elapsed().as_secs_f64() / N as f64;

    // Octets qu'un attaquant doit envoyer pour declencher une verification :
    // le temoin (clef + signature) plus les 44 octets de l'entree.
    let octets_par_entree = pk.len() + sg.len() + 44 + 4;
    let us_par_kio = par_verif * 1e6 / (octets_par_entree as f64 / 1024.0);

    println!("--- t02 : cout ML-DSA-65 mesure ---");
    println!("  verification valide  : {:.1} us", par_verif * 1e6);
    println!("  verification fausse  : {:.1} us", par_verif_fausse * 1e6);
    println!("  octets par entree    : {octets_par_entree}");
    println!("  cout CPU par Kio recu : {us_par_kio:.1} us/Kio");
    for debit_mbps in [10u64, 100, 1000] {
        let kio_par_sec = debit_mbps as f64 * 1e6 / 8.0 / 1024.0;
        let cpu_sec_par_sec = kio_par_sec * us_par_kio / 1e6;
        println!(
            "  a {debit_mbps} Mbit/s : {cpu_sec_par_sec:.1} s de CPU consommes par seconde \
             ({:.0} coeurs saturés)",
            cpu_sec_par_sec.ceil()
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Remplir le mempool a cout nul
// ---------------------------------------------------------------------------

/// Frais minimaux reels pour franchir MIN_FEE_RATE, et cout total d'un mempool plein.
#[test]
fn t03_cout_reel_de_saturer_le_reservoir() {
    // Transaction type : 1 entree ML-DSA-65, 2 sorties.
    let base = 4 + 1 + 44 + 1 + 2 * 41 + 8u64;
    let temoin = 1952 + 3309 + 6u64; // clef + signature + varints
    let poids = base * WITNESS_DISCOUNT + temoin;
    let taille = base + temoin;
    // fee * 1000 / poids >= MIN_FEE_RATE
    let frais_mini = (MIN_FEE_RATE * poids).div_ceil(1000);
    let n = MEMPOOL_MAX_BYTES as u64 / taille;

    println!("--- t03 : cout de saturation ---");
    println!("  transaction type ML-DSA-65 : {taille} octets, poids pondere {poids}");
    println!(
        "  frais minimaux acceptes    : {frais_mini} unites = {:.10} Q21",
        frais_mini as f64 / 1e8
    );
    println!("  transactions pour saturer 64 Mio : {n}");
    println!(
        "  cout total des frais       : {} unites = {:.8} Q21",
        n * frais_mini,
        (n * frais_mini) as f64 / 1e8
    );
    println!("  ... et ces frais ne sont dus QUE si les transactions sont minees (cf. t04/t05)");

    // Verification empirique du seuil sur une transaction Lamport reelle.
    let (u, ops) = utxo_synthetique(1, 1_000_000, 5_000);
    let mut m = Mempool::new();
    let t = tx_signee(&ops, vec![sortie(1_000_000 - 1, puits(1))], 0);
    let r = m.accept(&t, &u, RESEAU, 10);
    println!(
        "  1 unite de frais sur une transaction Lamport de {} octets : {r:?}",
        t.encode().len()
    );
    assert!(matches!(r, Err(MempoolError::TauxDeFraisTropBas { .. })));
}

// ---------------------------------------------------------------------------
// 4. Une transaction que personne ne peut miner
// ---------------------------------------------------------------------------

/// `accept` ne borne ni la taille ni le poids d'une transaction. Une transaction
/// plus lourde que le budget du mineur est acceptee, occupe le reservoir, et
/// n'est jamais selectionnee : ses frais ne sont donc jamais dus.
#[test]
fn t04_une_transaction_plus_lourde_qu_un_bloc_est_acceptee_et_jamais_minee() {
    // Le mineur du binaire q21 appelle select_for_block(2_000_000).
    const POIDS_MINEUR: u64 = 2_000_000;
    const K: u32 = 120; // 120 entrees Lamport ~ 3 Mo, poids > 2 000 000

    let (u, ops) = utxo_synthetique(K, 1_000_000, 10_000);
    // Frais tres eleves : taux de frais maximal, donc inevincable.
    let tx = tx_signee(&ops, vec![sortie(1, puits(2))], 0);
    let poids = tx.weight(WITNESS_DISCOUNT);
    let taille = tx.encode().len();

    let mut m = Mempool::new();
    let id = m
        .accept(&tx, &u, RESEAU, 10)
        .expect("le mempool accepte une transaction inminable");

    let choisies = m.select_for_block(POIDS_MINEUR);
    let choisies_max = m.select_for_block(u64::MAX);

    println!("--- t04 : transaction inminable ---");
    println!("  taille {taille} octets, poids pondere {poids} (budget mineur {POIDS_MINEUR})");
    println!(
        "  MAX_BLOCK_SIZE = {} octets",
        q21_core::consensus::MAX_BLOCK_SIZE
    );
    println!("  acceptee au mempool : oui, id {}", hex(&id));
    println!(
        "  select_for_block(2_000_000) : {} transaction(s)",
        choisies.len()
    );
    println!(
        "  select_for_block(u64::MAX)  : {} transaction(s)",
        choisies_max.len()
    );
    println!(
        "  frais reclames : {} unites, jamais payes",
        tx.inputs.len() as u64 * 1_000_000 - 1
    );

    assert!(poids > POIDS_MINEUR);
    assert!(
        choisies.is_empty(),
        "une transaction plus lourde que le budget n'est jamais selectionnee"
    );
    assert_eq!(m.len(), 1, "et elle reste indefiniment au reservoir");
}

/// Une transaction plus grosse que MAX_BLOCK_SIZE : jamais minable par personne.
#[test]
fn t04b_une_transaction_plus_grosse_qu_un_bloc_entier_est_acceptee() {
    const K: u32 = 200; // 200 * ~24,6 Kio ~ 4,9 Mio > MAX_BLOCK_SIZE (4 Mio)
    let (u, ops) = utxo_synthetique(K, 1_000_000, 20_000);
    let tx = tx_signee(&ops, vec![sortie(1, puits(3))], 0);
    let taille = tx.encode().len();

    let mut m = Mempool::new();
    let r = m.accept(&tx, &u, RESEAU, 10);

    println!("--- t04b : transaction plus grosse qu'un bloc ---");
    println!(
        "  taille {taille} octets vs MAX_BLOCK_SIZE {}",
        q21_core::consensus::MAX_BLOCK_SIZE
    );
    println!("  acceptee : {}", r.is_ok());
    assert!(taille > q21_core::consensus::MAX_BLOCK_SIZE);
    assert!(r.is_ok(), "aucun controle de taille a l'entree du mempool");
}

// ---------------------------------------------------------------------------
// 3/5. Eviction manipulable
// ---------------------------------------------------------------------------

/// Saturer le reservoir avec des transactions inminables a taux de frais eleve,
/// puis constater qu'une transaction honnete normale est refusee.
#[test]
fn t05_eviction_des_honnetes_par_des_transactions_qui_ne_seront_jamais_minees() {
    const PAR_TX: u32 = 90; // ~2,2 Mio, poids ~2,23 M > budget du mineur
    let mut m = Mempool::new();
    let mut depart = 100_000u32;
    let mut u = UtxoSet::new();
    let mut n_attaque = 0usize;
    let mut poids_attaque = 0u64;
    let t0 = Instant::now();

    // Chaque transaction : PAR_TX entrees, une seule sortie de 1 unite -> taux
    // de frais quasi maximal, et poids > budget du mineur.
    loop {
        let (uu, ops) = utxo_synthetique(PAR_TX, 1_000_000, depart);
        for (o, _) in &ops {
            u.insert(*o, *uu.get(o).unwrap());
        }
        depart += PAR_TX;
        let tx = tx_signee(&ops, vec![sortie(1, puits(4))], 0);
        poids_attaque = tx.weight(WITNESS_DISCOUNT);
        match m.accept(&tx, &u, RESEAU, 10) {
            Ok(_) => n_attaque += 1,
            Err(e) => {
                println!("  reservoir sature apres {n_attaque} transactions : {e:?}");
                break;
            }
        }
    }
    let duree_remplissage = t0.elapsed();
    println!("  poids d'une transaction d'attaque : {poids_attaque}");

    // Deuxieme couche : la plus PETITE transaction inminable possible. Le poids
    // pondere compte le corps quatre fois : une transaction a une entree et
    // ~12 100 sorties depasse le budget du mineur pour ~520 Kio seulement.
    let mut n_fines = 0usize;
    loop {
        let gap = MEMPOOL_MAX_BYTES.saturating_sub(m.bytes());
        let (uu, ops) = utxo_synthetique(1, 1_000_000, depart);
        depart += 1;
        for (o, _) in &ops {
            u.insert(*o, *uu.get(o).unwrap());
        }
        let mut outs: Vec<TxOut> = (0..12_100).map(|_| sortie(0, puits(4))).collect();
        outs[0] = sortie(1, puits(4));
        let tx = tx_signee(&ops, outs, 0);
        if tx.encode().len() > gap || tx.weight(WITNESS_DISCOUNT) <= 2_000_000 {
            println!(
                "  plus fine transaction inminable : {} octets, poids {} ; espace restant {gap}",
                tx.encode().len(),
                tx.weight(WITNESS_DISCOUNT)
            );
            break;
        }
        m.accept(&tx, &u, RESEAU, 10).expect("acceptation fine");
        n_fines += 1;
    }

    // Transaction honnete : 1 entree, frais genereux mais taux ordinaire.
    let (uh, oph) = utxo_synthetique(1, 1_000_000, 900_000);
    for (o, _) in &oph {
        u.insert(*o, *uh.get(o).unwrap());
    }
    let honnete = tx_signee(&oph, vec![sortie(900_000, puits(5))], 0);
    let poids_h = honnete.weight(WITNESS_DISCOUNT);
    let taux_h = 100_000u64 * 1000 / poids_h;
    let occupe = m.bytes();
    let r = m.accept(&honnete, &u, RESEAU, 10);

    let minables = m.select_for_block(2_000_000);
    let octets_minables: usize = minables.iter().map(|t| t.encode().len()).sum();

    println!("--- t05 : eviction ---");
    println!(
        "  remplissage : {n_attaque} grosses + {n_fines} fines, {} Mio sur 64, en {duree_remplissage:?}",
        occupe / 1024 / 1024
    );
    println!(
        "  part du reservoir occupee par de l'inminable : {:.2} %",
        100.0 * (occupe - octets_minables) as f64 / MEMPOOL_MAX_BYTES as f64
    );
    println!(
        "  espace laisse aux transactions honnetes : {} octets (~{} transactions ML-DSA de 5,4 Kio)",
        MEMPOOL_MAX_BYTES - occupe,
        (MEMPOOL_MAX_BYTES - occupe) / 5_400
    );
    println!("  contre {} sans attaque", MEMPOOL_MAX_BYTES / 5_400);
    println!("  honnete : poids {poids_h}, frais 100 000 unites, taux {taux_h} -> {r:?}");
    println!("  cout reel pour l'attaquant : 0 unite (rien n'est minable, donc rien n'est paye)");

    assert!(
        octets_minables * 100 < occupe,
        "plus de 1 % du reservoir est minable : {octets_minables} sur {occupe}"
    );
    assert!(
        MEMPOOL_MAX_BYTES - occupe < MEMPOOL_MAX_BYTES / 100,
        "il reste plus de 1 % de place : {} octets",
        MEMPOOL_MAX_BYTES - occupe
    );
}

// ---------------------------------------------------------------------------
// 4bis. Cout quadratique de l'eviction en paquet
// ---------------------------------------------------------------------------

/// Construit une chaine de `n` transactions non confirmees.
fn chaine_mempool(n: u32, m: &mut Mempool, base: u32) -> Hash256 {
    let (u, ops) = utxo_synthetique(1, 100_000_000, base);
    // Chaque maillon depense la sortie 0 du precedent.
    let mut courant = ops[0];
    let mut racine = Hash256::ZERO;
    for i in 0..n {
        let idx = base + 1 + i;
        let (_, _, h) = clef(idx);
        // Une sortie qui reste depensable par la clef suivante.
        let valeur = 100_000_000 - 1_000 * (i as u64 + 1);
        let tx = tx_signee(&[courant], vec![sortie(valeur, h)], 0);
        let id = m.accept(&tx, &u, RESEAU, 10).expect("maillon");
        if i == 0 {
            racine = id;
        }
        courant = (OutPoint { txid: id, index: 0 }, idx);
    }
    racine
}

#[test]
fn t06_l_eviction_en_paquet_est_quadratique_en_la_profondeur_de_chaine() {
    println!("--- t06 : cout de remove() sur une chaine ---");
    let mut mesures = Vec::new();
    for n in [500u32, 1000, 2000, 2600] {
        let mut m = Mempool::new();
        let racine = chaine_mempool(n, &mut m, 1_000_000 + n * 10);
        assert_eq!(m.len(), n as usize);
        let t0 = Instant::now();
        m.remove(&racine);
        let d = t0.elapsed();
        assert!(m.is_empty());
        println!("  chaine de {n:5} : remove() = {d:?}");
        mesures.push((n as f64, d.as_secs_f64()));
    }
    let (n1, t1) = mesures[0];
    let (n2, t2) = mesures[mesures.len() - 1];
    let exposant = (t2 / t1).ln() / (n2 / n1).ln();
    println!("  exposant empirique : n^{exposant:.2}  (1 = lineaire, 2 = quadratique)");
    println!(
        "  borne : le plafond de 64 Mio limite la chaine a ~{} maillons ML-DSA",
        MEMPOOL_MAX_BYTES / 5_400
    );
    assert!(
        exposant > 1.2,
        "attendu un comportement superlineaire, mesure n^{exposant:.2}"
    );
}

/// `select_for_block` recalcule le `txid` — donc un SHA-256 sur tout le corps de
/// la transaction — a **chaque comparaison** du tri : `Ordering::then` evalue son
/// argument sans paresse. Le cout devient n log n fois la taille des corps.
#[test]
fn t11_select_for_block_rehashe_a_chaque_comparaison_du_tri() {
    const N: u32 = 400;
    const SORTIES: usize = 12_000;

    let mut m = Mempool::new();
    let mut u = UtxoSet::new();
    for i in 0..N {
        let (uu, ops) = utxo_synthetique(1, 1_000_000, 2_000_000 + i);
        for (o, _) in &ops {
            u.insert(*o, *uu.get(o).unwrap());
        }
        let mut outs: Vec<TxOut> = (0..SORTIES).map(|_| sortie(0, puits(11))).collect();
        outs[0] = sortie(1, puits(11));
        let tx = tx_signee(&ops, outs, i as u64);
        if m.accept(&tx, &u, RESEAU, 10).is_err() {
            break;
        }
    }
    let n = m.len();
    let octets = m.bytes();

    let t0 = Instant::now();
    let choisies = m.select_for_block(2_000_000);
    let d = t0.elapsed();

    // Cout d'un seul txid, pour attribuer la depense.
    let un = m.txids();
    let tx0 = m.get(&un[0]).unwrap().clone();
    let t1 = Instant::now();
    for _ in 0..50 {
        let _ = tx0.txid();
    }
    let par_txid = t1.elapsed().as_secs_f64() / 50.0;

    println!("--- t11 : cout du tri de select_for_block ---");
    println!("  reservoir : {n} transactions, {} Mio", octets / 1048576);
    println!(
        "  select_for_block(2 000 000) : {d:?} pour {} transaction(s) retenue(s)",
        choisies.len()
    );
    println!(
        "  un txid = {:.0} us ; comparaisons attendues ~ n log2 n = {:.0}",
        par_txid * 1e6,
        n as f64 * (n as f64).log2()
    );
    println!(
        "  soit ~{:.2} s de SHA-256 pur pour un reservoir de 64 Mio ainsi rempli",
        d.as_secs_f64() * (MEMPOOL_MAX_BYTES as f64 / octets as f64)
    );
    println!(
        "  appele sous le verrou global du noeud a chaque modele de bloc (src/bin/q21.rs:1485)"
    );

    assert!(
        d.as_secs_f64() > 50.0 * par_txid,
        "le tri devrait couter bien plus qu'un txid : {d:?}"
    );
}

/// L'eviction ne raisonne que sur le taux de frais **individuel**. Un parent
/// moins-disant emporte tous ses descendants, y compris ceux qui paient le plus.
#[test]
fn t12_l_eviction_detruit_les_enfants_bien_payants_avec_leur_parent() {
    let (u, ops) = utxo_synthetique(1, 100_000_000, 3_000_000);
    let mut m = Mempool::new();

    // Parent a taux faible.
    let (_, _, h_enfant) = clef(3_000_001);
    let parent = tx_signee(&ops, vec![sortie(99_999_000, h_enfant)], 0);
    let id_parent = m.accept(&parent, &u, RESEAU, 10).unwrap();
    // Enfant a taux tres eleve.
    let enfant = tx_signee(
        &[(
            OutPoint {
                txid: id_parent,
                index: 0,
            },
            3_000_001,
        )],
        vec![sortie(1, puits(12))],
        0,
    );
    let id_enfant = m.accept(&enfant, &u, RESEAU, 10).unwrap();

    let taux = |t: &Transaction, frais: u64| frais * 1000 / t.weight(WITNESS_DISCOUNT);
    println!("--- t12 : eviction en paquet et frais des enfants ---");
    println!("  parent : frais 1 000, taux {}", taux(&parent, 1_000));
    println!(
        "  enfant : frais 99 998 999, taux {}",
        taux(&enfant, 99_998_999)
    );

    // Retirer le parent (ce que fait faire_de_la_place s'il est moins-disant)
    // emporte l'enfant, quel que soit ce que l'enfant paie.
    m.remove(&id_parent);
    println!(
        "  apres retrait du parent : enfant encore la ? {}",
        m.contains(&id_enfant)
    );
    assert!(
        !m.contains(&id_enfant),
        "l'enfant le mieux-disant du reservoir disparait avec son parent"
    );
    println!("  faire_de_la_place (src/mempool.rs:269) ne regarde que le taux individuel :");
    println!("  aucun score d'ancetre/descendant, donc pas de CPFP et un vecteur de pinning.");
}

// ---------------------------------------------------------------------------
// 5. revalidate
// ---------------------------------------------------------------------------

/// `revalidate` valide chaque transaction contre une vue dont `consommees`
/// contient **ses propres entrees**. Elles lui sont donc invisibles.
#[test]
fn t07_revalidate_detruit_un_reservoir_parfaitement_valide() {
    let (u, ops) = utxo_synthetique(3, 1_000_000, 300_000);
    let mut m = Mempool::new();
    for (i, op) in ops.iter().enumerate() {
        let tx = tx_signee(&[*op], vec![sortie(900_000, puits(6))], i as u64);
        m.accept(&tx, &u, RESEAU, 10).expect("acceptation");
    }
    let avant = m.len();

    // Rien n'a change : meme jeu d'UTXO, meme hauteur.
    m.revalidate(&u, RESEAU, 10);
    let apres = m.len();

    println!("--- t07 : revalidate ---");
    println!("  avant revalidate (jeu d'UTXO inchange) : {avant} transactions");
    println!("  apres revalidate                        : {apres} transactions");
    println!("  appele a CHAQUE bloc connecte : src/net.rs:976");

    assert_eq!(avant, 3);
    assert_eq!(
        apres, 0,
        "revalidate devrait etre l'identite ici ; elle vide le reservoir"
    );
}

/// Meme sur une chaine de transactions : tout part.
#[test]
fn t07b_revalidate_vide_aussi_les_chaines() {
    let mut m = Mempool::new();
    let _ = chaine_mempool(50, &mut m, 400_000);
    let avant = m.len();
    // La vue de revalidate n'a besoin d'aucun UTXO confirme pour les maillons
    // 2..n : ils dependent du mempool. Le maillon 1 depend du jeu confirme.
    let (u, _) = utxo_synthetique(1, 100_000_000, 400_000);
    m.revalidate(&u, RESEAU, 10);
    println!("--- t07b : chaine de 50 maillons ---");
    println!("  avant : {avant}   apres : {}", m.len());
    assert_eq!(avant, 50);
    assert_eq!(m.len(), 0);
}

/// Cout de revalidate si le defaut de t07 etait corrige : une reverification
/// complete de toutes les signatures du reservoir, a chaque bloc.
#[test]
fn t08_cout_latent_de_revalidate_a_chaque_bloc() {
    use q21_core::validate;
    use std::collections::HashSet;

    const N: u32 = 300;
    let (u, ops) = utxo_synthetique(N, 1_000_000, 500_000);
    let txs: Vec<Transaction> = ops
        .iter()
        .map(|op| tx_signee(&[*op], vec![sortie(900_000, puits(7))], 0))
        .collect();
    let octets: usize = txs.iter().map(|t| t.encode().len()).sum();

    let t0 = Instant::now();
    for t in &txs {
        let mut vues = HashSet::new();
        let _ = validate::check_transaction(t, &u, RESEAU, 11, &mut vues);
    }
    let d = t0.elapsed();
    let par_tx = d.as_secs_f64() / N as f64;
    let n_plein = MEMPOOL_MAX_BYTES as f64 / (octets as f64 / N as f64);

    println!("--- t08 : cout d'une revalidation complete ---");
    println!("  {N} transactions Lamport ({octets} octets) revalidees en {d:?}");
    println!("  {:.0} us par transaction", par_tx * 1e6);
    println!(
        "  extrapolation a un reservoir plein ({n_plein:.0} tx) : {:.2} s par bloc",
        n_plein * par_tx
    );
    println!(
        "  avec ML-DSA-65 (~192 us/entree au lieu de ~{:.0} us) : voir t02",
        par_tx * 1e6
    );
}

// ---------------------------------------------------------------------------
// 6. Double acceptation / reintegration
// ---------------------------------------------------------------------------

#[test]
fn t09_une_transaction_confirmee_ne_peut_pas_revenir_et_le_rejet_est_bon_marche() {
    let (mut u, ops) = utxo_synthetique(1, 1_000_000, 600_000);
    let tx = tx_signee(&ops, vec![sortie(900_000, puits(8))], 0);

    let mut m = Mempool::new();
    m.accept(&tx, &u, RESEAU, 10).expect("acceptation");
    // Simule la confirmation : la sortie consommee disparait du jeu.
    u.remove(&ops[0].0);
    m.remove(&tx.txid());

    let t0 = Instant::now();
    let r = m.accept(&tx, &u, RESEAU, 11);
    let d = t0.elapsed();

    // Comparaison : le meme rejet mais apres verification de signature.
    println!("--- t09 : rejeu d'une transaction confirmee ---");
    println!("  verdict : {r:?} en {d:?}");
    assert!(matches!(r, Err(MempoolError::DependanceNonConfirmee(_))));

    // Et une transaction deja presente ?
    let (u2, ops2) = utxo_synthetique(1, 1_000_000, 610_000);
    let tx2 = tx_signee(&ops2, vec![sortie(900_000, puits(8))], 0);
    let mut m2 = Mempool::new();
    m2.accept(&tx2, &u2, RESEAU, 10).unwrap();
    let t1 = Instant::now();
    let r2 = m2.accept(&tx2, &u2, RESEAU, 10);
    println!("  doublon : {r2:?} en {:?}", t1.elapsed());
    assert_eq!(r2, Err(MempoolError::DejaPresent));
}

// ---------------------------------------------------------------------------
// 8. Plafond memoire reel
// ---------------------------------------------------------------------------

/// Le plafond compte `tx.encode().len()`. Combien d'octets reels par octet compte ?
#[test]
fn t10_le_plafond_de_64_mio_ne_borne_pas_la_memoire_reelle() {
    // Transaction a 1 entree et beaucoup de sorties : chaque sortie pese 41
    // octets sur le fil mais cree une entree dans `creees`.
    const SORTIES: usize = 20_000;
    const TX: u32 = 40;

    let mut m = Mempool::new();
    let mut u = UtxoSet::new();
    let rss0 = rss_kio();
    for i in 0..TX {
        let (uu, ops) = utxo_synthetique(1, 1_000_000_000, 700_000 + i * 3);
        for (o, _) in &ops {
            u.insert(*o, *uu.get(o).unwrap());
        }
        let mut outs = Vec::with_capacity(SORTIES);
        for j in 0..SORTIES {
            outs.push(sortie(0, puits((j % 256) as u8)));
        }
        // Une sortie non nulle pour laisser des frais.
        outs[0] = sortie(1, puits(9));
        let tx = tx_signee(&ops, outs, 0);
        m.accept(&tx, &u, RESEAU, 10).expect("acceptation");
    }
    let rss1 = rss_kio();

    let compte = m.bytes();
    let reel = (rss1 - rss0) * 1024;
    println!("--- t10 : comptabilite memoire ---");
    println!("  transactions : {TX}, {SORTIES} sorties chacune");
    println!(
        "  octets comptes par le mempool : {compte} ({:.1} Mio)",
        compte as f64 / 1048576.0
    );
    println!(
        "  croissance RSS mesuree        : {reel} ({:.1} Mio)",
        reel as f64 / 1048576.0
    );
    println!(
        "  rapport reel/compte : x{:.2}",
        reel as f64 / compte as f64
    );
    println!(
        "  extrapolation au plafond de 64 Mio : {:.0} Mio de memoire reelle",
        64.0 * reel as f64 / compte as f64
    );
}

fn hex(h: &Hash256) -> String {
    h.as_bytes()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
