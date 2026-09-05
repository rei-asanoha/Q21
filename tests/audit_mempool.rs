//! Audit adverse — axe « reservoir de transactions et epuisement de ressources ».
//!
//! Ces epreuves ont d'abord servi a **mesurer** neuf failles d'engorgement —
//! la lecon que le protocole d'origine n'avait pas anticipee : un reservoir
//! qu'on remplit a cout nul de transactions qui ne seront jamais minees. Les
//! corrections sont en place (voir `src/mempool.rs`) ; ces tests **verrouillent
//! desormais le comportement corrige** : chacun echouerait si l'une des portes
//! se rouvrait. Les tests de cout (t02, t03, t08) restent des mesures.

use q21_core::amount::Amount;
use q21_core::consensus::{MIN_OUTPUT_VALUE, WITNESS_DISCOUNT};
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
fn utxo_synthetique(n: u32, valeur: u64, depart: u32) -> (UtxoSet, Vec<(OutPoint, u32, TxOut)>) {
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
        v.push((o, idx, u.get(&o).unwrap().output));
    }
    (u, v)
}

/// Construit et signe une transaction depensant `entrees` vers `sorties`.
///
/// Chaque entree porte la sortie qu'elle depense : le condensat signe
/// l'engage, comme le reseau.
fn tx_signee(
    entrees: &[(OutPoint, u32, TxOut)],
    sorties: Vec<TxOut>,
    lock_time: u64,
) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: entrees
            .iter()
            .map(|(o, _, _)| TxIn {
                prev_out: *o,
                witness: Witness::default(),
                sequence: 0xffff_ffff,
            })
            .collect(),
        outputs: sorties,
        lock_time,
    };
    // Le sighash ne couvre pas les temoins : on peut signer apres coup.
    for (i, (_, idx, depensee)) in entrees.iter().enumerate() {
        let (sk, pk, _) = clef(*idx);
        let m = tx.sighash(i as u32, RESEAU, depensee);
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

// ---------------------------------------------------------------------------
// 1. Cout de verification asymetrique : l'ordre des rejets
// ---------------------------------------------------------------------------

/// Le filtre de frais s'applique **avant** toute cryptographie.
///
/// Le defaut d'origine faisait l'inverse : 15,9 ms de calcul pour un rejet a
/// frais nuls contre 91 us pour un rejet de forme — un rapport de 175. Un
/// adversaire faisait bruler du processeur au prix d'un simple envoi. La preuve
/// du correctif ne depend d'aucune horloge : une transaction a la fois **sans
/// frais** et **a la clef non conforme** est rejetee pour ses FRAIS. Le filtre
/// a donc agi avant meme qu'on regarde la clef.
#[test]
fn t01_le_filtre_de_frais_precede_la_verification_des_signatures() {
    const K: u32 = 40;
    let (u, ops) = utxo_synthetique(K, 1_000, 0);

    // Frais nuls : la somme des sorties egale la somme des entrees.
    let tx = tx_signee(&ops, vec![sortie(K as u64 * 1_000, puits(0xaa))], 0);

    let mut m = Mempool::new();
    let t0 = Instant::now();
    let r = m.accept(&tx, &u, RESEAU, 10);
    let cher = t0.elapsed();

    // Meme transaction, mais une clef publique qui ne correspond a aucun verrou.
    let mut tx2 = tx.clone();
    for e in &mut tx2.inputs {
        e.witness.pubkey[0] ^= 0xff;
    }
    let mut m2 = Mempool::new();
    let t1 = Instant::now();
    let r2 = m2.accept(&tx2, &u, RESEAU, 10);
    let bon_marche = t1.elapsed();

    println!("--- t01 : ordre des rejets ---");
    println!("  rejet a frais nuls      : {r:?} en {cher:?}");
    println!("  rejet clef non conforme : {r2:?} en {bon_marche:?}");
    println!(
        "  rapport de cout : x{:.2} (il valait 175 avant le correctif)",
        cher.as_secs_f64() / bon_marche.as_secs_f64().max(1e-9)
    );

    assert!(
        matches!(r, Err(MempoolError::TauxDeFraisTropBas { .. })),
        "attendu : rejet pour frais insuffisants, obtenu {r:?}"
    );
    // Preuve structurelle, sans horloge : la clef falsifiee ne change rien au
    // verdict. Si les signatures etaient verifiees d'abord, `r2` serait une
    // erreur de validation, pas de frais.
    assert!(
        matches!(r2, Err(MempoolError::TauxDeFraisTropBas { .. })),
        "une clef non conforme ne doit rien changer : le filtre de frais passe \
         avant la cryptographie. Obtenu {r2:?}"
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
            Amount::from_units(50_000),
            Amount::from_units(100),
        )
        .expect("construction");

    let pk = tx.inputs[0].witness.pubkey.clone();
    let sg = tx.inputs[0].witness.signature.clone();
    let depensee = u.get(&tx.inputs[0].prev_out).unwrap().output;
    let msg = tx.sighash(0, RESEAU, &depensee);
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

/// Une transaction plus lourde que le budget du mineur est **refusee a
/// l'entree** : elle ne serait jamais selectionnee, l'accepter reviendrait a
/// offrir du reservoir gratuit a qui n'a aucune intention de payer.
#[test]
fn t04_une_transaction_plus_lourde_qu_un_bloc_est_refusee() {
    // Le mineur du binaire q21 appelle select_for_block(2_000_000).
    const POIDS_MINEUR: u64 = 2_000_000;
    const K: u32 = 120; // 120 entrees Lamport ~ 3 Mo, poids > 2 000 000

    let (u, ops) = utxo_synthetique(K, 1_000_000, 10_000);
    // Frais tres eleves : taux de frais maximal. Cela ne la sauve pas.
    let tx = tx_signee(&ops, vec![sortie(1, puits(2))], 0);
    let poids = tx.weight(WITNESS_DISCOUNT);

    let mut m = Mempool::new();
    let r = m.accept(&tx, &u, RESEAU, 10);

    println!("--- t04 : transaction inminable refusee ---");
    println!("  poids pondere {poids} (budget mineur {POIDS_MINEUR}) -> {r:?}");

    assert!(poids > POIDS_MINEUR);
    assert!(
        matches!(r, Err(MempoolError::Inminable { .. })),
        "une transaction plus lourde que le budget doit etre refusee, obtenu {r:?}"
    );
    assert_eq!(m.len(), 0, "elle n'occupe jamais le reservoir");
}

/// Une transaction plus grosse que MAX_BLOCK_SIZE : refusee, car jamais minable.
#[test]
fn t04b_une_transaction_plus_grosse_qu_un_bloc_entier_est_refusee() {
    const K: u32 = 200; // 200 * ~24,6 Kio ~ 4,9 Mio > MAX_BLOCK_SIZE (4 Mio)
    let (u, ops) = utxo_synthetique(K, 1_000_000, 20_000);
    let tx = tx_signee(&ops, vec![sortie(1, puits(3))], 0);
    let taille = tx.encode().len();

    let mut m = Mempool::new();
    let r = m.accept(&tx, &u, RESEAU, 10);

    println!("--- t04b : transaction plus grosse qu'un bloc ---");
    println!(
        "  taille {taille} octets vs MAX_BLOCK_SIZE {} -> {r:?}",
        q21_core::consensus::MAX_BLOCK_SIZE
    );
    assert!(taille > q21_core::consensus::MAX_BLOCK_SIZE);
    assert!(
        matches!(r, Err(MempoolError::Inminable { .. })),
        "une transaction plus grosse qu'un bloc doit etre refusee a l'entree, obtenu {r:?}"
    );
}

// ---------------------------------------------------------------------------
// 3/5. Eviction manipulable
// ---------------------------------------------------------------------------

/// L'inminable ne peut plus evincer les honnetes : il est refuse a l'entree.
///
/// L'attaque d'origine remplissait le reservoir a **99,8 %** de transactions
/// inminables a taux de frais eleve — donc inevincables — pour un cout reel de
/// **zero**, rien n'etant jamais mine. Il ne restait aux transactions honnetes
/// que 107 Kio sur 64 Mio. La borne de poids coupe l'attaque a la racine :
/// aucune de ces transactions n'entre plus au reservoir.
#[test]
fn t05_l_inminable_ne_peut_plus_evincer_les_honnetes() {
    const PAR_TX: u32 = 90; // ~2,23 M de poids > budget du mineur (2 000 000)
    let (u, ops) = utxo_synthetique(PAR_TX, 1_000_000, 100_000);
    // Une entree, une sortie de 1 unite : taux de frais quasi maximal — et
    // pourtant refusee, car trop lourde pour un bloc.
    let grosse = tx_signee(&ops, vec![sortie(1, puits(4))], 0);
    let poids = grosse.weight(WITNESS_DISCOUNT);

    let mut m = Mempool::new();
    let r_attaque = m.accept(&grosse, &u, RESEAU, 10);

    // La plus « fine » inminable : peu d'octets, mais un poids gonfle par ses
    // milliers de sorties. Refusee de meme.
    let (uf, opf) = utxo_synthetique(1, 1_000_000, 200_000);
    let mut outs: Vec<TxOut> = (0..12_100).map(|_| sortie(0, puits(4))).collect();
    outs[0] = sortie(1, puits(4));
    let fine = tx_signee(&opf, outs, 0);
    let r_fine = m.accept(&fine, &uf, RESEAU, 10);

    // Une transaction honnete ordinaire, elle, entre sans entrave.
    let (uh, oph) = utxo_synthetique(1, 1_000_000, 900_000);
    let honnete = tx_signee(&oph, vec![sortie(900_000, puits(5))], 0);
    let r_honnete = m.accept(&honnete, &uh, RESEAU, 10);

    println!("--- t05 : l'inminable est refuse a l'entree ---");
    println!("  grosse (poids {poids}, taux quasi max) -> {r_attaque:?}");
    println!(
        "  fine ({} octets, poids {}) -> {r_fine:?}",
        fine.encode().len(),
        fine.weight(WITNESS_DISCOUNT)
    );
    println!("  honnete -> {r_honnete:?}");

    assert!(poids > 2_000_000);
    assert!(
        matches!(r_attaque, Err(MempoolError::Inminable { .. })),
        "l'attaque inevincable doit etre refusee, obtenu {r_attaque:?}"
    );
    assert!(
        matches!(r_fine, Err(MempoolError::Inminable { .. })),
        "meme la plus fine inminable est refusee, obtenu {r_fine:?}"
    );
    assert!(
        r_honnete.is_ok(),
        "une transaction honnete normale doit entrer, obtenu {r_honnete:?}"
    );
    assert_eq!(m.len(), 1, "seule l'honnete occupe le reservoir");
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
        courant = (OutPoint { txid: id, index: 0 }, idx, tx.outputs[0]);
    }
    racine
}

/// Le retrait en paquet d'une chaine est lineaire, pas quadratique.
///
/// Le defaut : le parcours de la descendance testait l'appartenance par
/// `Vec::contains`, un balayage a chaque enfant — l'audit avait mesure n^1,35,
/// et le plafond de 64 Mio autorise des chaines de plusieurs milliers de
/// maillons. L'appartenance passe desormais par un ensemble : le retrait est
/// lineaire.
///
/// On ne le prouve pas par une horloge absolue — une machine d'integration lente
/// rendrait tout plafond fixe soit laxiste soit instable — mais par un RAPPORT,
/// insensible a la vitesse de la machine. Retirer une chaine huit fois plus
/// longue doit couter de l'ordre de huit fois plus (lineaire), pas soixante-
/// quatre fois plus (quadratique). Le retour au balayage `Vec::contains`
/// depasserait franchement le plafond du rapport ; le comportement lineaire
/// tient tres au large, sur n'importe quel runner.
#[test]
fn t06_le_retrait_en_paquet_est_lineaire() {
    println!("--- t06 : cout de remove() sur une chaine ---");

    // On mesure plusieurs fois et on retient, pour la petite chaine, le temps le
    // plus GRAND, et pour la grande, le plus PETIT. C'est la direction prudente :
    // elle rejette les pics d'ordonnancement qui gonfleraient artificiellement le
    // rapport, donc elle protege contre un echec a tort, pas contre un vrai
    // defaut.
    let mesure = |n: u32, prendre_min: bool| -> std::time::Duration {
        let mut best: Option<std::time::Duration> = None;
        for _ in 0..3 {
            let mut m = Mempool::new();
            let racine = chaine_mempool(n, &mut m, 1_000_000 + n * 10);
            assert_eq!(m.len(), n as usize);
            let t0 = Instant::now();
            m.remove(&racine);
            let d = t0.elapsed();
            assert!(m.is_empty());
            best = Some(match best {
                None => d,
                Some(b) if prendre_min => b.min(d),
                Some(b) => b.max(d),
            });
        }
        let d = best.unwrap();
        println!("  chaine de {n:5} : remove() = {d:?}");
        d
    };

    const PETIT: u32 = 600;
    const GRAND: u32 = 2_400; // quatre fois plus long
    let t_petit = mesure(PETIT, false); // le plus lent des trois
    let t_grand = mesure(GRAND, true); // le plus rapide des trois

    // Rapport attendu : ~4 (lineaire). Un plafond de 12 laisse une marge franche
    // pour le bruit et le cout fixe des petites tailles, tout en restant tres en
    // dessous des ~16 qu'imposerait un retrait quadratique.
    let facteur = t_grand.as_secs_f64() / t_petit.as_secs_f64().max(1e-9);
    assert!(
        facteur < 12.0,
        "remove() croit plus vite que la longueur de la chaine : \
         {PETIT} -> {t_petit:?}, {GRAND} -> {t_grand:?} \
         (rapport {facteur:.1}x ; lineaire ~4x, quadratique ~16x)"
    );

    println!(
        "  rapport {GRAND}/{PETIT} = {facteur:.1}x (lineaire ~4x) ; le plafond de \
         64 Mio limite la chaine a ~{} maillons",
        MEMPOOL_MAX_BYTES / 5_400
    );
}

/// `select_for_block` ne recalcule pas le `txid` a chaque comparaison du tri.
///
/// Le defaut : le comparateur appelait `txid()` — un SHA-256 sur tout le corps —
/// a chaque comparaison, donc O(n log n) fois. L'audit avait mesure **3,96
/// secondes pour retenir une seule transaction**, sous le verrou global du
/// noeud : tout s'arretait pendant ce temps, a chaque modele de bloc. Le txid et
/// le taux sont desormais calcules **une seule fois** : le tri redevient bon
/// marche, meme sur des transactions au corps volumineux.
#[test]
fn t11_select_for_block_ne_rehashe_pas_a_chaque_comparaison() {
    const N: u32 = 400;
    // Corps lourd a hasher, mais minable : chaque sortie pese desormais
    // POIDS_PAR_SORTIE en plus de ses octets, et vaut au moins la poussiere.
    const SORTIES: usize = 3_000;

    let mut m = Mempool::new();
    let mut u = UtxoSet::new();
    for i in 0..N {
        let (uu, ops) = utxo_synthetique(1, 100_000_000, 2_000_000 + i);
        for (o, _, _) in &ops {
            u.insert(*o, *uu.get(o).unwrap());
        }
        let outs: Vec<TxOut> = (0..SORTIES)
            .map(|_| sortie(MIN_OUTPUT_VALUE, puits(11)))
            .collect();
        let tx = tx_signee(&ops, outs, i as u64);
        if m.accept(&tx, &u, RESEAU, 10).is_err() {
            break;
        }
    }
    let n = m.len();
    assert!(n > 10, "il faut un reservoir consequent pour mesurer : {n}");

    let t0 = Instant::now();
    let choisies = m.select_for_block(2_000_000);
    let d = t0.elapsed();

    println!("--- t11 : cout du tri de select_for_block ---");
    println!("  reservoir : {n} transactions de {SORTIES} sorties");
    println!(
        "  select_for_block = {d:?} pour {} retenue(s)",
        choisies.len()
    );

    // Le defaut coutait des SECONDES. Une borne large — un dixieme de seconde —
    // passe tres au-dessus du cout reel (dizaines de us) tout en rattrapant tout
    // retour au rehash par comparaison, qui se compterait de nouveau en secondes.
    assert!(
        d < std::time::Duration::from_millis(100),
        "le tri ne doit pas rehasher a chaque comparaison : {d:?}"
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
            parent.outputs[0],
        )],
        vec![sortie(MIN_OUTPUT_VALUE, puits(12))],
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

/// `revalidate` sur un jeu d'UTXO inchange est l'identite.
///
/// Le defaut d'origine validait chaque transaction contre une vue ou
/// `consommees` contenait **ses propres entrees** : chacune se voyait comme sa
/// propre double depense et se retirait. Appelee a chaque bloc connecte, la
/// fonction **vidait integralement le reservoir** — mesure de l'audit : « avant
/// 50, apres 0 ». Elle ne verifie desormais que la disponibilite des entrees et
/// la maturite des coinbases : rien ne change quand rien n'a change.
#[test]
fn t07_revalidate_preserve_un_reservoir_valide() {
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

    println!("--- t07 : revalidate preserve ---");
    println!("  avant {avant}, apres {apres} (jeu d'UTXO inchange)");

    assert_eq!(avant, 3);
    assert_eq!(
        apres, 3,
        "revalidate sur un jeu inchange doit etre l'identite, pas un vidage"
    );
}

/// Meme sur une chaine de transactions dependantes : tout survit.
#[test]
fn t07b_revalidate_preserve_les_chaines() {
    let mut m = Mempool::new();
    let _ = chaine_mempool(50, &mut m, 400_000);
    let avant = m.len();
    // Les maillons 2..n dependent du mempool ; le maillon 1 du jeu confirme.
    let (u, _) = utxo_synthetique(1, 100_000_000, 400_000);
    m.revalidate(&u, RESEAU, 10);
    println!("--- t07b : chaine de 50 maillons ---");
    println!("  avant {avant}, apres {}", m.len());
    assert_eq!(avant, 50);
    assert_eq!(
        m.len(),
        50,
        "une chaine de dependances valides doit survivre a revalidate"
    );
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

/// La memoire reelle est bornee par le poids, pas seulement par les octets.
///
/// Le defaut : le plafond ne comptait que `tx.encode().len()`, alors que chaque
/// sortie cree une entree dans `creees` — de la memoire reelle qu'aucun octet
/// serialise ne refletait. La borne de poids ferme cette porte indirectement :
/// une transaction a assez de sorties pour gonfler la memoire pese, par ce meme
/// nombre de sorties, plus que le budget du mineur. Elle est donc refusee.
#[test]
fn t10_le_nombre_de_sorties_est_borne_par_le_poids() {
    const SORTIES: usize = 20_000;
    let (u, ops) = utxo_synthetique(1, 1_000_000_000, 700_000);
    let mut outs: Vec<TxOut> = (0..SORTIES)
        .map(|j| sortie(0, puits((j % 256) as u8)))
        .collect();
    outs[0] = sortie(1, puits(9));
    let tx = tx_signee(&ops, outs, 0);
    let poids = tx.weight(WITNESS_DISCOUNT);

    let mut m = Mempool::new();
    let r = m.accept(&tx, &u, RESEAU, 10);

    println!("--- t10 : sorties bornees par le poids ---");
    println!("  {SORTIES} sorties -> poids pondere {poids} (budget mineur 2 000 000)");
    println!("  {} octets serialises -> {r:?}", tx.encode().len());

    assert!(
        poids > 2_000_000,
        "20 000 sorties doivent peser plus que le budget : {poids}"
    );
    assert!(
        matches!(r, Err(MempoolError::Inminable { .. })),
        "une transaction qui gonfle la memoire par ses sorties est refusee, obtenu {r:?}"
    );
    assert_eq!(m.len(), 0);
}
