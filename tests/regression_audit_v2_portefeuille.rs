//! Regressions de l'audit adverse v2 — portefeuille et cryptographie.
//!
//! Chaque epreuve rejoue la preuve de l'audit contre le binaire ou la
//! bibliotheque, et exige le comportement corrige : le code de sauvegarde ne
//! passe plus par la ligne de commande (V1), le temporaire du portefeuille
//! nait restreint et le dossier est prive (V2), un portefeuille substitue est
//! refuse (V3), deux signatures ML-DSA du meme message different (V6), un
//! scelle sous le cout par defaut est rescelle (V9), et une reservation
//! Lamport abandonnee redevient libre (V8).

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
use q21_core::sig::SchemeId;
use q21_core::wallet::Wallet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn q21() -> &'static str {
    env!("CARGO_BIN_EXE_q21")
}

fn dossier(nom: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("q21-regression-v2-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Un fichier a soi seul, comme la documentation le demande.
fn fichier_prive(chemin: &Path, contenu: &str) {
    std::fs::write(chemin, contenu).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0)
}

fn lancer(datadir: &Path, phrase: &Path, args: &[&str]) -> std::process::Output {
    Command::new(q21())
        .arg("--datadir")
        .arg(datadir)
        .arg("--phrase-fichier")
        .arg(phrase)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("lancement de q21")
}

fn premiere_adresse(sortie: &[u8]) -> String {
    String::from_utf8_lossy(sortie)
        .lines()
        .find(|l| l.starts_with("rq21") || l.starts_with("tq21"))
        .unwrap_or("")
        .to_string()
}

/// V1 — le code de sauvegarde ne passe plus par `argv`.
///
/// Un code donne en argument est refuse avec la raison (historique du
/// terminal, `/proc`), et le chemin documente — `--code-fichier` — restaure
/// exactement le portefeuille de la graine sans que le code apparaisse
/// jamais dans la ligne de commande du processus.
#[test]
fn v1_le_code_de_sauvegarde_ne_passe_plus_par_la_ligne_de_commande() {
    let d = dossier("restore-argv");
    std::fs::create_dir_all(&d).unwrap();
    let phrase = d.join("phrase.txt");
    fichier_prive(&phrase, "phrase d'epreuve\n");
    let code = Wallet::from_seed([0x5a; 32], Network::Regtest).backup_code();

    // Le code en argument : refuse, et la raison est dite.
    let cible = d.join("par-argument");
    let s = lancer(&cible, &phrase, &["restore", &code, "regtest", "lamport"]);
    let err = String::from_utf8_lossy(&s.stderr);
    assert!(
        !s.status.success(),
        "CONSTAT : `q21 restore <code>` a accepte le code par argv :\n{}",
        String::from_utf8_lossy(&s.stdout)
    );
    assert!(
        err.contains("historique") && err.contains("--code-fichier"),
        "le refus doit expliquer pourquoi et comment faire :\n{err}"
    );
    assert!(
        !cible.join("wallet.dat").exists(),
        "rien ne doit avoir ete ecrit apres un refus"
    );

    // Le chemin documente : un fichier a soi seul.
    let fichier_code = d.join("code.txt");
    fichier_prive(&fichier_code, &format!("{code}\n"));
    let cible = d.join("par-fichier");
    // Le `mut` sert au bloc Linux plus bas, qui appelle `enfant.try_wait()`
    // en boucle pour lire `/proc/<pid>/cmdline` tant que le processus vit.
    // Hors Linux ce bloc n'existe pas, `enfant` n'est plus que consomme par
    // `wait_with_output`, et le `mut` devient inutile — la ou l'avertissement
    // est attendu, on le tait ; sur Linux il reste vif.
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut enfant = Command::new(q21())
        .arg("--datadir")
        .arg(&cible)
        .arg("--phrase-fichier")
        .arg(&phrase)
        .arg("--code-fichier")
        .arg(&fichier_code)
        .args(["restore", "regtest", "lamport"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("lancement");
    #[cfg(target_os = "linux")]
    {
        let pid = enfant.id();
        loop {
            if let Ok(c) = std::fs::read(format!("/proc/{pid}/cmdline")) {
                let texte = String::from_utf8_lossy(&c).replace('\0', " ");
                assert!(
                    !texte.contains(&code[..12]),
                    "le code est visible dans /proc/{pid}/cmdline : {texte}"
                );
            }
            if let Ok(Some(_)) = enfant.try_wait() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    let s = enfant.wait_with_output().unwrap();
    assert!(
        s.status.success(),
        "`--code-fichier` doit restaurer :\n{}",
        String::from_utf8_lossy(&s.stderr)
    );
    // Le portefeuille restaure est bien celui de la graine : l'adresse
    // suivante est celle de l'indice 1 (l'indice 0 est le beneficiaire de la
    // genese).
    let mut attendu = Wallet::from_seed([0x5a; 32], Network::Regtest);
    attendu.rescan(1);
    let attendue = attendu.new_address().to_string();
    let s = lancer(&cible, &phrase, &["address"]);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    assert_eq!(premiere_adresse(&s.stdout), attendue);

    let _ = std::fs::remove_dir_all(&d);
}

/// V2 — `wallet.tmp` nait en 0600, `addresses.dat` est en 0600, le dossier en
/// 0700.
///
/// Un guetteur sonde le temporaire pendant plusieurs ecritures scellees et ne
/// doit jamais le voir sous un autre mode que 0600 : la fenetre entre la
/// creation et la restriction n'existe plus.
#[cfg(unix)]
#[test]
fn v2_le_temporaire_nait_restreint_et_le_dossier_est_prive() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let d = dossier("droits");
    let phrase =
        std::env::temp_dir().join(format!("q21-regression-v2-phrase-{}", std::process::id()));
    fichier_prive(&phrase, "phrase d'epreuve\n");
    let s = lancer(&d, &phrase, &["init", "regtest", "lamport"]);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));

    let (m_dossier, m_wallet, m_seq, m_adr) = (
        mode(&d),
        mode(&d.join("wallet.dat")),
        mode(&d.join("wallet.seq")),
        mode(&d.join("addresses.dat")),
    );
    println!("dossier {m_dossier:o}  wallet.dat {m_wallet:o}  wallet.seq {m_seq:o}  addresses.dat {m_adr:o}");
    assert_eq!(m_wallet, 0o600);
    assert_eq!(m_seq, 0o600);
    assert_eq!(
        m_adr, 0o600,
        "CONSTAT : addresses.dat est lisible par d'autres comptes"
    );
    assert_eq!(
        m_dossier, 0o700,
        "CONSTAT : le dossier est lisible par d'autres comptes"
    );

    let tmp = d.join("wallet.tmp");
    let fini = Arc::new(AtomicBool::new(false));
    let (f2, t2) = (fini.clone(), tmp.clone());
    let guetteur = std::thread::spawn(move || {
        let mut modes: Vec<u32> = Vec::new();
        while !f2.load(Ordering::Relaxed) {
            if let Ok(m) = std::fs::metadata(&t2) {
                use std::os::unix::fs::PermissionsExt;
                modes.push(m.permissions().mode() & 0o777);
            }
        }
        modes
    });
    for _ in 0..4 {
        let s = lancer(&d, &phrase, &["address"]);
        assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    }
    fini.store(true, Ordering::Relaxed);
    let modes = guetteur.join().unwrap();
    let mut m = modes.clone();
    m.sort_unstable();
    m.dedup();
    println!(
        "wallet.tmp observe {} fois, modes : {:?}",
        modes.len(),
        m.iter().map(|x| format!("{x:o}")).collect::<Vec<_>>()
    );
    assert!(!modes.is_empty(), "le guetteur n'a jamais vu wallet.tmp");
    assert!(
        modes.iter().all(|m| *m == 0o600),
        "CONSTAT : wallet.tmp a ete vu sous un mode autre que 0600 : {m:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_file(&phrase);
}

/// V3 — un portefeuille substitue est refuse.
///
/// Un `wallet.dat` en clair d'une autre graine, portant le numero de serie
/// courant, etait adopte sans phrase et sans un mot. Le dossier retient
/// desormais qu'il a vu un scelle et l'empreinte publique de sa graine : le
/// fichier en clair est refuse en nommant la cause, un scelle d'une autre
/// graine est refuse sans confirmation explicite, et accepte avec.
#[test]
fn v3_un_portefeuille_substitue_est_refuse_en_nommant_la_cause() {
    let d = dossier("substitution");
    let phrase = std::env::temp_dir().join(format!(
        "q21-regression-v2-phrase-subst-{}",
        std::process::id()
    ));
    fichier_prive(&phrase, "phrase d'epreuve\n");
    let s = lancer(&d, &phrase, &["init", "regtest", "lamport"]);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    let legitime = std::fs::read(d.join("wallet.dat")).unwrap();

    let serie: u64 = std::fs::read_to_string(d.join("wallet.seq"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let graine_hex: String = [0x77u8; 32].iter().map(|b| format!("{b:02x}")).collect();
    let contenu_etranger = format!(
        "seed={graine_hex}\nnext_index=1\nnetwork=regtest\nscheme=4\nserie={serie}\nverifie_jusqu_a=0\nconsommes=\n"
    );

    // 1. En clair, d'une autre graine.
    std::fs::write(d.join("wallet.dat"), &contenu_etranger).unwrap();
    let s = Command::new(q21())
        .arg("--datadir")
        .arg(&d)
        .arg("address")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&s.stderr);
    assert!(
        !s.status.success(),
        "CONSTAT : le portefeuille en clair substitue a ete adopte :\n{}",
        String::from_utf8_lossy(&s.stdout)
    );
    assert!(
        err.contains("phrase"),
        "le refus doit dire que ce dossier etait protege par une phrase :\n{err}"
    );

    // 2. Scelle avec la meme phrase, mais d'une autre graine.
    let scelle = q21_core::kdf::sceller(
        b"phrase d'epreuve",
        contenu_etranger.as_bytes(),
        q21_core::kdf::COUT_DEFAUT,
    )
    .unwrap();
    std::fs::write(d.join("wallet.dat"), &scelle).unwrap();
    let s = lancer(&d, &phrase, &["address"]);
    let err = String::from_utf8_lossy(&s.stderr);
    assert!(
        !s.status.success(),
        "CONSTAT : un scelle d'une autre graine a ete adopte sans confirmation"
    );
    assert!(
        err.contains("graine") && err.contains("--accepter-autre-graine"),
        "le refus doit nommer la graine et la marche a suivre :\n{err}"
    );

    // 3. La meme substitution, confirmee explicitement : acceptee.
    let s = lancer(&d, &phrase, &["--accepter-autre-graine", "address"]);
    assert!(
        s.status.success(),
        "la confirmation explicite doit ouvrir :\n{}",
        String::from_utf8_lossy(&s.stderr)
    );
    let mut etranger = Wallet::from_seed([0x77u8; 32], Network::Regtest);
    etranger.rescan(1);
    assert_eq!(
        premiere_adresse(&s.stdout),
        etranger.new_address().to_string()
    );

    // 4. Le portefeuille legitime, remis en place, est refuse a son tour :
    //    le dossier appartient maintenant a la nouvelle graine.
    std::fs::write(d.join("wallet.dat"), &legitime).unwrap();
    let s = lancer(&d, &phrase, &["address"]);
    assert!(!s.status.success());

    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_file(&phrase);
}

/// V9 — un scelle sous le cout par defaut est rescelle a l'ouverture.
///
/// Un `wallet.dat` scelle a 8 Kio / 1 passe s'ouvrait en quarante
/// microsecondes sans un mot. Le binaire doit avertir et le reecrire au cout
/// par defaut.
#[test]
fn v9_un_scelle_sous_le_cout_par_defaut_est_rescelle() {
    let d = dossier("cout");
    let phrase = std::env::temp_dir().join(format!(
        "q21-regression-v2-phrase-cout-{}",
        std::process::id()
    ));
    fichier_prive(&phrase, "phrase d'epreuve\n");
    let s = lancer(&d, &phrase, &["init", "regtest", "lamport"]);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));

    // Le meme contenu, rescelle a un cout derisoire.
    let scelle = std::fs::read(d.join("wallet.dat")).unwrap();
    let clair = q21_core::kdf::desceller(b"phrase d'epreuve", &scelle).unwrap();
    let faible = q21_core::kdf::sceller(
        b"phrase d'epreuve",
        &clair,
        q21_core::kdf::Cout {
            memoire_kib: 8,
            passes: 1,
        },
    )
    .unwrap();
    std::fs::write(d.join("wallet.dat"), &faible).unwrap();

    let s = lancer(&d, &phrase, &["balance"]);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    let err = String::from_utf8_lossy(&s.stderr);
    let apres = std::fs::read(d.join("wallet.dat")).unwrap();
    let memoire = u32::from_le_bytes([apres[8], apres[9], apres[10], apres[11]]);
    let passes = u32::from_le_bytes([apres[12], apres[13], apres[14], apres[15]]);
    println!("cout apres ouverture : {memoire} Kio, {passes} passe(s)");
    assert_eq!(
        (memoire, passes),
        (
            q21_core::kdf::COUT_DEFAUT.memoire_kib,
            q21_core::kdf::COUT_DEFAUT.passes
        ),
        "CONSTAT : le scelle a 8 Kio / 1 passe n'a pas ete rescelle"
    );
    assert!(
        err.contains("cout") || err.contains("coût"),
        "l'ouverture doit avertir du cout insuffisant :\n{err}"
    );
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_file(&phrase);
}

/// V6 — ML-DSA signe en variante « hedged » : deux signatures du meme message
/// different, et toutes deux verifient.
#[cfg(feature = "mldsa")]
#[test]
fn v6_deux_signatures_ml_dsa_du_meme_message_different_et_verifient() {
    let graine = [0x31u8; 32];
    let mut w = Wallet::from_seed_scheme(graine, Network::Regtest, SchemeId::MlDsa65).unwrap();
    let a0 = w.new_address();
    let mut c = Chain::new(Network::Regtest, genesis_block(Network::Regtest));
    for i in 0..(COINBASE_MATURITY + 2) {
        let t = GENESIS_TIME + (i + 1) * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(a0.hash, SchemeId::MlDsa65, &[], t, 20_000_000)
            .unwrap();
        c.connect(&b, t + 1).unwrap();
    }
    let mut tiers = Wallet::from_seed([0x99; 32], Network::Regtest);
    let dest = tiers.new_address();
    let signer = || {
        let mut w = Wallet::from_seed_scheme(graine, Network::Regtest, SchemeId::MlDsa65).unwrap();
        w.rescan(1);
        w.create_transaction(
            &c.utxo,
            c.height(),
            &dest,
            Amount::from_units(50_000),
            Amount::from_units(1_000),
        )
        .unwrap()
    };
    let t1 = signer();
    let t2 = signer();
    assert_eq!(t1.txid(), t2.txid(), "meme transaction depouillee");
    let s1 = &t1.inputs[0].witness.signature;
    let s2 = &t2.inputs[0].witness.signature;
    assert_ne!(
        s1, s2,
        "CONSTAT : deux signatures ML-DSA du meme message sont identiques (variante deterministe)"
    );
    let depensee = c.utxo.get(&t1.inputs[0].prev_out).unwrap().output;
    for t in [&t1, &t2] {
        let m = t.sighash(0, Network::Regtest, &depensee);
        assert!(
            q21_core::sig::verify(
                SchemeId::MlDsa65,
                &t.inputs[0].witness.pubkey,
                &m,
                &t.inputs[0].witness.signature
            )
            .is_ok(),
            "chaque variante doit verifier"
        );
    }
}

/// V8 — un arret entre la reservation et la diffusion ne fige pas la piece.
///
/// L'indice est reserve et ecrit sur le disque avant la signature ; le
/// processus meurt avant de diffuser. Au redemarrage, la reservation est
/// relue : la piece reste indisponible le temps du delai, puis, la chaine ne
/// portant aucune signature de cette clef, l'indice redevient libre.
#[test]
fn v8_une_reservation_abandonnee_redevient_libre() {
    let graine = [0x21u8; 32];
    let mut w = Wallet::from_seed(graine, Network::Regtest);
    let a0 = w.new_address();
    let mut c = Chain::new(Network::Regtest, genesis_block(Network::Regtest));
    let miner = |c: &mut Chain, n: u64| {
        for _ in 0..n {
            let h = c.height();
            let t = GENESIS_TIME + (h + 1) * TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a0.hash, SchemeId::LamportOts, &[], t, 20_000_000)
                .unwrap();
            c.connect(&b, t + 1).unwrap();
        }
    };
    miner(&mut c, COINBASE_MATURITY + 2);
    let mut tiers = Wallet::from_seed([0x99; 32], Network::Regtest);
    let dest = tiers.new_address();

    // Reservation, ecriture anticipee... et arret avant la signature.
    let prepare = w
        .preparer_depense(
            &c.utxo,
            c.height(),
            &[(dest, Amount::from_units(50_000))],
            Amount::from_units(1_000),
        )
        .unwrap();
    assert!(w.est_reserve(0), "l'indice 0 doit etre reserve");
    assert!(!w.est_consomme(0), "rien n'a ete signe : rien n'est revele");
    let sur_le_disque_consommes = w.indices_consommes_pour_le_fichier();
    let sur_le_disque_reserves = w.indices_reserves();
    assert!(
        sur_le_disque_consommes.contains(&0),
        "conservateur pour un lecteur ancien"
    );
    drop(prepare);
    drop(w);

    // Redemarrage : relecture du fichier.
    let mut r = Wallet::from_seed(graine, Network::Regtest);
    r.rescan(2);
    r.marquer_consommes(&sur_le_disque_consommes);
    r.charger_reservations(&sur_le_disque_reserves);
    assert!(r.est_reserve(0) && !r.est_consomme(0));
    assert!(
        !r.spendable(&c.utxo, c.height())
            .iter()
            .any(|(_, _, i)| *i == 0),
        "reservee, la piece n'est pas proposee"
    );

    // Trop tot : la reservation tient.
    let (confirmees, liberees) = r.reexaminer_reservations(c.height(), |h| c.block_at(h));
    assert_eq!((confirmees, liberees), (0, 0));
    assert!(r.est_reserve(0));

    // Le delai passe, la chaine ne porte aucune signature : l'indice est libre.
    miner(&mut c, Wallet::DELAI_RESERVATION);
    let (confirmees, liberees) = r.reexaminer_reservations(c.height(), |h| c.block_at(h));
    assert_eq!((confirmees, liberees), (0, 1));
    assert!(!r.est_reserve(0) && !r.est_consomme(0));
    assert!(
        r.spendable(&c.utxo, c.height())
            .iter()
            .any(|(_, _, i)| *i == 0),
        "CONSTAT : la piece reste figee apres un arret entre reservation et diffusion"
    );
}
