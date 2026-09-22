//! Attaque adverse du coffre-fort Q21, avant lancement.
//!
//! But defensif : prouver qu'un attaquant ne peut ni tirer une graine
//! silencieusement fausse d'un code de sauvegarde abime, ni confondre une
//! adresse avec une sauvegarde, ni franchir un reseau, ni ouvrir un fichier
//! scelle sans la phrase, ni en corrompre le clair sans etre detecte, ni en
//! abaisser le cout de derivation.
//!
//! Chaque epreuve REUSSIT quand l'ATTAQUE ECHOUE : le test vert signifie que
//! la barriere a tenu. Un test rouge serait une breche a corriger.
//!
//! Compile/lance : `cargo test --locked --features audit --test attaque_coffre_fort`

use q21_core::address::Network;
use q21_core::kdf::{self, ScelleError, COUT_DEFAUT, COUT_EPREUVE};
use q21_core::wallet::{Wallet, WalletError};

/// Alphabet Bech32(m). Sert a fabriquer une faute de frappe qui reste dans le
/// jeu de caracteres — donc rejetee par la somme de controle, pas par un
/// caractere hors alphabet.
const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Une graine reproductible mais quelconque.
fn graine() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, o) in s.iter_mut().enumerate() {
        *o = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    s
}

// ---------------------------------------------------------------------------
// 1. Faute de frappe dans le code de sauvegarde.
//
//    Un seul caractere change dans la partie donnees doit toujours etre
//    rejete par la somme de controle Bech32m. Jamais une graine differente
//    rendue en silence.
// ---------------------------------------------------------------------------
#[test]
fn faute_de_frappe_dans_le_code_de_sauvegarde_est_rejetee() {
    let reseau = Network::Regtest;
    let seed = graine();
    let w = Wallet::from_seed(seed, reseau);
    let code = w.backup_code();

    // Position du separateur Bech32 : le dernier '1'. Les donnees suivent.
    let sep = code.rfind('1').expect("un code Bech32 a un separateur");
    let octets = code.as_bytes();

    let mut positions_testees = 0usize;
    for i in (sep + 1)..code.len() {
        let original = octets[i];
        // Un autre caractere du meme alphabet : une vraie faute de frappe.
        let remplacant = *CHARSET
            .iter()
            .find(|&&c| c != original)
            .expect("il existe un autre caractere");
        let mut abime: Vec<u8> = octets.to_vec();
        abime[i] = remplacant;
        let abime = String::from_utf8(abime).unwrap();

        match Wallet::seed_from_backup(&abime, reseau) {
            Err(_) => positions_testees += 1,
            Ok(autre) => panic!(
                "BRECHE : une faute de frappe en position {i} a rendu une graine \
                 silencieuse ({}). Attendu : erreur de somme de controle.\n\
                 origine={seed:02x?}\nrendue ={autre:02x?}",
                if autre == seed {
                    "identique"
                } else {
                    "DIFFERENTE"
                },
            ),
        }
    }
    assert!(positions_testees > 0, "aucune position de donnees testee");
}

// ---------------------------------------------------------------------------
// 2. Confusion adresse / graine.
//
//    Une adresse de reception collee a la place d'un code de sauvegarde doit
//    etre reconnue comme telle — erreur dediee — et jamais decodee en graine.
// ---------------------------------------------------------------------------
#[test]
fn une_adresse_nest_jamais_prise_pour_une_sauvegarde() {
    for reseau in [Network::Mainnet, Network::Testnet, Network::Regtest] {
        let mut w = Wallet::from_seed(graine(), reseau);
        let adresse = w.new_address().to_string_bech32();

        let r = Wallet::seed_from_backup(&adresse, reseau);
        assert_eq!(
            r,
            Err(WalletError::SauvegardeEstUneAdresse),
            "BRECHE : l'adresse {adresse} n'a pas ete reconnue comme adresse \
             (reseau {reseau:?}), resultat = {r:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Mauvais reseau.
//
//    Un code de sauvegarde de Testnet ne doit jamais ouvrir un portefeuille
//    Regtest ou Mainnet : erreur de reseau, pas de graine.
// ---------------------------------------------------------------------------
#[test]
fn un_code_dun_autre_reseau_est_refuse() {
    let w_testnet = Wallet::from_seed(graine(), Network::Testnet);
    let code = w_testnet.backup_code();

    for reseau in [Network::Regtest, Network::Mainnet] {
        let r = Wallet::seed_from_backup(&code, reseau);
        assert_eq!(
            r,
            Err(WalletError::SauvegardeAutreReseau),
            "BRECHE : un code Testnet a ete accepte (ou mal diagnostique) \
             sur {reseau:?}, resultat = {r:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Aller-retour honnete (non-regression).
//
//    Le code intact redonne exactement la graine d'origine.
// ---------------------------------------------------------------------------
#[test]
fn aller_retour_honnete_du_code_de_sauvegarde() {
    for reseau in [Network::Mainnet, Network::Testnet, Network::Regtest] {
        let seed = graine();
        let w = Wallet::from_seed(seed, reseau);
        let rendue = Wallet::seed_from_backup(&w.backup_code(), reseau)
            .expect("un code intact doit se relire");
        assert_eq!(
            rendue, seed,
            "l'aller-retour a change la graine ({reseau:?})"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Fichier scelle — mauvaise phrase.
//
//    Sceller avec la phrase A, tenter d'ouvrir avec la phrase B :
//    authentification refusee, le clair n'apparait jamais.
// ---------------------------------------------------------------------------
#[test]
fn desceller_avec_la_mauvaise_phrase_echoue() {
    let secret = b"graine=deadbeef, ne dois jamais fuir";
    let phrase_a = b"correcte horse batterie agrafe";
    let phrase_b = b"correcte horse batterie agraphe"; // une lettre de plus

    let scelle = kdf::sceller(phrase_a, secret, COUT_EPREUVE).expect("scellement");

    let r = kdf::desceller(phrase_b, &scelle);
    match r {
        Err(ScelleError::AuthentificationEchouee) => {}
        Ok(clair) => panic!(
            "BRECHE : une phrase fausse a ouvert le coffre. clair rendu = {:02x?}",
            clair
        ),
        autre => panic!("attendu AuthentificationEchouee, obtenu {autre:?}"),
    }
    // Et surtout : le secret n'a pas transpire, meme partiellement.
    if let Ok(clair) = &r {
        assert_ne!(clair.as_slice(), secret, "le clair a fuite");
    }
}

// ---------------------------------------------------------------------------
// 6. Fichier scelle — altération d'un octet.
//
//    Aucun octet retourne (corps, en-tete, sel, MAC) ne doit produire un clair.
//    On verifie deux points :
//      a) exhaustif — tout retournement d'un octet fait echouer desceller ;
//      b) cible — un octet du corps chiffre et un octet du sel donnent bien
//         AuthentificationEchouee (le MAC couvre l'en-tete et le corps).
// ---------------------------------------------------------------------------
#[test]
fn alterer_un_octet_du_scelle_est_toujours_detecte() {
    let secret = b"32 octets de graine tres secrete!";
    let phrase = b"phrase du proprietaire legitime";
    let scelle = kdf::sceller(phrase, secret, COUT_EPREUVE).expect("scellement");

    // a) Exhaustif : chaque octet, retourne, doit faire echouer l'ouverture,
    //    JAMAIS rendre un clair (corrompu ou non).
    for i in 0..scelle.len() {
        let mut abime = scelle.clone();
        abime[i] ^= 0x01;
        match kdf::desceller(phrase, &abime) {
            Err(_) => {}
            Ok(clair) => panic!(
                "BRECHE : octet {i} retourne, desceller a rendu un clair {:02x?} \
                 (secret d'origine {:02x?})",
                clair, secret
            ),
        }
    }

    // b) Cible corps chiffre : format
    //    MAGIE2(8) memoire(4) passes(4) sel(16) chiffre(n) mac(32).
    //    Le premier octet du chiffre est a l'offset 32.
    const DEBUT_CHIFFRE: usize = 8 + 4 + 4 + 16;
    let mut corrompu_corps = scelle.clone();
    corrompu_corps[DEBUT_CHIFFRE] ^= 0xFF;
    assert_eq!(
        kdf::desceller(phrase, &corrompu_corps),
        Err(ScelleError::AuthentificationEchouee),
        "BRECHE : un octet du corps chiffre n'a pas declenche le MAC",
    );

    // b') Cible sel (en-tete, dans les bornes) : couvert par le MAC lui aussi.
    let mut corrompu_sel = scelle.clone();
    corrompu_sel[16] ^= 0xFF; // premier octet du sel
    assert_eq!(
        kdf::desceller(phrase, &corrompu_sel),
        Err(ScelleError::AuthentificationEchouee),
        "BRECHE : un octet du sel n'a pas declenche le MAC",
    );
}

// ---------------------------------------------------------------------------
// 7. Abaissement de cout KDF.
//
//    L'en-tete expose memoire_kib et passes. Un attaquant les reecrit pour
//    forcer une derivation faible. Le MAC couvre l'en-tete : l'ouverture doit
//    etre refusee, jamais rendre le clair.
//
//    Deux variantes :
//      a) valeur BASSE mais dans les bornes (COUT_EPREUVE) -> le cout devient
//         legal, mais le MAC (calcule sur l'en-tete d'origine) tombe :
//         AuthentificationEchouee ;
//      b) valeur ABSURDE hors bornes -> rejet AVANT toute derivation :
//         CoutAberrant.
//    Dans les deux cas : aucun clair.
// ---------------------------------------------------------------------------
#[test]
fn abaisser_le_cout_kdf_est_rejete() {
    let secret = b"secret protege par 64 Mio d'Argon2id";
    let phrase = b"la bonne phrase, celle du proprietaire";

    // Scelle au cout par defaut (64 Mio, 3 passes).
    let scelle = kdf::sceller(phrase, secret, COUT_DEFAUT).expect("scellement");

    // L'en-tete annonce bien le cout par defaut.
    assert_eq!(kdf::cout_lu(&scelle), Some(COUT_DEFAUT));

    // a) Reecriture vers un cout bas mais legal (COUT_EPREUVE : 64 Kio, 1 passe).
    let mut abaisse = scelle.clone();
    abaisse[8..12].copy_from_slice(&COUT_EPREUVE.memoire_kib.to_le_bytes());
    abaisse[12..16].copy_from_slice(&COUT_EPREUVE.passes.to_le_bytes());
    // L'en-tete ment desormais, mais avec la BONNE phrase :
    let r = kdf::desceller(phrase, &abaisse);
    match r {
        Err(ScelleError::AuthentificationEchouee) => {}
        Ok(clair) => panic!(
            "BRECHE : cout abaisse a 64 Kio/1 passe accepte, clair rendu {:02x?}",
            clair
        ),
        autre => panic!(
            "cout abaisse legal : attendu AuthentificationEchouee (MAC couvre \
             l'en-tete), obtenu {autre:?}"
        ),
    }

    // b) Reecriture vers une valeur absurde hors bornes (memoire = 1 Kio).
    let mut absurde = scelle.clone();
    absurde[8..12].copy_from_slice(&1u32.to_le_bytes());
    match kdf::desceller(phrase, &absurde) {
        Err(ScelleError::CoutAberrant { .. }) => {}
        Ok(clair) => panic!("BRECHE : cout absurde accepte, clair rendu {:02x?}", clair),
        autre => panic!("cout hors bornes : attendu CoutAberrant, obtenu {autre:?}"),
    }
}

// ---------------------------------------------------------------------------
// 8. Aller-retour scelle honnete.
//
//    desceller(phrase, sceller(phrase, secret)) redonne exactement le secret.
// ---------------------------------------------------------------------------
#[test]
fn aller_retour_scelle_honnete() {
    let secret = b"le clair d'origine, intact";
    let phrase = b"phrase secrete du coffre";

    let scelle = kdf::sceller(phrase, secret, COUT_EPREUVE).expect("scellement");
    let rendu = kdf::desceller(phrase, &scelle).expect("ouverture legitime");
    assert_eq!(rendu.as_slice(), secret, "le scellement a altere le clair");
}
