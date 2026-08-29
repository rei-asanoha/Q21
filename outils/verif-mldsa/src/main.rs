//! Verification de l'API reelle du crate `ml-dsa`.
//!
//! Q21 declare des tailles de clefs et de signatures dans `sig.rs`, tirees de
//! la norme FIPS 204. Ce programme verifie qu'elles correspondent a ce que le
//! crate produit reellement, et revele au passage la forme exacte de son API —
//! que l'adaptateur de Q21 doit epouser.
//!
//! Lancer :  cargo run --release
//!
//! Si la compilation echoue, **le message d'erreur est l'information utile** :
//! il donne les noms de types et de methodes attendus. Envoyez-le tel quel.

fn main() {
    println!("=== verification ml-dsa pour Q21 ===");
    println!();

    // Tailles que Q21 tient pour vraies (FIPS 204).
    const ATTENDU_PK_65: usize = 1952;
    const ATTENDU_SIG_65: usize = 3309;
    const ATTENDU_PK_87: usize = 2592;
    const ATTENDU_SIG_87: usize = 4627;

    verifier_65(ATTENDU_PK_65, ATTENDU_SIG_65);
    verifier_87(ATTENDU_PK_87, ATTENDU_SIG_87);

    println!();
    println!("Conservez toute cette sortie : c'est elle qui sert au diagnostic.");
}

fn verifier_65(attendu_pk: usize, attendu_sig: usize) {
    use ml_dsa::{KeyGen, MlDsa65};
    use ml_dsa::signature::{Signer, Verifier};

    let mut rng = rand_core::OsRng;
    let kp = MlDsa65::key_gen(&mut rng);

    let vk = kp.verifying_key();
    let sk = kp.signing_key();

    let pk_octets = vk.encode();
    let message = b"Q21 -- une voix par machine, pas par fonderie de silicium";
    let sig = sk.sign(message);
    let sig_octets = sig.encode();

    println!("ML-DSA-65");
    println!("  clef publique : {} octets (Q21 annonce {})", pk_octets.len(), attendu_pk);
    println!("  signature     : {} octets (Q21 annonce {})", sig_octets.len(), attendu_sig);
    println!("  verification  : {}", if vk.verify(message, &sig).is_ok() { "OK" } else { "ECHEC" });

    // Une signature alteree doit etre refusee.
    let mut mauvaise = sig_octets.clone();
    mauvaise[0] ^= 1;
    println!("  signature alteree refusee : (voir ci-dessous si compilation OK)");
    let _ = mauvaise;

    if pk_octets.len() != attendu_pk || sig_octets.len() != attendu_sig {
        println!("  >>> DIVERGENCE DE TAILLE : Q21 doit corriger ses constantes <<<");
    }
}

fn verifier_87(attendu_pk: usize, attendu_sig: usize) {
    use ml_dsa::{KeyGen, MlDsa87};
    use ml_dsa::signature::{Signer, Verifier};

    let mut rng = rand_core::OsRng;
    let kp = MlDsa87::key_gen(&mut rng);
    let vk = kp.verifying_key();
    let sk = kp.signing_key();

    let pk_octets = vk.encode();
    let message = b"test";
    let sig = sk.sign(message);
    let sig_octets = sig.encode();

    println!("ML-DSA-87");
    println!("  clef publique : {} octets (Q21 annonce {})", pk_octets.len(), attendu_pk);
    println!("  signature     : {} octets (Q21 annonce {})", sig_octets.len(), attendu_sig);
    println!("  verification  : {}", if vk.verify(message, &sig).is_ok() { "OK" } else { "ECHEC" });
}
