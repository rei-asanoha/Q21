//! HMAC, derivation de clef et chiffrement authentifie.
//!
//! # Ce que ce module protege
//!
//! Jusqu'a la phase 8, la graine d'un portefeuille Q21 vivait **en clair** dans
//! `wallet.dat`, sur soixante-quatre caracteres hexadecimaux. Toute personne
//! ayant lu ce fichier une fois — une sauvegarde, un disque revendu, un
//! processus curieux, un partage reseau — detenait definitivement les fonds. Il
//! n'y avait aucun mot de passe, et rien ne le signalait.
//!
//! # Ce qu'on ne fabrique pas ici
//!
//! Aucune primitive nouvelle. Tout ce qui suit se construit **au-dessus de
//! SHA-256**, dont l'implementation est verifiee contre les vecteurs officiels
//! de FIPS 180-4 :
//!
//! - **HMAC-SHA256** (RFC 2104), verifie contre les vecteurs du RFC 4231 ;
//! - **PBKDF2-HMAC-SHA256** (RFC 8018), qui n'est que HMAC repete ;
//! - un **flot chiffrant** engendre par HMAC en mode compteur, puis
//!   **authentifie separement** (chiffrer-puis-authentifier).
//!
//! Inventer un chiffrement par bloc serait la meme faute qu'inventer un schema
//! de signature a reseaux euclidiens. Composer des constructions standard
//! au-dessus d'une fonction de hachage eprouvee n'en est pas une : c'est ce que
//! font HKDF, PBKDF2 et le mode CTR depuis trente ans.
//!
//! # Les limites, dites franchement
//!
//! **PBKDF2 n'est pas memory-hard.** Un attaquant equipe de circuits dedies
//! teste les mots de passe bien plus vite qu'un processeur. Argon2 ou scrypt
//! seraient meilleurs — et les ecrire soi-meme serait exactement le genre
//! d'initiative que ce projet refuse. Le nombre d'iterations est donc eleve, et
//! la vraie defense reste la **longueur de la phrase secrete**. Le module le
//! dit plutot que de le taire.

use crate::sha256::{sha256, Sha256};

/// Taille de bloc de SHA-256, en octets. C'est elle qui gouverne HMAC.
const BLOC: usize = 64;

/// Iterations par defaut de la derivation.
///
/// Environ une demi-seconde sur un processeur de bureau. Assez pour rendre une
/// recherche exhaustive couteuse, assez peu pour qu'ouvrir son portefeuille ne
/// soit pas une epreuve.
pub const ITERATIONS_DEFAUT: u32 = 600_000;

/// HMAC-SHA256, tel que decrit par le RFC 2104.
pub fn hmac_sha256(clef: &[u8], message: &[u8]) -> [u8; 32] {
    // Une clef plus longue qu'un bloc est d'abord hachee. Une clef plus courte
    // est completee de zeros. C'est la definition, et l'oublier casse
    // silencieusement l'interoperabilite.
    let mut k = [0u8; BLOC];
    if clef.len() > BLOC {
        k[..32].copy_from_slice(&sha256(clef));
    } else {
        k[..clef.len()].copy_from_slice(clef);
    }

    let mut ipad = [0x36u8; BLOC];
    let mut opad = [0x5cu8; BLOC];
    for i in 0..BLOC {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut interne = Sha256::new();
    interne.update(&ipad);
    interne.update(message);
    let h1 = interne.finalize();

    let mut externe = Sha256::new();
    externe.update(&opad);
    externe.update(&h1);
    externe.finalize()
}

/// PBKDF2-HMAC-SHA256, tel que decrit par le RFC 8018.
///
/// Rend `sortie.len()` octets derives de `mot_de_passe` et `sel`.
///
/// # Panique
///
/// Si `iterations` vaut zero. Une derivation sans iteration serait un simple
/// HMAC deguise en protection, ce qui est pire qu'aucune protection.
pub fn pbkdf2(mot_de_passe: &[u8], sel: &[u8], iterations: u32, sortie: &mut [u8]) {
    assert!(iterations > 0, "PBKDF2 sans iteration");

    let mut bloc_index: u32 = 1;
    let mut ecrit = 0usize;

    while ecrit < sortie.len() {
        // U1 = HMAC(mdp, sel || INT_32_BE(i))
        let mut entree = Vec::with_capacity(sel.len() + 4);
        entree.extend_from_slice(sel);
        entree.extend_from_slice(&bloc_index.to_be_bytes());

        let mut u = hmac_sha256(mot_de_passe, &entree);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha256(mot_de_passe, &u);
            for i in 0..32 {
                t[i] ^= u[i];
            }
        }

        let n = (sortie.len() - ecrit).min(32);
        sortie[ecrit..ecrit + n].copy_from_slice(&t[..n]);
        ecrit += n;
        bloc_index += 1;
    }
}

/// Flot chiffrant : HMAC en mode compteur.
///
/// `octet[i]` du flot vaut l'octet correspondant de
/// `HMAC(clef, "Q21/flot" || compteur)`. HMAC est une fonction pseudo-aleatoire
/// des lors que sa clef est secrete, ce qui est exactement ce qu'exige un mode
/// compteur.
///
/// Chaque clef ne sert **qu'une fois**, avec un sel neuf : reutiliser un flot
/// avec deux messages differents revelerait leur ou exclusif. Le format de
/// [`sceller`] garantit cette unicite par construction.
fn flot_xor(clef: &[u8; 32], donnees: &mut [u8]) {
    for (compteur, morceau) in (0u64..).zip(donnees.chunks_mut(32)) {
        let mut entree = [0u8; 16];
        entree[..8].copy_from_slice(b"Q21/flot");
        entree[8..].copy_from_slice(&compteur.to_le_bytes());
        let bloc = hmac_sha256(clef, &entree);
        for (o, k) in morceau.iter_mut().zip(bloc.iter()) {
            *o ^= k;
        }
    }
}

/// Comparaison en temps constant.
///
/// Comparer deux authentificateurs avec `==` laisse fuir, par le temps de
/// reponse, le nombre d'octets corrects — de quoi les reconstituer un octet a
/// la fois.
pub fn egal_temps_constant(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Deux clefs independantes derivees d'une phrase secrete.
struct Clefs {
    chiffrement: [u8; 32],
    authentification: [u8; 32],
}

fn deriver(phrase: &[u8], sel: &[u8; 16], iterations: u32) -> Clefs {
    // Une seule derivation de 64 octets, coupee en deux. Deriver deux fois
    // doublerait le cout pour l'utilisateur sans rien ajouter a l'attaquant.
    let mut brut = [0u8; 64];
    pbkdf2(phrase, sel, iterations, &mut brut);
    let mut chiffrement = [0u8; 32];
    let mut authentification = [0u8; 32];
    chiffrement.copy_from_slice(&brut[..32]);
    authentification.copy_from_slice(&brut[32..]);
    Clefs {
        chiffrement,
        authentification,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ScelleError {
    /// Le format n'est pas reconnu.
    FormatInvalide,
    /// L'authentificateur ne correspond pas : phrase secrete fausse, ou
    /// donnees alterees. On ne distingue pas les deux, et c'est voulu.
    AuthentificationEchouee,
    /// L'en-tete annonce un nombre d'iterations qu'aucun reglage honnete ne
    /// produit. Refuse **avant** la derivation, donc sans en payer le cout.
    IterationsAberrantes(u32),
}

impl std::fmt::Display for ScelleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScelleError::FormatInvalide => write!(f, "format scelle invalide"),
            ScelleError::AuthentificationEchouee => write!(
                f,
                "phrase secrete incorrecte, ou fichier altere\n  \
                 (les deux cas donnent le meme message : distinguer l'un de \
                 l'autre renseignerait un attaquant)"
            ),
            ScelleError::IterationsAberrantes(n) => write!(
                f,
                "ce fichier annonce {n} iterations, au-dela du plafond de \
                 {MAX_ITERATIONS} : il a ete altere"
            ),
        }
    }
}

const MAGIE: &[u8; 8] = b"Q21SCEL1";

/// Plafond du nombre d'iterations accepte a la lecture.
///
/// Cinquante millions d'iterations PBKDF2-HMAC-SHA256 representent environ une
/// minute sur un processeur courant : au-dela, aucune configuration honnete, et
/// une porte ouverte au deni de service par simple reecriture de quatre octets.
pub const MAX_ITERATIONS: u32 = 50_000_000;

/// Chiffre puis authentifie.
///
/// Format : `MAGIE(8) || iterations(4) || sel(16) || chiffre(n) || mac(32)`.
///
/// L'authentificateur couvre **tout ce qui precede**, en-tete compris : sans
/// cela, un attaquant pourrait ramener le nombre d'iterations a un et
/// transformer la protection en formalite.
///
/// L'ordre est chiffrer-**puis**-authentifier : on ne dechiffre jamais quoi que
/// ce soit avant d'avoir verifie que cela vient bien du detenteur de la phrase.
pub fn sceller(
    phrase: &[u8],
    clair: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, crate::rng::RngError> {
    let sel: [u8; 16] = crate::rng::octets()?;
    let k = deriver(phrase, &sel, iterations);

    let mut sortie = Vec::with_capacity(8 + 4 + 16 + clair.len() + 32);
    sortie.extend_from_slice(MAGIE);
    sortie.extend_from_slice(&iterations.to_le_bytes());
    sortie.extend_from_slice(&sel);

    let debut_chiffre = sortie.len();
    sortie.extend_from_slice(clair);
    flot_xor(&k.chiffrement, &mut sortie[debut_chiffre..]);

    let mac = hmac_sha256(&k.authentification, &sortie);
    sortie.extend_from_slice(&mac);
    Ok(sortie)
}

/// Verifie puis dechiffre.
pub fn desceller(phrase: &[u8], scelle: &[u8]) -> Result<Vec<u8>, ScelleError> {
    // --- Un fichier tronque ne doit pas se distinguer d'une mauvaise phrase.
    //
    // La documentation de ce module promettait que les deux cas donnent le meme
    // message ; un audit a montre que non. Une troncature rendait
    // `FormatInvalide`, une phrase fausse `AuthentificationEchouee` : de quoi
    // savoir, en observant les messages, si la phrase essayee etait la bonne
    // sur un fichier qu'on vient d'abimer soi-meme.
    //
    // On ne conserve la distinction que la ou elle informe l'utilisateur sans
    // rien dire a un attaquant : **la magie**. Absente, ce fichier n'est pas un
    // portefeuille Q21, et le dire ne renseigne personne. Presente mais le
    // reste illisible, c'est le meme message qu'une phrase fausse.
    if scelle.len() < 8 || &scelle[..8] != MAGIE {
        return Err(ScelleError::FormatInvalide);
    }
    if scelle.len() < 8 + 4 + 16 + 32 {
        return Err(ScelleError::AuthentificationEchouee);
    }
    let iterations = u32::from_le_bytes([scelle[8], scelle[9], scelle[10], scelle[11]]);
    if iterations == 0 {
        return Err(ScelleError::AuthentificationEchouee);
    }
    // --- Le nombre d'iterations est authentifie, mais il est **lu avant** de
    //     l'etre. C'est inevitable : il faut la clef pour verifier le MAC, et
    //     il faut ce nombre pour deriver la clef.
    //
    // Un audit s'en est servi : quatre octets ecrits dans `wallet.dat` — pas la
    // phrase, pas la graine, juste l'en-tete — imposaient jusqu'a 2^32-1
    // iterations de PBKDF2. Des heures de calcul avant le moindre rejet, et un
    // portefeuille qui semble simplement ne plus s'ouvrir.
    //
    // La borne se pose donc **avant** la derivation, sur une valeur qu'on n'a
    // pas encore le droit de croire. Elle est large : elle laisse passer tout
    // reglage legitime, et coupe l'absurde.
    if iterations > MAX_ITERATIONS {
        return Err(ScelleError::IterationsAberrantes(iterations));
    }
    let mut sel = [0u8; 16];
    sel.copy_from_slice(&scelle[12..28]);

    let (corps, mac_recu) = scelle.split_at(scelle.len() - 32);
    let k = deriver(phrase, &sel, iterations);

    // Verification AVANT tout dechiffrement.
    let mac = hmac_sha256(&k.authentification, corps);
    if !egal_temps_constant(&mac, mac_recu) {
        return Err(ScelleError::AuthentificationEchouee);
    }

    let mut clair = corps[28..].to_vec();
    flot_xor(&k.chiffrement, &mut clair);
    Ok(clair)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(o: &[u8]) -> String {
        o.iter().map(|b| format!("{b:02x}")).collect()
    }

    // -----------------------------------------------------------------------
    // Vecteurs officiels du RFC 4231
    // -----------------------------------------------------------------------
    //
    // Ces deux vecteurs valident d'un coup HMAC **et** l'implementation de
    // SHA-256 sur laquelle il repose. Les faire passer par accident est
    // impossible.

    #[test]
    fn hmac_vecteur_rfc4231_cas_1() {
        let clef = [0x0bu8; 20];
        let mac = hmac_sha256(&clef, b"Hi There");
        assert_eq!(
            hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_vecteur_rfc4231_cas_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// Cas 3 : clef et message d'un bloc entier de 0xaa / 0xdd.
    #[test]
    fn hmac_vecteur_rfc4231_cas_3() {
        let clef = [0xaau8; 20];
        let msg = [0xddu8; 50];
        let mac = hmac_sha256(&clef, &msg);
        assert_eq!(
            hex(&mac),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    /// Cas 6 : clef **plus longue qu'un bloc**, donc hachee au prealable. C'est
    /// la branche la plus facile a rater dans une implementation maison.
    #[test]
    fn hmac_vecteur_rfc4231_cas_6_clef_longue() {
        let clef = [0xaau8; 131];
        let mac = hmac_sha256(
            &clef,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    // -----------------------------------------------------------------------
    // PBKDF2
    // -----------------------------------------------------------------------

    /// Vecteur PBKDF2-HMAC-SHA256 largement publie (RFC 7914, section 11).
    #[test]
    fn pbkdf2_vecteur_connu() {
        let mut out = [0u8; 64];
        pbkdf2(b"passwd", b"salt", 1, &mut out);
        assert_eq!(
            hex(&out),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
             49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
    }

    #[test]
    fn pbkdf2_change_avec_le_sel_et_les_iterations() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        pbkdf2(b"mdp", b"sel-a", 1_000, &mut a);
        pbkdf2(b"mdp", b"sel-b", 1_000, &mut b);
        pbkdf2(b"mdp", b"sel-a", 1_001, &mut c);
        assert_ne!(a, b, "le sel doit changer la sortie");
        assert_ne!(a, c, "le nombre d'iterations doit changer la sortie");
    }

    #[test]
    fn pbkdf2_est_deterministe() {
        let mut a = [0u8; 40];
        let mut b = [0u8; 40];
        pbkdf2(b"phrase", b"sel", 500, &mut a);
        pbkdf2(b"phrase", b"sel", 500, &mut b);
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------------
    // Scellement
    // -----------------------------------------------------------------------

    #[test]
    fn aller_retour_sur_le_scellement() {
        let clair = b"graine tres secrete de trente-deux";
        let s = sceller(b"ma phrase secrete", clair, 1_000).unwrap();
        assert_eq!(desceller(b"ma phrase secrete", &s).unwrap(), clair);
    }

    #[test]
    fn une_mauvaise_phrase_est_refusee() {
        let s = sceller(b"bonne", b"secret", 1_000).unwrap();
        assert_eq!(
            desceller(b"mauvaise", &s),
            Err(ScelleError::AuthentificationEchouee)
        );
    }

    /// Le chiffre ne doit jamais laisser deviner le clair.
    #[test]
    fn le_clair_n_apparait_pas_dans_le_scelle() {
        let clair = b"MOTIF-RECONNAISSABLE-0123456789";
        let s = sceller(b"phrase", clair, 1_000).unwrap();
        assert!(
            !s.windows(clair.len()).any(|f| f == clair),
            "le clair figure tel quel dans le scelle"
        );
    }

    /// Deux scellements du meme clair avec la meme phrase doivent differer :
    /// sinon, un observateur apprend que rien n'a change.
    #[test]
    fn deux_scellements_du_meme_clair_different() {
        let a = sceller(b"phrase", b"identique", 1_000).unwrap();
        let b = sceller(b"phrase", b"identique", 1_000).unwrap();
        assert_ne!(a, b, "le sel doit etre neuf a chaque scellement");
        assert_eq!(desceller(b"phrase", &a).unwrap(), b"identique");
        assert_eq!(desceller(b"phrase", &b).unwrap(), b"identique");
    }

    /// Un octet modifie **n'importe ou** doit faire echouer l'ouverture, en
    /// particulier dans l'en-tete : c'est ce qui empeche de ramener le nombre
    /// d'iterations a un.
    #[test]
    fn un_octet_modifie_fait_echouer_l_ouverture() {
        // Peu d'iterations : ce test en fait une par octet du scelle, et c'est
        // la propriete qu'on verifie, pas le cout de la derivation.
        let s = sceller(b"phrase", b"secret bien garde", 4).unwrap();
        for pos in 0..s.len() {
            let mut altere = s.clone();
            altere[pos] ^= 0x01;
            assert!(
                desceller(b"phrase", &altere).is_err(),
                "l'octet {pos} a pu etre modifie sans etre detecte"
            );
        }
    }

    #[test]
    fn un_scelle_tronque_est_refuse() {
        let s = sceller(b"phrase", b"secret", 1_000).unwrap();
        for n in 0..s.len() {
            assert!(desceller(b"phrase", &s[..n]).is_err());
        }
    }

    #[test]
    fn un_fichier_quelconque_n_est_pas_un_scelle() {
        assert_eq!(
            desceller(b"phrase", b"ceci n'est pas un scelle du tout"),
            Err(ScelleError::FormatInvalide)
        );
    }

    #[test]
    fn la_comparaison_en_temps_constant_est_correcte() {
        assert!(egal_temps_constant(b"abc", b"abc"));
        assert!(!egal_temps_constant(b"abc", b"abd"));
        assert!(!egal_temps_constant(b"abc", b"ab"));
        assert!(egal_temps_constant(b"", b""));
    }
}
