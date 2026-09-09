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
//! # La derivation de clef : Argon2id
//!
//! La premiere version derivait la clef par PBKDF2, en le disant franchement :
//! PBKDF2 n'est pas resistant a la memoire, et un attaquant equipe de circuits
//! dedies teste les phrases bien plus vite qu'un processeur. La seule defense
//! etait la longueur de la phrase.
//!
//! La derivation est desormais **Argon2id** ([`crate::argon2`], RFC 9106) :
//! 64 Mio de memoire et trois passes par essai, ce qui coute a un circuit
//! dedie a peu pres ce que cela coute a l'utilisateur — un tiers de seconde
//! sur un processeur de bureau, une seconde sur un Raspberry. Ce n'est pas une
//! primitive inventee ici : c'est la norme, implementee d'apres son texte et
//! verifiee contre ses trois vecteurs, comme SHA-256 l'est contre FIPS 180-4.
//!
//! Les fichiers scelles par PBKDF2 (magie `Q21SCEL1`) restent lisibles ; ils
//! sont rescelles en Argon2id (magie `Q21SCEL2`) a leur prochaine ecriture, ce
//! qui arrive des la premiere adresse tiree ou la premiere depense.

use crate::sha256::{sha256, Sha256};

/// Taille de bloc de SHA-256, en octets. C'est elle qui gouverne HMAC.
const BLOC: usize = 64;

/// Iterations PBKDF2 des fichiers de l'ancien format (`Q21SCEL1`).
///
/// Ne sert plus qu'a les relire et aux epreuves ; les nouveaux fichiers sont
/// scelles par Argon2id avec [`COUT_DEFAUT`].
pub const ITERATIONS_DEFAUT: u32 = 600_000;

/// Cout d'une derivation Argon2id : memoire et passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cout {
    pub memoire_kib: u32,
    pub passes: u32,
}

/// Le cout par defaut : 64 Mio, trois passes, une lane.
///
/// C'est le reglage « conservateur » du RFC 9106 pour un usage interactif.
/// Mesure : 0,30 s sur un petit processeur de serveur, donc moins sur un PC
/// et environ une seconde sur un Raspberry — moins que les 600 000
/// iterations de PBKDF2 qu'il remplace, pour une resistance sans commune
/// mesure face au materiel dedie.
pub const COUT_DEFAUT: Cout = Cout {
    memoire_kib: 64 * 1024,
    passes: 3,
};

/// Le cout des epreuves : le meme algorithme, en une fraction de seconde.
pub const COUT_EPREUVE: Cout = Cout {
    memoire_kib: 64,
    passes: 1,
};

/// Plafonds acceptes a la lecture, pour les memes raisons que
/// [`MAX_ITERATIONS`] : un en-tete reecrit ne doit pas pouvoir imposer une
/// allocation enorme et des minutes de calcul avant le moindre rejet.
///
/// Les parametres se lisent **avant** de verifier le MAC — il le faut pour
/// deriver la clef — donc c'est cette borne, et elle seule, qui limite ce
/// qu'un fichier reecrit coute a l'ouverture. Quatre fois le reglage par
/// defaut en memoire, un peu plus de trois fois en passes : assez pour un
/// reglage renforce, pas pour une allocation d'un gibioctet qui, sur une
/// petite machine, tuait le processus avant l'echec d'authentification.
pub const MAX_MEMOIRE_KIB: u32 = 256 * 1024;
pub const MAX_PASSES: u32 = 10;

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

/// Met a zero un tampon sensible, d'une facon que l'optimiseur ne peut pas
/// supprimer.
///
/// Une ecriture ordinaire dont personne ne lit le resultat est un code mort
/// aux yeux du compilateur, et il l'enleve. `write_volatile` la rend
/// obligatoire. Cela ne protege ni d'un lecteur de la memoire vive pendant
/// l'execution, ni d'une page echangee sur disque ; cela evite qu'un secret
/// survive dans un tas reutilise, puis dans un fichier de vidage.
pub fn effacer(tampon: &mut [u8]) {
    for o in tampon.iter_mut() {
        // Sur : chaque pointeur vient d'un element valide du tampon.
        unsafe { std::ptr::write_volatile(o, 0) };
    }
}

/// Deux clefs independantes derivees d'une phrase secrete.
///
/// Effacees a la destruction : une clef de chiffrement de portefeuille qui
/// traine dans le tas vaut la phrase elle-meme.
struct Clefs {
    chiffrement: [u8; 32],
    authentification: [u8; 32],
}

impl Drop for Clefs {
    fn drop(&mut self) {
        effacer(&mut self.chiffrement);
        effacer(&mut self.authentification);
    }
}

fn deriver(phrase: &[u8], sel: &[u8; 16], iterations: u32) -> Clefs {
    // Une seule derivation de 64 octets, coupee en deux. Deriver deux fois
    // doublerait le cout pour l'utilisateur sans rien ajouter a l'attaquant.
    let mut brut = [0u8; 64];
    pbkdf2(phrase, sel, iterations, &mut brut);
    let clefs = couper(&brut);
    effacer(&mut brut);
    clefs
}

/// La derivation Argon2id du format courant.
fn deriver_argon2(phrase: &[u8], sel: &[u8; 16], cout: Cout) -> Clefs {
    let p = crate::argon2::Parametres {
        variante: crate::argon2::Variante::Id,
        memoire_kib: cout.memoire_kib,
        passes: cout.passes,
        lanes: 1,
    };
    let mut brut = crate::argon2::deriver(p, phrase, sel, &[], &[], 64);
    let mut tampon = [0u8; 64];
    tampon.copy_from_slice(&brut);
    let clefs = couper(&tampon);
    effacer(&mut brut);
    effacer(&mut tampon);
    clefs
}

fn couper(brut: &[u8; 64]) -> Clefs {
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
    /// L'en-tete du format courant annonce un cout Argon2id hors bornes.
    /// Refuse de la meme facon, avant toute derivation.
    CoutAberrant { memoire_kib: u32, passes: u32 },
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
            ScelleError::CoutAberrant {
                memoire_kib,
                passes,
            } => write!(
                f,
                "ce fichier annonce {memoire_kib} Kio et {passes} passe(s), hors des \
                 bornes (8 a {MAX_MEMOIRE_KIB} Kio, 1 a {MAX_PASSES} passes) : il a ete altere"
            ),
        }
    }
}

/// Magie de l'ancien format : PBKDF2. Lu, jamais ecrit.
const MAGIE: &[u8; 8] = b"Q21SCEL1";
/// Magie du format courant : Argon2id.
const MAGIE2: &[u8; 8] = b"Q21SCEL2";

/// Plafond du nombre d'iterations accepte a la lecture.
///
/// Cinquante millions d'iterations PBKDF2-HMAC-SHA256 representent environ une
/// minute sur un processeur courant : au-dela, aucune configuration honnete, et
/// une porte ouverte au deni de service par simple reecriture de quatre octets.
pub const MAX_ITERATIONS: u32 = 50_000_000;

/// Chiffre puis authentifie.
///
/// Format : `MAGIE2(8) || memoire_kib(4) || passes(4) || sel(16) || chiffre(n)
/// || mac(32)`.
///
/// L'authentificateur couvre **tout ce qui precede**, en-tete compris : sans
/// cela, un attaquant pourrait ramener le cout a rien et transformer la
/// protection en formalite.
///
/// L'ordre est chiffrer-**puis**-authentifier : on ne dechiffre jamais quoi que
/// ce soit avant d'avoir verifie que cela vient bien du detenteur de la phrase.
pub fn sceller(phrase: &[u8], clair: &[u8], cout: Cout) -> Result<Vec<u8>, crate::rng::RngError> {
    let sel: [u8; 16] = crate::rng::octets()?;
    let k = deriver_argon2(phrase, &sel, cout);

    let mut sortie = Vec::with_capacity(8 + 4 + 4 + 16 + clair.len() + 32);
    sortie.extend_from_slice(MAGIE2);
    sortie.extend_from_slice(&cout.memoire_kib.to_le_bytes());
    sortie.extend_from_slice(&cout.passes.to_le_bytes());
    sortie.extend_from_slice(&sel);

    let debut_chiffre = sortie.len();
    sortie.extend_from_slice(clair);
    flot_xor(&k.chiffrement, &mut sortie[debut_chiffre..]);

    let mac = hmac_sha256(&k.authentification, &sortie);
    sortie.extend_from_slice(&mac);
    Ok(sortie)
}

/// Ce contenu est-il un fichier scelle ?
///
/// Utile pour prevenir l'utilisateur *avant* de lui demander sa phrase secrete :
/// une invite nue, sans rien qui l'annonce, ressemble a une panne. On ne devine
/// jamais — soit le fichier porte la magie, soit il n'est pas scelle.
pub fn est_scelle(contenu: &[u8]) -> bool {
    contenu.starts_with(MAGIE) || contenu.starts_with(MAGIE2)
}

/// Ce scelle est-il de l'ancien format, a resceller ?
pub fn est_ancien_format(contenu: &[u8]) -> bool {
    contenu.starts_with(MAGIE)
}

/// Le cout Argon2id annonce par l'en-tete d'un scelle du format courant.
///
/// `None` pour tout autre contenu — un fichier en clair, ou l'ancien format,
/// qui n'a pas de cout Argon2. La valeur est lue **avant** d'etre
/// authentifiee, comme dans [`desceller`] : elle ne sert qu'a decider d'un
/// rescellement une fois la phrase verifiee, jamais a accorder quoi que ce
/// soit.
pub fn cout_lu(contenu: &[u8]) -> Option<Cout> {
    if !contenu.starts_with(MAGIE2) || contenu.len() < 16 {
        return None;
    }
    Some(Cout {
        memoire_kib: u32::from_le_bytes([contenu[8], contenu[9], contenu[10], contenu[11]]),
        passes: u32::from_le_bytes([contenu[12], contenu[13], contenu[14], contenu[15]]),
    })
}

/// Ce scelle est-il protege par moins que le cout par defaut ?
///
/// # Le defaut que ceci ferme
///
/// Le MAC couvre l'en-tete : un tiers sans la phrase ne peut pas abaisser le
/// cout. Mais un fichier scelle a 8 Kio et une passe — par un autre outil,
/// une version modifiee, une option d'essai — s'ouvrait en quarante
/// microsecondes sans un mot, et n'etait jamais rescelle : l'utilisateur
/// croyait son fichier derriere 64 Mio d'Argon2id. Un plancher n'aurait pas
/// suffi — refuser d'ouvrir un portefeuille legitime serait pire — mais il
/// faut le dire, et le resceller au defaut a la premiere ouverture.
///
/// L'ancien format (PBKDF2) est **toujours** sous le defaut : il n'a pas de
/// resistance a la memoire du tout, c'est pour cela qu'il est rescelle.
pub fn est_sous_le_cout_par_defaut(contenu: &[u8]) -> bool {
    if est_ancien_format(contenu) {
        return true;
    }
    match cout_lu(contenu) {
        Some(c) => c.memoire_kib < COUT_DEFAUT.memoire_kib || c.passes < COUT_DEFAUT.passes,
        None => false,
    }
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
    if scelle.len() < 8 {
        return Err(ScelleError::FormatInvalide);
    }
    if &scelle[..8] == MAGIE2 {
        return desceller_argon2(phrase, scelle);
    }
    if &scelle[..8] != MAGIE {
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

/// Le format courant. Meme discipline que l'ancien : le cout est lu avant
/// d'etre authentifie — il le faut pour deriver la clef — donc borne avant
/// toute derivation ; le MAC est verifie avant tout dechiffrement.
fn desceller_argon2(phrase: &[u8], scelle: &[u8]) -> Result<Vec<u8>, ScelleError> {
    const ENTETE: usize = 8 + 4 + 4 + 16;
    if scelle.len() < ENTETE + 32 {
        return Err(ScelleError::AuthentificationEchouee);
    }
    let memoire_kib = u32::from_le_bytes([scelle[8], scelle[9], scelle[10], scelle[11]]);
    let passes = u32::from_le_bytes([scelle[12], scelle[13], scelle[14], scelle[15]]);
    if !(8..=MAX_MEMOIRE_KIB).contains(&memoire_kib) || !(1..=MAX_PASSES).contains(&passes) {
        return Err(ScelleError::CoutAberrant {
            memoire_kib,
            passes,
        });
    }
    let mut sel = [0u8; 16];
    sel.copy_from_slice(&scelle[16..32]);

    let (corps, mac_recu) = scelle.split_at(scelle.len() - 32);
    let k = deriver_argon2(
        phrase,
        &sel,
        Cout {
            memoire_kib,
            passes,
        },
    );
    let mac = hmac_sha256(&k.authentification, corps);
    if !egal_temps_constant(&mac, mac_recu) {
        return Err(ScelleError::AuthentificationEchouee);
    }
    let mut clair = corps[ENTETE..].to_vec();
    flot_xor(&k.chiffrement, &mut clair);
    Ok(clair)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(o: &[u8]) -> String {
        o.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Un scelle sous le cout par defaut est reconnu comme tel ; un scelle au
    /// defaut, ou au-dela, ne l'est pas ; l'ancien format l'est toujours.
    #[test]
    fn un_scelle_sous_le_cout_par_defaut_est_reconnu() {
        let faible = sceller(
            b"p",
            b"x",
            Cout {
                memoire_kib: 8,
                passes: 1,
            },
        )
        .unwrap();
        assert_eq!(
            cout_lu(&faible),
            Some(Cout {
                memoire_kib: 8,
                passes: 1
            })
        );
        assert!(est_sous_le_cout_par_defaut(&faible));
        // Assez de memoire, pas assez de passes : c'est encore sous le defaut.
        let passes = sceller(
            b"p",
            b"x",
            Cout {
                memoire_kib: COUT_DEFAUT.memoire_kib,
                passes: 1,
            },
        )
        .unwrap();
        assert!(est_sous_le_cout_par_defaut(&passes));
        // Le cout par defaut lui-meme : rien a resceller.
        let defaut = sceller(b"p", b"x", COUT_DEFAUT).unwrap();
        assert_eq!(cout_lu(&defaut), Some(COUT_DEFAUT));
        assert!(!est_sous_le_cout_par_defaut(&defaut));
        // Un contenu en clair n'a pas de cout, et n'est pas « sous le defaut ».
        assert_eq!(cout_lu(b"seed=00"), None);
        assert!(!est_sous_le_cout_par_defaut(b"seed=00"));
        // L'ancien format est toujours a resceller.
        let mut ancien = Vec::new();
        ancien.extend_from_slice(MAGIE);
        ancien.extend_from_slice(&1_000u32.to_le_bytes());
        ancien.extend_from_slice(&[7u8; 16]);
        assert!(est_ancien_format(&ancien));
        assert!(est_sous_le_cout_par_defaut(&ancien));
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
        let s = sceller(b"ma phrase secrete", clair, COUT_EPREUVE).unwrap();
        assert_eq!(desceller(b"ma phrase secrete", &s).unwrap(), clair);
    }

    #[test]
    fn une_mauvaise_phrase_est_refusee() {
        let s = sceller(b"bonne", b"secret", COUT_EPREUVE).unwrap();
        assert_eq!(
            desceller(b"mauvaise", &s),
            Err(ScelleError::AuthentificationEchouee)
        );
    }

    /// Le chiffre ne doit jamais laisser deviner le clair.
    #[test]
    fn le_clair_n_apparait_pas_dans_le_scelle() {
        let clair = b"MOTIF-RECONNAISSABLE-0123456789";
        let s = sceller(b"phrase", clair, COUT_EPREUVE).unwrap();
        assert!(
            !s.windows(clair.len()).any(|f| f == clair),
            "le clair figure tel quel dans le scelle"
        );
    }

    /// Deux scellements du meme clair avec la meme phrase doivent differer :
    /// sinon, un observateur apprend que rien n'a change.
    #[test]
    fn deux_scellements_du_meme_clair_different() {
        let a = sceller(b"phrase", b"identique", COUT_EPREUVE).unwrap();
        let b = sceller(b"phrase", b"identique", COUT_EPREUVE).unwrap();
        assert_ne!(a, b, "le sel doit etre neuf a chaque scellement");
        assert_eq!(desceller(b"phrase", &a).unwrap(), b"identique");
        assert_eq!(desceller(b"phrase", &b).unwrap(), b"identique");
    }

    /// Un octet modifie **n'importe ou** doit faire echouer l'ouverture, en
    /// particulier dans l'en-tete : c'est ce qui empeche de ramener le nombre
    /// d'iterations a un.
    #[test]
    fn un_octet_modifie_fait_echouer_l_ouverture() {
        // Le cout d'epreuve : ce test fait une derivation par octet du scelle,
        // et c'est la propriete qu'on verifie, pas le cout de la derivation.
        let s = sceller(b"phrase", b"secret bien garde", COUT_EPREUVE).unwrap();
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
        let s = sceller(b"phrase", b"secret", COUT_EPREUVE).unwrap();
        for n in 0..s.len() {
            assert!(desceller(b"phrase", &s[..n]).is_err());
        }
    }

    /// Un scelle de l'ancien format (PBKDF2) s'ouvre toujours : personne ne
    /// doit perdre l'acces a son portefeuille parce que la derivation a
    /// change. Il se reconnait comme ancien, pour etre rescelle.
    #[test]
    fn un_scelle_de_l_ancien_format_s_ouvre_encore() {
        // Reproduction exacte de l'ancien `sceller`, avec un sel fixe.
        let phrase = b"phrase d'avant";
        let clair = b"seed=deadbeef\nnext_index=3\n";
        let iterations = 1_000u32;
        let sel = [7u8; 16];
        let k = deriver(phrase, &sel, iterations);
        let mut ancien = Vec::new();
        ancien.extend_from_slice(MAGIE);
        ancien.extend_from_slice(&iterations.to_le_bytes());
        ancien.extend_from_slice(&sel);
        let debut = ancien.len();
        ancien.extend_from_slice(clair);
        flot_xor(&k.chiffrement, &mut ancien[debut..]);
        let mac = hmac_sha256(&k.authentification, &ancien);
        ancien.extend_from_slice(&mac);

        assert!(est_scelle(&ancien));
        assert!(est_ancien_format(&ancien));
        assert_eq!(desceller(phrase, &ancien).unwrap(), clair);
        assert!(desceller(b"autre", &ancien).is_err());

        // Et le format courant n'est pas « ancien ».
        let neuf = sceller(phrase, clair, COUT_EPREUVE).unwrap();
        assert!(est_scelle(&neuf));
        assert!(!est_ancien_format(&neuf));
        assert_eq!(desceller(phrase, &neuf).unwrap(), clair);
    }

    /// Un cout reecrit dans l'en-tete est refuse avant toute derivation :
    /// un attaquant qui ecrit huit octets ne doit pas pouvoir imposer un
    /// gibioctet de calcul avant le moindre rejet.
    #[test]
    fn un_cout_aberrant_est_refuse_avant_de_deriver() {
        let s = sceller(b"phrase", b"secret", COUT_EPREUVE).unwrap();
        let mut memoire = s.clone();
        memoire[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let t = std::time::Instant::now();
        assert!(matches!(
            desceller(b"phrase", &memoire),
            Err(ScelleError::CoutAberrant { .. })
        ));
        assert!(t.elapsed() < std::time::Duration::from_millis(50));

        let mut passes = s.clone();
        passes[12..16].copy_from_slice(&1_000u32.to_le_bytes());
        assert!(matches!(
            desceller(b"phrase", &passes),
            Err(ScelleError::CoutAberrant { .. })
        ));
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
