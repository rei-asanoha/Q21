//! Schemas de signature et agilite algorithmique.
//!
//! C'est ici que se joue la lecon de la section 4 du livre blanc. Bitcoin est
//! prisonnier d'ECDSA parce que son format d'adresse d'origine n'a jamais
//! envisage qu'un autre schema puisse exister. Q21 encode l'identifiant du
//! schema dans l'adresse elle-meme : ajouter un schema devient une evolution
//! compatible, jamais une rupture de chaine.
//!
//! # Pourquoi ML-DSA n'est pas implemente dans ce fichier
//!
//! Ecrire soi-meme un schema de signature a reseaux euclidiens est une faute
//! professionnelle. Les canaux auxiliaires, l'echantillonnage de rejet et
//! l'arithmetique modulaire en temps constant sont exactement le terrain ou une
//! implementation maison parait correcte, passe tous les tests fonctionnels, et
//! fuit la clef privee.
//!
//! Rappel utile : en fevrier 2022, Rainbow — finaliste du concours NIST — est
//! tombe en un week-end sur un ordinateur portable. Quelques mois plus tard,
//! SIKE tombait en une heure sur un seul coeur. Ces schemas avaient survecu a
//! cinq ans d'examen public par des cryptographes professionnels. Notre code
//! maison n'aurait pas survecu cinq minutes.
//!
//! Ce module definit donc l'interface. L'implementation se branche via la
//! feature `mldsa`, adossee au crate `ml-dsa` de RustCrypto.

use crate::hash::{tagged_hash, tags, Hash256};

/// Identifiant de schema, tel qu'il apparait dans l'adresse et dans le temoin.
///
/// La valeur numerique est consensuelle : elle ne doit jamais changer une fois
/// le bloc de genese produit.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum SchemeId {
    /// Securite NIST niveau 3, environ AES-192.
    ///
    /// Conserve pour les usages ou le debit prime sur la marge : une
    /// transaction y pese 5 403 octets contre 7 361, soit 370 transactions par
    /// bloc au lieu de 271.
    MlDsa65 = 1,
    /// **Defaut de Q21.** Securite NIST niveau 5, environ AES-256.
    ///
    /// # Pourquoi le niveau maximal, et pas le niveau courant
    ///
    /// Le choix se decide sur ce qu'il coute, et la mesure a tranche. Sur une
    /// machine ordinaire :
    ///
    /// | | ML-DSA-65 | ML-DSA-87 |
    /// |---|---|---|
    /// | verifications par seconde | 3 944 | 2 494 |
    /// | **bloc plein verifie en** | **94 ms** | **109 ms** |
    ///
    /// Le bloc vise cent vingt secondes. Le niveau maximal de la norme coute
    /// donc **quinze millisecondes par bloc** : rien qui se remarque, jamais.
    ///
    /// Ce qui se paie vraiment est le debit — 271 transactions par bloc au lieu
    /// de 370, pour la meme taille. C'est le seul arbitrage reel, et il penche
    /// du cote de la marge : une chaine se lance une fois, et les adresses
    /// qu'elle emet vivent des decennies.
    ///
    /// # Ce qui n'aurait servi a rien
    ///
    /// Allonger la **graine** a 512 bits. FIPS 204 la fixe a trente-deux octets
    /// pour les trois niveaux, et la resistance quantique de ML-DSA ne vient
    /// pas de sa longueur mais du probleme sur reseaux euclidiens. Une graine
    /// de 256 bits face a Grover vaut 2^128 : un mur que rien n'atteindra.
    /// L'allonger aurait demande de reecrire ML-DSA a la main — la seule chose
    /// que ce projet s'interdit.
    MlDsa87 = 2,
    /// Le parachute. Securite fondee uniquement sur les fonctions de hachage,
    /// donc sur des hypotheses independantes des reseaux euclidiens.
    SphincsPlus = 3,
    /// Lamport, a usage unique. **Reseaux de test uniquement.**
    ///
    /// Presente pour que la chaine soit utilisable — miner, signer, transferer —
    /// avant que ML-DSA soit branche. Reutiliser une clef revele la clef privee ;
    /// [`SchemeId::allowed_on`] l'interdit donc sur le reseau principal, et cette
    /// interdiction est une regle de consensus, pas une recommandation.
    LamportOts = 4,
}

impl SchemeId {
    pub fn from_u8(v: u8) -> Option<SchemeId> {
        match v {
            1 => Some(SchemeId::MlDsa65),
            2 => Some(SchemeId::MlDsa87),
            3 => Some(SchemeId::SphincsPlus),
            4 => Some(SchemeId::LamportOts),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        match self {
            SchemeId::MlDsa65 => "ML-DSA-65",
            SchemeId::MlDsa87 => "ML-DSA-87",
            SchemeId::SphincsPlus => "SPHINCS+-SHA2-192s",
            SchemeId::LamportOts => "Lamport-OTS (test uniquement)",
        }
    }

    /// Taille attendue d'une clef publique, en octets.
    pub const fn pubkey_len(self) -> usize {
        match self {
            SchemeId::MlDsa65 => 1952,
            SchemeId::MlDsa87 => 2592,
            SchemeId::SphincsPlus => 48,
            SchemeId::LamportOts => crate::lamport::PUBKEY_LEN,
        }
    }

    /// Taille attendue d'une signature, en octets.
    ///
    /// A comparer aux 71 octets d'ECDSA. C'est cette ligne qui commande le
    /// dimensionnement des blocs.
    pub const fn sig_len(self) -> usize {
        match self {
            SchemeId::MlDsa65 => 3309,
            SchemeId::MlDsa87 => 4627,
            SchemeId::SphincsPlus => 16224,
            SchemeId::LamportOts => crate::lamport::SIG_LEN,
        }
    }

    /// Tous les schemas reconnus par le protocole.
    pub const ALL: [SchemeId; 4] = [
        SchemeId::MlDsa65,
        SchemeId::MlDsa87,
        SchemeId::SphincsPlus,
        SchemeId::LamportOts,
    ];

    /// Regle de consensus : quels schemas sont acceptes sur quel reseau.
    ///
    /// Lamport est a usage unique. Une clef reutilisee revele la clef privee, et
    /// rien ne permet a un validateur de detecter la reutilisation avant qu'il
    /// soit trop tard. Le reseau principal le refuse donc categoriquement.
    ///
    /// Cette regle vit dans le consensus et non dans la documentation, parce
    /// qu'une regle documentee est une regle qu'on oublie.
    pub const fn allowed_on(self, network: crate::address::Network) -> bool {
        match self {
            SchemeId::LamportOts => !matches!(network, crate::address::Network::Mainnet),
            _ => true,
        }
    }

    /// Une clef de ce schema ne peut servir qu'une fois.
    ///
    /// Vrai pour Lamport, et pour lui seul. C'est une propriete du schema, pas
    /// une precaution : signer deux fois avec la meme clef Lamport revele la
    /// clef privee. ML-DSA n'a pas cette contrainte — le portefeuille change
    /// tout de meme d'adresse a chaque fois, mais par confidentialite.
    pub const fn est_a_usage_unique(self) -> bool {
        matches!(self, SchemeId::LamportOts)
    }

    /// Ce binaire sait-il verifier ce schema ?
    ///
    /// Distinct de [`Self::allowed_on`] : le protocole peut autoriser un schema
    /// que cette compilation ne sait pas traiter. Un noeud qui rencontre ce cas
    /// doit refuser la transaction, jamais l'accepter sans la verifier.
    pub const fn disponible(self) -> bool {
        match self {
            SchemeId::LamportOts => true,
            SchemeId::MlDsa65 | SchemeId::MlDsa87 => cfg!(feature = "mldsa"),
            SchemeId::SphincsPlus => false,
        }
    }
}

/// Empreinte d'une clef publique, telle qu'elle apparait dans une adresse.
///
/// La clef complete n'est revelee qu'a la depense : une adresse ML-DSA-65
/// porterait sinon 1952 octets, ce qui la rendrait inutilisable.
pub fn pubkey_hash(scheme: SchemeId, pubkey: &[u8]) -> Hash256 {
    let mut buf = Vec::with_capacity(1 + pubkey.len());
    buf.push(scheme.as_u8());
    buf.extend_from_slice(pubkey);
    tagged_hash(tags::ADDRESS, &buf)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VerifyError {
    /// Le schema n'est pas encore compile dans ce binaire.
    SchemaNonDisponible(SchemeId),
    /// Longueur de clef publique incorrecte pour ce schema.
    LongueurClefInvalide { attendu: usize, recu: usize },
    /// Longueur de signature incorrecte pour ce schema.
    LongueurSignatureInvalide { attendu: usize, recu: usize },
    /// La signature ne verifie pas.
    SignatureInvalide,
}

/// Verifie que les tailles annoncees correspondent au schema.
///
/// Ce controle est utile meme sans implementation cryptographique branchee : il
/// rejette une transaction malformee avant tout calcul couteux, et fait donc
/// partie de la defense contre le deni de service.
pub fn check_sizes(scheme: SchemeId, pubkey: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
    if pubkey.len() != scheme.pubkey_len() {
        return Err(VerifyError::LongueurClefInvalide {
            attendu: scheme.pubkey_len(),
            recu: pubkey.len(),
        });
    }
    if sig.len() != scheme.sig_len() {
        return Err(VerifyError::LongueurSignatureInvalide {
            attendu: scheme.sig_len(),
            recu: sig.len(),
        });
    }
    Ok(())
}

/// Verifie une signature.
///
/// Sans la feature `mldsa`, les controles de forme s'appliquent mais la
/// verification cryptographique rend `SchemaNonDisponible`. Ce comportement est
/// deliberement bruyant : un noeud ne doit jamais accepter une signature qu'il
/// n'a pas verifiee.
pub fn verify(
    scheme: SchemeId,
    pubkey: &[u8],
    message: &Hash256,
    sig: &[u8],
) -> Result<(), VerifyError> {
    check_sizes(scheme, pubkey, sig)?;

    // Lamport ne depend d'aucun crate externe : toujours disponible.
    if scheme == SchemeId::LamportOts {
        return if crate::lamport::verify(pubkey, message, sig) {
            Ok(())
        } else {
            Err(VerifyError::SignatureInvalide)
        };
    }

    #[cfg(feature = "mldsa")]
    {
        if let Some(r) = mldsa_backend::verify(scheme, pubkey, message.as_bytes(), sig) {
            return if r {
                Ok(())
            } else {
                Err(VerifyError::SignatureInvalide)
            };
        }
    }

    let _ = message;
    Err(VerifyError::SchemaNonDisponible(scheme))
}

/// Adaptateur vers le crate `ml-dsa` de RustCrypto.
///
/// Compile uniquement avec `--features mldsa`. Le decoupage en module isole
/// entierement le reste du noyau de l'API du crate : si celle-ci evolue, seul
/// ce fichier bouge.
/// # Choix de conception verifies contre les sources de `ml-dsa` 0.1.1
///
/// **`VerifyingKey::decode` est infaillible.** Elle rend `Self`, pas
/// `Option<Self>` : n'importe quelle suite de 1952 octets se decode en *une*
/// clef. Une clef publique n'est donc jamais « invalide » — elle est seulement
/// bien ou mal formee en longueur, ce que `check_sizes` a deja tranche. Q21 ne
/// doit surtout pas inventer un rejet supplementaire ici : ce serait une regle
/// de consensus que les autres implementations n'auraient pas.
///
/// **`Signature::decode` est faillible**, elle. Elle rejette notamment les
/// signatures dont la norme infinie de `z` depasse `GAMMA1 - BETA`. Une
/// signature mal formee est donc invalide, pas indisponible : on rend
/// `Some(false)` et non `None`.
///
/// **Le contexte est vide.** `Verifier::verify` appelle `ML-DSA.Verify` de FIPS
/// 204 avec `ctx = []`. C'est le ML-DSA « pur ». Q21 lie deja la transaction a
/// son schema via le hachage tague de `pubkey_hash`, et un contexte non vide
/// serait une divergence par rapport a la norme.
#[cfg(feature = "mldsa")]
mod mldsa_backend {
    use super::SchemeId;
    use ml_dsa::{
        signature::Verifier, EncodedVerifyingKey, MlDsa65, MlDsa87, MlDsaParams, Signature,
        VerifyingKey,
    };

    /// Verification generique sur le jeu de parametres.
    ///
    /// `None` signifie « je ne sais pas verifier », `Some(false)` signifie
    /// « j'ai verifie et c'est faux ». Confondre les deux ferait accepter par
    /// defaut ce qu'on n'a pas su lire.
    fn verify_params<P: MlDsaParams>(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Option<bool> {
        // Longueur de clef : deja garantie par check_sizes, mais on ne fait pas
        // reposer la surete d'un decodage sur un appelant.
        let enc = EncodedVerifyingKey::<P>::try_from(pubkey).ok()?;
        let vk = VerifyingKey::<P>::decode(&enc);

        // Signature mal formee => invalide, et non indisponible.
        let Ok(s) = Signature::<P>::try_from(sig) else {
            return Some(false);
        };

        Some(vk.verify(msg, &s).is_ok())
    }

    pub fn verify(scheme: SchemeId, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Option<bool> {
        match scheme {
            SchemeId::MlDsa65 => verify_params::<MlDsa65>(pubkey, msg, sig),
            SchemeId::MlDsa87 => verify_params::<MlDsa87>(pubkey, msg, sig),
            // SPHINCS+ reste a brancher : voir feuille de route.
            SchemeId::SphincsPlus => None,
            SchemeId::LamportOts => None,
        }
    }
}

/// Epreuves de l'implementation reelle de ML-DSA.
///
/// Ces tests ne s'executent qu'avec `--features mldsa`. Ils ne verifient pas
/// « le code compile » : ils verifient que Q21 accepte une signature ML-DSA
/// authentique, en refuse une falsifiee, et que les tailles inscrites dans
/// [`SchemeId`] sont bien celles de FIPS 204.
#[cfg(all(test, feature = "mldsa"))]
mod epreuves_mldsa {
    use super::*;
    use crate::sha256::sha256;
    use ml_dsa::{signature::Keypair, MlDsaParams, Signer, SigningKey, B32};

    /// Graine du couple d'exemple publie par RustCrypto
    /// (`tests/examples/ML-DSA-*-seed.priv`) : les octets 0x00 a 0x1f.
    const GRAINE: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    /// SHA-256 de la clef publique attendue, extraite du fichier PKCS#8
    /// `ML-DSA-65.pub` de RustCrypto (les 1952 derniers octets du DER).
    const SHA_PK_65: &str = "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9";
    /// Idem pour `ML-DSA-87.pub` (les 2592 derniers octets du DER).
    const SHA_PK_87: &str = "91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd";

    fn hex(o: &[u8; 32]) -> String {
        o.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Fabrique un couple (clef publique, signature) authentique.
    fn couple<P: MlDsaParams>(msg: &Hash256) -> (Vec<u8>, Vec<u8>) {
        let sk = SigningKey::<P>::from_seed(&B32::from(GRAINE));
        let vk = sk.verifying_key().encode();
        let sig = sk.sign(msg.as_bytes()).encode();
        (vk[..].to_vec(), sig[..].to_vec())
    }

    /// Le vecteur externe : la clef derivee de la graine doit etre, octet pour
    /// octet, celle du fichier PKCS#8 publie. Si ce test tombe, l'encodage des
    /// clefs de Q21 a diverge de la norme et aucune autre implementation ne
    /// pourra lire nos adresses.
    #[test]
    fn la_clef_derivee_correspond_au_vecteur_externe() {
        let sk65 = SigningKey::<ml_dsa::MlDsa65>::from_seed(&B32::from(GRAINE));
        assert_eq!(hex(&sha256(&sk65.verifying_key().encode()[..])), SHA_PK_65);

        let sk87 = SigningKey::<ml_dsa::MlDsa87>::from_seed(&B32::from(GRAINE));
        assert_eq!(hex(&sha256(&sk87.verifying_key().encode()[..])), SHA_PK_87);
    }

    /// Les tailles de [`SchemeId`] etaient annoncees sans avoir jamais ete
    /// mesurees. Elles le sont ici, sur des objets reels.
    #[test]
    fn les_tailles_reelles_confirment_les_constantes() {
        let m = Hash256::ZERO;
        let (pk, sig) = couple::<ml_dsa::MlDsa65>(&m);
        assert_eq!(pk.len(), SchemeId::MlDsa65.pubkey_len());
        assert_eq!(sig.len(), SchemeId::MlDsa65.sig_len());

        let (pk, sig) = couple::<ml_dsa::MlDsa87>(&m);
        assert_eq!(pk.len(), SchemeId::MlDsa87.pubkey_len());
        assert_eq!(sig.len(), SchemeId::MlDsa87.sig_len());
    }

    #[test]
    fn une_signature_authentique_est_acceptee() {
        let m = tagged_hash("Q21/test", b"paiement");
        for (scheme, (pk, sig)) in [
            (SchemeId::MlDsa65, couple::<ml_dsa::MlDsa65>(&m)),
            (SchemeId::MlDsa87, couple::<ml_dsa::MlDsa87>(&m)),
        ] {
            assert_eq!(verify(scheme, &pk, &m, &sig), Ok(()), "{}", scheme.name());
        }
    }

    /// Un bit change n'importe ou dans la signature doit la rendre invalide —
    /// et invalide, pas « indisponible ».
    #[test]
    fn un_seul_bit_modifie_invalide_la_signature() {
        let m = tagged_hash("Q21/test", b"paiement");
        let (pk, sig) = couple::<ml_dsa::MlDsa65>(&m);

        // Debut, milieu, fin : les trois zones du format (c_tilde, z, h).
        for pos in [0usize, sig.len() / 2, sig.len() - 1] {
            let mut faux = sig.clone();
            faux[pos] ^= 0x01;
            assert_eq!(
                verify(SchemeId::MlDsa65, &pk, &m, &faux),
                Err(VerifyError::SignatureInvalide),
                "octet {pos}"
            );
        }
    }

    #[test]
    fn la_signature_ne_vaut_que_pour_son_message() {
        let m = tagged_hash("Q21/test", b"paiement");
        let autre = tagged_hash("Q21/test", b"paiement.");
        let (pk, sig) = couple::<ml_dsa::MlDsa65>(&m);

        assert_eq!(verify(SchemeId::MlDsa65, &pk, &m, &sig), Ok(()));
        assert_eq!(
            verify(SchemeId::MlDsa65, &pk, &autre, &sig),
            Err(VerifyError::SignatureInvalide)
        );
    }

    #[test]
    fn la_signature_ne_vaut_que_pour_sa_clef() {
        let m = tagged_hash("Q21/test", b"paiement");
        let (pk, sig) = couple::<ml_dsa::MlDsa65>(&m);

        let mut graine = GRAINE;
        graine[0] ^= 0xff;
        let autre_pk = SigningKey::<ml_dsa::MlDsa65>::from_seed(&B32::from(graine))
            .verifying_key()
            .encode()[..]
            .to_vec();
        assert_ne!(pk, autre_pk);

        assert_eq!(
            verify(SchemeId::MlDsa65, &autre_pk, &m, &sig),
            Err(VerifyError::SignatureInvalide)
        );
    }

    /// Les niveaux de securite ne sont pas interchangeables : une signature
    /// ML-DSA-87 presentee comme du ML-DSA-65 est rejetee sur la longueur,
    /// avant tout calcul.
    #[test]
    fn les_niveaux_ne_sont_pas_interchangeables() {
        let m = Hash256::ZERO;
        let (pk87, sig87) = couple::<ml_dsa::MlDsa87>(&m);
        assert!(matches!(
            verify(SchemeId::MlDsa65, &pk87, &m, &sig87),
            Err(VerifyError::LongueurClefInvalide { .. })
        ));
    }

    /// Banc de mesure, exclu des executions ordinaires.
    ///
    /// `cargo test --release --features mldsa -- --ignored --nocapture banc`
    ///
    /// Le chiffre qui compte pour le dimensionnement des blocs : combien de
    /// signatures un noeud peut-il verifier par seconde ? Un bloc de 2 Mio en
    /// ML-DSA-65 contient au plus ~380 temoins ; si la verification coute plus
    /// que le temps de propagation, le reseau se met a orpheliner.
    #[test]
    #[ignore = "banc de mesure, pas une assertion"]
    fn banc_de_verification() {
        let m = tagged_hash("Q21/test", b"banc");
        for (nom, (pk, sig)) in [
            ("ML-DSA-65", couple::<ml_dsa::MlDsa65>(&m)),
            ("ML-DSA-87", couple::<ml_dsa::MlDsa87>(&m)),
        ] {
            let scheme = if nom == "ML-DSA-65" {
                SchemeId::MlDsa65
            } else {
                SchemeId::MlDsa87
            };
            const N: u32 = 2_000;
            let t0 = std::time::Instant::now();
            for _ in 0..N {
                assert_eq!(verify(scheme, &pk, &m, &sig), Ok(()));
            }
            let d = t0.elapsed();
            let par_sec = f64::from(N) / d.as_secs_f64();
            println!(
                "{nom} : {par_sec:.0} verifications/s  ({:.1} us par signature)",
                d.as_secs_f64() * 1e6 / f64::from(N)
            );
        }
    }

    /// Une clef publique quelconque se decode toujours (c'est la norme), mais
    /// aucune signature ne peut alors verifier. Le noeud ne doit ni paniquer
    /// ni accepter.
    #[test]
    fn une_clef_arbitraire_ne_valide_rien() {
        let m = Hash256::ZERO;
        let pk = vec![0xabu8; SchemeId::MlDsa65.pubkey_len()];
        let sig = vec![0xcdu8; SchemeId::MlDsa65.sig_len()];
        assert_eq!(
            verify(SchemeId::MlDsa65, &pk, &m, &sig),
            Err(VerifyError::SignatureInvalide)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_identifiants_de_schema_sont_stables() {
        // Ces valeurs sont consensuelles. Les changer invalide toutes les
        // adresses existantes.
        assert_eq!(SchemeId::MlDsa65.as_u8(), 1);
        assert_eq!(SchemeId::MlDsa87.as_u8(), 2);
        assert_eq!(SchemeId::SphincsPlus.as_u8(), 3);
        assert_eq!(SchemeId::LamportOts.as_u8(), 4);
    }

    #[test]
    fn aller_retour_sur_l_identifiant() {
        for s in SchemeId::ALL {
            assert_eq!(SchemeId::from_u8(s.as_u8()), Some(s));
        }
        assert_eq!(SchemeId::from_u8(0), None);
        assert_eq!(SchemeId::from_u8(5), None);
        assert_eq!(SchemeId::from_u8(255), None);
    }

    /// Le schema par defaut de Q21 est le niveau maximal de la norme.
    ///
    /// Ce n'est pas un detail de confort : c'est le niveau de securite que
    /// portent toutes les adresses emises par le binaire, et il entre dans
    /// l'identifiant du bloc de genese. Le faire glisser sans s'en apercevoir
    /// changerait la chaine.
    #[test]
    fn le_defaut_est_le_niveau_maximal_de_la_norme() {
        use crate::address::Network;
        // Regtest, pas Mainnet : le schema de la genese ne depend pas du
        // reseau, alors que construire la genese du reseau principal demande la
        // table de preuve de travail de deux gibioctets. Un test ne doit jamais
        // payer ce prix pour verifier une constante.
        assert_eq!(
            crate::chain::genesis_block(Network::Regtest).transactions[0].outputs[0].scheme,
            SchemeId::MlDsa87,
            "la genese doit porter ML-DSA-87"
        );
        // Et le niveau maximal est bien celui-la : aucun schema a reseaux
        // euclidiens de rang superieur n'existe dans la norme.
        assert!(SchemeId::MlDsa87 > SchemeId::MlDsa65);
        assert!(SchemeId::MlDsa87.allowed_on(Network::Mainnet));
    }

    /// Les valeurs numeriques des schemas sont consensuelles.
    ///
    /// Elles apparaissent dans chaque adresse et dans chaque temoin. Les
    /// echanger — meme par une reorganisation innocente de l'enumeration —
    /// ferait lire les adresses existantes comme designant un autre schema.
    #[test]
    fn les_identifiants_de_schema_ne_bougent_pas() {
        assert_eq!(SchemeId::MlDsa65 as u8, 1);
        assert_eq!(SchemeId::MlDsa87 as u8, 2);
        assert_eq!(SchemeId::SphincsPlus as u8, 3);
        assert_eq!(SchemeId::LamportOts as u8, 4);
    }

    #[test]
    fn les_tailles_correspondent_a_fips_204() {
        assert_eq!(SchemeId::MlDsa65.pubkey_len(), 1952);
        assert_eq!(SchemeId::MlDsa65.sig_len(), 3309);
        assert_eq!(SchemeId::MlDsa87.pubkey_len(), 2592);
        assert_eq!(SchemeId::MlDsa87.sig_len(), 4627);
    }

    #[test]
    fn le_surcout_face_a_ecdsa_est_bien_celui_annonce() {
        // Le livre blanc annonce un facteur 47. Si ce test tombe, le
        // dimensionnement des blocs de la section 7 est a refaire.
        const ECDSA_SIG: usize = 71;
        let facteur = SchemeId::MlDsa65.sig_len() / ECDSA_SIG;
        assert_eq!(facteur, 46, "facteur reel : {facteur}");
    }

    #[test]
    fn les_mauvaises_tailles_sont_rejetees() {
        let s = SchemeId::MlDsa65;
        let bonne_clef = vec![0u8; s.pubkey_len()];
        let bonne_sig = vec![0u8; s.sig_len()];

        assert!(check_sizes(s, &bonne_clef, &bonne_sig).is_ok());
        assert!(matches!(
            check_sizes(s, &[0u8; 10], &bonne_sig),
            Err(VerifyError::LongueurClefInvalide { .. })
        ));
        assert!(matches!(
            check_sizes(s, &bonne_clef, &[0u8; 10]),
            Err(VerifyError::LongueurSignatureInvalide { .. })
        ));
    }

    #[test]
    fn sans_backend_la_verification_echoue_bruyamment() {
        let s = SchemeId::MlDsa65;
        let r = verify(
            s,
            &vec![0u8; s.pubkey_len()],
            &Hash256::ZERO,
            &vec![0u8; s.sig_len()],
        );
        // Jamais Ok(()) : un noeud ne valide pas ce qu'il n'a pas verifie.
        assert!(r.is_err());
    }

    #[test]
    fn deux_schemas_donnent_deux_empreintes_differentes() {
        let clef = vec![7u8; 100];
        assert_ne!(
            pubkey_hash(SchemeId::MlDsa65, &clef),
            pubkey_hash(SchemeId::MlDsa87, &clef),
            "l'empreinte doit lier la clef a son schema"
        );
    }
}
