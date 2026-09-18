//! Preuve de travail.
//!
//! # Ce que la chaine emploie reellement
//!
//! La preuve de travail de Q21 est [`Q21Pow`] : *memory-hard* a deux niveaux et
//! a table croissante, decrite en detail dans [`crate::memhard`]. C'est elle que
//! la chaine emploie pour valider comme pour miner, et c'est le levier
//! anti-ASIC du projet — celui qui aplatit la courbe d'efficacite entre un
//! processeur ordinaire et du materiel dedie, et donc ce qui decide si Q21 sera
//! minable par des gens ou par des fonderies.
//!
//! [`Sha256Pow`] existe encore, mais ne sert qu'aux epreuves qui n'ont rien a
//! voir avec la memoire — miner deux cents blocs de regression sans construire
//! de table. **Elle n'a aucune propriete anti-ASIC et n'est branchee sur aucune
//! chaine.**
//!
//! Cette note disait l'inverse jusqu'ici : elle presentait ce fichier comme un
//! echafaudage fournissant « en attendant » une preuve SHA-256, et avertissait
//! qu'un deploiement reproduirait la centralisation industrielle que le projet
//! combat. C'etait vrai avant que [`crate::memhard`] existe ; ce ne l'est plus
//! depuis. Une documentation qui decrit le contraire du code est pire qu'une
//! documentation absente — surtout sur la propriete dont depend la philosophie
//! du projet, et que tout lecteur du depot vient verifier ici en premier.
//!
//! # Ce que le decoupage par [`PowEngine`] apporte encore
//!
//! Le trait ne porte que le condensat ; la comparaison a la cible est commune a
//! tous ses implementeurs. Il n'existe donc qu'une seule regle de validite du
//! travail, et changer d'algorithme ne peut pas la faire deriver. C'est ce qui
//! permet a [`Q21PowAvecCache`] d'accelerer la verification d'une chaine
//! entiere sans reecrire cette regle.
//!
//! # Cible compacte
//!
//! Le champ `bits` de l'en-tete encode une cible de 256 bits sur 32 bits, dans
//! le format de Bitcoin : un octet d'exposant, trois octets de mantisse.
//! `cible = mantisse * 256^(exposant - 3)`. Le format admet un bit de signe
//! herite d'un choix malheureux de 2009 ; on le refuse explicitement plutot que
//! de le trainer.

use crate::block::BlockHeader;
use crate::hash::{tagged_hash, Hash256};
use crate::uint::U256;

/// Etiquette de domaine de la preuve de travail.
///
/// Distincte de celle de l'identifiant de bloc : confondre l'identifiant d'un
/// bloc et la valeur comparee a la cible est une erreur de conception classique.
pub const TAG_POW: &str = "Q21/pow/sha256-provisoire";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PowError {
    /// Mantisse negative : le format compact herite d'un bit de signe inutile.
    CibleNegative,
    CibleNulle,
    CibleTropGrande,
    /// Cible plus facile que le plancher de difficulte ([`INITIAL_BITS`]).
    ///
    /// Un en-tete peut annoncer une cible aussi grande qu'il veut ; sans borne,
    /// il suffirait d'annoncer une cible proche de 2^256 pour qu'un condensat
    /// quelconque passe avec un travail derisoire — « des en-tetes valides a
    /// l'infini sans miner ». La borne vivait jusqu'ici uniquement dans
    /// `chain.rs` (l'egalite `header.bits == next_bits(parent)`, qui plafonne a
    /// `INITIAL_BITS`). La fonction de travail elle-meme acceptait n'importe
    /// quelle cible. Un futur appelant de `check` — un validateur d'en-tetes
    /// avant les corps, par exemple — qui oublierait la borne la reintroduirait.
    /// On la met donc dans le calcul qu'elle protege, pas dans ses appelants.
    /// Trouve par la red-team de phase 8b.
    CibleTropFacile,
    TravailInsuffisant,
}

/// La cible la plus grande — la difficulte la plus faible — qu'un en-tete valide
/// puisse porter, derivee du plancher [`crate::consensus::INITIAL_BITS`].
///
/// Fonction, et non constante, parce que `target_from_compact` n'est pas `const`.
/// Le decodage de `INITIAL_BITS` ne peut pas echouer : c'est une cible compacte
/// bien formee, verifiee par une epreuve.
pub fn cible_plancher() -> U256 {
    target_from_compact(crate::consensus::INITIAL_BITS)
        .expect("INITIAL_BITS est une cible compacte valide")
}

/// Decode une cible compacte vers sa valeur 256 bits.
pub fn target_from_compact(bits: u32) -> Result<U256, PowError> {
    let exposant = bits >> 24;
    let mantisse = bits & 0x007f_ffff;

    if bits & 0x0080_0000 != 0 {
        return Err(PowError::CibleNegative);
    }
    if mantisse == 0 {
        return Err(PowError::CibleNulle);
    }

    let cible = if exposant <= 3 {
        U256::from_u64((mantisse >> (8 * (3 - exposant))) as u64)
    } else {
        let mut v = U256::from_u64(mantisse as u64);
        for _ in 0..(exposant - 3) {
            v = v.checked_mul_u64(256).ok_or(PowError::CibleTropGrande)?;
        }
        v
    };

    if cible.is_zero() {
        return Err(PowError::CibleNulle);
    }
    Ok(cible)
}

/// Encode une cible 256 bits vers sa forme compacte.
pub fn target_to_compact(cible: U256) -> u32 {
    if cible.is_zero() {
        return 0;
    }
    let octets = cible.to_be_bytes();
    let mut exposant = (cible.bits() as usize).div_ceil(8);

    // Les trois octets de poids fort de la valeur forment la mantisse.
    let debut = 32 - exposant;
    let mut mantisse: u32 = if exposant <= 3 {
        let mut v: u32 = 0;
        for o in &octets[debut..32] {
            v = (v << 8) | *o as u32;
        }
        v << (8 * (3 - exposant))
    } else {
        ((octets[debut] as u32) << 16)
            | ((octets[debut + 1] as u32) << 8)
            | octets[debut + 2] as u32
    };

    // Le bit de poids fort de la mantisse serait lu comme un signe.
    if mantisse & 0x0080_0000 != 0 {
        mantisse >>= 8;
        exposant += 1;
    }
    ((exposant as u32) << 24) | mantisse
}

/// Interface d'un algorithme de preuve de travail.
///
/// La phase 3 fournira une implementation memory-hard a table croissante. Le
/// parametre `height` est deja present parce que la taille de table en dependra.
pub trait PowEngine {
    fn hash(&self, header: &BlockHeader) -> Hash256;

    fn check(&self, header: &BlockHeader) -> Result<(), PowError> {
        let cible = target_from_compact(header.bits)?;
        // Plancher de difficulte, applique DANS la fonction de travail : une
        // cible plus facile que le plancher est refusee ici, et pas seulement
        // par l'egalite de bits que pose `chain.rs`. Voir `CibleTropFacile`.
        if cible > cible_plancher() {
            return Err(PowError::CibleTropFacile);
        }
        let valeur = U256::from_be_bytes(self.hash(header).as_bytes());
        if valeur > cible {
            return Err(PowError::TravailInsuffisant);
        }
        Ok(())
    }
}

/// Preuve de travail provisoire, SHA-256. Aucune propriete anti-ASIC.
///
/// Conservee pour les tests qui n'ont rien a voir avec la memoire, et pour
/// documenter par contraste ce que [`Q21Pow`] apporte.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sha256Pow;

impl PowEngine for Sha256Pow {
    fn hash(&self, header: &BlockHeader) -> Hash256 {
        tagged_hash(TAG_POW, &header.encode())
    }
}

/// Preuve de travail de Q21 : memory-hard a deux niveaux, table croissante.
///
/// Le chemin emprunte ici est celui de la **verification** : il recalcule les
/// `POW_K` elements necessaires a partir du cache, sans jamais materialiser la
/// table. Un noeud complet detient donc le cache (64 Mio sur le reseau
/// principal) et non les 2 Gio qu'exige un mineur. Voir [`crate::memhard`] pour
/// le detail, pour la mesure qui a impose cette structure a deux niveaux, et
/// pour l'avertissement sur l'absence de cryptanalyse externe.
#[derive(Clone, Copy, Debug)]
pub struct Q21Pow {
    params: crate::memhard::TableParams,
}

impl Q21Pow {
    pub const fn new(network: crate::address::Network) -> Q21Pow {
        Q21Pow {
            params: crate::memhard::TableParams::for_network(network),
        }
    }

    pub const fn params(&self) -> crate::memhard::TableParams {
        self.params
    }
}

impl PowEngine for Q21Pow {
    fn hash(&self, header: &BlockHeader) -> Hash256 {
        crate::memhard::hash_verify(header, self.params)
    }
}

/// Verification employant un cache d'epoque **deja construit**.
///
/// # Pourquoi ce moteur existe
///
/// [`Q21Pow`] passe par le registre global des caches a chaque en-tete : un
/// verrou, puis une recherche. C'est sans consequence pour un bloc isole, mais
/// une adoption d'amorce verifie toute une chaine — des centaines de milliers
/// d'en-tetes — et le fait en parallele. Ce registre deviendrait alors le
/// goulot : un verrou pris des millions de fois, que tous les fils se
/// disputeraient.
///
/// Ce moteur emprunte le cache par reference. Il ne redefinit **que** le
/// condensat : la comparaison a la cible reste celle du trait, donc il n'existe
/// toujours qu'une seule regle de validite du travail, impossible a faire
/// diverger.
pub struct Q21PowAvecCache<'a> {
    params: crate::memhard::TableParams,
    cache: &'a crate::memhard::PowCache,
}

impl<'a> Q21PowAvecCache<'a> {
    pub fn new(
        params: crate::memhard::TableParams,
        cache: &'a crate::memhard::PowCache,
    ) -> Q21PowAvecCache<'a> {
        Q21PowAvecCache { params, cache }
    }
}

impl PowEngine for Q21PowAvecCache<'_> {
    fn hash(&self, header: &BlockHeader) -> Hash256 {
        crate::memhard::hash_verify_avec_cache(header, self.params, self.cache)
    }
}

/// Minage avec table precalculee.
///
/// C'est le chemin du mineur. Recalculer les elements a chaque nonce, comme le
/// fait [`mine`], serait correct mais absurdement lent — c'est precisement ce
/// que la conception cherche a rendre couteux.
pub fn mine_with_table(
    header: &mut BlockHeader,
    table: &crate::memhard::PowTable,
    max_essais: u64,
) -> Result<u64, u64> {
    let cible = match target_from_compact(header.bits) {
        Ok(c) => c,
        Err(_) => return Err(0),
    };
    for essai in 0..max_essais {
        let valeur = U256::from_be_bytes(crate::memhard::hash_mining(header, table).as_bytes());
        if valeur <= cible {
            return Ok(essai);
        }
        header.nonce = header.nonce.wrapping_add(1);
    }
    Err(max_essais)
}

/// Nombre d'essais explores par fil avant de faire le point.
///
/// Compromis : trop court, on paie la creation des fils ; trop long, on
/// explore inutilement au-dela du gagnant. Cinq cents essais representent
/// quelques millisecondes de travail sur la table du reseau principal.
const LOT_PAR_FIL: u64 = 512;

/// Minage reparti sur plusieurs fils, **a resultat identique au minage
/// sequentiel**.
///
/// # Pourquoi ce n'est pas un detail de confort
///
/// Le mineur de reference etait mono-fil. Sur une machine a huit coeurs, cela
/// signifie que quiconque prend la peine d'ecrire un mineur parallele obtient
/// huit fois le debit des gens ordinaires — pour un travail d'apres-midi. Un
/// projet dont la raison d'etre est que le minage reste accessible ne peut pas
/// livrer un mineur qui laisse sept huitiemes de la machine inutilises.
///
/// # Pourquoi le resultat reste deterministe
///
/// Un mineur parallele naif rend le premier nonce trouve, qui depend de
/// l'ordonnancement : deux executions produisent deux blocs differents. Ici, la
/// recherche avance par **vagues** : les fils balaient ensemble un intervalle
/// contigu de nonces, on attend la fin de la vague, et l'on retient le **plus
/// petit** nonce gagnant. Le resultat est exactement celui qu'aurait trouve une
/// boucle sequentielle, quel que soit le nombre de fils. C'est ce qui permet
/// aux epreuves de comparer deux chaines minees independamment.
pub fn mine_with_table_parallel(
    header: &mut BlockHeader,
    table: &std::sync::Arc<crate::memhard::PowTable>,
    max_essais: u64,
    fils: usize,
) -> Result<u64, u64> {
    let fils = fils.max(1);
    if fils == 1 {
        return mine_with_table(header, table, max_essais);
    }
    let cible = match target_from_compact(header.bits) {
        Ok(c) => c,
        Err(_) => return Err(0),
    };

    // Sonde sequentielle : la plupart des blocs de reseau de test tombent en
    // quelques centaines d'essais, et creer des fils pour cela couterait plus
    // que le calcul lui-meme.
    let depart = header.nonce;
    let sonde = LOT_PAR_FIL.min(max_essais);
    for essai in 0..sonde {
        let valeur = U256::from_be_bytes(crate::memhard::hash_mining(header, table).as_bytes());
        if valeur <= cible {
            return Ok(essai);
        }
        header.nonce = header.nonce.wrapping_add(1);
    }

    let mut faits = sonde;
    while faits < max_essais {
        let par_fil = LOT_PAR_FIL
            .min((max_essais - faits).div_ceil(fils as u64))
            .max(1);
        let base = depart.wrapping_add(faits);

        let gagnant = std::thread::scope(|s| {
            let mut poignees = Vec::with_capacity(fils);
            for f in 0..fils as u64 {
                let table = std::sync::Arc::clone(table);
                let mut h = *header;
                poignees.push(s.spawn(move || {
                    let debut = base.wrapping_add(f * par_fil);
                    for k in 0..par_fil {
                        h.nonce = debut.wrapping_add(k);
                        let v =
                            U256::from_be_bytes(crate::memhard::hash_mining(&h, &table).as_bytes());
                        if v <= cible {
                            return Some(faits + f * par_fil + k);
                        }
                    }
                    None
                }));
            }
            poignees
                .into_iter()
                .filter_map(|p| p.join().ok().flatten())
                .min()
        });

        if let Some(essai) = gagnant {
            header.nonce = depart.wrapping_add(essai);
            return Ok(essai);
        }
        faits += par_fil * fils as u64;
    }

    header.nonce = depart.wrapping_add(max_essais);
    Err(max_essais)
}

// ---------------------------------------------------------------------------
// Travail
// ---------------------------------------------------------------------------

/// Travail attendu pour trouver un bloc a la cible donnee.
///
/// Vaut `2^256 / (cible + 1)`, soit l'esperance du nombre de tentatives. Comme
/// `2^256` ne tient pas dans un U256, on calcule `(~cible) / (cible + 1) + 1`,
/// qui donne exactement la meme valeur — c'est l'astuce de Bitcoin, et elle est
/// exacte, pas approchee.
///
/// # Pourquoi cette fonction decide de tout
///
/// Comparer deux chaines par leur **longueur** est un bug de conception : un
/// attaquant peut produire une chaine plus longue a difficulte basse. La seule
/// mesure honnete est le travail cumule, et c'est celle qu'utilise
/// [`crate::chain`] pour choisir entre deux fourches.
pub fn block_work(bits: u32) -> U256 {
    let cible = match target_from_compact(bits) {
        Ok(c) => c,
        // Une cible invalide ne vaut aucun travail.
        Err(_) => return U256::ZERO,
    };
    let denom = match cible.checked_add(U256::ONE) {
        Some(d) => d,
        None => return U256::ONE,
    };
    match cible.not().div_rem(denom) {
        Some((q, _)) => q.checked_add(U256::ONE).unwrap_or(q),
        None => U256::ZERO,
    }
}

/// Cherche un nonce satisfaisant la cible, dans la limite de `max_essais`.
///
/// Mono-fil et volontairement simple : le mineur serieux viendra avec la
/// phase 3. Rend le nombre d'essais consommes en cas d'echec.
pub fn mine<E: PowEngine>(
    engine: &E,
    header: &mut BlockHeader,
    max_essais: u64,
) -> Result<u64, u64> {
    let cible = match target_from_compact(header.bits) {
        Ok(c) => c,
        Err(_) => return Err(0),
    };
    for essai in 0..max_essais {
        let valeur = U256::from_be_bytes(engine.hash(header).as_bytes());
        if valeur <= cible {
            return Ok(essai);
        }
        header.nonce = header.nonce.wrapping_add(1);
    }
    Err(max_essais)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entete(bits: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            uncles_root: Hash256::ZERO,
            miner: Hash256([9u8; 32]),
            time: 1_755_000_000,
            bits,
            height: 1,
            nonce: 0,
        }
    }

    /// La propriete qui rend le mineur parallele acceptable : il doit trouver
    /// **exactement** le meme nonce qu'une boucle sequentielle, quel que soit le
    /// nombre de fils. Sans cela, deux noeuds partant du meme candidat
    /// produiraient deux blocs differents, et aucune epreuve ne pourrait plus
    /// comparer deux chaines minees independamment.
    #[test]
    fn le_minage_parallele_donne_le_meme_nonce_que_le_sequentiel() {
        use crate::address::Network;
        use crate::memhard::{PowTable, TableParams};

        let params = TableParams::for_network(Network::Regtest);
        let table = std::sync::Arc::new(PowTable::build(params, 0));

        // Une cible plus exigeante que celle du reseau de test, pour que la
        // recherche depasse la sonde sequentielle initiale et entre reellement
        // dans les vagues paralleles.
        let mut reference = None;
        for fils in [1usize, 2, 3, 5, 8] {
            let mut h = entete(0x2000_00ff);
            let essai = mine_with_table_parallel(&mut h, &table, 5_000_000, fils)
                .expect("un nonce doit exister");
            match reference {
                None => reference = Some((essai, h.nonce)),
                Some(r) => assert_eq!(
                    (essai, h.nonce),
                    r,
                    "{fils} fils ont trouve un autre nonce que le calcul sequentiel"
                ),
            }
            assert!(Q21Pow::new(Network::Regtest).check(&h).is_ok());
        }
    }

    /// Un echec doit rester un echec, quel que soit le nombre de fils.
    #[test]
    fn un_budget_epuise_echoue_pareil_en_parallele() {
        use crate::address::Network;
        use crate::memhard::{PowTable, TableParams};

        let params = TableParams::for_network(Network::Regtest);
        let table = std::sync::Arc::new(PowTable::build(params, 0));
        // Cible impossible a atteindre en si peu d'essais.
        for fils in [1usize, 4] {
            let mut h = entete(0x1d00_0001);
            assert!(mine_with_table_parallel(&mut h, &table, 2_000, fils).is_err());
        }
    }

    /// Banc de mesure du gain reel. Exclu des executions ordinaires.
    ///
    /// `cargo test --release -- --ignored --nocapture banc_de_minage`
    #[test]
    #[ignore = "banc de mesure, pas une assertion"]
    fn banc_de_minage_parallele() {
        use crate::address::Network;
        use crate::memhard::{PowTable, TableParams};

        let params = TableParams::for_network(Network::Testnet);
        let table = std::sync::Arc::new(PowTable::build(params, 0));
        let coeurs = std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(1);

        println!("coeurs disponibles : {coeurs}");
        let mut reference = 0.0f64;
        for fils in 1..=coeurs {
            let mut h = entete(0x2000_000f);
            let t0 = std::time::Instant::now();
            let essais = mine_with_table_parallel(&mut h, &table, 50_000_000, fils)
                .expect("un nonce doit exister");
            let d = t0.elapsed().as_secs_f64();
            let debit = essais as f64 / d.max(1e-9);
            if fils == 1 {
                reference = debit;
            }
            println!(
                "{fils} fil(s) : {debit:>10.0} tentatives/s   acceleration {:.2} x   nonce {}",
                debit / reference.max(1e-9),
                h.nonce
            );
        }
    }

    #[test]
    fn decodage_de_cibles_connues() {
        // Cible la plus facile de Bitcoin : mantisse 0xffff, exposant 0x1d.
        // Valeur canonique :
        // 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        let c = target_from_compact(0x1d00_ffff).unwrap();
        let b = c.to_be_bytes();
        assert_eq!(b[0..4], [0x00; 4]);
        assert_eq!(b[4..6], [0xff, 0xff]);
        assert_eq!(b[6..], [0u8; 26]);
    }

    #[test]
    fn une_cible_negative_est_refusee() {
        assert_eq!(
            target_from_compact(0x0180_0000),
            Err(PowError::CibleNegative)
        );
    }

    #[test]
    fn une_cible_nulle_est_refusee() {
        assert_eq!(target_from_compact(0x1d00_0000), Err(PowError::CibleNulle));
    }

    #[test]
    fn aller_retour_sur_l_encodage_compact() {
        for bits in [0x1d00_ffff_u32, 0x1c00_ffff, 0x2000_ffff, 0x0300_ffff] {
            let c = target_from_compact(bits).unwrap();
            let refait = target_to_compact(c);
            let c2 = target_from_compact(refait).unwrap();
            assert_eq!(c, c2, "aller-retour instable pour {bits:#x}");
        }
    }

    #[test]
    fn une_cible_plus_petite_est_plus_difficile() {
        let facile = target_from_compact(0x2000_ffff).unwrap();
        let dur = target_from_compact(0x1000_ffff).unwrap();
        assert!(dur < facile);
    }

    #[test]
    fn le_minage_trouve_un_nonce_pour_une_cible_facile() {
        let moteur = Sha256Pow;
        // La cible la plus facile ADMISE : le plancher lui-meme. Une sur ~256
        // tentatives passe, donc quelques centaines d'essais suffisent — et,
        // contrairement a l'ancienne `0x2100_ffff`, cette cible est dans les
        // bornes du consensus (voir `cible_plancher` et `CibleTropFacile`).
        let mut h = entete(crate::consensus::INITIAL_BITS);
        let essais = mine(&moteur, &mut h, 100_000).expect("aucun nonce trouve");
        assert!(moteur.check(&h).is_ok(), "le bloc mine ne valide pas");
        assert!(essais < 100_000);
    }

    /// ATTAQUE (red-team 8b) : un en-tete qui annonce une cible plus facile que
    /// le plancher passait `check` avec un nonce nul et un travail derisoire,
    /// tant qu'aucun appelant ne verifiait la borne au dehors. `check` doit
    /// desormais le refuser lui-meme.
    #[test]
    fn une_cible_plus_facile_que_le_plancher_est_refusee_par_check() {
        let moteur = Sha256Pow;
        // 0x2100_7fff : exposant 0x21, cible ~2^255, tres au-dessus du plancher
        // ~2^248. Le decodage reussit (pas de debordement), donc seule la borne
        // l'arrete. Nonce nul : aucun travail.
        let h = entete(0x2100_7fff);
        assert!(
            target_from_compact(h.bits).is_ok(),
            "la cible se decode : ce n'est pas un debordement qui l'arrete"
        );
        assert_eq!(
            moteur.check(&h),
            Err(PowError::CibleTropFacile),
            "une cible sous le plancher doit etre refusee DANS la fonction de travail"
        );
    }

    #[test]
    fn un_bloc_non_mine_echoue_a_la_verification() {
        let moteur = Sha256Pow;
        // Cible tres exigeante : le nonce nul ne peut pas convenir.
        let h = entete(0x0300_0001);
        assert_eq!(moteur.check(&h), Err(PowError::TravailInsuffisant));
    }

    #[test]
    fn changer_le_nonce_change_le_condensat() {
        let moteur = Sha256Pow;
        let a = entete(0x2000_ffff);
        let mut b = a;
        b.nonce = 1;
        assert_ne!(moteur.hash(&a), moteur.hash(&b));
    }

    #[test]
    fn le_condensat_de_travail_differe_de_l_identifiant_de_bloc() {
        let h = entete(0x2000_ffff);
        assert_ne!(
            Sha256Pow.hash(&h),
            h.block_id(),
            "confondre les deux est une erreur de conception"
        );
    }

    #[test]
    fn le_minage_abandonne_proprement() {
        let moteur = Sha256Pow;
        let mut h = entete(0x0300_0001);
        assert_eq!(mine(&moteur, &mut h, 50), Err(50));
    }
}
