//! Entropie du systeme. La brique dont depend tout le reste.
//!
//! # Pourquoi ce module existe
//!
//! Une clef privee ne vaut que son alea. Un portefeuille dont la graine est
//! previsible est un portefeuille vide : peu importe que la signature soit
//! post-quantique, que la preuve de travail soit memory-hard, que le plafond
//! soit inviolable. C'est le maillon le plus court de la chaine, et c'est celui
//! qu'on regarde le moins.
//!
//! # Ce que la phase 8 a corrige
//!
//! La version precedente faisait :
//!
//! ```text
//! std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?
//! ```
//!
//! Deux defauts, l'un fonctionnel et l'autre de conception.
//!
//! **Fonctionnel** : `/dev/urandom` n'existe pas sous Windows. `q21 init` y
//! echouait purement et simplement. Un logiciel de portefeuille qui ne demarre
//! pas sur le systeme le plus repandu n'est pas un logiciel de portefeuille.
//!
//! **De conception** : aucune verification de ce qui sortait. Un peripherique
//! rendant des zeros — machine virtuelle mal configuree, conteneur exotique,
//! disque monte en lecture seule — aurait produit une graine nulle sans que
//! personne ne s'en apercoive avant d'avoir perdu ses fonds.
//!
//! # Ce que ce module ne fait pas, et c'est deliberé
//!
//! Il ne **melange** rien. Pas d'horloge, pas d'identifiant de processus, pas
//! d'adresses memoire ajoutees « pour faire bonne mesure ». Melanger une source
//! forte a des sources faibles ne renforce rien et masque la panne : si le
//! generateur du systeme est casse, il faut le savoir et s'arreter, pas
//! fabriquer une illusion d'alea avec une horloge.
//!
//! La regle est donc : **on obtient de l'entropie du systeme, ou on echoue.**

use std::fmt;

#[derive(Debug)]
pub enum RngError {
    /// Le generateur du systeme est inaccessible.
    Indisponible(String),
    /// Le generateur a rendu quelque chose d'invraisemblable.
    SortieSuspecte(&'static str),
}

impl fmt::Display for RngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RngError::Indisponible(d) => write!(
                f,
                "generateur d'alea du systeme inaccessible : {d}\n  \
                 Aucune clef ne sera creee : mieux vaut aucun portefeuille \
                 qu'un portefeuille previsible."
            ),
            RngError::SortieSuspecte(d) => write!(
                f,
                "le generateur d'alea du systeme a rendu une sortie suspecte ({d}).\n  \
                 Creation interrompue."
            ),
        }
    }
}

impl std::error::Error for RngError {}

/// Remplit `sortie` avec de l'alea cryptographique du systeme.
///
/// # Erreurs
///
/// Echoue plutot que de rendre un alea de qualite inconnue. Aucun repli n'est
/// prevu, et c'est le point important de ce module.
pub fn remplir(sortie: &mut [u8]) -> Result<(), RngError> {
    imp::remplir(sortie)?;
    verifier(sortie)
}

/// Tire `N` octets d'alea du systeme.
pub fn octets<const N: usize>() -> Result<[u8; N], RngError> {
    let mut b = [0u8; N];
    remplir(&mut b)?;
    Ok(b)
}

/// Controles de vraisemblance sur la sortie du generateur.
///
/// Ces controles ne prouvent rien sur la qualite cryptographique — aucun test
/// statistique ne le peut sur 32 octets. Ils attrapent les pannes franches :
/// peripherique qui rend des zeros, tampon jamais ecrit, valeur constante.
/// C'est peu, et c'est infiniment mieux que rien.
fn verifier(b: &[u8]) -> Result<(), RngError> {
    if b.len() < 8 {
        return Ok(());
    }
    if b.iter().all(|&x| x == 0) {
        return Err(RngError::SortieSuspecte("tous les octets sont nuls"));
    }
    if b.iter().all(|&x| x == b[0]) {
        return Err(RngError::SortieSuspecte("tous les octets sont identiques"));
    }
    // Sur 32 octets tires uniformement, voir moins de 8 valeurs distinctes a une
    // probabilite ecrasante d'etre une panne, pas un hasard malchanceux.
    let mut vus = [false; 256];
    let mut distincts = 0usize;
    for &x in b {
        if !vus[x as usize] {
            vus[x as usize] = true;
            distincts += 1;
        }
    }
    if b.len() >= 32 && distincts < 8 {
        return Err(RngError::SortieSuspecte("trop peu de valeurs distinctes"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unix : /dev/urandom
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod imp {
    use super::RngError;
    use std::io::Read;

    pub fn remplir(sortie: &mut [u8]) -> Result<(), RngError> {
        // `/dev/urandom` et non `/dev/random` : depuis Linux 4.8 les deux
        // partagent le meme generateur, et `/dev/random` peut bloquer
        // indefiniment sans rien apporter.
        let mut f = std::fs::File::open("/dev/urandom")
            .map_err(|e| RngError::Indisponible(format!("/dev/urandom : {e}")))?;
        f.read_exact(sortie)
            .map_err(|e| RngError::Indisponible(format!("/dev/urandom : {e}")))
    }
}

// ---------------------------------------------------------------------------
// Windows : BCryptGenRandom
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use super::RngError;

    // Interface officielle du generateur de Windows, exposee par bcrypt.dll.
    // C'est celle que recommande Microsoft depuis Vista, et celle qu'utilise
    // l'ecosysteme Rust. On la declare a la main plutot que de dependre d'un
    // crate : le noyau de Q21 n'a aucune dependance obligatoire.
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }

    /// Demande a Windows d'utiliser son generateur systeme sans qu'on ait a lui
    /// ouvrir un fournisseur d'algorithme.
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    pub fn remplir(sortie: &mut [u8]) -> Result<(), RngError> {
        // `BCryptGenRandom` prend une longueur sur 32 bits : on decoupe, ce qui
        // ne se produira jamais en pratique pour une graine de 32 octets mais
        // evite une troncature silencieuse si ce module sert un jour a autre
        // chose.
        for morceau in sortie.chunks_mut(u32::MAX as usize) {
            // SAFETY : `morceau` est une tranche valide et exclusive, sa
            // longueur tient sur 32 bits par construction du `chunks_mut`, et
            // l'API n'ecrit que dans ce tampon.
            let statut = unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    morceau.as_mut_ptr(),
                    morceau.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if statut != 0 {
                return Err(RngError::Indisponible(format!(
                    "BCryptGenRandom a rendu le statut 0x{statut:08x}"
                )));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tout le reste : on refuse plutot que d'inventer
// ---------------------------------------------------------------------------

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::RngError;

    pub fn remplir(_sortie: &mut [u8]) -> Result<(), RngError> {
        Err(RngError::Indisponible(
            "aucune source d'entropie connue sur cette plateforme".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_systeme_fournit_de_l_alea() {
        let a: [u8; 32] = octets().expect("le systeme doit fournir de l'entropie");
        assert!(!a.iter().all(|&x| x == 0));
    }

    /// Deux tirages successifs identiques signifieraient un generateur casse.
    /// La probabilite d'une collision honnete sur 32 octets est de 2^-256.
    #[test]
    fn deux_tirages_different() {
        let a: [u8; 32] = octets().unwrap();
        let b: [u8; 32] = octets().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn les_sorties_degenerees_sont_refusees() {
        assert!(matches!(
            verifier(&[0u8; 32]),
            Err(RngError::SortieSuspecte(_))
        ));
        assert!(matches!(
            verifier(&[0x42u8; 32]),
            Err(RngError::SortieSuspecte(_))
        ));
        // Deux valeurs distinctes seulement : toujours suspect.
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = if i % 2 == 0 { 1 } else { 2 };
        }
        assert!(matches!(verifier(&b), Err(RngError::SortieSuspecte(_))));
    }

    #[test]
    fn une_sortie_normale_passe() {
        let a: [u8; 32] = octets().unwrap();
        assert!(verifier(&a).is_ok());
    }

    /// Un tirage de longueur quelconque doit rester correct.
    #[test]
    fn les_longueurs_inhabituelles_fonctionnent() {
        for n in [1usize, 7, 33, 100, 1024] {
            let mut v = vec![0u8; n];
            remplir(&mut v).unwrap();
        }
    }

    /// Mesure grossiere de l'uniformite : sur 4096 octets, chaque bit doit
    /// tomber a un environ une fois sur deux. Ce test n'atteste rien sur la
    /// cryptographie ; il attrape un generateur franchement biaise.
    #[test]
    fn la_sortie_n_est_pas_grossierement_biaisee() {
        let mut v = vec![0u8; 4096];
        remplir(&mut v).unwrap();
        let uns: u32 = v.iter().map(|b| b.count_ones()).sum();
        let total = (v.len() * 8) as u32;
        let ecart = (uns as i64 - (total / 2) as i64).unsigned_abs();
        assert!(
            ecart < total as u64 / 20,
            "{uns} bits a un sur {total} : biais anormal"
        );
    }
}
