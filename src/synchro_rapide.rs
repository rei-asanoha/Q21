//! Amorce de synchronisation rapide : le paquet qu'un pair transmet a un nouveau
//! venu pour lui epargner de tout revalider.
//!
//! # Le mot « amorce », deux sens
//!
//! Le module [`crate::amorce`] traite de l'amorcage au sens *par ou l'on entre
//! dans un reseau* — les premiers pairs a qui parler. Ici, « amorce » designe le
//! **paquet de synchronisation rapide** : l'etat tout fait qu'un pair transmet
//! pour eviter au nouveau venu de revalider toute l'histoire. Les deux partagent
//! le mot parce que l'utilisateur les a nommes ainsi ; ils ne partagent rien
//! d'autre.
//!
//! # Ce qu'elle contient
//!
//! Les trois memes pieces que l'amorce sur fichier (`q21 instantane
//! exporter-amorce`), reunies en un seul flux d'octets pour voyager sur le
//! reseau :
//!
//! - l'**instantane portable** — le jeu d'UTXO a une hauteur H, avec son
//!   empreinte ;
//! - les **en-tetes** de la genese a H — la chaine d'en-tetes qu'un noeud adopte
//!   ne peut pas reconstruire, faute des corps d'avant H ;
//! - une **fenetre bornee de corps** autour de H — la genese, puis les quelques
//!   blocs qui precedent H, dont la regle du double paiement d'oncle a besoin au
//!   rejeu.
//!
//! # Ce qu'elle n'est pas
//!
//! Elle ne porte pas sa propre confiance. Celui qui la recoit **doit** confronter
//! son empreinte a une valeur sure — celle qu'il tient d'un explorateur, passee
//! en ligne de commande. Un pair qui envoie une amorce est une source de
//! commodite, jamais d'autorite : voir [`crate::chain::Chain::adopter_instantane`].
//!
//! # Le transport
//!
//! Un instantane peut depasser la taille maximale d'un message ([`crate::wire`]).
//! L'amorce voyage donc **par tranches** : elle est serialisee une fois, puis
//! decoupee en morceaux transmis independamment et reassembles a l'arrivee. Ce
//! module definit le paquet et son (de)codage ; le decoupage et l'echange
//! relevent de la couche reseau.

use crate::address::Network;
use crate::block::{Block, BlockHeader};
use crate::hash::Hash256;
use crate::ser::{ReadError, Reader, Writer};
use crate::wire::{Message, WireError, HEADER_LEN, MAX_PAYLOAD, PROTOCOL_VERSION};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAGIE: &[u8; 8] = b"Q21AMORC";
const VERSION: u32 = 1;

/// Taille d'une tranche de transfert.
///
/// Sous la taille maximale d'un message (8 Mio) et sous le budget de reponse du
/// noeud (4 Mio) : une tranche qui ne tiendrait pas dans un message serait un
/// gaspillage a sens unique.
pub const TAILLE_TRANCHE: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Ancrages compiles dans le binaire
// ---------------------------------------------------------------------------

/// Un point de la chaine tenu pour vrai, **inscrit dans le binaire lui-meme**.
///
/// # Pourquoi cela existe
///
/// L'adoption d'une amorce s'appuie sur une tete et une empreinte que
/// l'operateur recopie depuis une source qu'il croit sure. C'est un maillon
/// humain : un explorateur usurpe, une interception, un miroir malveillant ou
/// une simple faute de frappe suffisent a le rompre. La reverification du
/// travail rend deja l'attaque couteuse — il faut refaire le travail de toute la
/// chaine — mais elle ne la rend pas impossible a qui detiendrait beaucoup de
/// puissance.
///
/// Un ancrage compile ferme cette porte pour de bon, aux hauteurs qu'il couvre :
/// la valeur ne vient plus d'un site web, elle vient du **logiciel que
/// l'utilisateur execute deja**, relu par quiconque lit le depot. C'est la
/// reponse de Bitcoin a la meme question, et elle est fidele a la philosophie de
/// Q21 : ce n'est pas une autorite qui tranche, c'est une valeur publique que
/// tout le monde peut verifier et contester avant qu'elle ne soit publiee.
///
/// # Comment en ajouter un
///
/// 1. Sur un noeud complet **dont on a soi-meme valide toute la chaine** :
///    `q21 instantane exporter-amorce <dossier> --reseau <nom>` affiche la
///    hauteur, la tete et l'empreinte.
/// 2. Faire confirmer ces trois valeurs par plusieurs personnes, sur des noeuds
///    independants. Un ancrage qu'une seule personne a vu ne vaut pas mieux que
///    la parole de cette personne.
/// 3. Les inscrire ici, dans la table du reseau concerne, et publier le
///    changement pour relecture.
///
/// Un ancrage n'est jamais retire ni modifie : il decrit un fait passe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ancrage {
    pub hauteur: u64,
    pub tete: Hash256,
    pub empreinte: Hash256,
}

/// Les ancrages connus du reseau, par ordre de hauteur croissante.
///
/// Les tables sont **vides tant qu'aucune valeur n'a ete confirmee de facon
/// independante** : inscrire une valeur non verifiee serait pire que de n'en
/// inscrire aucune, puisqu'elle porterait l'autorite du binaire sans en avoir
/// merite la confiance. Une table vide n'affaiblit rien — la reverification du
/// travail s'applique de toute facon.
pub fn ancrages_integres(reseau: Network) -> &'static [Ancrage] {
    match reseau {
        Network::Mainnet => &[],
        Network::Testnet => &[],
        Network::Regtest => &[],
    }
}

/// Plafond du telechargement complet d'une amorce, cote client. Meme borne que
/// le decodage : de quoi tenir un tres grand jeu d'UTXO, jamais l'infini.
const MAX_AMORCE_OCTETS: usize = 2 * 1024 * 1024 * 1024;

/// Bornes de securite a la lecture : une amorce vient d'un pair, donc d'un
/// inconnu. Aucune allocation n'est dictee par ce qu'il annonce.
const MAX_ENTETES: usize = 5_000_000;
const MAX_CORPS: usize = 100_000;
/// Un corps serialise ne peut pas depasser la taille d'un bloc.
const MAX_CORPS_OCTETS: usize = crate::consensus::MAX_BLOCK_SIZE;
/// Un instantane serialise, borne large : de quoi tenir un tres grand jeu d'UTXO
/// sans jamais faire reserver l'infini.
const MAX_INSTANTANE_OCTETS: usize = 2 * 1024 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum AmorceError {
    Magie,
    Version(u32),
    TropDElements { max: usize, recu: usize },
    Lecture(ReadError),
}

impl From<ReadError> for AmorceError {
    fn from(e: ReadError) -> Self {
        AmorceError::Lecture(e)
    }
}

impl std::fmt::Display for AmorceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AmorceError::Magie => write!(f, "ce flux n'est pas une amorce Q21"),
            AmorceError::Version(v) => write!(f, "amorce de version {v}, inconnue"),
            AmorceError::TropDElements { max, recu } => {
                write!(f, "{recu} elements annonces, {max} au plus : refuse")
            }
            AmorceError::Lecture(e) => write!(f, "amorce illisible : {e:?}"),
        }
    }
}

/// Le paquet d'amorce, tel qu'il voyage.
#[derive(Clone, Debug, PartialEq)]
pub struct Amorce {
    /// L'instantane portable, deja serialise (il porte sa propre empreinte et sa
    /// somme de controle).
    pub instantane: Vec<u8>,
    /// Les en-tetes, de la genese a la hauteur de l'instantane.
    pub entetes: Vec<BlockHeader>,
    /// La fenetre de corps : la genese, puis les blocs autour de l'instantane.
    pub corps: Vec<Block>,
}

impl Amorce {
    /// Serialise le paquet en un seul flux d'octets.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(MAGIE);
        w.u32(VERSION);
        w.var_bytes(&self.instantane);
        w.varint(self.entetes.len() as u64);
        for h in &self.entetes {
            w.bytes(&h.encode());
        }
        w.varint(self.corps.len() as u64);
        for b in &self.corps {
            w.var_bytes(&b.encode());
        }
        w.finish()
    }

    /// Relit un paquet d'amorce, en bornant tout avant d'allouer.
    ///
    /// Ne verifie **ni** l'empreinte **ni** la confiance : ce n'est qu'un
    /// decodage. L'adoption, elle, confronte l'empreinte a une valeur sure.
    pub fn decode(donnees: &[u8]) -> Result<Amorce, AmorceError> {
        let mut r = Reader::new(donnees);
        let mut magie = [0u8; 8];
        for o in &mut magie {
            *o = r.u8()?;
        }
        if &magie != MAGIE {
            return Err(AmorceError::Magie);
        }
        let version = r.u32()?;
        if version != VERSION {
            return Err(AmorceError::Version(version));
        }

        let instantane = r.var_bytes()?;
        if instantane.len() > MAX_INSTANTANE_OCTETS {
            return Err(AmorceError::TropDElements {
                max: MAX_INSTANTANE_OCTETS,
                recu: instantane.len(),
            });
        }

        // Chaque en-tete occupe une taille fixe connue : on ne reserve jamais
        // plus d'emplacements que le reste du flux ne peut en contenir.
        let n = borne(&mut r, MAX_ENTETES, BlockHeader::SIZE)?;
        let mut entetes = Vec::with_capacity(n);
        for _ in 0..n {
            let mut buf = [0u8; BlockHeader::SIZE];
            for o in buf.iter_mut() {
                *o = r.u8()?;
            }
            entetes.push(BlockHeader::decode(&buf)?);
        }

        // Un corps occupe au moins dix octets sur le fil.
        let n = borne(&mut r, MAX_CORPS, 10)?;
        let mut corps = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let brut = r.var_bytes()?;
            if brut.len() > MAX_CORPS_OCTETS {
                return Err(AmorceError::TropDElements {
                    max: MAX_CORPS_OCTETS,
                    recu: brut.len(),
                });
            }
            corps.push(
                Block::decode(brut).map_err(|_| AmorceError::Lecture(ReadError::ValeurInvalide))?,
            );
        }

        r.expect_end()?;
        Ok(Amorce {
            instantane: instantane.to_vec(),
            entetes,
            corps,
        })
    }

    /// L'empreinte de l'instantane, lue a sa position sans decoder tout le jeu
    /// d'UTXO.
    ///
    /// L'instantane portable range (magie, version, reseau, hauteur, tete, emis,
    /// empreinte, …). On lit l'empreinte a son decalage, ce qui permet a un pair
    /// d'annoncer l'empreinte de son amorce sans la deserialiser entierement.
    pub fn empreinte_annoncee(&self) -> Option<Hash256> {
        // magie(8) + version(4) + reseau(1) + hauteur(8) + tete(32) + emis(8)
        const DECALAGE: usize = 8 + 4 + 1 + 8 + 32 + 8;
        let fin = DECALAGE + 32;
        self.instantane
            .get(DECALAGE..fin)
            .map(|s| Hash256(s.try_into().unwrap()))
    }

    /// La hauteur de l'instantane, lue a sa position.
    pub fn hauteur_annoncee(&self) -> Option<u64> {
        const DECALAGE: usize = 8 + 4 + 1;
        self.instantane
            .get(DECALAGE..DECALAGE + 8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    }

    /// La tete de l'instantane, lue a sa position.
    pub fn tete_annoncee(&self) -> Option<Hash256> {
        const DECALAGE: usize = 8 + 4 + 1 + 8;
        self.instantane
            .get(DECALAGE..DECALAGE + 32)
            .map(|s| Hash256(s.try_into().unwrap()))
    }
}

/// Nombre de tranches pour une amorce de `taille` octets.
pub fn nombre_de_tranches(taille: usize) -> u32 {
    taille.div_ceil(TAILLE_TRANCHE) as u32
}

/// La tranche numero `index` des octets d'une amorce, ou vide si l'index est
/// hors de portee.
pub fn tranche(octets: &[u8], index: u32) -> &[u8] {
    let debut = (index as usize).saturating_mul(TAILLE_TRANCHE);
    if debut >= octets.len() {
        return &[];
    }
    let fin = (debut + TAILLE_TRANCHE).min(octets.len());
    &octets[debut..fin]
}

// ---------------------------------------------------------------------------
// Client : telecharger une amorce depuis un pair
// ---------------------------------------------------------------------------

/// Telecharge une amorce depuis un pair, la reassemble, et **verifie son
/// empreinte** contre la valeur de confiance fournie par l'operateur.
///
/// # Le modele de confiance, redit ici
///
/// Le pair fournit les octets ; il ne fournit pas la confiance. Une amorce dont
/// l'empreinte annoncee — puis l'empreinte du paquet reassemble — ne correspond
/// pas a `empreinte_attendue` est **rejetee** : le pair est ecarte, rien n'est
/// adopte. C'est a l'appelant d'essayer un autre pair. `empreinte_attendue` vient
/// de l'operateur (l'empreinte qu'affiche son explorateur), jamais du pair.
///
/// # Bornes
///
/// Chaque lecture a un delai, et l'ensemble a une echeance globale : un pair qui
/// distille les octets ne peut pas retenir le client indefiniment. La taille
/// totale est plafonnee avant toute reservation.
pub fn telecharger_amorce(
    adresse: SocketAddr,
    magie: [u8; 4],
    hauteur_locale: u64,
    empreinte_attendue: Hash256,
    delai_lecture: Duration,
    delai_total: Duration,
) -> Result<Amorce, String> {
    let echeance = Instant::now() + delai_total;
    let mut flux = TcpStream::connect_timeout(&adresse, delai_lecture)
        .map_err(|e| format!("connexion a {adresse} impossible : {e}"))?;
    let _ = flux.set_read_timeout(Some(delai_lecture));
    let _ = flux.set_write_timeout(Some(delai_lecture));
    let _ = flux.set_nodelay(true);

    // Poignee de main : on parle en premier, puis on scelle par un verack — c'est
    // lui qui, cote pair, ouvre l'acces aux messages couteux.
    ecrire(&mut flux, magie, &poignee(hauteur_locale))?;
    ecrire(&mut flux, magie, &Message::VerAck)?;
    ecrire(&mut flux, magie, &Message::GetAmorce)?;

    let mut tampon: Vec<u8> = Vec::with_capacity(64 * 1024);

    // On attend les metadonnees, en repondant aux pings et en ignorant le reste
    // (le pair peut tenter de nous synchroniser en parallele : ce n'est pas ce
    // qu'on est venu chercher).
    let (taille, tranches, empreinte) = loop {
        match lire_message(&mut flux, &mut tampon, magie, echeance)? {
            Message::AmorceInfo {
                taille,
                tranches,
                empreinte,
                ..
            } => break (taille as usize, tranches, empreinte),
            Message::Ping(n) => ecrire(&mut flux, magie, &Message::Pong(n))?,
            Message::Reject { raison, .. } => return Err(format!("le pair refuse : {raison}")),
            _ => {}
        }
    };

    if empreinte != empreinte_attendue {
        return Err(format!(
            "empreinte annoncee {empreinte} differente de la valeur de confiance \
             {empreinte_attendue} : ce pair est ecarte"
        ));
    }
    if taille > MAX_AMORCE_OCTETS {
        return Err(format!("amorce annoncee trop grande : {taille} octets"));
    }
    if nombre_de_tranches(taille) != tranches {
        return Err("le compte de tranches ne correspond pas a la taille".into());
    }

    // On demande les tranches dans l'ordre, une par une.
    let mut octets: Vec<u8> = Vec::with_capacity(taille.min(64 * 1024 * 1024));
    for i in 0..tranches {
        ecrire(&mut flux, magie, &Message::GetAmorceTranche { index: i })?;
        loop {
            match lire_message(&mut flux, &mut tampon, magie, echeance)? {
                Message::AmorceTranche { index, donnees } if index == i => {
                    if octets.len() + donnees.len() > taille {
                        return Err("le pair envoie plus que la taille annoncee".into());
                    }
                    octets.extend_from_slice(&donnees);
                    break;
                }
                Message::Ping(n) => ecrire(&mut flux, magie, &Message::Pong(n))?,
                _ => {}
            }
        }
    }

    if octets.len() != taille {
        return Err(format!(
            "taille recue {} differente de l'annonce {taille}",
            octets.len()
        ));
    }

    let amorce = Amorce::decode(&octets).map_err(|e| format!("amorce illisible : {e}"))?;
    // Ceinture et bretelles : l'empreinte du paquet reassemble doit, elle aussi,
    // egaler la valeur de confiance.
    if amorce.empreinte_annoncee() != Some(empreinte_attendue) {
        return Err("apres reassemblage, l'empreinte du paquet ne correspond plus".into());
    }
    Ok(amorce)
}

fn poignee(hauteur: u64) -> Message {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
        .unwrap_or(1)
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1);
    Message::Version {
        version: PROTOCOL_VERSION,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        nonce,
        user_agent: "q21:0.2".into(),
        start_height: hauteur,
    }
}

fn ecrire(flux: &mut TcpStream, magie: [u8; 4], m: &Message) -> Result<(), String> {
    flux.write_all(&m.frame(magie))
        .map_err(|e| format!("ecriture reseau : {e}"))
}

/// Lit le prochain message complet, en accumulant les octets. Le tampon ne
/// grandit jamais au-dela d'une trame, et l'echeance globale coupe un pair qui
/// distille.
fn lire_message(
    flux: &mut TcpStream,
    tampon: &mut Vec<u8>,
    magie: [u8; 4],
    echeance: Instant,
) -> Result<Message, String> {
    loop {
        match Message::parse(tampon, magie) {
            Ok((m, n)) => {
                tampon.drain(..n);
                return Ok(m);
            }
            Err(WireError::Incomplet) => {}
            Err(e) => return Err(format!("trame invalide recue : {e:?}")),
        }
        if Instant::now() >= echeance {
            return Err("delai global depasse pendant le telechargement".into());
        }
        if tampon.len() > MAX_PAYLOAD + HEADER_LEN {
            return Err("trame plus grande que le maximum du protocole".into());
        }
        let mut morceau = [0u8; 32 * 1024];
        let lu = flux
            .read(&mut morceau)
            .map_err(|e| format!("lecture reseau : {e}"))?;
        if lu == 0 {
            return Err("connexion fermee par le pair".into());
        }
        tampon.extend_from_slice(&morceau[..lu]);
    }
}

/// Lit un compte en le bornant par le maximum du protocole **et** par ce que le
/// reste du flux peut contenir.
fn borne(r: &mut Reader<'_>, max: usize, minimum: usize) -> Result<usize, AmorceError> {
    let n = r.varint()? as usize;
    if n > max {
        return Err(AmorceError::TropDElements { max, recu: n });
    }
    if let Some(tenable) = r.remaining().checked_div(minimum) {
        if n > tenable {
            return Err(AmorceError::TropDElements {
                max: tenable,
                recu: n,
            });
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::genesis_block;
    use crate::Network;

    fn entete(h: u64) -> BlockHeader {
        let mut e = genesis_block(Network::Regtest).header;
        e.height = h;
        e.nonce = h;
        e
    }

    fn amorce_exemple() -> Amorce {
        Amorce {
            instantane: vec![0xab; 300],
            entetes: (0..5).map(entete).collect(),
            corps: vec![genesis_block(Network::Regtest)],
        }
    }

    #[test]
    fn aller_retour_sur_une_amorce() {
        let a = amorce_exemple();
        let b = Amorce::decode(&a.encode()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn une_amorce_vide_de_corps_fait_l_aller_retour() {
        let a = Amorce {
            instantane: vec![1, 2, 3],
            entetes: vec![entete(0)],
            corps: Vec::new(),
        };
        assert_eq!(Amorce::decode(&a.encode()).unwrap(), a);
    }

    #[test]
    fn un_flux_sans_magie_est_refuse() {
        assert_eq!(
            Amorce::decode(b"pas une amorce du tout"),
            Err(AmorceError::Magie)
        );
    }

    #[test]
    fn une_amorce_tronquee_ne_panique_pas() {
        let brut = amorce_exemple().encode();
        for coupure in 0..brut.len() {
            // Ne doit jamais paniquer : rendre une erreur, c'est tout.
            let _ = Amorce::decode(&brut[..coupure]);
        }
    }

    #[test]
    fn un_compte_d_entetes_absurde_est_refuse_avant_allocation() {
        let mut w = Writer::new();
        w.bytes(MAGIE);
        w.u32(VERSION);
        w.var_bytes(&[0u8; 4]);
        w.varint(u64::MAX); // annonce des milliards d'en-tetes
        let brut = w.finish();
        assert!(matches!(
            Amorce::decode(&brut),
            Err(AmorceError::TropDElements { .. })
        ));
    }

    #[test]
    fn l_empreinte_annoncee_correspond_a_l_instantane() {
        use crate::state::Snapshot;
        use crate::utxo::UtxoSet;
        let hauteur = 5_000;
        let utxo = UtxoSet::new();
        let muhash = utxo.commitment();
        let s = Snapshot {
            network: Network::Regtest,
            height: hauteur,
            tip: Hash256([7u8; 32]),
            emis: crate::emission::total_supply_at(hauteur).units(),
            utxo,
            muhash,
        };
        let a = Amorce {
            instantane: s.to_portable_bytes(),
            entetes: vec![entete(0)],
            corps: Vec::new(),
        };
        assert_eq!(a.empreinte_annoncee(), Some(muhash));
    }
}
