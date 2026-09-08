//! Instantane de l'etat monetaire, persiste sur disque.
//!
//! # Le mur que ce module abat
//!
//! Jusqu'a la phase 7, demarrer un noeud signifiait revalider toute la chaine
//! depuis la genese. Avec la preuve de travail corrigee en phase 6 — 660 us par
//! bloc — et des signatures ML-DSA a verifier, un million de blocs demandait des
//! heures. Un noeud qu'on ne peut pas redemarrer en quelques secondes n'est pas
//! utilisable, et un logiciel qu'on n'ose pas redemarrer ne se met jamais a jour.
//!
//! # Ce qui est persiste, et ce qui ne l'est pas
//!
//! **Persiste** : le jeu d'UTXO, la tete, la hauteur, le total emis. C'est
//! l'etat de la monnaie, et c'est ce qui coute cher a reconstruire.
//!
//! **Non persiste** : l'index des en-tetes, qui se reconstruit par une lecture
//! sequentielle du fichier de blocs ([`crate::store::BlockStore::scan_headers`])
//! sans decoder une seule transaction.
//!
//! # Ce que cet instantane n'est pas
//!
//! Ce n'est **pas** une preuve. Un noeud qui charge cet instantane fait
//! confiance a son propre disque : la somme de controle detecte une corruption
//! accidentelle, pas un adversaire ayant acces au fichier. C'est exactement le
//! statut du `chainstate` de Bitcoin Core, et pour la meme raison : quiconque
//! peut reecrire vos fichiers a deja gagne.
//!
//! Ce qui reste garanti : tout bloc **arrive apres** l'instantane est valide
//! integralement, et un instantane illisible ou incoherent fait retomber sur la
//! revalidation complete plutot que sur une acceptation silencieuse.
//!
//! # Ecriture atomique
//!
//! On ecrit dans un fichier temporaire, on force son ecriture physique, puis on
//! renomme. Un renommage est atomique sur les systemes de fichiers usuels : a
//! aucun instant il n'existe d'instantane a demi ecrit. Une coupure de courant
//! laisse soit l'ancien instantane, soit le nouveau — jamais un melange.

use crate::address::Network;
use crate::amount::Amount;
use crate::hash::Hash256;
use crate::ser::{Reader, Writer};
use crate::sha256::sha256;
use crate::sig::SchemeId;
use crate::tx::{OutPoint, TxOut};
use crate::utxo::{UtxoEntry, UtxoSet};
use std::path::{Path, PathBuf};

const MAGIE: &[u8; 8] = b"Q21STATE";
const VERSION: u32 = 1;

/// Version du format d'instantane, distincte de [`VERSION`] (qui reste celle du
/// reservoir de transactions). Elle passe a 2 avec l'arrivee de l'empreinte
/// MuHash : un instantane porte desormais l'engagement sur son jeu d'UTXO, et un
/// ancien fichier de version 1 est simplement rejoue depuis les blocs.
const SNAPSHOT_VERSION: u32 = 2;

/// Borne de securite : un fichier corrompu ne doit pas provoquer une allocation
/// delirante avant meme la verification de la somme de controle.
const MAX_UTXO: u64 = 500_000_000;

#[derive(Debug)]
pub enum StateError {
    Io(std::io::Error),
    /// Le fichier n'est pas un instantane Q21.
    MagieInvalide,
    /// Ecrit par une version qui ne connaissait pas ce format.
    VersionInconnue(u32),
    /// Instantane d'un autre reseau : le charger melangerait deux monnaies.
    MauvaisReseau,
    /// La somme de controle ne correspond pas : fichier corrompu.
    SommeInvalide,
    /// Le sceau ne correspond pas : fichier corrompu **ou** fabrique par un
    /// tiers. On ne distingue pas les deux cas, et on traite le fichier comme
    /// absent dans les deux.
    SceauInvalide,
    /// L'instantane se contredit lui-meme : total emis impossible a cette
    /// hauteur, ou somme des sorties superieure a ce qui a jamais ete emis.
    Incoherent(&'static str),
    /// L'empreinte MuHash inscrite dans l'instantane ne correspond pas au jeu
    /// d'UTXO qu'il contient : le fichier a ete altere sans que l'empreinte soit
    /// recalculee, ou il a ete corrompu.
    EngagementInvalide,
    /// Structure illisible.
    Illisible,
    /// Nombre d'entrees annonce hors de toute vraisemblance.
    TropDEntrees(u64),
}

impl From<std::io::Error> for StateError {
    fn from(e: std::io::Error) -> Self {
        StateError::Io(e)
    }
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::Io(e) => write!(f, "erreur d'entree/sortie : {e}"),
            StateError::MagieInvalide => write!(f, "ce fichier n'est pas un instantane Q21"),
            StateError::VersionInconnue(v) => {
                write!(f, "instantane de version {v}, inconnue de ce binaire")
            }
            StateError::MauvaisReseau => write!(f, "instantane d'un autre reseau"),
            StateError::SommeInvalide => write!(
                f,
                "somme de controle invalide : instantane corrompu, \
                 la chaine sera revalidee integralement"
            ),
            StateError::SceauInvalide => write!(
                f,
                "sceau invalide : ce fichier n'a pas ete ecrit par ce noeud, \
                 il est ignore"
            ),
            StateError::Incoherent(quoi) => write!(f, "instantane incoherent : {quoi}"),
            StateError::EngagementInvalide => write!(
                f,
                "empreinte du jeu d'UTXO incorrecte : l'instantane ne correspond \
                 pas a l'etat qu'il pretend porter, il est ignore"
            ),
            StateError::Illisible => write!(f, "instantane illisible"),
            StateError::TropDEntrees(n) => write!(f, "{n} entrees annoncees : refuse"),
        }
    }
}

/// Etat monetaire a un point precis de la chaine.
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    pub network: Network,
    pub height: u64,
    pub tip: Hash256,
    /// Total emis, en unites.
    pub emis: u64,
    pub utxo: UtxoSet,
    /// Empreinte MuHash du jeu d'UTXO ci-dessus, calculee a l'ecriture et
    /// verifiee au chargement. C'est l'engagement sur l'etat : deux noeuds a la
    /// meme hauteur portent la meme, et un fichier dont le jeu ne la reproduit
    /// pas est rejete.
    pub muhash: Hash256,
}

impl Snapshot {
    /// Invariants que tout instantane honnete satisfait, verifies **sans faire
    /// confiance a personne**.
    ///
    /// # Pourquoi ce controle existe
    ///
    /// Un audit a fabrique un `state.dat` en y ajoutant une sortie de un
    /// milliard d'unites au nom de l'attaquant. Le noeud l'a charge sans
    /// broncher : la somme de controle etait juste — l'attaquant l'avait
    /// recalculee — et rien d'autre n'etait verifie. Le noeud repartait donc
    /// avec de la monnaie qui n'avait jamais ete minee.
    ///
    /// Les regles ci-dessous ne demandent aucune clef et aucune confiance :
    /// elles confrontent l'instantane au **calendrier d'emission**, qui est du
    /// consensus pur. Aucune monnaie ne peut exister au-dela de ce que le
    /// calendrier autorise a cette hauteur, quelle que soit l'origine du
    /// fichier.
    ///
    /// # Ce qu'elles n'attrapent pas, et ce qui s'en charge desormais
    ///
    /// Une falsification qui *deplace* la propriete sans rien creer — reecrire
    /// l'empreinte d'une sortie existante — respecte ces invariants d'emission.
    /// C'est l'**empreinte MuHash** ([`Snapshot::muhash`]) qui la voit : elle
    /// depend de chaque empreinte de clef, donc tout deplacement la change.
    ///
    /// Attention a ce que cela prouve, et a ce que cela ne prouve pas. Verifier
    /// que le jeu reproduit l'empreinte inscrite ne fait que lier le fichier a
    /// lui-meme : un faussaire qui reecrit le jeu recalcule l'empreinte pour
    /// suivre. La defense n'est complete que lorsque cette empreinte est comparee
    /// a une **valeur de confiance venue d'ailleurs** — un point de controle
    /// livre avec le binaire, ou l'empreinte qu'un pair deja synchronise
    /// annonce. Cet ancrage est l'etape suivante ; le present module calcule,
    /// porte et verifie l'empreinte pour la rendre possible.
    pub fn verifier_coherence(&self) -> Result<(), StateError> {
        use crate::consensus::{GENESIS_PREMINT, MAX_SUPPLY};

        // 1. Le plafond absolu. Il ne depend de rien d'autre.
        if self.emis > MAX_SUPPLY {
            return Err(StateError::Incoherent("total emis au-dela du plafond"));
        }

        // 2. Le calendrier d'emission borne ce qui peut exister a cette
        //    hauteur. Un mineur peut reclamer moins que sa subvention — jamais
        //    plus. L'inegalite est donc large dans un seul sens.
        let plafond_a_cette_hauteur = crate::emission::total_supply_at(self.height).units();
        if self.emis > plafond_a_cette_hauteur {
            return Err(StateError::Incoherent(
                "total emis superieur a ce que le calendrier permet a cette hauteur",
            ));
        }
        if self.emis < GENESIS_PREMINT {
            return Err(StateError::Incoherent(
                "total emis inferieur a la piece de genese",
            ));
        }

        // 3. Aucune monnaie non depensee ne peut depasser la monnaie emise.
        //    C'est la regle qui fait tomber la falsification par ajout.
        let mut somme: u64 = 0;
        for (_, e) in self.utxo.iter() {
            somme = somme
                .checked_add(e.output.value.units())
                .ok_or(StateError::Incoherent("somme des sorties au-dela de u64"))?;
            // 4. Une sortie ne peut pas venir d'un bloc qui n'existe pas encore.
            if e.height > self.height {
                return Err(StateError::Incoherent(
                    "une sortie est datee d'un bloc posterieur a la tete",
                ));
            }
        }
        if somme > self.emis {
            return Err(StateError::Incoherent(
                "somme des sorties superieure au total emis",
            ));
        }

        Ok(())
    }
}

fn code_reseau(n: Network) -> u8 {
    match n {
        Network::Mainnet => 0,
        Network::Testnet => 1,
        Network::Regtest => 2,
    }
}

impl Snapshot {
    fn encode(&self) -> Vec<u8> {
        // 105 octets par entree, plus l'en-tete : on evite quelques centaines de
        // reallocations sur un jeu d'UTXO reel.
        let mut w = Writer::with_capacity(96 + self.utxo.len() * 112);
        w.bytes(MAGIE);
        w.u32(SNAPSHOT_VERSION);
        w.u8(code_reseau(self.network));
        w.u64(self.height);
        w.bytes(self.tip.as_bytes());
        w.u64(self.emis);
        w.bytes(self.muhash.as_bytes());
        w.varint(self.utxo.len() as u64);

        // Ordre déterministe : deux nœuds au même état écrivent le même fichier,
        // ce qui rend les instantanés comparables octet pour octet.
        let mut entrees: Vec<(&OutPoint, &UtxoEntry)> = self.utxo.iter().collect();
        entrees.sort_by_key(|(o, _)| **o);

        for (o, e) in entrees {
            w.bytes(o.txid.as_bytes());
            w.u32(o.index);
            w.u64(e.output.value.units());
            w.u8(e.output.scheme.as_u8());
            w.bytes(e.output.pubkey_hash.as_bytes());
            w.u64(e.height);
            w.u8(u8::from(e.is_coinbase));
        }

        let mut donnees = w.finish();
        let somme = sha256(&donnees);
        donnees.extend_from_slice(&somme);
        donnees
    }

    fn decode(donnees: &[u8], attendu: Network) -> Result<Snapshot, StateError> {
        if donnees.len() < 32 {
            return Err(StateError::Illisible);
        }
        let (charge, somme) = donnees.split_at(donnees.len() - 32);
        if sha256(charge) != somme {
            return Err(StateError::SommeInvalide);
        }

        let mut r = Reader::new(charge);
        let mut magie = [0u8; 8];
        for o in &mut magie {
            *o = r.u8().map_err(|_| StateError::Illisible)?;
        }
        if &magie != MAGIE {
            return Err(StateError::MagieInvalide);
        }
        let version = r.u32().map_err(|_| StateError::Illisible)?;
        if version != SNAPSHOT_VERSION {
            return Err(StateError::VersionInconnue(version));
        }
        let reseau = r.u8().map_err(|_| StateError::Illisible)?;
        if reseau != code_reseau(attendu) {
            return Err(StateError::MauvaisReseau);
        }

        let height = r.u64().map_err(|_| StateError::Illisible)?;
        let tip = Hash256(r.array32().map_err(|_| StateError::Illisible)?);
        let emis = r.u64().map_err(|_| StateError::Illisible)?;
        let muhash = Hash256(r.array32().map_err(|_| StateError::Illisible)?);
        let n = r.varint().map_err(|_| StateError::Illisible)?;
        if n > MAX_UTXO {
            return Err(StateError::TropDEntrees(n));
        }

        let mut utxo = UtxoSet::new();
        for _ in 0..n {
            let txid = Hash256(r.array32().map_err(|_| StateError::Illisible)?);
            let index = r.u32().map_err(|_| StateError::Illisible)?;
            let value = Amount::from_units(r.u64().map_err(|_| StateError::Illisible)?);
            let scheme = SchemeId::from_u8(r.u8().map_err(|_| StateError::Illisible)?)
                .ok_or(StateError::Illisible)?;
            let pubkey_hash = Hash256(r.array32().map_err(|_| StateError::Illisible)?);
            let hauteur = r.u64().map_err(|_| StateError::Illisible)?;
            let coinbase = r.u8().map_err(|_| StateError::Illisible)? != 0;

            utxo.insert(
                OutPoint { txid, index },
                UtxoEntry {
                    output: TxOut {
                        value,
                        scheme,
                        pubkey_hash,
                    },
                    height: hauteur,
                    is_coinbase: coinbase,
                },
            );
        }
        r.expect_end().map_err(|_| StateError::Illisible)?;

        // L'engagement d'abord : le jeu d'UTXO doit reproduire l'empreinte
        // inscrite. Un fichier dont on a altere une sortie sans recalculer
        // l'empreinte tombe ici, avant meme les invariants d'emission.
        if utxo.commitment() != muhash {
            return Err(StateError::EngagementInvalide);
        }

        let s = Snapshot {
            network: attendu,
            height,
            tip,
            emis,
            utxo,
            muhash,
        };
        // Un instantane qui se contredit lui-meme n'est pas charge, quelle que
        // soit la validite de sa somme de controle.
        s.verifier_coherence()?;
        Ok(s)
    }
}

impl Snapshot {
    /// Serialise l'instantane sous sa forme **portable** : le meme encodage que
    /// l'instantane local, mais **sans le sceau du repertoire**.
    ///
    /// # Ce que ce format est, et ce qu'il n'est pas
    ///
    /// Il se partage : aucune clef locale n'y entre, donc n'importe quelle
    /// machine peut le relire. Sa **fidelite** — le jeu correspond-il a
    /// l'empreinte inscrite — est verifiee a la relecture, comme pour un
    /// instantane local. Ce qu'il ne porte pas, c'est la **confiance** : rien
    /// dans le fichier ne prouve que cette empreinte est celle de la vraie
    /// chaine. C'est a celui qui l'adopte de comparer [`Snapshot::muhash`] a une
    /// valeur qu'il tient d'une source sure — l'empreinte qu'affiche son propre
    /// explorateur, par exemple.
    pub fn to_portable_bytes(&self) -> Vec<u8> {
        self.encode()
    }

    /// Relit un instantane portable : verifie la somme de controle, puis que le
    /// jeu reproduit l'empreinte inscrite, puis la coherence d'emission.
    ///
    /// Ne verifie **pas** la confiance. L'appelant doit encore confronter
    /// l'empreinte relue a une valeur sure avant d'adopter l'etat.
    pub fn from_portable_bytes(donnees: &[u8], reseau: Network) -> Result<Snapshot, StateError> {
        Snapshot::decode(donnees, reseau)
    }
}

/// Secret propre a un repertoire de donnees.
///
/// # A quoi il sert, et a quoi il ne sert pas
///
/// Il **ne protege pas** contre un adversaire qui a deja les droits d'ecriture
/// sur le repertoire : celui-la peut lire la clef, ou simplement remplacer le
/// binaire. Sur ce point la position est celle de Bitcoin Core, et elle est
/// honnete : qui peut reecrire vos fichiers a deja gagne.
///
/// Il protege contre un cas different et bien plus courant : un fichier d'etat
/// **venu d'ailleurs**. Un « instantane de synchronisation rapide » telecharge,
/// une sauvegarde d'un autre poste, un volume partage. Ce fichier-la n'a pas le
/// sceau de ce repertoire, et il n'est pas adopte — il est ignore, et la chaine
/// est revalidee depuis le fichier de blocs, qui porte lui une preuve de
/// travail.
///
/// La clef est tiree du generateur du systeme a la premiere ouverture, ecrite
/// avec des droits restreints, et jamais transmise.
pub fn clef_de_repertoire(datadir: &Path) -> Result<[u8; 32], StateError> {
    let chemin = datadir.join("node.key");
    if let Ok(octets) = std::fs::read(&chemin) {
        if octets.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&octets);
            return Ok(k);
        }
        // Un fichier de clef de la mauvaise taille est un fichier casse : on le
        // remplace plutot que de s'arreter, l'instantane sera simplement rejoue.
    }
    let k = crate::rng::octets::<32>().map_err(|_| {
        StateError::Io(std::io::Error::other(
            "generateur d'alea du systeme inaccessible",
        ))
    })?;
    let tmp = chemin.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&k)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &chemin)?;
    restreindre(&chemin);
    Ok(k)
}

fn restreindre(chemin: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = chemin;
}

/// Fichier d'instantane.
pub struct StateStore {
    chemin: PathBuf,
    clef: [u8; 32],
}

impl StateStore {
    /// Instantane scelle par la clef du repertoire.
    pub fn new_scelle<P: AsRef<Path>>(chemin: P, clef: [u8; 32]) -> StateStore {
        StateStore {
            chemin: chemin.as_ref().to_path_buf(),
            clef,
        }
    }

    pub fn new<P: AsRef<Path>>(chemin: P) -> StateStore {
        StateStore {
            chemin: chemin.as_ref().to_path_buf(),
            clef: [0u8; 32],
        }
    }

    pub fn path(&self) -> &Path {
        &self.chemin
    }

    pub fn exists(&self) -> bool {
        self.chemin.exists()
    }

    /// Ecrit l'instantane de maniere atomique.
    ///
    /// Fichier temporaire, `sync_all`, puis renommage. Le `sync_all` n'est pas
    /// decoratif : sans lui, le renommage peut devenir visible avant que le
    /// contenu ne soit reellement sur le disque, et une coupure de courant
    /// laisserait un instantane valide en apparence et vide en fait.
    pub fn save(&self, s: &Snapshot) -> Result<(), StateError> {
        let mut donnees = s.encode();
        donnees.extend_from_slice(&crate::kdf::hmac_sha256(&self.clef, &donnees));
        let tmp = self.chemin.with_extension("tmp");

        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&donnees)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.chemin)?;

        // Le renommage lui-meme doit etre durable : sur la plupart des systemes
        // cela demande de synchroniser le repertoire parent. L'echec n'est pas
        // fatal — on aura simplement moins de garanties qu'espere.
        if let Some(parent) = self.chemin.parent() {
            if let Ok(d) = std::fs::File::open(parent) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }

    pub fn load(&self, network: Network) -> Result<Snapshot, StateError> {
        let donnees = std::fs::read(&self.chemin)?;
        if donnees.len() < 32 {
            return Err(StateError::Illisible);
        }
        let (charge, sceau) = donnees.split_at(donnees.len() - 32);
        let attendu = crate::kdf::hmac_sha256(&self.clef, charge);
        if !crate::kdf::egal_temps_constant(&attendu, sceau) {
            return Err(StateError::SceauInvalide);
        }
        Snapshot::decode(charge, network)
    }

    pub fn remove(&self) -> Result<(), StateError> {
        if self.exists() {
            std::fs::remove_file(&self.chemin)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cache d'adresses du portefeuille
// ---------------------------------------------------------------------------

const MAGIE_ADR: &[u8; 8] = b"Q21ADDRS";
/// Le cache d'adresses est passe d'une somme de controle nue a un sceau
/// authentifie. Un ancien fichier n'a pas de sceau valide : il sera rejete et
/// rederive, ce qui coute une seconde et ne perd rien.
const VERSION_ADR: u32 = 2;

/// Empreintes d'adresses deja derivees, en cache local.
///
/// # Le second mur du demarrage
///
/// Une fois la chaine rendue incrementale, le temps de demarrage a bascule
/// ailleurs : un portefeuille de soixante mille adresses ML-DSA demandait vingt
/// secondes de derivation, contre une demi-seconde pour toute la chaine. La
/// mesure a designe le coupable, comme toujours.
///
/// Ce fichier n'est qu'un cache : il ne contient aucun secret — une empreinte
/// de clef publique est deja publique — et sa perte ne coute qu'une derivation
/// complete. Le portefeuille le resonde avant de l'adopter
/// ([`crate::wallet::Wallet::adopt_hashes`]).
pub struct AddressCache {
    chemin: PathBuf,
}

impl AddressCache {
    pub fn new<P: AsRef<Path>>(chemin: P) -> AddressCache {
        AddressCache {
            chemin: chemin.as_ref().to_path_buf(),
        }
    }

    pub fn exists(&self) -> bool {
        self.chemin.exists()
    }

    pub fn save(
        &self,
        scheme: SchemeId,
        hashes: &[Hash256],
        clef: &[u8; 32],
    ) -> Result<(), StateError> {
        let mut w = Writer::with_capacity(32 + hashes.len() * 32);
        w.bytes(MAGIE_ADR);
        w.u32(VERSION_ADR);
        w.u8(scheme.as_u8());
        w.varint(hashes.len() as u64);
        for h in hashes {
            w.bytes(h.as_bytes());
        }
        let mut donnees = w.finish();
        let sceau = crate::kdf::hmac_sha256(clef, &donnees);
        donnees.extend_from_slice(&sceau);

        let tmp = self.chemin.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&donnees)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.chemin)?;
        Ok(())
    }

    pub fn load(&self, scheme: SchemeId, clef: &[u8; 32]) -> Result<Vec<Hash256>, StateError> {
        let donnees = std::fs::read(&self.chemin)?;
        if donnees.len() < 32 {
            return Err(StateError::Illisible);
        }
        let (charge, sceau) = donnees.split_at(donnees.len() - 32);
        // Comparaison a temps constant : le sceau est verifie avant toute
        // lecture de la charge, et un attaquant ne doit pas pouvoir le
        // reconstruire octet par octet en mesurant le refus.
        let attendu = crate::kdf::hmac_sha256(clef, charge);
        if !crate::kdf::egal_temps_constant(&attendu, sceau) {
            return Err(StateError::SceauInvalide);
        }

        let mut r = Reader::new(charge);
        let mut magie = [0u8; 8];
        for o in &mut magie {
            *o = r.u8().map_err(|_| StateError::Illisible)?;
        }
        if &magie != MAGIE_ADR {
            return Err(StateError::MagieInvalide);
        }
        let version = r.u32().map_err(|_| StateError::Illisible)?;
        if version != VERSION_ADR {
            return Err(StateError::VersionInconnue(version));
        }
        // Un cache derive pour un autre schema designerait d'autres clefs.
        if r.u8().map_err(|_| StateError::Illisible)? != scheme.as_u8() {
            return Err(StateError::Illisible);
        }

        let n = r.varint().map_err(|_| StateError::Illisible)?;
        if n > MAX_UTXO {
            return Err(StateError::TropDEntrees(n));
        }
        let mut v = Vec::with_capacity(n.min(1_000_000) as usize);
        for _ in 0..n {
            v.push(Hash256(r.array32().map_err(|_| StateError::Illisible)?));
        }
        r.expect_end().map_err(|_| StateError::Illisible)?;
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// Reservoir de transactions
// ---------------------------------------------------------------------------

const MAGIE_RESERVOIR: &[u8; 8] = b"Q21MEMPL";

/// Borne de securite a la lecture.
const MAX_TX_RESERVOIR: u64 = 200_000;

/// Le reservoir de transactions, conserve entre deux executions.
///
/// # La transaction qui disparaissait
///
/// Une transaction envoyee entre dans le reservoir — une salle d'attente en
/// memoire — et y patiente qu'un mineur la prenne. Le reservoir n'etait ecrit
/// nulle part : arreter le logiciel avant qu'elle soit minee l'effacait.
///
/// Ce n'est pas une hypothese. Un premier utilisateur a envoye une transaction,
/// arrete le portefeuille pour lancer le minage, et l'a vue disparaitre. Rien
/// n'etait perdu — les fonds n'avaient pas bouge — mais le paiement n'avait
/// jamais eu lieu, sans un mot d'explication.
///
/// Sur un reseau peuple, un pair aurait relaye la transaction et l'aurait
/// gardee. C'est donc surtout le noeud isole — celui d'un portefeuille de
/// bureau, precisement — qui payait ce defaut. Bitcoin Core ecrit son
/// `mempool.dat` a l'arret pour cette raison exacte.
///
/// # Ce qui est ecrit, et ce qui ne l'est pas
///
/// **Les transactions, rien d'autre.** Tout le reste de l'etat du reservoir —
/// sorties engagees, liens de parente, comptabilite memoire — se rededuit en
/// les rejouant. Ecrire un etat derive, c'est se donner deux sources de verite
/// pour une seule chose.
///
/// **Et le rejeu revalide.** La chaine a pu avancer pendant l'arret : une
/// transaction peut avoir ete confirmee entre-temps, ou etre devenue
/// impossible. Chacune repasse par `accept`, qui la refuse le cas echeant. Un
/// reservoir relu n'est jamais cru sur parole.
pub struct MempoolStore {
    chemin: PathBuf,
    clef: [u8; 32],
}

impl MempoolStore {
    pub fn new<P: AsRef<Path>>(chemin: P, clef: [u8; 32]) -> MempoolStore {
        MempoolStore {
            chemin: chemin.as_ref().to_path_buf(),
            clef,
        }
    }

    pub fn exists(&self) -> bool {
        self.chemin.exists()
    }

    /// Ecrit les transactions en attente, parents avant enfants.
    pub fn save(&self, transactions: &[crate::tx::Transaction]) -> Result<(), StateError> {
        let mut w = Writer::with_capacity(64 + transactions.len() * 256);
        w.bytes(MAGIE_RESERVOIR);
        w.u32(VERSION);
        w.varint(transactions.len() as u64);
        for tx in transactions {
            let brut = tx.encode();
            w.varint(brut.len() as u64);
            w.bytes(&brut);
        }
        let mut donnees = w.finish();
        donnees.extend_from_slice(&crate::kdf::hmac_sha256(&self.clef, &donnees));

        let tmp = self.chemin.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&donnees)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.chemin)?;
        Ok(())
    }

    /// Relit les transactions en attente.
    ///
    /// Elles ne sont pas validees ici : c'est a l'appelant de les repasser par
    /// `Mempool::accept`, seul endroit qui connaisse l'etat de la chaine.
    pub fn load(&self) -> Result<Vec<crate::tx::Transaction>, StateError> {
        let donnees = std::fs::read(&self.chemin)?;
        if donnees.len() < 32 {
            return Err(StateError::Illisible);
        }
        let (charge, sceau) = donnees.split_at(donnees.len() - 32);
        let attendu = crate::kdf::hmac_sha256(&self.clef, charge);
        if !crate::kdf::egal_temps_constant(&attendu, sceau) {
            return Err(StateError::SceauInvalide);
        }

        let mut r = Reader::new(charge);
        let mut magie = [0u8; 8];
        for o in &mut magie {
            *o = r.u8().map_err(|_| StateError::Illisible)?;
        }
        if &magie != MAGIE_RESERVOIR {
            return Err(StateError::MagieInvalide);
        }
        let version = r.u32().map_err(|_| StateError::Illisible)?;
        if version != VERSION {
            return Err(StateError::VersionInconnue(version));
        }
        let n = r.varint().map_err(|_| StateError::Illisible)?;
        if n > MAX_TX_RESERVOIR {
            return Err(StateError::TropDEntrees(n));
        }

        let mut v = Vec::with_capacity(n.min(10_000) as usize);
        for _ in 0..n {
            // `try_from` et non `as` : sur 32 bits, une longueur tronquee
            // passerait sous la borne qui suit.
            let taille = r
                .varint()
                .ok()
                .and_then(|t| usize::try_from(t).ok())
                .ok_or(StateError::Illisible)?;
            if taille > crate::consensus::MAX_BLOCK_SIZE {
                return Err(StateError::Illisible);
            }
            let mut brut = vec![0u8; taille];
            for o in brut.iter_mut() {
                *o = r.u8().map_err(|_| StateError::Illisible)?;
            }
            let tx = crate::tx::Transaction::decode(&brut).map_err(|_| StateError::Illisible)?;
            v.push(tx);
        }
        r.expect_end().map_err(|_| StateError::Illisible)?;
        Ok(v)
    }

    pub fn remove(&self) -> Result<(), StateError> {
        if self.exists() {
            std::fs::remove_file(&self.chemin)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chemin(nom: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("q21-state-{nom}-{}.dat", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn instantane(n: u32) -> Snapshot {
        let mut utxo = UtxoSet::new();
        for i in 0..n {
            utxo.insert(
                OutPoint {
                    txid: Hash256([i as u8; 32]),
                    index: i,
                },
                UtxoEntry {
                    output: TxOut {
                        value: Amount::from_units(1_000 + u64::from(i)),
                        scheme: SchemeId::MlDsa65,
                        pubkey_hash: Hash256([(i + 1) as u8; 32]),
                    },
                    height: u64::from(i),
                    is_coinbase: i % 3 == 0,
                },
            );
        }
        // Un instantane d'epreuve doit rester *coherent* : depuis que le
        // chargement confronte le total emis au calendrier d'emission, un
        // fixture fantaisiste serait refuse — a juste titre.
        let hauteur = 5_000;
        let muhash = utxo.commitment();
        Snapshot {
            network: Network::Regtest,
            height: hauteur,
            tip: Hash256([7u8; 32]),
            emis: crate::emission::total_supply_at(hauteur).units(),
            utxo,
            muhash,
        }
    }

    #[test]
    fn aller_retour_sur_le_disque() {
        let p = chemin("aller-retour");
        let s = StateStore::new(&p);
        let a = instantane(50);
        s.save(&a).unwrap();
        let b = s.load(Network::Regtest).unwrap();

        assert_eq!(a.height, b.height);
        assert_eq!(a.tip, b.tip);
        assert_eq!(a.emis, b.emis);
        assert_eq!(a.utxo.len(), b.utxo.len());
        for (o, e) in a.utxo.iter() {
            assert_eq!(b.utxo.get(o), Some(e), "entree perdue : {o:?}");
        }
        s.remove().unwrap();
    }

    #[test]
    fn l_empreinte_survit_a_l_aller_retour() {
        let p = chemin("empreinte");
        let s = StateStore::new(&p);
        let a = instantane(40);
        s.save(&a).unwrap();
        let b = s.load(Network::Regtest).unwrap();
        assert_eq!(a.muhash, b.muhash, "l'empreinte doit survivre au disque");
        assert_eq!(
            b.muhash,
            b.utxo.commitment(),
            "l'empreinte relue doit correspondre au jeu relu"
        );
        s.remove().unwrap();
    }

    #[test]
    fn une_empreinte_perimee_fait_rejeter_l_instantane() {
        let p = chemin("empreinte-perimee");
        let s = StateStore::new(&p);
        let mut a = instantane(15);
        // L'empreinte ne correspond plus au jeu : fichier altere ou corrompu.
        a.muhash = Hash256([0xAB; 32]);
        s.save(&a).unwrap();
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StateError::EngagementInvalide)
        ));
        s.remove().unwrap();
    }

    #[test]
    fn un_instantane_portable_fait_l_aller_retour() {
        let a = instantane(30);
        let octets = a.to_portable_bytes();
        let b = Snapshot::from_portable_bytes(&octets, Network::Regtest).unwrap();
        assert_eq!(a.muhash, b.muhash);
        assert_eq!(a.height, b.height);
        assert_eq!(a.tip, b.tip);
        assert_eq!(a.utxo.len(), b.utxo.len());
        assert_eq!(b.utxo.commitment(), b.muhash);
    }

    #[test]
    fn un_instantane_portable_corrompu_est_refuse() {
        let mut octets = instantane(20).to_portable_bytes();
        let milieu = octets.len() / 2;
        octets[milieu] ^= 0x01;
        assert!(matches!(
            Snapshot::from_portable_bytes(&octets, Network::Regtest),
            Err(StateError::SommeInvalide)
        ));
    }

    #[test]
    fn un_instantane_portable_d_un_autre_reseau_est_refuse() {
        // Le mecanisme sur lequel s'appuie la detection automatique du reseau :
        // relu sous le mauvais reseau, un instantane tombe sur MauvaisReseau.
        let octets = instantane(5).to_portable_bytes();
        assert!(matches!(
            Snapshot::from_portable_bytes(&octets, Network::Mainnet),
            Err(StateError::MauvaisReseau)
        ));
        assert!(Snapshot::from_portable_bytes(&octets, Network::Regtest).is_ok());
    }

    #[test]
    fn l_encodage_est_deterministe() {
        // Deux jeux identiques construits dans un ordre different doivent
        // produire le meme fichier : sinon on ne peut pas comparer deux noeuds.
        let a = instantane(30);
        let mut b = Snapshot {
            utxo: UtxoSet::new(),
            ..a.clone()
        };
        let mut entrees: Vec<_> = a.utxo.iter().map(|(o, e)| (*o, *e)).collect();
        entrees.reverse();
        for (o, e) in entrees {
            b.utxo.insert(o, e);
        }
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn un_octet_modifie_invalide_l_instantane() {
        let p = chemin("corrompu");
        let s = StateStore::new(&p);
        s.save(&instantane(20)).unwrap();

        let mut donnees = std::fs::read(&p).unwrap();
        let milieu = donnees.len() / 2;
        donnees[milieu] ^= 0x01;
        std::fs::write(&p, &donnees).unwrap();

        // Le sceau tombe avant la somme de controle : c'est le controle le
        // plus exterieur, et il couvre exactement les memes octets.
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StateError::SceauInvalide)
        ));
        s.remove().unwrap();
    }

    #[test]
    fn un_instantane_tronque_est_refuse() {
        let p = chemin("tronque");
        let s = StateStore::new(&p);
        s.save(&instantane(20)).unwrap();

        let donnees = std::fs::read(&p).unwrap();
        std::fs::write(&p, &donnees[..donnees.len() - 40]).unwrap();

        assert!(s.load(Network::Regtest).is_err());
        s.remove().unwrap();
    }

    /// Charger l'etat d'un autre reseau melangerait deux monnaies.
    #[test]
    fn un_instantane_d_un_autre_reseau_est_refuse() {
        let p = chemin("reseau");
        let s = StateStore::new(&p);
        s.save(&instantane(5)).unwrap();
        assert!(matches!(
            s.load(Network::Mainnet),
            Err(StateError::MauvaisReseau)
        ));
        s.remove().unwrap();
    }

    /// L'ecriture atomique doit laisser l'ancien instantane intact si la
    /// nouvelle echoue. On le verifie en constatant qu'aucun fichier temporaire
    /// ne subsiste et que le contenu est celui de la derniere ecriture reussie.
    #[test]
    fn l_ecriture_ne_laisse_pas_de_fichier_temporaire() {
        let p = chemin("atomique");
        let s = StateStore::new(&p);
        s.save(&instantane(10)).unwrap();
        s.save(&instantane(20)).unwrap();

        assert!(!p.with_extension("tmp").exists(), "temporaire non nettoye");
        assert_eq!(s.load(Network::Regtest).unwrap().utxo.len(), 20);
        s.remove().unwrap();
    }

    #[test]
    fn un_fichier_quelconque_n_est_pas_un_instantane() {
        let p = chemin("etranger");
        let s = StateStore::new(&p);

        // Un fichier etranger, scelle par une clef qui n'est pas la notre :
        // refuse sur le sceau, sans qu'une seule structure soit decodee.
        let etranger = StateStore::new_scelle(&p, [0x42u8; 32]);
        etranger.save(&instantane(4)).unwrap();
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StateError::SceauInvalide)
        ));

        // Et un fichier qui n'est un instantane d'aucune sorte, scelle par la
        // bonne clef : refuse plus loin, sur la magie.
        // Les deux couches sont satisfaites — somme interne et sceau externe —
        // et le contenu reste du charabia : le refus doit venir de la magie.
        let mut charge = b"ceci n'est pas un instantane".to_vec();
        let somme = sha256(&charge);
        charge.extend_from_slice(&somme);
        let mut donnees = charge.clone();
        donnees.extend_from_slice(&crate::kdf::hmac_sha256(&[0u8; 32], &charge));
        std::fs::write(&p, &donnees).unwrap();
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StateError::MagieInvalide)
        ));
        let _ = s.remove();
    }
}
