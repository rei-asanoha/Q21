//! Portefeuille.
//!
//! Deterministe : tout se derive d'une graine de 32 octets. Sauvegarder cette
//! graine et un compteur suffit a tout retrouver.
//!
//! # Le compteur n'est pas un detail de confort
//!
//! Lamport signe **une fois**. Reutiliser une clef revele la clef privee. Le
//! portefeuille garantit donc l'unicite en n'employant jamais deux fois le meme
//! indice, et en refusant de signer avec un indice deja consomme.
//!
//! Cette contrainte ne vaut que pour Lamport. ML-DSA est sans etat : une clef y
//! signe autant de fois qu'on veut. Le portefeuille continue neanmoins de
//! changer d'adresse a chaque paiement, mais pour une raison differente — la
//! confidentialite, non la survie de la clef. La distinction est portee par
//! [`SchemeId::est_a_usage_unique`], pas par un commentaire.
//!
//! C'est exactement le piege operationnel que la section 4 du livre blanc
//! reproche au schema XMSS de QRL. Le vivre une fois vaut mieux que le lire.

use crate::address::{Address, Network};
use crate::amount::Amount;
use crate::consensus::COINBASE_MATURITY;
use crate::hash::{tagged_hash_parts, tags, Hash256};
use crate::lamport::SecretKey;
use crate::sig::{pubkey_hash, SchemeId};
use crate::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use crate::utxo::UtxoSet;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WalletError {
    FondsInsuffisants {
        disponible: u64,
        demande: u64,
    },
    /// L'indice de clef a deja servi. Signer a nouveau revelerait la clef privee.
    ClefDejaUtilisee(u32),
    ClefInconnue,
    MontantNul,
    SchemaNonSupporte(SchemeId),
    /// Le generateur d'alea du systeme est inaccessible ou suspect.
    ///
    /// Aucune clef n'est creee dans ce cas : un portefeuille previsible est
    /// pire qu'un portefeuille absent.
    AleaIndisponible,
    /// Code de sauvegarde illisible : somme de controle fausse, ou longueur
    /// inattendue.
    SauvegardeInvalide,
    /// Code de sauvegarde d'un autre reseau.
    SauvegardeAutreReseau,
    /// Ce qu'on a recu est une adresse de reception, pas un code de sauvegarde.
    ///
    /// Les deux s'ecrivent pareil — Bech32m, meme alphabet — et ne different que
    /// par le prefixe. Un portefeuille perdu, une adresse sous les yeux, et la
    /// confusion est faite. La rejeter comme « somme de controle fausse »
    /// envoyait la personne verifier une recopie parfaite : c'est l'objet qui
    /// est faux, pas la copie, et c'est cela qu'il faut dire.
    SauvegardeEstUneAdresse,
    /// La clef derivee a cet indice ne correspond pas au verrou de la sortie
    /// que le portefeuille croyait pouvoir depenser.
    ///
    /// Ce refus est la derniere barriere avant une signature perdue : pour un
    /// schema a usage unique, signer avec la mauvaise clef la brulerait sans
    /// rien depenser. On s'arrete **avant** de signer, et rien n'est consomme.
    VerrouIncoherent {
        index: u32,
    },
    /// Montant ou frais au-dela de ce qui peut exister.
    ///
    /// Aucune somme legitime ne depasse le plafond d'emission. Refuser ici
    /// evite une addition qui deborde — et, en release, un arret du processus.
    MontantHorsBornes,
    /// Un montant sous le plancher de poussiere ([`crate::consensus::MIN_OUTPUT_VALUE`]).
    ///
    /// Le reseau refuserait la transaction ; la construire aurait consomme une
    /// clef a usage unique pour rien. On refuse avant.
    MontantSousLePlancher {
        minimum: u64,
        recu: u64,
    },
    /// L'enregistrement des indices consommes a echoue **avant** la signature.
    ///
    /// Rien n'a ete signe : les indices sont reserves en memoire, mais aucune
    /// signature n'existe, donc aucune clef n'est exposee. Disque plein,
    /// fichier verrouille, support retire — la depense est refusee plutot que
    /// de risquer, au prochain envoi, de resigner avec une clef que le disque
    /// croit encore vierge.
    EnregistrementImpossible,
    /// Entre la reservation des pieces et la signature, une d'elles a disparu
    /// du jeu de sorties : depensee par une autre transaction, ou emportee
    /// par une reorganisation. Rien n'a ete signe, la reservation est levee.
    ///
    /// N'arrive que sur le chemin en deux temps ([`Wallet::preparer_depense`]
    /// puis [`Wallet::signer_depense`]), ou le verrou de la chaine est rendu
    /// entre les deux le temps d'ecrire le portefeuille.
    PiecesDisparues,
    /// Schema a usage unique : la chaine n'a pas ete balayee jusqu'a la
    /// hauteur courante, et des corps manquent pour le faire. Signer sans
    /// savoir quelles clefs ont deja servi pourrait en resigner une.
    VerificationEnRetard {
        verifie: u64,
        hauteur: u64,
    },
}

/// En deca de ce nombre d'adresses, un cache est resonde **integralement**.
///
/// Mille vingt-quatre derivations ML-DSA coutent environ un tiers de seconde :
/// c'est invisible au demarrage, et cela couvre la quasi-totalite des
/// portefeuilles reels. Le cache ne sert vraiment qu'au-dela.
const SEUIL_VERIFICATION_COMPLETE: usize = 1024;

/// Prefixe humain du code de sauvegarde, par reseau.
/// Le prefixe d'un code de sauvegarde, pour le nommer dans un message.
///
/// Rendu public pour que l'interface puisse dire a quoi ressemble ce qu'elle
/// attend, sans recopier la table ici et la — une table recopiee derive.
pub fn hrp_graine_public(n: Network) -> &'static str {
    hrp_graine(n)
}

fn hrp_graine(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "q21seed",
        Network::Testnet => "tq21seed",
        Network::Regtest => "rq21seed",
    }
}

pub struct Wallet {
    seed: [u8; 32],
    network: Network,
    scheme: SchemeId,
    /// Prochain indice libre.
    next_index: u32,
    /// Empreinte de clef publique -> indice de derivation.
    connues: HashMap<Hash256, u32>,
    /// Indices deja employes pour signer. Interdits de reemploi.
    consommes: Vec<u32>,
    /// Indices **reserves** pour une depense en cours, avec la hauteur de la
    /// chaine au moment de la reservation.
    ///
    /// # Reserve n'est pas revele
    ///
    /// L'ecriture anticipee met l'indice sur le disque avant la signature —
    /// c'est ce qui empeche de resigner apres une coupure. Mais l'indice
    /// reserve porte la piece que l'on depense : le compter comme consomme
    /// des la reservation figeait cette piece pour toujours si le processus
    /// mourait entre la reservation et la diffusion, sans qu'aucune signature
    /// ait jamais existe. Le solde baissait, et rien ne l'expliquait.
    ///
    /// Une reservation est levee par la signature (l'indice passe dans
    /// `consommes`), par l'abandon avant signature (il redevient libre), ou par
    /// [`Wallet::reexaminer_reservations`] : si la chaine ne porte aucune
    /// signature de cette clef [`Wallet::DELAI_RESERVATION`] blocs apres la
    /// reservation, l'indice redevient libre. Sur le disque, un indice reserve
    /// figure **aussi** dans `consommes=` : un lecteur ancien le tient pour
    /// consomme, ce qui est le sens prudent.
    reserves: std::collections::BTreeMap<u32, u64>,
    /// Hauteur jusqu'a laquelle la chaine a ete balayee a la recherche de
    /// signatures de ce portefeuille.
    ///
    /// Le balayage est le filet qui rattrape une restauration : il retrouve
    /// dans la chaine les clefs deja revelees. Mais il coute une lecture
    /// complete, et sans memoire il recommencait a chaque commande.
    verifie_jusqu_a: u64,
    /// Etiquettes libres posees par le porteur sur ses adresses.
    ///
    /// # Pourquoi elles vivent dans le portefeuille
    ///
    /// Une adresse Q21 est une suite de caracteres que personne ne reconnait.
    /// Celui qui en distribue plusieurs — une par correspondant, comme le
    /// protocole y invite — perd tres vite le fil de qui a recu quoi. Le carnet
    /// est donc la reponse a un besoin cree par la vie privee elle-meme.
    ///
    /// Elles sont **strictement locales** : jamais transmises, jamais inscrites
    /// dans la chaine, jamais visibles d'un pair. Et elles sont scellees avec le
    /// reste du portefeuille quand une phrase secrete existe — « pour Mathis »
    /// en dit long sur qui l'on frequente, et cela ne regarde personne.
    etiquettes: HashMap<u32, String>,
    /// Indices que le porteur a **demandes** lui-meme : par le bouton
    /// « Nouvelle adresse », par `q21 address`, par `getnewaddress`.
    ///
    /// # Pourquoi cette distinction existe
    ///
    /// Le minage derive une adresse par bloc trouve, et c'est la bonne
    /// granularite : elle evite de relier publiquement toutes les recompenses
    /// entre elles. Mais au bout de quelques jours, un mineur possede un
    /// millier d'adresses qu'il n'a jamais demandees et n'a aucune raison de
    /// distribuer. Les lui presenter comme « ses adresses » noie les deux ou
    /// trois qu'il a reellement donnees a quelqu'un.
    ///
    /// L'ensemble ne change rien au solde ni a la securite : toutes les
    /// adresses derivees restent reconnues et depensables. Il ne sert qu'a
    /// savoir lesquelles montrer en premier.
    demandees: BTreeSet<u32>,
}

/// Efface la graine a la destruction du portefeuille.
///
/// Ne protege pas contre un adversaire qui lit la memoire du processus pendant
/// qu'il tourne, ni contre une page echangee sur disque par le systeme. Ce qu'il
/// evite : qu'une graine trainne dans un tas reutilise, puis dans un fichier de
/// vidage apres un plantage. C'est peu et ce n'est pas rien.
impl Drop for Wallet {
    fn drop(&mut self) {
        crate::kdf::effacer(&mut self.seed);
    }
}

impl Wallet {
    pub fn from_seed(seed: [u8; 32], network: Network) -> Wallet {
        Wallet {
            seed,
            network,
            scheme: SchemeId::LamportOts,
            next_index: 0,
            connues: HashMap::new(),
            consommes: Vec::new(),
            reserves: std::collections::BTreeMap::new(),
            verifie_jusqu_a: 0,
            etiquettes: HashMap::new(),
            demandees: BTreeSet::new(),
        }
    }

    /// Portefeuille sur un schema choisi.
    ///
    /// Deux refus possibles, et aucun n'est negociable :
    /// - le schema n'est pas autorise sur ce reseau (Lamport hors reseau de test) ;
    /// - le schema n'est pas compile dans ce binaire.
    ///
    /// Le second cas est le plus insidieux : un portefeuille qui derive des
    /// adresses ML-DSA sans savoir signer produirait des fonds inaccessibles.
    /// On echoue a la construction plutot qu'a la depense.
    pub fn from_seed_scheme(
        seed: [u8; 32],
        network: Network,
        scheme: SchemeId,
    ) -> Result<Wallet, WalletError> {
        if !scheme.allowed_on(network) || !scheme.disponible() {
            return Err(WalletError::SchemaNonSupporte(scheme));
        }
        Ok(Wallet {
            seed,
            network,
            scheme,
            next_index: 0,
            connues: HashMap::new(),
            consommes: Vec::new(),
            reserves: std::collections::BTreeMap::new(),
            verifie_jusqu_a: 0,
            etiquettes: HashMap::new(),
            demandees: BTreeSet::new(),
        })
    }

    /// Graine aleatoire tiree du systeme.
    ///
    /// # Ce qui a change en phase 8
    ///
    /// Cette fonction lisait `/dev/urandom` directement. Deux consequences :
    /// elle **echouait sous Windows**, ou ce peripherique n'existe pas, et elle
    /// ne verifiait rien de ce qu'elle obtenait. Une source degradee — machine
    /// virtuelle mal configuree, conteneur exotique — aurait produit une graine
    /// previsible sans qu'aucun message ne l'indique, et les fonds auraient ete
    /// perdus des le premier versement.
    ///
    /// Elle passe desormais par [`crate::rng`], qui interroge le generateur du
    /// systeme sur chaque plateforme et **echoue plutot que de rendre un alea de
    /// qualite inconnue**.
    pub fn generate(network: Network) -> Result<Wallet, crate::rng::RngError> {
        Ok(Wallet::from_seed(crate::rng::octets()?, network))
    }

    /// Portefeuille aleatoire sur un schema choisi.
    pub fn generate_scheme(network: Network, scheme: SchemeId) -> Result<Wallet, WalletError> {
        let seed = crate::rng::octets().map_err(|_| WalletError::AleaIndisponible)?;
        Wallet::from_seed_scheme(seed, network, scheme)
    }

    /// Code de sauvegarde de la graine, en Bech32m.
    ///
    /// # Pourquoi pas simplement l'hexadecimal
    ///
    /// La graine etait rendue sur soixante-quatre caracteres hexadecimaux, sans
    /// aucun controle. Recopier ce genre de chaine a la main est une operation
    /// ou l'on se trompe — et une seule faute de frappe donne une graine
    /// parfaitement valide qui n'ouvre rien. La perte est silencieuse et
    /// definitive.
    ///
    /// Bech32m (BIP 350) est concu exactement pour cela : alphabet sans
    /// caracteres confondables — pas de `1`/`l`, pas de `0`/`o` — et somme de
    /// controle qui **detecte jusqu'a quatre erreurs** et signale leur position
    /// approximative. C'est le meme encodage que les adresses Q21, deja
    /// implemente et deja teste.
    ///
    /// Le prefixe designe le reseau : une graine de test ne peut pas etre prise
    /// pour une graine du reseau principal.
    pub fn backup_code(&self) -> String {
        crate::bech32::encode(hrp_graine(self.network), &self.seed)
            .expect("32 octets encodent toujours")
    }

    /// Retrouve une graine depuis son code de sauvegarde.
    pub fn seed_from_backup(code: &str, network: Network) -> Result<[u8; 32], WalletError> {
        // L'alphabet Bech32m d'un code de sauvegarde ne contient aucun blanc.
        // Un copier-coller peut pourtant en glisser un au milieu — un retour a
        // la ligne, une tabulation, une espace insecable, un caractere de
        // largeur nulle. On les retire tous avant de decoder, pour qu'un code
        // correct soit toujours accepte, quelle que soit sa mise en forme.
        let nettoye: String = code
            .chars()
            .filter(|c| {
                !c.is_whitespace()
                    && !matches!(
                        *c,
                        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{00AD}'
                    )
            })
            .collect();
        let code = nettoye.as_str();
        // Une adresse de reception collee ici est reconnue a son prefixe,
        // avant meme de decoder : c'est le cas de confusion le plus probable,
        // et il merite sa propre reponse plutot que le verdict generique.
        if let Some((prefixe, _)) = code.rsplit_once('1') {
            if Network::from_hrp(&prefixe.to_ascii_lowercase()).is_some() {
                return Err(WalletError::SauvegardeEstUneAdresse);
            }
        }
        let (hrp, donnees) =
            crate::bech32::decode(code).map_err(|_| WalletError::SauvegardeInvalide)?;
        if hrp != hrp_graine(network) {
            return Err(WalletError::SauvegardeAutreReseau);
        }
        if donnees.len() != 32 {
            return Err(WalletError::SauvegardeInvalide);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&donnees);
        Ok(seed)
    }

    pub fn seed_hex(&self) -> String {
        self.seed.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn seed_from_hex(s: &str) -> Option<[u8; 32]> {
        Hash256::from_hex(s).map(|h| h.0)
    }

    /// Clef d'authentification du cache d'adresses.
    ///
    /// Un cache d'adresses ne contient aucun secret — une empreinte de clef
    /// publique est publique par construction. Mais il *designe* les clefs que
    /// le portefeuille croit siennes, et une seule entree substituee suffisait
    /// a lui faire signer avec la mauvaise clef. Le cache doit donc etre
    /// authentifie : seul le detenteur de la graine peut en produire un que ce
    /// portefeuille acceptera.
    ///
    /// La clef est **derivee** de la graine, jamais la graine elle-meme :
    /// meme un fichier de cache fuite ne dit rien des clefs privees.
    pub fn clef_cache(&self) -> [u8; 32] {
        self.empreinte_publique(b"Q21-CACHE-ADRESSES-v1")
    }

    /// Une empreinte publique de la graine sous une etiquette :
    /// `HMAC(graine, etiquette)`.
    ///
    /// Elle ne dit rien de la graine — HMAC sous une clef secrete est une
    /// fonction pseudo-aleatoire — mais elle suffit a reconnaitre la meme
    /// graine d'une fois sur l'autre, ou a en distinguer une autre. C'est ce
    /// qui ancre un dossier de donnees a *son* portefeuille : un fichier d'une
    /// autre graine y est reconnu comme etranger. Chaque usage a son
    /// etiquette, pour qu'une empreinte ne serve jamais a deux choses.
    pub fn empreinte_publique(&self, etiquette: &[u8]) -> [u8; 32] {
        crate::kdf::hmac_sha256(&self.seed, etiquette)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn scheme(&self) -> SchemeId {
        self.scheme
    }

    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    fn key(&self, index: u32) -> SecretKey {
        SecretKey::from_seed(self.seed, index)
    }

    /// Graine privee de l'indice `index`, pour les schemas autres que Lamport.
    ///
    /// Le schema entre dans la derivation : deux portefeuilles issus de la meme
    /// graine mais de schemas differents n'ont aucune clef en commun. Sans cela,
    /// une meme valeur secrete servirait a deux cryptographies distinctes, ce qui
    /// est exactement le genre de reutilisation qui finit mal.
    #[cfg_attr(not(feature = "mldsa"), allow(dead_code))]
    fn graine_derivee(&self, index: u32) -> [u8; 32] {
        tagged_hash_parts(
            tags::WALLET_SEED,
            &[&self.seed, &index.to_le_bytes(), &[self.scheme.as_u8()]],
        )
        .0
    }

    /// Clef publique de l'indice `index`.
    ///
    /// # Panique
    ///
    /// Si le schema du portefeuille n'est pas disponible. C'est un invariant
    /// etabli a la construction ([`Wallet::from_seed_scheme`]) : y arriver
    /// signifierait que le portefeuille a ete fabrique par un chemin qui ne
    /// valide pas son propre schema.
    fn public_key(&self, index: u32) -> Vec<u8> {
        match self.scheme {
            SchemeId::LamportOts => self.key(index).public_key(),
            #[cfg(feature = "mldsa")]
            SchemeId::MlDsa65 => {
                let mut g = self.graine_derivee(index);
                let pk = mldsa_wallet::public_key::<ml_dsa::MlDsa65>(&g);
                crate::kdf::effacer(&mut g);
                pk
            }
            #[cfg(feature = "mldsa")]
            SchemeId::MlDsa87 => {
                let mut g = self.graine_derivee(index);
                let pk = mldsa_wallet::public_key::<ml_dsa::MlDsa87>(&g);
                crate::kdf::effacer(&mut g);
                pk
            }
            autre => panic!("portefeuille sur un schema indisponible : {}", autre.name()),
        }
    }

    /// Signe `message` avec l'indice `index`.
    ///
    /// ML-DSA signe en variante « hedged » : trente-deux octets d'alea du
    /// systeme entrent dans chaque signature. Si l'alea manque, on **refuse de
    /// signer** plutot que de retomber sur la variante deterministe — voir
    /// `mldsa_wallet::sign`.
    ///
    /// # Panique
    ///
    /// Meme invariant que [`Wallet::public_key`].
    fn sign_at(&self, index: u32, message: &Hash256) -> Result<Vec<u8>, WalletError> {
        match self.scheme {
            SchemeId::LamportOts => Ok(self.key(index).sign(message)),
            #[cfg(feature = "mldsa")]
            SchemeId::MlDsa65 => {
                let mut g = self.graine_derivee(index);
                let sig = mldsa_wallet::sign::<ml_dsa::MlDsa65>(&g, message);
                crate::kdf::effacer(&mut g);
                sig
            }
            #[cfg(feature = "mldsa")]
            SchemeId::MlDsa87 => {
                let mut g = self.graine_derivee(index);
                let sig = mldsa_wallet::sign::<ml_dsa::MlDsa87>(&g, message);
                crate::kdf::effacer(&mut g);
                sig
            }
            autre => panic!("portefeuille sur un schema indisponible : {}", autre.name()),
        }
    }

    /// Produit une adresse neuve, jamais employee.
    ///
    /// Chaque appel consomme un indice. Avec Lamport c'est obligatoire, pas une
    /// bonne pratique de confidentialite.
    pub fn new_address(&mut self) -> Address {
        let index = self.next_index;
        self.next_index += 1;
        let h = pubkey_hash(self.scheme, &self.public_key(index));
        self.connues.insert(h, index);
        Address {
            network: self.network,
            scheme: self.scheme,
            hash: h,
        }
    }

    /// Produit une adresse neuve **a la demande du porteur**, et s'en souvient.
    ///
    /// C'est la seule difference avec [`Wallet::new_address`] : l'indice est
    /// note comme demande, pour que l'interface la presente parmi les adresses
    /// que le porteur a reellement distribuees, et non parmi les centaines que
    /// le minage derive tout seul.
    pub fn demander_adresse(&mut self) -> Address {
        let a = self.new_address();
        self.demandees.insert(self.next_index - 1);
        a
    }

    /// Cette adresse a-t-elle ete demandee par le porteur, plutot que derivee
    /// par le minage ou par une restauration ?
    pub fn est_demandee(&self, indice: u32) -> bool {
        self.demandees.contains(&indice)
    }

    /// Indices demandes par le porteur, tries, pour l'ecriture du portefeuille.
    pub fn indices_demandes(&self) -> Vec<u32> {
        self.demandees.iter().copied().collect()
    }

    /// Reinstalle les indices demandes lus dans le fichier.
    ///
    /// Un fichier ecrit avant l'arrivee de cette distinction n'a pas la ligne :
    /// toutes ses adresses passent alors pour derivees par le minage, et le
    /// porteur les retrouve en les cherchant ou en les nommant. Rien n'est
    /// perdu, seul l'ordre de presentation change.
    pub fn charger_demandees(&mut self, indices: &[u32]) {
        self.demandees.extend(indices.iter().copied());
    }

    /// Rejoue la derivation pour retrouver les adresses apres un redemarrage.
    pub fn rescan(&mut self, jusqu_a: u32) {
        for index in 0..jusqu_a {
            let h = pubkey_hash(self.scheme, &self.public_key(index));
            self.connues.insert(h, index);
        }
        self.next_index = self.next_index.max(jusqu_a);
    }

    /// Ecart de decouverte : combien d'adresses vides on derive avant de
    /// conclure qu'il n'y a plus rien.
    ///
    /// La valeur est celle qu'emploie l'ecosysteme depuis BIP44, et elle n'a pas
    /// ete choisie au hasard : elle couvre le cas d'un porteur qui aurait
    /// distribue des dizaines d'adresses sans qu'aucune soit payee, tout en
    /// bornant le cout d'une restauration. Chaque indice derive une clef ML-DSA,
    /// ce qui n'est pas gratuit.
    pub const ECART_DECOUVERTE: u32 = 200;

    /// Retrouve les adresses de ce portefeuille en interrogeant un ensemble de
    /// sorties, et avance l'indice au-dela de la derniere trouvee.
    ///
    /// # Le defaut que cette fonction repare
    ///
    /// Un portefeuille restaure depuis son code de sauvegarde ne connaissait que
    /// les adresses qu'il avait lui-meme derivees — c'est-a-dire aucune. Il
    /// affichait donc **zero** sur une chaine qui contenait ses fonds. La
    /// promesse « ce code suffit a tout retrouver » etait fausse, et l'essai qui
    /// l'a montre tient en trois commandes : creer, miner, restaurer ailleurs.
    ///
    /// # Comment elle procede
    ///
    /// Elle derive par fenetres de [`Self::ECART_DECOUVERTE`] indices et demande
    /// pour chacun si `possede` le reconnait. Des qu'une fenetre trouve quelque
    /// chose, on repart apres la trouvaille ; quand une fenetre entiere ne
    /// trouve rien, on s'arrete. C'est la regle de l'ecart, celle que tous les
    /// portefeuilles deterministes emploient.
    ///
    /// Rend le nombre d'adresses reconnues.
    pub fn decouvrir<F>(&mut self, possede: F) -> usize
    where
        F: Fn(&Hash256) -> bool,
    {
        let mut trouvees = 0usize;
        // Dernier indice **inclus** qui a servi, s'il y en a un.
        let mut dernier: Option<u32> = None;
        let mut i: u32 = 0;
        // `checked_add` borne la boucle : au bout des indices possibles, on
        // s'arrete plutot que de reboucler a zero.
        while let Some(fin) = i.checked_add(Self::ECART_DECOUVERTE) {
            let mut vu_dans_la_fenetre = false;
            for index in i..fin {
                let h = pubkey_hash(self.scheme, &self.public_key(index));
                self.connues.insert(h, index);
                if possede(&h) {
                    trouvees += 1;
                    dernier = Some(index);
                    vu_dans_la_fenetre = true;
                }
            }
            if !vu_dans_la_fenetre {
                break;
            }
            i = fin;
        }
        // L'indice suivant se place apres la derniere adresse qui a servi. On ne
        // le place pas apres la derniere **derivee** : cela sauterait les deux
        // cents indices vides que la fenetre vient d'explorer, et un porteur qui
        // restaure deux fois de suite les sauterait deux fois.
        if let Some(d) = dernier {
            self.next_index = self.next_index.max(d + 1);
        }
        trouvees
    }

    /// Rattrape les adresses distribuees mais jamais enregistrees.
    ///
    /// # Le defaut que ceci ferme
    ///
    /// Le minage derive une adresse par bloc trouve, et le portefeuille
    /// n'etait ecrit qu'a l'arret propre. Apres une coupure — courant, `kill`,
    /// carte SD retiree — `next_index` reculait sur le disque, et les
    /// recompenses des blocs trouves depuis restaient invisibles : le
    /// portefeuille voyait *des* fonds, donc la decouverte de restauration ne
    /// se declenchait pas, et rien ne se reparait jamais. Mesure : 16 Q21
    /// affiches pour 803 reellement detenus.
    ///
    /// Ici on ne repart pas de zero : on derive une fenetre **au-dela** de
    /// `next_index`, et on avance tant qu'on y trouve quelque chose. Quand
    /// rien ne manque, c'est une fenetre de clefs derivee pour rien — quelques
    /// dizaines de millisecondes, une fois par demarrage.
    pub fn rattraper<F>(&mut self, possede: F) -> usize
    where
        F: Fn(&Hash256) -> bool,
    {
        let mut trouvees = 0usize;
        let mut dernier: Option<u32> = None;
        let mut i: u32 = self.next_index;
        while let Some(fin) = i.checked_add(Self::ECART_DECOUVERTE) {
            let mut vu = false;
            for index in i..fin {
                let h = pubkey_hash(self.scheme, &self.public_key(index));
                if possede(&h) {
                    self.connues.insert(h, index);
                    trouvees += 1;
                    dernier = Some(index);
                    vu = true;
                }
            }
            if !vu {
                break;
            }
            i = fin;
        }
        if let Some(d) = dernier {
            // Les indices intermediaires, eux aussi distribues, sont reconnus.
            for index in self.next_index..=d {
                let h = pubkey_hash(self.scheme, &self.public_key(index));
                self.connues.insert(h, index);
            }
            self.next_index = self.next_index.max(d + 1);
        }
        trouvees
    }

    /// Empreintes deja derivees, dans l'ordre des indices.
    pub fn known_hashes(&self) -> Vec<Hash256> {
        let mut v: Vec<(u32, Hash256)> = self.connues.iter().map(|(h, i)| (*i, *h)).collect();
        v.sort_unstable();
        v.into_iter().map(|(_, h)| h).collect()
    }

    /// Recharge les empreintes depuis un cache local, sans rederiver.
    ///
    /// # Pourquoi ce cache existe
    ///
    /// [`Wallet::rescan`] rederive chaque adresse. Avec Lamport c'etait une
    /// poignee de condensats ; avec ML-DSA c'est une generation de clef a
    /// reseaux euclidiens par adresse. Un portefeuille de soixante mille
    /// adresses demandait vingt secondes **a chaque demarrage** — plus que toute
    /// la revalidation de la chaine.
    ///
    /// # Pourquoi il n'est pas cru sur parole
    ///
    /// Un cache issu d'une autre graine ou d'un autre schema ferait croire au
    /// portefeuille qu'il detient des fonds qu'il ne saura pas depenser.
    ///
    /// La version precedente ne resondait que la premiere et la derniere
    /// empreinte. Un audit a substitue **une seule** entree au milieu : elle
    /// passait. Le portefeuille croyait alors posseder l'adresse de
    /// l'attaquant, affichait ses fonds a la place des siens, et — pire —
    /// signait une depense avec une clef Lamport qui n'ouvrait pas ce verrou :
    /// une clef brulee pour une transaction que le reseau rejetait.
    ///
    /// On resonde desormais un **echantillon reparti** de racine de `n`
    /// indices, extremites comprises. Le cout reste negligeable — 245
    /// derivations pour soixante mille adresses, quelques dizaines de
    /// millisecondes — et une substitution en masse ne passe plus.
    ///
    /// # Ce que l'echantillon ne suffit pas a garantir
    ///
    /// Une substitution unique et bien placee peut encore echapper au tirage.
    /// Elle est neutralisee ailleurs, par deux barrieres qui, elles, ne sont pas
    /// probabilistes :
    ///
    /// - le cache sur disque est **scelle** par une clef derivee de la graine
    ///   ([`Wallet::clef_cache`]) : un tiers ne peut pas en fabriquer un ;
    /// - [`Wallet::create_transaction`] verifie, avant de signer, que la clef
    ///   derivee ouvre bien le verrou de la sortie depensee.
    ///
    /// Rend `false` si le cache est refuse ; l'appelant doit alors appeler
    /// [`Wallet::rescan`].
    pub fn adopt_hashes(&mut self, hashes: &[Hash256]) -> bool {
        if hashes.is_empty() {
            return true;
        }
        let n = hashes.len();
        let dernier = n - 1;

        // En dessous du seuil, on verifie **tout**. C'est le cas de la quasi-
        // totalite des portefeuilles reels, et un echantillon y serait un luxe
        // paye par un trou : sur six adresses, une substitution au troisieme
        // rang passait entre les points de controle.
        //
        // Au-dela, le cout de la derivation complete est precisement ce que ce
        // cache existe pour eviter : on retombe sur un echantillon reparti.
        let mut pas = if n <= SEUIL_VERIFICATION_COMPLETE {
            1
        } else {
            (n as f64).sqrt() as usize
        };
        if pas == 0 {
            pas = 1;
        }

        let mut i = 0usize;
        loop {
            if pubkey_hash(self.scheme, &self.public_key(i as u32)) != hashes[i] {
                return false;
            }
            if i == dernier {
                break;
            }
            i = (i + pas).min(dernier);
        }

        for (i, h) in hashes.iter().enumerate() {
            self.connues.insert(*h, i as u32);
        }
        self.next_index = self.next_index.max(hashes.len() as u32);
        true
    }

    pub fn owns(&self, h: &Hash256) -> bool {
        self.connues.contains_key(h)
    }

    /// Le portefeuille reconnait-il au moins une sortie non depensee de cet
    /// ensemble comme etant la sienne ?
    ///
    /// C'est le vrai signal d'un portefeuille « a jour » : non pas le nombre
    /// d'adresses qu'il a derivees, mais le fait qu'il **voie ses fonds**. Un
    /// portefeuille restaure puis simplement ouvert a deja derive quelques
    /// adresses — la page d'accueil en tire une — sans pour autant reconnaitre
    /// le moindre de ses avoirs sur la chaine. C'est ce cas que la decouverte
    /// doit rattraper, et que l'ancien declencheur `next_index <= 1` manquait.
    pub fn voit_des_fonds(&self, utxo: &crate::utxo::UtxoSet) -> bool {
        self.connues.keys().any(|h| utxo.connait(h))
    }

    /// Cet indice a-t-il deja servi a signer ?
    ///
    /// Pour un schema a usage unique, la reponse `true` est definitive : la clef
    /// est morte. L'exposer permet de verifier qu'un refus n'a **rien** brule.
    pub fn est_consomme(&self, index: u32) -> bool {
        self.consommes.contains(&index)
    }

    /// Indices deja employes pour signer, tries.
    ///
    /// Cette liste **doit** etre persistee. Elle ne l'etait pas : elle mourait
    /// avec le processus. Un portefeuille Lamport redemarre repartait donc avec
    /// une ardoise vierge, et deux signatures d'une meme clef Lamport revelent
    /// la clef privee.
    ///
    /// Ne contient que les clefs **revelees**. Les indices seulement reserves
    /// sont rendus par [`Wallet::indices_reserves`], et la ligne du fichier
    /// par [`Wallet::indices_consommes_pour_le_fichier`].
    pub fn indices_consommes(&self) -> Vec<u32> {
        let mut v = self.consommes.clone();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Cet indice est-il reserve pour une depense en cours ?
    pub fn est_reserve(&self, index: u32) -> bool {
        self.reserves.contains_key(&index)
    }

    /// Indices reserves, avec la hauteur de leur reservation, tries.
    pub fn indices_reserves(&self) -> Vec<(u32, u64)> {
        self.reserves.iter().map(|(i, h)| (*i, *h)).collect()
    }

    /// Ce que la ligne `consommes=` du fichier doit porter : les clefs
    /// revelees **et** les indices reserves.
    ///
    /// Un indice reserve y figure a dessein. Un binaire anterieur, qui ignore
    /// la ligne `reserves=`, le tiendra pour consomme : c'est le sens prudent,
    /// celui qui ne resigne jamais. Le binaire courant le retire de
    /// `consommes` en relisant `reserves=` ([`Wallet::charger_reservations`]).
    pub fn indices_consommes_pour_le_fichier(&self) -> Vec<u32> {
        let mut v = self.consommes.clone();
        v.extend(self.reserves.keys().copied());
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Reinstalle les reservations lues dans le fichier.
    ///
    /// Chaque indice est retire de `consommes` — ou il figure aussi, par
    /// prudence pour les lecteurs anciens — et redevient une reservation, qui
    /// sera confirmee ou levee par [`Wallet::reexaminer_reservations`]. Un
    /// indice que le fichier donne comme consomme sans le donner comme reserve
    /// reste consomme : on ne libere jamais sur un doute.
    pub fn charger_reservations(&mut self, reservations: &[(u32, u64)]) {
        for (i, h) in reservations {
            if !self.reserves.contains_key(i) {
                self.consommes.retain(|c| c != i);
                self.reserves.insert(*i, *h);
            }
        }
    }

    /// Blocs apres lesquels une reservation sans signature dans la chaine est
    /// levee.
    ///
    /// Vingt blocs, soit une quarantaine de minutes a la cadence cible. Une
    /// transaction diffusee est minee bien avant ; une reservation encore la
    /// au bout de ce delai est celle d'un processus mort entre la reservation
    /// et la diffusion — la piece n'a pas a rester figee pour cela. Le risque
    /// residuel est une transaction signee, annoncee, jamais minee en vingt
    /// blocs puis minee ensuite : elle entrerait en conflit avec la depense
    /// suivante de la meme piece, et les deux signatures seraient publiques.
    /// C'est la limite acceptee, et elle ne concerne que les reseaux d'essai.
    pub const DELAI_RESERVATION: u64 = 20;

    /// Reexamine les reservations a la lumiere de la chaine.
    ///
    /// `lire_bloc` rend le bloc actif a une hauteur, s'il est disponible. Pour
    /// chaque reservation dont le delai est ecoule, les blocs ecrits depuis la
    /// reservation sont relus a la recherche d'une signature de cette clef :
    /// trouvee, l'indice est consomme ; absente, il redevient libre. Une
    /// reservation plus jeune que le delai est laissee telle quelle. Si un
    /// bloc de la fenetre manque, on ne libere rien : liberer sur une
    /// lecture incomplete serait liberer sur un doute.
    ///
    /// Rend `(confirmees, liberees)`.
    pub fn reexaminer_reservations<L>(&mut self, hauteur: u64, lire_bloc: L) -> (usize, usize)
    where
        L: Fn(u64) -> Option<crate::block::Block>,
    {
        let echues: Vec<(u32, u64)> = self
            .reserves
            .iter()
            .filter(|(_, h)| hauteur >= h.saturating_add(Self::DELAI_RESERVATION))
            .map(|(i, h)| (*i, *h))
            .collect();
        if echues.is_empty() {
            return (0, 0);
        }
        let depuis = echues.iter().map(|(_, h)| *h).min().unwrap_or(hauteur);
        let mut complet = true;
        for h in depuis..=hauteur {
            match lire_bloc(h) {
                Some(b) => {
                    self.noter_depenses(&b);
                }
                None => complet = false,
            }
        }
        let confirmees = echues
            .iter()
            .filter(|(i, _)| self.consommes.contains(i))
            .count();
        let mut liberees = 0;
        if complet {
            for (i, _) in &echues {
                if self.reserves.remove(i).is_some() {
                    liberees += 1;
                }
            }
        }
        (confirmees, liberees)
    }

    /// Montant immobilise par les reservations en cours, pour que l'interface
    /// puisse nommer ce qui manque au solde et pourquoi.
    pub fn montant_reserve(&self, utxo: &UtxoSet, hauteur: u64) -> Amount {
        if !self.scheme.est_a_usage_unique() {
            return Amount::ZERO;
        }
        let mut total: u64 = 0;
        for (h, index) in &self.connues {
            if !self.reserves.contains_key(index) {
                continue;
            }
            let plus_grosse = utxo
                .spendable_for(h, hauteur, COINBASE_MATURITY)
                .iter()
                .map(|(_, e)| e.output.value.units())
                .max()
                .unwrap_or(0);
            total = total.saturating_add(plus_grosse);
        }
        Amount::from_units(total)
    }

    /// Hauteur jusqu'a laquelle la chaine a deja ete balayee.
    pub fn verifie_jusqu_a(&self) -> u64 {
        self.verifie_jusqu_a
    }

    /// Pose, remplace ou retire l'etiquette d'une adresse.
    ///
    /// Une chaine vide — ou faite d'espaces — **retire** l'etiquette plutot
    /// que d'en enregistrer une invisible : sinon le carnet se remplit de
    /// lignes vides qu'on ne peut plus distinguer d'une adresse sans nom.
    ///
    /// Le texte est borne a [`Wallet::ETIQUETTE_MAX`] caracteres. La coupure
    /// se fait sur les **caracteres** et non sur les octets : couper un octet
    /// au milieu d'un accent produirait une chaine qui n'est pas de l'UTF-8, et
    /// le fichier du portefeuille deviendrait illisible. C'est un carnet, pas
    /// un journal intime : un nom, un prenom, un motif court.
    pub fn etiqueter(&mut self, indice: u32, texte: &str) {
        let propre: String = texte
            .trim()
            // Les sauts de ligne et les tabulations casseraient le format du
            // fichier, qui est une ligne par clef. On les remplace plutot que
            // de refuser : l'utilisateur a colle un texte, il ne veut pas d'un
            // message d'erreur.
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(Self::ETIQUETTE_MAX)
            .collect();
        let propre = propre.trim().to_string();
        if propre.is_empty() {
            self.etiquettes.remove(&indice);
        } else {
            self.etiquettes.insert(indice, propre);
        }
    }

    /// Longueur maximale d'une etiquette, en caracteres.
    pub const ETIQUETTE_MAX: usize = 64;

    /// L'etiquette d'une adresse, s'il y en a une.
    pub fn etiquette(&self, indice: u32) -> Option<&str> {
        self.etiquettes.get(&indice).map(|s| s.as_str())
    }

    /// Toutes les etiquettes, pour l'ecriture du portefeuille.
    pub fn etiquettes(&self) -> &HashMap<u32, String> {
        &self.etiquettes
    }

    /// Reinstalle les etiquettes lues dans le fichier.
    pub fn charger_etiquettes(&mut self, e: HashMap<u32, String>) {
        self.etiquettes = e;
    }

    /// Note qu'un balayage a couvert la chaine jusqu'a cette hauteur.
    ///
    /// Ne recule jamais : une verification acquise ne se perd pas.
    pub fn noter_verification(&mut self, hauteur: u64) {
        self.verifie_jusqu_a = self.verifie_jusqu_a.max(hauteur);
    }

    /// Oublie jusqu'ou la chaine a ete verifiee : a n'employer que lorsque la
    /// chaine elle-meme a change — un reseau de test reparti d'une nouvelle
    /// genese. Les hauteurs de l'ancienne chaine n'y designent plus rien, et
    /// les garder ferait sauter le balayage des premiers blocs de la nouvelle.
    pub fn oublier_la_verification(&mut self) {
        self.verifie_jusqu_a = 0;
    }

    /// Declare des indices comme deja employes.
    ///
    /// Sert au rechargement depuis le disque et a l'observation de la chaine.
    /// L'ensemble ne fait que croitre : on n'efface jamais une consommation,
    /// puisque l'oublier est precisement le defaut a corriger.
    pub fn marquer_consommes(&mut self, indices: &[u32]) {
        for i in indices {
            if !self.consommes.contains(i) {
                self.consommes.push(*i);
            }
        }
    }

    /// Observe un bloc et marque comme consommee toute clef qui y a signe.
    ///
    /// # Pourquoi la chaine est la meilleure source
    ///
    /// Un fichier peut etre remplace par une version anterieure ; la chaine,
    /// non — elle est adossee a la preuve de travail. Si une signature de ce
    /// portefeuille figure dans un bloc, la clef correspondante a ete revelee
    /// une fois, point final. C'est un constat, pas une comptabilite.
    ///
    /// Rend le nombre d'indices nouvellement marques.
    pub fn noter_depenses(&mut self, bloc: &crate::block::Block) -> usize {
        let mut nouveaux = 0;
        for tx in &bloc.transactions {
            for entree in &tx.inputs {
                if entree.witness.pubkey.is_empty() {
                    continue; // coinbase
                }
                let h = pubkey_hash(self.scheme, &entree.witness.pubkey);
                if let Some(index) = self.connues.get(&h).copied() {
                    // Une signature dans un bloc leve la reservation : la
                    // clef n'est plus reservee, elle est revelee.
                    self.reserves.remove(&index);
                    if !self.consommes.contains(&index) {
                        self.consommes.push(index);
                        nouveaux += 1;
                    }
                }
            }
        }
        nouveaux
    }

    /// Balaie les blocs actifs depuis la derniere hauteur verifiee, et note
    /// les clefs de ce portefeuille qui y ont signe.
    ///
    /// # Le defaut que ceci ferme
    ///
    /// Le balayage n'existait qu'au chargement. Sur une machine neuve, l'ordre
    /// est inverse — on restaure, *puis* la chaine arrive — et la decouverte
    /// d'adresses se faisait dans la boucle du noeud sans relire un seul bloc.
    /// Jusqu'au redemarrage suivant, une clef Lamport deja revelee dans un
    /// bloc etait annoncee depensable, et le portefeuille signait une seconde
    /// fois. Le noeud appelle ceci apres toute decouverte fructueuse, et
    /// l'envoi de fonds l'appelle avant de choisir ses pieces.
    ///
    /// `lire_bloc` rend le bloc actif a une hauteur, s'il est disponible. Le
    /// balayage s'arrete au premier bloc manquant, et la hauteur verifiee
    /// n'avance que jusque-la : on ne declare pas verifie ce qu'on n'a pas lu.
    /// Rend le nombre de clefs nouvellement marquees.
    pub fn balayer_la_chaine<L>(&mut self, hauteur: u64, lire_bloc: L) -> usize
    where
        L: Fn(u64) -> Option<crate::block::Block>,
    {
        let mut trouves = 0usize;
        let mut h = self.verifie_jusqu_a.saturating_add(1);
        while h <= hauteur {
            match lire_bloc(h) {
                Some(b) => trouves += self.noter_depenses(&b),
                None => break,
            }
            self.verifie_jusqu_a = h;
            h += 1;
        }
        trouves
    }

    /// Associe de force une empreinte a un indice, pour les epreuves d'audit.
    ///
    /// N'existe que dans les compilations de test : c'est precisement l'etat
    /// incoherent qu'un cache falsifie produirait, et il faut pouvoir le
    /// fabriquer pour prouver que la barriere de signature tient.
    #[cfg(any(test, feature = "audit"))]
    pub fn forcer_association_pour_epreuve(&mut self, empreinte: Hash256, index: u32) {
        self.connues.insert(empreinte, index);
    }

    /// Sorties reellement depensables appartenant au portefeuille.
    ///
    /// « Reellement » n'est pas un ornement. Avec un schema a usage unique, une
    /// clef ne signe qu'une fois : si une adresse a recu deux paiements — parce
    /// que celui qui paie a reutilise l'adresse — une seule des deux pieces
    /// pourra jamais etre depensee. Les annoncer toutes reviendrait a afficher
    /// un solde que la depense refuserait ensuite, sans explication. Cette
    /// methode ne rend donc que ce qui est vrai ; [`Wallet::montant_fige`] dit
    /// ce qui manque et pourquoi.
    pub fn spendable(&self, utxo: &UtxoSet, hauteur: u64) -> Vec<(OutPoint, TxOut, u32)> {
        let usage_unique = self.scheme.est_a_usage_unique();
        let mut v = Vec::new();
        for (h, index) in &self.connues {
            // Une clef Lamport consommee est morte : les fonds qu'elle garde ne
            // sont plus depensables sans reveler la clef privee. ML-DSA n'a pas
            // cette contrainte, et masquer ses fonds serait un bogue.
            if usage_unique && (self.consommes.contains(index) || self.reserves.contains_key(index))
            {
                continue;
            }
            let pieces = utxo.spendable_for(h, hauteur, COINBASE_MATURITY);
            if usage_unique {
                // Une seule piece par indice, et la plus grosse : c'est celle
                // qui laisse le plus de valeur accessible. A montant egal, le
                // point de sortie departage, pour que deux executions du meme
                // portefeuille choisissent toujours la meme piece.
                if let Some((o, e)) =
                    pieces
                        .into_iter()
                        .max_by_key(|(o, e): &(OutPoint, crate::utxo::UtxoEntry)| {
                            (e.output.value.units(), std::cmp::Reverse(*o))
                        })
                {
                    v.push((o, e.output, *index));
                }
            } else {
                for (o, e) in pieces {
                    v.push((o, e.output, *index));
                }
            }
        }
        v.sort_by_key(|(o, _, _)| *o);
        v
    }

    /// Montant immobilise par la discipline d'usage unique, et par elle seule.
    ///
    /// Une clef Lamport ne signe qu'une fois. Deux pieces sur la meme adresse,
    /// c'est donc une piece depensable et une piece figee : signer les deux
    /// revelerait la clef privee, et le portefeuille refuse de le faire.
    ///
    /// Cette somme appartient bien a l'utilisateur et ne se depensera pourtant
    /// jamais. La taire serait le pire choix possible — il verrait un solde
    /// diminuer sans cause, ou une depense echouer sans raison affichee. On la
    /// nomme donc, pour que l'interface puisse l'expliquer.
    ///
    /// Vaut toujours zero pour un schema sans usage unique (ML-DSA).
    pub fn montant_fige(&self, utxo: &UtxoSet, hauteur: u64) -> Amount {
        if !self.scheme.est_a_usage_unique() {
            return Amount::ZERO;
        }
        let mut total: u64 = 0;
        for (h, index) in &self.connues {
            let pieces = utxo.spendable_for(h, hauteur, COINBASE_MATURITY);
            let somme = pieces
                .iter()
                .fold(0u64, |a, (_, e)| a.saturating_add(e.output.value.units()));
            // Clef deja employee : tout ce qui reste dessus est fige. Sinon,
            // tout sauf la piece que `spendable` retiendra.
            let retenue = if self.consommes.contains(index) {
                0
            } else {
                pieces
                    .iter()
                    .map(|(_, e)| e.output.value.units())
                    .max()
                    .unwrap_or(0)
            };
            total = total.saturating_add(somme.saturating_sub(retenue));
        }
        Amount::from_units(total)
    }

    /// Ce qui appartient au portefeuille mais n'est pas encore mur, et la
    /// hauteur a laquelle la **prochaine** part se liberera.
    ///
    /// # Pourquoi passer par l'index
    ///
    /// L'interface interrogeait ce montant en parcourant **tout** le jeu d'UTXO,
    /// et le faisait toutes les six secondes, sous le verrou global — celui qui
    /// sert aussi a valider les blocs. Sur une chaine mure, chaque portefeuille
    /// ouvert aurait donc fige la validation a intervalle regulier, sans que
    /// personne ne fasse le rapprochement : c'est son propre portefeuille qui
    /// ralentit son propre noeud.
    ///
    /// Le portefeuille connait ses adresses, et le jeu d'UTXO sait les retrouver
    /// par son index. Le prix passe de la taille du jeu entier au nombre de
    /// sorties reellement detenues.
    ///
    /// # Ce que la seconde valeur apporte
    ///
    /// « Quand ? » est la question qu'on pose devant un solde bloque. Rendre la
    /// hauteur de la prochaine liberation et le montant qu'elle porte permet
    /// d'afficher un compte a rebours plutot qu'un mystere. A hauteur egale les
    /// montants se cumulent : plusieurs sorties d'un meme bloc se liberent
    /// ensemble.
    pub fn immature(&self, utxo: &UtxoSet, hauteur: u64) -> (Amount, Option<(u64, Amount)>) {
        let mut total: u64 = 0;
        let mut prochaine: Option<(u64, u64)> = None;
        for empreinte in self.connues.keys() {
            for (_, e) in utxo.sorties_de(empreinte) {
                if !e.is_coinbase || hauteur >= e.height + COINBASE_MATURITY {
                    continue;
                }
                let valeur = e.output.value.units();
                total = total.saturating_add(valeur);
                let libre_a = e.height + COINBASE_MATURITY;
                prochaine = match prochaine {
                    Some((h, m)) if h == libre_a => Some((h, m.saturating_add(valeur))),
                    // On garde toujours la liberation la plus proche.
                    Some((h, m)) if h < libre_a => Some((h, m)),
                    _ => Some((libre_a, valeur)),
                };
            }
        }
        (
            Amount::from_units(total),
            prochaine.map(|(h, m)| (h, Amount::from_units(m))),
        )
    }

    /// Adresses ayant recu plus d'un paiement, avec le nombre de pieces.
    ///
    /// C'est la cause, la ou [`Wallet::montant_fige`] en donne le montant : elle
    /// permet a l'interface de dire *quelle* adresse a ete reutilisee, et donc
    /// d'apprendre a l'utilisateur a ne plus la redonner. Vide pour un schema
    /// sans usage unique.
    pub fn adresses_reutilisees(&self, utxo: &UtxoSet, hauteur: u64) -> Vec<(Hash256, usize)> {
        if !self.scheme.est_a_usage_unique() {
            return Vec::new();
        }
        let mut v: Vec<(Hash256, usize)> = self
            .connues
            .keys()
            .filter_map(|h| {
                let n = utxo.spendable_for(h, hauteur, COINBASE_MATURITY).len();
                (n > 1).then_some((*h, n))
            })
            .collect();
        v.sort_by_key(|(h, _)| *h);
        v
    }

    pub fn balance(&self, utxo: &UtxoSet, hauteur: u64) -> Amount {
        Amount::checked_sum(
            self.spendable(utxo, hauteur)
                .iter()
                .map(|(_, o, _)| o.value),
        )
        .unwrap_or(Amount::ZERO)
    }

    /// Construit et signe une transaction.
    ///
    /// Selection naive des entrees : les plus anciennes d'abord, jusqu'a couvrir
    /// le montant. Suffisant pour la phase 2 ; une vraie selection viendra avec
    /// le portefeuille de la phase 5.
    /// Choisit les pieces a depenser pour couvrir `besoin`.
    ///
    /// # Pourquoi cette selection est exposee
    ///
    /// Les frais dependent de la **taille** de la transaction, et la taille
    /// depend du nombre d'entrees — avec ML-DSA-87 chaque entree porte 7 219
    /// octets de temoin. Or le nombre d'entrees n'est connu qu'apres la
    /// selection.
    ///
    /// Une estimation qui demande a l'appelant de *supposer* un nombre
    /// d'entrees se trompe donc systematiquement. Un essai reel l'a montre :
    /// une estimation faite pour une entree a propose huit unites, la
    /// transaction reelle en a consomme deux, et le reservoir l'a refusee pour
    /// taux de frais trop bas. L'utilisateur voyait un refus incomprehensible
    /// sur une transaction qu'il venait de confirmer.
    ///
    /// Exposer la selection permet d'estimer sur la transaction **qui sera
    /// reellement construite**.
    ///
    /// Rend les pieces choisies et leur total.
    #[allow(clippy::type_complexity)]
    pub fn selectionner(
        &self,
        utxo: &UtxoSet,
        hauteur: u64,
        besoin: u64,
    ) -> Result<(Vec<(OutPoint, TxOut, u32)>, u64), WalletError> {
        let disponibles = self.spendable(utxo, hauteur);

        // Un schema a usage unique (Lamport) ne peut signer qu'une seule fois
        // par clef, jamais deux : signer deux messages differents avec la meme
        // clef en revele les deux preimages, et **livre la clef privee**. Le
        // garde `consommes` ferme ce risque *entre* deux transactions ; il
        // manquait de le fermer *a l'interieur* d'une meme transaction. Deux
        // pieces recues sur le meme indice (une adresse reutilisee par celui qui
        // paie) seraient sinon co-signees ici, chacune sur son propre condensat,
        // et la clef partirait dans le bloc. On n'en retient donc qu'une par
        // indice ; l'autre reste non depensee — une piece figee vaut infiniment
        // mieux qu'une clef brulee.
        let usage_unique = self.scheme.est_a_usage_unique();
        let mut indices_pris: std::collections::HashSet<u32> = std::collections::HashSet::new();

        let mut choisies: Vec<(OutPoint, TxOut, u32)> = Vec::new();
        let mut total: u64 = 0;
        for e in disponibles {
            if usage_unique && !indices_pris.insert(e.2) {
                continue;
            }
            total += e.1.value.units();
            choisies.push(e);
            if total >= besoin {
                break;
            }
        }
        if total < besoin {
            return Err(WalletError::FondsInsuffisants {
                disponible: total,
                demande: besoin,
            });
        }

        // Aucun indice choisi ne doit avoir deja servi — pour un schema a usage
        // unique seulement.
        if self.scheme.est_a_usage_unique() {
            for (_, _, index) in &choisies {
                if self.consommes.contains(index) || self.reserves.contains_key(index) {
                    return Err(WalletError::ClefDejaUtilisee(*index));
                }
            }
        }
        Ok((choisies, total))
    }

    pub fn create_transaction(
        &mut self,
        utxo: &UtxoSet,
        hauteur: u64,
        destinataire: &Address,
        montant: Amount,
        frais: Amount,
    ) -> Result<Transaction, WalletError> {
        self.create_transaction_multi(utxo, hauteur, &[(*destinataire, montant)], frais)
    }

    /// Une transaction qui paie **plusieurs** destinataires d'un coup.
    ///
    /// # Pourquoi elle existe
    ///
    /// Payer dix personnes en dix transactions, c'est dix ossatures, dix
    /// signatures d'entree, dix fois le passage au reservoir. Les regrouper en
    /// une seule transaction a N sorties partage l'ossature et n'engage les
    /// pieces qu'une fois : le debit de paiements par seconde grimpe d'un ordre
    /// de grandeur, et les frais totaux baissent d'autant.
    ///
    /// Le reste ne change pas : selection des pieces, monnaie sur une adresse
    /// neuve, une signature a usage unique par entree, et la meme derniere
    /// barriere qui refuse de signer si la clef derivee n'ouvre pas le verrou.
    pub fn create_transaction_multi(
        &mut self,
        utxo: &UtxoSet,
        hauteur: u64,
        destinations: &[(Address, Amount)],
        frais: Amount,
    ) -> Result<Transaction, WalletError> {
        self.create_transaction_multi_gardee(utxo, hauteur, destinations, frais, &mut |_| Ok(()))
    }

    /// Comme [`Self::create_transaction_multi`], avec une **ecriture anticipee**.
    ///
    /// # L'ordre des operations, et pourquoi il compte
    ///
    /// Avant, l'ordre etait : signer, placer dans le reservoir, enregistrer,
    /// annoncer. La transaction existait — et pouvait etre minee par ce noeud
    /// meme — avant que le disque sache que ses clefs avaient servi. Une
    /// coupure de courant ou un disque plein entre les deux, et le prochain
    /// envoi resignait avec une clef a usage unique deja employee : deux
    /// signatures Lamport d'une meme clef suffisent a en forger une troisieme.
    ///
    /// L'ordre est desormais : reserver les indices, **enregistrer**, puis
    /// signer. `garde` recoit le portefeuille avec les indices deja reserves
    /// et doit les mettre sur le disque de facon durable ; s'il echoue, rien
    /// n'est signe, la reservation est levee et la depense est refusee.
    ///
    /// C'est [`Self::preparer_depense`] puis [`Self::signer_depense`] en un
    /// seul appel, pour qui tient le jeu de sorties d'un bout a l'autre. Le
    /// noeud, lui, rend le verrou de la chaine entre les deux le temps
    /// d'ecrire le portefeuille.
    pub fn create_transaction_multi_gardee(
        &mut self,
        utxo: &UtxoSet,
        hauteur: u64,
        destinations: &[(Address, Amount)],
        frais: Amount,
        garde: &mut dyn FnMut(&Wallet) -> Result<(), String>,
    ) -> Result<Transaction, WalletError> {
        let depense = self.preparer_depense(utxo, hauteur, destinations, frais)?;
        if garde(&*self).is_err() {
            // Rien n'a ete signe et le disque n'a rien retenu : l'indice
            // redevient libre. Le garder reserve figerait la piece pour rien.
            self.abandonner_depense(depense);
            return Err(WalletError::EnregistrementImpossible);
        }
        self.signer_depense(utxo, depense)
    }

    /// Premier temps d'une depense : choisir les pieces, verifier les clefs,
    /// **reserver** les indices. Rien n'est signe.
    ///
    /// # Pourquoi la depense est coupee en deux
    ///
    /// Entre la reservation et la signature, le portefeuille doit etre ecrit
    /// sur le disque — et cette ecriture est un scellement Argon2id de
    /// plusieurs dixiemes de seconde. Le noeud la faisait sous le verrou de
    /// la chaine et du reservoir : validation des blocs et service des pairs
    /// s'arretaient a chaque envoi. Couper ici permet de rendre le verrou,
    /// d'ecrire, puis de le reprendre pour [`Self::signer_depense`], qui
    /// revérifie que les pieces sont toujours la.
    ///
    /// L'adresse de monnaie est tiree ici : elle fait partie de ce que le
    /// disque doit connaitre avant la signature.
    pub fn preparer_depense(
        &mut self,
        utxo: &UtxoSet,
        hauteur: u64,
        destinations: &[(Address, Amount)],
        frais: Amount,
    ) -> Result<DepensePreparee, WalletError> {
        if destinations.is_empty() {
            return Err(WalletError::MontantNul);
        }
        if !self.scheme.disponible() {
            return Err(WalletError::SchemaNonSupporte(self.scheme));
        }

        // --- Le debordement qui arretait le noeud.
        //
        // `montant + frais` etait une addition nue. Avec `overflow-checks` sur
        // tous les profils et `panic = "abort"` en release, un appel RPC
        // portant un montant proche de `u64::MAX` **arretait le demon**. Et
        // l'analyseur JSON ne fermait pas la porte : `as_u64` accepte une
        // chaine, donc la borne `i64::MAX` se contourne en passant le nombre
        // entre guillemets. Un lot n'ajoute qu'une chose : la somme des
        // montants doit, elle aussi, rester sous le plafond a chaque pas.
        //
        // Aucun montant legitime ne depasse le plafond d'emission. On refuse
        // les deux : le debordement, et l'invraisemblance.
        if frais.units() > crate::consensus::MAX_SUPPLY {
            return Err(WalletError::MontantHorsBornes);
        }
        let mut total_sortant: u64 = 0;
        for (_, montant) in destinations {
            if montant.units() == 0 {
                return Err(WalletError::MontantNul);
            }
            if montant.units() < crate::consensus::MIN_OUTPUT_VALUE {
                return Err(WalletError::MontantSousLePlancher {
                    minimum: crate::consensus::MIN_OUTPUT_VALUE,
                    recu: montant.units(),
                });
            }
            total_sortant = total_sortant
                .checked_add(montant.units())
                .filter(|t| *t <= crate::consensus::MAX_SUPPLY)
                .ok_or(WalletError::MontantHorsBornes)?;
        }
        let besoin = total_sortant
            .checked_add(frais.units())
            .filter(|t| *t <= crate::consensus::MAX_SUPPLY)
            .ok_or(WalletError::MontantHorsBornes)?;
        let (choisies, total) = self.selectionner(utxo, hauteur, besoin)?;

        let mut sorties: Vec<TxOut> = destinations
            .iter()
            .map(|(adresse, montant)| TxOut {
                value: *montant,
                scheme: adresse.scheme,
                pubkey_hash: adresse.hash,
            })
            .collect();

        let monnaie = total - besoin;
        // Une monnaie sous le plancher de poussiere serait refusee par le
        // reseau : on la laisse aux frais plutot que de creer une sortie que
        // personne ne pourrait jamais depenser utilement.
        if monnaie >= crate::consensus::MIN_OUTPUT_VALUE {
            // La monnaie part sur une adresse neuve : reutiliser l'adresse
            // d'origine reemploierait une clef Lamport deja consommee.
            let rendu = self.new_address();
            sorties.push(TxOut {
                value: Amount::from_units(monnaie),
                scheme: rendu.scheme,
                pubkey_hash: rendu.hash,
            });
        }

        let tx = Transaction {
            version: 1,
            inputs: choisies
                .iter()
                .map(|(o, _, _)| TxIn {
                    prev_out: *o,
                    witness: Witness::default(),
                    sequence: u32::MAX,
                })
                .collect(),
            outputs: sorties,
            lock_time: 0,
        };

        // Derniere barriere avant la signature : la clef derivee a cet indice
        // ouvre-t-elle vraiment ce verrou ?
        //
        // Le portefeuille sait quels indices lui appartiennent par sa table
        // `connues`, alimentee par la derivation — mais aussi par un cache sur
        // disque. Un cache fausse sur une seule entree suffisait a lui faire
        // signer une depense avec la mauvaise clef : la transaction etait
        // rejetee par tout le reseau, et pour un schema a usage unique la clef
        // etait **brulee pour rien**. La graine est la, la derivation est
        // deterministe : on verifie, on ne suppose pas.
        //
        // Le cout est nul : la clef publique calculee ici est exactement celle
        // que le temoin porte ensuite.
        let mut clefs = Vec::with_capacity(choisies.len());
        for (_, sortie, index) in &choisies {
            let pubkey = self.public_key(*index);
            if pubkey_hash(self.scheme, &pubkey) != sortie.pubkey_hash {
                return Err(WalletError::VerrouIncoherent { index: *index });
            }
            clefs.push(pubkey);
        }

        // Reservation : les indices sont retenus, et l'appelant doit les mettre
        // sur le disque **avant** que la moindre signature existe. Ils ne sont
        // pas encore consommes : rien n'est revele tant que rien n'est signe.
        for (_, _, index) in &choisies {
            self.reserves.entry(*index).or_insert(hauteur);
        }
        Ok(DepensePreparee {
            choisies,
            clefs,
            tx,
        })
    }

    /// Renonce a une depense preparee : les indices reserves redeviennent
    /// libres. A n'appeler que si **rien n'a ete signe**, ce que garantit le
    /// type — une depense signee n'existe plus sous cette forme.
    pub fn abandonner_depense(&mut self, depense: DepensePreparee) {
        for (_, _, index) in &depense.choisies {
            self.reserves.remove(index);
        }
    }

    /// Second temps : revérifier les pieces, signer, consommer.
    ///
    /// Le jeu de sorties a pu changer pendant que le verrou etait rendu : une
    /// piece depensee ailleurs, une reorganisation. Chaque piece choisie doit
    /// etre encore la, identique. Sinon rien n'est signe, la reservation est
    /// levee, et l'appelant recommence sur l'etat courant.
    ///
    /// Apres la signature, les indices passent de reserves a consommes : la
    /// clef est revelee, que la transaction soit diffusee ou non — elle existe.
    pub fn signer_depense(
        &mut self,
        utxo: &UtxoSet,
        depense: DepensePreparee,
    ) -> Result<Transaction, WalletError> {
        let toujours_la = depense
            .choisies
            .iter()
            .all(|(o, sortie, _)| utxo.get(o).map(|e| e.output == *sortie).unwrap_or(false));
        if !toujours_la {
            self.abandonner_depense(depense);
            return Err(WalletError::PiecesDisparues);
        }
        let DepensePreparee {
            choisies,
            clefs,
            mut tx,
        } = depense;

        // Signature : le condensat couvre la transaction depouillee, donc il ne
        // change pas a mesure qu'on remplit les temoins. Un echec de l'alea
        // arrete tout avant la premiere signature ecrite : les temoins deja
        // calcules ne quittent pas cette fonction.
        let mut temoins = Vec::with_capacity(choisies.len());
        for (i, ((_, depensee, index), pubkey)) in choisies.iter().zip(clefs).enumerate() {
            let message = tx.sighash(i as u32, self.network, depensee);
            let signature = match self.sign_at(*index, &message) {
                Ok(s) => s,
                Err(e) => {
                    // Les signatures deja produites en memoire sont jetees ;
                    // pour un schema a usage unique, on les tient neanmoins
                    // pour revelees — elles ont existe.
                    for (_, _, index) in choisies.iter().take(temoins.len()) {
                        self.consommer(*index);
                    }
                    return Err(e);
                }
            };
            temoins.push(Witness { pubkey, signature });
        }
        for (i, ((_, _, index), temoin)) in choisies.iter().zip(temoins).enumerate() {
            tx.inputs[i].witness = temoin;
            self.consommer(*index);
        }
        Ok(tx)
    }

    /// Un indice reserve devient consomme : la clef a signe.
    fn consommer(&mut self, index: u32) {
        self.reserves.remove(&index);
        if !self.consommes.contains(&index) {
            self.consommes.push(index);
        }
    }
}

/// Une depense preparee et non signee : pieces choisies, clefs publiques
/// verifiees, transaction depouillee. Voir [`Wallet::preparer_depense`].
///
/// Le type ne se construit que par le portefeuille et se consomme par
/// [`Wallet::signer_depense`] ou [`Wallet::abandonner_depense`] : une depense
/// preparee ne peut ni etre signee deux fois, ni etre oubliee en silence.
pub struct DepensePreparee {
    choisies: Vec<(OutPoint, TxOut, u32)>,
    clefs: Vec<Vec<u8>>,
    tx: Transaction,
}

impl DepensePreparee {
    /// Indices dont les pieces sont engagees dans cette depense.
    pub fn indices(&self) -> Vec<u32> {
        self.choisies.iter().map(|(_, _, i)| *i).collect()
    }
}

/// Cote signature de ML-DSA, isole comme l'est la verification dans `sig`.
///
/// Le noeud ne compile jamais ce module : il n'a pas a savoir signer. Seul le
/// portefeuille en a besoin.
#[cfg(feature = "mldsa")]
mod mldsa_wallet {
    use super::WalletError;
    use crate::hash::Hash256;
    use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
    use ml_dsa::{signature::Keypair, MlDsaParams, SigningKey, B32};

    /// Le generateur du systeme, presente a `ml-dsa` sous le trait qu'il
    /// attend. Aucun etat : chaque appel interroge [`crate::rng`], qui echoue
    /// plutot que de degrader.
    struct Alea;

    impl TryRng for Alea {
        type Error = crate::rng::RngError;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from_le_bytes(crate::rng::octets()?))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from_le_bytes(crate::rng::octets()?))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            crate::rng::remplir(dst)
        }
    }

    impl TryCryptoRng for Alea {}

    pub fn public_key<P: MlDsaParams>(graine: &[u8; 32]) -> Vec<u8> {
        SigningKey::<P>::from_seed(&B32::from(*graine))
            .verifying_key()
            .encode()[..]
            .to_vec()
    }

    /// Signature ML-DSA en variante « hedged » (FIPS 204, algorithme 2 avec
    /// `rnd` tire au sort).
    ///
    /// # Le defaut que ceci ferme
    ///
    /// Le portefeuille signait en variante deterministe (`rnd = 0`) : deux
    /// signatures du meme message etaient identiques. FIPS 204 l'autorise
    /// mais recommande la variante aleatoire, qui protege contre les attaques
    /// par faute — une faute pendant le calcul de `z` avec un `y` rejouable
    /// revele `s1`. Le verificateur accepte les deux variantes : rien ne
    /// change pour le reseau.
    ///
    /// Si le generateur du systeme manque, on **refuse de signer** : jamais de
    /// repli sur `rnd = 0`, qui serait exactement la variante qu'on quitte.
    pub fn sign<P: MlDsaParams>(
        graine: &[u8; 32],
        message: &Hash256,
    ) -> Result<Vec<u8>, WalletError> {
        let clef = SigningKey::<P>::from_seed(&B32::from(*graine));
        let signature = clef
            .expanded_key()
            .sign_randomized(message.as_bytes(), b"", &mut Alea)
            .map_err(|_| WalletError::AleaIndisponible)?;
        Ok(signature.encode()[..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le minage derive des adresses ; seules celles que le porteur demande
    /// sont notees comme telles, et la note survit au rechargement.
    ///
    /// Un mineur possede vite un millier d'adresses qu'il n'a jamais
    /// distribuees : les presenter au meme rang que les deux qu'il a donnees
    /// noie ces deux-la. La distinction ne touche ni au solde ni aux clefs.
    #[test]
    fn seules_les_adresses_demandees_sont_notees_comme_telles() {
        let mut w = Wallet::from_seed([7u8; 32], Network::Regtest);
        let minage = w.new_address();
        let donnee = w.demander_adresse();
        let _ = w.new_address();
        assert!(
            !w.est_demandee(0),
            "une adresse de minage n'est pas demandee"
        );
        assert!(w.est_demandee(1), "une adresse demandee l'est");
        assert!(!w.est_demandee(2));
        assert_ne!(minage.hash, donnee.hash);
        assert_eq!(w.indices_demandes(), vec![1]);
        // Les deux restent reconnues comme siennes : rien ne change au solde.
        assert!(w.owns(&minage.hash));
        assert!(w.owns(&donnee.hash));

        // Rechargement depuis le fichier : la note revient, et un fichier
        // anterieur sans la ligne donne simplement un ensemble vide.
        let mut r = Wallet::from_seed([7u8; 32], Network::Regtest);
        r.rescan(3);
        assert!(!r.est_demandee(1), "sans la ligne, rien n'est demande");
        r.charger_demandees(&w.indices_demandes());
        assert!(r.est_demandee(1));
        assert_eq!(r.indices_demandes(), vec![1]);
    }
    use crate::chain::{genesis_block, Chain, GENESIS_TIME};
    use crate::consensus::TARGET_BLOCK_SECS;

    fn portefeuille() -> Wallet {
        Wallet::from_seed([0x11; 32], Network::Regtest)
    }

    /// Un fichier en retard sur la chaine — arret brutal pendant le minage —
    /// est rattrape : les adresses distribuees au-dela de `next_index` sont
    /// reconnues, et l'indice suivant repart apres la derniere qui a servi.
    #[test]
    fn le_rattrapage_retrouve_les_adresses_distribuees_apres_la_derniere_ecriture() {
        // Le portefeuille « d'avant la coupure » a distribue les indices 0 a 9.
        let mut avant = portefeuille();
        let servies: Vec<Hash256> = (0..10).map(|_| avant.new_address().hash).collect();
        // Le fichier relu n'en connait que trois.
        let mut apres = portefeuille();
        for _ in 0..3 {
            let _ = apres.new_address();
        }
        assert_eq!(apres.next_index(), 3);
        let n = apres.rattraper(|h| servies.contains(h));
        assert_eq!(n, 7, "les sept adresses distribuees apres l'ecriture");
        assert_eq!(apres.next_index(), 10);
        for h in &servies {
            assert!(
                apres.connues.contains_key(h),
                "chaque adresse servie est reconnue"
            );
        }
        // Rien de plus a rattraper : une fenetre vide, et l'indice ne bouge pas.
        assert_eq!(apres.rattraper(|h| servies.contains(h)), 0);
        assert_eq!(apres.next_index(), 10);
    }

    /// Prepare une chaine ou `w` detient des fonds mûrs.
    fn chaine_avec_fonds(w: &mut Wallet) -> Chain {
        let _ = w.new_address();
        let g = genesis_block(Network::Regtest);
        let mut c = Chain::new(Network::Regtest, g);

        // Mine assez de blocs pour que la piece de genese soit mûre.
        for i in 0..(COINBASE_MATURITY + 2) {
            let a = w.new_address();
            let t = GENESIS_TIME + (i + 1) * TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a.hash, SchemeId::LamportOts, &[], t, 20_000_000)
                .expect("minage");
            c.connect(&b, t + 1).expect("connexion");
        }
        c
    }

    #[test]
    fn chaque_adresse_est_neuve() {
        let mut w = portefeuille();
        let a = w.new_address();
        let b = w.new_address();
        assert_ne!(a.hash, b.hash);
        assert_eq!(w.next_index(), 2);
    }

    #[test]
    fn les_adresses_portent_le_bon_reseau() {
        let mut w = portefeuille();
        assert!(w.new_address().to_string_bech32().starts_with("rq21"));
    }

    #[test]
    fn la_graine_reproduit_les_memes_adresses() {
        let mut a = Wallet::from_seed([7u8; 32], Network::Regtest);
        let mut b = Wallet::from_seed([7u8; 32], Network::Regtest);
        assert_eq!(a.new_address().hash, b.new_address().hash);
        assert_eq!(a.new_address().hash, b.new_address().hash);
    }

    #[test]
    fn le_rescan_retrouve_les_adresses() {
        let mut a = Wallet::from_seed([9u8; 32], Network::Regtest);
        let attendues: Vec<Hash256> = (0..5).map(|_| a.new_address().hash).collect();

        let mut b = Wallet::from_seed([9u8; 32], Network::Regtest);
        b.rescan(5);
        for h in &attendues {
            assert!(b.owns(h), "adresse perdue apres rescan");
        }
    }

    #[test]
    fn le_solde_reflete_les_fonds_murs() {
        let mut w = portefeuille();
        let c = chaine_avec_fonds(&mut w);
        assert!(
            w.balance(&c.utxo, c.height()).units() > 0,
            "le portefeuille devrait detenir des fonds"
        );
    }

    #[test]
    fn une_coinbase_immature_ne_compte_pas_dans_le_solde() {
        let mut w = portefeuille();
        let _ = w.new_address();
        let g = genesis_block(Network::Regtest);
        let c = Chain::new(Network::Regtest, g);
        // Hauteur 0 : la piece de genese est une coinbase toute fraiche.
        assert_eq!(w.balance(&c.utxo, 0), Amount::ZERO);
    }

    #[test]
    fn une_transaction_construite_est_valide() {
        let mut w = portefeuille();
        let c = chaine_avec_fonds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();

        let tx = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a,
                Amount::from_units(50_000),
                Amount::from_units(1_000),
            )
            .expect("construction");

        let mut vues = std::collections::HashSet::new();
        let frais = crate::validate::check_transaction(
            &tx,
            &c.utxo,
            Network::Regtest,
            c.height() + 1,
            &mut vues,
        )
        .expect("la transaction devrait valider");
        assert_eq!(frais, Amount::from_units(1_000));
    }

    /// L'ecriture anticipee : les indices sont sur le disque **avant** la
    /// signature, et un disque qui refuse empeche la signature.
    ///
    /// La garde joue le disque. Elle verifie qu'au moment ou elle est appelee,
    /// les indices des pieces choisies sont deja reserves — et figurent dans
    /// ce que le fichier ecrira sous `consommes=` — et qu'aucune signature
    /// n'existe encore ; puis elle refuse. Rien ne doit avoir ete signe, et
    /// la reservation est levee : le disque n'a rien retenu, la piece n'a pas
    /// a rester figee pour une ecriture qui n'a pas eu lieu.
    #[test]
    fn les_indices_sont_enregistres_avant_de_signer_et_un_disque_qui_refuse_bloque() {
        let mut w = portefeuille();
        let c = chaine_avec_fonds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();
        let avant: Vec<u32> = w.indices_consommes_pour_le_fichier();

        let mut vus_par_la_garde: Vec<u32> = Vec::new();
        let mut reserves_par_la_garde: Vec<(u32, u64)> = Vec::new();
        let r = w.create_transaction_multi_gardee(
            &c.utxo,
            c.height(),
            &[(a, Amount::from_units(50_000))],
            Amount::from_units(1_000),
            &mut |portefeuille| {
                vus_par_la_garde = portefeuille.indices_consommes_pour_le_fichier();
                reserves_par_la_garde = portefeuille.indices_reserves();
                assert!(
                    portefeuille.indices_consommes().is_empty(),
                    "rien n'est revele avant la signature"
                );
                Err("disque plein".to_string())
            },
        );
        assert_eq!(r, Err(WalletError::EnregistrementImpossible));
        assert!(
            vus_par_la_garde.len() > avant.len(),
            "la garde doit voir les indices reserves dans la ligne du fichier"
        );
        assert!(
            !reserves_par_la_garde.is_empty()
                && reserves_par_la_garde.iter().all(|(_, h)| *h == c.height()),
            "la reservation porte la hauteur courante"
        );
        assert!(
            w.indices_reserves().is_empty() && w.indices_consommes().is_empty(),
            "un disque qui refuse ne fige rien : rien n'a ete signe"
        );

        // Le meme envoi, avec un disque qui accepte : les indices vus par la
        // garde sont exactement ceux qui signent, et ils sont consommes apres.
        let mut vus: Vec<u32> = Vec::new();
        let tx = w
            .create_transaction_multi_gardee(
                &c.utxo,
                c.height(),
                &[(a, Amount::from_units(50_000))],
                Amount::from_units(1_000),
                &mut |portefeuille| {
                    vus = portefeuille.indices_consommes_pour_le_fichier();
                    Ok(())
                },
            )
            .expect("le disque accepte");
        for entree in &tx.inputs {
            let h = pubkey_hash(w.scheme(), &entree.witness.pubkey);
            let index = *w.connues.get(&h).expect("clef du portefeuille");
            assert!(
                vus.contains(&index),
                "l'indice {index} a signe sans avoir ete enregistre d'abord"
            );
            assert!(w.est_consomme(index) && !w.est_reserve(index));
        }
    }

    /// La depense en deux temps : entre la reservation et la signature, une
    /// piece qui disparait leve la reservation sans rien signer ; une piece
    /// toujours la est signee, et l'indice passe de reserve a consomme.
    #[test]
    fn une_piece_disparue_entre_reservation_et_signature_ne_brule_rien() {
        let mut w = portefeuille();
        let c = chaine_avec_fonds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();

        let prepare = w
            .preparer_depense(
                &c.utxo,
                c.height(),
                &[(a, Amount::from_units(50_000))],
                Amount::from_units(1_000),
            )
            .expect("preparation");
        let indices = prepare.indices();
        assert!(!indices.is_empty());
        assert!(indices
            .iter()
            .all(|i| w.est_reserve(*i) && !w.est_consomme(*i)));
        // Reservee, la piece n'est plus proposee a une seconde depense.
        assert!(!w
            .spendable(&c.utxo, c.height())
            .iter()
            .any(|(_, _, i)| indices.contains(i)));

        // Le jeu de sorties change : la piece n'y est plus.
        let vide = UtxoSet::new();
        assert_eq!(
            w.signer_depense(&vide, prepare).err(),
            Some(WalletError::PiecesDisparues)
        );
        assert!(
            indices
                .iter()
                .all(|i| !w.est_reserve(*i) && !w.est_consomme(*i)),
            "rien n'a ete signe : les indices sont rendus"
        );

        // Sur le jeu inchange, la signature aboutit et consomme.
        let prepare = w
            .preparer_depense(
                &c.utxo,
                c.height(),
                &[(a, Amount::from_units(50_000))],
                Amount::from_units(1_000),
            )
            .expect("preparation");
        let indices = prepare.indices();
        let tx = w.signer_depense(&c.utxo, prepare).expect("signature");
        assert_eq!(tx.inputs.len(), indices.len());
        assert!(indices
            .iter()
            .all(|i| w.est_consomme(*i) && !w.est_reserve(*i)));
    }

    /// Une reservation relue du disque est confirmee par la chaine si la
    /// signature y figure, et levee si elle n'y figure pas passe le delai —
    /// jamais avant, jamais sur une lecture incomplete.
    #[test]
    fn une_reservation_est_confirmee_ou_levee_par_la_chaine() {
        let mut w = portefeuille();
        let mut c = chaine_avec_fonds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();
        let h0 = c.height();

        // Deux depenses preparees, une seule signee et minee.
        let signee = w
            .preparer_depense(
                &c.utxo,
                h0,
                &[(a, Amount::from_units(50_000))],
                Amount::from_units(1_000),
            )
            .unwrap();
        let abandonnee = w
            .preparer_depense(
                &c.utxo,
                h0,
                &[(a, Amount::from_units(50_000))],
                Amount::from_units(1_000),
            )
            .unwrap();
        let i_signee = signee.indices()[0];
        let i_abandonnee = abandonnee.indices()[0];
        assert_ne!(i_signee, i_abandonnee);
        let tx = w.signer_depense(&c.utxo, signee).unwrap();
        // « Arret » : on relit un portefeuille depuis ce que le fichier porte.
        let fichier_consommes = w.indices_consommes_pour_le_fichier();
        let fichier_reserves = w.indices_reserves();
        assert!(fichier_consommes.contains(&i_abandonnee));
        assert_eq!(fichier_reserves, vec![(i_abandonnee, h0)]);
        drop(abandonnee);

        let mineur = w.new_address();
        let t = GENESIS_TIME + (h0 + 1) * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(mineur.hash, mineur.scheme, &[tx], t, 20_000_000)
            .unwrap();
        c.connect(&b, t + 1).unwrap();

        let mut r = Wallet::from_seed([0x11; 32], Network::Regtest);
        r.rescan(w.next_index());
        r.marquer_consommes(&fichier_consommes);
        r.charger_reservations(&fichier_reserves);
        assert!(r.est_consomme(i_signee));
        assert!(r.est_reserve(i_abandonnee) && !r.est_consomme(i_abandonnee));

        // Trop tot : rien ne bouge.
        assert_eq!(
            r.reexaminer_reservations(c.height(), |h| c.block_at(h)),
            (0, 0)
        );
        assert!(r.est_reserve(i_abandonnee));

        // Le delai passe, mais un bloc manque : rien n'est libere.
        for _ in 0..Wallet::DELAI_RESERVATION {
            let m = w.new_address();
            let t = GENESIS_TIME + (c.height() + 1) * TARGET_BLOCK_SECS;
            let b = c.mine_block(m.hash, m.scheme, &[], t, 20_000_000).unwrap();
            c.connect(&b, t + 1).unwrap();
        }
        let trou = h0 + 3;
        assert_eq!(
            r.reexaminer_reservations(c.height(), |h| if h == trou { None } else { c.block_at(h) }),
            (0, 0)
        );
        assert!(
            r.est_reserve(i_abandonnee),
            "une lecture incomplete ne libere rien"
        );

        // Lecture complete : l'indice abandonne est libre, et une reservation
        // dont la signature est dans la chaine serait confirmee.
        let mut r2 = Wallet::from_seed([0x11; 32], Network::Regtest);
        r2.rescan(w.next_index());
        r2.charger_reservations(&[(i_signee, h0), (i_abandonnee, h0)]);
        assert_eq!(
            r2.reexaminer_reservations(c.height(), |h| c.block_at(h)),
            (1, 1)
        );
        assert!(r2.est_consomme(i_signee) && !r2.est_reserve(i_signee));
        assert!(!r2.est_consomme(i_abandonnee) && !r2.est_reserve(i_abandonnee));
    }

    /// Le balayage incremental : les blocs au-dela de la hauteur verifiee
    /// sont relus, la hauteur avance jusqu'au premier bloc manquant, et une
    /// clef vue dans un bloc n'est plus proposee.
    #[test]
    fn le_balayage_incremental_s_arrete_au_premier_bloc_manquant() {
        let mut w = portefeuille();
        let mut c = chaine_avec_fonds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();
        let tx = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a,
                Amount::from_units(50_000),
                Amount::from_units(1_000),
            )
            .unwrap();
        let signataire = pubkey_hash(w.scheme(), &tx.inputs[0].witness.pubkey);
        let index = *w.connues.get(&signataire).unwrap();
        let h_depense = c.height() + 1;
        let mineur = w.new_address();
        let t = GENESIS_TIME + h_depense * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(mineur.hash, mineur.scheme, &[tx], t, 20_000_000)
            .unwrap();
        c.connect(&b, t + 1).unwrap();

        // Un portefeuille de la meme graine, qui ne sait rien de la depense.
        let mut r = Wallet::from_seed([0x11; 32], Network::Regtest);
        r.rescan(w.next_index());
        assert!(!r.est_consomme(index));
        // Un trou avant le bloc de la depense : le balayage s'arrete devant.
        let trou = h_depense - 2;
        let marquees =
            r.balayer_la_chaine(c.height(), |h| if h == trou { None } else { c.block_at(h) });
        assert_eq!(marquees, 0);
        assert_eq!(r.verifie_jusqu_a(), trou - 1);
        // Lecture complete : la clef est marquee, la hauteur atteint la tete.
        assert_eq!(r.balayer_la_chaine(c.height(), |h| c.block_at(h)), 1);
        assert_eq!(r.verifie_jusqu_a(), c.height());
        assert!(r.est_consomme(index));
        assert!(!r
            .spendable(&c.utxo, c.height())
            .iter()
            .any(|(_, _, i)| *i == index));
    }

    /// Epreuves du portefeuille ML-DSA — le chemin qui sera celui du reseau
    /// principal. Lamport n'est qu'une bequille de developpement.
    #[cfg(feature = "mldsa")]
    mod mldsa {
        use super::*;

        fn portefeuille_mldsa(graine: [u8; 32]) -> Wallet {
            Wallet::from_seed_scheme(graine, Network::Regtest, SchemeId::MlDsa65)
                .expect("ML-DSA-65 doit etre disponible avec --features mldsa")
        }

        fn chaine_avec_fonds_mldsa(w: &mut Wallet) -> Chain {
            let _ = w.new_address();
            let g = genesis_block(Network::Regtest);
            let mut c = Chain::new(Network::Regtest, g);
            for i in 0..(COINBASE_MATURITY + 2) {
                let a = w.new_address();
                let t = GENESIS_TIME + (i + 1) * TARGET_BLOCK_SECS;
                let b = c
                    .mine_block(a.hash, SchemeId::MlDsa65, &[], t, 20_000_000)
                    .expect("minage");
                c.connect(&b, t + 1).expect("connexion");
            }
            c
        }

        /// Le test qui compte : une transaction signee en ML-DSA, validee par le
        /// meme code de consensus que n'importe quelle autre.
        #[test]
        fn une_transaction_ml_dsa_est_validee_par_le_consensus() {
            let mut w = portefeuille_mldsa([0x11; 32]);
            let c = chaine_avec_fonds_mldsa(&mut w);
            let mut dest = portefeuille_mldsa([0x99; 32]);
            let a = dest.new_address();

            let tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(50_000),
                    Amount::from_units(1_000),
                )
                .expect("construction");

            assert_eq!(tx.inputs[0].witness.pubkey.len(), 1952);
            assert_eq!(tx.inputs[0].witness.signature.len(), 3309);

            let mut vues = std::collections::HashSet::new();
            let frais = crate::validate::check_transaction(
                &tx,
                &c.utxo,
                Network::Regtest,
                c.height() + 1,
                &mut vues,
            )
            .expect("la transaction ML-DSA devrait valider");
            assert_eq!(frais, Amount::from_units(1_000));
        }

        /// Un temoin falsifie doit etre refuse par le consensus, pas seulement
        /// par le portefeuille.
        #[test]
        fn un_temoin_ml_dsa_falsifie_est_refuse() {
            let mut w = portefeuille_mldsa([0x11; 32]);
            let c = chaine_avec_fonds_mldsa(&mut w);
            let mut dest = portefeuille_mldsa([0x99; 32]);
            let a = dest.new_address();

            let mut tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(50_000),
                    Amount::from_units(1_000),
                )
                .expect("construction");

            tx.inputs[0].witness.signature[100] ^= 0x01;

            let mut vues = std::collections::HashSet::new();
            assert!(crate::validate::check_transaction(
                &tx,
                &c.utxo,
                Network::Regtest,
                c.height() + 1,
                &mut vues,
            )
            .is_err());
        }

        /// La contrainte d'usage unique de Lamport ne doit pas avoir survecu au
        /// changement de schema : une clef ML-DSA signe autant de fois qu'on veut.
        #[test]
        fn une_clef_ml_dsa_signe_plusieurs_fois() {
            let w = portefeuille_mldsa([0x11; 32]);
            assert!(!w.scheme().est_a_usage_unique());

            let pk = w.public_key(0);
            let m1 = crate::hash::tagged_hash("Q21/test", b"un");
            let m2 = crate::hash::tagged_hash("Q21/test", b"deux");

            for m in [m1, m2] {
                let s = w.sign_at(0, &m).expect("alea disponible");
                assert_eq!(crate::sig::verify(SchemeId::MlDsa65, &pk, &m, &s), Ok(()));
            }
        }

        /// ML-DSA signe en variante « hedged » : deux signatures du meme
        /// message different, et chacune verifie. La variante deterministe
        /// (`rnd = 0`) rendait deux signatures identiques, la plus exposee aux
        /// attaques par faute.
        #[test]
        fn deux_signatures_ml_dsa_du_meme_message_different_et_verifient() {
            let w = portefeuille_mldsa([0x11; 32]);
            let pk = w.public_key(0);
            let m = crate::hash::tagged_hash("Q21/test", b"le meme message");
            let a = w.sign_at(0, &m).expect("alea disponible");
            let b = w.sign_at(0, &m).expect("alea disponible");
            assert_ne!(a, b, "deux signatures identiques : variante deterministe");
            assert_eq!(crate::sig::verify(SchemeId::MlDsa65, &pk, &m, &a), Ok(()));
            assert_eq!(crate::sig::verify(SchemeId::MlDsa65, &pk, &m, &b), Ok(()));
        }

        /// Deux schemas issus de la meme graine ne partagent aucune clef.
        #[test]
        fn le_schema_entre_dans_la_derivation() {
            let mut a = portefeuille_mldsa([0x11; 32]);
            let mut b = Wallet::from_seed_scheme([0x11; 32], Network::Regtest, SchemeId::MlDsa87)
                .expect("disponible");
            assert_ne!(a.public_key(0), b.public_key(0));
            assert_ne!(a.new_address().hash, b.new_address().hash);
        }

        /// Meme graine, meme schema : memes adresses. C'est ce qui rend une
        /// sauvegarde de 32 octets suffisante.
        #[test]
        fn les_adresses_ml_dsa_sont_reproductibles() {
            let mut a = portefeuille_mldsa([0x77; 32]);
            let mut b = portefeuille_mldsa([0x77; 32]);
            for _ in 0..3 {
                assert_eq!(a.new_address(), b.new_address());
            }
        }

        /// ML-DSA est le seul schema utilisable sur le reseau principal.
        #[test]
        fn le_reseau_principal_accepte_ml_dsa_et_refuse_lamport() {
            assert!(
                Wallet::from_seed_scheme([0x01; 32], Network::Mainnet, SchemeId::MlDsa65).is_ok()
            );
            assert!(
                Wallet::from_seed_scheme([0x01; 32], Network::Mainnet, SchemeId::MlDsa87).is_ok()
            );
            // `.err()` plutot que le Result complet : `Wallet` n'implemente ni
            // Debug ni PartialEq, et ce n'est pas un oubli — un portefeuille qui
            // sait s'afficher est un portefeuille dont la graine finit dans un
            // journal.
            assert_eq!(
                Wallet::from_seed_scheme([0x01; 32], Network::Mainnet, SchemeId::LamportOts).err(),
                Some(WalletError::SchemaNonSupporte(SchemeId::LamportOts))
            );
        }

        /// SPHINCS+ est declare par le protocole mais n'est pas implemente. Un
        /// portefeuille ne doit pas pouvoir deriver des adresses qu'il ne saura
        /// pas depenser.
        #[test]
        fn un_schema_non_implemente_est_refuse_a_la_construction() {
            assert_eq!(
                Wallet::from_seed_scheme([0x01; 32], Network::Regtest, SchemeId::SphincsPlus).err(),
                Some(WalletError::SchemaNonSupporte(SchemeId::SphincsPlus))
            );
        }
    }

    #[test]
    fn les_fonds_insuffisants_sont_signales() {
        let mut w = portefeuille();
        let c = chaine_avec_fonds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();

        // Un montant plausible mais superieur aux fonds : refus par manque.
        let r = w.create_transaction(
            &c.utxo,
            c.height(),
            &a,
            Amount::from_units(crate::consensus::MAX_SUPPLY),
            Amount::ZERO,
        );
        assert!(
            matches!(r, Err(WalletError::FondsInsuffisants { .. })),
            "{r:?}"
        );

        // Un montant qui n'a aucun sens : refus **avant** toute arithmetique.
        // C'est ce chemin qui faisait deborder une addition et, en release avec
        // `panic = "abort"`, arretait le noeud sur un simple appel RPC.
        for (m, f) in [
            (u64::MAX, 0),
            (u64::MAX / 2, u64::MAX / 2 + 2),
            (crate::consensus::MAX_SUPPLY, u64::MAX),
        ] {
            let r = w.create_transaction(
                &c.utxo,
                c.height(),
                &a,
                Amount::from_units(m),
                Amount::from_units(f),
            );
            assert!(
                matches!(r, Err(WalletError::MontantHorsBornes)),
                "montant {m} frais {f} : {r:?}"
            );
        }
    }

    #[test]
    fn un_montant_nul_est_refuse() {
        let mut w = portefeuille();
        let c = chaine_avec_fonds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();
        assert_eq!(
            w.create_transaction(&c.utxo, c.height(), &a, Amount::ZERO, Amount::ZERO),
            Err(WalletError::MontantNul)
        );
    }

    /// Le point critique de Lamport.
    #[test]
    fn une_clef_ne_sert_jamais_deux_fois() {
        let mut w = portefeuille();
        let c = chaine_avec_fonds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);

        let a1 = dest.new_address();
        let tx1 = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a1,
                Amount::from_units(50_000),
                Amount::ZERO,
            )
            .expect("premiere depense");

        // Les entrees de tx1 sont encore dans l'UTXO tant que le bloc n'est pas
        // mine. Une seconde construction ne doit pas les reprendre.
        let a2 = dest.new_address();
        let tx2 = w.create_transaction(
            &c.utxo,
            c.height(),
            &a2,
            Amount::from_units(1_000),
            Amount::ZERO,
        );

        if let Ok(t2) = tx2 {
            for e1 in &tx1.inputs {
                for e2 in &t2.inputs {
                    assert_ne!(
                        e1.prev_out, e2.prev_out,
                        "la meme clef Lamport signerait deux messages : clef privee revelee"
                    );
                }
            }
        }
    }

    /// Deux pieces recues sur le **meme** indice a usage unique ne doivent
    /// jamais entrer ensemble dans une transaction : les co-signer signerait
    /// deux condensats differents avec une clef Lamport, ce qui en revele les
    /// deux preimages et **livre la clef privee**. Le garde `consommes` ferme ce
    /// risque entre transactions ; ce test verrouille sa fermeture *a
    /// l'interieur* d'une meme transaction. Le portefeuille prefere refuser
    /// (une piece figee) plutot que de bruler la clef.
    #[test]
    fn deux_utxo_du_meme_indice_ne_se_co_signent_jamais() {
        let mut w = portefeuille();
        let a = w.new_address(); // indice 0 — toutes les coinbases y vont
        let g = genesis_block(Network::Regtest);
        let mut c = Chain::new(Network::Regtest, g);
        for i in 0..(COINBASE_MATURITY + 2) {
            let t = GENESIS_TIME + (i + 1) * TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a.hash, SchemeId::LamportOts, &[], t, 20_000_000)
                .expect("minage");
            c.connect(&b, t + 1).expect("connexion");
        }

        // L'adresse a recu bien plus d'une piece...
        let reutilisees = w.adresses_reutilisees(&c.utxo, c.height());
        assert_eq!(
            reutilisees.len(),
            1,
            "une adresse reutilisee doit etre signalee comme telle"
        );
        assert!(reutilisees[0].1 >= 2, "elle porte plusieurs pieces");

        // ... mais une seule est depensable, et c'est la plus grosse.
        let pieces = w.spendable(&c.utxo, c.height());
        assert_eq!(
            pieces.len(),
            1,
            "une clef a usage unique ne peut rendre qu'une piece depensable"
        );
        let une_piece = pieces[0].1.value.units();

        // Le solde annonce est exactement ce qui est depensable, et le reste
        // est nomme « fige » plutot que tu.
        let solde = w.balance(&c.utxo, c.height()).units();
        assert_eq!(
            solde, une_piece,
            "le solde doit etre celui qu'on peut payer"
        );
        assert!(
            w.montant_fige(&c.utxo, c.height()).units() > 0,
            "les pieces immobilisees doivent etre visibles"
        );

        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);

        // Un montant au-dela du solde annonce : refus franc, jamais une
        // co-signature (qui revelerait la clef Lamport).
        let d = dest.new_address();
        let r = w.create_transaction(
            &c.utxo,
            c.height(),
            &d,
            Amount::from_units(solde + 1),
            Amount::ZERO,
        );
        assert!(
            matches!(r, Err(WalletError::FondsInsuffisants { .. })),
            "le portefeuille a co-signe deux pieces du meme indice : clef Lamport revelee"
        );

        // La promesse inverse, celle qui rend le portefeuille utilisable : tout
        // ce qui est annonce se paie vraiment, et en une seule entree.
        let d2 = dest.new_address();
        let tx = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &d2,
                Amount::from_units(solde),
                Amount::ZERO,
            )
            .expect("le solde annonce doit toujours etre payable");
        assert_eq!(
            tx.inputs.len(),
            1,
            "une seule entree pour un montant couvert par une piece"
        );
    }

    #[test]
    fn la_monnaie_rendue_va_sur_une_adresse_neuve() {
        let mut w = portefeuille();
        let c = chaine_avec_fonds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();

        let avant = w.next_index();
        let tx = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a,
                Amount::from_units(50_000),
                Amount::ZERO,
            )
            .expect("construction");

        assert_eq!(tx.outputs.len(), 2, "il devrait y avoir de la monnaie");
        assert!(w.next_index() > avant, "aucune adresse neuve creee");
        assert!(w.owns(&tx.outputs[1].pubkey_hash));
    }

    /// La sauvegarde doit survivre a une recopie a la main : c'est tout son
    /// interet par rapport a soixante-quatre caracteres hexadecimaux.
    #[test]
    fn le_code_de_sauvegarde_reconstitue_la_graine() {
        let w = portefeuille();
        let code = w.backup_code();
        assert!(code.starts_with("rq21seed1"), "prefixe inattendu : {code}");
        assert_eq!(
            Wallet::seed_from_backup(&code, Network::Regtest).unwrap(),
            [0x11; 32]
        );
    }

    /// Une seule faute de frappe doit etre attrapee. C'est la propriete qui
    /// evite une perte de fonds silencieuse.
    #[test]
    fn une_faute_de_frappe_dans_la_sauvegarde_est_detectee() {
        let w = portefeuille();
        let code = w.backup_code();
        let octets: Vec<char> = code.chars().collect();
        let mut attrapees = 0;
        let mut essais = 0;

        // On substitue chaque caractere de la partie donnees par un autre de
        // l'alphabet Bech32.
        for i in (code.find('1').unwrap() + 1)..octets.len() {
            for remplacant in ['q', 'p', 'z', 'r', 'y', '9', 'x', '8'] {
                if octets[i] == remplacant {
                    continue;
                }
                let mut fausse: Vec<char> = octets.clone();
                fausse[i] = remplacant;
                let s: String = fausse.into_iter().collect();
                essais += 1;
                if Wallet::seed_from_backup(&s, Network::Regtest).is_err() {
                    attrapees += 1;
                }
            }
        }
        assert!(essais > 100, "l'epreuve doit couvrir tout le code");
        assert_eq!(
            attrapees,
            essais,
            "{} faute(s) de frappe sur {} sont passees inapercues",
            essais - attrapees,
            essais
        );
    }

    /// Une graine de test ne doit jamais etre prise pour une graine du reseau
    /// principal.
    #[test]
    fn une_sauvegarde_d_un_autre_reseau_est_refusee() {
        let w = portefeuille();
        let code = w.backup_code();
        assert_eq!(
            Wallet::seed_from_backup(&code, Network::Mainnet),
            Err(WalletError::SauvegardeAutreReseau)
        );
    }

    /// Une adresse collee a la place du code est reconnue pour ce qu'elle est.
    ///
    /// Le cas reel : un portefeuille perdu, une adresse de reception sous les
    /// yeux, et la certitude que « c'est pareil ». Le verdict generique —
    /// « somme de controle fausse, verifiez la recopie » — faisait chercher une
    /// faute de frappe dans une copie parfaite. Le programme doit nommer
    /// l'objet recu, sur les trois reseaux, quelle que soit la casse.
    #[test]
    fn une_adresse_collee_a_la_place_du_code_est_nommee() {
        for reseau in [Network::Regtest, Network::Testnet, Network::Mainnet] {
            let mut w = Wallet::from_seed([7u8; 32], reseau);
            let adresse = w.new_address().to_string();
            assert!(adresse.starts_with(reseau.hrp()), "adresse : {adresse}");
            assert_eq!(
                Wallet::seed_from_backup(&adresse, reseau),
                Err(WalletError::SauvegardeEstUneAdresse),
                "une adresse {reseau:?} n'est pas nommee comme telle"
            );
            // Quelle que soit la casse et les espaces autour : on lit ce
            // qu'une personne colle, pas ce qu'un programme produit.
            let brouillonne = format!("  {}  ", adresse.to_ascii_uppercase());
            assert_eq!(
                Wallet::seed_from_backup(&brouillonne, reseau),
                Err(WalletError::SauvegardeEstUneAdresse)
            );
        }
        // Et le vrai code passe toujours, exactement comme avant.
        let w = portefeuille();
        assert_eq!(
            Wallet::seed_from_backup(&w.backup_code(), w.network()),
            Ok([0x11; 32])
        );
        // Une chaine quelconque reste « illisible », pas « une adresse ».
        assert_eq!(
            Wallet::seed_from_backup("n'importe quoi", Network::Testnet),
            Err(WalletError::SauvegardeInvalide)
        );
    }

    /// Un copier-coller maladroit ne doit pas faire echouer une restauration.
    ///
    /// Le cas reel : le code, colle depuis un carnet ou un gestionnaire de mots
    /// de passe, arrive coupe par un retour a la ligne au milieu, ou entoure
    /// d'espaces. Il reste le meme code ; l'alphabet Bech32m n'ayant aucun
    /// blanc, tout blanc est du bruit de mise en forme. La restauration doit
    /// donc reconstituer la meme graine, quelle que soit la maniere dont le
    /// code a ete colle.
    #[test]
    fn un_code_truffe_de_blancs_restaure_la_meme_graine() {
        let w = portefeuille();
        let code = w.backup_code();
        let attendu = Wallet::seed_from_backup(&code, Network::Regtest).unwrap();

        // Coupe en son milieu par un retour a la ligne.
        let milieu = code.len() / 2;
        let coupe = format!("{}\n{}", &code[..milieu], &code[milieu..]);
        // Un panache de tous les blancs qu'un collage peut introduire :
        // espaces, tabulation, retours a la ligne, espace insecable, largeur
        // nulle, autour et au milieu.
        let bruite = format!(
            "  {}\t{}\u{00A0}{}\u{200B}\r\n{}  ",
            &code[..8],
            &code[8..milieu],
            &code[milieu..code.len() - 4],
            &code[code.len() - 4..]
        );
        for essai in [coupe, bruite] {
            assert_eq!(
                Wallet::seed_from_backup(&essai, Network::Regtest).unwrap(),
                attendu,
                "un code colle avec des blancs doit restaurer la meme graine : {essai:?}"
            );
        }
    }

    /// La graine tiree du systeme doit etre differente a chaque fois.
    #[test]
    fn deux_portefeuilles_engendres_different() {
        let a = Wallet::generate(Network::Regtest).expect("alea");
        let b = Wallet::generate(Network::Regtest).expect("alea");
        assert_ne!(a.seed_hex(), b.seed_hex());
    }

    #[test]
    fn aller_retour_sur_la_graine_hexadecimale() {
        let w = portefeuille();
        assert_eq!(Wallet::seed_from_hex(&w.seed_hex()), Some([0x11u8; 32]));
        assert_eq!(Wallet::seed_from_hex("pas hexadecimal"), None);
    }

    /// Le code de sauvegarde retrouve tout, y compris ce qu'on n'a jamais
    /// derive sur cette machine.
    ///
    /// # Le defaut que cette epreuve fige
    ///
    /// Un portefeuille restaure ne connaissait que les adresses qu'il avait
    /// lui-meme derivees — aucune. Il affichait donc zero sur une chaine qui
    /// contenait ses fonds, et la promesse du code de sauvegarde etait fausse.
    #[test]
    fn un_portefeuille_restaure_retrouve_ses_adresses() {
        let mut origine = Wallet::from_seed([42u8; 32], Network::Regtest);
        // Le porteur a distribue quarante adresses ; la trentieme a ete payee.
        let mut payees = Vec::new();
        for i in 0..40 {
            let a = origine.new_address();
            if i == 29 {
                payees.push(a.hash);
            }
        }

        // Une machine neuve : meme graine, aucune adresse derivee.
        let mut restaure = Wallet::from_seed([42u8; 32], Network::Regtest);
        assert!(
            !restaure.owns(&payees[0]),
            "sans decouverte, l'adresse payee doit etre inconnue"
        );

        let trouvees = restaure.decouvrir(|h| payees.contains(h));
        assert_eq!(trouvees, 1, "l'adresse payee n'a pas ete retrouvee");
        assert!(restaure.owns(&payees[0]), "elle n'est pas devenue sienne");
        // L'indice suivant se place apres la derniere adresse qui a servi, pas
        // apres la derniere exploree.
        assert_eq!(restaure.next_index(), 30);
    }

    /// Au-dela de l'ecart, on s'arrete — et l'on ne pretend pas avoir cherche.
    #[test]
    fn la_decouverte_s_arrete_apres_un_ecart_vide() {
        let mut origine = Wallet::from_seed([7u8; 32], Network::Regtest);
        // Une adresse tres loin devant, bien au-dela de l'ecart admis.
        let mut lointaine = Hash256::ZERO;
        for i in 0..(Wallet::ECART_DECOUVERTE + 50) {
            let a = origine.new_address();
            if i == Wallet::ECART_DECOUVERTE + 49 {
                lointaine = a.hash;
            }
        }
        let mut restaure = Wallet::from_seed([7u8; 32], Network::Regtest);
        let trouvees = restaure.decouvrir(|h| *h == lointaine);
        assert_eq!(
            trouvees, 0,
            "une adresse au-dela de l'ecart ne doit pas etre trouvee : \
             la pretendre trouvable donnerait une fausse garantie"
        );
    }

    /// Une adresse juste avant la limite de l'ecart reste trouvable, et la
    /// fenetre suivante est bien exploree.
    #[test]
    fn la_decouverte_enjambe_les_fenetres() {
        let mut origine = Wallet::from_seed([11u8; 32], Network::Regtest);
        let mut cibles = Vec::new();
        for i in 0..(Wallet::ECART_DECOUVERTE * 2 + 5) {
            let a = origine.new_address();
            // Une dans la premiere fenetre, une dans la deuxieme.
            if i == Wallet::ECART_DECOUVERTE - 1 || i == Wallet::ECART_DECOUVERTE + 3 {
                cibles.push(a.hash);
            }
        }
        let mut restaure = Wallet::from_seed([11u8; 32], Network::Regtest);
        let trouvees = restaure.decouvrir(|h| cibles.contains(h));
        assert_eq!(trouvees, 2, "la deuxieme fenetre n'a pas ete exploree");
        assert_eq!(restaure.next_index(), Wallet::ECART_DECOUVERTE + 4);
    }

    /// Deux graines differentes ne se reconnaissent pas.
    ///
    /// C'est l'autre moitie de la promesse : le code de sauvegarde retrouve
    /// **vos** fonds, et rien d'autre.
    #[test]
    fn une_autre_graine_ne_decouvre_rien() {
        let mut a = Wallet::from_seed([1u8; 32], Network::Regtest);
        let sienne = a.new_address().hash;
        let mut b = Wallet::from_seed([2u8; 32], Network::Regtest);
        assert_eq!(b.decouvrir(|h| *h == sienne), 0);
    }

    /// Construit un jeu d'UTXO tenant une sortie vers `empreinte`.
    fn utxo_avec(empreinte: Hash256) -> crate::utxo::UtxoSet {
        let mut u = crate::utxo::UtxoSet::new();
        u.insert(
            OutPoint {
                txid: Hash256([9u8; 32]),
                index: 0,
            },
            crate::utxo::UtxoEntry {
                output: TxOut {
                    value: crate::amount::Amount::from_units(1),
                    scheme: SchemeId::LamportOts,
                    pubkey_hash: empreinte,
                },
                height: 1,
                is_coinbase: false,
            },
        );
        u
    }

    /// Le vrai declencheur de la restauration : voir ses fonds, pas compter ses
    /// adresses.
    ///
    /// Le defaut corrige : la decouverte ne se lançait que si `next_index <= 1`.
    /// Or un portefeuille restaure derive une adresse des qu'on l'ouvre, une
    /// autre au premier clic — et des le deuxieme indice la decouverte etait
    /// coupee. Le porteur voyait alors **zero** sur une chaine qui portait ses
    /// fonds. Le bon signal n'est pas le compteur d'indices : c'est que le
    /// portefeuille ne reconnaisse encore aucun de ses avoirs.
    #[test]
    fn un_portefeuille_deja_entame_voit_encore_qu_il_lui_manque_ses_fonds() {
        // Le porteur possede l'adresse d'indice 30 sur la chaine.
        let mut origine = Wallet::from_seed([64u8; 32], Network::Regtest);
        let mut payee = Hash256::ZERO;
        for i in 0..40 {
            let a = origine.new_address();
            if i == 30 {
                payee = a.hash;
            }
        }
        let utxo = utxo_avec(payee);

        // Machine neuve : restauree, puis DEJA entamee — deux adresses tirees,
        // comme a l'ouverture de la page. L'ancien test `next_index <= 1` aurait
        // ici saute la decouverte.
        let mut restaure = Wallet::from_seed([64u8; 32], Network::Regtest);
        restaure.new_address();
        restaure.new_address();
        assert!(restaure.next_index() > 1);

        // Avant decouverte : le portefeuille ne voit aucun de ses fonds.
        assert!(
            !restaure.voit_des_fonds(&utxo),
            "il ne devrait pas encore reconnaitre l'adresse payee"
        );

        // C'est exactement ce que le declencheur corrige regarde. On cherche.
        let trouvees = restaure.decouvrir(|h| utxo.connait(h));
        assert_eq!(trouvees, 1, "l'adresse payee n'a pas ete retrouvee");

        // Apres decouverte : il voit ses fonds, et ne relancera donc plus rien.
        assert!(
            restaure.voit_des_fonds(&utxo),
            "apres decouverte, ses fonds doivent etre visibles"
        );
    }

    /// Un portefeuille vraiment vierge, lui, ne voit rien — et c'est correct :
    /// le declencheur restera actif tant qu'aucun fonds n'apparait, sans jamais
    /// pretendre le contraire.
    #[test]
    fn un_portefeuille_sans_fonds_ne_voit_rien() {
        let w = Wallet::from_seed([65u8; 32], Network::Regtest);
        // Une sortie qui paie l'adresse d'un AUTRE portefeuille.
        let mut autre = Wallet::from_seed([66u8; 32], Network::Regtest);
        let etrangere = autre.new_address().hash;
        assert!(!w.voit_des_fonds(&utxo_avec(etrangere)));
    }

    #[test]
    fn une_adresse_se_nomme_et_se_renomme() {
        let mut w = Wallet::from_seed([3u8; 32], Network::Regtest);
        assert_eq!(w.etiquette(0), None, "rien n'est nomme au depart");
        w.etiqueter(0, "  pour Mathis  ");
        assert_eq!(
            w.etiquette(0),
            Some("pour Mathis"),
            "les espaces de bord n'appartiennent pas au nom"
        );
        w.etiqueter(0, "loyer");
        assert_eq!(w.etiquette(0), Some("loyer"), "un nom se remplace");
    }

    #[test]
    fn un_nom_vide_retire_l_etiquette() {
        // Sinon le carnet se remplit de lignes vides qu'on ne distingue plus
        // d'une adresse sans nom, et qu'aucun bouton ne permet d'effacer.
        let mut w = Wallet::from_seed([4u8; 32], Network::Regtest);
        w.etiqueter(7, "provisoire");
        w.etiqueter(7, "   ");
        assert_eq!(w.etiquette(7), None);
        assert!(w.etiquettes().is_empty());
    }

    #[test]
    fn un_nom_ne_peut_pas_casser_le_fichier_ni_s_etendre_sans_fin() {
        let mut w = Wallet::from_seed([5u8; 32], Network::Regtest);
        // Les caracteres de controle casseraient le format du portefeuille, qui
        // est une ligne par clef : un retour a la ligne dans un nom decalerait
        // la lecture de tout ce qui suit.
        w.etiqueter(0, "Marie\nBoulangerie\tcentre");
        let e = w.etiquette(0).expect("nom pose");
        assert!(
            !e.contains('\n') && !e.contains('\t'),
            "controle survivant : {e:?}"
        );
        assert_eq!(e, "Marie Boulangerie centre");

        // La coupure se fait sur les caracteres, jamais sur les octets : couper
        // un accent en deux produirait une chaine qui n'est pas de l'UTF-8, et
        // le portefeuille deviendrait illisible.
        w.etiqueter(1, &"é".repeat(200));
        let long = w.etiquette(1).expect("nom pose");
        assert_eq!(long.chars().count(), Wallet::ETIQUETTE_MAX);
        assert!(long.chars().all(|c| c == 'é'));
    }

    /// Le montant immature rendu par l'index doit coincider exactement avec un
    /// balayage complet — montant **et** hauteur de la prochaine liberation.
    ///
    /// C'est la contrepartie d'une optimisation : elle ne vaut que si elle ne
    /// change pas la reponse. Un mineur qui verrait un compte a rebours faux
    /// preferait encore l'ancien balayage lent.
    #[test]
    fn le_montant_immature_coincide_avec_le_balayage() {
        fn balayage(w: &Wallet, utxo: &UtxoSet, hauteur: u64) -> (u64, Option<(u64, u64)>) {
            let mut immature = 0u64;
            let mut prochaine: Option<(u64, u64)> = None;
            for (_, e) in utxo.iter() {
                if e.is_coinbase
                    && hauteur < e.height + COINBASE_MATURITY
                    && w.owns(&e.output.pubkey_hash)
                {
                    immature += e.output.value.units();
                    let libre_a = e.height + COINBASE_MATURITY;
                    match prochaine {
                        Some((h, m)) if h == libre_a => {
                            prochaine = Some((h, m + e.output.value.units()))
                        }
                        Some((h, _)) if h < libre_a => {}
                        _ => prochaine = Some((libre_a, e.output.value.units())),
                    }
                }
            }
            (immature, prochaine)
        }

        let mut w = portefeuille();
        let c = chaine_avec_fonds(&mut w);

        // A plusieurs hauteurs : avant maturite, pendant, et bien apres. Les
        // trois cas font varier a la fois le montant et la prochaine echeance.
        for h in [
            0u64,
            1,
            c.height() / 2,
            c.height(),
            c.height() + COINBASE_MATURITY,
        ] {
            let attendu = balayage(&w, &c.utxo, h);
            let (m, p) = w.immature(&c.utxo, h);
            let obtenu = (m.units(), p.map(|(x, y)| (x, y.units())));
            assert_eq!(
                obtenu, attendu,
                "l'index diverge du balayage a la hauteur {h}"
            );
        }

        // Et il doit exister au moins une hauteur ou la reponse n'est pas vide,
        // sans quoi l'epreuve ne prouverait rien.
        let (m, p) = w.immature(&c.utxo, c.height());
        assert!(
            m.units() > 0 && p.is_some(),
            "le montage doit produire des fonds immatures"
        );
    }
}
