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
use std::collections::HashMap;

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
}

/// En deca de ce nombre d'adresses, un cache est resonde **integralement**.
///
/// Mille vingt-quatre derivations ML-DSA coutent environ un tiers de seconde :
/// c'est invisible au demarrage, et cela couvre la quasi-totalite des
/// portefeuilles reels. Le cache ne sert vraiment qu'au-dela.
const SEUIL_VERIFICATION_COMPLETE: usize = 1024;

/// Prefixe humain du code de sauvegarde, par reseau.
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
}

/// Efface la graine a la destruction du portefeuille.
///
/// Ne protege pas contre un adversaire qui lit la memoire du processus pendant
/// qu'il tourne, ni contre une page echangee sur disque par le systeme. Ce qu'il
/// evite : qu'une graine trainne dans un tas reutilise, puis dans un fichier de
/// vidage apres un plantage. C'est peu et ce n'est pas rien.
impl Drop for Wallet {
    fn drop(&mut self) {
        for o in self.seed.iter_mut() {
            // `write_volatile` : sans cela, l'optimiseur a parfaitement le droit
            // de supprimer une ecriture dont plus personne ne lit le resultat.
            unsafe { std::ptr::write_volatile(o, 0) };
        }
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
            verifie_jusqu_a: 0,
            etiquettes: HashMap::new(),
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
            verifie_jusqu_a: 0,
            etiquettes: HashMap::new(),
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
        let (hrp, donnees) =
            crate::bech32::decode(code.trim()).map_err(|_| WalletError::SauvegardeInvalide)?;
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
        crate::kdf::hmac_sha256(&self.seed, b"Q21-CACHE-ADRESSES-v1")
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
                mldsa_wallet::public_key::<ml_dsa::MlDsa65>(&self.graine_derivee(index))
            }
            #[cfg(feature = "mldsa")]
            SchemeId::MlDsa87 => {
                mldsa_wallet::public_key::<ml_dsa::MlDsa87>(&self.graine_derivee(index))
            }
            autre => panic!("portefeuille sur un schema indisponible : {}", autre.name()),
        }
    }

    /// Signe `message` avec l'indice `index`.
    ///
    /// # Panique
    ///
    /// Meme invariant que [`Wallet::public_key`].
    fn sign_at(&self, index: u32, message: &Hash256) -> Vec<u8> {
        match self.scheme {
            SchemeId::LamportOts => self.key(index).sign(message),
            #[cfg(feature = "mldsa")]
            SchemeId::MlDsa65 => {
                mldsa_wallet::sign::<ml_dsa::MlDsa65>(&self.graine_derivee(index), message)
            }
            #[cfg(feature = "mldsa")]
            SchemeId::MlDsa87 => {
                mldsa_wallet::sign::<ml_dsa::MlDsa87>(&self.graine_derivee(index), message)
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
    pub fn indices_consommes(&self) -> Vec<u32> {
        let mut v = self.consommes.clone();
        v.sort_unstable();
        v.dedup();
        v
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
                    if !self.consommes.contains(&index) {
                        self.consommes.push(index);
                        nouveaux += 1;
                    }
                }
            }
        }
        nouveaux
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

    /// Sorties depensables appartenant au portefeuille.
    pub fn spendable(&self, utxo: &UtxoSet, hauteur: u64) -> Vec<(OutPoint, TxOut, u32)> {
        let mut v = Vec::new();
        for (h, index) in &self.connues {
            // Une clef Lamport consommee est morte : les fonds qu'elle garde ne
            // sont plus depensables sans reveler la clef privee. ML-DSA n'a pas
            // cette contrainte, et masquer ses fonds serait un bogue.
            if self.scheme.est_a_usage_unique() && self.consommes.contains(index) {
                continue;
            }
            for (o, e) in utxo.spendable_for(h, hauteur, COINBASE_MATURITY) {
                v.push((o, e.output, *index));
            }
        }
        v.sort_by_key(|(o, _, _)| *o);
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

        let mut choisies: Vec<(OutPoint, TxOut, u32)> = Vec::new();
        let mut total: u64 = 0;
        for e in disponibles {
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
                if self.consommes.contains(index) {
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
        if montant.units() == 0 {
            return Err(WalletError::MontantNul);
        }
        if !self.scheme.disponible() {
            return Err(WalletError::SchemaNonSupporte(self.scheme));
        }

        // --- Le debordement qui arretait le noeud.
        //
        // `montant + frais` etait une addition nue. Avec `overflow-checks` sur
        // tous les profils et `panic = "abort"` en release, un appel RPC
        // `sendtoaddress` portant un montant proche de `u64::MAX` **arretait le
        // demon**. Et l'analyseur JSON ne fermait pas la porte : `as_u64`
        // accepte une chaine, donc la borne `i64::MAX` se contourne en passant
        // le nombre entre guillemets.
        //
        // Aucun montant legitime ne depasse le plafond d'emission. On refuse
        // les deux : le debordement, et l'invraisemblance.
        if montant.units() > crate::consensus::MAX_SUPPLY
            || frais.units() > crate::consensus::MAX_SUPPLY
        {
            return Err(WalletError::MontantHorsBornes);
        }
        let besoin = montant
            .units()
            .checked_add(frais.units())
            .filter(|t| *t <= crate::consensus::MAX_SUPPLY)
            .ok_or(WalletError::MontantHorsBornes)?;
        let (choisies, total) = self.selectionner(utxo, hauteur, besoin)?;

        let mut sorties = vec![TxOut {
            value: montant,
            scheme: destinataire.scheme,
            pubkey_hash: destinataire.hash,
        }];

        let monnaie = total - besoin;
        if monnaie > 0 {
            // La monnaie part sur une adresse neuve : reutiliser l'adresse
            // d'origine reemploierait une clef Lamport deja consommee.
            let rendu = self.new_address();
            sorties.push(TxOut {
                value: Amount::from_units(monnaie),
                scheme: rendu.scheme,
                pubkey_hash: rendu.hash,
            });
        }

        let mut tx = Transaction {
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

        // Signature : le condensat couvre la transaction depouillee, donc il ne
        // change pas a mesure qu'on remplit les temoins.
        for (i, ((_, _, index), pubkey)) in choisies.iter().zip(clefs).enumerate() {
            let message = tx.sighash(i as u32);
            tx.inputs[i].witness = Witness {
                pubkey,
                signature: self.sign_at(*index, &message),
            };
        }

        for (_, _, index) in &choisies {
            self.consommes.push(*index);
        }

        Ok(tx)
    }
}

/// Cote signature de ML-DSA, isole comme l'est la verification dans `sig`.
///
/// Le noeud ne compile jamais ce module : il n'a pas a savoir signer. Seul le
/// portefeuille en a besoin.
#[cfg(feature = "mldsa")]
mod mldsa_wallet {
    use crate::hash::Hash256;
    use ml_dsa::{signature::Keypair, MlDsaParams, Signer, SigningKey, B32};

    pub fn public_key<P: MlDsaParams>(graine: &[u8; 32]) -> Vec<u8> {
        SigningKey::<P>::from_seed(&B32::from(*graine))
            .verifying_key()
            .encode()[..]
            .to_vec()
    }

    pub fn sign<P: MlDsaParams>(graine: &[u8; 32], message: &Hash256) -> Vec<u8> {
        SigningKey::<P>::from_seed(&B32::from(*graine))
            .sign(message.as_bytes())
            .encode()[..]
            .to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{genesis_block, Chain, GENESIS_TIME};
    use crate::consensus::TARGET_BLOCK_SECS;

    fn portefeuille() -> Wallet {
        Wallet::from_seed([0x11; 32], Network::Regtest)
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
                let s = w.sign_at(0, &m);
                assert_eq!(crate::sig::verify(SchemeId::MlDsa65, &pk, &m, &s), Ok(()));
            }
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
                Amount::from_units(1_000),
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
                Amount::from_units(1_000),
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
}
