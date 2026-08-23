//! # q21-core
//!
//! Noyau de consensus du protocole Q21 : une monnaie electronique pair-a-pair
//! concue pour survivre a l'algorithme de Shor, et pour etre minee sur une
//! machine ordinaire.
//!
//! Ce crate correspond a la **phase 1** de la feuille de route du livre blanc :
//! types de base, calendrier d'emission, hachage, arbres de Merkle, format
//! d'adresse versionne, structures de transaction et de bloc. Il ne contient ni
//! reseau, ni stockage, ni preuve de travail : ces couches viennent ensuite et
//! dependent toutes de celle-ci.
//!
//! ## Deux principes qui expliquent le reste du code
//!
//! **Aucune dependance obligatoire.** Tout ce qui est ici — SHA-256, Bech32m,
//! Merkle, emission — est implemente et verifie contre des vecteurs officiels.
//! Une mise a jour de dependance qui changerait un comportement de hachage
//! scinderait la chaine ; ce risque n'est pas acceptable sur du code de
//! consensus.
//!
//! **Une exception absolue : ML-DSA.** Ecrire soi-meme un schema de signature a
//! reseaux euclidiens est une faute professionnelle. Le module [`sig`] definit
//! l'interface et les tailles ; l'implementation se branche via la feature
//! `mldsa` sur le crate `ml-dsa` de RustCrypto. Sans cette feature, la
//! verification echoue bruyamment plutot que d'accepter en silence.
//!
//! ## Exemple
//!
//! ```
//! use q21_core::{address::{Address, Network}, sig::SchemeId, emission, consensus};
//!
//! // Une adresse porte le schema de signature qui la protege.
//! let pubkey = vec![0u8; SchemeId::MlDsa65.pubkey_len()];
//! let adresse = Address::from_pubkey(Network::Testnet, SchemeId::MlDsa65, &pubkey);
//! assert!(adresse.to_string_bech32().starts_with("tq21"));
//!
//! // Le plafond tient, quelle que soit la hauteur consideree.
//! let dans_trente_ans = consensus::BLOCKS_PER_YEAR * 30;
//! assert!(emission::total_supply_at(dans_trente_ans).units() <= consensus::MAX_SUPPLY);
//! ```

pub mod addr;
pub mod address;
pub mod amount;
pub mod arret;
pub mod bech32;
pub mod block;
pub mod chain;
pub mod compact;
pub mod consensus;
pub mod emission;
pub mod explorer;
pub mod hash;
pub mod http;
pub mod json;
pub mod kdf;
pub mod lamport;
pub mod memhard;
pub mod mempool;
pub mod merkle;
pub mod net;
pub mod pow;
pub mod prompt;
pub mod rng;
pub mod rpc;
pub mod ser;
pub mod sha256;
pub mod sig;
pub mod siphash;
pub mod state;
pub mod store;
pub mod tx;
pub mod uint;
pub mod utxo;
pub mod validate;
pub mod verrou;
pub mod wallet;
pub mod wallet_ui;
pub mod wire;

pub use address::{Address, Network};
pub use amount::Amount;
pub use block::{Block, BlockHeader};
pub use chain::Chain;
pub use hash::Hash256;
pub use sig::SchemeId;
pub use tx::{OutPoint, Transaction, TxIn, TxOut};
pub use utxo::UtxoSet;
pub use wallet::Wallet;
