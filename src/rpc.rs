//! API JSON-RPC 2.0.
//!
//! # Pourquoi cette API existe, et pourquoi elle est locale
//!
//! Pour consulter une chaine, presque tout le monde ouvre aujourd'hui le site
//! d'un tiers. C'est-a-dire qu'on **fait confiance a quelqu'un** pour savoir ce
//! que contient un systeme concu precisement pour ne faire confiance a personne.
//! L'explorateur de Q21 est servi par le noeud lui-meme, sur le bouclage local.
//! Ce que vous lisez, votre machine l'a valide.
//!
//! # Deux familles de methodes, separees exprès
//!
//! - **Lecture** : etat de la chaine, blocs, transactions, mempool, emission.
//!   Elles ne peuvent rien deplacer.
//! - **Portefeuille** : solde, adresse neuve, envoi. Elles peuvent perdre des
//!   fonds, et sont donc **desactivees par defaut** — il faut les demander
//!   explicitement. Un port RPC de consultation ne doit jamais devenir un port
//!   de depense par inadvertance.
//!
//! # Montants
//!
//! Chaque montant sort deux fois : en entier d'unites indivisibles, et en
//! chaine formatee. Jamais en flottant. Un client qui relit un solde en `double`
//! perd des unites, et personne ne s'en apercoit avant qu'il soit trop tard.

use crate::address::{Address, Network};
use crate::amount::Amount;
use crate::block::Block;
use crate::consensus::*;
use crate::emission;
use crate::hash::Hash256;
use crate::json::{parse, Json};
use crate::memhard;
use crate::net::Node;
use crate::sig::SchemeId;
use crate::tx::Transaction;
use crate::wallet::Wallet;
use std::sync::{Arc, Mutex};

/// Codes d'erreur JSON-RPC 2.0.
pub const ERR_PARSE: i64 = -32700;

/// Message rendu a l'appelant pour une erreur de portefeuille.
///
/// # Ce qui fuyait
///
/// L'erreur etait rendue par `format!("{e:?}")`, donc avec son contenu :
/// `FondsInsuffisants { disponible: 43120000, demande: ... }`. Le solde exact
/// partait ainsi vers un appelant qui n'avait qu'a demander une somme absurde
/// pour l'obtenir. Un refus n'a pas a etre un relevé de compte.
///
/// Les autres variantes ne portent rien de sensible et gardent un message
/// precis : un utilisateur qui se trompe doit comprendre pourquoi.
/// Secondes depuis 1970, pour horodater ce qui n'est pas encore dans un bloc.
///
/// Une transaction du reservoir n'a pas d'heure de protocole : la sienne sera
/// celle du bloc qui l'inclura. En attendant, l'interface a besoin de quelque
/// chose a afficher, et « maintenant » est la moins fausse des reponses.
fn maintenant_utc() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Message rendu a l'appelant pour un refus du reservoir.
///
/// # Ce qui etait rendu avant
///
/// `format!("{e:?}")`, donc la structure Rust brute :
/// `ConflitDeDepense(OutPoint { txid: Hash256(3f2a...), index: 0 })`.
/// Illisible pour qui n'a pas la definition sous les yeux, et sans la moindre
/// indication de ce qu'il faut faire. Un essai reel de l'interface a bute
/// dessus deux fois de suite.
///
/// Chaque refus dit maintenant **ce qui s'est passe** et **ce qui peut y
/// remedier**. Les valeurs numeriques restent, elles sont utiles ; c'est la
/// syntaxe de debogage qui disparait.
fn message_reservoir(e: &crate::mempool::MempoolError) -> String {
    use crate::mempool::MempoolError as M;
    match e {
        M::DejaPresent => "cette transaction est deja en attente".to_string(),
        M::ConflitDeDepense(_) => "une transaction deja en attente depense les memes fonds. \
             Attendez qu'elle soit confirmee avant d'en envoyer une autre."
            .to_string(),
        M::DependanceNonConfirmee(_) => {
            "cette depense s'appuie sur des fonds recus dans une transaction \
             encore non confirmee. Attendez un bloc."
                .to_string()
        }
        M::TauxDeFraisTropBas { recu, minimum } => format!(
            "frais trop bas pour etre relayee : {recu} par millier d'unites de poids, \
             minimum {minimum}. Demandez une nouvelle estimation."
        ),
        M::Inminable { poids, size } => format!(
            "transaction trop lourde pour tenir dans un bloc : {size} octets, \
             poids {poids}. Envoyez un montant qui demande moins d'entrees."
        ),
        M::PleinEtTropPeuPayee => "le reservoir est plein et cette transaction paie moins \
             que la moins-disante. Augmentez les frais."
            .to_string(),
        M::Validation(v) => format!("refusee par la validation : {v:?}"),
    }
}

fn message_portefeuille(e: &crate::wallet::WalletError) -> &'static str {
    use crate::wallet::WalletError as W;
    match e {
        W::FondsInsuffisants { .. } => "fonds insuffisants",
        W::ClefDejaUtilisee(_) => {
            "cette clef a deja signe : sur un schema a usage unique, resigner \
             revelerait la clef privee"
        }
        W::ClefInconnue => "clef inconnue de ce portefeuille",
        W::MontantNul => "montant nul",
        W::MontantHorsBornes => "montant ou frais au-dela de ce qui peut exister",
        W::SchemaNonSupporte(_) => "schema de signature non disponible dans ce binaire",
        W::AleaIndisponible => "generateur d'alea du systeme inaccessible",
        W::SauvegardeInvalide => "code de sauvegarde illisible",
        W::SauvegardeAutreReseau => "code de sauvegarde d'un autre reseau",
        W::VerrouIncoherent { .. } => {
            "incoherence entre la clef derivee et la sortie a depenser : rien \
             n'a ete signe"
        }
        W::EnregistrementImpossible => {
            "le portefeuille n'a pas pu etre enregistre avant la signature : rien \
             n'a ete signe, verifiez le disque"
        }
    }
}

/// Appels acceptes dans un seul lot JSON-RPC.
///
/// Un lot n'existe que pour epargner des allers-retours reseau. Cent suffisent
/// a cela ; dix mille ne servent qu'a multiplier le travail du noeud par dix
/// mille pour le prix d'une requete.
pub const MAX_LOT: usize = 100;

/// Taille cumulee des reponses d'un lot, en octets.
///
/// La reponse etait assemblee entierement en memoire avant emission, sans
/// aucune borne : une requete d'un mebioctet produisait des dizaines de
/// mebioctets de tas.
pub const MAX_REPONSE_LOT: usize = 8 * 1024 * 1024;

/// Blocs remontes au maximum par `gettransaction` sans index.
///
/// Le balayage arriere de toute la chaine, sous le verrou global du noeud, est
/// une amplification en travail : le cout croit avec la hauteur, et un lot le
/// multipliait. En attendant un index par identifiant de transaction, on borne
/// la recherche et on **le dit** dans la reponse plutot que de mentir par
/// omission.
pub const MAX_BLOCS_BALAYES: u64 = 2_000;

/// Frais retenus quand l'appelant n'en propose aucun, en unites.
///
/// Volontairement modeste : sur une chaine peu chargee, payer davantage
/// n'accelere rien. `estimatefee` propose une valeur mesuree sur l'etat reel du
/// reservoir ; celle-ci n'est qu'un repli.
pub const FRAIS_DEFAUT: u64 = 1_000;

/// Blocs remontes par `listtransactions`.
///
/// Sans index par adresse, retrouver l'historique demande de relire les corps.
/// La fenetre est bornee et **annoncee dans la reponse** : un portefeuille qui
/// affiche un historique tronque sans le dire ment a son porteur.
pub const FENETRE_HISTORIQUE: u64 = 5_000;

/// Duree de deverrouillage par defaut, en secondes.
pub const DEVERROUILLAGE_DEFAUT: u64 = 300;
pub const ERR_REQUETE: i64 = -32600;
pub const ERR_METHODE: i64 = -32601;
pub const ERR_PARAMS: i64 = -32602;
pub const ERR_INTERNE: i64 = -32603;
/// Erreurs applicatives.
pub const ERR_INTROUVABLE: i64 = -1;
pub const ERR_PORTEFEUILLE_DESACTIVE: i64 = -2;
pub const ERR_PORTEFEUILLE: i64 = -3;

/// Ce qui est appele apres toute operation ayant modifie le portefeuille.
///
/// # Le defaut que ce rappel repare
///
/// `sendtoaddress` et `getnewaddress` mutent le portefeuille : la premiere
/// marque une clef comme consommee, la seconde avance le compteur d'indices.
/// **Rien n'ecrivait ces changements sur disque.** Ils vivaient dans la memoire
/// du processus et mouraient avec lui.
///
/// Pour ML-DSA la consequence se limite a une adresse reemployee — un defaut de
/// confidentialite. Pour un schema a usage unique, c'est une clef Lamport qui
/// resservirait, donc une clef privee publiee. Le balayage de la chaine au
/// demarrage rattrape ce cas precis, mais un filet de securite n'est pas une
/// excuse pour laisser le trou.
///
/// Le rappel est fourni par l'appelant, qui seul sait ou vit le fichier.
/// Rappel d'enregistrement du portefeuille.
///
/// Rend un resultat : quand il sert d'ecriture anticipee avant une signature,
/// un echec doit **empecher** la signature, pas seulement etre affiche.
pub type SurChangement = Arc<dyn Fn(&Wallet) -> Result<(), String> + Send + Sync>;

pub struct RpcContext {
    pub node: Arc<Node>,
    /// Absent si les methodes de portefeuille sont desactivees.
    pub wallet: Option<Arc<Mutex<Wallet>>>,
    pub network: Network,
    /// Index d'adresses, si le noeud a ete lance avec `--index-adresses`.
    ///
    /// Absent, les recherches d'adresse et de transaction retombent sur le
    /// balayage borne. La difference se voit a l'ecran : la reponse porte un
    /// champ qui dit laquelle des deux voies a servi, et jusqu'ou elle a
    /// cherche. Une reponse incomplete qui se presente comme complete est pire
    /// qu'une absence de reponse.
    pub index: Option<Arc<Mutex<crate::index::Index>>>,
    /// Interrupteur et compteurs du minage, si ce nœud peut miner.
    ///
    /// Absent, `getminage` repond que la machine ne mine pas et `setminage`
    /// refuse : un nœud sans portefeuille n'a nulle part ou verser une
    /// subvention, et le lui laisser croire serait pire que le lui refuser.
    pub minage: Option<Arc<crate::minage::Minage>>,
    /// Appele apres chaque operation qui modifie le portefeuille.
    ///
    /// Absent en memoire pure (epreuves). En production il **doit** etre
    /// fourni : sans lui, une depense n'est pas enregistree.
    pub sur_changement: Option<SurChangement>,
}

impl RpcContext {
    /// Contexte de lecture seule : aucune methode de portefeuille.
    pub fn lecture_seule(node: Arc<Node>, network: Network) -> RpcContext {
        RpcContext {
            node,
            wallet: None,
            network,
            index: None,
            minage: None,
            sur_changement: None,
        }
    }
}

fn erreur(code: i64, message: &str) -> Json {
    Json::obj()
        .set("code", Json::Int(code))
        .set("message", Json::str(message))
        .build()
}

fn montant(a: Amount) -> Json {
    Json::obj()
        .set("unites", Json::u64(a.units()))
        .set("q21", Json::str(a.to_string()))
        .build()
}

fn entete_json(h: &crate::block::BlockHeader) -> Json {
    Json::obj()
        .set("id", Json::str(h.block_id().to_hex()))
        .set("hauteur", Json::u64(h.height))
        .set("parent", Json::str(h.prev_block.to_hex()))
        .set("merkle", Json::str(h.merkle_root.to_hex()))
        .set("oncles_racine", Json::str(h.uncles_root.to_hex()))
        .set("mineur", Json::str(h.miner.to_hex()))
        .set("horodatage", Json::u64(h.time))
        .set("bits", Json::str(format!("{:#010x}", h.bits)))
        .set("nonce", Json::u64(h.nonce))
        .build()
}

/// Rendu d'une transaction.
///
/// Le reseau est exige parce qu'une sortie doit montrer une **adresse**, pas
/// seulement l'empreinte de clef qu'elle porte. L'empreinte est ce que le
/// protocole manipule ; l'adresse est ce qu'un humain copie, colle et
/// reconnait — et une adresse ne se forme pas sans savoir de quel reseau elle
/// releve. Un explorateur qui n'afficherait que des empreintes obligerait a
/// faire la conversion de tete pour retrouver une adresse dans son
/// portefeuille.
fn tx_json(t: &Transaction, reseau: Network) -> Json {
    let entrees: Vec<Json> = t
        .inputs
        .iter()
        .map(|e| {
            Json::obj()
                .set("txid", Json::str(e.prev_out.txid.to_hex()))
                .set("index", Json::u64(e.prev_out.index as u64))
                .set(
                    "temoin_octets",
                    Json::u64((e.witness.pubkey.len() + e.witness.signature.len()) as u64),
                )
                .build()
        })
        .collect();
    let sorties: Vec<Json> = t
        .outputs
        .iter()
        .map(|o| {
            Json::obj()
                .set("valeur", montant(o.value))
                .set("schema", Json::str(o.scheme.name()))
                .set("empreinte_clef", Json::str(o.pubkey_hash.to_hex()))
                .set(
                    "adresse",
                    Json::str(
                        crate::address::Address {
                            network: reseau,
                            scheme: o.scheme,
                            hash: o.pubkey_hash,
                        }
                        .to_string_bech32(),
                    ),
                )
                .build()
        })
        .collect();

    let complet = t.encode().len();
    let corps = t.encode_without_witness().len();
    Json::obj()
        .set("txid", Json::str(t.txid().to_hex()))
        .set("wtxid", Json::str(t.wtxid().to_hex()))
        .set("coinbase", Json::Bool(t.is_coinbase()))
        .set("entrees", Json::array(entrees))
        .set("sorties", Json::array(sorties))
        .set("taille_octets", Json::u64(complet as u64))
        .set("temoin_octets", Json::u64((complet - corps) as u64))
        .set(
            "temoin_pourcent",
            Json::u64(((complet - corps) * 100).checked_div(complet).unwrap_or(0) as u64),
        )
        .set("poids", Json::u64(t.weight(WITNESS_DISCOUNT)))
        .build()
}

/// Lit un montant en Q21 (ex. `1.5`, `0.005`) et le rend en unites, sans
/// jamais passer par un flottant. Rend `None` sur une saisie qui n'est pas un
/// montant : plus de huit decimales, un caractere etranger, ou rien du tout.
fn montant_en_unites(s: &str) -> Option<u64> {
    let s = s.trim();
    let (ent, frac) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    if ent.is_empty() && frac.is_empty() {
        return None;
    }
    if frac.len() > DECIMALS as usize {
        return None;
    }
    if !ent.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let e: u64 = if ent.is_empty() { 0 } else { ent.parse().ok()? };
    let mut f: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse().ok()?
    };
    for _ in frac.len()..DECIMALS as usize {
        f = f.checked_mul(10)?;
    }
    e.checked_mul(UNITS_PER_COIN)?.checked_add(f)
}

fn bloc_json(b: &Block, reseau: Network) -> Json {
    let txs: Vec<Json> = b.transactions.iter().map(|t| tx_json(t, reseau)).collect();
    let oncles: Vec<Json> = b.uncles.iter().map(entete_json).collect();
    Json::obj()
        .set("entete", entete_json(&b.header))
        .set("taille_octets", Json::u64(b.encode().len() as u64))
        .set(
            "subvention",
            montant(emission::block_subsidy(b.header.height)),
        )
        .set("nb_transactions", Json::u64(b.transactions.len() as u64))
        .set("transactions", Json::array(txs))
        .set("oncles", Json::array(oncles))
        .build()
}

impl RpcContext {
    /// Traite un document JSON-RPC et rend la reponse encodee.
    pub fn handle(&self, corps: &str) -> String {
        let requete = match parse(corps) {
            Ok(v) => v,
            Err(_) => {
                return Json::obj()
                    .set("jsonrpc", Json::str("2.0"))
                    .set("id", Json::Null)
                    .set("error", erreur(ERR_PARSE, "document JSON illisible"))
                    .build()
                    .encode()
            }
        };

        // --- Lot de requetes : chacune traitee independamment, mais pas
        //     gratuitement.
        //
        // Un audit a mesure l'amplification : une requete d'un mebioctet — la
        // taille maximale d'un corps — contient des dizaines de milliers
        // d'appels, chacun produisant sa reponse, le tout assemble **en
        // memoire** avant emission. Certains appels coutent bien plus que leur
        // taille : un `gettransaction` balaie toute la chaine, sous le verrou
        // global du noeud.
        //
        // Le lot reste utile — il epargne des allers-retours — mais il est
        // borne, et la reponse aussi.
        if let Some(lot) = requete.as_array() {
            if lot.len() > MAX_LOT {
                return Json::obj()
                    .set("jsonrpc", Json::str("2.0"))
                    .set("id", Json::Null)
                    .set(
                        "error",
                        erreur(
                            ERR_REQUETE,
                            &format!("lot de {} appels : maximum {MAX_LOT}", lot.len()),
                        ),
                    )
                    .build()
                    .encode();
            }
            let mut reponses: Vec<Json> = Vec::with_capacity(lot.len());
            let mut octets = 0usize;
            for r in lot {
                let rep = self.une(r);
                octets += rep.encode().len();
                if octets > MAX_REPONSE_LOT {
                    reponses.push(
                        Json::obj()
                            .set("jsonrpc", Json::str("2.0"))
                            .set("id", Json::Null)
                            .set(
                                "error",
                                erreur(ERR_REQUETE, "reponse de lot trop volumineuse : tronquee"),
                            )
                            .build(),
                    );
                    break;
                }
                reponses.push(rep);
            }
            return Json::array(reponses).encode();
        }
        self.une(&requete).encode()
    }

    fn une(&self, requete: &Json) -> Json {
        let id = requete.get("id").cloned().unwrap_or(Json::Null);
        let methode = match requete.get("method").and_then(|m| m.as_str()) {
            Some(m) => m.to_string(),
            None => {
                return Json::obj()
                    .set("jsonrpc", Json::str("2.0"))
                    .set("id", id)
                    .set("error", erreur(ERR_REQUETE, "champ 'method' absent"))
                    .build()
            }
        };
        let params = requete.get("params").cloned().unwrap_or(Json::Null);

        match self.dispatch(&methode, &params) {
            Ok(r) => Json::obj()
                .set("jsonrpc", Json::str("2.0"))
                .set("id", id)
                .set("result", r)
                .build(),
            Err(e) => Json::obj()
                .set("jsonrpc", Json::str("2.0"))
                .set("id", id)
                .set("error", e)
                .build(),
        }
    }

    /// Liste des methodes exposees.
    pub fn methodes() -> Vec<(&'static str, &'static str)> {
        vec![
            ("getinfo", "Etat de la chaine, du reseau et du mempool"),
            ("getblock", "Bloc complet, par hauteur ou par identifiant"),
            ("getblockheader", "En-tete seul"),
            ("gettransaction", "Transaction, dans un bloc ou au mempool"),
            ("getmempool", "Contenu du reservoir de transactions"),
            ("getpeers", "Pairs connectes"),
            ("getemission", "Courbe d'emission a une hauteur donnee"),
            ("getpow", "Parametres de la preuve de travail memory-hard"),
            (
                "getsecurity",
                "Ce qui est protege face a une attaque a 51 %",
            ),
            ("getsupply", "Masse monetaire emise et plafond"),
            (
                "getempreinteutxo",
                "Empreinte MuHash du jeu d'UTXO a la tete (engagement sur l'etat)",
            ),
            ("listmethods", "Cette liste"),
            ("getbalance", "[portefeuille] Solde depensable"),
            ("getnewaddress", "[portefeuille] Adresse de reception neuve"),
            ("sendtoaddress", "[portefeuille] Envoi de fonds"),
            (
                "sendmany",
                "[portefeuille] Envoi a plusieurs destinataires en une transaction",
            ),
            (
                "getwalletinfo",
                "[portefeuille] Schema, reseau, adresses, clefs consommees",
            ),
            (
                "listaddresses",
                "[portefeuille] Adresses connues du portefeuille",
            ),
            (
                "setaddresslabel",
                "[portefeuille] Nomme une adresse dans le carnet local",
            ),
            (
                "listtransactions",
                "[portefeuille] Historique des mouvements",
            ),
            (
                "estimatefee",
                "[portefeuille] Frais suggeres, a nombre d'entrees suppose",
            ),
            (
                "preparersend",
                "[portefeuille] Chiffres exacts d'un envoi, pieces reellement selectionnees",
            ),
            (
                "getminage",
                "Etat du minage : actif, debit mesure, blocs trouves",
            ),
            (
                "getreseau",
                "Effort de minage du reseau, mesure sur la difficulte des derniers blocs",
            ),
            (
                "setminage",
                "[portefeuille] Allume ou eteint le minage sans relancer le programme",
            ),
            ("getsyncstatus", "Etat de la synchronisation avec le reseau"),
            (
                "arreter",
                "[portefeuille] Demande l'arret propre du noeud qui sert cette page",
            ),
            (
                "rechercher",
                "Devine ce qu'on lui donne : hauteur, bloc, transaction, adresse ou montant",
            ),
            (
                "getadresse",
                "Mouvements et solde d'une adresse, sans qu'elle appartienne au portefeuille",
            ),
            (
                "getmontant",
                "Transactions portant une sortie d'un montant donne, sur une fenetre bornee",
            ),
        ]
    }

    fn dispatch(&self, methode: &str, params: &Json) -> Result<Json, Json> {
        match methode {
            "getinfo" => Ok(self.getinfo()),
            "getempreinteutxo" => Ok(self.getempreinteutxo()),
            "getblock" => self.getblock(params, true),
            "getblockheader" => self.getblock(params, false),
            "gettransaction" => self.gettransaction(params),
            "getmempool" => Ok(self.getmempool()),
            "getpeers" => Ok(self.getpeers()),
            "getemission" => self.getemission(params),
            "getpow" => Ok(self.getpow()),
            "getsecurity" => Ok(Self::getsecurity()),
            "getsupply" => Ok(self.getsupply()),
            "listmethods" => Ok(Json::array(
                Self::methodes()
                    .into_iter()
                    .map(|(n, d)| {
                        Json::obj()
                            .set("nom", Json::str(n))
                            .set("description", Json::str(d))
                            .build()
                    })
                    .collect(),
            )),
            "getbalance" => self.getbalance(),
            "getnewaddress" => self.getnewaddress(),
            "sendtoaddress" => self.sendtoaddress(params),
            "sendmany" => self.sendmany(params),
            "getwalletinfo" => self.getwalletinfo(),
            "listaddresses" => self.listaddresses(),
            "setaddresslabel" => self.setaddresslabel(params),
            "listtransactions" => self.listtransactions(params),
            "estimatefee" => self.estimatefee(params),
            "preparersend" => self.preparersend(params),
            "getsyncstatus" => Ok(self.getsyncstatus()),
            "getminage" => Ok(self.getminage()),
            "getreseau" => Ok(self.getreseau()),
            "setminage" => self.setminage(params),
            "arreter" => self.arreter(),
            "rechercher" => self.rechercher(params),
            "getadresse" => self.getadresse(params),
            "getmontant" => self.getmontant(params),
            autre => Err(erreur(
                ERR_METHODE,
                &format!("methode inconnue : {autre}. Essayez listmethods."),
            )),
        }
    }

    // -----------------------------------------------------------------------
    // Lecture
    // -----------------------------------------------------------------------

    fn getinfo(&self) -> Json {
        use std::sync::atomic::Ordering;
        let (hauteur, tete, travail, connus, emis, utxo, bits) = self.node.with_chain(|c| {
            (
                c.height(),
                c.tip_id().to_hex(),
                c.total_work().bits(),
                c.known_blocks(),
                c.total_issued(),
                c.utxo.len(),
                c.tip().bits,
            )
        });
        let s = &self.node.stats;

        Json::obj()
            .set("reseau", Json::str(format!("{:?}", self.network)))
            .set("hauteur", Json::u64(hauteur))
            .set("tete", Json::str(tete))
            .set("travail_cumule_bits", Json::u64(travail as u64))
            .set("blocs_connus", Json::u64(connus as u64))
            .set("difficulte_bits", Json::str(format!("{bits:#010x}")))
            .set("emis", montant(emis))
            .set("utxo_total", Json::u64(utxo as u64))
            .set("pairs", Json::u64(self.node.peer_count() as u64))
            .set("mempool", Json::u64(self.node.mempool_len() as u64))
            .set("portefeuille_actif", Json::Bool(self.wallet.is_some()))
            // --- Deux constantes du protocole, rendues avec l'etat.
            //
            // Une interface qui veut annoncer *quand* une recompense sera
            // disponible a besoin des deux : combien de blocs il faut attendre,
            // et combien de temps dure un bloc. Les recopier dans la page
            // serait les figer a la main, et donc mentir le jour ou elles
            // changeraient. Le nœud est la seule source qui ait le droit de les
            // dire.
            .set("maturite_coinbase", Json::u64(COINBASE_MATURITY))
            .set("intervalle_cible_secondes", Json::u64(TARGET_BLOCK_SECS))
            .set(
                "reseau_stats",
                Json::obj()
                    .set(
                        "blocs_recus",
                        Json::u64(s.blocs_recus.load(Ordering::Relaxed)),
                    )
                    .set(
                        "blocs_acceptes",
                        Json::u64(s.blocs_acceptes.load(Ordering::Relaxed)),
                    )
                    .set(
                        "compacts_recus",
                        Json::u64(s.compacts_recus.load(Ordering::Relaxed)),
                    )
                    .set(
                        "compacts_sans_aller_retour",
                        Json::u64(s.compacts_sans_aller_retour.load(Ordering::Relaxed)),
                    )
                    .set("tx_recues", Json::u64(s.tx_recues.load(Ordering::Relaxed)))
                    .set(
                        "pairs_bannis",
                        Json::u64(s.pairs_bannis.load(Ordering::Relaxed)),
                    )
                    .build(),
            )
            .build()
    }

    /// Engagement sur l'etat de la monnaie : l'empreinte MuHash du jeu d'UTXO a
    /// la tete, avec le nombre de sorties et le total en circulation.
    ///
    /// Le calcul parcourt tout le jeu d'UTXO — c'est un appel qu'on fait a la
    /// demande, quand on veut comparer deux noeuds ou verifier un instantane, pas
    /// une valeur qu'on rafraichit en boucle. `getinfo` reste donc leger.
    fn getempreinteutxo(&self) -> Json {
        let (hauteur, tete, entrees, emis, empreinte) = self.node.with_chain(|c| {
            (
                c.height(),
                c.tip_id().to_hex(),
                c.utxo_count(),
                c.total_issued(),
                c.utxo_commitment().to_hex(),
            )
        });
        Json::obj()
            .set("hauteur", Json::u64(hauteur))
            .set("tete", Json::str(tete))
            .set("entrees", Json::u64(entrees as u64))
            .set("total", montant(emis))
            .set("empreinte", Json::str(empreinte))
            .build()
    }

    fn getblock(&self, params: &Json, complet: bool) -> Result<Json, Json> {
        let bloc = self.node.with_chain(|c| {
            if let Some(h) = params.get("hauteur").and_then(|v| v.as_u64()) {
                return c.block_at(h);
            }
            if let Some(id) = params.get("id").and_then(|v| v.as_str()) {
                if let Some(h) = Hash256::from_hex(id) {
                    return c.block_by_id(&h);
                }
            }
            // Sans parametre : le bloc de tete.
            c.block_at(c.height())
        });

        match bloc {
            Some(b) if complet => Ok(bloc_json(&b, self.network)),
            Some(b) => Ok(entete_json(&b.header)),
            None => Err(erreur(ERR_INTROUVABLE, "bloc introuvable")),
        }
    }

    fn gettransaction(&self, params: &Json) -> Result<Json, Json> {
        let txid = params
            .get("txid")
            .and_then(|v| v.as_str())
            .and_then(Hash256::from_hex)
            .ok_or_else(|| erreur(ERR_PARAMS, "parametre 'txid' attendu, en hexadecimal"))?;

        // Au mempool d'abord : c'est la que regarde celui qui vient d'envoyer.
        if let Some(t) = self.node.with_mempool(|m| m.get(&txid).cloned()) {
            return Ok(Json::obj()
                .set("confirmee", Json::Bool(false))
                .set("transaction", tx_json(&t, self.network))
                .set_all(self.champs_frais(&t))
                .build());
        }

        // L'index, s'il existe : une lecture de table plutot qu'un balayage.
        if let Some((hauteur, rang)) = self.situer_transaction(&txid) {
            let trouve = self.node.with_chain(|c| {
                let b = c.block_at(hauteur)?;
                let t = b.transactions.get(rang as usize)?.clone();
                Some((t, b.header.block_id()))
            });
            if let Some((t, bloc)) = trouve {
                return Ok(Json::obj()
                    .set("confirmee", Json::Bool(true))
                    .set("hauteur", Json::u64(hauteur))
                    .set("bloc", Json::str(bloc.to_hex()))
                    .set("transaction", tx_json(&t, self.network))
                    .set_all(self.champs_frais(&t))
                    .build());
            }
        }

        // Sinon, dans la chaine. Balayage arriere : une transaction cherchee
        // est presque toujours recente. Sans index, on reste honnete sur le
        // cout — et sur la borne.
        let mut fond_atteint = false;
        let trouve = self.node.with_chain(|c| {
            let mut h = c.height() as i64;
            let plancher = (c.height().saturating_sub(MAX_BLOCS_BALAYES)) as i64;
            while h >= 0 {
                if h < plancher {
                    fond_atteint = true;
                    return None;
                }
                if let Some(b) = c.block_at(h as u64) {
                    if let Some(t) = b.transactions.iter().find(|t| t.txid() == txid) {
                        return Some((t.clone(), b.header.height, b.header.block_id()));
                    }
                }
                h -= 1;
            }
            None
        });

        if trouve.is_none() && fond_atteint {
            return Err(erreur(
                ERR_REQUETE,
                &format!(
                    "transaction introuvable dans les {MAX_BLOCS_BALAYES} derniers \
                     blocs. Ce noeud n'a pas d'index par identifiant : au-dela, \
                     la recherche n'est pas rendue."
                ),
            ));
        }

        match trouve {
            Some((t, hauteur, bloc)) => Ok(Json::obj()
                .set("confirmee", Json::Bool(true))
                .set("hauteur", Json::u64(hauteur))
                .set("bloc", Json::str(bloc.to_hex()))
                .set("transaction", tx_json(&t, self.network))
                .set_all(self.champs_frais(&t))
                .build()),
            None => Err(erreur(ERR_INTROUVABLE, "transaction introuvable")),
        }
    }

    fn getmempool(&self) -> Json {
        let (n, octets, ids) = self.node.with_mempool(|m| (m.len(), m.bytes(), m.txids()));
        Json::obj()
            .set("nb_transactions", Json::u64(n as u64))
            .set("octets", Json::u64(octets as u64))
            .set(
                "txids",
                Json::array(
                    ids.iter()
                        .take(200)
                        .map(|h| Json::str(h.to_hex()))
                        .collect(),
                ),
            )
            .build()
    }

    fn getpeers(&self) -> Json {
        Json::obj()
            .set("nb_pairs", Json::u64(self.node.peer_count() as u64))
            .set("maximum", Json::u64(crate::net::MAX_PEERS as u64))
            .build()
    }

    fn getemission(&self, params: &Json) -> Result<Json, Json> {
        let hauteur = match params.get("hauteur").and_then(|v| v.as_u64()) {
            Some(h) => h,
            None => self.node.with_chain(|c| c.height()),
        };
        let cumul = emission::total_supply_at(hauteur);
        Ok(Json::obj()
            .set("hauteur", Json::u64(hauteur))
            .set("annee_approx", Json::u64(hauteur / BLOCKS_PER_YEAR))
            .set("subvention", montant(emission::block_subsidy(hauteur)))
            .set("emis_cumule", montant(cumul))
            .set("plafond", montant(Amount::from_units(MAX_SUPPLY)))
            .set(
                "pourcent_du_plafond_millieme",
                Json::u64(cumul.units().saturating_mul(100_000) / MAX_SUPPLY),
            )
            .build())
    }

    fn getpow(&self) -> Json {
        let params = self.node.with_chain(|c| c.pow_params());
        let hauteur = self.node.with_chain(|c| c.height());
        let epoque = memhard::epoch_of(hauteur);
        let n = memhard::table_size(params, epoque);
        let c = memhard::cache_size(params, epoque);
        Json::obj()
            .set(
                "algorithme",
                Json::str("Q21 memory-hard a deux niveaux, table croissante"),
            )
            .set("epoque", Json::u64(epoque))
            .set("elements_table", Json::u64(n as u64))
            .set("elements_cache", Json::u64(c as u64))
            .set(
                "memoire_mineur_octets",
                Json::u64(n as u64 * POW_ELEMENT_SIZE as u64),
            )
            .set(
                "memoire_noeud_octets",
                Json::u64(c as u64 * POW_ELEMENT_SIZE as u64),
            )
            .set("acces_par_tentative", Json::u64(POW_K as u64))
            .set("acces_cache_par_element", Json::u64(POW_J as u64))
            .set("croissance_pourcent", Json::u64(POW_TABLE_GROWTH_PCT))
            .set("blocs_par_epoque", Json::u64(POW_EPOCH_BLOCKS))
            .set(
                "note",
                Json::str(
                    "Un noeud detient le cache (niveau 1), pas la table (niveau 2). \
                     C'est le prix de la correction de la phase 6 : sans elle, se \
                     passer de memoire ne coutait que 2,86 x.",
                ),
            )
            .build()
    }

    fn getsupply(&self) -> Json {
        let (emis, utxo) = self
            .node
            .with_chain(|c| (c.total_issued(), c.utxo.total_value()));
        Json::obj()
            .set("emis", montant(emis))
            .set("dans_les_utxo", montant(utxo))
            .set("plafond", montant(Amount::from_units(MAX_SUPPLY)))
            .set("plafond_q21", Json::u64(MAX_SUPPLY_COINS))
            .set("sous_le_plafond", Json::Bool(emis.units() <= MAX_SUPPLY))
            .build()
    }

    /// Expose la position du projet sur l'attaque a 51 %, en donnees.
    ///
    /// Une API qui ne dit que ce qui rassure ment par omission.
    fn getsecurity() -> Json {
        Json::obj()
            .set("protection_100_pourcent_possible", Json::Bool(false))
            .set(
                "pourquoi",
                Json::str(
                    "Le consensus definit la chaine valide comme celle qui porte le plus \
                     de travail. Un majoritaire en produit plus que tous les autres, par \
                     definition. Refuser sa chaine supposerait de savoir que c'est lui : \
                     une identite, donc une autorite, donc la fin du caractere sans \
                     permission. C'est un theoreme, pas une lacune d'implementation.",
                ),
            )
            .set(
                "un_attaquant_peut",
                Json::array(vec![
                    Json::str("reorganiser les blocs recents, donc annuler ses propres paiements"),
                    Json::str("refuser d'inclure certaines transactions"),
                ]),
            )
            .set(
                "un_attaquant_ne_peut_pas",
                Json::array(vec![
                    Json::str("voler une piece dont il n'a pas la clef"),
                    Json::str("fabriquer une unite au-dela de la subvention"),
                    Json::str("relever le plafond de 21 000 001"),
                    Json::str("changer une regle : ses blocs sont simplement rejetes"),
                ]),
            )
            .set(
                "defenses",
                Json::obj()
                    .set("choix_par_travail_cumule", Json::Bool(true))
                    .set("finalite_glissante_blocs", Json::u64(MAX_REORG_DEPTH))
                    .set(
                        "finalite_glissante_heures",
                        Json::u64(MAX_REORG_DEPTH * TARGET_BLOCK_SECS / 3600),
                    )
                    .set(
                        "penalite_a_partir_de_blocs",
                        Json::u64(REORG_PENALTY_FROM_DEPTH),
                    )
                    .set(
                        "penalite_pourcent_par_bloc",
                        Json::u64(REORG_PENALTY_PCT_PER_BLOCK),
                    )
                    .set(
                        "penalite_plafond_pourcent",
                        Json::u64(REORG_PENALTY_MAX_PCT),
                    )
                    .set("recompenses_oncles", Json::Bool(true))
                    .set("pow_memory_hard", Json::Bool(true))
                    .build(),
            )
            .set(
                "cout_de_la_finalite_glissante",
                Json::str(
                    "Elle ne supprime pas l'attaque, elle en change la nature. Une \
                     partition reseau prolongee produit deux chaines qui ne se \
                     reconcilieront pas seules. On echange une reecriture silencieuse \
                     contre une scission visible.",
                ),
            )
            .build()
    }

    // -----------------------------------------------------------------------
    // Portefeuille
    // -----------------------------------------------------------------------

    /// Ecrit le portefeuille sur disque apres une modification.
    ///
    /// Silencieux si aucun rappel n'est fourni — le cas des epreuves en
    /// memoire. En production l'absence de rappel serait un defaut, et le
    /// lanceur en fournit toujours un.
    /// Enregistre le portefeuille apres une modification.
    ///
    /// Un echec est rendu a l'appelant ; les modifications qui ne mettent pas
    /// de clef en jeu (une etiquette, une adresse neuve) peuvent se contenter
    /// de le signaler, une depense doit s'arreter dessus.
    fn enregistrer(&self, w: &Wallet) -> Result<(), String> {
        match &self.sur_changement {
            Some(f) => f(w),
            None => Ok(()),
        }
    }

    fn portefeuille(&self) -> Result<&Arc<Mutex<Wallet>>, Json> {
        self.wallet.as_ref().ok_or_else(|| {
            erreur(
                ERR_PORTEFEUILLE_DESACTIVE,
                "methodes de portefeuille desactivees. Elles peuvent deplacer des \
                 fonds et doivent etre demandees explicitement au demarrage.",
            )
        })
    }

    /// Demande l'arret propre du noeud qui sert cette page.
    ///
    /// # Le defaut que cette methode repare
    ///
    /// Le seul moyen d'arreter le portefeuille etait Ctrl-C dans la fenetre
    /// noire. Sur Windows, un Ctrl-C recu pendant un fichier `.bat` fait poser
    /// par l'interpreteur sa propre question — « Terminer le programme de
    /// commandes (O/N) ? » — a laquelle les deux reponses ferment la fenetre.
    /// Le premier utilisateur a lu cela comme une panne. Ce n'en etait pas une :
    /// l'ecriture avait deja eu lieu. Mais on ne peut pas demander a quelqu'un
    /// de faire confiance a un message qui ressemble a une erreur.
    ///
    /// Une application se ferme par un bouton. Celui-ci leve le meme drapeau
    /// que Ctrl-C, la boucle principale le voit au tour suivant, ecrit ce
    /// qu'elle doit ecrire et rend la main : l'interpreteur n'a alors aucune
    /// question a poser, puisque rien n'a ete interrompu.
    ///
    /// # Pourquoi elle est reservee au mode portefeuille
    ///
    /// Un noeud public expose des methodes de lecture a qui les demande.
    /// « Arrete-toi » n'en est pas une. Elle passe donc par le meme controle
    /// que les methodes qui deplacent des fonds : le jeton, et le mode
    /// portefeuille demande explicitement au demarrage.
    fn arreter(&self) -> Result<Json, Json> {
        self.portefeuille()?;
        crate::arret::demander_arret();
        Ok(Json::obj()
            .set("arret", Json::Bool(true))
            .set(
                "note",
                Json::str(
                    "arret demande : le noeud ecrit son etat puis rend la main, \
                     en general en moins d'une seconde",
                ),
            )
            .build())
    }

    // -----------------------------------------------------------------------
    // Exploration
    // -----------------------------------------------------------------------

    /// Ou se trouve cette transaction, sans balayer si l'index est la.
    fn situer_transaction(&self, txid: &Hash256) -> Option<(u64, u32)> {
        if let Some(index) = &self.index {
            if let Ok(i) = index.lock() {
                if let Some(p) = i.position(txid) {
                    return Some((p.hauteur, p.rang));
                }
            }
        }
        None
    }

    /// Retrouve une sortie designee par un point d'entree.
    ///
    /// Sert a dire ce qu'une transaction a **depense** : une entree ne porte
    /// que la reference de la sortie qu'elle consomme, pas son montant ni son
    /// proprietaire. Sans index, on ne cherche pas : une reponse qui coute un
    /// balayage complet par entree n'est pas une reponse, et la page dit alors
    /// simplement qu'elle ne sait pas.
    fn resoudre_sortie(&self, point: &crate::tx::OutPoint) -> Option<crate::tx::TxOut> {
        let (hauteur, rang) = self.situer_transaction(&point.txid)?;
        self.node.with_chain(|c| {
            let b = c.block_at(hauteur)?;
            let t = b.transactions.get(rang as usize)?;
            t.outputs.get(point.index as usize).cloned()
        })
    }

    /// Le montant de chaque entree, la somme entrante, et si tout est resolu.
    ///
    /// Une entree ne porte que la reference de la sortie qu'elle consomme, pas
    /// son montant. On le retrouve par l'index — une lecture de table, pas un
    /// balayage. Si une seule entree echappe a l'index (pas d'index, ou piece
    /// trop ancienne pour lui), `connu` passe a `false` : les frais ne se
    /// calculent pas sur une somme partielle, et la page le dira plutot que de
    /// livrer un chiffre faux.
    ///
    /// Rend `(entrees, entrant, connu)` : `entrees` est aligne sur les entrees
    /// de la transaction, chaque element portant `valeur` quand elle est connue.
    fn resoudre_entrees(&self, t: &Transaction) -> (Vec<Json>, u64, bool) {
        let mut entrees = Vec::with_capacity(t.inputs.len());
        let mut entrant = 0u64;
        let mut connu = true;
        for e in &t.inputs {
            if e.prev_out.is_coinbase() {
                entrees.push(Json::obj().set("connu", Json::Bool(true)).build());
                continue;
            }
            match self.resoudre_sortie(&e.prev_out) {
                Some(o) => {
                    entrant = entrant.saturating_add(o.value.units());
                    entrees.push(
                        Json::obj()
                            .set("valeur", montant(o.value))
                            .set("connu", Json::Bool(true))
                            .build(),
                    );
                }
                None => {
                    connu = false;
                    entrees.push(Json::obj().set("connu", Json::Bool(false)).build());
                }
            }
        }
        (entrees, entrant, connu)
    }

    /// Enrichit une reponse de transaction confirmee avec les montants d'entree
    /// et les frais, quand ils sont resolus.
    ///
    /// Les frais d'une coinbase n'ont pas de sens — elle *percoit* les frais du
    /// bloc, elle n'en paie pas — donc on ne les affiche pas pour elle.
    fn champs_frais(&self, t: &Transaction) -> Vec<(&'static str, Json)> {
        let (entrees, entrant, connu) = self.resoudre_entrees(t);
        let coinbase = t.is_coinbase();
        let sortant: u64 = t.outputs.iter().map(|o| o.value.units()).sum();
        let frais_connu = connu && !coinbase;
        vec![
            ("entrees_montants", Json::array(entrees)),
            ("frais_connu", Json::Bool(frais_connu)),
            (
                "montant_entrant",
                if frais_connu {
                    montant(Amount::from_units(entrant))
                } else {
                    Json::Null
                },
            ),
            (
                "frais",
                if frais_connu {
                    montant(Amount::from_units(entrant.saturating_sub(sortant)))
                } else {
                    Json::Null
                },
            ),
        ]
    }

    /// Devine ce qu'on lui donne, et dit ou aller.
    ///
    /// Un explorateur n'a qu'un champ de saisie. C'est a lui de reconnaitre
    /// une hauteur, un identifiant de bloc, un identifiant de transaction ou
    /// une adresse — pas a l'utilisateur de choisir dans un menu ce qu'il tient
    /// deja dans le presse-papier.
    fn rechercher(&self, params: &Json) -> Result<Json, Json> {
        let brut = params
            .get("q")
            .and_then(|v| v.as_str())
            .ok_or_else(|| erreur(ERR_PARAMS, "parametre 'q' attendu"))?
            .trim()
            .to_string();
        if brut.is_empty() {
            return Err(erreur(ERR_PARAMS, "recherche vide"));
        }
        // Trop long pour etre quoi que ce soit : on refuse avant de travailler.
        if brut.len() > 200 {
            return Err(erreur(ERR_PARAMS, "recherche trop longue"));
        }

        let trouve = |genre: &str, valeur: String| {
            Ok(Json::obj()
                .set("genre", Json::str(genre))
                .set("valeur", Json::str(&valeur))
                .build())
        };

        // Une suite de chiffres : une hauteur.
        if brut.chars().all(|c| c.is_ascii_digit()) {
            let h: u64 = brut
                .parse()
                .map_err(|_| erreur(ERR_PARAMS, "hauteur illisible"))?;
            let existe = self.node.with_chain(|c| h <= c.height());
            if !existe {
                return Err(erreur(
                    ERR_INTROUVABLE,
                    &format!("aucun bloc a la hauteur {h} : la chaine s'arrete plus bas"),
                ));
            }
            return trouve("bloc", h.to_string());
        }

        // Un nombre a virgule decimale : un montant. La hauteur, elle, est un
        // entier — le point suffit a lever l'ambiguite, sans menu a choisir.
        if brut.contains('.') {
            let unites = montant_en_unites(&brut)
                .ok_or_else(|| erreur(ERR_PARAMS, "montant illisible : au plus 8 decimales"))?;
            // Forme canonique en Q21 : lisible dans l'URL, et reparsable telle
            // quelle par `getmontant`.
            return trouve("montant", Amount::from_units(unites).to_string());
        }

        // Une adresse : elle porte sa propre somme de controle, donc une faute
        // de frappe se detecte au lieu de mener ailleurs.
        if let Ok(a) = crate::address::Address::parse(&brut) {
            if a.network != self.network {
                return Err(erreur(
                    ERR_PARAMS,
                    &format!(
                        "cette adresse appartient au reseau {:?}, ce noeud suit {:?}",
                        a.network, self.network
                    ),
                ));
            }
            return trouve("adresse", brut);
        }

        // Soixante-quatre caracteres hexadecimaux : un bloc ou une transaction.
        // On regarde d'abord les blocs, dont la table est immediate.
        if let Some(h) = Hash256::from_hex(&brut) {
            if self.node.with_chain(|c| c.block_by_id(&h).is_some()) {
                return trouve("bloc-id", h.to_hex());
            }
            if self.node.with_mempool(|m| m.get(&h).is_some()) {
                return trouve("transaction", h.to_hex());
            }
            if self.situer_transaction(&h).is_some() {
                return trouve("transaction", h.to_hex());
            }
            // Sans index, on ne peut pas conclure a l'absence : on renvoie tout
            // de meme vers la page de transaction, qui balaiera et dira ce
            // qu'elle a pu voir.
            if self.index.is_none() {
                return trouve("transaction", h.to_hex());
            }
            return Err(erreur(
                ERR_INTROUVABLE,
                "ni bloc, ni transaction connue de ce noeud",
            ));
        }

        Err(erreur(
            ERR_PARAMS,
            "ni une hauteur, ni un identifiant de 64 caracteres hexadecimaux, \
             ni une adresse valide",
        ))
    }

    /// Mouvements et solde d'une adresse quelconque.
    ///
    /// « Quelconque » est le mot important : cette methode ne demande pas que
    /// l'adresse appartienne au portefeuille. C'est ce qui distingue un
    /// explorateur d'un portefeuille.
    ///
    /// Elle dit toujours **comment** elle a repondu — par l'index ou par un
    /// balayage borne — et jusqu'ou elle a cherche. Une reponse incomplete qui
    /// se presenterait comme complete serait pire qu'une absence de reponse :
    /// elle ferait conclure a tort qu'une adresse est vide.
    fn getadresse(&self, params: &Json) -> Result<Json, Json> {
        let brut = params
            .get("adresse")
            .and_then(|v| v.as_str())
            .ok_or_else(|| erreur(ERR_PARAMS, "parametre 'adresse' attendu"))?;
        let adresse = crate::address::Address::parse(brut)
            .map_err(|e| erreur(ERR_PARAMS, &format!("adresse illisible : {e:?}")))?;
        if adresse.network != self.network {
            return Err(erreur(
                ERR_PARAMS,
                &format!(
                    "cette adresse appartient au reseau {:?}, ce noeud suit {:?}",
                    adresse.network, self.network
                ),
            ));
        }
        let empreinte = adresse.hash;
        let maximum = params
            .get("max")
            .and_then(|v| v.as_u64())
            .unwrap_or(50)
            .clamp(1, 200) as usize;

        let hauteur = self.node.with_chain(|c| c.height());

        // --- Ou apparait cette adresse.
        let (mut positions, via_index, plancher) = match &self.index {
            Some(index) => {
                let i = index
                    .lock()
                    .map_err(|_| erreur(ERR_REQUETE, "index indisponible"))?;
                let v: Vec<(u64, u32)> = i
                    .positions(&empreinte)
                    .iter()
                    .map(|p| (p.hauteur, p.rang))
                    .collect();
                (v, true, 0u64)
            }
            None => {
                // Balayage arriere borne. La reponse le dira.
                let plancher = hauteur.saturating_sub(MAX_BLOCS_BALAYES);
                let v = self.node.with_chain(|c| {
                    let mut v: Vec<(u64, u32)> = Vec::new();
                    for h in plancher..=hauteur {
                        if let Some(b) = c.block_at(h) {
                            for (rang, t) in b.transactions.iter().enumerate() {
                                if t.outputs.iter().any(|o| o.pubkey_hash == empreinte) {
                                    v.push((h, rang as u32));
                                }
                            }
                        }
                    }
                    v
                });
                (v, false, plancher)
            }
        };
        positions.sort_unstable();
        positions.dedup();
        let total_mouvements = positions.len();
        // Du plus recent au plus ancien : c'est ce qu'on veut voir en premier.
        positions.reverse();
        positions.truncate(maximum);

        // --- Le detail de chaque mouvement.
        let mut mouvements = Vec::with_capacity(positions.len());
        let mut sortants_tous_resolus = true;
        for (h, rang) in positions {
            let Some(bloc) = self.node.with_chain(|c| c.block_at(h)) else {
                continue;
            };
            let Some(tx) = bloc.transactions.get(rang as usize).cloned() else {
                continue;
            };
            let recu: u64 = tx
                .outputs
                .iter()
                .filter(|o| o.pubkey_hash == empreinte)
                .map(|o| o.value.units())
                .sum();
            let mut envoye: u64 = 0;
            let mut connu = true;
            for entree in &tx.inputs {
                if entree.prev_out.is_coinbase() {
                    continue;
                }
                match self.resoudre_sortie(&entree.prev_out) {
                    Some(o) if o.pubkey_hash == empreinte => envoye += o.value.units(),
                    Some(_) => {}
                    None => connu = false,
                }
            }
            if !connu {
                sortants_tous_resolus = false;
            }
            mouvements.push(
                Json::obj()
                    .set("txid", Json::str(tx.txid().to_hex()))
                    .set("hauteur", Json::u64(h))
                    .set("horodatage", Json::u64(bloc.header.time))
                    .set("confirmations", Json::u64(hauteur.saturating_sub(h) + 1))
                    .set("coinbase", Json::Bool(tx.is_coinbase()))
                    .set("recu", montant(Amount::from_units(recu)))
                    .set("envoye", montant(Amount::from_units(envoye)))
                    .set("montant_sortant_connu", Json::Bool(connu))
                    .build(),
            );
        }

        // --- Le solde : ce que l'ensemble UTXO garde pour cette empreinte.
        //
        // Il ne depend ni de l'index ni du balayage : c'est l'etat que ce noeud
        // a valide lui-meme, et il est donc toujours exact, meme quand
        // l'historique affiche est borne.
        // Par l'index d'empreintes, jamais par un balayage : cette requete est
        // publique et non authentifiee, et le verrou qu'elle prend est celui du
        // consensus. Voir `UtxoSet::solde_de`.
        let (solde, sorties) = self.node.with_chain(|c| c.utxo.solde_de(&empreinte));

        Ok(Json::obj()
            .set("adresse", Json::str(brut))
            .set("empreinte", Json::str(empreinte.to_hex()))
            .set("solde", montant(Amount::from_units(solde)))
            .set("sorties_non_depensees", Json::u64(sorties))
            .set("mouvements", Json::array(mouvements))
            .set("mouvements_total", Json::u64(total_mouvements as u64))
            .set("via_index", Json::Bool(via_index))
            .set(
                "montants_sortants_tous_resolus",
                Json::Bool(sortants_tous_resolus),
            )
            .set("historique_complet", Json::Bool(via_index || plancher == 0))
            .set("plancher", Json::u64(plancher))
            .set("hauteur", Json::u64(hauteur))
            .set(
                "note",
                Json::str(if via_index {
                    "Historique complet : l'index d'adresses couvre toute la chaine."
                } else {
                    "Historique borne : ce noeud tourne sans index d'adresses. Les \
                     envois ne sont pas resolus, et la recherche s'arrete au plancher \
                     indique. Relancez-le avec --index-adresses pour une reponse \
                     complete."
                }),
            )
            .build())
    }

    /// Transactions portant une sortie d'exactement ce montant.
    ///
    /// # Le compromis, assume
    ///
    /// Il n'y a pas d'index par montant : le batir doublerait la taille de
    /// l'index pour une recherche rare, dont une somme courante — `1.00000000`
    /// — renvoie des milliers de resultats. On balaie donc en arriere une
    /// **fenetre bornee**, exactement comme `gettransaction` sans index : la
    /// requete coute au plus [`MAX_BLOCS_BALAYES`] lectures, jamais toute la
    /// chaine, et la reponse **dit jusqu'ou** elle a cherche. C'est le meme
    /// honnete « voila ce que j'ai pu voir » qu'ailleurs, plutot qu'une
    /// promesse que le cout dementirait a mesure que la chaine grandit.
    ///
    /// Les resultats sont plafonnes : personne ne lit mille lignes, et un
    /// plafond protege le service autant que le lecteur.
    fn getmontant(&self, params: &Json) -> Result<Json, Json> {
        const MAX_RESULTATS: usize = 100;
        let unites = params
            .get("unites")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                params
                    .get("montant")
                    .and_then(|v| v.as_str())
                    .and_then(montant_en_unites)
            })
            .ok_or_else(|| erreur(ERR_PARAMS, "parametre 'unites' ou 'montant' attendu"))?;

        let (resultats, hauteur, depuis, plafonne) = self.node.with_chain(|c| {
            let hauteur = c.height();
            let depuis = hauteur.saturating_sub(MAX_BLOCS_BALAYES);
            let mut out: Vec<Json> = Vec::new();
            let mut plafonne = false;
            let mut h = hauteur as i64;
            'blocs: while h >= depuis as i64 {
                if let Some(b) = c.block_at(h as u64) {
                    for tx in &b.transactions {
                        let txid = tx.txid();
                        for (i, o) in tx.outputs.iter().enumerate() {
                            if o.value.units() != unites {
                                continue;
                            }
                            if out.len() >= MAX_RESULTATS {
                                plafonne = true;
                                break 'blocs;
                            }
                            out.push(
                                Json::obj()
                                    .set("txid", Json::str(txid.to_hex()))
                                    .set("hauteur", Json::u64(h as u64))
                                    .set("index", Json::u64(i as u64))
                                    .set(
                                        "adresse",
                                        Json::str(
                                            crate::address::Address {
                                                network: self.network,
                                                scheme: o.scheme,
                                                hash: o.pubkey_hash,
                                            }
                                            .to_string_bech32(),
                                        ),
                                    )
                                    .set("valeur", montant(o.value))
                                    .build(),
                            );
                        }
                    }
                }
                h -= 1;
            }
            (out, hauteur, depuis, plafonne)
        });

        Ok(Json::obj()
            .set("montant", montant(Amount::from_units(unites)))
            .set("resultats", Json::array(resultats))
            .set("hauteur", Json::u64(hauteur))
            .set("depuis", Json::u64(depuis))
            .set("fenetre", Json::u64(MAX_BLOCS_BALAYES))
            .set("plafonne", Json::Bool(plafonne))
            .build())
    }

    // -----------------------------------------------------------------------
    // Portefeuille : ce qu'un logiciel de bureau doit pouvoir demander
    // -----------------------------------------------------------------------

    /// Etat du portefeuille, sans rien reveler de secret.
    ///
    /// Tout ce qu'un porteur a besoin de voir en ouvrant son logiciel : quel
    /// schema de signature, quel reseau, combien d'adresses distribuees,
    /// combien de clefs a usage unique deja brulees.
    fn getwalletinfo(&self) -> Result<Json, Json> {
        let w = self.portefeuille()?;
        let g = w
            .lock()
            .map_err(|_| erreur(ERR_INTERNE, "portefeuille verrouille"))?;
        let schema = g.scheme();
        let consommees = g.indices_consommes().len() as u64;
        Ok(Json::obj()
            .set("reseau", Json::str(format!("{:?}", self.network)))
            .set("schema", Json::str(schema.name()))
            .set("schema_id", Json::u64(u64::from(schema.as_u8())))
            .set("usage_unique", Json::Bool(schema.est_a_usage_unique()))
            .set("adresses_derivees", Json::u64(u64::from(g.next_index())))
            .set("clefs_consommees", Json::u64(consommees))
            .set(
                "clef_publique_octets",
                Json::u64(schema.pubkey_len() as u64),
            )
            .set("signature_octets", Json::u64(schema.sig_len() as u64))
            .build())
    }

    /// Toutes les adresses que ce portefeuille reconnait comme siennes.
    ///
    /// Une empreinte de clef publique est publique par construction : la rendre
    /// ne revele rien. Ce qui serait grave serait de rendre la graine, et
    /// aucune methode ne le fait.
    fn listaddresses(&self) -> Result<Json, Json> {
        let w = self.portefeuille()?;
        let g = w
            .lock()
            .map_err(|_| erreur(ERR_INTERNE, "portefeuille verrouille"))?;
        let schema = g.scheme();
        let consommees = g.indices_consommes();
        let v: Vec<Json> = g
            .known_hashes()
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let a = crate::address::Address {
                    network: self.network,
                    scheme: schema,
                    hash: *h,
                };
                let mut o = Json::obj()
                    .set("indice", Json::u64(i as u64))
                    .set("adresse", Json::str(a.to_string_bech32()))
                    .set("consommee", Json::Bool(consommees.contains(&(i as u32))));
                // L'etiquette n'est presente que si elle existe : une chaine
                // vide dans la reponse obligerait chaque appelant a distinguer
                // « sans nom » de « nomme par du vide ».
                if let Some(e) = g.etiquette(i as u32) {
                    o = o.set("etiquette", Json::str(e));
                }
                o.build()
            })
            .collect();
        Ok(Json::array(v))
    }

    /// Nomme une adresse dans le carnet local.
    ///
    /// # Pourquoi cela existe
    ///
    /// Q21 pousse a donner une adresse differente a chaque correspondant : c'est
    /// ce qui empeche de relier vos paiements entre eux. Le prix a payer est
    /// qu'au bout d'un mois on a quatre cents suites de caracteres et aucune
    /// idee de qui est qui. Le carnet rend au porteur ce que la vie privee lui a
    /// coute.
    ///
    /// # Ce que cela n'est pas
    ///
    /// Ces noms **ne quittent jamais la machine**. Ils ne sont ni transmis aux
    /// pairs, ni inscrits dans la chaine, ni visibles de quiconque recoit un
    /// paiement. Ils sont scelles avec le portefeuille quand une phrase secrete
    /// existe, parce que « pour Mathis » en dit long sur qui l'on frequente.
    fn setaddresslabel(&self, params: &Json) -> Result<Json, Json> {
        let w = self.portefeuille()?;
        let indice = params
            .get("indice")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| erreur(-32602, "parametre `indice` entier attendu"))?;
        let indice = u32::try_from(indice)
            .map_err(|_| erreur(-32602, "indice d'adresse hors des valeurs possibles"))?;
        let texte = params
            .get("etiquette")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut g = w
            .lock()
            .map_err(|_| erreur(ERR_INTERNE, "portefeuille verrouille"))?;
        // On refuse de nommer une adresse qui n'existe pas : accepter
        // laisserait des noms orphelins dans le fichier, et masquerait une
        // faute de frappe de l'appelant.
        if indice as usize >= g.known_hashes().len() {
            return Err(erreur(
                -32602,
                "cette adresse n'existe pas encore dans ce portefeuille",
            ));
        }
        g.etiqueter(indice, &texte);
        if let Err(e) = self.enregistrer(&g) {
            eprintln!("ALERTE : etiquette non enregistree : {e}");
        }
        Ok(Json::obj()
            .set("indice", Json::u64(indice as u64))
            .set(
                "etiquette",
                match g.etiquette(indice) {
                    Some(e) => Json::str(e),
                    None => Json::Null,
                },
            )
            .set("longueur_maximale", Json::u64(Wallet::ETIQUETTE_MAX as u64))
            .build())
    }

    /// Historique des mouvements de ce portefeuille.
    ///
    /// # Le cout, et pourquoi il est annonce
    ///
    /// Q21 n'a pas d'index par adresse. Retrouver l'historique demande de relire
    /// les corps des blocs et d'y chercher nos empreintes. La fenetre est donc
    /// bornee a [`FENETRE_HISTORIQUE`] blocs, et la reponse **dit jusqu'ou elle
    /// a regarde**. Un portefeuille qui affiche un historique tronque sans le
    /// signaler ment a son porteur — et c'est le genre de mensonge qui fait
    /// croire a des fonds disparus.
    fn listtransactions(&self, params: &Json) -> Result<Json, Json> {
        let w = self.portefeuille()?;
        let limite = params
            .get("limite")
            .and_then(|v| v.as_u64())
            .unwrap_or(50)
            .clamp(1, 500);

        let g = w
            .lock()
            .map_err(|_| erreur(ERR_INTERNE, "portefeuille verrouille"))?;
        let schema = g.scheme();

        // --- Ce qui attend au reservoir compte comme un mouvement.
        //
        // L'historique ne lisait que les blocs. Un envoi tout juste emis
        // n'apparaissait donc **nulle part** tant qu'aucun mineur ne l'avait
        // inclus — soit deux minutes en moyenne, et bien plus si le reseau est
        // charge. Vu de celui qui vient de payer, son argent avait disparu :
        // le solde avait baisse, et rien n'expliquait pourquoi. C'est le genre
        // de silence qui fait douter d'un portefeuille, et douter d'un
        // portefeuille est pire qu'une erreur affichee.
        //
        // On lit donc le reservoir avant les blocs. Ces lignes portent
        // `en_attente` et zero confirmation : elles disent la verite, qui est
        // « c'est parti, ce n'est pas encore grave dans la pierre ».
        //
        // Le verrou du reservoir est pris et relache **avant** celui de la
        // chaine : deux verrous imbriques dans deux ordres differents sont la
        // recette d'un blocage mortel.
        let en_attente: Vec<Transaction> = self.node.with_mempool(|m| {
            m.txids()
                .iter()
                .filter_map(|id| m.get(id).cloned())
                .collect()
        });

        let (mouvements, depuis, hauteur, tout_resolu, corps_absents) = self.node.with_chain(|c| {
            let hauteur = c.height();
            let depuis = hauteur.saturating_sub(FENETRE_HISTORIQUE);

            // --- Retrouver ce qui est SORTI, pas seulement ce qui est entre.
            //
            // Une entree ne porte pas son montant : elle designe une sortie
            // anterieure. Sans resolution, l'historique affichait « envoi » sans
            // jamais dire combien — le chiffre qui interesse justement celui qui
            // a envoye.
            //
            // On construit donc, au fil du balayage, une table des sorties
            // rencontrees. Elle ne couvre que la fenetre : une depense dont la
            // piece d'origine est plus ancienne reste non resolue, et c'est dit
            // dans la reponse plutot que compte comme zero.
            let mut sorties_vues: std::collections::HashMap<(Hash256, u32), u64> =
                std::collections::HashMap::new();
            let mut blocs: Vec<Block> = Vec::new();
            // --- Un bloc illisible ne doit pas effacer un paiement en silence.
            //
            // Ce balayage sautait sans un mot les hauteurs dont le corps ne
            // pouvait pas etre lu. Consequence observee sur un vrai reseau :
            // apres un arret brutal et une resynchronisation, un virement recu
            // avait purement et simplement **disparu de l'historique**, alors
            // que le solde, lui, le comptait toujours. Un portefeuille qui perd
            // une ligne sans le dire est pire qu'un portefeuille en panne : on
            // le croit.
            //
            // On compte donc ces hauteurs, et la reponse les annonce.
            let mut corps_absents: Vec<u64> = Vec::new();
            let mut h = hauteur;
            loop {
                if h < depuis {
                    break;
                }
                match c.block_at(h) {
                    Some(b) => {
                        for tx in &b.transactions {
                            let id = tx.txid();
                            for (i, o) in tx.outputs.iter().enumerate() {
                                sorties_vues.insert((id, i as u32), o.value.units());
                            }
                        }
                        blocs.push(b);
                    }
                    None => corps_absents.push(h),
                }
                if h == 0 {
                    break;
                }
                h -= 1;
            }

            let mut v: Vec<Json> = Vec::new();
            let mut tout_resolu = true;

            // Le reservoir d'abord : c'est le plus recent, et c'est ce que
            // cherche des yeux celui qui vient d'appuyer sur « Envoyer ».
            for tx in &en_attente {
                let recu: u64 = tx
                    .outputs
                    .iter()
                    .filter(|o| g.owns(&o.pubkey_hash))
                    .map(|o| o.value.units())
                    .sum();
                let mut engage: u64 = 0;
                let mut engage_complet = true;
                let mut emis = false;
                for e in &tx.inputs {
                    if e.witness.pubkey.is_empty() {
                        continue;
                    }
                    if !g.owns(&crate::sig::pubkey_hash(schema, &e.witness.pubkey)) {
                        continue;
                    }
                    emis = true;
                    // Une piece consommee par une transaction du reservoir est
                    // toujours dans le jeu d'UTXO : le reservoir n'y touche pas,
                    // seul un bloc le fait. C'est donc la qu'on lit son montant.
                    match c.utxo.get(&e.prev_out) {
                        Some(e) => engage += e.output.value.units(),
                        None => engage_complet = false,
                    }
                }
                if recu == 0 && !emis {
                    continue;
                }
                if emis && !engage_complet {
                    tout_resolu = false;
                }
                let sorti = engage.saturating_sub(recu);
                let mut ligne = Json::obj()
                    .set("txid", Json::str(tx.txid().to_hex()))
                    // Pas de hauteur : elle n'existera qu'au bloc qui l'inclura.
                    // Zero serait un mensonge lisible — la hauteur du bloc de
                    // genese.
                    .set("hauteur", Json::Null)
                    .set("horodatage", Json::u64(maintenant_utc()))
                    .set("confirmations", Json::u64(0))
                    .set("en_attente", Json::Bool(true))
                    .set("genre", Json::str(if emis { "envoi" } else { "reception" }))
                    .set("recu", montant(Amount::from_units(recu)))
                    // Une transaction du reservoir n'est jamais une coinbase :
                    // la maturite ne la concerne pas.
                    .set("mature", Json::Bool(true));
                if emis {
                    ligne = ligne
                        .set("engage", montant(Amount::from_units(engage)))
                        .set("sorti", montant(Amount::from_units(sorti)))
                        .set("montant_sortant_connu", Json::Bool(engage_complet));
                }
                v.push(ligne.build());
                if v.len() as u64 >= limite {
                    break;
                }
            }

            for b in &blocs {
                if v.len() as u64 >= limite {
                    break;
                }
                for tx in &b.transactions {
                    let recu: u64 = tx
                        .outputs
                        .iter()
                        .filter(|o| g.owns(&o.pubkey_hash))
                        .map(|o| o.value.units())
                        .sum();

                    // Ce que ce portefeuille a engage : la somme des sorties
                    // anterieures que ses propres clefs ont deverrouillees.
                    let mut engage: u64 = 0;
                    let mut engage_complet = true;
                    let mut emis = false;
                    for e in &tx.inputs {
                        if e.witness.pubkey.is_empty() {
                            continue; // coinbase
                        }
                        if !g.owns(&crate::sig::pubkey_hash(schema, &e.witness.pubkey)) {
                            continue;
                        }
                        emis = true;
                        match sorties_vues.get(&(e.prev_out.txid, e.prev_out.index)) {
                            Some(m) => engage += m,
                            None => engage_complet = false,
                        }
                    }
                    if recu == 0 && !emis {
                        continue;
                    }
                    if emis && !engage_complet {
                        tout_resolu = false;
                    }

                    let coinbase =
                        tx.inputs.len() == 1 && tx.inputs[0].prev_out.txid == Hash256::ZERO;
                    // Sorti pour de bon : ce qui a ete engage, moins ce qui est
                    // revenu en monnaie.
                    let sorti = engage.saturating_sub(recu);
                    let mut ligne = Json::obj()
                        .set("txid", Json::str(tx.txid().to_hex()))
                        .set("hauteur", Json::u64(b.header.height))
                        .set("horodatage", Json::u64(b.header.time))
                        .set("confirmations", Json::u64(hauteur - b.header.height + 1))
                        .set(
                            "genre",
                            Json::str(if coinbase {
                                "minage"
                            } else if emis {
                                "envoi"
                            } else {
                                "reception"
                            }),
                        )
                        .set("recu", montant(Amount::from_units(recu)))
                        .set(
                            "mature",
                            Json::Bool(!coinbase || hauteur >= b.header.height + COINBASE_MATURITY),
                        );
                    if emis {
                        ligne = ligne
                            .set("engage", montant(Amount::from_units(engage)))
                            .set("sorti", montant(Amount::from_units(sorti)))
                            .set("montant_sortant_connu", Json::Bool(engage_complet));
                    }
                    v.push(ligne.build());
                    if v.len() as u64 >= limite {
                        break;
                    }
                }
            }
            (v, depuis, hauteur, tout_resolu, corps_absents)
        });

        let complet = depuis == 0 && corps_absents.is_empty();
        let mut sortie = Json::obj()
            .set("mouvements", Json::array(mouvements))
            .set("regarde_depuis_hauteur", Json::u64(depuis))
            .set("hauteur", Json::u64(hauteur))
            .set("historique_complet", Json::Bool(complet))
            .set("montants_sortants_tous_resolus", Json::Bool(tout_resolu))
            .set("blocs_illisibles", Json::u64(corps_absents.len() as u64));
        // Les hauteurs concernees, bornees : de quoi agir sans noyer la reponse.
        if !corps_absents.is_empty() {
            let apercu: Vec<Json> = corps_absents
                .iter()
                .take(20)
                .map(|h| Json::u64(*h))
                .collect();
            sortie = sortie.set("hauteurs_illisibles", Json::array(apercu));
        }
        Ok(sortie
            .set(
                "note",
                Json::str(if !corps_absents.is_empty() {
                    "Historique INCOMPLET : le corps de certains blocs de la chaine active \
                     n'a pas pu etre lu, et ce qu'ils contenaient n'apparait pas ici. Ce \
                     n'est pas une perte de fonds — le solde, lui, reste juste. Relancez le \
                     noeud : il redemandera ces blocs au reseau."
                } else if complet {
                    "Historique complet : la recherche est remontee jusqu'a la genese."
                } else {
                    "Historique partiel. Ce noeud n'a pas d'index par adresse : \
                     la recherche s'arrete a la hauteur indiquee."
                }),
            )
            .build())
    }

    /// Prepare un envoi : selectionne les pieces, et rend les chiffres exacts.
    ///
    /// # Pourquoi cette methode existe
    ///
    /// `estimatefee` demandait a l'appelant de **supposer** un nombre
    /// d'entrees. C'est une supposition impossible a faire juste : les pieces
    /// ne sont choisies qu'au moment de construire la transaction, et avec
    /// ML-DSA-87 chaque entree ajoute 7 219 octets de temoin.
    ///
    /// Un essai reel de l'interface l'a montre sans appel : une estimation
    /// faite pour une entree a propose huit unites de frais, la transaction
    /// reelle en a consomme deux, et le reservoir l'a refusee pour taux de
    /// frais trop bas. L'utilisateur voyait un refus incomprehensible sur une
    /// transaction qu'il venait de confirmer.
    ///
    /// Cette methode fait la **vraie** selection, sans rien signer ni depenser,
    /// et rend les chiffres de la transaction qui sera effectivement
    /// construite. L'ecran de confirmation peut alors dire la verite.
    ///
    /// Elle ne modifie rien : aucun indice n'est consomme, aucun compteur
    /// n'avance.
    fn preparersend(&self, params: &Json) -> Result<Json, Json> {
        let w = self.portefeuille()?;
        let adresse = params
            .get("adresse")
            .and_then(|v| v.as_str())
            .ok_or_else(|| erreur(ERR_PARAMS, "parametre 'adresse' attendu"))?;
        let unites = params
            .get("unites")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| erreur(ERR_PARAMS, "parametre 'unites' attendu (entier)"))?;
        if unites == 0 {
            return Err(erreur(ERR_PARAMS, "montant nul"));
        }
        let dest = Address::parse_on(adresse, self.network)
            .map_err(|e| erreur(ERR_PARAMS, &format!("adresse invalide : {e:?}")))?;

        let g = w
            .lock()
            .map_err(|_| erreur(ERR_INTERNE, "portefeuille verrouille"))?;
        let schema = g.scheme();

        let (taux_median, en_attente) = self
            .node
            .with_mempool(|m| (m.taux_median().unwrap_or(0), m.len() as u64));
        let taux = taux_median.max(crate::mempool::MIN_FEE_RATE);

        // Deux passes : la premiere pour connaitre le nombre d'entrees, la
        // seconde parce que des frais plus eleves peuvent en demander une de
        // plus. Deux suffisent en pratique ; on ne boucle pas indefiniment.
        let mut frais = FRAIS_DEFAUT;
        let mut resultat = None;
        for _ in 0..2 {
            let besoin = unites
                .checked_add(frais)
                .ok_or_else(|| erreur(ERR_PARAMS, "montant et frais debordent"))?;
            let (choisies, total) = self
                .node
                .with_chain(|c| g.selectionner(&c.utxo, c.height(), besoin))
                .map_err(|e| erreur(ERR_PORTEFEUILLE, message_portefeuille(&e)))?;

            let n = choisies.len() as u64;
            let monnaie = total - besoin;
            // Une sortie pour le destinataire, une pour la monnaie s'il y en a.
            let sorties = if monnaie > 0 { 2 } else { 1 };
            let ossature = 8 + n * 48 + sorties * 41;
            let temoin = n * (schema.pubkey_len() as u64 + schema.sig_len() as u64);
            let poids = ossature * WITNESS_DISCOUNT + temoin;
            // Arrondi vers le haut : sous le plancher, la transaction n'est pas
            // relayee du tout.
            let calcules = poids.saturating_mul(taux).div_ceil(1000).max(1);

            resultat = Some((n, ossature + temoin, poids, monnaie, total));
            if calcules <= frais {
                break;
            }
            frais = calcules;
        }

        let (entrees, taille, poids, monnaie, total) =
            resultat.ok_or_else(|| erreur(ERR_INTERNE, "selection impossible"))?;

        Ok(Json::obj()
            .set("adresse", Json::str(dest.to_string_bech32()))
            .set("montant", montant(Amount::from_units(unites)))
            .set("frais", montant(Amount::from_units(frais)))
            .set("total_debite", montant(Amount::from_units(unites + frais)))
            .set("monnaie_rendue", montant(Amount::from_units(monnaie)))
            .set("pieces_engagees", montant(Amount::from_units(total)))
            .set("entrees", Json::u64(entrees))
            .set("taille_octets", Json::u64(taille))
            .set("poids", Json::u64(poids))
            .set("taux_par_millier_de_poids", Json::u64(taux))
            .set("transactions_en_attente", Json::u64(en_attente))
            .set(
                "note",
                Json::str(
                    "Chiffres exacts : les pieces ont ete reellement selectionnees. \
                     Rien n'a ete signe ni consomme. Passez ces frais tels quels a \
                     sendtoaddress.",
                ),
            )
            .build())
    }

    /// Frais suggeres pour une transaction de ce portefeuille.
    ///
    /// **Preferez [`Self::preparersend`]** : cette methode-ci demande un nombre
    /// d'entrees que l'appelant ne peut pas connaitre, et se trompe donc des
    /// que la selection en retient un autre. Elle reste pour repondre a la
    /// question generale « combien coute une transaction ici ».
    ///
    /// La suggestion se fonde sur la taille reelle qu'aura la transaction — avec
    /// ML-DSA-87 le temoin pese 99 % du total — et sur ce que paient les
    /// transactions deja en attente.
    fn estimatefee(&self, params: &Json) -> Result<Json, Json> {
        let w = self.portefeuille()?;
        let entrees = params
            .get("entrees")
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
            .clamp(1, 100);
        let sorties = params
            .get("sorties")
            .and_then(|v| v.as_u64())
            .unwrap_or(2)
            .clamp(1, 100);

        let schema = {
            let g = w
                .lock()
                .map_err(|_| erreur(ERR_INTERNE, "portefeuille verrouille"))?;
            g.scheme()
        };
        // --- Taille, poids, et taux : trois grandeurs a ne pas confondre.
        //
        // Le reservoir ordonne par **taux de frais au poids ponderé**, exprime
        // en unites par millier d'unites de poids. Le poids n'est pas la
        // taille : l'ossature compte pour `WITNESS_DISCOUNT` fois sa taille, le
        // temoin pour une seule.
        //
        // Multiplier la taille par ce taux — ce que faisait la premiere version
        // de cette methode — surestimait les frais d'un facteur mille. Personne
        // n'aurait perdu de fonds, mais chacun aurait paye mille fois trop.
        let ossature = 8 + entrees * 48 + sorties * 41;
        let temoin = entrees * (schema.pubkey_len() as u64 + schema.sig_len() as u64);
        let taille = ossature + temoin;
        let poids = ossature * WITNESS_DISCOUNT + temoin;

        let (taux_reservoir, en_attente) = self.node.with_mempool(|m| {
            let n = m.len() as u64;
            let taux = m.taux_median().unwrap_or(0);
            (taux, n)
        });
        // Le plancher du reseau, ou le taux constate s'il est plus eleve.
        let taux = taux_reservoir.max(crate::mempool::MIN_FEE_RATE);
        // Arrondi vers le haut : une transaction sous le plancher n'est pas
        // relayee du tout, et un arrondi vers le bas la ferait tomber dessus.
        let suggere = poids.saturating_mul(taux).div_ceil(1000).max(1);

        Ok(Json::obj()
            .set("taille_estimee_octets", Json::u64(taille))
            .set("poids_estime", Json::u64(poids))
            .set("entrees", Json::u64(entrees))
            .set("sorties", Json::u64(sorties))
            .set("taux_par_millier_de_poids", Json::u64(taux))
            .set("transactions_en_attente", Json::u64(en_attente))
            .set("frais_suggeres", montant(Amount::from_units(suggere)))
            .build())
    }

    /// Ou en est la synchronisation avec le reseau.
    ///
    /// Un portefeuille qui affiche un solde sans dire qu'il est en retard de
    /// mille blocs affiche un chiffre faux. Cette methode existe pour que
    /// l'interface puisse le dire.
    fn getsyncstatus(&self) -> Json {
        let hauteur = self.node.height();
        let pairs = self.node.peer_count() as u64;
        let cible = self.node.hauteur_annoncee_max().max(hauteur);
        let restant = cible.saturating_sub(hauteur);
        Json::obj()
            .set("hauteur", Json::u64(hauteur))
            .set("hauteur_reseau", Json::u64(cible))
            .set("blocs_restants", Json::u64(restant))
            .set("pairs", Json::u64(pairs))
            .set("synchronise", Json::Bool(restant == 0 && pairs > 0))
            .set(
                "note",
                Json::str(if pairs == 0 {
                    "Aucun pair connecte : ce noeud ne peut pas savoir s'il est a jour."
                } else if restant == 0 {
                    "A jour avec les pairs connus."
                } else {
                    "Synchronisation en cours. Les soldes affiches sont incomplets."
                }),
            )
            .build()
    }

    /// Etat du minage : ce que la machine fait en ce moment.
    ///
    /// Toujours servi, meme sans portefeuille — savoir qu'on ne mine pas est
    /// une reponse utile, et elle ne revele rien.
    fn getminage(&self) -> Json {
        let (actif, debit, blocs, total, gagne, trouves) = match &self.minage {
            Some(m) => (
                m.actif(),
                m.debit(),
                m.blocs(),
                m.essais_total(),
                m.gagne_total(),
                m.trouves(),
            ),
            None => (false, 0.0, 0, 0, 0, Vec::new()),
        };
        // La table de preuve de travail de l'epoque courante : sa taille est ce
        // que le minage occupe reellement en memoire vive sur cette machine.
        let (memoire_de_minage, epoque) = self.node.with_chain(|c| {
            let epoque = crate::memhard::epoch_of(c.height().saturating_add(1));
            let n = crate::memhard::table_size(c.pow_params(), epoque) as u64;
            (n * crate::consensus::POW_ELEMENT_SIZE as u64, epoque)
        });

        // Les vingt dernieres trouvailles suffisent a l'ecran ; le compteur et
        // le gain, eux, portent le total depuis le lancement.
        let liste: Vec<Json> = trouves
            .iter()
            .take(20)
            .map(|t| {
                Json::obj()
                    .set("hauteur", Json::u64(t.hauteur))
                    .set("identifiant", Json::str(t.identifiant.to_string()))
                    .set("recompense", montant(Amount::from_units(t.recompense)))
                    .set("horodatage", Json::u64(t.horodatage))
                    .build()
            })
            .collect();
        Json::obj()
            .set("actif", Json::Bool(actif))
            .set(
                "possible",
                Json::Bool(self.minage.is_some() && self.wallet.is_some()),
            )
            .set("essais_par_seconde", Json::Int(debit as i64))
            .set("essais_total", Json::u64(total))
            .set("blocs_trouves", Json::u64(blocs))
            .set("gagne", montant(Amount::from_units(gagne)))
            .set("trouves", Json::array(liste))
            // --- La memoire : ce qui fait tout l'interet de cette preuve de
            // travail, et qui n'etait affiche nulle part.
            //
            // Q21 mine avec une table qui doit tenir en memoire vive, et qui
            // grandit de 5 % toutes les 71 journees. C'est elle qui rend une
            // machine specialisee sans interet : on ne grave pas de la memoire.
            // La taille employee **maintenant**, sur cette machine, est donc le
            // chiffre qui explique pourquoi le minage reste a la portee de tous
            // — et il faut pouvoir la lire.
            .set("memoire_octets", Json::u64(memoire_de_minage))
            .set("memoire_epoque", Json::u64(epoque))
            .build()
    }

    /// Ce que le reseau depense en travail, et ce qu'on ne peut pas en deduire.
    ///
    /// # La question qu'on aimerait poser
    ///
    /// « Combien de mineurs y a-t-il ? » Tout le monde la pose, et **aucune
    /// chaine ne peut y repondre**. Un mineur ne s'annonce pas ; il pose des
    /// blocs. Rien ne distingue mille machines d'une personne qui en possede
    /// mille, et rien ne distingue une machine de quelqu'un qui en loue mille
    /// pour une heure.
    ///
    /// On a d'abord voulu compter les empreintes de mineur distinctes dans les
    /// derniers blocs. C'etait deja une borne inferieure et non un compte ; c'est
    /// devenu inutilisable le jour ou le mineur a cesse de reutiliser son
    /// adresse. Il en derive une par bloc trouve — pour ne pas relier
    /// publiquement toutes ses recompenses entre elles — de sorte que le nombre
    /// d'empreintes distinctes vaut desormais le nombre de blocs. La bonne
    /// propriete de vie privee a detruit la mauvaise mesure, et c'est tres bien.
    ///
    /// # La question a laquelle on peut repondre
    ///
    /// **Combien de travail le reseau depense-t-il ?** Cela se lit dans la
    /// difficulte : elle s'ajuste pour qu'un bloc tombe toutes les deux minutes,
    /// donc le travail accumule divise par le temps ecoule est le debit du
    /// reseau entier. C'est une mesure, pas une declaration, et personne ne peut
    /// la gonfler sans depenser reellement.
    ///
    /// Le reste — combien de personnes, combien de machines — se deduit en
    /// divisant par le debit d'**une** machine, et l'interface le presente comme
    /// une equivalence, jamais comme un decompte.
    fn getreseau(&self) -> Json {
        // Une journee de blocs, ou ce qui existe si la chaine est plus jeune.
        const FENETRE: usize = 720;
        let entetes = self.node.with_chain(|c| c.headers());
        let n = entetes.len();
        // --- La genese ne compte jamais comme point de depart.
        //
        // Son horodatage est une constante du protocole, pas l'instant ou
        // quelqu'un a mine. Sur une chaine jeune, la fenetre l'englobait et
        // l'ecart mesure devenait la distance entre cette constante et
        // aujourd'hui : 141 blocs mines en neuf secondes s'annoncaient comme
        // « 371,8 jours de chaine », et le debit qui en decoulait etait nul.
        // L'ancre est le premier bloc de la fenetre : c'est son horodatage qui
        // ouvre l'intervalle, et le travail se somme sur ceux qui la suivent.
        // Elle ne descend jamais sous la hauteur 1.
        //
        // Un premier jet ecrivait `.max(1)` puis relisait `entetes[debut - 1..]`,
        // ce qui reintroduisait exactement la genese qu'on venait d'exclure.
        // L'epreuve `la_genese_ne_sert_pas_de_point_de_depart` l'a vu tout de
        // suite ; la relecture, non.
        let ancre = n.saturating_sub(FENETRE + 1).max(1);
        let tranche = if n > ancre {
            &entetes[ancre..]
        } else {
            &entetes[..0]
        };

        let mut travail: u128 = 0;
        for h in tranche.iter().skip(1) {
            travail = travail.saturating_add(travail_en_u128(crate::pow::block_work(h.bits)));
        }
        // Les horodatages d'une chaine ne sont pas monotones : la regle du temps
        // median laisse un bloc etre anterieur a son parent. On prend donc les
        // extremes de la tranche, et l'on refuse de diviser par un ecart nul ou
        // negatif plutot que d'annoncer un debit infini.
        let (t0, t1) = (
            tranche.first().map(|h| h.time).unwrap_or(0),
            tranche.last().map(|h| h.time).unwrap_or(0),
        );
        let secondes = t1.saturating_sub(t0);
        let blocs = tranche.len().saturating_sub(1) as u64;
        // --- Le debit se calcule au millieme.
        //
        // La division entiere `travail / secondes` rendait zero des que le
        // reseau produisait moins d'une unite de travail par seconde — ce qui
        // est le cas normal d'un reseau d'essai peu difficile. Un zero se lit
        // « le reseau est arrete », et c'etait faux. On multiplie donc avant de
        // diviser, et l'unite annoncee est le milliexemplaire.
        let debit_milli = if secondes > 0 && blocs > 0 {
            travail.saturating_mul(1000) / secondes as u128
        } else {
            0
        };

        Json::obj()
            .set("pairs", Json::u64(self.node.peer_count() as u64))
            // --- Le carnet : ce qui se rapproche le plus d'un « combien de
            // machines ».
            //
            // Le nombre de mineurs reste inconnaissable, et le restera. Mais le
            // nombre de machines dont ce nœud a **appris l'existence** est un
            // fait, lui : chaque poignee de main echange des adresses, et le
            // carnet les retient. Ce n'est pas un decompte du reseau — une
            // machine eteinte y figure encore, une machine qui vient d'arriver
            // pas encore — et c'est dit tel quel dans l'interface.
            .set("carnet", Json::u64(self.node.address_count() as u64))
            .set("blocs_examines", Json::u64(blocs))
            .set("secondes_examinees", Json::u64(secondes))
            .set("travail_total", Json::str(travail.to_string()))
            .set("debit_reseau_milli", Json::str(debit_milli.to_string()))
            .set("mesurable", Json::Bool(secondes > 0 && blocs > 0))
            .set(
                "note",
                Json::str(
                    "Le nombre de mineurs n'est pas connaissable : un mineur ne s'annonce \
                     pas, et celui-ci change d'adresse a chaque bloc trouve. Ce qui se \
                     mesure est le travail depense, lu dans la difficulte.",
                ),
            )
            .build()
    }

    /// Allume ou eteint le minage.
    ///
    /// Range parmi les methodes de portefeuille, et pour une raison de fond :
    /// miner verse une subvention a une adresse du portefeuille. Sans
    /// portefeuille servi, l'autoriser reviendrait a laisser une page decider
    /// d'un travail dont le produit n'irait nulle part.
    fn setminage(&self, params: &Json) -> Result<Json, Json> {
        let m = self
            .minage
            .as_ref()
            .ok_or_else(|| erreur(-32004, "ce noeud ne peut pas miner"))?;
        if self.wallet.is_none() {
            return Err(erreur(
                -32004,
                "miner demande un portefeuille : sans lui la subvention n'irait nulle part",
            ));
        }
        let vers = match params.get("actif") {
            Some(Json::Bool(b)) => *b,
            _ => return Err(erreur(-32602, "parametre `actif` booleen attendu")),
        };
        m.basculer(vers);
        Ok(self.getminage())
    }

    fn getbalance(&self) -> Result<Json, Json> {
        let w = self.portefeuille()?;
        // --- Ne pas recopier l'ensemble des UTXO a chaque appel.
        //
        // `c.utxo.clone()` dupliquait tout le jeu d'UTXO — des centaines de
        // mebioctets sur une chaine reelle — pour lire un solde, et un lot en
        // demandait autant de copies. On travaille sous le verrou, sur une
        // reference : le calcul est identique, l'allocation disparait.
        let g = w
            .lock()
            .map_err(|_| erreur(ERR_INTERNE, "portefeuille verrouille"))?;
        let (solde, sorties, immature, hauteur, prochaine, fige, reutilisees) =
            self.node.with_chain(|c| {
                let hauteur = c.height();
                let solde = g.balance(&c.utxo, hauteur);
                let sorties = g.spendable(&c.utxo, hauteur).len();
                // --- « Quand ? » est la question qu'on pose devant un solde bloque.
                //
                // Le portefeuille annoncait une somme en attente de maturite sans
                // jamais dire a quelle date elle se libererait. Un mineur voyait
                // donc son gain monter et son solde disponible rester a zero,
                // pendant des heures, sans le moindre reperage. Plusieurs y ont vu
                // une panne. On rend donc la hauteur de la **prochaine**
                // liberation et le montant qu'elle porte.
                //
                // Le calcul passe par l'index d'empreintes du jeu d'UTXO : cette
                // requete revient toutes les six secondes, et un balayage complet
                // sous le verrou de consensus aurait fait figer la validation des
                // blocs au rythme du rafraichissement de l'interface.
                let (immature_montant, prochaine_amount) = g.immature(&c.utxo, hauteur);
                let immature = immature_montant.units();
                let prochaine: Option<(u64, u64)> = prochaine_amount.map(|(h, m)| (h, m.units()));
                // Ce qu'une adresse reutilisee a immobilise. Une clef a usage unique
                // ne signe qu'une fois : la seconde piece recue sur une meme adresse
                // ne sera jamais depensable. La taire ferait disparaitre des fonds
                // sans explication ; on la nomme, avec sa cause.
                let fige = g.montant_fige(&c.utxo, hauteur);
                let reutilisees = g.adresses_reutilisees(&c.utxo, hauteur).len();
                (
                    solde,
                    sorties,
                    immature,
                    hauteur,
                    prochaine,
                    fige,
                    reutilisees,
                )
            });

        let mut sortie = Json::obj()
            .set("depensable", montant(solde))
            .set("immature", montant(Amount::from_units(immature)))
            .set("sorties_depensables", Json::u64(sorties as u64))
            .set("adresses_derivees", Json::u64(g.next_index() as u64))
            .set("hauteur", Json::u64(hauteur));
        if fige.units() > 0 {
            sortie = sortie
                .set("fige_par_reutilisation", montant(fige))
                .set("adresses_reutilisees", Json::u64(reutilisees as u64))
                .set(
                    "avertissement",
                    Json::str(
                        "Une clef a usage unique ne signe qu'une fois : sur une adresse \
                         ayant recu plusieurs paiements, seule la plus grosse piece reste \
                         depensable. Donnez une adresse neuve a chaque paiement.",
                    ),
                );
        }
        if let Some((libre_a, montant_libere)) = prochaine {
            sortie = sortie
                .set("prochaine_maturite_hauteur", Json::u64(libre_a))
                .set(
                    "prochaine_maturite_blocs",
                    Json::u64(libre_a.saturating_sub(hauteur)),
                )
                .set(
                    "prochaine_maturite_montant",
                    montant(Amount::from_units(montant_libere)),
                );
        }
        Ok(sortie.build())
    }

    fn getnewaddress(&self) -> Result<Json, Json> {
        let w = self.portefeuille()?;
        let mut g = w
            .lock()
            .map_err(|_| erreur(ERR_INTERNE, "portefeuille verrouille"))?;
        let a = g.new_address();
        // Le compteur d'indices vient d'avancer : sans ecriture, un redemarrage
        // redistribuerait la meme adresse. On ne la donne donc pas si le disque
        // ne l'a pas vue.
        self.enregistrer(&g).map_err(|e| {
            erreur(
                ERR_PORTEFEUILLE,
                &format!("adresse non enregistree, donc non distribuee : {e}"),
            )
        })?;
        Ok(Json::obj()
            .set("adresse", Json::str(a.to_string_bech32()))
            .set("schema", Json::str(a.scheme.name()))
            .set("usage_unique", Json::Bool(a.scheme.est_a_usage_unique()))
            .set(
                "avertissement",
                Json::str(if a.scheme.est_a_usage_unique() {
                    "Adresse a usage unique : Lamport revele la clef privee si elle \
                     signe deux fois. Ne la reutilisez jamais."
                } else {
                    "Adresse reutilisable sans affaiblir la clef. Une adresse neuve \
                     par paiement reste conseillee, par confidentialite."
                }),
            )
            .build())
    }

    fn sendtoaddress(&self, params: &Json) -> Result<Json, Json> {
        let w = self.portefeuille()?;

        let adresse = params
            .get("adresse")
            .and_then(|v| v.as_str())
            .ok_or_else(|| erreur(ERR_PARAMS, "parametre 'adresse' attendu"))?;
        let unites = params
            .get("unites")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| erreur(ERR_PARAMS, "parametre 'unites' attendu (entier)"))?;
        // --- Des frais mal typés ne doivent pas devenir les frais par defaut.
        //
        // `.and_then(as_u64).unwrap_or(1_000)` remplacait silencieusement toute
        // valeur illisible par la valeur par defaut : la transaction construite
        // n'etait pas celle que le client avait ecrite. Un champ present et
        // invalide est une erreur, pas une invitation a deviner.
        let frais = match params.get("frais") {
            None | Some(Json::Null) => FRAIS_DEFAUT,
            Some(v) => v.as_u64().ok_or_else(|| {
                erreur(
                    ERR_PARAMS,
                    "parametre 'frais' present mais illisible : un entier d'unites est attendu",
                )
            })?,
        };

        let dest = Address::parse_on(adresse, self.network)
            .map_err(|e| erreur(ERR_PARAMS, &format!("adresse invalide : {e:?}")))?;

        // Construction et acceptation sous **un seul** verrou : la chaine et le
        // reservoir vivent sous le meme, et les prendre l'un dans l'autre
        // figerait le noeud.
        //
        // Sur une reference, jamais sur une copie : recopier le jeu d'UTXO pour
        // construire une transaction coutait des centaines de mebioctets sur
        // une chaine reelle, et un lot en demandait autant de copies.
        let (tx, txid) = {
            let mut g = w
                .lock()
                .map_err(|_| erreur(ERR_INTERNE, "portefeuille verrouille"))?;
            let resultat = self.node.with_chain_and_mempool(|c, m| {
                let tx = g.create_transaction_multi_gardee(
                    &c.utxo,
                    c.height(),
                    &[(dest, Amount::from_units(unites))],
                    Amount::from_units(frais),
                    &mut |w| self.enregistrer(w),
                );
                match tx {
                    Ok(tx) => {
                        let r = m.accept(&tx, &c.utxo, self.network, c.height());
                        Ok((tx, r))
                    }
                    Err(e) => Err(e),
                }
            });
            // Les indices sont deja sur le disque (ecriture anticipee, avant
            // la signature). On enregistre encore pour ce qui a pu bouger
            // depuis — l'adresse de monnaie, par exemple.
            if let Err(e) = self.enregistrer(&g) {
                eprintln!("ALERTE : portefeuille non enregistre apres l'envoi : {e}");
            }
            let (tx, accepte) =
                resultat.map_err(|e| erreur(ERR_PORTEFEUILLE, message_portefeuille(&e)))?;
            let txid = accepte.map_err(|e| erreur(ERR_PORTEFEUILLE, &message_reservoir(&e)))?;
            (tx, txid)
        };

        self.node.announce_tx(txid);

        Ok(Json::obj()
            .set("txid", Json::str(txid.to_hex()))
            .set("transaction", tx_json(&tx, self.network))
            .build())
    }

    /// Paie plusieurs destinataires en **une seule** transaction.
    ///
    /// Meme chemin que `sendtoaddress` — un seul verrou pour construire et
    /// accepter, la clef consommee ecrite sur disque quoi qu'il arrive — mais
    /// sur une liste de sorties. Le nombre de destinataires est borne : une
    /// transaction demesuree serait de toute facon refusee par le poids, et un
    /// plafond franc vaut mieux qu'un refus obscur du reservoir.
    fn sendmany(&self, params: &Json) -> Result<Json, Json> {
        const MAX_DESTINATAIRES: usize = 1000;
        let w = self.portefeuille()?;

        let liste = params
            .get("destinations")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                erreur(
                    ERR_PARAMS,
                    "parametre 'destinations' attendu : une liste d'objets {adresse, unites}",
                )
            })?;
        if liste.is_empty() {
            return Err(erreur(ERR_PARAMS, "au moins un destinataire est attendu"));
        }
        if liste.len() > MAX_DESTINATAIRES {
            return Err(erreur(
                ERR_PARAMS,
                &format!("au plus {MAX_DESTINATAIRES} destinataires par envoi"),
            ));
        }

        let mut destinations = Vec::with_capacity(liste.len());
        for d in liste {
            let adresse = d.get("adresse").and_then(|v| v.as_str()).ok_or_else(|| {
                erreur(ERR_PARAMS, "chaque destination attend un champ 'adresse'")
            })?;
            let unites = d.get("unites").and_then(|v| v.as_u64()).ok_or_else(|| {
                erreur(
                    ERR_PARAMS,
                    "chaque destination attend un champ 'unites' (entier)",
                )
            })?;
            let dest = Address::parse_on(adresse, self.network)
                .map_err(|e| erreur(ERR_PARAMS, &format!("adresse invalide : {e:?}")))?;
            destinations.push((dest, Amount::from_units(unites)));
        }

        let frais = match params.get("frais") {
            None | Some(Json::Null) => FRAIS_DEFAUT,
            Some(v) => v.as_u64().ok_or_else(|| {
                erreur(
                    ERR_PARAMS,
                    "parametre 'frais' present mais illisible : un entier d'unites est attendu",
                )
            })?,
        };

        let (tx, txid) = {
            let mut g = w
                .lock()
                .map_err(|_| erreur(ERR_INTERNE, "portefeuille verrouille"))?;
            let resultat = self.node.with_chain_and_mempool(|c, m| {
                let tx = g.create_transaction_multi_gardee(
                    &c.utxo,
                    c.height(),
                    &destinations,
                    Amount::from_units(frais),
                    &mut |w| self.enregistrer(w),
                );
                match tx {
                    Ok(tx) => {
                        let r = m.accept(&tx, &c.utxo, self.network, c.height());
                        Ok((tx, r))
                    }
                    Err(e) => Err(e),
                }
            });
            if let Err(e) = self.enregistrer(&g) {
                eprintln!("ALERTE : portefeuille non enregistre apres l'envoi : {e}");
            }
            let (tx, accepte) =
                resultat.map_err(|e| erreur(ERR_PORTEFEUILLE, message_portefeuille(&e)))?;
            let txid = accepte.map_err(|e| erreur(ERR_PORTEFEUILLE, &message_reservoir(&e)))?;
            (tx, txid)
        };

        self.node.announce_tx(txid);

        Ok(Json::obj()
            .set("txid", Json::str(txid.to_hex()))
            .set("destinataires", Json::u64(destinations.len() as u64))
            .set("transaction", tx_json(&tx, self.network))
            .build())
    }
}

/// Schema par defaut du portefeuille, expose pour la documentation.
///
/// Depend de la compilation : ML-DSA-87 des que la feature `mldsa` est active,
/// Lamport sinon. Un noeud sans ML-DSA n'a pas sa place sur le reseau principal.
///
/// Cette constante annoncait ML-DSA-65 alors que le binaire creait des
/// portefeuilles ML-DSA-87 depuis le passage au niveau NIST 5. Une constante
/// qui contredit le comportement reel est pire qu'absente : elle sert de
/// reference a qui lit le code, et elle ment.
pub const SCHEMA_PORTEFEUILLE: SchemeId = if cfg!(feature = "mldsa") {
    SchemeId::MlDsa87
} else {
    SchemeId::LamportOts
};

/// Convertit un travail de bloc en entier de 128 bits, en saturant.
///
/// Le travail d'un bloc tient tres largement dans 128 bits aux difficultes
/// atteignables ; la saturation est une precaution, pas un cas attendu. On
/// prefere un chiffre plafonne a une panique ou a un repli silencieux sur zero,
/// qui ferait croire a un reseau a l'arret.
fn travail_en_u128(t: crate::uint::U256) -> u128 {
    let o = t.to_be_bytes();
    if o[..16].iter().any(|&x| x != 0) {
        return u128::MAX;
    }
    let mut bas = [0u8; 16];
    bas.copy_from_slice(&o[16..]);
    u128::from_be_bytes(bas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{genesis_block, Chain};
    use crate::json::parse as jparse;

    const RESEAU: Network = Network::Regtest;

    fn contexte(avec_portefeuille: bool) -> RpcContext {
        let g = genesis_block(RESEAU);
        let node = Arc::new(Node::new(RESEAU, Chain::new(RESEAU, g)));
        RpcContext {
            sur_changement: None,
            index: None,
            // Les epreuves du RPC voient un minage possible : c'est ce qui
            // permet de verifier que l'interrupteur repond, et que sans
            // portefeuille il refuse.
            minage: Some(Arc::new(crate::minage::Minage::new(false))),
            node,
            wallet: if avec_portefeuille {
                Some(Arc::new(Mutex::new(Wallet::from_seed([9u8; 32], RESEAU))))
            } else {
                None
            },
            network: RESEAU,
        }
    }

    /// Un contexte dont le portefeuille a reellement des pieces depensables.
    ///
    /// Mine jusqu'a depasser la maturite des coinbases, sans quoi rien n'est
    /// depensable et l'on n'eprouve que le message « fonds insuffisants ».
    fn contexte_avec_fonds() -> RpcContext {
        let mut w = Wallet::from_seed([0x5a; 32], RESEAU);
        let g = genesis_block(RESEAU);
        let mut c = Chain::new(RESEAU, g);
        for i in 1..=(COINBASE_MATURITY + 3) {
            let a = w.new_address();
            let t = crate::chain::GENESIS_TIME + i * TARGET_BLOCK_SECS;
            // Le schema vient de l'adresse elle-meme, jamais d'une constante :
            // l'empreinte d'une clef publique depend du schema, et miner vers
            // un autre que celui du portefeuille produit un verrou qu'il ne
            // sait pas ouvrir. Le defaut ne se voyait qu'avec ML-DSA active,
            // ou la constante et le portefeuille divergent.
            let b = c
                .mine_block(a.hash, a.scheme, &[], t, 5_000_000)
                .expect("minage");
            c.connect(&b, t + 1).expect("connexion");
        }
        RpcContext {
            sur_changement: None,
            index: None,
            minage: Some(Arc::new(crate::minage::Minage::new(false))),
            node: Arc::new(Node::new(RESEAU, c)),
            wallet: Some(Arc::new(Mutex::new(w))),
            network: RESEAU,
        }
    }

    fn appel(c: &RpcContext, methode: &str, params: &str) -> Json {
        let corps = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{methode}","params":{params}}}"#);
        jparse(&c.handle(&corps)).expect("reponse JSON valide")
    }

    fn resultat(c: &RpcContext, methode: &str, params: &str) -> Json {
        let r = appel(c, methode, params);
        assert!(
            r.get("error").is_none(),
            "{methode} a renvoye une erreur : {}",
            r.encode()
        );
        r.get("result").cloned().expect("champ result")
    }

    #[test]
    fn getinfo_decrit_la_chaine() {
        let c = contexte(false);
        let r = resultat(&c, "getinfo", "{}");
        assert_eq!(r.get("hauteur").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(r.get("reseau").and_then(|v| v.as_str()), Some("Regtest"));
        assert_eq!(
            r.get("portefeuille_actif"),
            Some(&Json::Bool(false)),
            "le portefeuille doit etre annonce inactif"
        );
    }

    #[test]
    fn getempreinteutxo_rend_l_engagement_sur_l_etat() {
        let c = contexte(false);
        let r = resultat(&c, "getempreinteutxo", "{}");
        assert_eq!(r.get("hauteur").and_then(|v| v.as_u64()), Some(0));
        let empreinte = r
            .get("empreinte")
            .and_then(|v| v.as_str())
            .expect("champ empreinte");
        assert_eq!(empreinte.len(), 64, "un condensat de 256 bits en hexa");
        // Elle doit egaler ce que la chaine calcule directement.
        let attendue = c.node.with_chain(|ch| ch.utxo_commitment().to_hex());
        assert_eq!(empreinte, attendue);
    }

    #[test]
    fn getblock_rend_la_genese() {
        let c = contexte(false);
        let r = resultat(&c, "getblock", r#"{"hauteur":0}"#);
        let e = r.get("entete").expect("entete");
        assert_eq!(e.get("hauteur").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(r.get("nb_transactions").and_then(|v| v.as_u64()), Some(1));
        // La coinbase de genese emet exactement la piece.
        let txs = r.get("transactions").and_then(|v| v.as_array()).unwrap();
        assert!(txs[0].get("coinbase") == Some(&Json::Bool(true)));
    }

    #[test]
    fn getblock_sans_parametre_rend_la_tete() {
        let c = contexte(false);
        let r = resultat(&c, "getblock", "{}");
        assert!(r.get("entete").is_some());
    }

    /// Les frais sont toujours annonces — connus, ou avoues comme inconnus.
    ///
    /// Une coinbase ne paie pas de frais : elle les percoit. Le champ existe
    /// donc, et il vaut `false`, plutot qu'un montant qui n'aurait pas de sens.
    /// Sans index (le cas de ce contexte d'essai), une depense ordinaire serait
    /// de meme « non resolue » — jamais un chiffre invente.
    #[test]
    fn gettransaction_annonce_les_frais_ou_avoue_ne_pas_savoir() {
        let c = contexte_avec_fonds();
        let bloc = resultat(&c, "getblock", r#"{"hauteur":1}"#);
        let txid = bloc.get("transactions").and_then(|v| v.as_array()).unwrap()[0]
            .get("txid")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let r = resultat(&c, "gettransaction", &format!(r#"{{"txid":"{txid}"}}"#));

        // Le champ est toujours la : la page ne devine jamais son absence.
        assert_eq!(
            r.get("frais_connu"),
            Some(&Json::Bool(false)),
            "une coinbase ne paie pas de frais"
        );
        assert_eq!(r.get("frais"), Some(&Json::Null));
        // Un montant par entree, aligne sur la transaction — ici l'unique
        // entree de coinbase.
        let m = r
            .get("entrees_montants")
            .and_then(|v| v.as_array())
            .expect("entrees_montants present");
        assert_eq!(m.len(), 1);
    }

    /// Un nombre a virgule est reconnu comme un montant, sous sa forme canonique.
    #[test]
    fn rechercher_reconnait_un_montant() {
        let c = contexte(false);
        let r = resultat(&c, "rechercher", r#"{"q":"1.5"}"#);
        assert_eq!(r.get("genre").and_then(|v| v.as_str()), Some("montant"));
        assert_eq!(
            r.get("valeur").and_then(|v| v.as_str()),
            Some("1.50000000"),
            "le montant doit revenir sous sa forme canonique en Q21"
        );
    }

    /// La recherche par montant retrouve une sortie qui existe, et ne rend que
    /// des sorties de ce montant exact.
    #[test]
    fn getmontant_trouve_une_sortie_de_ce_montant() {
        let c = contexte_avec_fonds();
        // La valeur exacte de la piece de genese, lue sur la chaine.
        let g = resultat(&c, "getblock", r#"{"hauteur":0}"#);
        let val = g.get("transactions").and_then(|v| v.as_array()).unwrap()[0]
            .get("sorties")
            .and_then(|v| v.as_array())
            .unwrap()[0]
            .get("valeur")
            .and_then(|v| v.get("q21"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let r = resultat(&c, "getmontant", &format!(r#"{{"montant":"{val}"}}"#));
        let res = r.get("resultats").and_then(|v| v.as_array()).unwrap();
        assert!(
            !res.is_empty(),
            "une sortie de {val} Q21 existe et devrait etre trouvee"
        );
        assert!(
            res.iter().all(|s| s
                .get("valeur")
                .and_then(|v| v.get("q21"))
                .and_then(|v| v.as_str())
                == Some(val.as_str())),
            "toutes les sorties rendues doivent valoir exactement le montant cherche"
        );
    }

    /// Un seul envoi paie plusieurs destinataires : la transaction porte bien
    /// toutes leurs sorties, et la monnaie revient au portefeuille.
    #[test]
    fn sendmany_paie_plusieurs_destinataires_en_une_transaction() {
        let c = contexte_avec_fonds();
        let mut autre = Wallet::from_seed([0x11; 32], RESEAU);
        let a1 = autre.new_address().to_string_bech32();
        let a2 = autre.new_address().to_string_bech32();

        let params = format!(
            r#"{{"destinations":[{{"adresse":"{a1}","unites":1000}},{{"adresse":"{a2}","unites":2000}}]}}"#
        );
        let r = resultat(&c, "sendmany", &params);

        assert!(
            r.get("txid").and_then(|v| v.as_str()).is_some(),
            "un envoi accepte doit rendre un identifiant"
        );
        assert_eq!(r.get("destinataires").and_then(|v| v.as_u64()), Some(2));

        let sorties = r
            .get("transaction")
            .and_then(|t| t.get("sorties"))
            .and_then(|v| v.as_array())
            .expect("sorties presentes");
        // Deux destinataires, plus la monnaie : au moins deux sorties.
        assert!(sorties.len() >= 2);
        let unites: Vec<u64> = sorties
            .iter()
            .filter_map(|s| {
                s.get("valeur")
                    .and_then(|v| v.get("unites"))
                    .and_then(|v| v.as_u64())
            })
            .collect();
        assert!(
            unites.contains(&1000) && unites.contains(&2000),
            "les deux montants demandes doivent figurer parmi les sorties : {unites:?}"
        );
    }

    /// Un envoi sans destinataire est refuse proprement, pas construit a vide.
    #[test]
    fn sendmany_refuse_une_liste_vide() {
        let c = contexte_avec_fonds();
        let r = appel(&c, "sendmany", r#"{"destinations":[]}"#);
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_PARAMS)
        );
    }

    #[test]
    fn une_hauteur_inexistante_est_une_erreur_propre() {
        let c = contexte(false);
        let r = appel(&c, "getblock", r#"{"hauteur":9999}"#);
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_INTROUVABLE)
        );
    }

    #[test]
    fn une_methode_inconnue_est_signalee() {
        let c = contexte(false);
        let r = appel(&c, "nexistepas", "{}");
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_METHODE)
        );
    }

    #[test]
    fn un_document_illisible_rend_une_erreur_d_analyse() {
        let c = contexte(false);
        let r = jparse(&c.handle("{ceci n'est pas du json")).unwrap();
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_PARSE)
        );
    }

    /// La separation qui evite qu'un port de consultation devienne un port de
    /// depense.
    #[test]
    fn les_methodes_de_portefeuille_sont_refusees_par_defaut() {
        let c = contexte(false);
        for m in ["getbalance", "getnewaddress", "sendtoaddress"] {
            let r = appel(&c, m, "{}");
            assert_eq!(
                r.get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(|v| v.as_i64()),
                Some(ERR_PORTEFEUILLE_DESACTIVE),
                "{m} aurait du etre refusee"
            );
        }
    }

    #[test]
    fn les_methodes_de_portefeuille_repondent_quand_il_est_actif() {
        let c = contexte(true);
        let r = resultat(&c, "getbalance", "{}");
        assert_eq!(
            r.get("depensable")
                .and_then(|m| m.get("unites"))
                .and_then(|v| v.as_u64()),
            Some(0)
        );

        let a = resultat(&c, "getnewaddress", "{}");
        let adr = a.get("adresse").and_then(|v| v.as_str()).unwrap();
        assert!(adr.starts_with("rq21"), "adresse inattendue : {adr}");
        assert!(
            a.get("avertissement").is_some(),
            "l'usage unique doit etre rappele"
        );
    }

    /// Aucun montant ne doit transiter en flottant.
    ///
    /// La verification est indirecte mais forte : l'analyseur de `crate::json`
    /// **refuse** les flottants. Si l'encodeur en produisait un, relire la
    /// reponse echouerait. Chaque methode est donc passee au retour.
    #[test]
    fn aucune_reponse_ne_contient_de_flottant() {
        let c = contexte(true);
        for (m, p) in [
            ("getinfo", "{}"),
            ("getsupply", "{}"),
            ("getemission", r#"{"hauteur":1051200}"#),
            ("getblock", r#"{"hauteur":0}"#),
            ("getpow", "{}"),
            ("getsecurity", "{}"),
            ("getbalance", "{}"),
            ("getmempool", "{}"),
        ] {
            let brut = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{m}","params":{p}}}"#);
            let sortie = c.handle(&brut);
            assert!(
                jparse(&sortie).is_ok(),
                "{m} produit un document que notre propre analyseur refuse —                  signe qu'un flottant s'y est glisse : {sortie}"
            );
        }

        // Et la forme des montants reste celle promise : entier plus texte.
        let r = resultat(&c, "getsupply", "{}");
        let emis = r.get("emis").unwrap();
        assert!(emis.get("unites").and_then(|v| v.as_u64()).is_some());
        assert_eq!(emis.get("q21").and_then(|v| v.as_str()), Some("1.00000000"));
    }

    #[test]
    fn getsecurity_ne_dit_pas_que_ce_qui_rassure() {
        let c = contexte(false);
        let r = resultat(&c, "getsecurity", "{}");
        assert_eq!(
            r.get("protection_100_pourcent_possible"),
            Some(&Json::Bool(false)),
            "l'API ne doit pas laisser croire a une immunite"
        );
        assert!(
            r.get("un_attaquant_peut")
                .and_then(|v| v.as_array())
                .unwrap()
                .len()
                >= 2
        );
        assert!(r.get("cout_de_la_finalite_glissante").is_some());
    }

    /// Le solde dit quand la prochaine somme se liberera.
    ///
    /// Sans cela, l'interface annonce « en attente de maturite » et rien
    /// d'autre : un mineur voit son gain monter et son disponible rester a
    /// zero pendant des heures, sans repere. La question devant un solde
    /// bloque n'est pas « combien », c'est « quand ».
    #[test]
    fn le_solde_annonce_la_prochaine_maturite() {
        let c = contexte_avec_fonds();
        let r = resultat(&c, "getbalance", "{}");
        // La chaine d'epreuve mine au-dela de la maturite : il reste donc des
        // coinbases immatures en haut, et la reponse doit les dater.
        assert!(
            r.get("prochaine_maturite_hauteur").is_some(),
            "aucune date de liberation annoncee : {}",
            r.encode()
        );
        let blocs = r
            .get("prochaine_maturite_blocs")
            .and_then(|v| v.as_u64())
            .expect("blocs restants");
        assert!(
            blocs > 0 && blocs <= COINBASE_MATURITY,
            "attente absurde : {blocs}"
        );
        assert!(r.get("prochaine_maturite_montant").is_some());

        // Et les constantes qui permettent de traduire cette attente en temps
        // viennent du nœud, pour n'etre ecrites qu'a un seul endroit au monde.
        let i = resultat(&c, "getinfo", "{}");
        assert_eq!(
            i.get("maturite_coinbase").and_then(|v| v.as_u64()),
            Some(COINBASE_MATURITY)
        );
        assert_eq!(
            i.get("intervalle_cible_secondes").and_then(|v| v.as_u64()),
            Some(TARGET_BLOCK_SECS)
        );
    }

    /// Un bloc illisible ne fait pas disparaitre un paiement en silence.
    ///
    /// # L'incident que cette epreuve fige
    ///
    /// Le balayage de l'historique sautait sans un mot les hauteurs dont le
    /// corps ne pouvait pas etre lu. Sur un vrai reseau, apres un arret brutal
    /// et une resynchronisation, un virement recu avait purement et simplement
    /// disparu de l'historique — alors que le solde, lui, le comptait toujours.
    /// Un portefeuille qui perd une ligne sans le dire est pire qu'un
    /// portefeuille en panne : on le croit.
    #[test]
    fn l_historique_avoue_les_blocs_qu_il_n_a_pas_pu_lire() {
        // La reponse porte toujours le compte, meme quand il est nul : un
        // appelant ne doit pas avoir a distinguer « champ absent » de « zero ».
        let c = contexte(true);
        let r = resultat(&c, "listtransactions", r#"{"limite":5}"#);
        assert_eq!(
            r.get("blocs_illisibles").and_then(|v| v.as_u64()),
            Some(0),
            "le compte doit etre annonce meme a zero"
        );
        assert_eq!(r.get("historique_complet"), Some(&Json::Bool(true)));
        // Et le texte de la page RPC doit nommer le remede, pas seulement le mal.
        let s = c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"listtransactions"}"#);
        assert!(s.contains("historique_complet"));
    }

    /// Une adresse se nomme, et le nom revient avec la liste.
    ///
    /// Q21 pousse a donner une adresse par correspondant. Sans carnet, on se
    /// retrouve au bout d'un mois avec quatre cents suites de caracteres et
    /// aucune idee de qui est qui : le carnet rend au porteur ce que la vie
    /// privee lui a coute.
    #[test]
    fn une_adresse_se_nomme_et_le_nom_revient() {
        let c = contexte(true);
        let _ = resultat(&c, "getnewaddress", "{}");
        let r = resultat(
            &c,
            "setaddresslabel",
            r#"{"indice":0,"etiquette":"pour Mathis"}"#,
        );
        assert_eq!(
            r.get("etiquette").and_then(|v| v.as_str()),
            Some("pour Mathis")
        );

        let liste = resultat(&c, "listaddresses", "{}");
        let a = liste.as_array().expect("tableau d'adresses");
        assert_eq!(
            a[0].get("etiquette").and_then(|v| v.as_str()),
            Some("pour Mathis"),
            "le nom doit revenir avec l'adresse qu'il designe"
        );

        // Un nom vide efface, et l'adresse repart sans champ `etiquette` :
        // une chaine vide obligerait chaque appelant a distinguer « sans nom »
        // de « nomme par du vide ».
        let _ = resultat(&c, "setaddresslabel", r#"{"indice":0,"etiquette":""}"#);
        let liste = resultat(&c, "listaddresses", "{}");
        assert!(liste.as_array().expect("tableau")[0]
            .get("etiquette")
            .is_none());
    }

    /// On ne nomme pas une adresse qui n'existe pas.
    ///
    /// L'accepter laisserait des noms orphelins dans le fichier et masquerait
    /// une faute de frappe de l'appelant.
    #[test]
    fn nommer_une_adresse_inexistante_est_refuse() {
        let c = contexte(true);
        let r = appel(&c, "setaddresslabel", r#"{"indice":9999,"etiquette":"x"}"#);
        assert!(
            r.get("error").is_some(),
            "un indice inconnu doit etre refuse"
        );
    }

    /// Un envoi se voit dans l'historique **avant** d'etre dans un bloc.
    ///
    /// C'est le defaut que cette epreuve fige. L'historique ne lisait que les
    /// blocs : entre l'instant ou l'on appuie sur « Envoyer » et le bloc qui
    /// inclut la transaction — deux minutes en moyenne, davantage si le reseau
    /// est charge — le paiement n'apparaissait nulle part, alors que le solde
    /// avait deja baisse. Constate sur un vrai noeud, par quelqu'un qui a cru
    /// son argent perdu.
    #[test]
    fn un_envoi_apparait_dans_l_historique_des_le_reservoir() {
        let c = contexte_avec_fonds();
        let mut dest = Wallet::from_seed([0xcc; 32], RESEAU);
        let adresse = dest.new_address().to_string_bech32();

        // Rien en attente avant l'envoi : ce qui suit mesure bien l'effet de
        // l'envoi, et non une ligne qui trainait.
        let avant = resultat(&c, "listtransactions", r#"{"limite":5}"#);
        assert!(
            avant
                .get("mouvements")
                .and_then(|v| v.as_array())
                .expect("mouvements")
                .iter()
                .all(|m| m.get("en_attente").is_none()),
            "aucune ligne ne doit etre en attente avant l'envoi"
        );

        let envoi = resultat(
            &c,
            "sendtoaddress",
            &format!(r#"{{"adresse":"{adresse}","unites":100000}}"#),
        );
        let txid = envoi
            .get("txid")
            .and_then(|v| v.as_str())
            .expect("txid")
            .to_string();
        assert_eq!(
            c.node.mempool_len(),
            1,
            "la transaction doit etre au reservoir"
        );

        let apres = resultat(&c, "listtransactions", r#"{"limite":5}"#);
        let mouvements = apres
            .get("mouvements")
            .and_then(|v| v.as_array())
            .expect("mouvements");
        assert_eq!(
            mouvements
                .iter()
                .filter(|m| m.get("en_attente").is_some())
                .count(),
            1,
            "l'envoi doit ajouter exactement une ligne en attente"
        );

        // La plus recente est en tete : c'est celle qu'on cherche des yeux.
        let l = &mouvements[0];
        assert_eq!(l.get("txid").and_then(|v| v.as_str()), Some(txid.as_str()));
        assert_eq!(l.get("en_attente"), Some(&Json::Bool(true)));
        assert_eq!(
            l.get("confirmations").and_then(|v| v.as_u64()),
            Some(0),
            "rien ne la confirme encore, et il faut le dire"
        );
        assert_eq!(
            l.get("hauteur"),
            Some(&Json::Null),
            "pas de hauteur tant qu'aucun bloc ne la porte : zero serait la genese"
        );
        assert_eq!(l.get("genre").and_then(|v| v.as_str()), Some("envoi"));
        // Le montant engage se lit dans le jeu d'UTXO : le reservoir n'y touche
        // pas, donc les pieces consommees y sont encore.
        assert_eq!(l.get("montant_sortant_connu"), Some(&Json::Bool(true)));
        assert!(
            l.get("sorti")
                .and_then(|v| v.get("unites"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                >= 100_000,
            "le montant sortant doit etre annonce, pas laisse a zero"
        );
    }

    /// Une transaction en attente ne se compte pas comme confirmee.
    ///
    /// L'inverse serait pire que le silence d'origine : afficher « confirmee »
    /// pour ce qui peut encore etre evince du reservoir ferait expedier une
    /// marchandise contre un paiement qui n'existe pas.
    #[test]
    fn le_reservoir_ne_se_fait_pas_passer_pour_un_bloc() {
        let c = contexte_avec_fonds();
        let mut dest = Wallet::from_seed([0xcd; 32], RESEAU);
        let adresse = dest.new_address().to_string_bech32();
        let _ = resultat(
            &c,
            "sendtoaddress",
            &format!(r#"{{"adresse":"{adresse}","unites":100000}}"#),
        );
        let r = c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"listtransactions"}"#);
        assert!(r.contains("\"en_attente\":true"));
        assert!(
            !r.contains("\"en_attente\":true,\"genre\":\"minage\""),
            "une coinbase ne passe jamais par le reservoir"
        );
    }

    /// Le carnet est annonce, et il ne pretend pas denombrer le reseau.
    #[test]
    fn getreseau_annonce_le_carnet_sans_pretendre_compter() {
        let c = contexte(false);
        let r = c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"getreseau"}"#);
        assert!(
            r.contains("\"carnet\""),
            "le carnet doit etre annonce : {r}"
        );
        // Le nom compte : « carnet » dit ce que c'est — des adresses apprises —
        // la ou « machines » aurait laisse croire a un decompte du reseau.
        assert!(!r.contains("\"machines\":"));
    }

    /// Le reseau se mesure en travail, et refuse de compter les mineurs.
    ///
    /// La tentation etait de compter les empreintes de mineur distinctes. Cette
    /// epreuve fige le refus : la reponse ne doit contenir aucun champ qui
    /// pretende denombrer des personnes ou des machines.
    #[test]
    fn getreseau_mesure_le_travail_et_ne_compte_personne() {
        let c = contexte(false);
        let r = c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"getreseau"}"#);
        for attendu in [
            "\"pairs\"",
            "\"blocs_examines\"",
            "\"debit_reseau_milli\"",
            "\"travail_total\"",
            "\"mesurable\"",
        ] {
            assert!(r.contains(attendu), "champ absent : {attendu} dans {r}");
        }
        // On cherche des **clefs**, pas des mots : la note emploie a bon droit
        // le mot « mineurs » pour dire qu'on ne les compte pas. Un premier jet
        // de cette epreuve cherchait la sous-chaine nue et tombait sur sa propre
        // explication.
        for interdit in ["\"mineurs\":", "\"nombre_de_mineurs\":", "\"machines\":"] {
            assert!(
                !r.contains(interdit),
                "la reponse pretend compter ce qui ne se compte pas : {interdit}"
            );
        }
        // Et elle doit le dire, pas seulement s'en abstenir.
        assert!(
            r.contains("n'est pas connaissable"),
            "la reponse ne dit pas pourquoi elle ne compte pas les mineurs"
        );
    }

    /// La genese n'est jamais l'ancre de la mesure.
    ///
    /// Son horodatage est une constante du protocole. L'inclure faisait mesurer
    /// la distance entre cette constante et aujourd'hui : sur une chaine minee
    /// en neuf secondes, la reponse annoncait « 371,8 jours ».
    #[test]
    fn la_genese_ne_sert_pas_de_point_de_depart() {
        let g = genesis_block(RESEAU);
        let mut chaine = Chain::new(RESEAU, g);
        // Trois blocs mines maintenant, tres loin de l'horodatage de la genese.
        let maintenant = chaine.tip().time + 10_000_000;
        for i in 0..3u64 {
            let t = maintenant + i;
            let b = chaine
                .mine_block(Hash256([7u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
                .expect("minage");
            chaine.connect(&b, t + 1).expect("connexion");
        }
        let node = Arc::new(Node::new(RESEAU, chaine));
        let c = RpcContext {
            sur_changement: None,
            index: None,
            minage: None,
            node,
            wallet: None,
            network: RESEAU,
        };
        let r = c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"getreseau"}"#);
        // Trois blocs espaces d'une seconde : l'ecart mesure doit rester petit,
        // et non valoir les dix millions de secondes qui les separent de la
        // genese.
        let d = r
            .find("\"secondes_examinees\":")
            .map(|i| {
                r[i + 21..]
                    .split(&[',', '}'][..])
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .expect("champ present");
        let secondes: u64 = d.trim().parse().expect("un nombre");
        assert!(
            secondes < 100,
            "la genese sert encore d'ancre : {secondes} secondes mesurees"
        );
    }

    /// Une chaine d'un seul bloc ne produit pas un debit infini.
    ///
    /// Sur la genese seule, l'ecart de temps de la fenetre vaut zero. Diviser
    /// par lui donnerait une division par zero, ou pire un chiffre enorme
    /// affiche comme une mesure.
    #[test]
    fn un_reseau_sans_histoire_avoue_qu_il_ne_mesure_rien() {
        let c = contexte(false);
        let r = c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"getreseau"}"#);
        assert!(r.contains(r#""mesurable":false"#), "{r}");
        assert!(r.contains(r#""debit_reseau_milli":"0""#), "{r}");
    }

    #[test]
    fn le_travail_d_un_bloc_sature_au_lieu_de_deborder() {
        // Un travail qui ne tient pas dans 128 bits doit rendre le plafond, et
        // non zero : un zero se lirait comme « le reseau est arrete ».
        let enorme = crate::uint::U256::from_be_bytes(&[0xff; 32]);
        assert_eq!(travail_en_u128(enorme), u128::MAX);
        assert_eq!(travail_en_u128(crate::uint::U256::ZERO), 0);
    }

    #[test]
    fn getpow_expose_l_asymetrie_entre_noeud_et_mineur() {
        let c = contexte(false);
        let r = resultat(&c, "getpow", "{}");
        let noeud = r
            .get("memoire_noeud_octets")
            .and_then(|v| v.as_u64())
            .expect("memoire_noeud_octets");
        let mineur = r
            .get("memoire_mineur_octets")
            .and_then(|v| v.as_u64())
            .expect("memoire_mineur_octets");

        // Ce test affirmait auparavant `noeud == 0`. La phase 6 a montre que
        // cette gratuite etait precisement ce qui rendait la preuve de travail
        // contournable : un element de table se recalculait pour un condensat.
        // L'asymetrie subsiste, elle n'est simplement plus infinie.
        assert!(noeud > 0, "un noeud detient desormais le cache");
        assert!(mineur > noeud, "et un mineur detient bien davantage");
        assert_eq!(
            mineur / noeud,
            u64::from(POW_CACHE_RATIO),
            "le rapport entre les deux niveaux est une constante de consensus"
        );
    }

    #[test]
    fn un_lot_de_requetes_est_traite() {
        let c = contexte(false);
        let corps = r#"[{"jsonrpc":"2.0","id":1,"method":"getinfo"},
                        {"jsonrpc":"2.0","id":2,"method":"getsupply"}]"#;
        let r = jparse(&c.handle(corps)).expect("reponse");
        let v = r.as_array().expect("un tableau de reponses");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].get("id").and_then(|x| x.as_u64()), Some(1));
        assert_eq!(v[1].get("id").and_then(|x| x.as_u64()), Some(2));
    }

    #[test]
    fn listmethods_documente_l_api() {
        let c = contexte(false);
        let r = resultat(&c, "listmethods", "{}");
        let v = r.as_array().expect("tableau");
        assert!(v.len() >= 10);
        assert!(v
            .iter()
            .all(|m| m.get("nom").is_some() && m.get("description").is_some()));
    }

    #[test]
    fn une_transaction_inconnue_est_signalee() {
        let c = contexte(false);
        let r = appel(&c, "gettransaction", r#"{"txid":"00"}"#);
        assert!(r.get("error").is_some());
    }

    #[test]
    fn getemission_suit_la_courbe() {
        let c = contexte(false);
        let r = resultat(&c, "getemission", r#"{"hauteur":1051200}"#);
        assert_eq!(r.get("annee_approx").and_then(|v| v.as_u64()), Some(4));
        let cumul = r
            .get("emis_cumule")
            .and_then(|m| m.get("unites"))
            .and_then(|v| v.as_u64())
            .unwrap();
        assert!(
            cumul <= MAX_SUPPLY,
            "le plafond ne doit jamais etre franchi"
        );
    }

    /// La recherche reconnait une hauteur.
    #[test]
    fn rechercher_reconnait_une_hauteur() {
        let c = contexte(false);
        let r = resultat(&c, "rechercher", r#"{"q":"0"}"#);
        assert_eq!(r.get("genre").and_then(|v| v.as_str()), Some("bloc"));
        assert_eq!(r.get("valeur").and_then(|v| v.as_str()), Some("0"));
    }

    /// Une hauteur au-dela du sommet est refusee, et le dit.
    #[test]
    fn rechercher_refuse_une_hauteur_absente() {
        let c = contexte(false);
        let r = appel(&c, "rechercher", r#"{"q":"999999"}"#);
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_INTROUVABLE)
        );
    }

    /// La recherche reconnait un identifiant de bloc.
    #[test]
    fn rechercher_reconnait_un_identifiant_de_bloc() {
        let c = contexte(false);
        let id = c
            .node
            .with_chain(|ch| ch.block_at(0).unwrap().header.block_id());
        let r = resultat(&c, "rechercher", &format!(r#"{{"q":"{}"}}"#, id.to_hex()));
        assert_eq!(r.get("genre").and_then(|v| v.as_str()), Some("bloc-id"));
    }

    /// La recherche reconnait une adresse, et refuse celle d'un autre reseau.
    ///
    /// Une adresse porte sa propre somme de controle **et** son reseau. Laisser
    /// passer une adresse de reseau principal sur un noeud d'essai ferait
    /// chercher une chaine dans une autre : la reponse serait « rien trouve »,
    /// ce qui est vrai et parfaitement trompeur.
    #[test]
    fn rechercher_reconnait_une_adresse_et_refuse_un_autre_reseau() {
        let c = contexte(true);
        let a = {
            let mut w = c.wallet.as_ref().unwrap().lock().unwrap();
            w.new_address()
        };
        let r = resultat(
            &c,
            "rechercher",
            &format!(r#"{{"q":"{}"}}"#, a.to_string_bech32()),
        );
        assert_eq!(r.get("genre").and_then(|v| v.as_str()), Some("adresse"));

        let etrangere = crate::address::Address {
            network: Network::Mainnet,
            scheme: a.scheme,
            hash: a.hash,
        };
        let r = appel(
            &c,
            "rechercher",
            &format!(r#"{{"q":"{}"}}"#, etrangere.to_string_bech32()),
        );
        assert!(
            r.get("error").is_some(),
            "une adresse d'un autre reseau a ete acceptee"
        );
    }

    /// Une saisie qui n'est rien du tout est refusee sans travail.
    #[test]
    fn rechercher_refuse_ce_qui_n_est_rien() {
        let c = contexte(false);
        for q in ["bonjour", "", "0x1234", &"a".repeat(300)] {
            let r = appel(&c, "rechercher", &format!(r#"{{"q":"{q}"}}"#));
            assert!(r.get("error").is_some(), "accepte a tort : {q}");
        }
    }

    /// Une adresse quelconque a un solde et un historique, sans appartenir au
    /// portefeuille.
    ///
    /// C'est ce qui separe un explorateur d'un portefeuille : il repond sur des
    /// adresses qui ne sont pas les siennes.
    #[test]
    fn getadresse_repond_sur_une_adresse_quelconque() {
        let c = contexte(true);
        let a = {
            let mut w = c.wallet.as_ref().unwrap().lock().unwrap();
            w.new_address()
        };
        let r = resultat(
            &c,
            "getadresse",
            &format!(r#"{{"adresse":"{}"}}"#, a.to_string_bech32()),
        );
        assert_eq!(
            r.get("solde")
                .and_then(|m| m.get("unites"))
                .and_then(|v| v.as_u64()),
            Some(0)
        );
        // Sans index, la reponse doit l'avouer.
        assert_eq!(r.get("via_index"), Some(&Json::Bool(false)));
        assert!(r
            .get("note")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("borne"));
    }

    /// Une adresse illisible ne fait pas travailler le noeud.
    #[test]
    fn getadresse_refuse_une_adresse_illisible() {
        let c = contexte(false);
        let r = appel(&c, "getadresse", r#"{"adresse":"tq21pasunevraieadresse"}"#);
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_PARAMS)
        );
    }

    /// « Arrete-toi » n'est pas une methode de lecture.
    ///
    /// Un noeud public repond volontiers a qui demande sa hauteur ; il ne doit
    /// pas s'eteindre parce qu'on le lui demande. La methode passe donc par le
    /// meme controle que celles qui deplacent des fonds.
    #[test]
    fn arreter_est_refuse_a_un_noeud_sans_portefeuille() {
        let _v = crate::arret::VERROU_EPREUVE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::arret::arret_termine();
        let c = contexte(false);
        let r = appel(&c, "arreter", "{}");
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_PORTEFEUILLE_DESACTIVE)
        );
        assert!(
            !crate::arret::demande(),
            "un noeud sans portefeuille a quand meme leve le drapeau d'arret"
        );
    }

    /// En mode portefeuille, le bouton leve le meme drapeau que Ctrl-C.
    ///
    /// C'est tout ce qu'il fait : la boucle principale le voit au tour suivant
    /// et fait le travail — reservoir, instantane, carnet, portefeuille — dans
    /// un contexte normal. Rien n'est ecrit depuis la reponse a une requete.
    #[test]
    fn arreter_leve_le_drapeau_en_mode_portefeuille() {
        let _v = crate::arret::VERROU_EPREUVE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::arret::arret_termine();
        let c = contexte(true);
        let r = resultat(&c, "arreter", "{}");
        assert_eq!(r.get("arret"), Some(&Json::Bool(true)));
        assert!(crate::arret::demande(), "le drapeau d'arret n'est pas leve");
        // Le drapeau est global au processus : le laisser leve ferait sortir
        // toute boucle qui le consulte ensuite.
        crate::arret::arret_termine();
    }
}
