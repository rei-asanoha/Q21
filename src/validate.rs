//! Regles de consensus.
//!
//! Ce fichier decide ce qui est valide. C'est le seul endroit du projet ou une
//! erreur ne produit pas un bug mais une scission de chaine : deux noeuds qui ne
//! repondent pas la meme chose a « ce bloc est-il valide ? » ne sont plus sur le
//! meme reseau.
//!
//! Les regles sont donc ecrites une par une, nommees, et chacune a son test.
//! Aucune n'est implicite.
//!
//! # Ce que ce module ne fait pas
//!
//! Il ne choisit pas entre deux chaines concurrentes — c'est le role de
//! [`crate::chain`]. Il repond a une question locale : ce bloc-ci, dans cet
//! etat-la, est-il acceptable ?

use crate::address::Network;
use crate::amount::Amount;
use crate::block::{Block, BlockError};
use crate::consensus::*;
use crate::emission::block_subsidy;
use crate::pow::{PowEngine, PowError};
use crate::sig::{self, SchemeId, VerifyError};
use crate::tx::{OutPoint, Transaction, TxError};
use crate::utxo::{UtxoSet, UtxoView};
use std::collections::{HashMap, HashSet};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ValidationError {
    Structure(BlockError),
    Transaction(TxError),
    PreuveDeTravail(PowError),

    // --- Chainage ---
    HauteurIncorrecte {
        attendu: u64,
        recu: u64,
    },
    ParentIncorrect,
    DifficulteIncorrecte {
        attendu: u32,
        recu: u32,
    },

    // --- Horodatage ---
    HorodatageTropAncien {
        median: u64,
        recu: u64,
    },
    HorodatageDansLeFutur {
        limite: u64,
        recu: u64,
    },

    // --- Taille ---
    BlocTropGros {
        max: usize,
        recu: usize,
    },

    // --- Valeur ---
    EntreeIntrouvable(OutPoint),
    DoubleDepense(OutPoint),
    CoinbaseImmature {
        disponible_a: u64,
        hauteur: u64,
    },
    ValeurNonConservee {
        entrees: u64,
        sorties: u64,
    },
    SubventionExcessive {
        autorise: u64,
        reclame: u64,
    },
    FraisDebordent,

    // --- Oncles ---
    TropDOncles {
        max: usize,
        recu: usize,
    },
    OncleDuplique(crate::hash::Hash256),
    OncleTropAncien {
        age: u64,
        max: u64,
    },
    OncleDansLeFutur,
    OncleOrphelin,
    OncleDejaReclame(crate::hash::Hash256),
    OncleEstUnAncetre,
    PreuveDeTravailDOncle(PowError),
    /// La coinbase ne paie pas le mineur annonce dans l'en-tete.
    CoinbaseNePaiePasLeMineur,
    /// La coinbase ne verse pas sa part a un oncle inclus.
    OncleNonRemunere {
        index: usize,
    },

    /// Un oncle porte une difficulte differente de celle attendue a sa hauteur.
    DifficulteDOncleInvalide {
        attendu: u32,
        recu: u32,
    },
    /// Ce bloc porterait l'emission cumulee au-dela du plafond absolu.
    PlafondDepasse {
        cumul: u64,
        emission: u64,
        plafond: u64,
    },
    /// La coinbase ne commet pas sa hauteur : deux blocs pourraient partager un
    /// meme identifiant de transaction.
    CoinbaseSansHauteur,
    /// Un corps de bloc recent manque : impossible de verifier une regle qui en
    /// depend. On refuse plutot que de valider a l'aveugle.
    HistoriqueIncomplet,

    // --- Signatures ---
    ClefNeCorrespondPasAuVerrou,
    SchemaInterditSurCeReseau(SchemeId),
    Signature(VerifyError),

    // --- Poussiere ---
    /// Une sortie sous [`MIN_OUTPUT_VALUE`] : elle occuperait le jeu d'UTXO de
    /// tous les noeuds sans jamais valoir le prix de sa propre depense.
    SortiePoussiere {
        minimum: u64,
        recu: u64,
    },
}

impl From<BlockError> for ValidationError {
    fn from(e: BlockError) -> Self {
        ValidationError::Structure(e)
    }
}
impl From<TxError> for ValidationError {
    fn from(e: TxError) -> Self {
        ValidationError::Transaction(e)
    }
}
impl From<PowError> for ValidationError {
    fn from(e: PowError) -> Self {
        ValidationError::PreuveDeTravail(e)
    }
}

/// Contexte necessaire pour valider un bloc : ce que la chaine sait deja.
pub struct BlockContext<'a> {
    pub network: Network,
    pub height: u64,
    pub prev_id: crate::hash::Hash256,
    /// Horodatages des `MEDIAN_TIME_SPAN` derniers blocs, ordre quelconque.
    pub recent_times: &'a [u64],
    pub expected_bits: u32,
    /// Heure courante, injectee plutot que lue : un consensus qui appelle
    /// l'horloge systeme n'est pas testable de facon deterministe.
    pub now: u64,
    /// Identifiants des ancetres recents, du parent vers l'arriere.
    ///
    /// Sert a verifier qu'un oncle se rattache bien a la branche courante et
    /// qu'il n'en fait pas deja partie.
    pub ancestors: &'a [crate::hash::Hash256],
    /// Oncles deja reclames par les blocs recents.
    ///
    /// Sans ce controle, deux blocs successifs pourraient encaisser deux fois la
    /// recompense du meme travail orphelin.
    pub claimed_uncles: &'a HashSet<crate::hash::Hash256>,
    /// Difficulte attendue pour un enfant de chaque ancetre recent.
    ///
    /// Un oncle est le frere d'un bloc de la chaine active : il doit porter la
    /// meme difficulte que celui-ci. Sans ce controle, la preuve de travail d'un
    /// oncle etait verifiee contre `header.bits`, un champ que son auteur
    /// remplit — donc contre une cible qu'il choisit. Fabriquer un oncle ne
    /// coutait alors aucun calcul.
    pub uncle_expected_bits: &'a HashMap<crate::hash::Hash256, u32>,
    /// Total deja emis avant ce bloc, en unites.
    ///
    /// Sert au dernier rempart : aucun bloc ne peut porter l'emission cumulee
    /// au-dela de [`MAX_SUPPLY`]. Cette regle ne depend d'aucun calendrier,
    /// d'aucune subvention et d'aucun oncle — elle tient meme si tout le reste
    /// est faux.
    pub cumul_emis: u64,
}

/// Recompenses liees aux oncles, en unites indivisibles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UncleRewards {
    /// Part versee a chaque mineur d'oncle, **prelevee sur la subvention**.
    pub par_oncle: u64,
    /// Ce qui reste au mineur du bloc, hors frais.
    pub part_mineur: u64,
}

/// Calcule le partage de la subvention entre le mineur et les oncles.
///
/// # L'invariant que cette fonction porte
///
/// `part_mineur + n_oncles * par_oncle == subvention(hauteur)`, toujours.
///
/// La version precedente **ajoutait** les parts d'oncles a la subvention, plus
/// une prime d'inclusion. Un bloc pouvait donc emettre 210 % de sa subvention,
/// et l'emission maximale du protocole atteignait 44 099 999 Q21 pour un plafond
/// annonce a 21 000 001. Un plafond qu'une regle de consensus peut franchir
/// n'est pas un plafond.
pub fn uncle_rewards(hauteur: u64, n_oncles: usize) -> UncleRewards {
    let base = block_subsidy(hauteur).units();
    let par_oncle = base / 100 * UNCLE_REWARD_PCT;
    // `saturating` par prudence : `n_oncles` est deja borne par MAX_UNCLES en
    // amont, mais cette fonction est publique et ne doit pas dependre de
    // l'ordre des verifications de son appelant.
    let verse = par_oncle.saturating_mul(n_oncles as u64);
    UncleRewards {
        par_oncle,
        part_mineur: base.saturating_sub(verse),
    }
}

/// Verifie les oncles rattaches a un bloc.
///
/// Chaque regle repond a une tricherie precise, nommee en commentaire. Un oncle
/// est du travail reel qui a perdu une course de propagation : on le paie, mais
/// on verifie qu'il est bien ce qu'il pretend etre.
pub fn check_uncles<E: PowEngine>(
    block: &Block,
    ctx: &BlockContext<'_>,
    pow: &E,
) -> Result<(), ValidationError> {
    if block.uncles.len() > MAX_UNCLES {
        return Err(ValidationError::TropDOncles {
            max: MAX_UNCLES,
            recu: block.uncles.len(),
        });
    }

    let mut vus: HashSet<crate::hash::Hash256> = HashSet::new();
    let ancetres: HashSet<crate::hash::Hash256> = ctx.ancestors.iter().copied().collect();

    for oncle in &block.uncles {
        let id = oncle.block_id();

        // Tricherie : inclure deux fois le meme oncle dans un bloc.
        if !vus.insert(id) {
            return Err(ValidationError::OncleDuplique(id));
        }

        // Tricherie : encaisser un travail deja paye a un bloc precedent.
        if ctx.claimed_uncles.contains(&id) {
            return Err(ValidationError::OncleDejaReclame(id));
        }

        // Tricherie : presenter un ancetre de la chaine principale comme un
        // orphelin, et se faire payer une seconde fois le meme bloc.
        if ancetres.contains(&id) {
            return Err(ValidationError::OncleEstUnAncetre);
        }

        // Tricherie : accumuler de vieux orphelins et les encaisser d'un coup.
        if oncle.height >= ctx.height {
            return Err(ValidationError::OncleDansLeFutur);
        }
        let age = ctx.height - oncle.height;
        if age > MAX_UNCLE_AGE {
            return Err(ValidationError::OncleTropAncien {
                age,
                max: MAX_UNCLE_AGE,
            });
        }

        // Tricherie : inventer un oncle sorti de nulle part. Son parent doit
        // appartenir a la branche courante.
        if !ancetres.contains(&oncle.prev_block) {
            return Err(ValidationError::OncleOrphelin);
        }

        // Tricherie : se choisir sa propre difficulte.
        //
        // `pow.check` decode la cible depuis `oncle.bits`, que son auteur
        // remplit. Sans la comparaison qui suit, un en-tete portant une cible
        // quasi maximale passait sans qu'aucun calcul ait ete fait — et le bloc
        // qui l'incluait se faisait payer pour ce travail inexistant.
        let attendu = ctx
            .uncle_expected_bits
            .get(&oncle.prev_block)
            .copied()
            .ok_or(ValidationError::OncleOrphelin)?;
        if oncle.bits != attendu {
            return Err(ValidationError::DifficulteDOncleInvalide {
                attendu,
                recu: oncle.bits,
            });
        }

        // Tricherie : fabriquer un en-tete sans depenser de travail.
        pow.check(oncle)
            .map_err(ValidationError::PreuveDeTravailDOncle)?;
    }
    Ok(())
}

/// Mediane des horodatages recents.
pub fn median_time(times: &[u64]) -> u64 {
    if times.is_empty() {
        return 0;
    }
    let mut v: Vec<u64> = times.iter().rev().take(MEDIAN_TIME_SPAN).copied().collect();
    v.sort_unstable();
    v[v.len() / 2]
}

/// Verifie une transaction isolee contre le jeu d'UTXO.
///
/// Rend les frais qu'elle degage. La coinbase n'est pas traitee ici.
pub fn check_transaction<V: UtxoView + ?Sized>(
    tx: &Transaction,
    utxo: &V,
    network: Network,
    hauteur: u64,
    deja_vues: &mut HashSet<OutPoint>,
) -> Result<Amount, ValidationError> {
    tx.check_shape()?;

    // --- Regle : les sorties doivent utiliser un schema autorise, et ne pas
    //     etre de la poussiere.
    //
    // Avant les entrees : ces controles ne coutent rien, la verification des
    // signatures coute cher. On refuse le bon marche d'abord.
    for sortie in &tx.outputs {
        if !sortie.scheme.allowed_on(network) {
            return Err(ValidationError::SchemaInterditSurCeReseau(sortie.scheme));
        }
        if sortie.value.units() < MIN_OUTPUT_VALUE {
            return Err(ValidationError::SortiePoussiere {
                minimum: MIN_OUTPUT_VALUE,
                recu: sortie.value.units(),
            });
        }
    }

    let mut total_entrees: u64 = 0;

    for (i, entree) in tx.inputs.iter().enumerate() {
        // --- Regle : pas deux fois la meme sortie, ni dans ce bloc ni ailleurs.
        if !deja_vues.insert(entree.prev_out) {
            return Err(ValidationError::DoubleDepense(entree.prev_out));
        }

        let e = utxo
            .lookup(&entree.prev_out)
            .ok_or(ValidationError::EntreeIntrouvable(entree.prev_out))?;

        // --- Regle : maturite des coinbases.
        if e.is_coinbase && hauteur < e.height + COINBASE_MATURITY {
            return Err(ValidationError::CoinbaseImmature {
                disponible_a: e.height + COINBASE_MATURITY,
                hauteur,
            });
        }

        // --- Regle : le schema doit etre autorise sur ce reseau.
        if !e.output.scheme.allowed_on(network) {
            return Err(ValidationError::SchemaInterditSurCeReseau(e.output.scheme));
        }

        // --- Regle : la clef presentee doit correspondre au verrou.
        let empreinte = sig::pubkey_hash(e.output.scheme, &entree.witness.pubkey);
        if empreinte != e.output.pubkey_hash {
            return Err(ValidationError::ClefNeCorrespondPasAuVerrou);
        }

        // --- Regle : la signature doit verifier sur le condensat de cette entree.
        let message = tx.sighash(i as u32);
        sig::verify(
            e.output.scheme,
            &entree.witness.pubkey,
            &message,
            &entree.witness.signature,
        )
        .map_err(ValidationError::Signature)?;

        total_entrees = total_entrees
            .checked_add(e.output.value.units())
            .ok_or(ValidationError::FraisDebordent)?;
    }

    // --- Regle : conservation de la valeur. On ne cree pas de monnaie.
    let total_sorties = tx.total_output()?.units();
    if total_sorties > total_entrees {
        return Err(ValidationError::ValeurNonConservee {
            entrees: total_entrees,
            sorties: total_sorties,
        });
    }

    Ok(Amount::from_units(total_entrees - total_sorties))
}

/// Valide un bloc complet.
pub fn check_block<E: PowEngine>(
    block: &Block,
    utxo: &UtxoSet,
    ctx: &BlockContext<'_>,
    pow: &E,
) -> Result<Amount, ValidationError> {
    // --- Regle : structure, coinbase unique, racines de Merkle.
    block.check_shape()?;

    // --- Regle : taille.
    let taille = block.encode().len();
    if taille > MAX_BLOCK_SIZE {
        return Err(ValidationError::BlocTropGros {
            max: MAX_BLOCK_SIZE,
            recu: taille,
        });
    }

    // --- Regle : chainage.
    if block.header.height != ctx.height {
        return Err(ValidationError::HauteurIncorrecte {
            attendu: ctx.height,
            recu: block.header.height,
        });
    }
    if block.header.prev_block != ctx.prev_id {
        return Err(ValidationError::ParentIncorrect);
    }

    // --- Regle : difficulte imposee par la chaine, pas choisie par le mineur.
    if block.header.bits != ctx.expected_bits {
        return Err(ValidationError::DifficulteIncorrecte {
            attendu: ctx.expected_bits,
            recu: block.header.bits,
        });
    }

    // --- Regle : horodatage posterieur a la mediane recente.
    let median = median_time(ctx.recent_times);
    if !ctx.recent_times.is_empty() && block.header.time <= median {
        return Err(ValidationError::HorodatageTropAncien {
            median,
            recu: block.header.time,
        });
    }

    // --- Regle : horodatage pas trop loin dans le futur.
    let limite = ctx.now + MAX_FUTURE_TIME;
    if block.header.time > limite {
        return Err(ValidationError::HorodatageDansLeFutur {
            limite,
            recu: block.header.time,
        });
    }

    // --- Regle : preuve de travail.
    pow.check(&block.header)?;

    // --- Regle : chaque transaction valide, aucune double depense.
    let mut deja_vues: HashSet<OutPoint> = HashSet::new();
    let mut frais_totaux: u64 = 0;
    for tx in &block.transactions[1..] {
        let f = check_transaction(tx, utxo, ctx.network, ctx.height, &mut deja_vues)?;
        frais_totaux = frais_totaux
            .checked_add(f.units())
            .ok_or(ValidationError::FraisDebordent)?;
    }

    // --- Regle : les oncles sont valides.
    check_uncles(block, ctx, pow)?;

    // --- Regle : la coinbase ne prend pas plus que son du.
    //
    // C'est la regle anti-inflation. Elle et la conservation de la valeur sont
    // les deux seules choses qui empechent de fabriquer de la monnaie — y
    // compris pour un attaquant detenant 51 % de la puissance, qui peut
    // reorganiser des blocs mais jamais en creer davantage.
    let coinbase = &block.transactions[0];
    let recompenses = uncle_rewards(ctx.height, block.uncles.len());

    // --- Regle : pas de poussiere dans la coinbase non plus.
    //
    // Un mineur qui paie des frais se les paie a lui-meme : seule
    // l'immobilisation de capital le freine, et elle passe par ce plancher.
    // La genese est exempte — elle porte l'unite indepensable du plafond.
    if ctx.height > 0 {
        for sortie in &coinbase.outputs {
            if sortie.value.units() < MIN_OUTPUT_VALUE {
                return Err(ValidationError::SortiePoussiere {
                    minimum: MIN_OUTPUT_VALUE,
                    recu: sortie.value.units(),
                });
            }
        }
    }

    // --- Regle : la coinbase commet sa hauteur.
    //
    // Sans cela, deux coinbases du meme mineur pour le meme montant ont le meme
    // identifiant de transaction : la seconde ecrase la premiere dans le jeu
    // d'UTXO, et defaire la seconde detruit la sortie de la premiere. Deux
    // noeuds honnetes se retrouvent alors avec la meme tete et des jeux d'UTXO
    // differents — une scission silencieuse. C'est la lecon de BIP 30 et de
    // BIP 34 dans Bitcoin, apprise ici par un audit adverse.
    let marque = ctx.height.to_le_bytes();
    if !coinbase.inputs[0].witness.signature.starts_with(&marque) {
        return Err(ValidationError::CoinbaseSansHauteur);
    }

    // Structure imposee : le mineur d'abord, puis un versement par oncle.
    if coinbase.outputs.len() != 1 + block.uncles.len() {
        return Err(ValidationError::OncleNonRemunere { index: 0 });
    }
    if coinbase.outputs[0].pubkey_hash != block.header.miner {
        return Err(ValidationError::CoinbaseNePaiePasLeMineur);
    }
    for (i, oncle) in block.uncles.iter().enumerate() {
        let sortie = &coinbase.outputs[i + 1];
        if sortie.pubkey_hash != oncle.miner || sortie.value.units() != recompenses.par_oncle {
            return Err(ValidationError::OncleNonRemunere { index: i });
        }
    }

    // La part du mineur est ce qui reste de la subvention, plus les frais. Les
    // parts d'oncles sont prelevees dessus, jamais ajoutees.
    let autorise_mineur = recompenses
        .part_mineur
        .checked_add(frais_totaux)
        .ok_or(ValidationError::FraisDebordent)?;
    let reclame = coinbase.outputs[0].value.units();
    if reclame > autorise_mineur {
        return Err(ValidationError::SubventionExcessive {
            autorise: autorise_mineur,
            reclame,
        });
    }

    // --- Regle : le plafond absolu. Le dernier rempart.
    //
    // Tout ce qui precede est un calendrier ; ceci est une borne. Elle ne
    // depend ni de la subvention, ni des oncles, ni des frais : elle compare
    // l'emission cumulee au plafond et refuse tout ce qui le franchirait. Meme
    // si une regle economique se revelait fausse — c'est arrive, deux fois —
    // aucun bloc ne peut porter l'emission au-dela de 21 000 001 Q21.
    let total_coinbase = coinbase
        .total_output()
        .map_err(|_| ValidationError::FraisDebordent)?
        .units();
    let emission = total_coinbase.saturating_sub(frais_totaux);
    let cumul = ctx
        .cumul_emis
        .checked_add(emission)
        .ok_or(ValidationError::FraisDebordent)?;
    if cumul > MAX_SUPPLY {
        return Err(ValidationError::PlafondDepasse {
            cumul: ctx.cumul_emis,
            emission,
            plafond: MAX_SUPPLY,
        });
    }

    // --- Regle : les sorties de coinbase respectent le reseau.
    for sortie in &block.transactions[0].outputs {
        if !sortie.scheme.allowed_on(ctx.network) {
            return Err(ValidationError::SchemaInterditSurCeReseau(sortie.scheme));
        }
    }

    Ok(Amount::from_units(frais_totaux))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash256;

    #[test]
    fn la_mediane_ignore_une_valeur_aberrante() {
        let t = [100u64, 101, 102, 103, 999_999];
        assert_eq!(median_time(&t), 102);
    }

    #[test]
    fn la_mediane_gere_les_cas_limites() {
        assert_eq!(median_time(&[]), 0);
        assert_eq!(median_time(&[42]), 42);
        assert_eq!(median_time(&[2, 1]), 2);
    }

    #[test]
    fn la_mediane_ne_regarde_que_la_fenetre() {
        // Vingt blocs anciens a 0, onze recents a 1000 : la mediane doit suivre
        // les recents.
        let mut t = vec![0u64; 20];
        t.extend(vec![1000u64; MEDIAN_TIME_SPAN]);
        assert_eq!(median_time(&t), 1000);
    }

    #[test]
    fn lamport_est_refuse_sur_le_reseau_principal() {
        assert!(!SchemeId::LamportOts.allowed_on(Network::Mainnet));
        assert!(SchemeId::LamportOts.allowed_on(Network::Testnet));
        assert!(SchemeId::LamportOts.allowed_on(Network::Regtest));
    }

    #[test]
    fn ml_dsa_est_accepte_partout() {
        for r in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert!(SchemeId::MlDsa65.allowed_on(r));
            assert!(SchemeId::MlDsa87.allowed_on(r));
            assert!(SchemeId::SphincsPlus.allowed_on(r));
        }
    }

    #[test]
    fn une_entree_introuvable_est_rejetee() {
        let utxo = UtxoSet::new();
        let tx = Transaction {
            version: 1,
            inputs: vec![crate::tx::TxIn {
                prev_out: OutPoint {
                    txid: Hash256([1u8; 32]),
                    index: 0,
                },
                witness: crate::tx::Witness::default(),
                sequence: 0,
            }],
            outputs: vec![crate::tx::TxOut {
                value: Amount::from_units(MIN_OUTPUT_VALUE),
                scheme: SchemeId::LamportOts,
                pubkey_hash: Hash256::ZERO,
            }],
            lock_time: 0,
        };
        let mut vues = HashSet::new();
        assert!(matches!(
            check_transaction(&tx, &utxo, Network::Testnet, 1, &mut vues),
            Err(ValidationError::EntreeIntrouvable(_))
        ));
    }
}
