//! Elagage du fichier de blocs, et redemarrage d'un noeud sur ce qu'il a.
//!
//! # Pourquoi
//!
//! Le fichier de blocs ne faisait que grossir. Un noeud qui valide pour lui —
//! un portefeuille, un mineur sur Raspberry — n'a pourtant besoin que de ce
//! qu'il peut encore defaire (la fenetre de reorganisation) et de ce que son
//! historique affiche : tout ce qui precede se resume dans l'instantane. Une
//! carte SD ne tient pas dix ans de corps ; elle tient dix ans d'instantanes.
//!
//! # Ce qui rend l'elagage sur : l'ordre des ecritures
//!
//! Un noeud elague est, au redemarrage, dans la situation exacte d'un noeud
//! qui a adopte un instantane : il repart de l'etat enregistre, relit ses
//! en-tetes dans le magasin d'en-tetes, et rejoue les corps posterieurs a
//! l'instantane. Trois choses doivent donc etre vraies **avant** de retirer
//! un seul corps :
//!
//! 1. l'instantane est **sur le disque** — non pas « vient d'etre ecrit »
//!    d'apres l'appelant, mais relu du fichier par [`elaguer`] elle-meme ;
//! 2. le magasin d'en-tetes couvre la genese jusqu'a la hauteur de
//!    l'instantane — on le complete ici, et si cela echoue on n'elague pas ;
//! 3. les corps posterieurs a l'instantane restent — la fenetre conservee
//!    depasse largement le recul de l'instantane, et c'est verifie ici.
//!
//! La reecriture du fichier ne prend pas le verrou de la chaine plus
//! longtemps que la lecture des en-tetes ; l'archive serialise elle-meme ses
//! lectures et ecritures.
//!
//! # Le redemarrage, pour tout noeud
//!
//! [`reprendre_la_chaine`] est le chemin unique par lequel le binaire
//! reconstruit sa chaine au demarrage — noeud complet, elague ou adopte. Il
//! est ici, dans la bibliotheque, pour une raison simple : c'est le chemin qui
//! doit fonctionner le jour ou le disque a menti, et il n'est eprouvable que
//! s'il est appelable depuis une epreuve. Sa regle : **une corruption locale
//! coute du reseau, jamais le refus de demarrer**, tant que la genese est
//! lisible. Ce qui ne se relit pas est retire, ce qui manque sera redemande.
//!
//! # Ce qu'un noeud elague ne peut plus faire
//!
//! Servir d'explorateur (l'index d'adresses renvoie a des corps qu'il n'a
//! plus), et revalider son histoire sans qu'on lui fournisse les corps d'un
//! noeud complet. Il verifie toujours tout ce qu'il recoit ; il ne garde
//! simplement pas ce qu'il ne relira jamais.

use crate::address::Network;
use crate::block::BlockHeader;
use crate::chain::Chain;
use crate::consensus::{BODY_WINDOW, MAX_FUTURE_TIME};
use crate::state::StateStore;
use crate::store::{BlockArchive, Elagage, HeaderStore};
use std::sync::Arc;

/// Ce qu'un noeud elague conserve, et a quel rythme il elague.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Politique {
    /// Corps conserves sous la tete.
    pub corps_conserves: u64,
    /// Blocs entre deux elagages.
    pub pas: u64,
}

/// La politique par defaut : la fenetre d'historique du portefeuille plus la
/// fenetre de reorganisation — tout ce qu'un noeud peut encore avoir a relire
/// ou a afficher —, et une reecriture tous les deux mille blocs (moins de
/// trois jours), assez pour tenir le fichier a sa taille de croisiere sans
/// le reecrire toutes les cinq minutes.
pub const POLITIQUE_DEFAUT: Politique = Politique {
    corps_conserves: crate::rpc::FENETRE_HISTORIQUE + BODY_WINDOW as u64,
    pas: 2_016,
};

/// Complete le magasin d'en-tetes, de ce qu'il contient deja jusqu'a la
/// hauteur `jusqu_a` incluse, avec les en-tetes de la chaine active.
///
/// # Le defaut que ceci ferme
///
/// Le magasin n'etait complete qu'a l'elagage, tous les 2 016 blocs. Entre
/// deux elagages, la chaine d'en-tetes d'un noeud elague etait donc le
/// magasin (genese -> dernier elagage) **prolonge par les en-tetes lus dans
/// le fichier de blocs**. Dans cette fenetre — jusqu'a trois mille blocs —
/// les 164 premiers octets de chaque enregistrement etaient vitaux : un bit
/// retourne dans l'un d'eux, et l'instantane n'etait plus sur la chaine, sans
/// aucun corps pour reconstruire l'etat. Appelee apres chaque instantane
/// ecrit, cette fonction fait disparaitre la fenetre : quelques en-tetes de
/// 160 octets toutes les cinq minutes, et le magasin couvre toujours la
/// genese jusqu'a l'instantane.
///
/// Elle ne relit pas le fichier : sa taille dit combien d'en-tetes il porte,
/// et sa queue est confrontee a la chaine avant d'ecrire a sa suite (voir
/// [`raccorder_le_magasin`]).
///
/// Rend le nombre d'en-tetes ajoutes.
pub fn completer_le_magasin(
    chain: &Chain,
    entetes: &HeaderStore,
    jusqu_a: u64,
) -> Result<usize, String> {
    let deja = raccorder_le_magasin(chain, entetes)?;
    completer_depuis(chain, entetes, deja, jusqu_a)
}

/// Ramene la queue du magasin a ce que la chaine active confirme, et rend la
/// prochaine hauteur a ecrire.
///
/// Le magasin ne verifie pas la preuve de travail a la relecture : un en-tete
/// abime qui s'enchaine encore sur son parent — un bit dans son nonce — y
/// reste, en derniere position, puisque celui qui le suivait ne s'enchaine
/// plus sur lui et a ete coupe. La chaine en memoire, elle, sait quel est le
/// vrai en-tete a cette hauteur. On remonte depuis la fin jusqu'au premier
/// en-tete que la chaine confirme, on coupe ce qui suit, et l'appelant
/// reecrit la suite depuis la chaine. Sans cela, un magasin dont la queue
/// etait fausse ne se completait plus jamais, et le noeud n'elaguait plus.
///
/// Un en-tete abime est rare : la remontee s'arrete presque toujours au
/// premier — une seule lecture de 160 octets.
pub fn raccorder_le_magasin(chain: &Chain, entetes: &HeaderStore) -> Result<u64, String> {
    let compte = entetes.compte().unwrap_or(0);
    let mut n = compte;
    while n > 0 {
        let confirme = entetes
            .entete_a(n - 1)
            .is_some_and(|h| h.height + 1 == n && chain.active_at(h.height) == Some(h.block_id()));
        if confirme {
            break;
        }
        n -= 1;
    }
    if n < compte {
        entetes
            .tronquer(n)
            .map_err(|e| format!("magasin d'en-tetes non tronque : {e}"))?;
        eprintln!(
            "  magasin d'en-tetes repare : {} en-tete(s) en queue que la chaine dement, \
             retire(s) a partir de la hauteur {n} ; ils seront reecrits depuis la chaine",
            compte - n
        );
    }
    Ok(n)
}

/// Ecrit les en-tetes `deja..=jusqu_a` de la chaine active a la suite du
/// magasin. L'appelant a verifie que `deja` est bien la prochaine hauteur.
fn completer_depuis(
    chain: &Chain,
    entetes: &HeaderStore,
    deja: u64,
    jusqu_a: u64,
) -> Result<usize, String> {
    if deja > jusqu_a {
        return Ok(0);
    }
    let mut nouveaux: Vec<BlockHeader> = Vec::with_capacity((jusqu_a - deja + 1) as usize);
    for h in deja..=jusqu_a {
        let id = chain
            .active_at(h)
            .ok_or_else(|| format!("la chaine active n'atteint pas la hauteur {h}"))?;
        let entete = chain
            .header_of(&id)
            .ok_or_else(|| format!("en-tete de la hauteur {h} absent de l'index"))?;
        nouveaux.push(entete);
    }
    entetes
        .append(&nouveaux)
        .map_err(|e| format!("en-tetes non ecrits : {e}"))?;
    Ok(nouveaux.len())
}

/// Elague si assez de blocs se sont accumules depuis le dernier elagage.
///
/// `instantane` est le fichier d'instantane du dossier : sa hauteur est relue
/// **du disque** ici, avant de retirer quoi que ce soit. `derniere` est la
/// hauteur de la tete au dernier elagage, mise a jour ici.
///
/// # Le defaut que ceci ferme
///
/// La hauteur de l'instantane etait un parametre, fourni par l'appelant
/// d'apres l'instantane qu'il venait de **tenter** d'ecrire. Quand l'ecriture
/// echouait — disque plein, renommage refuse — la hauteur passee etait
/// fictive, le garde-fou la comparait a la fenetre conservee, et laissait
/// passer : les corps entre l'instantane reellement sur le disque et la
/// fenetre etaient retires. Au redemarrage, le premier corps a rejouer
/// manquait, et le noeud regressait a l'ancien instantane. Ici, la seule
/// hauteur qui compte est celle que le fichier annonce, sceau verifie ; si
/// elle est plus ancienne que la fenetre, on n'elague pas et on le dit.
///
/// Rend `Ok(None)` quand il n'y avait rien a faire, `Ok(Some(bilan))` apres
/// une reecriture, et une erreur — le fichier alors intact — si l'instantane
/// du disque est illisible, trop ancien ou hors chaine, ou si le magasin
/// d'en-tetes n'a pas pu etre complete.
pub fn elaguer(
    chain: &Chain,
    archive: &BlockArchive,
    entetes: &HeaderStore,
    instantane: &StateStore,
    reseau: Network,
    politique: Politique,
    derniere: &mut u64,
) -> Result<Option<Elagage>, String> {
    let tete = chain.height();
    if tete < *derniere + politique.pas || tete <= politique.corps_conserves {
        return Ok(None);
    }

    // Garde-fou 1 : l'instantane, tel que le disque le porte.
    let (hauteur_instantane, tete_instantane) = instantane
        .en_tete_sur_disque(reseau)
        .map_err(|e| format!("l'instantane sur le disque est illisible ({e}) : on n'elague pas"))?;
    if chain.active_at(hauteur_instantane) != Some(tete_instantane) {
        return Err(format!(
            "l'instantane sur le disque (hauteur {hauteur_instantane}) ne designe pas la \
             chaine active : on n'elague pas"
        ));
    }
    // Garde-fou 3 : ce qui suit l'instantane doit rester. La politique par
    // defaut le garantit de loin ; une politique d'epreuve, ou un instantane
    // dont l'ecriture echoue depuis des heures, pourraient l'oublier.
    let garde = tete.saturating_sub(politique.corps_conserves);
    if hauteur_instantane < garde {
        return Err(format!(
            "l'instantane sur le disque (hauteur {hauteur_instantane}) est plus ancien que \
             la fenetre conservee (a partir de {garde}) : elaguer perdrait des corps a \
             rejouer, on n'elague pas"
        ));
    }
    // Garde-fou 2 : le magasin d'en-tetes, de la genese a l'instantane. Relu
    // en entier ici — c'est rare — pour qu'un en-tete abime soit coupe et
    // reecrit depuis la chaine, qui les a tous en memoire, plutot que
    // decouvert au prochain demarrage.
    entetes
        .load(reseau)
        .map_err(|e| format!("magasin d'en-tetes illisible : {e}"))?;
    let deja = raccorder_le_magasin(chain, entetes)?;
    completer_depuis(chain, entetes, deja, hauteur_instantane)?;

    // Les corps : la genese, et tout ce qui est a moins de `corps_conserves`
    // de la tete. Ce qui est plus ancien est resume dans l'instantane.
    let elagage = archive
        .elaguer(|h| h.height == 0 || h.height >= garde)
        .map_err(|e| format!("reecriture du fichier de blocs : {e}"))?;

    // La hauteur « derniere elaguee » n'est avancee qu'ICI, apres le succes de
    // l'elagage. Placee plus haut, un echec de `load`, `raccorder_le_magasin`,
    // `completer_depuis` ou `elaguer` l'aurait fait avancer sans qu'aucun corps
    // n'ait ete retire, retardant le prochain elagage d'un pas entier.
    *derniere = tete;
    Ok(Some(elagage))
}

/// Un corps illisible ou refuse au rejeu : on s'arrete au dernier bloc sain.
///
/// # Le defaut que ceci ferme
///
/// Une corruption d'un corps qui n'etait pas en queue du fichier — un bit
/// retourne sur une carte SD — rendait tout demarrage impossible, avec un
/// message qui ne disait pas quoi faire. Rien n'etait faux dans ce refus :
/// mieux vaut ne pas demarrer qu'adopter un etat faux. Mais un noeud sait
/// exactement quoi faire de ce cas : garder ce qui precede, retirer ce qui
/// suit, et redemander le reste au reseau. C'est ce qu'on fait ici — la
/// reecriture passe par le meme chemin que l'elagage, sur, et ce qui est
/// retire etait de toute facon inutilisable.
/// Un bloc que **ce binaire** ne sait pas verifier n'est pas un bloc faux :
/// on ne coupe rien, on s'arrete en le disant.
///
/// Sans cette garde, un binaire construit sans ML-DSA qui rouvrait un dossier
/// portant une transaction ML-DSA retirait tous les corps a partir de ce bloc
/// — mesure : 72 342 octets ramenes a 56 625, « bloc 208 refuse a la
/// reconstruction : SchemaNonDisponible » — et le noeud repartait tronque,
/// sur une chaine qu'il n'aurait pas pu suivre de toute facon.
fn refuser_de_couper_si_incapable(
    e: &crate::validate::ValidationError,
    hauteur: u64,
) -> Result<(), String> {
    if let Some(schema) = e.incapacite_locale() {
        return Err(format!(
            "le bloc {hauteur} porte des signatures {} que ce binaire ne sait pas verifier \
             (construit sans ML-DSA). Rien n'est coupe : le fichier des blocs est intact.\n\n\
             Reconstruisez-le :   cargo build --release   (ML-DSA est inclus par defaut)",
            schema.name()
        ));
    }
    Ok(())
}

pub fn couper_l_archive_a(
    archive: &BlockArchive,
    hauteur: u64,
    raison: &str,
) -> Result<(), String> {
    eprintln!(
        "  fichier des blocs : {raison}.\n               Les corps a partir de la hauteur {hauteur} sont retires ; le reseau \n               fournira le reste."
    );
    archive
        .elaguer(|h| h.height < hauteur)
        .map(|_| ())
        .map_err(|e| format!("impossible de couper le fichier des blocs : {e}"))
}

/// Nom sous lequel un magasin d'en-tetes inutilisable est mis de cote.
fn chemin_abime(entetes: &HeaderStore) -> std::path::PathBuf {
    let mut nom = entetes
        .path()
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    nom.push(".abime");
    entetes.path().with_file_name(nom)
}

/// Reconstruit la chaine d'un dossier a partir de ce que son disque permet.
///
/// `seuls_entetes` sont les en-tetes que [`BlockArchive::open`] a balayes ;
/// `magasin` et `etat` sont le magasin d'en-tetes et l'instantane du dossier,
/// presents ou non.
///
/// # Les trois chemins, et ce qui les relie
///
/// 1. **Dossier adopte ou elague** (le magasin existe) : la chaine d'en-tetes
///    est le magasin — genese jusqu'ou il va — prolonge par les en-tetes du
///    fichier de blocs au-dela. Le magasin se repare lui-meme a la relecture
///    (troncature au premier en-tete abime) ; s'il est inutilisable, il est
///    mis de cote sous `entetes.dat.abime` et l'on continue avec le fichier
///    de blocs seul.
/// 2. **Instantane** : s'il se relit et designe un bloc de la chaine active,
///    on repart de lui et l'on rejoue les corps qui suivent. Un corps
///    illisible ou refuse arrete le rejeu au dernier bloc sain, et le fichier
///    est coupe la : le reseau fournira le reste.
/// 3. **Sans instantane exploitable** : revalidation depuis la genese, dans
///    l'ordre des hauteurs, aussi loin que les corps le permettent. Sur un
///    dossier qui n'a pas les corps d'avant l'instantane, cela s'arrete a la
///    genese — c'est l'**etat minimal** : le noeud demarre, et resynchronise.
///
/// # Le defaut que ceci ferme
///
/// Le chemin 3 etait interdit aux dossiers adoptes ou elagues : « rien a
/// rejouer, resynchronisez dans un dossier vide ». Un seul bit retourne —
/// dans le magasin, ou dans un en-tete du fichier de blocs entre le dernier
/// elagage et l'instantane — rendait donc le dossier definitivement
/// indemarrable, et le conseil donne menait a effacer un dossier qui
/// contient le portefeuille. Desormais un dossier ne refuse de demarrer que
/// si sa genese est illisible ; tout le reste coute du reseau, pas des
/// donnees.
pub fn reprendre_la_chaine(
    reseau: Network,
    archive: &Arc<BlockArchive>,
    mut seuls_entetes: Vec<BlockHeader>,
    magasin: &HeaderStore,
    etat: &StateStore,
) -> Result<Chain, String> {
    // --- 1. Dossier adopte : la chaine d'en-tetes vient du magasin, pas des
    // corps. Un noeud parti d'un instantane n'a pas les corps d'avant lui,
    // donc leurs en-tetes ne se relisent pas du fichier de blocs.
    let adopte = magasin.exists();
    if adopte {
        let base = match magasin.load(reseau) {
            Ok(b) if !b.is_empty() => Some(b),
            Ok(_) => {
                eprintln!("avertissement : magasin d'en-tetes vide, ignore");
                None
            }
            Err(e) => {
                let a_cote = chemin_abime(magasin);
                let range = std::fs::rename(magasin.path(), &a_cote).is_ok();
                eprintln!(
                    "avertissement : magasin d'en-tetes inutilisable ({e}).\n               {} \
                     La chaine repart de ce que le fichier de blocs permet ; le reseau \n               \
                     refournira les en-tetes manquants. Le portefeuille n'est pas touche.",
                    if range {
                        format!("Il est mis de cote dans {}.", a_cote.display())
                    } else {
                        String::new()
                    }
                );
                None
            }
        };
        if let Some(mut base) = base {
            // Les en-tetes du fichier de blocs sont **tous** ajoutes, pas
            // seulement ceux d'au-dela du magasin : l'arborescence fusionne
            // les doublons par identifiant, et c'est la chaine la plus
            // travaillee qui l'emporte. Ne prendre que les posterieurs
            // laissait le dernier maillon du magasin, s'il etait abime mais
            // encore enchaine, faire loi sur le vrai en-tete que le fichier
            // de blocs portait a la meme hauteur — et la reconstruction
            // coupait l'archive a cette hauteur, apres une resynchronisation
            // pourtant complete.
            base.extend(seuls_entetes.iter().copied());
            seuls_entetes = base;
        }
    }

    // --- 2. Reprise sur instantane, si l'on en a un et qu'il est coherent.
    let reprise = match etat.load(reseau) {
        Ok(i) => match Chain::from_snapshot(reseau, i, &seuls_entetes) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("avertissement : instantane inutilisable ({e}) — revalidation complete");
                None
            }
        },
        Err(e) if etat.exists() => {
            eprintln!("avertissement : {e}");
            None
        }
        Err(_) => None,
    };

    if let Some(r) = reprise {
        let mut c = r.chain;
        // Le fournisseur de corps est branche AVANT le rejeu : la regle du
        // double paiement d'oncle relit les corps anterieurs a l'instantane,
        // et valider sans eux serait valider a l'aveugle.
        c.set_body_source(archive.clone());
        // Seule la fenetre qui suit l'instantane est revalidee — c'est ce qui
        // reconstruit les enregistrements d'annulation, donc la capacite a
        // reorganiser.
        for id in &r.a_rejouer {
            let Some(b) = archive.read(id) else {
                couper_l_archive_a(archive, c.height() + 1, "corps manquant au rejeu")?;
                break;
            };
            let now = b.header.time + MAX_FUTURE_TIME;
            if let Err(e) = c.connect(&b, now) {
                refuser_de_couper_si_incapable(&e, b.header.height)?;
                couper_l_archive_a(
                    archive,
                    b.header.height,
                    &format!("bloc {} refuse au rejeu : {e:?}", b.header.height),
                )?;
                break;
            }
        }
        return Ok(c);
    }

    // --- 3. Sans instantane exploitable, on reconstruit depuis la genese.
    //
    // C'est le chemin de secours, celui qui doit fonctionner le jour ou tout
    // le reste a echoue — un debranchement, une batterie a plat, un arret
    // force, un bit retourne.
    //
    // Sur un dossier adopte ou elague, il n'y a pas de corps d'avant
    // l'instantane : la reconstruction s'arrete a la genese, ou au dernier
    // corps present, et le reseau refournit le reste. C'est un cout — une
    // resynchronisation — et non un refus : le dossier, et le portefeuille
    // qu'il contient, restent en place.
    if adopte {
        eprintln!(
            "avertissement : ce dossier n'a pas toute l'histoire (adopte depuis une \
             amorce, ou elague) et son instantane n'est pas exploitable.\n               \
             On repart de ce que le fichier de blocs permet de reconstruire ; le reseau \n               \
             refournira le reste. Le portefeuille n'est pas touche."
        );
    }
    //
    // --- Ce qui n'allait pas, et qui a coute un incident
    //
    // Ce chemin rejouait le fichier **dans son ordre d'ecriture**, en
    // appelant `submit` pour chaque enregistrement. Or le fichier n'est
    // pas une ligne droite : il consigne aussi les branches laterales,
    // sans quoi aucune reorganisation ne survivrait a un redemarrage.
    // Rejouer cet ordre revenait donc a demander a la chaine d'accepter
    // des dizaines de reorganisations successives — et a se heurter aux
    // **defenses anti-reorganisation**, qui sont faites pour repousser
    // un attaquant, pas pour relire sa propre histoire deja validee.
    //
    // Mesure faite sur deux noeuds minant l'un contre l'autre : au bout
    // de deux mille blocs, le noeud refusait purement et simplement de
    // redemarrer, avec un message qui ne pouvait mener nulle part —
    // `FinaliteDepassee { profondeur: 18446744073709551615 }`. Un noeud
    // incapable de relire son propre fichier est un noeud a une coupure
    // de courant de la perte totale.
    //
    // --- Ce qu'on fait a la place
    //
    // On demande d'abord aux **en-tetes** quelle est la chaine active —
    // c'est un calcul, pas une opinion : la tete la plus lourde, puis la
    // remontee jusqu'a la genese. Puis on valide cette suite **dans
    // l'ordre des hauteurs**, de la genese a la tete, avec `connect`.
    //
    // Il n'y a alors plus une seule reorganisation a accepter : chaque
    // bloc prolonge le precedent, par construction. Les branches
    // laterales restent dans le fichier et dans l'index — une
    // reorganisation ulterieure retrouvera leurs corps.
    let ordre = Chain::arborescence(&seuls_entetes)
        .map_err(|e| format!("index des blocs illisible : {e:?}"))?;
    let genese_id = ordre.active[0];
    let corps_genese = archive.read(&genese_id).ok_or(
        "le corps du bloc de genese ne se relit pas du fichier des blocs : c'est la seule \
         perte qui empeche de demarrer. Mettez d'abord le portefeuille a l'abri (wallet.dat, \
         wallet.seq, addresses.dat). Puis, soit deplacez blocks.dat, state.dat et \
         entetes.dat hors du dossier — la genese sera reecrite et le reseau refournira la \
         chaine —, soit resynchronisez dans un dossier vide",
    )?;
    let mut c = Chain::new(reseau, corps_genese);
    c.set_body_source(archive.clone());
    for id in ordre.active.iter().skip(1) {
        let Some(b) = archive.read(id) else {
            couper_l_archive_a(
                archive,
                c.height() + 1,
                &format!("corps du bloc {id} absent du fichier"),
            )?;
            break;
        };
        let now = b.header.time + MAX_FUTURE_TIME;
        if let Err(e) = c.connect(&b, now) {
            refuser_de_couper_si_incapable(&e, b.header.height)?;
            couper_l_archive_a(
                archive,
                b.header.height,
                &format!(
                    "bloc {} refuse a la reconstruction : {e:?}",
                    b.header.height
                ),
            )?;
            break;
        }
    }
    // Les branches laterales sont reinjectees ensuite, une fois la chaine
    // active en place. Chacune est alors une simple branche concurrente
    // moins lourde : aucune ne declenche de reorganisation, et leur presence
    // dans l'index est ce qui permettra d'en adopter une plus tard si elle
    // prend l'avantage.
    let actifs: std::collections::HashSet<_> = ordre.active.iter().copied().collect();
    let mut laterales = 0usize;
    for (id, entete) in &ordre.par_id {
        if actifs.contains(id) || !ordre.travail.contains_key(id) {
            continue;
        }
        let Some(b) = archive.read(id) else { continue };
        let now = entete.time + MAX_FUTURE_TIME;
        if c.submit(&b, now).is_ok() {
            laterales += 1;
        }
    }
    if laterales > 0 {
        println!("  {laterales} bloc(s) de branches laterales reintegres");
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{genesis_block, BodySource};
    use crate::consensus::TARGET_BLOCK_SECS;
    use crate::hash::Hash256;
    use crate::sig::SchemeId;
    use crate::state::Snapshot;
    use std::path::{Path, PathBuf};

    fn etat_de(d: &Path) -> StateStore {
        StateStore::new_scelle(d.join("state.dat"), [3u8; 32])
    }

    const RESEAU: Network = Network::Regtest;

    fn dossier(nom: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("q21-elagage-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn miner(c: &mut Chain, archive: &BlockArchive, n: usize) {
        for _ in 0..n {
            let t = c.tip().time + TARGET_BLOCK_SECS;
            let b = c
                .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
                .expect("minage");
            c.connect(&b, t + 1).expect("connexion");
            archive.append(&b).unwrap();
        }
    }

    /// Un noeud elague redemarre exactement la ou il en etait.
    ///
    /// On mine une chaine, on la journalise, on l'elague avec une politique
    /// courte ; puis on la « redemarre » comme le fait le binaire : instantane,
    /// en-tetes du magasin completes par ceux des corps restants, rejeu des
    /// corps posterieurs a l'instantane depuis l'archive elaguee. La tete, le
    /// jeu d'UTXO et l'emission doivent etre ceux de la chaine d'origine — et
    /// la chaine redemarree doit pouvoir continuer.
    #[test]
    fn un_noeud_elague_redemarre_la_ou_il_en_etait() {
        let d = dossier("redemarrage");
        let (archive, _, _) = BlockArchive::open(d.join("blocks.dat"), RESEAU).unwrap();
        let archive = Arc::new(archive);
        let magasin = HeaderStore::new(d.join("entetes.dat"));

        let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
        archive.append(&genesis_block(RESEAU)).unwrap();
        miner(&mut c, &archive, 120);
        let tete = c.height();
        let instantane: Snapshot = c.snapshot_at_depth(20).expect("instantane");
        assert_eq!(instantane.height, tete - 20);
        let etat = etat_de(&d);
        etat.save(&instantane).expect("instantane ecrit");

        let politique = Politique {
            corps_conserves: 40,
            pas: 10,
        };
        let mut derniere = 0;
        let bilan = elaguer(
            &c,
            &archive,
            &magasin,
            &etat,
            RESEAU,
            politique,
            &mut derniere,
        )
        .expect("elagage")
        .expect("il y avait a elaguer");
        // Genese + les corps de hauteur 80..=120.
        assert_eq!(bilan.conserves, 1 + 41);
        assert_eq!(bilan.retires, 120 - 41);
        assert_eq!(derniere, tete);

        // Trop tot pour recommencer.
        assert_eq!(
            elaguer(
                &c,
                &archive,
                &magasin,
                &etat,
                RESEAU,
                politique,
                &mut derniere
            )
            .unwrap(),
            None
        );

        // Le magasin couvre la genese jusqu'a l'instantane.
        let base = magasin.load(RESEAU).expect("magasin lisible");
        assert_eq!(base.first().map(|h| h.height), Some(0));
        assert_eq!(base.last().map(|h| h.height), Some(instantane.height));

        // --- Le redemarrage, tel que le fait le binaire.
        let (archive2, restants, souci) = BlockArchive::open(d.join("blocks.dat"), RESEAU).unwrap();
        assert!(souci.is_none());
        let h_inst = base.last().unwrap().height;
        let mut entetes = base.clone();
        let mut posterieurs: Vec<BlockHeader> = restants
            .iter()
            .copied()
            .filter(|h| h.height > h_inst)
            .collect();
        posterieurs.sort_by_key(|h| h.height);
        entetes.extend(posterieurs);

        let r = Chain::from_snapshot(RESEAU, instantane, &entetes).expect("reprise");
        let archive2 = Arc::new(archive2);
        let mut rc = r.chain;
        rc.set_body_source(archive2.clone());
        for id in &r.a_rejouer {
            let b = archive2.body(id).expect("corps posterieur a l'instantane");
            rc.connect(&b, b.header.time + 1).expect("rejeu");
        }
        assert_eq!(rc.height(), c.height());
        assert_eq!(rc.tip_id(), c.tip_id());
        assert_eq!(rc.utxo, c.utxo);
        assert_eq!(rc.total_issued(), c.total_issued());

        // Et elle continue.
        miner(&mut rc, &archive2, 1);
        assert_eq!(rc.height(), tete + 1);

        // Un second elagage, plus tard, complete le magasin sans le reecrire.
        miner(&mut rc, &archive2, 30);
        let inst2 = rc.snapshot_at_depth(5).expect("instantane");
        etat.save(&inst2).expect("instantane ecrit");
        let bilan2 = elaguer(
            &rc,
            &archive2,
            &magasin,
            &etat,
            RESEAU,
            politique,
            &mut derniere,
        )
        .expect("second elagage")
        .expect("il y avait a elaguer");
        assert!(bilan2.retires > 0);
        let base2 = magasin.load(RESEAU).expect("magasin lisible");
        assert_eq!(base2.last().map(|h| h.height), Some(inst2.height));
        assert!(base2.windows(2).all(|w| w[1].height == w[0].height + 1));

        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un instantane plus ancien que la fenetre conservee est refuse : on ne
    /// jette jamais un corps qu'il faudrait rejouer.
    #[test]
    fn un_instantane_trop_ancien_empeche_l_elagage() {
        let d = dossier("trop-ancien");
        let (archive, _, _) = BlockArchive::open(d.join("blocks.dat"), RESEAU).unwrap();
        let magasin = HeaderStore::new(d.join("entetes.dat"));
        let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
        archive.append(&genesis_block(RESEAU)).unwrap();
        miner(&mut c, &archive, 60);
        let politique = Politique {
            corps_conserves: 10,
            pas: 1,
        };
        let mut derniere = 0;
        let avant = archive.len();
        let etat = etat_de(&d);
        etat.save(&c.snapshot_at_depth(40).expect("instantane a 20"))
            .expect("instantane ecrit");
        let r = elaguer(
            &c,
            &archive,
            &magasin,
            &etat,
            RESEAU,
            politique,
            &mut derniere,
        );
        assert!(
            r.is_err(),
            "un instantane a la hauteur 20 ne couvre pas les corps 21..50"
        );
        assert_eq!(derniere, 0, "un refus ne compte pas comme un elagage");
        assert_eq!(archive.len(), avant, "le fichier est intact");
        assert!(!magasin.exists(), "rien n'a ete ecrit");
        let _ = std::fs::remove_dir_all(&d);
    }
}
