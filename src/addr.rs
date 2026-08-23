//! Carnet d'adresses et defense contre l'eclipse.
//!
//! # L'attaque que ce module vise
//!
//! Une attaque par eclipse ne cherche pas a casser la cryptographie : elle
//! cherche a **isoler** un noeud. Si toutes ses connexions aboutissent a des
//! machines controlees par une meme personne, ce noeud ne voit plus le vrai
//! reseau. On peut alors lui cacher des blocs, lui montrer une chaine
//! fabriquee, lui faire accepter un paiement deja depense ailleurs. Aucune
//! preuve de travail ne l'en protege : il verifie parfaitement des blocs qui ne
//! sont adresses qu'a lui.
//!
//! Eclipser un noeud coute bien moins cher que d'attaquer le reseau. C'est
//! l'attaque la plus rentable contre une petite chaine, et Q21 en sera une.
//!
//! # La defense : compter les groupes, pas les adresses
//!
//! Un adversaire obtient facilement des milliers d'adresses IP, mais rarement
//! dans des milliers de plages differentes : elles proviennent d'un ou deux
//! hebergeurs, donc d'un petit nombre de blocs `/16`. La contre-mesure suit
//! cette asymetrie, comme le fait Bitcoin Core depuis 2015 :
//!
//! - le carnet est **range par groupe reseau** (`/16`), avec un plafond par
//!   groupe : inonder une plage n'achete presque rien ;
//! - la selection ne rend **jamais deux adresses du meme groupe**, ni une
//!   adresse d'un groupe deja represente parmi les pairs connectes.
//!
//! Detenir 10 000 adresses dans un `/16` donne donc autant d'influence que d'en
//! detenir une seule. Pour peser, il faut posseder des plages entieres — ce qui
//! se compte en argent et en traces administratives, pas en scripts.
//!
//! # Ce que cela ne garantit pas
//!
//! Un adversaire disposant de plages reellement diverses — un grand hebergeur,
//! un operateur — reste dangereux. La diversite par groupe releve le cout, elle
//! ne le rend pas infini. Et un noeud dont **toutes** les adresses de depart
//! viennent de l'attaquant est perdu d'avance : le point d'amorcage reste le
//! maillon faible, ici comme ailleurs.

use crate::ser::{Reader, Writer};
use crate::sha256::sha256;
use crate::wire::NetAddr;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Adresses conservees par groupe `/16`.
///
/// Au-dela, les plus anciennes cedent la place. C'est le plafond qui rend
/// l'inondation inutile.
pub const MAX_PAR_GROUPE: usize = 32;

/// Groupes distincts conserves.
pub const MAX_GROUPES: usize = 512;

/// Age au-dela duquel une adresse cesse d'etre proposee, en secondes.
///
/// Trente jours, comme Bitcoin. Une adresse plus vieille n'a pas disparu du
/// carnet : elle passe simplement apres celles qui ont donne signe de vie.
pub const AGE_MAX: u64 = 30 * 24 * 3600;

const MAGIE: &[u8; 8] = b"Q21ADDRB";
const VERSION: u32 = 1;

/// Groupe reseau d'une adresse : ses deux premiers octets.
///
/// Grossier, et c'est voulu : la question n'est pas de decrire la topologie
/// d'Internet mais d'obliger un adversaire a payer des plages distinctes.
pub fn groupe(ip: [u8; 4]) -> [u8; 2] {
    [ip[0], ip[1]]
}

/// Une adresse routable sur un reseau public ?
///
/// Les plages privees et reservees n'ont aucun sens sur un reseau public, et
/// les propager permettrait de faire composer a un noeud des adresses de son
/// propre reseau local — un scan de port par procuration.
///
/// Le bouclage reste accepte sur les reseaux de test, ou tout se passe sur une
/// seule machine.
pub fn routable(ip: [u8; 4], autoriser_local: bool) -> bool {
    match ip {
        [127, ..] | [0, ..] => autoriser_local,
        [10, ..] => autoriser_local,
        [192, 168, ..] => autoriser_local,
        [169, 254, ..] => autoriser_local,
        [172, b, ..] if (16..32).contains(&b) => autoriser_local,
        [100, b, ..] if (64..128).contains(&b) => autoriser_local,
        [a, ..] if a >= 224 => false, // multidiffusion et reserve
        [255, ..] => false,
        _ => true,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entree {
    pub addr: NetAddr,
    /// Tentatives de connexion consecutives ayant echoue.
    pub echecs: u32,
    /// Derniere connexion reussie, en secondes depuis l'epoque. Zero si jamais.
    pub dernier_succes: u64,
}

/// Tolerance sur un horodatage annonce par un tiers.
///
/// Une adresse annoncee comme « vue » dans le futur n'a aucun sens. Un audit
/// s'en est servi : en inscrivant `last_seen = u64::MAX`, ses adresses gagnaient
/// **toutes** les comparaisons de fraicheur, pour toujours. Elles ne pouvaient
/// plus etre evincees et sortaient toujours premieres a la selection. Un
/// horodatage venu du reseau est une declaration, pas un fait : on le borne.
pub const TOLERANCE_FUTUR: u64 = 10 * 60;

/// Carnet d'adresses range par groupe reseau.
#[derive(Debug)]
pub struct AddrBook {
    groupes: HashMap<[u8; 2], Vec<Entree>>,
    /// Autorise les adresses de bouclage : reseaux de test uniquement.
    local: bool,
    /// Sel propre a ce noeud, tire au demarrage.
    ///
    /// Il ordonne les candidats a la selection. Sans lui, l'ordre etait une
    /// fonction publique des donnees que l'adversaire fournit lui-meme : il
    /// suffisait d'annoncer le bon horodatage pour passer devant. Avec lui,
    /// l'ordre est imprevisible **pour qui ne connait pas le sel**, et le sel ne
    /// sort jamais du processus. C'est la meme idee que le `nKey` d'addrman
    /// dans Bitcoin Core.
    sel: (u64, u64),
}

impl Default for AddrBook {
    fn default() -> AddrBook {
        AddrBook::new(false)
    }
}

impl AddrBook {
    pub fn new(autoriser_local: bool) -> AddrBook {
        // Un sel imprevisible si le systeme sait en fournir un ; a defaut, un
        // sel fixe. L'echec du generateur ne doit pas empecher un noeud de
        // demarrer : on y perd l'imprevisibilite de l'ordre, pas le
        // cloisonnement par groupe, qui reste la defense principale.
        let sel = match crate::rng::octets::<16>() {
            Ok(o) => (
                u64::from_le_bytes(o[..8].try_into().unwrap()),
                u64::from_le_bytes(o[8..].try_into().unwrap()),
            ),
            Err(_) => (0x5171_2953_5f43_4152, 0x4e45_545f_5145_3231),
        };
        AddrBook::new_avec_sel(autoriser_local, sel)
    }

    /// Carnet a sel impose : rend la selection reproductible pour les epreuves.
    pub fn new_avec_sel(autoriser_local: bool, sel: (u64, u64)) -> AddrBook {
        AddrBook {
            groupes: HashMap::new(),
            local: autoriser_local,
            sel,
        }
    }

    /// Rang d'une adresse dans l'ordre secret de ce noeud.
    fn rang(&self, a: &NetAddr) -> u64 {
        let mut brut = [0u8; 6];
        brut[..4].copy_from_slice(&a.ip);
        brut[4..].copy_from_slice(&a.port.to_le_bytes());
        crate::siphash::siphash24(self.sel.0, self.sel.1, &brut)
    }

    /// Un groupe dont aucune adresse n'a jamais repondu.
    ///
    /// C'est la matiere premiere d'une eclipse : un adversaire peut annoncer
    /// autant de groupes qu'il veut, mais il ne peut pas faire repondre une
    /// machine qui n'existe pas.
    fn groupe_jamais_eprouve(v: &[Entree]) -> bool {
        v.iter().all(|e| e.dernier_succes == 0)
    }

    pub fn len(&self) -> usize {
        self.groupes.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn groupes(&self) -> usize {
        self.groupes.len()
    }

    /// Ajoute ou rafraichit une adresse.
    ///
    /// Rend `false` si l'adresse est refusee : non routable, port nul, ou groupe
    /// deja plein sans candidat plus ancien a remplacer.
    pub fn ajouter(&mut self, a: NetAddr, maintenant: u64) -> bool {
        if a.port == 0 || !routable(a.ip, self.local) {
            return false;
        }
        // Un horodatage annonce ne peut pas etre dans le futur.
        let mut a = a;
        a.last_seen = a.last_seen.min(maintenant.saturating_add(TOLERANCE_FUTUR));
        let g = groupe(a.ip);

        if let Some(v) = self.groupes.get_mut(&g) {
            if let Some(e) = v
                .iter_mut()
                .find(|e| e.addr.ip == a.ip && e.addr.port == a.port)
            {
                e.addr.last_seen = e.addr.last_seen.max(a.last_seen);
                return true;
            }
            if v.len() >= MAX_PAR_GROUPE {
                // Le groupe est plein : la nouvelle adresse ne prend la place
                // que d'une plus ancienne. Un adversaire qui inonde une plage
                // ne fait donc que remplacer ses propres adresses.
                let (pos, plus_vieille) = v
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.addr.last_seen)
                    .map(|(i, e)| (i, e.addr.last_seen))
                    .expect("groupe non vide");
                if a.last_seen <= plus_vieille {
                    return false;
                }
                v[pos] = Entree {
                    addr: a,
                    echecs: 0,
                    dernier_succes: 0,
                };
                return true;
            }
            v.push(Entree {
                addr: a,
                echecs: 0,
                dernier_succes: 0,
            });
            return true;
        }

        if self.groupes.len() >= MAX_GROUPES {
            // --- Le plafond de groupes ne doit pas devenir un verrou.
            //
            // Un audit a rempli les 512 groupes avec des adresses a lui. Plus
            // aucune adresse honnete ne pouvait entrer : le carnet etait
            // definitivement fige sur la vision de l'attaquant, et la selection
            // ne rendait plus que ses adresses. C'est une eclipse complete,
            // obtenue sans posseder une seule machine joignable.
            //
            // Un groupe dont **aucune** adresse n'a jamais repondu n'a rien
            // prouve. Il cede la place. Un groupe qui contient un pair avec
            // lequel ce noeud a reellement parle est conserve : celui-la a paye
            // le prix d'une machine qui existe.
            let victime = self
                .groupes
                .iter()
                .filter(|(_, v)| Self::groupe_jamais_eprouve(v))
                .min_by_key(|(g, v)| {
                    let fraicheur = v.iter().map(|e| e.addr.last_seen).max().unwrap_or(0);
                    (fraicheur, **g)
                })
                .map(|(g, _)| *g);
            match victime {
                Some(g) => {
                    self.groupes.remove(&g);
                }
                // Tous les groupes contiennent un pair eprouve : le carnet est
                // plein de vrais pairs, et il n'y a rien a gagner a en chasser un.
                None => return false,
            }
        }
        self.groupes.insert(
            g,
            vec![Entree {
                addr: a,
                echecs: 0,
                dernier_succes: 0,
            }],
        );
        true
    }

    pub fn marquer_succes(&mut self, ip: [u8; 4], port: u16, maintenant: u64) {
        if let Some(e) = self.chercher(ip, port) {
            e.echecs = 0;
            e.dernier_succes = maintenant;
            e.addr.last_seen = maintenant;
        }
    }

    pub fn marquer_echec(&mut self, ip: [u8; 4], port: u16) {
        if let Some(e) = self.chercher(ip, port) {
            e.echecs = e.echecs.saturating_add(1);
        }
    }

    fn chercher(&mut self, ip: [u8; 4], port: u16) -> Option<&mut Entree> {
        self.groupes
            .get_mut(&groupe(ip))?
            .iter_mut()
            .find(|e| e.addr.ip == ip && e.addr.port == port)
    }

    /// Choisit jusqu'a `combien` adresses a essayer, **toutes de groupes
    /// distincts** et differentes de celles deja connectees.
    ///
    /// C'est ici que se joue la defense : peu importe combien d'adresses un
    /// adversaire a reussi a inserer, il ne peut occuper qu'une place par
    /// groupe qu'il possede reellement.
    pub fn selectionner(&self, combien: usize, deja: &[[u8; 4]], maintenant: u64) -> Vec<NetAddr> {
        let mut interdits: HashSet<[u8; 2]> = deja.iter().map(|ip| groupe(*ip)).collect();
        let connectes: HashSet<[u8; 4]> = deja.iter().copied().collect();

        // Un ordre stable et sans horloge : par groupe, puis par qualite.
        let mut candidats: Vec<(&[u8; 2], &Entree)> = Vec::new();
        for (g, v) in &self.groupes {
            if interdits.contains(g) {
                continue;
            }
            // Le meilleur representant du groupe : le moins d'echecs, puis le
            // plus recemment vu.
            if let Some(e) = v
                .iter()
                .filter(|e| !connectes.contains(&e.addr.ip))
                .min_by_key(|e| (e.echecs, u64::MAX - e.dernier_succes, self.rang(&e.addr)))
            {
                candidats.push((g, e));
            }
        }

        // L'ordre ne doit rien devoir a une valeur que l'adversaire ecrit.
        //
        // Il reposait sur `last_seen`, un champ annonce par le pair lui-meme :
        // il suffisait de le mettre au maximum pour passer devant tout le monde,
        // indefiniment. On garde ce qui est **constate par ce noeud** — les
        // echecs, les succes, l'age au-dela de trente jours — et on tranche le
        // reste par le sel local, imprevisible de l'exterieur.
        candidats.sort_by_key(|(g, e)| {
            let perimee = u8::from(maintenant.saturating_sub(e.addr.last_seen) > AGE_MAX);
            let jamais_eprouve = u8::from(e.dernier_succes == 0);
            (perimee, e.echecs, jamais_eprouve, self.rang(&e.addr), **g)
        });

        let mut sortie = Vec::new();
        for (g, e) in candidats {
            if sortie.len() >= combien {
                break;
            }
            if interdits.insert(*g) {
                sortie.push(e.addr);
            }
        }
        sortie
    }

    /// Adresses a annoncer a un pair qui demande `getaddr`.
    ///
    /// Reparties sur les groupes, pour ne pas propager la vision biaisee d'un
    /// carnet qu'un adversaire aurait partiellement rempli.
    pub fn a_annoncer(&self, combien: usize) -> Vec<NetAddr> {
        let mut v: Vec<NetAddr> = Vec::new();
        let mut groupes: Vec<&[u8; 2]> = self.groupes.keys().collect();
        groupes.sort();
        let mut rang = 0;
        while v.len() < combien {
            let mut ajoute = false;
            for g in &groupes {
                if let Some(e) = self.groupes[*g].get(rang) {
                    v.push(e.addr);
                    ajoute = true;
                    if v.len() >= combien {
                        break;
                    }
                }
            }
            if !ajoute {
                break;
            }
            rang += 1;
        }
        v
    }

    pub fn toutes(&self) -> Vec<Entree> {
        let mut v: Vec<Entree> = self.groupes.values().flatten().copied().collect();
        v.sort_by_key(|e| (e.addr.ip, e.addr.port));
        v
    }
}

/// Carnet persiste sur disque.
pub struct AddrStore {
    chemin: PathBuf,
}

impl AddrStore {
    pub fn new<P: AsRef<Path>>(chemin: P) -> AddrStore {
        AddrStore {
            chemin: chemin.as_ref().to_path_buf(),
        }
    }

    pub fn exists(&self) -> bool {
        self.chemin.exists()
    }

    pub fn save(&self, book: &AddrBook) -> std::io::Result<()> {
        self.save_entrees(&book.toutes())
    }

    /// Ecrit des entrees telles quelles.
    ///
    /// Le binaire reconstruisait un carnet neuf a partir des seules adresses
    /// avant d'ecrire : les compteurs d'echec et, surtout, la date du dernier
    /// succes repartaient a zero **a chaque arret**. Un noeud oubliait donc a
    /// chaque redemarrage quels pairs lui avaient reellement repondu — c'est-a-
    /// dire exactement ce qui distingue un pair reel d'une adresse annoncee.
    pub fn save_entrees(&self, entrees: &[Entree]) -> std::io::Result<()> {
        let mut w = Writer::with_capacity(32 + entrees.len() * 24);
        w.bytes(MAGIE);
        w.u32(VERSION);
        w.varint(entrees.len() as u64);
        for e in entrees {
            w.bytes(&e.addr.ip);
            w.u32(u32::from(e.addr.port));
            w.u64(e.addr.last_seen);
            w.u32(e.echecs);
            w.u64(e.dernier_succes);
        }
        let mut donnees = w.finish();
        donnees.extend_from_slice(&sha256(&donnees));

        let tmp = self.chemin.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&donnees)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.chemin)
    }

    /// Recharge le carnet. Un fichier corrompu rend un carnet vide, jamais une
    /// erreur fatale : on repart de l'amorcage.
    /// Relit le carnet.
    ///
    /// `maintenant` sert a borner les horodatages : un carnet venu d'ailleurs
    /// pourrait annoncer des adresses « vues » et « eprouvees » dans le futur,
    /// ce qui les rendrait a la fois inevincables et prioritaires. Ce sont des
    /// declarations d'un fichier, pas des constats de ce noeud.
    pub fn load(&self, autoriser_local: bool, maintenant: u64) -> AddrBook {
        let mut book = AddrBook::new(autoriser_local);
        let Ok(donnees) = std::fs::read(&self.chemin) else {
            return book;
        };
        if donnees.len() < 32 {
            return book;
        }
        let (charge, somme) = donnees.split_at(donnees.len() - 32);
        if sha256(charge) != somme {
            return book;
        }
        let mut r = Reader::new(charge);
        let mut magie = [0u8; 8];
        for o in &mut magie {
            match r.u8() {
                Ok(v) => *o = v,
                Err(_) => return book,
            }
        }
        if &magie != MAGIE || r.u32().ok() != Some(VERSION) {
            return book;
        }
        let Ok(n) = r.varint() else { return book };
        for _ in 0..n.min(1_000_000) {
            let (Ok(a), Ok(b), Ok(c), Ok(d)) = (r.u8(), r.u8(), r.u8(), r.u8()) else {
                break;
            };
            let (Ok(port), Ok(last_seen), Ok(echecs), Ok(succes)) =
                (r.u32(), r.u64(), r.u32(), r.u64())
            else {
                break;
            };
            let addr = NetAddr {
                ip: [a, b, c, d],
                port: port as u16,
                last_seen,
            };
            if book.ajouter(addr, maintenant) {
                if let Some(e) = book.chercher(addr.ip, addr.port) {
                    e.echecs = echecs;
                    // Un succes ne peut pas avoir eu lieu dans le futur.
                    e.dernier_succes = succes.min(maintenant);
                }
            }
        }
        book
    }
}

#[cfg(test)]
mod tests {
    /// Horloge de reference des epreuves : bien au-dela des horodatages
    /// employes ci-dessous, pour qu'aucun ne soit borne par megarde.
    const MAINTENANT: u64 = 2_000_000_000;

    use super::*;

    fn a(ip: [u8; 4], port: u16, vu: u64) -> NetAddr {
        NetAddr {
            ip,
            port,
            last_seen: vu,
        }
    }

    #[test]
    fn les_plages_privees_sont_refusees_sur_un_reseau_public() {
        let mut b = AddrBook::new(false);
        for ip in [
            [127, 0, 0, 1],
            [10, 0, 0, 5],
            [192, 168, 1, 1],
            [172, 20, 0, 1],
            [169, 254, 1, 1],
            [100, 70, 0, 1],
            [0, 0, 0, 0],
            [239, 1, 1, 1],
        ] {
            assert!(
                !b.ajouter(a(ip, 21021, 100), MAINTENANT),
                "{ip:?} aurait du etre refusee"
            );
        }
        assert!(b.ajouter(a([93, 184, 216, 34], 21021, 100), MAINTENANT));
    }

    #[test]
    fn le_bouclage_reste_utilisable_sur_un_reseau_de_test() {
        let mut b = AddrBook::new(true);
        assert!(b.ajouter(a([127, 0, 0, 1], 21021, 100), MAINTENANT));
    }

    #[test]
    fn un_port_nul_est_refuse() {
        let mut b = AddrBook::new(true);
        assert!(!b.ajouter(a([127, 0, 0, 1], 0, 100), MAINTENANT));
    }

    /// Le coeur de la defense : inonder une plage n'achete presque rien.
    #[test]
    fn inonder_un_groupe_ne_donne_qu_une_place() {
        let mut b = AddrBook::new(false);

        // L'adversaire insere dix mille adresses, toutes dans 203.0.x.x.
        for i in 0..10_000u32 {
            let ip = [203, 0, (i >> 8) as u8, i as u8];
            b.ajouter(a(ip, 21021, 1_000 + u64::from(i)), MAINTENANT);
        }
        assert!(
            b.len() <= MAX_PAR_GROUPE,
            "{} adresses retenues pour un seul groupe",
            b.len()
        );

        // Quatre pairs honnetes, dans quatre plages distinctes.
        for (i, ip) in [
            [93, 184, 216, 34],
            [8, 8, 8, 8],
            [1, 1, 1, 1],
            [198, 51, 100, 7],
        ]
        .into_iter()
        .enumerate()
        {
            b.ajouter(a(ip, 21021, 900 + i as u64), MAINTENANT);
        }

        let choix = b.selectionner(8, &[], 2_000);
        let de_l_adversaire = choix.iter().filter(|x| x.ip[0] == 203).count();
        assert_eq!(
            de_l_adversaire, 1,
            "dix mille adresses n'ont droit qu'a une seule place : {choix:?}"
        );
        assert_eq!(
            choix.len(),
            5,
            "les quatre honnetes plus une de l'attaquant"
        );
    }

    #[test]
    fn la_selection_ne_rend_jamais_deux_fois_le_meme_groupe() {
        let mut b = AddrBook::new(false);
        for i in 0..40u8 {
            for j in 0..5u8 {
                b.ajouter(a([50 + i, 10, j, 1], 21021, 100 + u64::from(j)), MAINTENANT);
            }
        }
        let choix = b.selectionner(20, &[], 200);
        let groupes: HashSet<[u8; 2]> = choix.iter().map(|x| groupe(x.ip)).collect();
        assert_eq!(groupes.len(), choix.len(), "un groupe est apparu deux fois");
    }

    /// Un groupe deja represente parmi les pairs connectes est exclu : c'est ce
    /// qui empeche un adversaire de finir par occuper toutes les places.
    #[test]
    fn un_groupe_deja_connecte_est_exclu() {
        let mut b = AddrBook::new(false);
        b.ajouter(a([93, 184, 216, 34], 21021, 100), MAINTENANT);
        b.ajouter(a([93, 184, 9, 9], 21021, 100), MAINTENANT);
        b.ajouter(a([8, 8, 8, 8], 21021, 100), MAINTENANT);

        let choix = b.selectionner(5, &[[93, 184, 216, 34]], 200);
        assert_eq!(choix.len(), 1);
        assert_eq!(choix[0].ip, [8, 8, 8, 8]);
    }

    #[test]
    fn les_echecs_repoussent_une_adresse_sans_l_effacer() {
        let mut b = AddrBook::new(false);
        b.ajouter(a([93, 184, 216, 34], 21021, 100), MAINTENANT);
        b.ajouter(a([93, 184, 216, 35], 21021, 100), MAINTENANT);
        b.marquer_echec([93, 184, 216, 34], 21021);

        let choix = b.selectionner(1, &[], 200);
        assert_eq!(
            choix[0].ip,
            [93, 184, 216, 35],
            "l'adresse saine passe devant"
        );
        assert_eq!(b.len(), 2, "et l'autre reste dans le carnet");
    }

    #[test]
    fn le_nombre_de_groupes_est_borne() {
        let mut b = AddrBook::new(false);
        for i in 0..2_000u32 {
            let ip = [1 + (i / 256) as u8 % 200, (i % 256) as u8, 1, 1];
            b.ajouter(a(ip, 21021, 100), MAINTENANT);
        }
        assert!(b.groupes() <= MAX_GROUPES);
    }

    #[test]
    fn l_annonce_repartit_sur_les_groupes() {
        let mut b = AddrBook::new(false);
        for g in 0..10u8 {
            for k in 0..20u8 {
                b.ajouter(a([100 + g, 1, k, 1], 21021, 100), MAINTENANT);
            }
        }
        let v = b.a_annoncer(10);
        let groupes: HashSet<[u8; 2]> = v.iter().map(|x| groupe(x.ip)).collect();
        assert_eq!(groupes.len(), 10, "l'annonce doit couvrir tous les groupes");
    }

    #[test]
    fn aller_retour_sur_le_disque() {
        let mut p = std::env::temp_dir();
        p.push(format!("q21-peers-{}.dat", std::process::id()));
        let _ = std::fs::remove_file(&p);

        let mut b = AddrBook::new(false);
        for i in 0..30u8 {
            b.ajouter(
                a([50 + i, 10, 1, 1], 21021, 1_000 + u64::from(i)),
                MAINTENANT,
            );
        }
        b.marquer_succes([50, 10, 1, 1], 21021, 4_242);
        b.marquer_echec([51, 10, 1, 1], 21021);

        let s = AddrStore::new(&p);
        s.save(&b).unwrap();
        let relu = s.load(false, MAINTENANT);

        assert_eq!(relu.len(), b.len());
        assert_eq!(relu.toutes(), b.toutes());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn un_carnet_corrompu_se_lit_comme_vide() {
        let mut p = std::env::temp_dir();
        p.push(format!("q21-peers-corrompu-{}.dat", std::process::id()));
        std::fs::write(&p, b"n'importe quoi").unwrap();
        assert!(AddrStore::new(&p).load(false, MAINTENANT).is_empty());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn une_adresse_reannoncee_ne_se_duplique_pas() {
        let mut b = AddrBook::new(false);
        assert!(b.ajouter(a([93, 184, 216, 34], 21021, 100), MAINTENANT));
        assert!(b.ajouter(a([93, 184, 216, 34], 21021, 500), MAINTENANT));
        assert_eq!(b.len(), 1);
        assert_eq!(b.toutes()[0].addr.last_seen, 500);
    }
}
