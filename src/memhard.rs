//! Preuve de travail memory-hard a deux niveaux, table croissante.
//!
//! C'est le levier A de la section 5 du livre blanc, et la seule partie du
//! protocole qui decide si Q21 sera minable par des gens ou par des fonderies.
//!
//! # Ce que la phase 6 a corrige
//!
//! La conception initiale derivait chaque element de table par un condensat
//! independant, `element(i) = H(graine, i)`. Sur la vraie table de 2 Gio, le
//! banc a rendu son verdict :
//!
//! ```text
//! fraction detenue   memoire      cout relatif d'une tentative
//!        1/1         2048 Mio          1,00 x
//!        1/2         1024 Mio          1,98 x
//!        1/8          256 Mio          2,85 x
//!        0/1            0 Mio          2,86 x
//! ```
//!
//! Deux lectures, toutes deux mauvaises. D'abord, se passer **entierement** de
//! memoire ne coutait que 2,86 x : un circuit dedie dont le condensat est trois
//! fois plus rapide qu'un processeur avait interet a n'embarquer aucune DRAM —
//! et un circuit SHA-256 depasse un processeur d'un facteur ~10^8. Ensuite, la
//! courbe s'aplatissait des 256 Mio : au-dela, acheter de la memoire n'achetait
//! plus rien. La propriete anti-ASIC etait fausse, et seule la mesure sur la
//! vraie taille l'a montre — sur 32 Mio, tout tenait en cache et le rapport
//! affichait un rassurant 6,46 x.
//!
//! # La structure a deux niveaux
//!
//! La correction reprend celle d'Ethash.
//!
//! - **Niveau 1, le cache** ([`PowCache`]) : `N / POW_CACHE_RATIO` elements,
//!   soit 64 Mio sur le reseau principal. Genere **en chaine** — l'element `i`
//!   depend de `i-1` — puis melange [`POW_CACHE_ROUNDS`] fois. On ne peut pas en
//!   reconstruire un fragment sans reconstruire tout ce qui precede.
//! - **Niveau 2, la table** ([`PowTable`]) : `N` elements, 2 Gio. Chaque element
//!   se calcule par [`POW_J`] acces aleatoires **dependants** au cache.
//!
//! Miner sans la table ne fait donc plus economiser de la memoire : cela
//! multiplie par [`POW_J`] le nombre d'acces, donc la bande passante — la seule
//! ressource qu'un circuit ne peut pas fabriquer avec du silicium.
//!
//! # Le prix, dit franchement
//!
//! Un noeud qui verifie devait auparavant **zero** octet. Il doit desormais
//! detenir le cache : 64 Mio. C'est le cout exact de la correction, et c'est le
//! meme compromis qu'a fait Ethereum. Verifier un bloc passe de ~45 us a
//! ~660 us ; rattraper dix ans de chaine coute une demi-heure de calcul de
//! preuve de travail, soit moins que la verification des signatures ML-DSA de la
//! meme periode.
//!
//! Un mineur, lui, detient toujours 2 Gio, et reconstruit sa table une fois par
//! epoque — environ 71 jours.
//!
//! # La table grandit
//!
//! Sa taille croit de [`POW_TABLE_GROWTH_PCT`] a chaque epoque. Un circuit concu
//! autour d'une quantite de memoire fixe devient mediocre des que la table la
//! depasse, et le materiel dedie se perime donc tout seul. Monero a du s'infliger
//! quatre ruptures de chaine defensives entre 2018 et 2019 pour obtenir le meme
//! effet a la main ; on prefere l'automatiser.
//!
//! # Ce que la revue de septembre 2026 a corrige
//!
//! La boucle de melange derivait l'indice de la prochaine lecture des **32
//! bits de poids faible** de l'accumulateur, et l'accumulation etait une
//! addition dont la retenue ne remonte jamais dans ces bits. Tout le parcours
//! — les [`POW_K`] lectures — ne dependait donc que d'un mot de 32 bits, quel
//! que soit le reste de l'etat. Une table de 2^32 entrees (128 Gio), calculee
//! une fois par epoque, remplacait les 32 lectures dependantes par une seule :
//! un gain de bande passante x32 pour une machine a memoire HBM, et une
//! croissance de la table devenue sans effet, puisque l'etat restait sur 32
//! bits quelle que soit sa taille. La faiblesse etait mathematique, pas
//! statistique : deux etats qui ne different que par leurs 224 bits hauts
//! parcouraient exactement les memes adresses.
//!
//! L'indice se derive desormais d'un melange des **quatre** mots de l'etat, et
//! chaque lecture est suivie d'une diffusion sur toute la largeur — quatre
//! tours de Feistel batis sur la finalisation de SplitMix64. Apres une seule
//! iteration, chaque bit de l'etat depend de chaque bit de la lecture et de
//! l'etat precedent ; il n'existe plus de sous-etat court dont le parcours
//! dependrait. Le cout est d'une dizaine de nanosecondes, contre une centaine
//! pour l'acces a la DRAM qu'il suit : la memoire reste le goulot, ce qui est
//! tout l'objet. La meme correction s'applique a la generation des elements
//! depuis le cache.
//!
//! # Avertissement que ce fichier se doit de porter
//!
//! Concevoir une fonction de preuve de travail est un exercice ou l'on se trompe
//! facilement et durablement — ce fichier en est deja la preuve deux fois. La
//! construction actuelle **n'a recu aucune cryptanalyse externe**. Les mesures
//! qu'elle affiche ont ete faites par son auteur, sur une seule machine, contre
//! une implementation de reference et non contre une implementation optimisee
//! par quelqu'un dont le metier est de la battre. Tant que cette relecture
//! n'existe pas, la propriete anti-ASIC reste une hypothese etayee, pas un
//! acquis.

use crate::block::BlockHeader;
use crate::consensus::*;
use crate::hash::{tagged_hash_parts, Hash256};
use crate::uint::U256;

const TAG_EPOCH: &str = "Q21/pow/epoch";
const TAG_ELEM: &str = "Q21/pow/elem";
const TAG_SEED: &str = "Q21/pow/seed";
const TAG_FINAL: &str = "Q21/pow/final";
const TAG_CACHE_SEED: &str = "Q21/pow/cache/seed";
const TAG_CACHE: &str = "Q21/pow/cache";
const TAG_CACHE_MIX: &str = "Q21/pow/cache/mix";
const TAG_ELEM_FINAL: &str = "Q21/pow/elem/final";

/// Parametres de table pour un reseau donne.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableParams {
    pub n0: u32,
    pub nmax: u32,
}

impl TableParams {
    pub const fn for_network(network: crate::address::Network) -> TableParams {
        match network {
            crate::address::Network::Mainnet => TableParams {
                n0: POW_TABLE_N0_MAINNET,
                nmax: POW_TABLE_NMAX_MAINNET,
            },
            crate::address::Network::Testnet => TableParams {
                n0: POW_TABLE_N0_TESTNET,
                nmax: POW_TABLE_NMAX_TESTNET,
            },
            crate::address::Network::Regtest => TableParams {
                n0: POW_TABLE_N0_REGTEST,
                nmax: POW_TABLE_NMAX_REGTEST,
            },
        }
    }
}

/// Epoque de preuve de travail correspondant a une hauteur.
pub const fn epoch_of(height: u64) -> u64 {
    height / POW_EPOCH_BLOCKS
}

/// Nombre d'elements de la table a une epoque donnee.
pub fn table_size(params: TableParams, epoch: u64) -> u32 {
    let mut n = params.n0 as u64;
    let max = params.nmax as u64;
    for _ in 0..epoch {
        n = n * (100 + POW_TABLE_GROWTH_PCT) / 100;
        if n >= max {
            return params.nmax;
        }
    }
    n as u32
}

/// Graine d'une epoque. Change tous les [`POW_EPOCH_BLOCKS`] blocs.
pub fn epoch_seed(epoch: u64) -> Hash256 {
    tagged_hash_parts(TAG_EPOCH, &[&epoch.to_le_bytes()])
}

/// Nombre d'elements du cache a une epoque donnee.
pub fn cache_size(params: TableParams, epoch: u64) -> u32 {
    (table_size(params, epoch) / POW_CACHE_RATIO).max(1)
}

// ---------------------------------------------------------------------------
// Niveau 1 : le cache
// ---------------------------------------------------------------------------

/// Cache d'une epoque : le niveau 1 de la preuve de travail.
///
/// # Ce qu'il corrige
///
/// La premiere conception derivait chaque element de table par un condensat
/// independant : `element(i) = H(graine, i)`. C'etait elegant, et faux. Le banc
/// de la phase 6, sur la vraie table de 2 Gio, a mesure que se passer
/// entierement de memoire ne coutait que **2,86 x** — et qu'au-dela de 256 Mio,
/// la memoire n'achetait plus rien. Un circuit dedie n'avait donc aucune raison
/// d'embarquer de la DRAM.
///
/// Ici, un element de table ne se calcule qu'en parcourant ce cache
/// [`POW_J`] fois, en acces aleatoires **sequentiellement dependants**. Refuser
/// la table ne fait plus economiser de la memoire : cela multiplie par
/// [`POW_J`] le nombre d'acces — donc la bande passante, la seule ressource
/// qu'un circuit ne peut pas fabriquer avec du silicium.
///
/// # Ce que cela coute honnetement
///
/// Un noeud qui verifie doit desormais detenir ce cache : 64 Mio sur le reseau
/// principal, au lieu de zero. C'est le prix exact de la correction, et c'est le
/// meme compromis qu'a fait Ethereum avec Ethash. Un mineur, lui, detient
/// toujours 2 Gio.
pub struct PowCache {
    epoch: u64,
    c: u32,
    seed: Hash256,
    data: Vec<u8>,
}

impl PowCache {
    /// Construit le cache d'une epoque.
    ///
    /// La generation est **sequentielle** : l'element `i` derive de l'element
    /// `i-1`, puis [`POW_CACHE_ROUNDS`] passes de melange lient chaque element a
    /// un autre tire au hasard. On ne peut donc pas reconstruire un fragment de
    /// cache sans reconstruire tout ce qui le precede.
    pub fn build(params: TableParams, epoch: u64) -> PowCache {
        let c = cache_size(params, epoch);
        let seed = epoch_seed(epoch);
        let mut data = vec![0u8; c as usize * POW_ELEMENT_SIZE];

        // Chaine initiale.
        let mut courant = tagged_hash_parts(TAG_CACHE_SEED, &[seed.as_bytes()]);
        data[0..POW_ELEMENT_SIZE].copy_from_slice(courant.as_bytes());
        for i in 1..c as usize {
            courant = tagged_hash_parts(TAG_CACHE, &[courant.as_bytes()]);
            data[i * POW_ELEMENT_SIZE..(i + 1) * POW_ELEMENT_SIZE]
                .copy_from_slice(courant.as_bytes());
        }

        // Passes de melange : chaque element depend du precedent et d'un autre
        // element designe par son propre contenu.
        let mut xor = [0u8; POW_ELEMENT_SIZE];
        for _ in 0..POW_CACHE_ROUNDS {
            for i in 0..c as usize {
                let prec = if i == 0 { c as usize - 1 } else { i - 1 };
                let mut j = {
                    let d = &data[i * POW_ELEMENT_SIZE..i * POW_ELEMENT_SIZE + 4];
                    (u32::from_le_bytes([d[0], d[1], d[2], d[3]]) % c) as usize
                };
                // Si l'element tire est le precedent lui-meme, le XOR ci-dessous
                // s'annulerait et l'element deviendrait une constante — H(0) pour
                // ce tag — au lieu de dependre du cache. Perte d'entropie dans la
                // structure meme que les verificateurs detiennent (red-team 8b).
                // On decale alors d'un cran : les deux termes melanges restent
                // deux elements distincts, donc le XOR n'est jamais nul. Seules
                // les cases degenerees (environ une sur `c`) changent ; toutes les
                // autres gardent exactement leur valeur.
                if j == prec && c > 1 {
                    j = (prec + 1) % c as usize;
                }
                for k in 0..POW_ELEMENT_SIZE {
                    xor[k] = data[prec * POW_ELEMENT_SIZE + k] ^ data[j * POW_ELEMENT_SIZE + k];
                }
                let h = tagged_hash_parts(TAG_CACHE_MIX, &[&xor]);
                data[i * POW_ELEMENT_SIZE..(i + 1) * POW_ELEMENT_SIZE]
                    .copy_from_slice(h.as_bytes());
            }
        }

        PowCache {
            epoch,
            c,
            seed,
            data,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn len(&self) -> u32 {
        self.c
    }

    pub fn is_empty(&self) -> bool {
        self.c == 0
    }

    pub fn memory_bytes(&self) -> usize {
        self.data.len()
    }

    #[inline]
    fn lire(&self, i: u32) -> U256 {
        let debut = i as usize * POW_ELEMENT_SIZE;
        let mut b = [0u8; POW_ELEMENT_SIZE];
        b.copy_from_slice(&self.data[debut..debut + POW_ELEMENT_SIZE]);
        U256::from_be_bytes(&b)
    }
}

/// Cache partage par tout le processus.
///
/// Construire le cache coute quelques secondes sur le reseau principal ; le
/// refaire par fil d'execution serait absurde, et en garder un par pair
/// serait ruineux. On en conserve au plus deux epoques : la courante et la
/// precedente, le temps qu'une transition d'epoque se termine.
type CachesPartages = std::sync::Mutex<Vec<(TableParams, u64, std::sync::Arc<PowCache>)>>;
static CACHES: std::sync::OnceLock<CachesPartages> = std::sync::OnceLock::new();

/// Rend le cache d'une epoque, en le construisant au besoin.
pub fn cache_for(params: TableParams, epoch: u64) -> std::sync::Arc<PowCache> {
    let m = CACHES.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, _, c)) = g.iter().find(|(p, e, _)| *p == params && *e == epoch) {
        return c.clone();
    }
    let c = std::sync::Arc::new(PowCache::build(params, epoch));
    g.push((params, epoch, c.clone()));
    // On ne garde que les deux dernieres entrees.
    while g.len() > 2 {
        g.remove(0);
    }
    c
}

// ---------------------------------------------------------------------------
// Niveau 2 : les elements de table
// ---------------------------------------------------------------------------

/// Calcule l'element d'indice `i` de la table, a partir du cache.
///
/// Cout : deux condensats et [`POW_J`] acces aleatoires **dependants** au
/// cache. C'est ce cout qui rend le refus de la table onereux.
#[inline]
pub fn element(cache: &PowCache, i: u32) -> Hash256 {
    let mut acc = U256::from_be_bytes(
        tagged_hash_parts(TAG_ELEM, &[cache.seed.as_bytes(), &i.to_le_bytes()]).as_bytes(),
    );
    for _ in 0..POW_J {
        let idx = index_from(&acc, cache.c);
        acc = absorber(acc, cache.lire(idx));
    }
    tagged_hash_parts(TAG_ELEM_FINAL, &[&acc.to_be_bytes()])
}

/// Table precalculee d'une epoque. Utile au mineur, inutile au validateur.
pub struct PowTable {
    epoch: u64,
    n: u32,
    /// Elements concatenes, `POW_ELEMENT_SIZE` octets chacun.
    data: Vec<u8>,
}

impl PowTable {
    /// Construit la table d'une epoque, en parallele sur tous les coeurs.
    ///
    /// Les elements sont independants les uns des autres une fois le cache
    /// construit : la construction se parallelise donc sans effort. C'est la
    /// seule etape de la conception ou le parallelisme est voulu.
    pub fn build(params: TableParams, epoch: u64) -> PowTable {
        let cache = cache_for(params, epoch);
        Self::build_avec_cache(&cache, params, epoch)
    }

    pub fn build_avec_cache(cache: &PowCache, params: TableParams, epoch: u64) -> PowTable {
        let n = table_size(params, epoch);
        let mut data = vec![0u8; n as usize * POW_ELEMENT_SIZE];

        let fils = std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(1)
            .max(1);
        let par_fil = (n as usize).div_ceil(fils).max(1);

        std::thread::scope(|s| {
            for (bloc, morceau) in data.chunks_mut(par_fil * POW_ELEMENT_SIZE).enumerate() {
                let cache = &*cache;
                s.spawn(move || {
                    let base = bloc * par_fil;
                    for k in 0..morceau.len() / POW_ELEMENT_SIZE {
                        let e = element(cache, (base + k) as u32);
                        morceau[k * POW_ELEMENT_SIZE..(k + 1) * POW_ELEMENT_SIZE]
                            .copy_from_slice(e.as_bytes());
                    }
                });
            }
        });

        PowTable { epoch, n, data }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn len(&self) -> u32 {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Occupation memoire, en octets.
    pub fn memory_bytes(&self) -> usize {
        self.data.len()
    }

    #[inline]
    fn get(&self, i: u32) -> &[u8] {
        let debut = i as usize * POW_ELEMENT_SIZE;
        &self.data[debut..debut + POW_ELEMENT_SIZE]
    }
}

/// Point de depart d'une tentative : condensat de l'en-tete complet, nonce inclus.
#[inline]
fn seed_of_header(header: &BlockHeader) -> Hash256 {
    tagged_hash_parts(TAG_SEED, &[&header.encode()])
}

/// Finalisation de SplitMix64 : une bijection de 64 bits ou chaque bit de
/// sortie depend de chaque bit d'entree. Trois decalages, deux multiplications.
#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Derive l'indice du prochain acces depuis l'accumulateur courant.
///
/// Cree la dependance sequentielle : impossible de savoir ou lire ensuite avant
/// d'avoir integre la lecture precedente.
///
/// Les **quatre** mots de l'etat entrent dans l'indice. La version qui ne
/// lisait que le mot bas rendait le parcours entier fonction de 32 bits — voir
/// la note de tete du module. Les bits de poids fort du melange sont retenus :
/// ce sont ceux que les multiplications ont le mieux brasses.
#[inline]
fn index_from(acc: &U256, n: u32) -> u32 {
    let m = mix64(
        acc.0[0] ^ acc.0[1].rotate_left(17) ^ acc.0[2].rotate_left(34) ^ acc.0[3].rotate_left(51),
    );
    ((m >> 32) as u32) % n
}

/// Integre une lecture a l'etat, puis diffuse sur toute la largeur.
///
/// L'addition modulo 2^256 conserve la chaine de retenues. Suivent quatre
/// tours de Feistel sur les quatre mots, deux mots modifies par tour a partir
/// de deux mots laisses intacts : chaque tour est une bijection par
/// construction, et les deux operations d'un tour sont independantes, donc
/// le processeur les execute de front. Apres le quatrieme tour, chaque mot de
/// sortie depend de chacun des quatre mots d'entree — c'est ce qui manquait.
/// L'etat reste uniformement distribue, et deux etats distincts ne peuvent
/// pas se rejoindre autrement que par une collision de la lecture elle-meme.
/// Une quinzaine de nanosecondes de latence, pour une lecture DRAM qui en
/// coute une centaine.
#[inline]
fn absorber(acc: U256, lecture: U256) -> U256 {
    let mut s = acc.wrapping_add(lecture).0;
    s[1] ^= mix64(s[0]);
    s[3] ^= mix64(s[2]);
    s[0] ^= mix64(s[3]);
    s[2] ^= mix64(s[1]);
    s[1] ^= mix64(s[0]);
    s[3] ^= mix64(s[2]);
    s[0] ^= mix64(s[1]);
    s[2] ^= mix64(s[3]);
    U256(s)
}

/// Boucle de melange.
///
/// # Pourquoi elle ne hache pas a chaque acces
///
/// La premiere version de ce fichier hachait a chaque iteration. Le banc de
/// mesure a rendu son verdict : **1,63 x** d'avantage seulement pour le mineur
/// disposant de la table. La raison invalide la conception : un condensat coute
/// a peu pres aussi cher qu'un acces aleatoire a la DRAM. Recalculer un element
/// au lieu de le lire ne coutait donc presque rien, et la memoire n'etait pas le
/// goulot d'etranglement — la promesse anti-ASIC etait vide.
///
/// La boucle ne fait qu'une addition modulo 2^256 et une diffusion de quelques
/// nanosecondes par acces ([`absorber`]). Le cout d'une iteration reste celui
/// de la lecture memoire, et presque rien d'autre.
///
/// Le condensat n'intervient plus qu'aux deux extremites, comme dans
/// Autolykos v2 : une fois pour derouler la graine, une fois pour produire la
/// valeur comparee a la cible.
#[inline]
fn melange(depart: Hash256, mut lire: impl FnMut(u32) -> U256, n: u32) -> Hash256 {
    let mut acc = U256::from_be_bytes(depart.as_bytes());
    for _ in 0..POW_K {
        let idx = index_from(&acc, n);
        acc = absorber(acc, lire(idx));
    }
    tagged_hash_parts(TAG_FINAL, &[&acc.to_be_bytes()])
}

/// Chemin de minage : lit la table precalculee.
pub fn hash_mining(header: &BlockHeader, table: &PowTable) -> Hash256 {
    let depart = seed_of_header(header);
    melange(
        depart,
        |i| {
            let mut b = [0u8; 32];
            b.copy_from_slice(table.get(i));
            U256::from_be_bytes(&b)
        },
        table.n,
    )
}

/// Mineur ne detenant qu'une **fraction** de la table.
///
/// # Pourquoi ce type existe
///
/// Comparer « table complete » a « aucune table » ne dit presque rien. Aucun
/// concepteur de circuit ne choisit l'un de ces deux extremes : il choisit la
/// quantite de memoire qui maximise son debit par euro depense. La question
/// pertinente est donc la **courbe** — combien coute une tentative quand on ne
/// detient qu'une fraction `f` de la table, en recalculant le reste ?
///
/// Les indices d'acces sont uniformes sur `[0, n)`. Conserver les `f * n`
/// premiers elements donne donc un taux de succes de `f`, quel que soit le
/// sous-ensemble reellement choisi par l'attaquant : aucun element n'est plus
/// utile qu'un autre.
///
/// Ce type n'appartient pas au consensus. Il n'existe que pour mesurer.
pub struct PartialTable {
    epoch: u64,
    n: u32,
    /// Nombre d'elements reellement stockes, parmi les `n`.
    stockes: u32,
    cache: std::sync::Arc<PowCache>,
    data: Vec<u8>,
}

impl PartialTable {
    /// Construit une table partielle detenant `num/den` des elements.
    ///
    /// `num = 0` modelise l'attaquant sans memoire, `num = den` le mineur
    /// pleinement equipe.
    pub fn build(params: TableParams, epoch: u64, num: u32, den: u32) -> PartialTable {
        assert!(den > 0 && num <= den, "fraction invalide : {num}/{den}");
        let n = table_size(params, epoch);
        let cache = cache_for(params, epoch);
        let stockes = ((n as u64 * num as u64) / den as u64) as u32;

        let mut data = vec![0u8; stockes as usize * POW_ELEMENT_SIZE];
        {
            let cache = &*cache;
            let fils = std::thread::available_parallelism()
                .map(|v| v.get())
                .unwrap_or(1)
                .max(1);
            let par_fil = (stockes as usize).div_ceil(fils).max(1);
            std::thread::scope(|s| {
                for (bloc, morceau) in data.chunks_mut(par_fil * POW_ELEMENT_SIZE).enumerate() {
                    s.spawn(move || {
                        let base = bloc * par_fil;
                        for k in 0..morceau.len() / POW_ELEMENT_SIZE {
                            let e = element(cache, (base + k) as u32);
                            morceau[k * POW_ELEMENT_SIZE..(k + 1) * POW_ELEMENT_SIZE]
                                .copy_from_slice(e.as_bytes());
                        }
                    });
                }
            });
        }
        PartialTable {
            epoch,
            n,
            stockes,
            cache,
            data,
        }
    }

    /// Reprend une table complete deja construite, sans la reconstruire.
    ///
    /// Le banc de mesure balaie plusieurs fractions ; reconstruire 2 Gio a
    /// chaque point couterait des heures pour rien.
    pub fn depuis_table(table: PowTable, cache: std::sync::Arc<PowCache>) -> PartialTable {
        PartialTable {
            epoch: table.epoch,
            n: table.n,
            stockes: table.n,
            cache,
            data: table.data,
        }
    }

    /// Reduit la part de table detenue, sans liberer ni reallouer.
    ///
    /// Les elements au-dela de la limite seront recalcules a la volee — c'est
    /// exactement le comportement d'un mineur qui aurait choisi moins de memoire.
    pub fn restreindre(&mut self, num: u32, den: u32) {
        assert!(den > 0 && num <= den, "fraction invalide : {num}/{den}");
        self.stockes = ((self.n as u64 * num as u64) / den as u64) as u32;
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn len(&self) -> u32 {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Elements effectivement conserves en memoire.
    pub fn stockes(&self) -> u32 {
        self.stockes
    }

    /// Memoire reellement exigee par la strategie, et non memoire allouee.
    pub fn memory_bytes(&self) -> usize {
        self.stockes as usize * POW_ELEMENT_SIZE
    }

    #[inline]
    fn lire(&self, i: u32) -> U256 {
        if i < self.stockes {
            let debut = i as usize * POW_ELEMENT_SIZE;
            let mut b = [0u8; 32];
            b.copy_from_slice(&self.data[debut..debut + POW_ELEMENT_SIZE]);
            U256::from_be_bytes(&b)
        } else {
            U256::from_be_bytes(element(&self.cache, i).as_bytes())
        }
    }
}

/// Tentative de minage avec une table partielle.
///
/// Rend exactement la meme valeur que [`hash_mining`] et [`hash_verify`] : la
/// strategie de l'attaquant change son cout, jamais son resultat. C'est
/// precisement ce qui rend l'attaque possible, et donc ce qu'il faut mesurer.
pub fn hash_mining_partial(header: &BlockHeader, table: &PartialTable) -> Hash256 {
    let depart = seed_of_header(header);
    melange(depart, |i| table.lire(i), table.n)
}

/// Chemin de verification : recalcule les [`POW_K`] elements necessaires.
///
/// Aucune table, aucune allocation notable. C'est ce que fait un noeud complet,
/// et c'est ce qui coute cher a un mineur qui voudrait s'en passer.
pub fn hash_verify(header: &BlockHeader, params: TableParams) -> Hash256 {
    let epoch = epoch_of(header.height);
    let cache = cache_for(params, epoch);
    hash_verify_avec_cache(header, params, &cache)
}

/// Variante pour qui detient deja le cache — c'est le cas d'un noeud en cours
/// de synchronisation, qui verifie des milliers de blocs de la meme epoque.
pub fn hash_verify_avec_cache(
    header: &BlockHeader,
    params: TableParams,
    cache: &PowCache,
) -> Hash256 {
    // Un cache d'une autre epoque donne un condensat different **en silence**.
    // Deux noeuds, l'un avec le bon cache et l'autre avec un cache perime,
    // rendraient deux verdicts opposes sur le meme bloc — une scission dont
    // personne ne verrait la cause. L'audit de la phase 8b l'a mesuree :
    // « hauteur 51200, cache e0 == cache e1 ? false ».
    //
    // On ne devine pas : si le cache ne correspond pas, on en construit un bon.
    let epoque = epoch_of(header.height);
    if cache.epoch() != epoque {
        return hash_verify(header, params);
    }
    let n = table_size(params, epoque);
    let depart = seed_of_header(header);
    melange(
        depart,
        |i| U256::from_be_bytes(element(cache, i).as_bytes()),
        n,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;

    fn params() -> TableParams {
        TableParams::for_network(Network::Regtest)
    }

    fn entete(nonce: u64, height: u64) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: Hash256::ZERO,
            merkle_root: Hash256([7u8; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([9u8; 32]),
            time: 1_755_000_000,
            bits: INITIAL_BITS,
            height,
            nonce,
        }
    }

    /// La propriete qui rend le protocole utilisable par des noeuds legers.
    #[test]
    fn les_deux_chemins_donnent_le_meme_resultat() {
        let p = params();
        let table = PowTable::build(p, 0);
        for nonce in 0..50u64 {
            let h = entete(nonce, 10);
            assert_eq!(
                hash_mining(&h, &table),
                hash_verify(&h, p),
                "divergence minage/verification au nonce {nonce}"
            );
        }
    }

    #[test]
    fn les_deux_chemins_concordent_sur_plusieurs_epoques() {
        let p = params();
        for epoch in 0..3u64 {
            let table = PowTable::build(p, epoch);
            let h = entete(42, epoch * POW_EPOCH_BLOCKS + 5);
            assert_eq!(hash_mining(&h, &table), hash_verify(&h, p));
        }
    }

    #[test]
    fn la_table_grandit_puis_plafonne() {
        let p = params();
        let t0 = table_size(p, 0);
        let t1 = table_size(p, 1);
        let t10 = table_size(p, 10);

        assert_eq!(t0, p.n0);
        assert!(t1 > t0, "la table doit grandir");
        assert!(t10 > t1);
        assert_eq!(
            table_size(p, 10_000),
            p.nmax,
            "la croissance doit finir par plafonner"
        );
    }

    #[test]
    fn la_croissance_est_bien_de_cinq_pour_cent() {
        let p = TableParams::for_network(Network::Mainnet);
        let attendu = (p.n0 as u64) * 105 / 100;
        assert_eq!(table_size(p, 1) as u64, attendu);
    }

    /// C'est ce test qui traduit la promesse anti-ASIC en propriete verifiable.
    #[test]
    fn changer_d_epoque_change_toute_la_table() {
        let p = params();
        let a = PowTable::build(p, 0);
        let b = PowTable::build(p, 1);
        // Meme les elements de meme indice different : la graine a change.
        assert_ne!(a.get(0), b.get(0));
        assert_ne!(a.get(5), b.get(5));
        assert!(b.len() > a.len(), "et la table a grandi");
    }

    #[test]
    fn un_nonce_different_donne_un_condensat_different() {
        let p = params();
        let table = PowTable::build(p, 0);
        let a = hash_mining(&entete(0, 1), &table);
        let b = hash_mining(&entete(1, 1), &table);
        assert_ne!(a, b);
    }

    #[test]
    fn la_hauteur_participe_au_condensat() {
        let p = params();
        // Deux hauteurs de la meme epoque : seule l'en-tete change.
        assert_ne!(hash_verify(&entete(0, 1), p), hash_verify(&entete(0, 2), p));
    }

    #[test]
    fn deux_reseaux_ne_partagent_pas_la_meme_difficulte_memoire() {
        let r = TableParams::for_network(Network::Regtest);
        let t = TableParams::for_network(Network::Testnet);
        let m = TableParams::for_network(Network::Mainnet);
        assert!(r.n0 < t.n0);
        assert!(t.n0 < m.n0);
    }

    #[test]
    fn la_table_du_reseau_principal_pese_bien_deux_gio() {
        let p = TableParams::for_network(Network::Mainnet);
        let octets = p.n0 as u64 * POW_ELEMENT_SIZE as u64;
        assert_eq!(octets, 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn l_occupation_memoire_est_celle_annoncee() {
        let p = params();
        let t = PowTable::build(p, 0);
        assert_eq!(t.memory_bytes(), t.len() as usize * POW_ELEMENT_SIZE);
        assert_eq!(t.memory_bytes(), 32 * 1024);
    }

    #[test]
    fn le_calcul_est_deterministe() {
        let p = params();
        let h = entete(123, 456);
        assert_eq!(hash_verify(&h, p), hash_verify(&h, p));
    }

    /// Verrouille la propriete qui justifie tout ce module.
    ///
    /// Ce test aurait attrape l'erreur de conception initiale. La premiere
    /// version hachait a chaque acces : le rapport tombait a 1,63 x, ce qui
    /// signifie qu'un mineur pouvait se passer de memoire pour presque rien —
    /// la promesse anti-ASIC etait vide. Avec un melange bon marche, le rapport
    /// remonte au-dela de 6 x.
    ///
    /// Le seuil est volontairement bas : la mesure varie selon la machine, et un
    /// test flaky serait pire qu'aucun test. Ce qu'il verrouille, c'est l'ordre
    /// de grandeur.
    #[test]
    fn se_passer_de_la_table_coute_significativement_plus_cher() {
        let p = params();
        let table = PowTable::build(p, 0);
        let n = 3_000u64;

        // Chauffe : sans cela, la premiere boucle paie les defauts de cache.
        for nonce in 0..200 {
            std::hint::black_box(hash_mining(&entete(nonce, 1), &table));
            std::hint::black_box(hash_verify(&entete(nonce, 1), p));
        }

        let t0 = std::time::Instant::now();
        for nonce in 0..n {
            std::hint::black_box(hash_mining(&entete(nonce, 1), &table));
        }
        let avec = t0.elapsed().as_secs_f64();

        let t1 = std::time::Instant::now();
        for nonce in 0..n {
            std::hint::black_box(hash_verify(&entete(nonce, 1), p));
        }
        let sans = t1.elapsed().as_secs_f64();

        let rapport = sans / avec.max(1e-9);
        assert!(
            rapport > 10.0,
            "miner sans table ne coute que {rapport:.2} x plus cher : la \
             derivation des elements est redevenue trop bon marche"
        );
    }

    /// La table partielle ne doit rien changer au resultat, quelle que soit la
    /// fraction detenue. Sans cette propriete, la mesure du compromis
    /// temps-memoire ne mesurerait pas la meme fonction.
    #[test]
    fn une_table_partielle_donne_le_meme_condensat() {
        let p = params();
        let complete = PowTable::build(p, 0);
        for (num, den) in [(0, 1), (1, 4), (1, 2), (3, 4), (1, 1)] {
            let partielle = PartialTable::build(p, 0, num, den);
            for nonce in 0..25u64 {
                let h = entete(nonce, 10);
                assert_eq!(
                    hash_mining_partial(&h, &partielle),
                    hash_mining(&h, &complete),
                    "divergence a {num}/{den}, nonce {nonce}"
                );
            }
        }
    }

    #[test]
    fn la_memoire_de_la_table_partielle_suit_la_fraction() {
        let p = params();
        let n = table_size(p, 0);
        assert_eq!(PartialTable::build(p, 0, 0, 4).stockes(), 0);
        assert_eq!(PartialTable::build(p, 0, 1, 4).stockes(), n / 4);
        assert_eq!(PartialTable::build(p, 0, 4, 4).stockes(), n);
        assert_eq!(
            PartialTable::build(p, 0, 1, 2).memory_bytes(),
            (n / 2) as usize * POW_ELEMENT_SIZE
        );
    }

    /// La propriete que la phase 6 a du reconstruire.
    ///
    /// Calculer un element de table doit couter bien plus cher que le lire.
    /// Dans la premiere conception, c'etait un seul condensat — et c'est
    /// exactement pour cela que se passer de memoire ne coutait que 2,86 x sur
    /// la vraie table de 2 Gio.
    #[test]
    fn calculer_un_element_coute_bien_plus_cher_que_le_lire() {
        let p = params();
        let table = PowTable::build(p, 0);
        let cache = cache_for(p, 0);
        let n = 20_000u32;

        for i in 0..1_000 {
            std::hint::black_box(element(&cache, i % table.len()));
        }

        let t0 = std::time::Instant::now();
        for i in 0..n {
            std::hint::black_box(element(&cache, i % table.len()));
        }
        let calcul = t0.elapsed().as_secs_f64() / f64::from(n);

        let t1 = std::time::Instant::now();
        for i in 0..n {
            std::hint::black_box(table.get(i % table.len()));
        }
        let lecture = t1.elapsed().as_secs_f64() / f64::from(n);

        let rapport = calcul / lecture.max(1e-12);
        assert!(
            rapport > 10.0,
            "recalculer un element ne coute que {rapport:.1} x sa lecture : \
             la derivation est trop bon marche et le compromis temps-memoire \
             redevient favorable a l'attaquant"
        );
    }

    /// Le parcours en memoire ne depend plus d'un sous-etat court.
    ///
    /// # Le defaut que cette epreuve fige
    ///
    /// L'indice de lecture venait des 32 bits bas de l'accumulateur, et
    /// l'addition n'y faisait jamais remonter de retenue : deux etats qui ne
    /// differaient que par leurs 224 bits hauts lisaient exactement les memes
    /// adresses, dans le meme ordre, et la somme des lectures etait la meme.
    /// Une table de 2^32 sommes (128 Gio) par epoque remplacait alors les
    /// trente-deux lectures dependantes par une seule.
    ///
    /// On rejoue mille paires d'etats de memes bits bas ; aucune ne doit
    /// partager son parcours.
    #[test]
    fn deux_etats_de_memes_bits_bas_ne_parcourent_pas_les_memes_adresses() {
        fn parcours(depart: U256, n: u32) -> Vec<u32> {
            let mut acc = depart;
            let mut v = Vec::with_capacity(POW_K);
            for _ in 0..POW_K {
                let idx = index_from(&acc, n);
                v.push(idx);
                // Une « table » synthetique : l'element ne depend que de son
                // indice, comme une vraie table.
                let lecture = U256::from_be_bytes(
                    tagged_hash_parts("Q21/test/elem", &[&idx.to_le_bytes()]).as_bytes(),
                );
                acc = absorber(acc, lecture);
            }
            v
        }
        let n = 1u32 << 26;
        let mut graine = 0x9E37_79B9_7F4A_7C15u64;
        let mut suivant = move || {
            graine = mix64(graine.wrapping_add(0x1234_5678_9ABC_DEF1));
            graine
        };
        let mut identiques = 0;
        for _ in 0..1000 {
            let bas = suivant() & 0xFFFF_FFFF;
            let a = U256([suivant() << 32 | bas, suivant(), suivant(), suivant()]);
            let b = U256([suivant() << 32 | bas, suivant(), suivant(), suivant()]);
            assert_eq!(
                a.0[0] as u32, b.0[0] as u32,
                "meme mot bas par construction"
            );
            if parcours(a, n) == parcours(b, n) {
                identiques += 1;
            }
        }
        assert_eq!(
            identiques, 0,
            "{identiques} paires sur 1000 partagent leur parcours : le parcours depend d'un \
             sous-etat court"
        );
    }

    /// Chaque bit de l'etat comme de la lecture se diffuse sur toute la largeur.
    ///
    /// Inverser un seul bit en entree de `absorber` doit changer environ la
    /// moitie des 256 bits de sortie — le critere d'avalanche. On l'exige entre
    /// un quart et trois quarts pour chacun des 512 bits d'entree, ce qui
    /// exclut toute lane independante : c'est exactement ce qui manquait.
    #[test]
    fn une_lecture_se_diffuse_sur_tout_l_etat() {
        fn poids(a: U256, b: U256) -> u32 {
            (0..4).map(|i| (a.0[i] ^ b.0[i]).count_ones()).sum()
        }
        let acc = U256([
            0x0123_4567_89AB_CDEF,
            0xFEDC_BA98_7654_3210,
            0x0F1E_2D3C_4B5A_6978,
            0x8796_A5B4_C3D2_E1F0,
        ]);
        let lecture = U256([
            0xDEAD_BEEF_CAFE_F00D,
            0x1357_9BDF_2468_ACE0,
            0x0000_0000_0000_0001,
            0xFFFF_FFFF_FFFF_FFFF,
        ]);
        let reference = absorber(acc, lecture);
        for bit in 0..512u32 {
            let (mut a, mut l) = (acc, lecture);
            if bit < 256 {
                a.0[(bit / 64) as usize] ^= 1u64 << (bit % 64);
            } else {
                let b = bit - 256;
                l.0[(b / 64) as usize] ^= 1u64 << (b % 64);
            }
            let p = poids(reference, absorber(a, l));
            assert!(
                (64..=192).contains(&p),
                "le bit {bit} ne change que {p} bits de sortie sur 256"
            );
        }
    }
}
