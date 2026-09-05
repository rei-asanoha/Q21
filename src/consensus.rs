//! Constantes de consensus.
//!
//! Tout ce qui suit definit la monnaie. Un seul de ces nombres qui change, et
//! deux noeuds ne sont plus sur la meme chaine. Ils vivent ici, dans un seul
//! fichier, pour qu'un auditeur puisse verifier l'integralite des regles
//! economiques sans lire le reste du code.
//!
//! Regle absolue : aucun flottant. Nulle part. Voir `emission`.

// ---------------------------------------------------------------------------
// Unites
// ---------------------------------------------------------------------------

/// Nombre de decimales de la monnaie.
pub const DECIMALS: u32 = 8;

/// Nombre d'unites indivisibles dans un Q21 entier.
pub const UNITS_PER_COIN: u64 = 100_000_000;

/// Plafond absolu, en Q21 entiers. Ce nombre est le projet.
pub const MAX_SUPPLY_COINS: u64 = 21_000_001;

/// Plafond absolu, en unites indivisibles.
///
/// 21_000_001 * 1e8 = 2.1e15, tres en dessous de u64::MAX (1.8e19).
pub const MAX_SUPPLY: u64 = MAX_SUPPLY_COINS * UNITS_PER_COIN;

/// La piece de genese : l'unite qui depasse les 21 000 000.
///
/// Frappee une seule fois dans le bloc 0, hors coinbase ordinaire. Elle ne
/// participe pas au calendrier d'emission.
pub const GENESIS_PREMINT: u64 = UNITS_PER_COIN;

/// Ce que le minage peut emettre au total, hors piece de genese.
pub const EMISSION_CAP: u64 = MAX_SUPPLY - GENESIS_PREMINT;

// ---------------------------------------------------------------------------
// Rythme
// ---------------------------------------------------------------------------

/// Intervalle de bloc vise, en secondes.
///
/// PROVISOIRE. Deux minutes divisent la variance par cinq par rapport a
/// Bitcoin, mais alourdissent le taux d'orphelins — d'autant plus que les
/// signatures ML-DSA pesent 47 fois une signature ECDSA. A confirmer par la
/// mesure sur reseau de test, pas par le raisonnement.
pub const TARGET_BLOCK_SECS: u64 = 120;

/// Blocs par an au rythme vise (525 600 minutes / 2).
pub const BLOCKS_PER_YEAR: u64 = 262_800;

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

/// Recompense initiale, en unites indivisibles : 13,82743055 Q21.
///
/// # Comment cette valeur a ete obtenue, et pourquoi la premiere etait fausse
///
/// La derivation naive part de la decroissance *continue* :
/// `R0 = CAP * ln(2) / demi_vie`, ce qui donne 13,847118 Q21. C'est faux ici.
///
/// Q21 ne decroit pas continument : la recompense reste **constante pendant
/// toute une epoque** de 4 320 blocs, puis chute d'un coup. Sur chaque epoque on
/// paie donc la valeur de debut d'epoque, superieure a la moyenne de la courbe
/// continue. C'est une somme de Riemann par la gauche, et elle surestime.
/// L'ecart parait negligeable — 0,14 % — mais il place la somme infinie
/// theorique a 21 029 899 Q21, soit **au-dessus du plafond**.
///
/// L'emission reelle serait quand meme restee sous les 21 millions, parce que
/// l'arrondi vers le bas ronge la courbe a chaque epoque. Se reposer la-dessus
/// serait dependre d'un accident arithmetique plutot que d'une garantie.
///
/// La valeur retenue est donc bornee par construction :
///
/// ```text
/// R0 = floor( CAP * (DEN - NUM) / (DEN * EPOCH) )
/// ```
///
/// ce qui garantit `R0 * EPOCH * DEN / (DEN - NUM) <= EMISSION_CAP` — la somme
/// infinie de la serie geometrique discrete, avant meme tout arrondi, tient sous
/// le plafond. Verifie par
/// `emission::tests::la_recompense_initiale_respecte_le_plafond`.
pub const INITIAL_REWARD: u64 = 1_382_743_055;

/// Duree d'une epoque de decroissance, en blocs (~6 jours).
pub const DECAY_EPOCH_BLOCKS: u64 = 4_320;

/// Facteur de decroissance par epoque, exprime en fraction entiere.
///
/// 99_715_550 / 100_000_000 = 0,9971555 par epoque, soit une demi-vie de
/// 243,33 epoques ~ 4 ans. On stocke un numerateur et un denominateur, jamais
/// un flottant : `reward * NUM / DEN` en u128 est reproductible bit a bit sur
/// toute plateforme, `reward * 0.9971555` ne l'est pas.
pub const DECAY_NUM: u128 = 99_715_550;
pub const DECAY_DEN: u128 = 100_000_000;

/// Duree de la rampe de demarrage, en blocs (~28 jours).
///
/// Sur cet intervalle la recompense monte lineairement depuis zero. Sans elle,
/// les quelques mineurs presents la premiere semaine capteraient une part
/// disproportionnee de la masse totale.
pub const SLOW_START_BLOCKS: u64 = 20_000;

/// Plancher de la recompense de bloc, en unites : 0,01 Q21.
///
/// # Le defaut que ce plancher repare
///
/// La decroissance geometrique tronquee a l'entier ne rejoint jamais le
/// plafond. Calcule sur la trajectoire reelle : la recompense passait sous
/// l'unite indivisible a l'annee 91, et **137 899 Q21 sur 21 000 001 ne
/// seraient jamais crees**. Le nombre grave dans le nom du projet aurait ete
/// une asymptote, pas une promesse.
///
/// # Ce que le plancher change
///
/// La recompense de base d'une epoque vaut desormais
/// `max(decroissance geometrique, RECOMPENSE_PLANCHER)`, et l'emission cumulee
/// est ecretee **exactement** a [`EMISSION_CAP`] : le dernier bloc emetteur
/// recoit le reliquat, puis plus rien, pour toujours. Chaque unite du plafond
/// finit donc par exister — c'est `emission::block_subsidy` qui applique la
/// regle, et une epreuve verifie l'egalite exacte.
///
/// # Pourquoi 0,01 Q21
///
/// Assez petit pour ne rien changer au premier demi-siecle — la geometrique ne
/// passe sous ce plancher que vers l'annee 42, quand plus de 99 % du plafond
/// est deja emis. Assez grand pour que la fin arrive a echelle humaine plutot
/// que geologique : le reliquat s'epuise en quelques decennies de queue, la ou
/// un plancher d'une unite indivisible aurait etale la meme somme sur des
/// dizaines de milliers d'annees. Et pendant toute la queue, un mineur touche
/// un revenu de subvention plancher, previsible, en plus des frais.
pub const TAIL_REWARD: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Nombre de blocs avant qu'une recompense de bloc devienne depensable.
///
/// Protege contre les reorganisations : une coinbase depensee puis orphelinee
/// invaliderait toute la chaine de transactions qui en descend. Bitcoin retient
/// 100 blocs, soit environ 16 heures. Q21 minant cinq fois plus vite, on retient
/// 200 blocs pour conserver un delai du meme ordre — environ 6 h 40 — plutot que
/// de recopier le nombre sans reflechir a ce qu'il protege.
pub const COINBASE_MATURITY: u64 = 200;

/// Tolerance sur un horodatage situe dans le futur, en secondes.
///
/// Au-dela, le bloc est rejete.
///
/// # Pourquoi ce n'est pas deux heures, contrairement a Bitcoin
///
/// Bitcoin peut se permettre deux heures parce que sa difficulte ne bouge que
/// tous les 2 016 blocs : un horodatage isole n'y pese presque rien. Q21 ajuste
/// **a chaque bloc** sur une fenetre de 90 : la meme tolerance y devient un
/// levier.
///
/// L'audit de la phase 8b a mesure qu'un mineur detenant 20 % de la puissance
/// et inscrivant des horodatages a deux heures dans le futur faisait chuter la
/// difficulte de 70 % — et de 97 % avec une variante. Le seuil d'effondrement
/// total se situait a 20,7 % de la puissance.
///
/// Dix minutes suffisent largement a absorber la derive d'horloge d'une
/// machine ordinaire — les systemes courants se synchronisent a la seconde —
/// et reduisent d'un facteur douze la surface de cette attaque. La borne
/// etait de vingt minutes ; la moitie suffit, et chaque minute de tolerance
/// est une minute de levier. La defense principale reste toutefois le temps
/// de resolution **signe** et **dissymetrique** de `next_bits`, pas cette
/// borne.
pub const MAX_FUTURE_TIME: u64 = 10 * 60;

/// Borne haute du temps de resolution dans LWMA : un intervalle ne compte
/// jamais pour plus de ce multiple de la cible, si long qu'il paraisse.
///
/// # Pourquoi elle est plus basse que la borne de retard
///
/// Avec une borne symetrique a 6T, un mineur qui inscrit `parent + 6T`
/// injectait 6T ; le bloc honnete suivant, contraint par la mediane, n'en
/// retirait qu'une partie : il restait un solde positif, donc une baisse de
/// difficulte, donc une emission acceleree — 33 % de blocs en plus pour une
/// moitie de la puissance. Avec 4T a l'avance et 6T au retard, le bloc
/// honnete retire plus que l'attaquant n'a injecte : la manipulation
/// **augmente** la difficulte, et un mineur rationnel n'y gagne rien. Mesure
/// par l'epreuve `a1` : plus aucune strategie ne fait baisser la difficulte.
///
/// Le prix pour le reseau honnete : apres une chute brutale de puissance, un
/// intervalle reel de dix minutes ne compte que pour huit ; la difficulte
/// redescend un peu moins vite. Sur une fenetre de 90 blocs, c'est
/// negligeable.
pub const LWMA_AVANCE_MAX: u64 = 4;

/// Borne basse du temps de resolution dans LWMA, en multiples de la cible :
/// un horodatage recule ne retire jamais plus que cela.
pub const LWMA_RETARD_MAX: u64 = 6;

/// Taille de la fenetre du temps median passe.
///
/// L'horodatage d'un bloc doit depasser strictement la mediane des `N`
/// precedents. Une mediane resiste a la manipulation d'un mineur isole, la ou
/// une moyenne se laisse tirer.
pub const MEDIAN_TIME_SPAN: usize = 11;

/// Taille maximale d'un bloc serialise, en octets.
///
/// PROVISOIRE, et le chiffre est explique en section 7 du livre blanc : une
/// signature ML-DSA-65 pese 3 309 octets contre 71 pour ECDSA. Retenir 1 Mo
/// comme Bitcoin limiterait un bloc a environ 300 transactions. La valeur
/// definitive se cale sur les mesures de taux d'orphelins de la phase 6.
pub const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Taille serialisee minimale d'une transaction, hors temoin, en octets.
///
/// Une transaction a une entree et une sortie pese :
/// version(4) + varint(1) + outpoint(36) + sequence(4) + varint(1)
/// + sortie(8 + 1 + 32) + lock_time(8) = 95 octets.
///
/// On retient 64, sciemment en dessous du minimum reel : cette constante ne sert
/// qu'a **borner** des allocations, et une borne trop genereuse reste sure la ou
/// une borne trop serree refuserait un bloc legitime.
pub const MIN_TX_SIZE: usize = 64;

/// Nombre maximal de transactions qu'un bloc peut contenir.
///
/// Derive de [`MAX_BLOCK_SIZE`] plutot que choisi : un bloc ne peut pas contenir
/// plus de transactions que sa taille ne le permet. La valeur precedente —
/// 500 000, posee a la main — laissait une annonce compacte de trois megaoctets
/// declencher une allocation de plusieurs dizaines de megaoctets. Le rapport
/// entre ce qu'un adversaire envoie et ce qu'il fait allouer doit rester borne,
/// et petit.
pub const MAX_TX_PAR_BLOC: usize = MAX_BLOCK_SIZE / MIN_TX_SIZE;

/// Poids vise par le mineur lors de l'assemblage d'un bloc.
///
/// Ce n'est pas une regle de consensus mais une politique : un bloc plus leger
/// se propage plus vite et s'orpheline moins. Elle est publiee ici parce que le
/// reservoir doit s'y caler — accepter une transaction qu'aucun mineur ne
/// selectionnera revient a offrir de la place a qui ne paiera jamais.
pub const POIDS_BLOC_CIBLE: u64 = 2_000_000;

/// Ponderation des donnees hors temoin dans le calcul du poids.
///
/// Traduction du *witness discount* : le corps d'une transaction compte quatre
/// fois, le temoin une seule. Sans cela, le poids d'une transaction Q21 serait
/// presque entierement dicte par sa signature post-quantique.
pub const WITNESS_DISCOUNT: u64 = 4;

/// Poids ajoute a une transaction pour **chaque sortie qu'elle cree**.
///
/// # Ce que cela tarife
///
/// Une sortie ne coute pas que ses 41 octets sur le fil : elle entre dans le
/// jeu d'UTXO de tous les noeuds, en memoire vive, et y reste tant qu'elle
/// n'est pas depensee — potentiellement pour toujours. Un octet de temoin,
/// lui, est oublie des que le bloc est enfoui. Tarifer les deux au meme prix
/// revenait a offrir la ressource la plus rare du reseau au prix de la plus
/// abondante : un bloc plein de sorties minuscules coutait quelques centaines
/// d'unites et imposait vingt gigaoctets par jour a chaque noeud.
///
/// Quatre cents unites de poids, c'est l'equivalent d'une centaine d'octets
/// d'ossature : creer une sorte coute desormais plus que la transporter. Ce
/// n'est pas une regle de consensus mais une politique de relais et
/// d'assemblage ; la regle de consensus qui protege les mineurs d'eux-memes
/// est [`MIN_OUTPUT_VALUE`].
pub const POIDS_PAR_SORTIE: u64 = 400;

/// Valeur minimale d'une sortie, en unites : la **poussiere** est refusee.
///
/// # Pourquoi c'est une regle de consensus, et pas seulement de relais
///
/// Bitcoin refuse la poussiere au relais seulement. Ici, la regle doit tenir
/// aussi contre un mineur qui remplirait ses propres blocs : les frais qu'il
/// paie lui reviennent, donc aucune tarification ne le freine. Ce qui le
/// freine, c'est le capital immobilise : a 10 000 unites par sortie, soixante
/// millions de sorties — une journee de blocs pleins — immobilisent six mille
/// Q21, a une epoque ou le reseau entier en emet dix mille par jour. Et ces
/// unites ne sont pas perdues pour lui : les regrouper ensuite lui coute des
/// frais et du temps, ce qui est exactement le prix qu'on voulait faire payer.
///
/// 10 000 unites = 0,0001 Q21. Un paiement legitime plus petit n'a pas de sens
/// : il ne couvrirait pas les frais de sa propre depense.
///
/// La genese est exempte : sa coinbase porte l'unite qui fait passer le
/// plafond de 21 000 000 a 21 000 001, et cette unite est indepensable.
pub const MIN_OUTPUT_VALUE: u64 = 10_000;

// ---------------------------------------------------------------------------
// Difficulte
// ---------------------------------------------------------------------------

/// Fenetre de l'ajustement de difficulte LWMA, en blocs.
///
/// Un ajustement a chaque bloc sur une moyenne mobile ponderee, et non tous les
/// 2 016 blocs comme Bitcoin. Une petite chaine dont le hashrate double ou
/// disparait en une journee ne peut pas attendre deux semaines : elle se ferait
/// eteindre par la premiere ferme qui arrive et repart.
pub const LWMA_WINDOW: usize = 90;

/// Cible de difficulte initiale, en forme compacte.
///
/// Volontairement permissive : au bloc 1, le reseau compte une machine.
pub const INITIAL_BITS: u32 = 0x2000_ffff;

/// Facteur maximal de variation de la cible entre deux blocs.
///
/// Borne les oscillations qu'un mineur pourrait provoquer en manipulant les
/// horodatages dans la fenetre autorisee.
pub const MAX_TARGET_CHANGE: u64 = 4;

// ---------------------------------------------------------------------------
// Preuve de travail memory-hard
// ---------------------------------------------------------------------------

/// Nombre d'acces a la table par tentative de minage.
///
/// Ces acces sont **sequentiellement dependants** : l'indice du suivant se
/// deduit du resultat du precedent. Un circuit ne peut donc ni les paralleliser
/// ni les prefetcher, et se retrouve limite par la latence de la DRAM — une
/// grandeur physique sur laquelle personne n'a d'avantage decisif.
pub const POW_K: usize = 32;

/// Taille d'un element de table, en octets.
pub const POW_ELEMENT_SIZE: usize = 32;

/// Duree d'une epoque de preuve de travail, en blocs (~71 jours a 2 min).
///
/// A chaque epoque, la graine change et la table grandit.
pub const POW_EPOCH_BLOCKS: u64 = 51_200;

/// Croissance de la table par epoque, en pourcentage.
///
/// C'est le mecanisme central du levier A du livre blanc. Un circuit concu
/// autour d'une quantite de memoire fixe devient mediocre des que la table la
/// depasse. Le materiel dedie se perime donc tout seul, sans qu'on ait besoin
/// de convoquer une rupture de chaine defensive tous les six mois — ce que
/// Monero a du s'infliger quatre fois entre 2018 et 2019.
pub const POW_TABLE_GROWTH_PCT: u64 = 5;

/// Nombre initial d'elements de la table, par reseau.
///
/// Reseau principal : 2^26 elements x 32 o = 2 Gio. Choisi pour tenir sur une
/// machine grand public tout en obligeant un circuit dedie a embarquer de la
/// DRAM.
pub const POW_TABLE_N0_MAINNET: u32 = 1 << 26;
pub const POW_TABLE_N0_TESTNET: u32 = 1 << 20; // 32 Mio
pub const POW_TABLE_N0_REGTEST: u32 = 1 << 10; // 32 Kio

/// Plafond de croissance de la table, par reseau.
///
/// Reseau principal : 2^27 elements x 32 o = **4 Gio**, atteints a la
/// quinzieme epoque, soit vers la troisieme annee. Le plafond etait de 8 Gio ;
/// c'est la promesse « minable par tout le monde » qui l'a ramene a 4. Un
/// Raspberry Pi 5 possede 8 Go en tout, un portable courant 8 ou 16 : une
/// table de 8 Gio les excluait vers la sixieme annee, pour un gain marginal
/// contre du materiel dedie, qui achete de la memoire a volonte. La table
/// doit peser sur le silicium, pas sur le particulier. A reevaluer dans cinq
/// ans, quand 16 Go seront le bas de gamme.
pub const POW_TABLE_NMAX_MAINNET: u32 = 1 << 27; // 4 Gio, atteint vers 3 ans
pub const POW_TABLE_NMAX_TESTNET: u32 = 1 << 22;
pub const POW_TABLE_NMAX_REGTEST: u32 = 1 << 12;

// ---------------------------------------------------------------------------
// Le cache : niveau 1 de la preuve de travail
// ---------------------------------------------------------------------------
//
// La premiere conception derivait chaque element de table par un condensat
// independant. Le banc de la phase 6, sur la vraie table de 2 Gio, a rendu son
// verdict : se passer entierement de memoire ne coutait que **2,86 x**, et
// au-dela de 256 Mio la memoire n'achetait plus rien du tout. Un circuit dedie
// dont le condensat est trois fois plus rapide qu'un processeur avait donc
// interet a n'embarquer aucune DRAM — la promesse anti-ASIC etait fausse.
//
// La correction reprend la structure a deux niveaux d'Ethash : un cache
// sequentiellement genere, et des elements de table qui ne se calculent qu'en
// parcourant ce cache. Recalculer un element cesse d'etre bon marche.

/// Rapport entre la table (niveau 2) et le cache (niveau 1).
///
/// Reseau principal : table 2 Gio, cache 64 Mio. Le cache est ce que doit
/// detenir un noeud qui verifie — plus un mineur qui refuserait la table.
pub const POW_CACHE_RATIO: u32 = 32;

/// Acces au cache necessaires pour calculer **un** element de table.
///
/// C'est le facteur de penalite impose a qui refuse la table : un mineur equipe
/// paie une lecture la ou un mineur sans table en paie [`POW_J`]. C'est aussi le
/// facteur qui multiplie la bande passante memoire exigee — la seule grandeur
/// qu'un circuit dedie ne peut pas contourner par du silicium.
pub const POW_J: usize = 256;

/// Passes de melange lors de la construction du cache.
///
/// Le cache se genere en chaine : l'element `i` depend de l'element `i-1`. Les
/// passes supplementaires (RandMemoHash, Lerner 2014, comme Ethash) empechent
/// de reconstruire un fragment de cache sans reconstruire tout ce qui precede.
pub const POW_CACHE_ROUNDS: usize = 3;

// ---------------------------------------------------------------------------
// Defense contre les reorganisations profondes
// ---------------------------------------------------------------------------

/// Profondeur maximale d'une reorganisation acceptee.
///
/// # Ce que cette regle fait, et ce qu'elle coute
///
/// Au-dela de cette profondeur, un noeud refuse de basculer sur une chaine
/// concurrente meme si elle porte plus de travail. Une transaction enfouie sous
/// autant de blocs devient donc irreversible pour ce noeud : c'est une finalite
/// glissante.
///
/// Ce n'est **pas** gratuit, et pretendre le contraire serait malhonnete. Cette
/// regle ne supprime pas l'attaque a 51 %, elle en change la nature : un
/// attaquant majoritaire ne peut plus reecrire l'histoire ancienne, mais une
/// partition reseau durant plus de `MAX_REORG_DEPTH` blocs produit deux chaines
/// qui ne se reconcilieront jamais d'elles-memes. On echange un risque de
/// reecriture contre un risque de scission.
///
/// Le compromis est retenu parce qu'une scission est visible, diagnosticable et
/// reparable par intervention humaine, alors qu'une reecriture profonde est
/// silencieuse et vole des gens.
///
/// 720 blocs a 2 minutes = 24 heures.
pub const MAX_REORG_DEPTH: u64 = 720;

/// Profondeur au-dela de laquelle une fourche doit montrer un exces de travail.
///
/// Entre cette profondeur et [`MAX_REORG_DEPTH`], une chaine concurrente n'est
/// acceptee que si son travail cumule depasse celui de la chaine courante d'une
/// marge qui croit avec la profondeur de la fourche. Reorganiser devient de plus
/// en plus cher a mesure qu'on remonte, au lieu d'etre gratuit des qu'on a une
/// tete d'avance.
pub const REORG_PENALTY_FROM_DEPTH: u64 = 6;

/// Pourcentage de travail supplementaire exige par bloc de profondeur, au-dela
/// de [`REORG_PENALTY_FROM_DEPTH`].
pub const REORG_PENALTY_PCT_PER_BLOCK: u64 = 1;

/// Plafond de la majoration, en pourcentage du travail produit depuis la
/// fourche.
///
/// # Pourquoi un plafond
///
/// Sans lui, la majoration atteignait 100 % a la profondeur 106 et plus de
/// 700 % a la profondeur maximale. Une partition reseau ordinaire — deux
/// pays, deux fournisseurs — minant a puissance egale des deux cotes
/// devenait alors **definitive en deux heures** (simulation : derniere
/// reunification possible a 66 blocs en mediane pour une minorite a 50 %,
/// 153 blocs pour une minorite a 40 %), la ou la documentation annoncait
/// vingt-quatre heures. Chaque cote se voyait majore, et aucun ne rejoignait
/// jamais l'autre.
///
/// Avec 25 %, toute majorite superieure a 56 % de la puissance reunifie le
/// reseau dans la fenetre de [`MAX_REORG_DEPTH`], et une reorganisation
/// profonde par un attaquant reste plus chere d'un quart — ce qui, joint a la
/// profondeur maximale, suffit a l'objectif de depart.
pub const REORG_PENALTY_MAX_PCT: u64 = 25;

// ---------------------------------------------------------------------------
// Oncles
// ---------------------------------------------------------------------------

/// Nombre maximal d'oncles rattaches a un bloc : **zero**, le mecanisme est
/// retire.
///
/// # Pourquoi il est retire
///
/// La part d'un oncle etait prelevee sur la subvention du bloc qui
/// l'incluait — jamais ajoutee, pour que l'emission reste exactement celle du
/// calendrier. Un mineur qui incluait un oncle cedait donc un quart de sa
/// recompense a un concurrent sans rien recevoir en echange : aucun mineur
/// rationnel ne le faisait, et le mineur du binaire ne l'a jamais fait. Le
/// mecanisme ne servait qu'a une chose : offrir a un attaquant une surface de
/// validation supplementaire — trois defauts y ont deja ete trouves et
/// corriges, dont un qui faisait diverger un noeud repris sur instantane
/// d'un noeud complet.
///
/// Le faire fonctionner demanderait de payer les oncles **en plus** de la
/// subvention, comme Ethereum, donc de renoncer a une emission exactement
/// previsible ; ce n'est pas un echange que ce projet veut faire. A deux
/// minutes par bloc et avec les annonces compactes, les blocs orphelins sont
/// rares ; les payer ne vaut pas ce qu'il en coute.
///
/// Le format du bloc conserve sa liste d'oncles et sa racine, vides : rien ne
/// change sur le fil. Un bloc qui en porte est refuse.
pub const MAX_UNCLES: usize = 0;

/// Anciennete maximale d'un oncle, en blocs.
///
/// Au-dela, le bloc orphelin n'est plus rattachable : sans cette borne, un
/// mineur pourrait accumuler des oncles anciens et se les faire payer d'un coup.
pub const MAX_UNCLE_AGE: u64 = 7;

/// Corps de blocs conserves en memoire, en nombre de blocs.
///
/// Un noeud n'a besoin du **corps** d'un bloc que pour deux raisons : defaire
/// une reorganisation, et verifier les oncles reclames. Les deux sont bornees —
/// par [`MAX_REORG_DEPTH`] et [`MAX_UNCLE_AGE`]. Au-dela, le corps ne sert plus
/// qu'a repondre a un pair qui se synchronise, et le disque suffit.
///
/// Sans cette borne, un noeud gardait en memoire vive l'integralite de la
/// chaine : quelques milliers de blocs en developpement, plusieurs dizaines de
/// gigaoctets apres quelques annees. La marge au-dela de la profondeur de
/// reorganisation absorbe les oncles et les branches laterales en cours
/// d'evaluation.
pub const BODY_WINDOW: usize = MAX_REORG_DEPTH as usize + 288;

/// Part de la subvention versee au mineur d'un oncle, en pourcentage.
///
/// Levier C du livre blanc : payer le travail orphelin d'un mineur mal connecte
/// plutot que de le jeter. Sans cela, le gros mineur gagne les courses de
/// propagation et touche donc **plus** que sa part de puissance — un rendement
/// super-lineaire qui concentre le minage sans que personne n'attaque rien.
///
/// # Cette part est **prelevee sur** la subvention, pas ajoutee
///
/// La premiere conception versait cette part **en plus** de la subvention, plus
/// une prime d'inclusion. Avec deux oncles au maximum, un bloc pouvait donc
/// emettre 210 % de sa subvention, et l'emission maximale reelle du protocole
/// s'etablissait a **44 099 999 Q21** — pour un plafond annonce a 21 000 001.
/// L'audit adverse de la phase 8 l'a demontre par un test.
///
/// Desormais : `mineur = subvention - somme des parts d'oncles + frais`. Un bloc
/// emet **exactement** sa subvention, quoi qu'il contienne, et le plafond tient
/// par construction. Le prix de cette correction est explicite : inclure un
/// oncle coute au mineur ce qu'il verse. Voir `AUDIT.md`.
pub const UNCLE_REWARD_PCT: u64 = 25;

// ---------------------------------------------------------------------------
// Genese
// ---------------------------------------------------------------------------

/// Beneficiaire de la piece de genese.
///
/// # Pourquoi cette valeur est nulle, et pourquoi c'est un choix
///
/// Ce champ **doit etre une constante du reseau**, pas une adresse locale. Une
/// genese qui depend du portefeuille de celui qui lance le noeud produit une
/// genese differente par machine, donc autant de chaines incompatibles que de
/// participants. Le defaut a ete decouvert en lancant reellement deux noeuds :
/// ils echangeaient des dizaines de milliers de blocs sans jamais progresser,
/// chaque bloc arrivant avec un parent inconnu.
///
/// La valeur retenue est l'empreinte nulle. Personne n'en connait la preimage :
/// aucune clef publique ne peut produire ce condensat autrement que par une
/// attaque en preimage sur SHA-256. La piece de genese est donc **definitivement
/// indepensable**.
///
/// Ce n'est pas un pis-aller mais une position : le chiffre 21 000 001 dit que
/// le compte n'est pas solde, et l'unite qui depasse n'appartient a personne —
/// surtout pas a celui qui a lance la chaine. Un fondateur qui se pre-attribue
/// la premiere piece commence mal une monnaie sans autorite.
pub const GENESIS_BENEFICIARY: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Identifiants de chaine
// ---------------------------------------------------------------------------

/// Prefixe Bech32m des adresses du reseau principal.
pub const HRP_MAINNET: &str = "q21";

/// Prefixe Bech32m des adresses du reseau de test.
pub const HRP_TESTNET: &str = "tq21";

/// Prefixe Bech32m du reseau de regression.
///
/// Reseau local jetable, a difficulte figee au minimum, pour developper et
/// tester sans attendre. Bitcoin a le meme, pour la meme raison.
pub const HRP_REGTEST: &str = "rq21";

/// Magie reseau, prefixe de chaque message du protocole p2p.
pub const NETWORK_MAGIC_MAINNET: [u8; 4] = [0x51, 0x32, 0x31, 0x01];
pub const NETWORK_MAGIC_TESTNET: [u8; 4] = [0x51, 0x32, 0x31, 0x74];

// ---------------------------------------------------------------------------
// Invariants verifies a la compilation
// ---------------------------------------------------------------------------
//
// Ces controles ne sont pas des tests : ils cassent la compilation. Un
// parametre de consensus incoherent ne doit pas pouvoir produire un binaire,
// meme si personne ne lance `cargo test` avant de deployer.

const _: () = {
    assert!(MAX_SUPPLY == 2_100_000_100_000_000);
    assert!(EMISSION_CAP + GENESIS_PREMINT == MAX_SUPPLY);
    assert!(EMISSION_CAP == 21_000_000 * UNITS_PER_COIN);

    // Large marge avant debordement : aucune somme de montants legitimes ne
    // peut approcher u64::MAX.
    assert!(MAX_SUPPLY < u64::MAX / 1000);

    // La recompense doit decroitre, et pas trop vite.
    assert!(DECAY_NUM < DECAY_DEN);
    assert!(DECAY_NUM > DECAY_DEN / 100 * 99);

    // Garantie fondamentale : la somme geometrique discrete a l'infini tient
    // sous le plafond, avant meme tout arrondi. C'est cette ligne qui rend
    // impossible de depasser 21 000 000 par le minage, a toute hauteur.
    assert!(
        (INITIAL_REWARD as u128 * DECAY_EPOCH_BLOCKS as u128 * DECAY_DEN) / (DECAY_DEN - DECAY_NUM)
            <= EMISSION_CAP as u128
    );

    assert!(SLOW_START_BLOCKS > 0);
    assert!(DECAY_EPOCH_BLOCKS > 0);

    // Le plancher de queue : strictement positif — c'est lui qui garantit que
    // l'emission atteint le plafond en temps fini — et tres en dessous de la
    // recompense initiale, pour qu'il ne morde que la queue de la courbe et
    // jamais son corps.
    assert!(TAIL_REWARD > 0);
    assert!(TAIL_REWARD < INITIAL_REWARD / 1000);
};
