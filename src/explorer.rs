//! Explorateur web, servi par le noeud.
//!
//! # Pourquoi il n'est pas hebergé ailleurs
//!
//! Pour consulter une chaine, presque tout le monde ouvre le site d'un tiers.
//! On fait donc confiance a un serveur pour savoir ce que contient un systeme
//! bati pour ne faire confiance a personne — et ce serveur peut mentir, se
//! tromper, disparaitre, ou etre contraint.
//!
//! Cette page est servie par votre noeud, sur le bouclage local, et n'affiche
//! que ce que votre machine a valide elle-meme. Elle ne charge **aucune
//! ressource externe** : ni police, ni feuille de style, ni script distant. Une
//! page d'exploration qui appelle un CDN transmet a ce CDN la liste de tout ce
//! que vous consultez.
//!
//! Elle affiche aussi, en clair, ce que le protocole **ne** protege **pas**.
//! Un explorateur qui ne montre que ce qui rassure ment par omission.

/// Page complete. Aucune ressource externe, par construction.
///
/// # Ce qui a change avec la phase 3
///
/// La page ne montrait qu'un tableau de bord : l'etat de la chaine, la monnaie
/// emise, les derniers blocs. On pouvait la regarder ; on ne pouvait rien y
/// chercher.
///
/// Elle porte maintenant quatre vues — accueil, bloc, transaction, adresse — et
/// un champ de recherche unique. Le routage se fait dans le **fragment**, ce
/// qui suit le `#` : il ne quitte jamais le navigateur, aucune requete n'est
/// faite au serveur pour changer de page, et la page reste un fichier unique
/// servi tel quel.
///
/// Le jeton employait deja ce fragment. Les deux cohabitent sans ambiguite :
/// une route commence toujours par une barre oblique, un jeton jamais. Le jeton
/// est lu une fois, range dans `localStorage` — cloisonne par port, et mort
/// avec le processus qui l'a tire — et le fragment rendu au routage.
pub const PAGE: &str = r##"<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Q21 — explorateur local</title>
<style>
:root{
  --fond:#f5f4f0; --carte:#fffefb; --bord:#dcd8cf; --bord-fort:#c3bdb1;
  --texte:#1a1a18; --doux:#57554d; --tenu:#8b887d;
  --accent:#1d6f66; --accent-fond:#e2eeeb; --alerte:#8a5a1e; --alerte-fond:#f4e9d8;
}
@media (prefers-color-scheme: dark){
  :root{
    --fond:#131410; --carte:#1c1e18; --bord:#32352b; --bord-fort:#454940;
    --texte:#ecebe0; --doux:#aca99a; --tenu:#7b786b;
    --accent:#62bfb2; --accent-fond:#16302c; --alerte:#d9a75f; --alerte-fond:#312716;
  }
}
*{box-sizing:border-box}
body{
  margin:0;background:var(--fond);color:var(--texte);
  font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
.enveloppe{max-width:1080px;margin:0 auto;padding:2rem 1.2rem 4rem}
header{border-bottom:2px solid var(--texte);padding-bottom:1rem;margin-bottom:1.6rem}
h1{margin:0;font-size:1.7rem;letter-spacing:-.02em}
h1 a{color:inherit;text-decoration:none}
.sous{color:var(--doux);font-size:.9rem;margin-top:.35rem}
.etat{display:inline-block;padding:.12rem .5rem;border-radius:3px;font-size:.75rem;
  font-family:ui-monospace,monospace;background:var(--accent-fond);color:var(--accent);margin-left:.5rem}
h2{font-size:1rem;text-transform:uppercase;letter-spacing:.08em;color:var(--doux);
  margin:2rem 0 .8rem;font-weight:600}
h2:first-child{margin-top:0}
.grille{display:grid;gap:.9rem;grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}
.tuile{background:var(--carte);border:1px solid var(--bord);border-radius:6px;padding:.85rem 1rem}
.tuile .k{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--tenu)}
.tuile .v{font-size:1.3rem;font-family:ui-monospace,monospace;margin-top:.2rem;
  font-variant-numeric:tabular-nums;word-break:break-all}
.tuile .n{font-size:.76rem;color:var(--doux);margin-top:.2rem;word-break:break-all}
table{width:100%;border-collapse:collapse;font-family:ui-monospace,monospace;font-size:.82rem}
th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--bord);
  font-variant-numeric:tabular-nums;white-space:nowrap}
th{color:var(--tenu);font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;
  border-bottom:1px solid var(--bord-fort)}
tbody tr:hover{background:var(--accent-fond)}
.defile{overflow-x:auto;background:var(--carte);border:1px solid var(--bord);border-radius:6px}
.mono{font-family:ui-monospace,monospace}
.coupe{max-width:22ch;overflow:hidden;text-overflow:ellipsis;display:inline-block;vertical-align:bottom}
.avert{background:var(--carte);border:1px solid var(--bord);border-left:3px solid var(--alerte);
  border-radius:5px;padding:1rem 1.1rem;margin:.9rem 0}
.avert h3{margin:0 0 .5rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--alerte)}
.avert p{margin:0 0 .6rem;font-size:.9rem;color:var(--doux)}
.avert p:last-child{margin-bottom:0}
.avert ul{margin:.3rem 0 .6rem;padding-left:1.2rem;font-size:.88rem;color:var(--doux)}
.info{border-left-color:var(--accent)}
.info h3{color:var(--accent)}
.deux{display:grid;gap:.9rem;grid-template-columns:1fr 1fr}
@media(max-width:720px){.deux{grid-template-columns:1fr}}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--bord);
  color:var(--tenu);font-size:.78rem}
code{background:var(--accent-fond);color:var(--accent);padding:.1em .35em;border-radius:3px;
  font-size:.85em}
.err{color:var(--alerte)}
a{color:var(--accent)}
a.plat{text-decoration:none}
a.plat:hover{text-decoration:underline}

/* Recherche : un seul champ, qui devine ce qu'on lui donne. */
.chercher{display:flex;gap:.5rem;margin-top:.9rem;flex-direction:column}
@media(min-width:560px){.chercher{flex-direction:row}}
.chercher input{
  flex:1;background:var(--carte);color:var(--texte);border:1px solid var(--bord-fort);
  border-radius:5px;padding:.55rem .7rem;font:inherit;font-family:ui-monospace,monospace;
  font-size:.88rem;min-width:0;
}
.chercher input:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:var(--accent)}
.chercher button{
  background:var(--accent);color:var(--fond);border:1px solid var(--accent);border-radius:5px;
  padding:.55rem 1.1rem;font:inherit;font-size:.88rem;font-weight:600;cursor:pointer;
}
.chercher button:hover{filter:brightness(1.08)}
.aide{font-size:.78rem;color:var(--tenu);margin-top:.35rem}

/* Fil d'Ariane */
.fil{font-size:.82rem;color:var(--tenu);margin-bottom:.9rem}
.fil a{color:var(--doux)}

/* Flux d'une transaction : ce qui entre a gauche, ce qui sort a droite. */
.flux{display:grid;gap:.9rem;grid-template-columns:1fr 1fr;margin-top:.5rem}
@media(max-width:720px){.flux{grid-template-columns:1fr}}
.pile{background:var(--carte);border:1px solid var(--bord);border-radius:6px;padding:.3rem .9rem}
.pile .l{padding:.55rem 0;border-bottom:1px solid var(--bord);font-size:.84rem;
  display:flex;justify-content:space-between;gap:.8rem;align-items:baseline}
.pile .l:last-child{border-bottom:none}
.pile .l .g{font-family:ui-monospace,monospace;overflow:hidden;text-overflow:ellipsis}
.pile .l .d{font-family:ui-monospace,monospace;white-space:nowrap;font-variant-numeric:tabular-nums}
.pile .t{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--tenu);
  padding:.6rem 0 .2rem}
.badge{display:inline-block;padding:.05rem .4rem;border-radius:3px;font-size:.72rem;
  background:var(--accent-fond);color:var(--accent)}
.badge.gris{background:var(--bord);color:var(--doux)}

/* Choix de la langue : le meme que dans le portefeuille. */
.entete-haut{display:flex;align-items:center;justify-content:space-between;gap:.8rem;flex-wrap:wrap}
.langues{display:flex;gap:.25rem;align-items:center}
.langues button{background:transparent;border:1px solid transparent;border-radius:.4rem;
  padding:.15rem .35rem;font-size:1.05rem;line-height:1;cursor:pointer;opacity:.55}
.langues button:hover{opacity:.9;background:var(--accent-fond)}
.langues button[aria-pressed="true"]{opacity:1;border-color:var(--bord-fort)}
.langues button:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
</style>
</head>
<body>
<div class="enveloppe">

<header>
  <div class="entete-haut">
    <h1><a href="#/">Q21</a> <span class="etat" id="reseau">…</span></h1>
    <div class="langues" id="langues" role="group" aria-label="Langue / Language">
      <button type="button" data-langue="fr" aria-pressed="true" title="Français">&#127467;&#127479;</button>
      <button type="button" data-langue="en" aria-pressed="false" title="English">&#127468;&#127463;</button>
      <button type="button" data-langue="ja" aria-pressed="false" title="&#26085;&#26412;&#35486;">&#127471;&#127477;</button>
    </div>
  </div>
  <div class="sous">
    Explorateur servi par <strong>votre nœud</strong>, en local. Aucune ressource
    externe n'est chargée&nbsp;: ce que vous lisez, votre machine l'a validé.
  </div>
  <form class="chercher" id="forme-chercher" autocomplete="off">
    <input id="saisie-chercher" placeholder="hauteur, bloc, transaction, adresse ou montant (ex. 1.5)" spellcheck="false">
    <button type="submit">Chercher</button>
  </form>
  <div class="aide" id="aide-chercher">Un seul champ&nbsp;: le nœud reconnaît ce que vous collez.</div>
</header>

<div id="panneau-jeton" class="avert" hidden>
  <h3>Jeton d'accès requis</h3>
  <p>
    Le nœud exige un jeton. Il est normalement transmis par le lanceur dans le
    fragment de l'adresse&nbsp;; si vous avez ouvert cette page à la main,
    saisissez ici le jeton passé à <code>--rpc-token</code>.
  </p>
  <form id="forme-jeton" class="chercher" autocomplete="off">
    <input type="password" id="saisie-jeton" placeholder="jeton d'accès" autocomplete="off" spellcheck="false">
    <button type="submit">Déverrouiller</button>
  </form>
</div>

<div id="erreur" class="avert" hidden>
  <h3>Nœud injoignable</h3>
  <p id="erreur-detail"></p>
</div>

<section class="vue" id="vue-accueil">
  <h2>Chaîne</h2>
  <div class="grille" id="tuiles"></div>

  <h2>Monnaie</h2>
  <div class="grille" id="monnaie"></div>

  <div class="deux">
    <div>
      <h2>Preuve de travail</h2>
      <div class="defile"><table id="pow"></table></div>
    </div>
    <div>
      <h2>Réseau</h2>
      <div class="defile"><table id="reseau-stats"></table></div>
    </div>
  </div>

  <h2>Derniers blocs</h2>
  <div class="defile">
    <table>
      <thead><tr><th>Hauteur</th><th>Identifiant</th><th>Tx</th><th>Taille</th><th>Subvention</th><th>Horodatage</th></tr></thead>
      <tbody id="blocs"></tbody>
    </table>
  </div>

  <h2>Réservoir de transactions</h2>
  <div class="defile"><table id="mempool"></table></div>

  <h2>Ce que le protocole ne protège pas</h2>
  <div class="avert" id="securite">
    <h3>Chargement…</h3>
  </div>
</section>

<section class="vue" id="vue-bloc" hidden>
  <div class="fil"><a href="#/">Accueil</a> → bloc</div>
  <h2 id="bloc-titre">Bloc</h2>
  <div class="grille" id="bloc-tuiles"></div>
  <div class="defile" style="margin-top:.9rem"><table id="bloc-entete"></table></div>
  <h2>Transactions</h2>
  <div class="defile">
    <table>
      <thead><tr><th>#</th><th>Identifiant</th><th>Genre</th><th>Entrées</th><th>Sorties</th><th>Valeur sortante</th><th>Poids</th></tr></thead>
      <tbody id="bloc-transactions"></tbody>
    </table>
  </div>
  <div id="bloc-oncles"></div>
</section>

<section class="vue" id="vue-tx" hidden>
  <div class="fil"><a href="#/">Accueil</a> → transaction</div>
  <h2>Transaction</h2>
  <div class="grille" id="tx-tuiles"></div>
  <div class="flux">
    <div>
      <div class="pile" id="tx-entrees"></div>
    </div>
    <div>
      <div class="pile" id="tx-sorties"></div>
    </div>
  </div>
  <div id="tx-note"></div>
</section>

<section class="vue" id="vue-adresse" hidden>
  <div class="fil"><a href="#/">Accueil</a> → adresse</div>
  <h2>Adresse</h2>
  <div class="defile" style="margin-bottom:.9rem"><table id="adresse-identite"></table></div>
  <div class="grille" id="adresse-tuiles"></div>
  <div id="adresse-note"></div>
  <h2>Mouvements</h2>
  <div class="defile">
    <table>
      <thead><tr><th>Genre</th><th>Reçu</th><th>Envoyé</th><th>Conf.</th><th>Hauteur</th><th>Horodatage</th><th>Identifiant</th></tr></thead>
      <tbody id="adresse-mouvements"></tbody>
    </table>
  </div>
</section>

<section class="vue" id="vue-montant" hidden>
  <div class="fil"><a href="#/">Accueil</a> → montant</div>
  <h2>Recherche par montant</h2>
  <div class="grille" id="montant-tuiles"></div>
  <div id="montant-note"></div>
  <h2>Sorties trouvées</h2>
  <div class="defile">
    <table>
      <thead><tr><th>Transaction</th><th>Hauteur</th><th>Adresse</th><th>Montant</th></tr></thead>
      <tbody id="montant-lignes"></tbody>
    </table>
  </div>
</section>

<footer>
  <p style="margin:0 0 .6rem" id="pied-portefeuille" hidden>
    <a class="plat" id="lien-portefeuille" href="/portefeuille">Portefeuille</a> —
    servi par le même nœud, sur le même port.
  </p>
  API JSON-RPC sur <code>POST /rpc</code> — <code>listmethods</code> énumère les
  méthodes disponibles. Code de recherche, non audité&nbsp;: ne protège aucune
  valeur réelle.
</footer>

</div>
<script>
// ---------------------------------------------------------------------------
// Langue
//
// Meme moteur que le portefeuille, et meme cle de rangement `q21-langue` : la
// langue choisie dans le portefeuille suit dans l'explorateur, qui s'ouvre dans
// le meme onglet, et inversement. `sessionStorage` ne sert qu'a cela, jamais au
// jeton, qui reste dans `localStorage` sous l'origine.
//
// La page ecrit toujours ses textes en francais ; le moteur les traduit a
// l'affichage. C'est ce qui permet de changer de langue a tout moment, dans les
// deux sens, sans recharger. Les textes venus du noeud (notes, erreurs) passent
// par la meme table : l'explorateur ne demande rien au noeud selon la langue.
// ---------------------------------------------------------------------------
const I18N = {"en": {"Q21 — explorateur local": "Q21 — local explorer", "Explorateur servi par": "Explorer served by", "votre nœud": "your node", ", en local. Aucune ressource externe n'est chargée : ce que vous lisez, votre machine l'a validé.": ", locally. No external resource is loaded: what you read, your machine has validated.", "hauteur, bloc, transaction, adresse ou montant (ex. 1.5)": "height, block, transaction, address or amount (e.g. 1.5)", "Chercher": "Search", "Un seul champ : le nœud reconnaît ce que vous collez.": "One field: the node recognises whatever you paste.", "Recherche…": "Searching…", "Jeton d'accès requis": "Access token required", "Le nœud exige un jeton. Il est normalement transmis par le lanceur dans le fragment de l'adresse ; si vous avez ouvert cette page à la main, saisissez ici le jeton passé à": "The node requires a token. The launcher normally passes it in the address fragment; if you opened this page by hand, enter here the token given to", "jeton d'accès": "access token", "Déverrouiller": "Unlock", "Nœud injoignable": "Node unreachable", "Portefeuille": "Wallet", "— servi par le même nœud, sur le même port.": "— served by the same node, on the same port.", "API JSON-RPC sur": "JSON-RPC API at", "énumère les méthodes disponibles. Code de recherche, non audité : ne protège aucune valeur réelle.": "lists the available methods. Research code, not audited: it protects no real value.", "Chargement…": "Loading…", "Chaîne": "Chain", "Monnaie": "Currency", "Preuve de travail": "Proof of work", "Réseau": "Network", "Derniers blocs": "Latest blocks", "Réservoir de transactions": "Transaction pool", "Ce que le protocole ne protège pas": "What the protocol does not protect", "Accueil": "Home", "→ bloc": "→ block", "→ transaction": "→ transaction", "→ adresse": "→ address", "→ montant": "→ amount", "Bloc": "Block", "Transactions": "Transactions", "Transaction": "Transaction", "Adresse": "Address", "Mouvements": "Movements", "Recherche par montant": "Search by amount", "Sorties trouvées": "Outputs found", "Oncles": "Uncles", "Hauteur": "Height", "Identifiant": "Identifier", "Identifiants": "Identifiers", "Taille": "Size", "Subvention": "Subsidy", "Horodatage": "Timestamp", "Genre": "Kind", "Entrées": "Inputs", "Sorties": "Outputs", "Valeur sortante": "Output value", "Poids": "Weight", "Reçu": "Received", "Envoyé": "Sent", "Conf.": "Conf.", "Montant": "Amount", "Confirmations": "Confirmations", "Parent": "Parent", "Racine de Merkle": "Merkle root", "Mineur": "Miner", "Nonce": "Nonce", "Difficulté": "Difficulty", "Tête": "Tip", "Travail cumulé": "Cumulative work", "tentatives espérées": "expected attempts", "Pairs": "Peers", "Blocs connus": "Known blocks", "branches latérales comprises": "side branches included", "Émis": "Issued", "Dans les UTXO": "In the UTXO set", "Plafond": "Cap", "sous le plafond ✓": "under the cap ✓", "PLAFOND FRANCHI": "CAP EXCEEDED", "Part émise": "Share issued", "Sorties non dépensées": "Unspent outputs", "Empreinte de l'état": "State fingerprint", "Époque": "Epoch", "Éléments de table": "Table elements", "Mémoire du mineur": "Miner memory", "Mémoire du nœud": "Node memory", "Accès par tentative": "Accesses per attempt", "Croissance": "Growth", "Blocs reçus": "Blocks received", "Blocs acceptés": "Blocks accepted", "Annonces compactes": "Compact announcements", "Reconstruits sans aller-retour": "Rebuilt without a round trip", "Transactions reçues": "Transactions received", "Pairs bannis": "Banned peers", "Octets": "Bytes", "Protection à 100 % contre une attaque à 51 % : impossible": "100 % protection against a 51 % attack: impossible", "Protection à 100 % contre une attaque à 51 % : oui": "100 % protection against a 51 % attack: yes", "Un attaquant majoritaire peut :": "A majority attacker can:", "Il ne peut pas, même avec 99 % de la puissance :": "Even with 99 % of the power, it cannot:", "Finalité glissante :": "Sliding finality:", "Le consensus definit la chaine valide comme celle qui porte le plus de travail. Un majoritaire en produit plus que tous les autres, par definition. Refuser sa chaine supposerait de savoir que c'est lui : une identite, donc une autorite, donc la fin du caractere sans permission. C'est un theoreme, pas une lacune d'implementation.": "Consensus defines the valid chain as the one carrying the most work. A majority produces more of it than everyone else, by definition. Refusing its chain would require knowing that it is them: an identity, hence an authority, hence the end of permissionlessness. This is a theorem, not an implementation gap.", "reorganiser les blocs recents, donc annuler ses propres paiements": "reorganise recent blocks, and so undo its own payments", "refuser d'inclure certaines transactions": "refuse to include certain transactions", "voler une piece dont il n'a pas la clef": "steal a coin it holds no key for", "fabriquer une unite au-dela de la subvention": "create a single unit beyond the subsidy", "relever le plafond de 21 000 001": "raise the cap of 21 000 001", "changer une regle : ses blocs sont simplement rejetes": "change a rule: its blocks are simply rejected", "minage": "mining", "transfert": "transfer", "Frais": "Fees", "une coinbase les perçoit, elle n'en paie pas": "a coinbase collects them, it pays none", "payés au mineur": "paid to the miner", "non résolu sans index": "unresolved without an index", "État": "Status", "confirmée": "confirmed", "en attente": "pending", "dans le réservoir": "in the pool", "Création monétaire — cette transaction ne consomme rien": "Money creation — this transaction consumes nothing", "Transaction de minage": "Mining transaction", "Elle crée la subvention du bloc et récolte les frais des autres transactions. Elle ne consomme aucune sortie antérieure, et ce qu'elle produit n'est dépensable qu'après le délai de maturité — de sorte qu'un bloc annulé par une réorganisation n'ait pas déjà servi à payer quelqu'un.": "It creates the block subsidy and collects the fees of the other transactions. It consumes no earlier output, and what it produces can only be spent after the maturity delay — so that a block undone by a reorganisation has not already been used to pay someone.", "Frais non résolus": "Fees unresolved", "Une entrée au moins échappe à l'index de ce nœud — index absent, ou pièce trop ancienne pour lui. Les frais ne se calculent pas sur une somme partielle : la page préfère se taire plutôt qu'afficher un chiffre qu'elle n'a pas vérifié.": "At least one input escapes this node's index — no index, or a coin too old for it. Fees are not computed on a partial sum: the page would rather stay silent than show a figure it has not verified.", "Empreinte de clef": "Key fingerprint", "Solde": "Balance", "tous affichés": "all shown", "Reçu (affiché)": "Received (shown)", "Envoyé (affiché)": "Sent (shown)", "Historique complet": "Full history", "Historique borné": "Bounded history", "Historique complet : l'index d'adresses couvre toute la chaine.": "Full history: the address index covers the whole chain.", "Historique borne : ce noeud tourne sans index d'adresses. Les envois ne sont pas resolus, et la recherche s'arrete au plancher indique. Relancez-le avec --index-adresses pour une reponse complete.": "Bounded history: this node runs without an address index. Sends are not resolved, and the search stops at the floor shown. Restart it with --index-adresses for a complete answer.", "Le solde, lui, ne dépend d'aucun index : il vient de l'ensemble des sorties non dépensées que ce nœud a validé lui-même. Il est exact même quand l'historique ne l'est pas.": "The balance, however, depends on no index: it comes from the set of unspent outputs this node validated itself. It is exact even when the history is not.", "envoi": "sending", "réception": "receiving", "Aucun mouvement dans la portée de la recherche.": "No movement within the search range.", "Montant cherché": "Amount searched", "les 100 plus récentes": "the 100 most recent", "Fenêtre": "Window", "Recherche bornée": "Bounded search", "Aucune sortie de ce montant dans la fenêtre parcourue.": "No output of this amount in the window searched.", "recherche vide": "empty search", "recherche trop longue": "search too long", "hauteur illisible": "unreadable height", "montant illisible : au plus 8 decimales": "unreadable amount: at most 8 decimals", "ni bloc, ni transaction connue de ce noeud": "neither a block nor a transaction known to this node", "ni une hauteur, ni un identifiant de 64 caracteres hexadecimaux, ni une adresse valide": "neither a height, nor a 64-character hexadecimal identifier, nor a valid address", "index indisponible": "index unavailable", "transaction introuvable": "transaction not found", "bloc introuvable": "block not found", "trop de recherches en cours sur ce service public : reessayez dans une minute": "too many searches in progress on this public service: try again in a minute"}, "ja": {"Q21 — explorateur local": "Q21 — ローカル・エクスプローラー", "Explorateur servi par": "このエクスプローラーを提供しているのは", "votre nœud": "あなたのノード", ", en local. Aucune ressource externe n'est chargée : ce que vous lisez, votre machine l'a validé.": "です(ローカル動作)。外部リソースは一切読み込みません。表示内容はすべてあなたのマシンが検証したものです。", "hauteur, bloc, transaction, adresse ou montant (ex. 1.5)": "高さ、ブロック、トランザクション、アドレス、または金額(例:1.5)", "Chercher": "検索", "Un seul champ : le nœud reconnaît ce que vous collez.": "入力欄はひとつだけ。貼り付けた内容をノードが判別します。", "Recherche…": "検索中…", "Jeton d'accès requis": "アクセストークンが必要です", "Le nœud exige un jeton. Il est normalement transmis par le lanceur dans le fragment de l'adresse ; si vous avez ouvert cette page à la main, saisissez ici le jeton passé à": "ノードはトークンを要求しています。通常はランチャーがアドレスのフラグメントで渡します。このページを手動で開いた場合は、次のオプションに渡したトークンをここに入力してください:", "jeton d'accès": "アクセストークン", "Déverrouiller": "ロック解除", "Nœud injoignable": "ノードに接続できません", "Portefeuille": "ウォレット", "— servi par le même nœud, sur le même port.": "— 同じノード、同じポートで提供されています。", "API JSON-RPC sur": "JSON-RPC API:", "énumère les méthodes disponibles. Code de recherche, non audité : ne protège aucune valeur réelle.": "で利用できるメソッドを一覧できます。研究用のコードで未監査のため、実際の価値は一切保護しません。", "Chargement…": "読み込み中…", "Chaîne": "チェーン", "Monnaie": "通貨", "Preuve de travail": "プルーフ・オブ・ワーク", "Réseau": "ネットワーク", "Derniers blocs": "最新のブロック", "Réservoir de transactions": "トランザクションプール", "Ce que le protocole ne protège pas": "プロトコルが守らないもの", "Accueil": "ホーム", "→ bloc": "→ ブロック", "→ transaction": "→ トランザクション", "→ adresse": "→ アドレス", "→ montant": "→ 金額", "Bloc": "ブロック", "Transactions": "トランザクション", "Transaction": "トランザクション", "Adresse": "アドレス", "Mouvements": "入出金", "Recherche par montant": "金額で検索", "Sorties trouvées": "見つかった出力", "Oncles": "アンクル", "Hauteur": "高さ", "Identifiant": "識別子", "Identifiants": "識別子", "Taille": "サイズ", "Subvention": "補助金", "Horodatage": "タイムスタンプ", "Genre": "種類", "Entrées": "入力", "Sorties": "出力", "Valeur sortante": "出力額", "Poids": "重み", "Reçu": "受取", "Envoyé": "送金", "Conf.": "承認", "Montant": "金額", "Confirmations": "承認数", "Parent": "親ブロック", "Racine de Merkle": "マークル・ルート", "Mineur": "マイナー", "Nonce": "ナンス", "Difficulté": "難易度", "Tête": "先端", "Travail cumulé": "累積ワーク", "tentatives espérées": "期待試行回数", "Pairs": "ピア", "Blocs connus": "既知のブロック", "branches latérales comprises": "側枝を含む", "Émis": "発行済み", "Dans les UTXO": "UTXO内", "Plafond": "上限", "sous le plafond ✓": "上限以内 ✓", "PLAFOND FRANCHI": "上限超過", "Part émise": "発行割合", "Sorties non dépensées": "未使用出力", "Empreinte de l'état": "状態フィンガープリント", "Époque": "エポック", "Éléments de table": "テーブル要素数", "Mémoire du mineur": "マイナーのメモリ", "Mémoire du nœud": "ノードのメモリ", "Accès par tentative": "試行あたりのアクセス数", "Croissance": "増加", "Blocs reçus": "受信ブロック", "Blocs acceptés": "受理したブロック", "Annonces compactes": "コンパクト通知", "Reconstruits sans aller-retour": "往復なしで再構成", "Transactions reçues": "受信トランザクション", "Pairs bannis": "禁止されたピア", "Octets": "バイト", "Protection à 100 % contre une attaque à 51 % : impossible": "51 % 攻撃に対する 100 % の防御:不可能", "Protection à 100 % contre une attaque à 51 % : oui": "51 % 攻撃に対する 100 % の防御:可能", "Un attaquant majoritaire peut :": "過半数を握る攻撃者にできること:", "Il ne peut pas, même avec 99 % de la puissance :": "計算力の 99 % を握っていても、できないこと:", "Finalité glissante :": "スライディング・ファイナリティ:", "Le consensus definit la chaine valide comme celle qui porte le plus de travail. Un majoritaire en produit plus que tous les autres, par definition. Refuser sa chaine supposerait de savoir que c'est lui : une identite, donc une autorite, donc la fin du caractere sans permission. C'est un theoreme, pas une lacune d'implementation.": "コンセンサスは、最も多くのワークを持つチェーンを正当なチェーンと定めます。過半数を握る者は、定義上、他の全員より多くのワークを生み出します。そのチェーンを拒むには、それが誰かを知る必要があります。それは身元、つまり権威を意味し、許可不要という性質の終わりです。これは実装の欠陥ではなく、定理です。", "reorganiser les blocs recents, donc annuler ses propres paiements": "最近のブロックを再編成し、自分自身の支払いを取り消すこと", "refuser d'inclure certaines transactions": "特定のトランザクションの取り込みを拒むこと", "voler une piece dont il n'a pas la clef": "鍵を持たないコインを盗むこと", "fabriquer une unite au-dela de la subvention": "補助金を超えて 1 単位でも作り出すこと", "relever le plafond de 21 000 001": "21 000 001 の上限を引き上げること", "changer une regle : ses blocs sont simplement rejetes": "ルールを変えること:そのブロックは単に拒否されます", "minage": "マイニング", "transfert": "送金", "Frais": "手数料", "une coinbase les perçoit, elle n'en paie pas": "コインベースは手数料を受け取り、支払いはしません", "payés au mineur": "マイナーに支払い済み", "non résolu sans index": "インデックスなしでは未解決", "État": "状態", "confirmée": "承認済み", "en attente": "保留中", "dans le réservoir": "プール内", "Création monétaire — cette transaction ne consomme rien": "通貨の発行 — このトランザクションは何も消費しません", "Transaction de minage": "マイニング・トランザクション", "Elle crée la subvention du bloc et récolte les frais des autres transactions. Elle ne consomme aucune sortie antérieure, et ce qu'elle produit n'est dépensable qu'après le délai de maturité — de sorte qu'un bloc annulé par une réorganisation n'ait pas déjà servi à payer quelqu'un.": "ブロックの補助金を生み出し、他のトランザクションの手数料を集めます。以前の出力は何も消費せず、生み出したものは成熟期間を過ぎるまで使えません。これにより、再編成で取り消されたブロックが、すでに誰かへの支払いに使われていたという事態を防ぎます。", "Frais non résolus": "手数料は未解決", "Une entrée au moins échappe à l'index de ce nœud — index absent, ou pièce trop ancienne pour lui. Les frais ne se calculent pas sur une somme partielle : la page préfère se taire plutôt qu'afficher un chiffre qu'elle n'a pas vérifié.": "少なくとも 1 つの入力がこのノードのインデックスの対象外です(インデックスがないか、古すぎるコインです)。手数料は部分的な合計からは計算しません。検証していない数字を表示するより、何も表示しないことを選びます。", "Empreinte de clef": "鍵フィンガープリント", "Solde": "残高", "tous affichés": "すべて表示", "Reçu (affiché)": "受取(表示分)", "Envoyé (affiché)": "送金(表示分)", "Historique complet": "完全な履歴", "Historique borné": "範囲を限定した履歴", "Historique complet : l'index d'adresses couvre toute la chaine.": "完全な履歴:アドレス・インデックスがチェーン全体をカバーしています。", "Historique borne : ce noeud tourne sans index d'adresses. Les envois ne sont pas resolus, et la recherche s'arrete au plancher indique. Relancez-le avec --index-adresses pour une reponse complete.": "範囲を限定した履歴:このノードはアドレス・インデックスなしで動作しています。送金は解決されず、検索は表示された下限で止まります。完全な結果を得るには --index-adresses を付けて再起動してください。", "Le solde, lui, ne dépend d'aucun index : il vient de l'ensemble des sorties non dépensées que ce nœud a validé lui-même. Il est exact même quand l'historique ne l'est pas.": "一方、残高はインデックスに依存しません。このノード自身が検証した未使用出力の集合から得られるため、履歴が不完全なときでも正確です。", "envoi": "送金", "réception": "受取", "Aucun mouvement dans la portée de la recherche.": "検索範囲内に入出金はありません。", "Montant cherché": "検索した金額", "les 100 plus récentes": "最新の 100 件", "Fenêtre": "検索範囲", "Recherche bornée": "範囲を限定した検索", "Aucune sortie de ce montant dans la fenêtre parcourue.": "検索した範囲に、この金額の出力はありません。", "recherche vide": "検索語が空です", "recherche trop longue": "検索語が長すぎます", "hauteur illisible": "高さを読み取れません", "montant illisible : au plus 8 decimales": "金額を読み取れません:小数点以下は最大 8 桁です", "ni bloc, ni transaction connue de ce noeud": "このノードが知るブロックでもトランザクションでもありません", "ni une hauteur, ni un identifiant de 64 caracteres hexadecimaux, ni une adresse valide": "高さでも、64 文字の 16 進識別子でも、有効なアドレスでもありません", "index indisponible": "インデックスを利用できません", "transaction introuvable": "トランザクションが見つかりません", "bloc introuvable": "ブロックが見つかりません", "trop de recherches en cours sur ce service public : reessayez dans une minute": "この公開サービスでは検索が集中しています。1 分後にもう一度お試しください"}};
const I18N_MOTIFS = {
  "en": [
    [/^Bloc (\d+)$/, "Block $1"],
    [/^(\d+) confirmation\(s\)$/, "$1 confirmation(s)"],
    [/^(\d+) sortie\(s\) non dépensée\(s\)$/, "$1 unspent output(s)"],
    [/^(\d+) affiché\(s\)$/, "$1 shown"],
    [/^(\d+) % de témoin$/, "$1 % witness data"],
    [/^Entrées \((\d+)\)$/, "Inputs ($1)"],
    [/^Sorties \((\d+)\)$/, "Outputs ($1)"],
    [/^(\d+) \(plafonné\)$/, "$1 (capped)"],
    [/^blocs (\d+) → (\d+)$/, "blocks $1 → $2"],
    [/^(\d+) blocs au plus$/, "at most $1 blocks"],
    [/^\+([\d\s.,]+) % \/ ([\d\s.,]+) blocs$/, "+$1 % / $2 blocks"],
    [/^([\d.]+) Mio — la vérification n'en a pas besoin$/, "$1 MiB — verification does not need it"],
    [/^([\d.]+) Kio — la vérification n'en a pas besoin$/, "$1 KiB — verification does not need it"],
    [/^(\d+) o — la vérification n'en a pas besoin$/, "$1 B — verification does not need it"],
    [/^([\d.]+) Mio$/, "$1 MiB"],
    [/^([\d.]+) Kio$/, "$1 KiB"],
    [/^(\d+) o$/, "$1 B"],
    [/^(\d+) blocs \((\d+) h\)\. Elle ne supprime pas l'attaque, elle en change la nature\. Une partition reseau prolongee produit deux chaines qui ne se reconcilieront pas seules\. On echange une reecriture silencieuse contre une scission visible\.$/, "$1 blocks ($2 h). It does not remove the attack, it changes its nature. A prolonged network partition produces two chains that will not reconcile on their own. A silent rewrite is traded for a visible split."],
    [/^Recherche remontée jusqu'au bloc (\d+) sur (\d+)\. Le solde affiché reste exact : il vient de l'ensemble des sorties non dépensées, pas de cette liste\.$/, "Search went back to block $1 of $2. The balance shown stays exact: it comes from the set of unspent outputs, not from this list."],
    [/^Sans index par montant, la recherche remonte une fenêtre de (\d+) blocs — ici de (\d+) à (\d+)\. Une somme courante peut apparaître des milliers de fois : la liste est plafonnée aux 100 plus récentes\. Rapide, bornée, et la page dit jusqu'où elle est allée\.$/, "Without an amount index, the search goes back over a window of $1 blocks — here from $2 to $3. A common sum can appear thousands of times: the list is capped at the 100 most recent. Fast, bounded, and the page says how far it went."],
    [/^aucun bloc a la hauteur (\d+) : la chaine s'arrete plus bas$/, "no block at height $1: the chain stops lower"],
    [/^cette adresse appartient au reseau (\w+), ce noeud suit (\w+)$/, "this address belongs to the $1 network, this node follows $2"],
    [/^transaction introuvable dans les (\d+) derniers blocs\. Ce noeud n'a pas d'index par identifiant : au-dela, la recherche n'est pas rendue\.$/, "transaction not found in the last $1 blocks. This node has no index by identifier: beyond that, the search is not carried out."],
    [/^Impossible d'interroger le nœud : (.*)\. Si un jeton d'accès est configuré, l'explorateur le demandera\.$/, "Could not query the node: $1. If an access token is configured, the explorer will ask for it."]
  ],
  "ja": [
    [/^Bloc (\d+)$/, "ブロック $1"],
    [/^(\d+) confirmation\(s\)$/, "$1 回承認"],
    [/^(\d+) sortie\(s\) non dépensée\(s\)$/, "未使用出力 $1 件"],
    [/^(\d+) affiché\(s\)$/, "$1 件を表示"],
    [/^(\d+) % de témoin$/, "証人データ $1 %"],
    [/^Entrées \((\d+)\)$/, "入力($1)"],
    [/^Sorties \((\d+)\)$/, "出力($1)"],
    [/^(\d+) \(plafonné\)$/, "$1(上限あり)"],
    [/^blocs (\d+) → (\d+)$/, "ブロック $1 → $2"],
    [/^(\d+) blocs au plus$/, "最大 $1 ブロック"],
    [/^\+([\d\s.,]+) % \/ ([\d\s.,]+) blocs$/, "+$1 % / $2 ブロック"],
    [/^([\d.]+) Mio — la vérification n'en a pas besoin$/, "$1 MiB — 検証には不要です"],
    [/^([\d.]+) Kio — la vérification n'en a pas besoin$/, "$1 KiB — 検証には不要です"],
    [/^(\d+) o — la vérification n'en a pas besoin$/, "$1 B — 検証には不要です"],
    [/^([\d.]+) Mio$/, "$1 MiB"],
    [/^([\d.]+) Kio$/, "$1 KiB"],
    [/^(\d+) o$/, "$1 B"],
    [/^(\d+) blocs \((\d+) h\)\. Elle ne supprime pas l'attaque, elle en change la nature\. Une partition reseau prolongee produit deux chaines qui ne se reconcilieront pas seules\. On echange une reecriture silencieuse contre une scission visible\.$/, "$1 ブロック($2 時間)。攻撃をなくすのではなく、その性質を変えます。ネットワークの分断が長く続くと、自然には和解しない 2 本のチェーンが生まれます。気づかれない書き換えを、目に見える分裂と引き換えにするのです。"],
    [/^Recherche remontée jusqu'au bloc (\d+) sur (\d+)\. Le solde affiché reste exact : il vient de l'ensemble des sorties non dépensées, pas de cette liste\.$/, "検索はブロック $1(全 $2)まで遡りました。表示された残高は正確なままです。この一覧ではなく、未使用出力の集合から得られています。"],
    [/^Sans index par montant, la recherche remonte une fenêtre de (\d+) blocs — ici de (\d+) à (\d+)\. Une somme courante peut apparaître des milliers de fois : la liste est plafonnée aux 100 plus récentes\. Rapide, bornée, et la page dit jusqu'où elle est allée\.$/, "金額のインデックスがないため、検索は $1 ブロックの範囲を遡ります(今回は $2 から $3 まで)。よくある金額は何千回も現れることがあるため、一覧は最新の 100 件に制限されます。速く、範囲が限られ、どこまで調べたかをページが示します。"],
    [/^aucun bloc a la hauteur (\d+) : la chaine s'arrete plus bas$/, "高さ $1 のブロックはありません:チェーンはそれより手前で終わっています"],
    [/^cette adresse appartient au reseau (\w+), ce noeud suit (\w+)$/, "このアドレスは $1 ネットワークのもので、このノードは $2 を追っています"],
    [/^transaction introuvable dans les (\d+) derniers blocs\. Ce noeud n'a pas d'index par identifiant : au-dela, la recherche n'est pas rendue\.$/, "直近 $1 ブロック内にトランザクションが見つかりません。このノードには識別子のインデックスがないため、それ以上は検索しません。"],
    [/^Impossible d'interroger le nœud : (.*)\. Si un jeton d'accès est configuré, l'explorateur le demandera\.$/, "ノードに問い合わせできません:$1。アクセストークンが設定されている場合は、エクスプローラーが入力を求めます。"]
  ]
};
const I18N_PREFIXES = {"en": {"adresse illisible : ": "unreadable address: "}, "ja": {"adresse illisible : ": "アドレスを読み取れません:"}};
let LANGUE = "fr";

function q21Locale(){
  return LANGUE === "en" ? "en-US" : (LANGUE === "ja" ? "ja-JP" : "fr-FR");
}

function q21Norm(s){ return s.replace(/ /g, " ").replace(/\s+/g, " ").trim(); }

function q21Trad(src){
  const d = I18N[LANGUE];
  if (!d) return null;
  const n = q21Norm(src);
  let v = d[n];
  if (v === undefined){
    const pr = I18N_PREFIXES[LANGUE] || {};
    for (const k in pr){ if (n.startsWith(k)){ v = pr[k] + n.slice(k.length); break; } }
  }
  if (v === undefined){
    for (const [motif, modele] of (I18N_MOTIFS[LANGUE] || [])){
      if (motif.test(n)){ v = n.replace(motif, modele); break; }
    }
  }
  if (v === undefined) return null;
  const av = src.match(/^\s*/)[0], ap = src.match(/\s*$/)[0];
  return av + v + ap;
}

function q21TraduireTexte(n){
  // Meme distinction que dans le portefeuille : une valeur que nous avons posee
  // nous-memes n'est pas une nouvelle source. Sans cela, un rafraichissement
  // ferait traduire une traduction.
  if (n.__q21pose === undefined || n.nodeValue !== n.__q21pose) n.__q21fr = n.nodeValue;
  let v = n.__q21fr;
  if (LANGUE !== "fr"){ const t = q21Trad(n.__q21fr); if (t !== null) v = t; }
  if (n.nodeValue !== v) n.nodeValue = v;
  n.__q21pose = v;
}

const Q21_ATTRS = ["placeholder", "title", "aria-label"];

function q21Traduire(n){
  if (!n) return;
  if (n.nodeType === 3){ q21TraduireTexte(n); return; }
  if (n.nodeType !== 1) return;
  const t = n.tagName;
  if (t === "SCRIPT" || t === "STYLE") return;
  if (n.id !== "langues"){
    for (const a of Q21_ATTRS){
      if (!n.hasAttribute(a)) continue;
      const cle = "__q21a_" + a;
      if (n[cle] === undefined) n[cle] = n.getAttribute(a);
      let v = n[cle];
      if (LANGUE !== "fr"){ const x = q21Trad(n[cle]); if (x !== null) v = x; }
      if (n.getAttribute(a) !== v) n.setAttribute(a, v);
    }
  }
  if (n.id === "langues") return;
  for (const e of n.childNodes) q21Traduire(e);
}

let q21Titre = null;

function q21AppliquerLangue(code){
  LANGUE = (code === "en" || code === "ja") ? code : "fr";
  document.documentElement.lang = LANGUE;
  try { sessionStorage.setItem("q21-langue", LANGUE); } catch (e) {}
  if (q21Titre === null) q21Titre = document.title;
  const titre = LANGUE === "fr" ? null : q21Trad(q21Titre);
  document.title = titre === null ? q21Titre : titre;
  q21Traduire(document.body);
  const g = document.getElementById("langues");
  if (g) for (const b of g.querySelectorAll("button"))
    b.setAttribute("aria-pressed", b.dataset.langue === LANGUE ? "true" : "false");
}

(function q21InitLangue(){
  let choix = null;
  try { choix = sessionStorage.getItem("q21-langue"); } catch (e) {}
  if (!choix){
    const n = (navigator.language || "fr").slice(0, 2).toLowerCase();
    choix = (n === "en" || n === "ja") ? n : "fr";
  }
  const demarrer = function(){
    const g = document.getElementById("langues");
    if (g) g.addEventListener("click", function(ev){
      const b = ev.target.closest("button[data-langue]");
      if (b) q21AppliquerLangue(b.dataset.langue);
    });
    q21AppliquerLangue(choix);
    // Ce que le script ecrit ensuite — chaque vue, chaque rafraichissement de
    // l'accueil — doit etre traduit aussi.
    new MutationObserver(function(ms){
      if (LANGUE === "fr") return;
      for (const m of ms){
        if (m.type === "characterData") q21Traduire(m.target);
        else for (const n of m.addedNodes) q21Traduire(n);
      }
    }).observe(document.body, {childList:true, subtree:true, characterData:true});
  };
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", demarrer);
  else demarrer();
})();

// ---------------------------------------------------------------------------
// Le jeton, et le fragment qu'il partage avec le routage
//
// Le jeton ne voyage pas dans la requete : une adresse finit dans l'historique
// du navigateur, dans les journaux de tout mandataire, et dans l'en-tete
// Referer de la premiere ressource externe chargee. Il arrive dans le
// **fragment**, que le navigateur ne transmet jamais au serveur.
//
// Ce fragment sert aussi au routage. Les deux ne se confondent pas : une route
// commence toujours par une barre oblique, un jeton jamais. Le jeton est lu une
// fois, range sous cette origine, et le fragment rendu au routage.
//
// Le rangement est `localStorage`, cloisonne par port : depuis que le lien du
// lanceur ne sert qu'une fois, un onglet ferme doit pouvoir se rouvrir tant
// que le programme tourne. Le jeton est tire a chaque execution et meurt avec
// elle ; ce qui reste dans le navigateur ensuite n'ouvre plus rien, et le
// premier 401 l'efface.
// ---------------------------------------------------------------------------
const RPC = "/rpc";
const CLEF_SESSION = "q21-jeton-explorateur";
let jeton = null;
let compteur = 0;

function rangement(){
  try { return window.localStorage; } catch (e) { return null; }
}

function jetonRange(){
  try { const r = rangement(); return r ? r.getItem(CLEF_SESSION) : null; } catch (e) { return null; }
}

function retenirJeton(v){
  jeton = v;
  try { const r = rangement(); if (v && r) r.setItem(CLEF_SESSION, v); } catch (e) {}
}

function oublierJeton(){
  jeton = null;
  try { const r = rangement(); if (r) r.removeItem(CLEF_SESSION); } catch (e) {}
}

// Ce que le lanceur met dans le fragment est une amorce a usage unique, pas le
// jeton : l'adresse passe par la ligne de commande du navigateur, lisible par
// d'autres comptes. La page l'echange contre le jeton de session, et les
// appels attendent que ce soit fait. Si l'echange echoue — lien deja servi —
// la page reprend le jeton range sous cette origine s'il y en a un ; sinon le
// 401 qui suit ouvre le panneau de saisie, comme pour une ouverture a la main.
let echange = null;

async function echangerAmorce(amorce){
  try {
    const r = await fetch("/session", {method:"POST",
      headers:{"Content-Type":"application/json", "Authorization":"Bearer " + amorce}});
    if (r.ok){ const d = await r.json(); retenirJeton(d.jeton); return; }
  } catch (e) {}
  const garde = jetonRange();
  if (garde) jeton = garde;
}

(function lireJeton(){
  const f = location.hash.slice(1);
  if (f && !f.startsWith("/")){
    // On efface aussitot : une capture d'ecran ou un partage d'onglet ne
    // doivent pas emporter le secret.
    history.replaceState(null, "", location.pathname + "#/");
    echange = echangerAmorce(decodeURIComponent(f));
    return;
  }
  const garde = jetonRange();
  if (garde) jeton = garde;
})();

function entetes(){
  const h = {"Content-Type":"application/json"};
  if (jeton) h["Authorization"] = "Bearer " + jeton;
  return h;
}

let attenteJeton = null;
function demanderJeton(){
  if (attenteJeton) return attenteJeton;
  const panneau = document.getElementById("panneau-jeton");
  panneau.hidden = false;
  document.getElementById("saisie-jeton").focus();
  attenteJeton = new Promise(resoudre => {
    document.getElementById("forme-jeton").addEventListener("submit", ev => {
      ev.preventDefault();
      const v = document.getElementById("saisie-jeton").value.trim();
      if (!v) return;
      retenirJeton(v);
      panneau.hidden = true;
      document.getElementById("saisie-jeton").value = "";
      attenteJeton = null;
      resoudre();
    }, {once:true});
  });
  return attenteJeton;
}

async function appel(methode, params){
  if (echange){ await echange; echange = null; }
  const r = await fetch(RPC, {
    method:"POST",
    headers: entetes(),
    body: JSON.stringify({jsonrpc:"2.0", id:++compteur, method:methode, params:params||{}})
  });
  if (r.status === 401){
    oublierJeton();
    await demanderJeton();
    return appel(methode, params);
  }
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

// ---------------------------------------------------------------------------
// Rendu
//
// `v` et `n` etaient inseres bruts : l'invariant ne tenait qu'a la discipline de
// chaque appelant. Un champ que l'explorateur croit numerique peut arriver en
// chaine — `Json::u64` bascule en chaine au-dela de i64::MAX — et devenir une
// injection. On echappe par defaut ; le fragment de balisage voulu se declare.
// ---------------------------------------------------------------------------
const ech = s => String(s).replace(/[&<>"']/g, c =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const court = (h,n)=> h ? ech(h.slice(0,n||16))+"…" : "—";
const octets = n => n>=1048576 ? (n/1048576).toFixed(2)+" Mio"
                 : n>=1024 ? (n/1024).toFixed(1)+" Kio" : n+" o";
const date = t => new Date(t*1000).toISOString().replace("T"," ").slice(0,19);
const brut = h => ({__html: h});
const rendu = x => (x && x.__html !== undefined) ? x.__html : ech(x);

// Un lien de navigation. La cible est echappee comme le reste : une adresse ou
// un identifiant venus du noeud restent des donnees.
// Les deux moities sont echappees : la route comme le texte. Un identifiant ou
// une adresse viennent du noeud, mais rien n'oblige un noeud a etre honnete —
// et cette page est aussi celle qu'on ouvrira un jour sur la chaine d'un autre.
const lien = (route, texte) =>
  `<a class="plat" href="#/${ech(route)}">${ech(texte)}</a>`;
const lienBloc = h => lien("bloc/"+h, h);
const lienTx = (id,n) => lien("tx/"+id, (id||"").slice(0,n||16)+"…");
const lienAdresse = (a,n) => a ? lien("adresse/"+a, n ? a.slice(0,n)+"…" : a) : "—";

// Etiquette. Rend directement du balisage marque `brut`, parce que c'est la
// seule facon de ne pas se tromper.
//
// Le defaut repare ici : la tuile « Etat » recevait sa chaine `<span
// class="badge">confirmee</span>` telle quelle. `tuile` echappe par defaut —
// c'est la bonne direction, celle qui protege — et la page affichait donc son
// propre balisage en clair, a l'ecran, sous les yeux du premier utilisateur qui
// a ouvert une transaction.
//
// Ecrire du balisage a la main dans un argument est l'erreur ; on ne la corrige
// pas en ajoutant `brut` a cet endroit-la, mais en donnant une fonction qui
// fabrique l'etiquette et se charge du marquage. Une epreuve verifie qu'aucun
// appel a `tuile` ne contient de balisage sans passer par `brut`.
const badge = (texte, gris) =>
  brut(`<span class="badge${gris ? " gris" : ""}">${ech(texte)}</span>`);

function tuile(k,v,n){
  return `<div class="tuile"><div class="k">${ech(k)}</div>
          <div class="v">${rendu(v)}</div>${n?`<div class="n">${rendu(n)}</div>`:""}</div>`;
}
function lignes(cible, paires){
  document.getElementById(cible).innerHTML =
    paires.map(([k,v])=>`<tr><th>${ech(k)}</th><td>${rendu(v)}</td></tr>`).join("");
}
function signalerErreur(message){
  document.getElementById("erreur").hidden = false;
  document.getElementById("erreur-detail").textContent = message;
}
function effacerErreur(){ document.getElementById("erreur").hidden = true; }

// ---------------------------------------------------------------------------
// Routage
//
// Tout se joue dans le fragment : aucune requete au serveur pour changer de
// page, et la page reste un fichier unique servi tel quel. Le bouton « page
// precedente » du navigateur fonctionne sans qu'on ait rien a ecrire.
// ---------------------------------------------------------------------------
let battement = null;

function montrer(vue){
  for (const s of document.querySelectorAll(".vue")) s.hidden = true;
  document.getElementById("vue-" + vue).hidden = false;
  // L'accueil se rafraichit ; les pages de detail sont figees, parce qu'un
  // bloc passe ne change plus et qu'une page qui se recharge sous les yeux
  // pendant qu'on la lit est une nuisance.
  if (battement){ clearInterval(battement); battement = null; }
  if (vue === "accueil") battement = setInterval(accueil, 4000);
}

async function routeur(){
  const f = location.hash.slice(1);
  if (f && !f.startsWith("/")) return; // un jeton, pas une route
  const bouts = f.replace(/^\//, "").split("/").filter(x => x.length);
  // L'etiquette du reseau n'etait remplie que par l'accueil : arrive par un
  // lien direct vers un bloc ou une transaction, on lisait « … » en haut de la
  // page. On la remplit une fois, sans faire attendre la vue.
  const etiquette = document.getElementById("reseau");
  if (etiquette.textContent === "…")
    appel("getinfo").then(i => { etiquette.textContent = i.reseau; }).catch(() => {});
  try{
    if (!bouts.length){ montrer("accueil"); await accueil(); return; }
    switch (bouts[0]){
      case "bloc":    montrer("bloc");    await voirBloc(decodeURIComponent(bouts[1]||"")); break;
      case "tx":      montrer("tx");      await voirTx(decodeURIComponent(bouts[1]||"")); break;
      case "adresse": montrer("adresse"); await voirAdresse(decodeURIComponent(bouts[1]||"")); break;
      case "montant": montrer("montant"); await voirMontant(decodeURIComponent(bouts[1]||"")); break;
      default:        location.hash = "#/";
    }
  }catch(e){
    signalerErreur(e.message);
  }
}

window.addEventListener("hashchange", routeur);

document.getElementById("forme-chercher").addEventListener("submit", async ev => {
  ev.preventDefault();
  const q = document.getElementById("saisie-chercher").value.trim();
  if (!q) return;
  const aide = document.getElementById("aide-chercher");
  aide.textContent = "Recherche…";
  try{
    const r = await appel("rechercher", {q});
    aide.textContent = "Un seul champ : le nœud reconnaît ce que vous collez.";
    document.getElementById("saisie-chercher").value = "";
    if (r.genre === "bloc")            location.hash = "#/bloc/" + encodeURIComponent(r.valeur);
    else if (r.genre === "bloc-id")    location.hash = "#/bloc/" + encodeURIComponent(r.valeur);
    else if (r.genre === "transaction")location.hash = "#/tx/" + encodeURIComponent(r.valeur);
    else if (r.genre === "adresse")    location.hash = "#/adresse/" + encodeURIComponent(r.valeur);
    else if (r.genre === "montant")    location.hash = "#/montant/" + encodeURIComponent(r.valeur);
  }catch(e){
    aide.innerHTML = `<span class="err">${ech(e.message)}</span>`;
  }
});

// ---------------------------------------------------------------------------
// Accueil
// ---------------------------------------------------------------------------

async function accueil(){
  try{
    const [info, supply, pow, sec, mem, emp] = await Promise.all([
      appel("getinfo"), appel("getsupply"), appel("getpow"),
      appel("getsecurity"), appel("getmempool"), appel("getempreinteutxo")
    ]);
    effacerErreur();
    document.getElementById("reseau").textContent = info.reseau;

    // Le lien vers le portefeuille n'apparait que si ce noeud le sert
    // reellement. `q21 explorateur` n'expose aucune methode de portefeuille :
    // afficher le lien y menerait a une page qui ne pourrait rien demander, et
    // qui aurait l'air cassee alors qu'elle serait simplement au mauvais
    // endroit.
    const pied = document.getElementById("pied-portefeuille");
    if (info.portefeuille_actif){
      pied.hidden = false;
      if (jeton) document.getElementById("lien-portefeuille").href =
        "/portefeuille#" + encodeURIComponent(jeton);
    }

    document.getElementById("tuiles").innerHTML =
      tuile("Hauteur", brut(lienBloc(info.hauteur))) +
      tuile("Tête", brut(`<span class="coupe">${lien("bloc/"+info.tete, info.tete.slice(0,20)+"…")}</span>`)) +
      tuile("Travail cumulé", "2^" + info.travail_cumule_bits, "tentatives espérées") +
      tuile("Difficulté", ech(info.difficulte_bits)) +
      tuile("Pairs", info.pairs) +
      tuile("Blocs connus", info.blocs_connus, "branches latérales comprises");

    const pct = (supply.emis.unites * 100 / supply.plafond.unites);
    document.getElementById("monnaie").innerHTML =
      tuile("Émis", ech(supply.emis.q21) + " Q21") +
      tuile("Dans les UTXO", ech(supply.dans_les_utxo.q21) + " Q21") +
      tuile("Plafond", supply.plafond_q21.toLocaleString("fr-FR"),
            supply.sous_le_plafond ? "sous le plafond ✓" : "PLAFOND FRANCHI") +
      tuile("Part émise", pct.toFixed(6) + " %") +
      tuile("Sorties non dépensées", info.utxo_total) +
      tuile("Empreinte de l'état", court(emp.empreinte, 20), ech(emp.empreinte));

    lignes("pow", [
      ["Époque", pow.epoque],
      ["Éléments de table", pow.elements_table.toLocaleString("fr-FR")],
      ["Mémoire du mineur", octets(pow.memoire_mineur_octets)],
      ["Mémoire du nœud", octets(pow.memoire_noeud_octets) + " — la vérification n'en a pas besoin"],
      ["Accès par tentative", pow.acces_par_tentative],
      ["Croissance", "+" + pow.croissance_pourcent + " % / " + pow.blocs_par_epoque.toLocaleString("fr-FR") + " blocs"]
    ]);

    const s = info.reseau_stats;
    lignes("reseau-stats", [
      ["Blocs reçus", s.blocs_recus],
      ["Blocs acceptés", s.blocs_acceptes],
      ["Annonces compactes", s.compacts_recus],
      ["Reconstruits sans aller-retour", s.compacts_sans_aller_retour],
      ["Transactions reçues", s.tx_recues],
      ["Pairs bannis", s.pairs_bannis]
    ]);

    lignes("mempool", [
      ["Transactions", mem.nb_transactions],
      ["Octets", octets(mem.octets)],
      ["Identifiants", brut(mem.txids.length
          ? mem.txids.map(t=>lienTx(t,12)).join(" ")
          : "—")]
    ]);

    const debut = Math.max(0, info.hauteur - 11);
    const blocs = await Promise.all(
      Array.from({length: info.hauteur - debut + 1}, (_,i)=>
        appel("getblock", {hauteur: info.hauteur - i}))
    );
    document.getElementById("blocs").innerHTML = blocs.map(b=>`
      <tr>
        <td>${lienBloc(b.entete.hauteur)}</td>
        <td><span class="coupe">${lien("bloc/"+b.entete.id, b.entete.id.slice(0,24)+"…")}</span></td>
        <td>${b.nb_transactions}</td>
        <td>${octets(b.taille_octets)}</td>
        <td>${ech(b.subvention.q21)}</td>
        <td>${date(b.entete.horodatage)}</td>
      </tr>`).join("");

    document.getElementById("securite").innerHTML = `
      <h3>Protection à 100 % contre une attaque à 51 %&nbsp;: ${sec.protection_100_pourcent_possible ? "oui" : "impossible"}</h3>
      <p>${ech(sec.pourquoi)}</p>
      <p><strong>Un attaquant majoritaire peut&nbsp;:</strong></p>
      <ul>${sec.un_attaquant_peut.map(x=>`<li>${ech(x)}</li>`).join("")}</ul>
      <p><strong>Il ne peut pas, même avec 99 % de la puissance&nbsp;:</strong></p>
      <ul>${sec.un_attaquant_ne_peut_pas.map(x=>`<li>${ech(x)}</li>`).join("")}</ul>
      <p><strong>Finalité glissante&nbsp;:</strong> ${sec.defenses.finalite_glissante_blocs}
         blocs (${sec.defenses.finalite_glissante_heures} h).
         ${ech(sec.cout_de_la_finalite_glissante)}</p>`;
  }catch(e){
    signalerErreur("Impossible d'interroger le nœud : " + e.message +
      ". Si un jeton d'accès est configuré, l'explorateur le demandera.");
  }
}

// ---------------------------------------------------------------------------
// Bloc
// ---------------------------------------------------------------------------

const estHexa = s => /^[0-9a-fA-F]{64}$/.test(s);

async function voirBloc(cle){
  effacerErreur();
  const params = estHexa(cle) ? {id: cle} : {hauteur: Number(cle)};
  const b = await appel("getblock", params);
  const e = b.entete;
  document.getElementById("bloc-titre").textContent = "Bloc " + e.hauteur;

  const info = await appel("getinfo");
  const confirmations = info.hauteur - e.hauteur + 1;

  document.getElementById("bloc-tuiles").innerHTML =
    tuile("Hauteur", brut(lienBloc(e.hauteur))) +
    tuile("Transactions", b.nb_transactions) +
    tuile("Taille", octets(b.taille_octets)) +
    tuile("Subvention", ech(b.subvention.q21) + " Q21") +
    tuile("Confirmations", confirmations) +
    tuile("Oncles", b.oncles.length);

  lignes("bloc-entete", [
    ["Identifiant", brut(`<span class="mono">${ech(e.id)}</span>`)],
    ["Parent", brut(e.hauteur > 0 ? lien("bloc/"+e.parent, e.parent) : "—")],
    ["Racine de Merkle", brut(`<span class="mono">${ech(e.merkle)}</span>`)],
    ["Mineur", brut(`<span class="mono">${ech(e.mineur)}</span>`)],
    ["Horodatage", date(e.horodatage) + " UTC"],
    ["Difficulté", e.bits],
    ["Nonce", e.nonce]
  ]);

  document.getElementById("bloc-transactions").innerHTML = b.transactions.map((t,i)=>{
    const sortant = t.sorties.reduce((a,o)=>a + BigInt(o.valeur.unites), 0n);
    return `<tr>
      <td>${ech(i)}</td>
      <td><span class="coupe">${lienTx(t.txid, 24)}</span></td>
      <td>${t.coinbase ? '<span class="badge">minage</span>' : '<span class="badge gris">transfert</span>'}</td>
      <td>${ech(t.entrees.length)}</td>
      <td>${ech(t.sorties.length)}</td>
      <td>${ech(q21(sortant))}</td>
      <td>${ech(t.poids)}</td>
    </tr>`;
  }).join("");

  document.getElementById("bloc-oncles").innerHTML = b.oncles.length
    ? `<h2>Oncles</h2><div class="defile"><table><thead><tr><th>Hauteur</th><th>Identifiant</th><th>Mineur</th></tr></thead><tbody>` +
      b.oncles.map(o=>`<tr><td>${ech(o.hauteur)}</td><td><span class="coupe">${ech(o.id)}</span></td><td><span class="coupe">${court(o.mineur,20)}</span></td></tr>`).join("") +
      `</tbody></table></div>`
    : "";
}

// Conversion d'unites vers Q21, en entiers uniquement.
//
// Un montant ne passe jamais par un flottant : 0,1 + 0,2 ne fait pas 0,3 en
// virgule flottante binaire, et une chaine de blocs qui arrondit un solde n'est
// plus une chaine de blocs.
function q21(unites){
  const u = BigInt(unites);
  const neg = u < 0n;
  const a = neg ? -u : u;
  const ent = a / 100000000n;
  const dec = (a % 100000000n).toString().padStart(8, "0");
  return (neg ? "-" : "") + ent.toString() + "." + dec;
}

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

async function voirTx(txid){
  effacerErreur();
  const r = await appel("gettransaction", {txid});
  const t = r.transaction;
  const info = await appel("getinfo");
  const sortant = t.sorties.reduce((a,o)=>a + BigInt(o.valeur.unites), 0n);

  // Les frais : ce que les entrées apportent moins ce que les sorties emportent.
  // Le nœud les résout par son index ; sans lui, ou pour une pièce trop
  // ancienne, `frais_connu` est faux et l'on ne montre pas un chiffre inventé.
  const fraisTuile = t.coinbase
    ? tuile("Frais", "—", "une coinbase les perçoit, elle n'en paie pas")
    : (r.frais_connu
        ? tuile("Frais", ech(r.frais.q21) + " Q21", "payés au mineur")
        : tuile("Frais", "—", "non résolu sans index"));

  document.getElementById("tx-tuiles").innerHTML =
    tuile("Identifiant", brut(`<span class="coupe">${ech(t.txid.slice(0,20))}…</span>`), t.txid) +
    tuile("État", badge(r.confirmee ? "confirmée" : "en attente", !r.confirmee),
      r.confirmee ? (info.hauteur - r.hauteur + 1) + " confirmation(s)" : "dans le réservoir") +
    tuile("Bloc", brut(r.confirmee ? lienBloc(r.hauteur) : "—")) +
    tuile("Valeur sortante", q21(sortant) + " Q21") +
    fraisTuile +
    tuile("Taille", octets(t.taille_octets), t.temoin_pourcent + " % de témoin") +
    tuile("Poids", t.poids.toLocaleString("fr-FR"));

  // Chaque entrée porte maintenant le montant de la sortie qu'elle consomme,
  // quand l'index a su le retrouver. Un « ? » dit honnêtement « non résolu ».
  const mont = r.entrees_montants || [];
  document.getElementById("tx-entrees").innerHTML =
    `<div class="t">Entrées (${ech(t.entrees.length)})</div>` +
    (t.coinbase
      ? `<div class="l"><span class="g">Création monétaire — cette transaction ne consomme rien</span></div>`
      : t.entrees.map((e,i)=>{
          const m = mont[i] || {};
          const v = (m.connu && m.valeur) ? m.valeur.q21 : "?";
          return `
        <div class="l">
          <span class="g">${lienTx(e.txid, 18)}<span style="color:var(--tenu)"> : ${ech(e.index)}</span></span>
          <span class="d">${ech(v)}</span>
        </div>`;}).join(""));

  document.getElementById("tx-sorties").innerHTML =
    `<div class="t">Sorties (${ech(t.sorties.length)})</div>` +
    t.sorties.map(o=>`
      <div class="l">
        <span class="g">${lienAdresse(o.adresse, 22)}</span>
        <span class="d">${ech(o.valeur.q21)}</span>
      </div>`).join("");

  document.getElementById("tx-note").innerHTML = t.coinbase
    ? `<div class="avert info"><h3>Transaction de minage</h3>
       <p>Elle crée la subvention du bloc et récolte les frais des autres
       transactions. Elle ne consomme aucune sortie antérieure, et ce qu'elle
       produit n'est dépensable qu'après le délai de maturité — de sorte qu'un
       bloc annulé par une réorganisation n'ait pas déjà servi à payer
       quelqu'un.</p></div>`
    : (r.frais_connu
        ? ""
        : `<div class="avert info"><h3>Frais non résolus</h3>
       <p>Une entrée au moins échappe à l'index de ce nœud — index absent, ou
       pièce trop ancienne pour lui. Les frais ne se calculent pas sur une somme
       partielle&nbsp;: la page préfère se taire plutôt qu'afficher un chiffre
       qu'elle n'a pas vérifié.</p></div>`);
}

// ---------------------------------------------------------------------------
// Adresse
// ---------------------------------------------------------------------------

async function voirAdresse(adresse){
  effacerErreur();
  const a = await appel("getadresse", {adresse, max: 100});

  lignes("adresse-identite", [
    ["Adresse", brut(`<span class="mono" style="word-break:break-all;white-space:normal">${ech(a.adresse)}</span>`)],
    ["Empreinte de clef", brut(`<span class="mono" style="word-break:break-all;white-space:normal">${ech(a.empreinte)}</span>`)]
  ]);

  const recu = a.mouvements.reduce((s,m)=>s + BigInt(m.recu.unites), 0n);
  const envoye = a.mouvements.reduce((s,m)=>s + BigInt(m.envoye.unites), 0n);

  document.getElementById("adresse-tuiles").innerHTML =
    tuile("Solde", ech(a.solde.q21) + " Q21", a.sorties_non_depensees + " sortie(s) non dépensée(s)") +
    tuile("Mouvements", a.mouvements_total,
          a.mouvements.length < a.mouvements_total
            ? a.mouvements.length + " affiché(s)" : "tous affichés") +
    tuile("Reçu (affiché)", q21(recu) + " Q21") +
    tuile("Envoyé (affiché)", a.montants_sortants_tous_resolus
            ? q21(envoye) + " Q21" : "—",
          a.montants_sortants_tous_resolus ? null : "non résolu sans index");

  // L'honnetete de la reponse est affichee, pas devinee : une adresse dont
  // l'historique est borne ressemble sinon a une adresse sans passe.
  document.getElementById("adresse-note").innerHTML = a.historique_complet
    ? `<div class="avert info"><h3>Historique complet</h3><p>${ech(a.note)}</p>
       <p>Le solde, lui, ne dépend d'aucun index&nbsp;: il vient de l'ensemble
       des sorties non dépensées que ce nœud a validé lui-même. Il est exact
       même quand l'historique ne l'est pas.</p></div>`
    : `<div class="avert"><h3>Historique borné</h3><p>${ech(a.note)}</p>
       <p>Recherche remontée jusqu'au bloc ${ech(a.plancher)} sur ${ech(a.hauteur)}.
       Le solde affiché reste exact&nbsp;: il vient de l'ensemble des sorties
       non dépensées, pas de cette liste.</p></div>`;

  document.getElementById("adresse-mouvements").innerHTML = a.mouvements.length
    ? a.mouvements.map(m=>`
      <tr>
        <td>${m.coinbase ? '<span class="badge">minage</span>'
             : (BigInt(m.envoye.unites) > 0n ? '<span class="badge gris">envoi</span>'
                                             : '<span class="badge gris">réception</span>')}</td>
        <td>${BigInt(m.recu.unites) > 0n ? ech(m.recu.q21) : "—"}</td>
        <td>${!m.montant_sortant_connu ? '<span style="color:var(--tenu)">?</span>'
             : (BigInt(m.envoye.unites) > 0n ? ech(m.envoye.q21) : "—")}</td>
        <td>${ech(m.confirmations)}</td>
        <td>${lienBloc(m.hauteur)}</td>
        <td>${date(m.horodatage)}</td>
        <td><span class="coupe">${lienTx(m.txid, 18)}</span></td>
      </tr>`).join("")
    : `<tr><td colspan="7" style="color:var(--tenu)">Aucun mouvement dans la portée de la recherche.</td></tr>`;
}

// ---------------------------------------------------------------------------
// Montant
// ---------------------------------------------------------------------------

async function voirMontant(m){
  effacerErreur();
  const r = await appel("getmontant", {montant: m});

  document.getElementById("montant-tuiles").innerHTML =
    tuile("Montant cherché", ech(r.montant.q21) + " Q21") +
    tuile("Sorties trouvées", r.resultats.length + (r.plafonne ? " (plafonné)" : ""),
          r.plafonne ? "les 100 plus récentes" : null) +
    tuile("Fenêtre", "blocs " + ech(r.depuis) + " → " + ech(r.hauteur),
          ech(r.fenetre) + " blocs au plus");

  // Le même honnête « voilà jusqu'où j'ai cherché » que le reste de la page.
  document.getElementById("montant-note").innerHTML =
    `<div class="avert info"><h3>Recherche bornée</h3>
     <p>Sans index par montant, la recherche remonte une fenêtre de ${ech(r.fenetre)}
     blocs — ici de ${ech(r.depuis)} à ${ech(r.hauteur)}. Une somme courante peut
     apparaître des milliers de fois&nbsp;: la liste est plafonnée aux 100 plus
     récentes. Rapide, bornée, et la page dit jusqu'où elle est allée.</p></div>`;

  document.getElementById("montant-lignes").innerHTML = r.resultats.length
    ? r.resultats.map(s=>`
      <tr>
        <td><span class="coupe">${lienTx(s.txid, 18)}</span></td>
        <td>${lienBloc(s.hauteur)}</td>
        <td>${lienAdresse(s.adresse, 22)}</td>
        <td>${ech(s.valeur.q21)}</td>
      </tr>`).join("")
    : `<tr><td colspan="4" style="color:var(--tenu)">Aucune sortie de ce montant dans la fenêtre parcourue.</td></tr>`;
}

// ---------------------------------------------------------------------------

routeur();
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    /// Extrait le contenu du bloc `<script>` de la page.
    fn script() -> &'static str {
        let debut = PAGE.find("<script>").expect("bloc script") + "<script>".len();
        let fin = PAGE.find("</script>").expect("fin du bloc script");
        &PAGE[debut..fin]
    }

    #[test]
    fn la_page_ne_charge_aucune_ressource_externe() {
        // Un explorateur qui appelle un CDN transmet a ce CDN la liste de tout
        // ce que l'on consulte. La verification est grossiere mais elle attrape
        // l'erreur la plus probable : une police ou un script ajoute plus tard.
        for interdit in [
            "http://",
            "https://",
            "//cdn",
            "fonts.googleapis",
            "unpkg",
            "jsdelivr",
        ] {
            assert!(
                !PAGE.contains(interdit),
                "la page reference une ressource externe : {interdit}"
            );
        }
    }

    #[test]
    fn la_page_est_bien_formee() {
        assert!(PAGE.starts_with("<!doctype html>"));
        assert!(PAGE.trim_end().ends_with("</html>"));
        assert_eq!(
            PAGE.matches("<script").count(),
            PAGE.matches("</script>").count()
        );
        assert_eq!(
            PAGE.matches("<style").count(),
            PAGE.matches("</style>").count()
        );
    }

    /// L'explorateur se traduit comme le portefeuille, et garde la langue.
    ///
    /// Regression v0.2.0 : la langue choisie dans le portefeuille se perdait en
    /// ouvrant l'explorateur, qui n'avait aucun moyen de traduction.
    #[test]
    fn l_explorateur_se_traduit_et_garde_la_langue() {
        let s = script();
        for piece in [
            "const I18N =",
            "const I18N_MOTIFS =",
            "const I18N_PREFIXES =",
            "function q21Trad(",
            "function q21AppliquerLangue(",
            "new MutationObserver(",
            r#"sessionStorage.getItem("q21-langue")"#,
            r#"sessionStorage.setItem("q21-langue", LANGUE)"#,
        ] {
            assert!(
                s.contains(piece),
                "moteur de traduction incomplet : {piece}"
            );
        }
        assert!(
            PAGE.contains(r#"id="langues""#),
            "selecteur de langue absent"
        );
        for code in ["fr", "en", "ja"] {
            assert!(
                PAGE.contains(&format!(r#"data-langue="{code}""#)),
                "langue {code} absente du selecteur"
            );
        }
        // Les libelles principaux ont bien leur traduction dans les deux langues.
        let debut = s.find("const I18N =").expect("dictionnaire");
        let fin = debut + s[debut..].find('\n').expect("fin du dictionnaire");
        let dico = &s[debut..fin];
        for cle in [
            "\"Derniers blocs\"",
            "\"Preuve de travail\"",
            "\"Ce que le protocole ne protège pas\"",
            "\"Racine de Merkle\"",
            "\"Historique complet\"",
        ] {
            assert_eq!(
                dico.matches(cle).count(),
                2,
                "{cle} doit etre traduit en anglais et en japonais"
            );
        }
    }

    /// La page lit l'en-tete de bloc sous les noms que le noeud lui donne.
    ///
    /// Regression : la page lisait `prev_block`, `merkle_root` et `miner`, alors
    /// que le noeud rend `parent`, `merkle` et `mineur`. Les lignes Parent,
    /// Racine de Merkle et Mineur affichaient « undefined ».
    #[test]
    fn l_en_tete_de_bloc_se_lit_sous_les_noms_du_noeud() {
        let s = script();
        for ancien in ["e.prev_block", "e.merkle_root", "e.miner", "o.miner"] {
            assert!(
                !s.contains(ancien),
                "champ inexistant cote noeud : {ancien}"
            );
        }
        for nouveau in ["e.parent", "e.merkle)", "e.mineur)", "o.mineur,"] {
            assert!(s.contains(nouveau), "champ attendu : {nouveau}");
        }
        let rpc = include_str!("rpc.rs");
        for champ in [r#".set("parent""#, r#".set("merkle""#, r#".set("mineur""#] {
            assert!(rpc.contains(champ), "le noeud ne rend plus {champ}");
        }
    }

    #[test]
    fn la_page_prevoit_les_deux_themes() {
        assert!(PAGE.contains("prefers-color-scheme: dark"));
    }

    #[test]
    fn la_page_echappe_ce_qu_elle_affiche() {
        // Les identifiants et messages viennent du noeud, mais un pair peut y
        // avoir injecte n'importe quoi. Tout passe par une fonction d'echappement.
        assert!(PAGE.contains("const ech ="));
        assert!(PAGE.contains("&amp;"));
        assert!(PAGE.contains("&lt;"));
    }

    /// Ce que cette page affiche et que les explorateurs publics taisent.
    #[test]
    fn la_page_montre_ce_qui_n_est_pas_protege() {
        assert!(PAGE.contains("Ce que le protocole ne protège pas"));
        assert!(PAGE.contains("un_attaquant_peut"));
        assert!(PAGE.contains("cout_de_la_finalite_glissante"));
    }

    /// Le jeton se demande, il ne se met plus dans l'adresse.
    #[test]
    fn la_page_explique_le_jeton_en_cas_d_echec() {
        assert!(PAGE.contains("l'explorateur le demandera"));
        assert!(PAGE.contains("Authorization"));
        assert!(
            !PAGE.contains("location.search"),
            "la chaine de requete ne doit plus etre recopiee vers le RPC"
        );
    }

    /// Les quatre vues existent, et le routeur les connait toutes.
    #[test]
    fn les_quatre_vues_existent() {
        for v in ["accueil", "bloc", "tx", "adresse"] {
            assert!(
                PAGE.contains(&format!(r#"id="vue-{v}""#)),
                "vue manquante : {v}"
            );
        }
        for r in ["case \"bloc\":", "case \"tx\":", "case \"adresse\":"] {
            assert!(PAGE.contains(r), "route manquante : {r}");
        }
    }

    /// Le jeton et le routage partagent le fragment sans se confondre.
    ///
    /// Une route commence par une barre oblique, un jeton jamais. C'est ce qui
    /// permet au lanceur de passer le jeton dans le fragment — ou il n'est
    /// jamais envoye au serveur — sans priver la page de son routage.
    #[test]
    fn le_jeton_et_la_route_se_distinguent_dans_le_fragment() {
        assert!(
            PAGE.contains(r#"if (f && !f.startsWith("/"))"#),
            "rien ne distingue un jeton d'une route"
        );
        // Et le fragment est efface aussitot lu : une capture d'ecran ou un
        // partage d'onglet ne doivent pas emporter le secret.
        assert!(PAGE.contains("history.replaceState"));
    }

    /// Le fragment est une amorce a usage unique, echangee avant tout appel.
    ///
    /// Meme regle que pour le portefeuille : ce que le lanceur met dans
    /// l'adresse passe par la ligne de commande du navigateur, et ne doit
    /// donc valoir qu'une fois.
    #[test]
    fn le_fragment_est_une_amorce_echangee_avant_tout_appel() {
        assert!(PAGE.contains("echange = echangerAmorce(decodeURIComponent(f));"));
        assert!(!PAGE.contains("retenirJeton(decodeURIComponent(f));"));
        assert!(PAGE.contains("fetch(\"/session\""));
        let attente = PAGE
            .find("if (echange){ await echange; echange = null; }")
            .expect("attente");
        let appel = PAGE.find("async function appel(").expect("appel");
        assert!(
            attente > appel && attente - appel < 80,
            "l'attente doit ouvrir `appel`"
        );
    }

    /// Un onglet ferme se rouvre tant que le programme tourne.
    ///
    /// Le lien du lanceur ne sert qu'une fois. Rouvert, l'echange echoue et la
    /// page reprend le jeton range sous cette origine — `localStorage`,
    /// cloisonne par port, touche par un seul point d'acces. Un jeton perime
    /// est efface par le 401 qui suit, avant que le panneau ne s'ouvre.
    #[test]
    fn un_onglet_rouvert_reprend_le_jeton_range() {
        assert_eq!(PAGE.matches("window.localStorage").count(), 1);
        assert!(!PAGE.contains("localStorage."));
        // `sessionStorage` ne porte que la langue choisie, comme dans le
        // portefeuille : jamais le jeton. Chaque usage vise `q21-langue` et se
        // tient dans un `try`, car un navigateur peut refuser le stockage.
        for (i, _) in PAGE.match_indices("sessionStorage.") {
            let suite = &PAGE[i..(i + 60).min(PAGE.len())];
            assert!(
                suite.contains("q21-langue"),
                "seul le choix de langue passe par sessionStorage : {suite}"
            );
            // Le `try` se lit sur la meme ligne, avant l'acces. On borne a la
            // ligne plutot qu'a un nombre d'octets : un decoupage au milieu d'un
            // caractere accentue ferait paniquer l'epreuve elle-meme.
            let ligne = PAGE[..i].rfind('\n').map(|d| d + 1).unwrap_or(0);
            let avant = &PAGE[ligne..i];
            assert!(
                avant.contains("try {"),
                "acces au stockage non garde : {avant}"
            );
        }
        assert!(PAGE.contains("r.setItem(CLEF_SESSION"));
        assert!(PAGE.contains("r.removeItem(CLEF_SESSION"));
        let echec = PAGE
            .find("} catch (e) {}\n  const garde = jetonRange();\n  if (garde) jeton = garde;\n}")
            .expect("reprise apres un echange echoue");
        assert!(
            echec
                > PAGE
                    .find("async function echangerAmorce(")
                    .expect("echange")
        );
        assert!(
            PAGE.contains(
                "if (r.status === 401){\n    oublierJeton();\n    await demanderJeton();"
            ),
            "un 401 doit effacer le jeton range avant de le redemander"
        );
        for interdit in ["indexedDB.open", "document.cookie ="] {
            assert!(!PAGE.contains(interdit), "{interdit}");
        }
    }

    /// Le jeton se demande dans la page, pas par une fenetre du navigateur.
    ///
    /// `window.prompt` bloque tout l'onglet, ne se met pas en forme, et sur
    /// certains navigateurs ne s'affiche tout simplement pas.
    #[test]
    fn le_jeton_se_demande_dans_la_page() {
        assert!(PAGE.contains(r#"id="panneau-jeton""#));
        assert!(
            !PAGE.contains("window.prompt"),
            "le jeton est encore demande par une fenetre du navigateur"
        );
    }

    /// La page a un champ de recherche, et il passe par le noeud.
    ///
    /// Deviner cote page ce qu'est une saisie obligerait a y reimplementer la
    /// lecture d'une adresse — donc bech32, donc sa somme de controle. Le noeud
    /// sait deja le faire, et une seule implementation ne peut pas diverger
    /// d'elle-meme.
    #[test]
    fn la_recherche_passe_par_le_noeud() {
        assert!(PAGE.contains(r#"id="forme-chercher""#));
        assert!(PAGE.contains(r#"appel("rechercher", {q})"#));
    }

    /// Aucun montant ne passe par un flottant.
    ///
    /// La page additionne des montants — les sorties d'une transaction, ce
    /// qu'une adresse a recu. En virgule flottante binaire, ces sommes
    /// derivent. Une chaine de blocs qui arrondit un solde n'est plus une
    /// chaine de blocs.
    #[test]
    fn aucun_flottant_sur_un_montant() {
        let script = {
            let d = PAGE.find("<script>").expect("bloc script") + "<script>".len();
            let f = PAGE.find("</script>").expect("fin du script");
            &PAGE[d..f]
        };
        assert!(
            script.contains("BigInt("),
            "les montants ne sont pas en entiers"
        );
        assert!(
            script.contains("100000000n"),
            "la conversion en Q21 doit se faire en entiers"
        );
        for interdit in ["parseFloat", "Number(o.valeur", "toFixed(8)"] {
            assert!(
                !script.contains(interdit),
                "un montant passe par un flottant : {interdit}"
            );
        }
    }

    /// Une page de detail ne se recharge pas sous les yeux de qui la lit.
    #[test]
    fn seul_l_accueil_se_rafraichit() {
        assert!(PAGE.contains("clearInterval(battement)"));
        assert!(PAGE.contains(r#"if (vue === "accueil") battement = setInterval"#));
    }

    /// Aucun appel a `tuile` ne porte de balisage sans passer par `brut`.
    ///
    /// # Le defaut que cette epreuve verrouille
    ///
    /// La tuile « Etat » d'une transaction recevait sa chaine telle quelle :
    ///
    /// ```text
    ///     tuile("Etat", r.confirmee ? '<span class="badge">confirmee</span>' : ...)
    /// ```
    ///
    /// `tuile` echappe par defaut — c'est la bonne direction, celle qui protege
    /// contre l'injection — et la page affichait donc son propre balisage en
    /// clair, a l'ecran. Le premier utilisateur a ouvrir une transaction l'a vu.
    ///
    /// Aucune epreuve ne pouvait l'attraper : celles qui existaient cherchaient
    /// le defaut inverse, du balisage insere **sans** echappement. Il fallait
    /// regarder dans l'autre sens.
    ///
    /// La correction n'est pas d'ajouter `brut` a cet endroit-la, mais de
    /// donner une fonction — `badge` — qui fabrique l'etiquette et se charge du
    /// marquage. Cette epreuve verifie qu'on n'y revient pas.
    #[test]
    fn aucune_tuile_ne_porte_de_balisage_non_marque() {
        let s = script();
        let mut reste = s;
        let mut examines = 0;
        while let Some(i) = reste.find("tuile(") {
            reste = &reste[i + "tuile(".len()..];
            // Parenthese fermante equilibree : les arguments contiennent
            // eux-memes des appels de fonction.
            let mut profondeur = 1usize;
            let mut fin = reste.len();
            for (j, c) in reste.char_indices() {
                match c {
                    '(' => profondeur += 1,
                    ')' => {
                        profondeur -= 1;
                        if profondeur == 0 {
                            fin = j;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let args = &reste[..fin];
            examines += 1;

            // Du balisage, c'est un chevron suivi d'une lettre ou d'une barre
            // oblique. Une comparaison — `a.length < b` — porte un espace, et
            // ne doit pas etre confondue avec une balise.
            let octets = args.as_bytes();
            let balisage = octets
                .windows(2)
                .any(|f| f[0] == b'<' && (f[1].is_ascii_alphabetic() || f[1] == b'/'));
            assert!(
                !balisage || args.contains("brut("),
                "une tuile porte du balisage sans le marquer : il sera echappe \
                 et affiche en clair a l'ecran.\n\n    tuile({})\n\n\
                 Employez badge(), ou enveloppez la valeur dans brut().",
                args.trim()
            );
        }
        assert!(
            examines >= 10,
            "le balayage n'a trouve que {examines} tuiles : la page a change de \
             forme et l'epreuve ne verifie plus rien"
        );
    }

    /// Les points d'insertion `innerHTML` echappent par defaut.
    #[test]
    fn les_valeurs_sont_echappees_par_defaut() {
        assert!(PAGE.contains("const rendu ="));
        assert!(PAGE.contains("${rendu(v)}"));
    }
}
