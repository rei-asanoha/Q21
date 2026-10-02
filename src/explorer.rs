//! Web explorer, served by the node.
//!
//! # Why it is not hosted elsewhere
//!
//! To look at a chain, almost everyone opens a third party's website. So one
//! trusts a server to learn what a system built to trust no one contains — and
//! that server can lie, make mistakes, disappear, or be coerced.
//!
//! This page is served by your node, on the loopback interface, and shows only
//! what your machine has validated itself. It loads **no external resource**:
//! no font, no stylesheet, no remote script. An explorer page that calls a CDN
//! hands that CDN the list of everything you look at.
//!
//! It also shows, plainly, what the protocol does **not** protect. An explorer
//! that only shows what reassures lies by omission.

/// The complete page. No external resource, by construction.
///
/// # What changed with phase 3
///
/// The page only showed a dashboard: the state of the chain, the money issued,
/// the latest blocks. It could be looked at; nothing could be searched in it.
///
/// It now carries four views — home, block, transaction, address — and a
/// single search field. Routing happens in the **fragment**, what follows the
/// `#`: it never leaves the browser, no request is made to the server to change
/// pages, and the page remains a single file served as is.
///
/// The token already used that fragment. The two live together without
/// ambiguity: a route always starts with a slash, a token never does. The token
/// is read once, stored in `localStorage` — partitioned by port, and dead along
/// with the process that drew it — and the fragment is handed back to routing.
///
/// # Language
///
/// The page is written in English. French and Japanese are translations,
/// applied in the browser by the same engine as the wallet, from tables keyed
/// by the English text (see `wallet_ui.rs`).
pub const PAGE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Q21 — local explorer</title>
<style>
:root{
  --bg:#f5f4f0; --card:#fffefb; --border:#dcd8cf; --border-strong:#c3bdb1;
  --text:#1a1a18; --soft:#57554d; --muted:#8b887d;
  --accent:#1d6f66; --accent-bg:#e2eeeb; --warn:#8a5a1e; --warn-bg:#f4e9d8;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#131410; --card:#1c1e18; --border:#32352b; --border-strong:#454940;
    --text:#ecebe0; --soft:#aca99a; --muted:#7b786b;
    --accent:#62bfb2; --accent-bg:#16302c; --warn:#d9a75f; --warn-bg:#312716;
  }
}
*{box-sizing:border-box}
body{
  margin:0;background:var(--bg);color:var(--text);
  font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
.shell{max-width:1080px;margin:0 auto;padding:2rem 1.2rem 4rem}
header{border-bottom:2px solid var(--text);padding-bottom:1rem;margin-bottom:1.6rem}
h1{margin:0;font-size:1.7rem;letter-spacing:-.02em}
h1 a{color:inherit;text-decoration:none}
.sub{color:var(--soft);font-size:.9rem;margin-top:.35rem}
.net-tag{display:inline-block;padding:.12rem .5rem;border-radius:3px;font-size:.75rem;
  font-family:ui-monospace,monospace;background:var(--accent-bg);color:var(--accent);margin-left:.5rem}
h2{font-size:1rem;text-transform:uppercase;letter-spacing:.08em;color:var(--soft);
  margin:2rem 0 .8rem;font-weight:600}
h2:first-child{margin-top:0}
.grid{display:grid;gap:.9rem;grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}
.tile{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:.85rem 1rem}
.tile .k{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.tile .v{font-size:1.3rem;font-family:ui-monospace,monospace;margin-top:.2rem;
  font-variant-numeric:tabular-nums;word-break:break-all}
.tile .n{font-size:.76rem;color:var(--soft);margin-top:.2rem;word-break:break-all}
table{width:100%;border-collapse:collapse;font-family:ui-monospace,monospace;font-size:.82rem}
th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--border);
  font-variant-numeric:tabular-nums;white-space:nowrap}
th{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;
  border-bottom:1px solid var(--border-strong)}
tbody tr:hover{background:var(--accent-bg)}
.scroll{overflow-x:auto;background:var(--card);border:1px solid var(--border);border-radius:6px}
.mono{font-family:ui-monospace,monospace}
.clip{max-width:22ch;overflow:hidden;text-overflow:ellipsis;display:inline-block;vertical-align:bottom}
.warn{background:var(--card);border:1px solid var(--border);border-left:3px solid var(--warn);
  border-radius:5px;padding:1rem 1.1rem;margin:.9rem 0}
.warn h3{margin:0 0 .5rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--warn)}
.warn p{margin:0 0 .6rem;font-size:.9rem;color:var(--soft)}
.warn p:last-child{margin-bottom:0}
.warn ul{margin:.3rem 0 .6rem;padding-left:1.2rem;font-size:.88rem;color:var(--soft)}
.info{border-left-color:var(--accent)}
.info h3{color:var(--accent)}
.two{display:grid;gap:.9rem;grid-template-columns:1fr 1fr}
@media(max-width:720px){.two{grid-template-columns:1fr}}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--border);
  color:var(--muted);font-size:.78rem}
code{background:var(--accent-bg);color:var(--accent);padding:.1em .35em;border-radius:3px;
  font-size:.85em}
.err{color:var(--warn)}
a{color:var(--accent)}
a.flat{text-decoration:none}
a.flat:hover{text-decoration:underline}

/* Search: a single field, which works out what it is given. */
.search{display:flex;gap:.5rem;margin-top:.9rem;flex-direction:column}
@media(min-width:560px){.search{flex-direction:row}}
.search input{
  flex:1;background:var(--card);color:var(--text);border:1px solid var(--border-strong);
  border-radius:5px;padding:.55rem .7rem;font:inherit;font-family:ui-monospace,monospace;
  font-size:.88rem;min-width:0;
}
.search input:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:var(--accent)}
.search button{
  background:var(--accent);color:var(--bg);border:1px solid var(--accent);border-radius:5px;
  padding:.55rem 1.1rem;font:inherit;font-size:.88rem;font-weight:600;cursor:pointer;
}
.search button:hover{filter:brightness(1.08)}
.help{font-size:.78rem;color:var(--muted);margin-top:.35rem}

/* Breadcrumbs */
.crumbs{font-size:.82rem;color:var(--muted);margin-bottom:.9rem}
.crumbs a{color:var(--soft)}

/* Flow of a transaction: what comes in on the left, what goes out on the right. */
.flow{display:grid;gap:.9rem;grid-template-columns:1fr 1fr;margin-top:.5rem}
@media(max-width:720px){.flow{grid-template-columns:1fr}}
.stack{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:.3rem .9rem}
.stack .l{padding:.55rem 0;border-bottom:1px solid var(--border);font-size:.84rem;
  display:flex;justify-content:space-between;gap:.8rem;align-items:baseline}
.stack .l:last-child{border-bottom:none}
.stack .l .g{font-family:ui-monospace,monospace;overflow:hidden;text-overflow:ellipsis}
.stack .l .d{font-family:ui-monospace,monospace;white-space:nowrap;font-variant-numeric:tabular-nums}
.stack .t{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
  padding:.6rem 0 .2rem}
.badge{display:inline-block;padding:.05rem .4rem;border-radius:3px;font-size:.72rem;
  background:var(--accent-bg);color:var(--accent)}
.badge.gray{background:var(--border);color:var(--soft)}

/* Language choice: the same as in the wallet. */
.header-top{display:flex;align-items:center;justify-content:space-between;gap:.8rem;flex-wrap:wrap}
.languages{display:flex;gap:.25rem;align-items:center}
.languages button{background:transparent;border:1px solid transparent;border-radius:.4rem;
  padding:.15rem .35rem;font-size:1.05rem;line-height:1;cursor:pointer;opacity:.55}
.languages button:hover{opacity:.9;background:var(--accent-bg)}
.languages button[aria-pressed="true"]{opacity:1;border-color:var(--border-strong)}
.languages button:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
</style>
</head>
<body>
<div class="shell">

<header>
  <div class="header-top">
    <h1><a href="#/">Q21</a> <span class="net-tag" id="network">…</span></h1>
    <div class="languages" id="languages" role="group" aria-label="Language">
      <button type="button" data-lang="en" aria-pressed="true" title="English">&#127482;&#127480;</button>
      <button type="button" data-lang="fr" aria-pressed="false" title="Français">&#127467;&#127479;</button>
      <button type="button" data-lang="ja" aria-pressed="false" title="&#26085;&#26412;&#35486;">&#127471;&#127477;</button>
    </div>
  </div>
  <div class="sub">
    Explorer served by <strong>your node</strong>, locally. No external resources
    are loaded: everything you read here was validated by your machine.
  </div>
  <form class="search" id="search-form" autocomplete="off">
    <input id="search-input" placeholder="height, block, transaction, address or amount (e.g. 1.5)" spellcheck="false">
    <button type="submit">Search</button>
  </form>
  <div class="help" id="search-help">One field: the node recognizes whatever you paste.</div>
</header>

<div id="token-panel" class="warn" hidden>
  <h3>Access token required</h3>
  <p>
    The node requires a token. The launcher normally passes it in the address
    fragment; if you opened this page manually, enter the token given to
    <code>--rpc-token</code>.
  </p>
  <form id="token-form" class="search" autocomplete="off">
    <input type="password" id="token-input" placeholder="access token" autocomplete="off" spellcheck="false">
    <button type="submit">Unlock</button>
  </form>
</div>

<div id="error" class="warn" hidden>
  <h3>Node unreachable</h3>
  <p id="error-detail"></p>
</div>

<section class="view" id="view-home">
  <h2>Chain</h2>
  <div class="grid" id="tiles"></div>

  <h2>Supply</h2>
  <div class="grid" id="supply"></div>

  <div class="two">
    <div>
      <h2>Proof of work</h2>
      <div class="scroll"><table id="pow"></table></div>
    </div>
    <div>
      <h2>Network</h2>
      <div class="scroll"><table id="network-stats"></table></div>
    </div>
  </div>

  <h2>Latest blocks</h2>
  <div class="scroll">
    <table>
      <thead><tr><th>Height</th><th>ID</th><th>Tx</th><th>Size</th><th>Subsidy</th><th>Timestamp</th></tr></thead>
      <tbody id="blocks"></tbody>
    </table>
  </div>

  <h2>Mempool</h2>
  <div class="scroll"><table id="mempool"></table></div>

  <h2>What the protocol does not protect</h2>
  <div class="warn" id="security">
    <h3>Loading…</h3>
  </div>
</section>

<section class="view" id="view-block" hidden>
  <div class="crumbs"><a href="#/">Home</a> → block</div>
  <h2 id="block-title">Block</h2>
  <div class="grid" id="block-tiles"></div>
  <div class="scroll" style="margin-top:.9rem"><table id="block-header"></table></div>
  <h2>Transactions</h2>
  <div class="scroll">
    <table>
      <thead><tr><th>#</th><th>ID</th><th>Type</th><th>Inputs</th><th>Outputs</th><th>Output value</th><th>Weight</th></tr></thead>
      <tbody id="block-transactions"></tbody>
    </table>
  </div>
  <div id="block-uncles"></div>
</section>

<section class="view" id="view-tx" hidden>
  <div class="crumbs"><a href="#/">Home</a> → transaction</div>
  <h2>Transaction</h2>
  <div class="grid" id="tx-tiles"></div>
  <div class="flow">
    <div>
      <div class="stack" id="tx-inputs"></div>
    </div>
    <div>
      <div class="stack" id="tx-outputs"></div>
    </div>
  </div>
  <div id="tx-note"></div>
</section>

<section class="view" id="view-address" hidden>
  <div class="crumbs"><a href="#/">Home</a> → address</div>
  <h2>Address</h2>
  <div class="scroll" style="margin-bottom:.9rem"><table id="address-identity"></table></div>
  <div class="grid" id="address-tiles"></div>
  <div id="address-note"></div>
  <h2>Movements</h2>
  <div class="scroll">
    <table>
      <thead><tr><th>Type</th><th>Received</th><th>Sent</th><th>Conf.</th><th>Height</th><th>Timestamp</th><th>ID</th></tr></thead>
      <tbody id="address-movements"></tbody>
    </table>
  </div>
</section>

<section class="view" id="view-amount" hidden>
  <div class="crumbs"><a href="#/">Home</a> → amount</div>
  <h2>Search by amount</h2>
  <div class="grid" id="amount-tiles"></div>
  <div id="amount-note"></div>
  <h2>Outputs found</h2>
  <div class="scroll">
    <table>
      <thead><tr><th>Transaction</th><th>Height</th><th>Address</th><th>Amount</th></tr></thead>
      <tbody id="amount-rows"></tbody>
    </table>
  </div>
</section>

<footer>
  <p style="margin:0 0 .6rem" id="wallet-footer" hidden>
    <a class="flat" id="wallet-link" href="/wallet">Wallet</a> —
    served by the same node, on the same port.
  </p>
  JSON-RPC API at <code>POST /rpc</code> — <code>listmethods</code> lists the
  available methods. Research code, not audited: it protects no real value.
</footer>

</div>
<script>
// ---------------------------------------------------------------------------
// Language
//
// Same engine as the wallet, and the same storage key `q21-language`: the
// language chosen in the wallet carries over to the explorer, which opens in
// the same tab, and the other way around. `sessionStorage` is used for that
// alone, never for the token, which stays in `localStorage` under the origin.
//
// The page always writes its text in English; the engine translates it at
// display time. That is what makes it possible to switch languages at any
// moment, in any direction, without reloading. Texts that come from the node
// (notes, errors) go through the same tables: the explorer asks nothing of
// the node according to the language. The tables are keyed by the English
// text; a text missing from them is shown in English.
// ---------------------------------------------------------------------------
const I18N = {"fr": {"Q21 — local explorer": "Q21 — explorateur local", "Explorer served by": "Explorateur servi par", "your node": "votre nœud", ", locally. No external resources are loaded: everything you read here was validated by your machine.": ", en local. Aucune ressource externe n'est chargée\u00a0: ce que vous lisez, votre machine l'a validé.", "height, block, transaction, address or amount (e.g. 1.5)": "hauteur, bloc, transaction, adresse ou montant (ex. 1.5)", "Search": "Chercher", "One field: the node recognizes whatever you paste.": "Un seul champ\u00a0: le nœud reconnaît ce que vous collez.", "Searching…": "Recherche…", "Access token required": "Jeton d'accès requis", "The node requires a token. The launcher normally passes it in the address fragment; if you opened this page manually, enter the token given to": "Le nœud exige un jeton. Il est normalement transmis par le lanceur dans le fragment de l'adresse\u00a0; si vous avez ouvert cette page à la main, saisissez ici le jeton passé à", "access token": "jeton d'accès", "Unlock": "Déverrouiller", "Node unreachable": "Nœud injoignable", "Wallet": "Portefeuille", "— served by the same node, on the same port.": "— servi par le même nœud, sur le même port.", "JSON-RPC API at": "API JSON-RPC sur", "lists the available methods. Research code, not audited: it protects no real value.": "énumère les méthodes disponibles. Code de recherche, non audité\u00a0: ne protège aucune valeur réelle.", "Loading…": "Chargement…", "Chain": "Chaîne", "Supply": "Monnaie", "Proof of work": "Preuve de travail", "Network": "Réseau", "Latest blocks": "Derniers blocs", "Mempool": "Réservoir de transactions", "What the protocol does not protect": "Ce que le protocole ne protège pas", "Home": "Accueil", "→ block": "→ bloc", "→ transaction": "→ transaction", "→ address": "→ adresse", "→ amount": "→ montant", "Block": "Bloc", "Transactions": "Transactions", "Transaction": "Transaction", "Address": "Adresse", "Movements": "Mouvements", "Search by amount": "Recherche par montant", "Outputs found": "Sorties trouvées", "Uncles": "Oncles", "Height": "Hauteur", "ID": "Identifiant", "IDs": "Identifiants", "Size": "Taille", "Subsidy": "Subvention", "Timestamp": "Horodatage", "Type": "Genre", "Inputs": "Entrées", "Outputs": "Sorties", "Output value": "Valeur sortante", "Weight": "Poids", "Received": "Reçu", "Sent": "Envoyé", "Conf.": "Conf.", "Amount": "Montant", "Confirmations": "Confirmations", "Parent": "Parent", "Merkle root": "Racine de Merkle", "Miner": "Mineur", "Nonce": "Nonce", "Difficulty": "Difficulté", "Tip": "Tête", "Cumulative work": "Travail cumulé", "expected attempts": "tentatives espérées", "Peers": "Pairs", "Known blocks": "Blocs connus", "including side branches": "branches latérales comprises", "Issued": "Émis", "In the UTXO set": "Dans les UTXO", "Cap": "Plafond", "under the cap ✓": "sous le plafond ✓", "CAP EXCEEDED": "PLAFOND FRANCHI", "Share issued": "Part émise", "Unspent outputs": "Sorties non dépensées", "State commitment": "Empreinte de l'état", "Epoch": "Époque", "Table elements": "Éléments de table", "Miner memory": "Mémoire du mineur", "Node memory": "Mémoire du nœud", "Accesses per attempt": "Accès par tentative", "Growth": "Croissance", "Blocks received": "Blocs reçus", "Blocks accepted": "Blocs acceptés", "Compact announcements": "Annonces compactes", "Rebuilt without a round trip": "Reconstruits sans aller-retour", "Transactions received": "Transactions reçues", "Banned peers": "Pairs bannis", "Bytes": "Octets", "100% protection against a 51% attack: impossible": "Protection à 100 % contre une attaque à 51 %\u00a0: impossible", "100% protection against a 51% attack: yes": "Protection à 100 % contre une attaque à 51 % : oui", "A majority attacker can:": "Un attaquant majoritaire peut\u00a0:", "Even with 99% of the hash power, it cannot:": "Il ne peut pas, même avec 99 % de la puissance\u00a0:", "Rolling finality:": "Finalité glissante\u00a0:", "Consensus defines the valid chain as the one carrying the most work. A majority produces more of it than everyone else, by definition. Refusing its chain would require knowing that it is them: an identity, hence an authority, hence the end of permissionlessness. This is a theorem, not an implementation gap.": "Le consensus definit la chaine valide comme celle qui porte le plus de travail. Un majoritaire en produit plus que tous les autres, par definition. Refuser sa chaine supposerait de savoir que c'est lui : une identite, donc une autorite, donc la fin du caractere sans permission. C'est un theoreme, pas une lacune d'implementation.", "reorganize recent blocks, and so undo its own payments": "reorganiser les blocs recents, donc annuler ses propres paiements", "refuse to include certain transactions": "refuser d'inclure certaines transactions", "steal a coin it holds no key for": "voler une piece dont il n'a pas la clef", "create a single unit beyond the subsidy": "fabriquer une unite au-dela de la subvention", "raise the cap of 21,000,001": "relever le plafond de 21 000 001", "change a rule: its blocks are simply rejected": "changer une regle : ses blocs sont simplement rejetes", "mining": "minage", "transfer": "transfert", "Fee": "Frais", "a coinbase collects fees, it pays none": "une coinbase les perçoit, elle n'en paie pas", "paid to the miner": "payés au mineur", "unresolved without an index": "non résolu sans index", "Status": "État", "confirmed": "confirmée", "pending": "en attente", "in the mempool": "dans le réservoir", "Coin creation — this transaction consumes nothing": "Création monétaire — cette transaction ne consomme rien", "Mining transaction": "Transaction de minage", "It creates the block subsidy and collects the fees of the other transactions. It consumes no earlier output, and what it produces can only be spent after the maturity delay — so that a block undone by a reorg cannot already have been used to pay someone.": "Elle crée la subvention du bloc et récolte les frais des autres transactions. Elle ne consomme aucune sortie antérieure, et ce qu'elle produit n'est dépensable qu'après le délai de maturité — de sorte qu'un bloc annulé par une réorganisation n'ait pas déjà servi à payer quelqu'un.", "Fee unresolved": "Frais non résolus", "At least one input is outside this node's index — no index, or a coin too old for it. The fee is not computed from a partial sum: the page would rather stay silent than show a figure it has not verified.": "Une entrée au moins échappe à l'index de ce nœud — index absent, ou pièce trop ancienne pour lui. Les frais ne se calculent pas sur une somme partielle\u00a0: la page préfère se taire plutôt qu'afficher un chiffre qu'elle n'a pas vérifié.", "Key hash": "Empreinte de clef", "Balance": "Solde", "all shown": "tous affichés", "Received (shown)": "Reçu (affiché)", "Sent (shown)": "Envoyé (affiché)", "Full history": "Historique complet", "Bounded history": "Historique borné", "Full history: the address index covers the whole chain.": "Historique complet : l'index d'adresses couvre toute la chaine.", "Bounded history: this node runs without an address index. Sends are not resolved, and the search stops at the floor shown. Restart it with --address-index for a complete answer.": "Historique borne : ce noeud tourne sans index d'adresses. Les envois ne sont pas resolus, et la recherche s'arrete au plancher indique. Relancez-le avec --address-index pour une reponse complete.", "The balance, however, depends on no index: it comes from the set of unspent outputs this node validated itself. It is exact even when the history is not.": "Le solde, lui, ne dépend d'aucun index\u00a0: il vient de l'ensemble des sorties non dépensées que ce nœud a validé lui-même. Il est exact même quand l'historique ne l'est pas.", "sent": "envoi", "received": "réception", "No movement within the search range.": "Aucun mouvement dans la portée de la recherche.", "Amount searched": "Montant cherché", "the 100 most recent": "les 100 plus récentes", "Window": "Fenêtre", "Bounded search": "Recherche bornée", "No output of this amount in the window searched.": "Aucune sortie de ce montant dans la fenêtre parcourue.", "empty search": "recherche vide", "search too long": "recherche trop longue", "unreadable height": "hauteur illisible", "unreadable amount: at most 8 decimals": "montant illisible : au plus 8 decimales", "neither a block nor a transaction known to this node": "ni bloc, ni transaction connue de ce noeud", "neither a height, nor a 64-character hexadecimal identifier, nor a valid address": "ni une hauteur, ni un identifiant de 64 caracteres hexadecimaux, ni une adresse valide", "index unavailable": "index indisponible", "transaction not found": "transaction introuvable", "block not found": "bloc introuvable", "too many searches in progress on this public service: try again in a minute": "trop de recherches en cours sur ce service public : reessayez dans une minute"}, "ja": {"Q21 — local explorer": "Q21 — ローカル・エクスプローラー", "Explorer served by": "このエクスプローラーを提供しているのは", "your node": "あなたのノード", ", locally. No external resources are loaded: everything you read here was validated by your machine.": "です(ローカル動作)。外部リソースは一切読み込みません。表示内容はすべてあなたのマシンが検証したものです。", "height, block, transaction, address or amount (e.g. 1.5)": "高さ、ブロック、トランザクション、アドレス、または金額(例:1.5)", "Search": "検索", "One field: the node recognizes whatever you paste.": "入力欄はひとつだけ。貼り付けた内容をノードが判別します。", "Searching…": "検索中…", "Access token required": "アクセストークンが必要です", "The node requires a token. The launcher normally passes it in the address fragment; if you opened this page manually, enter the token given to": "ノードはトークンを要求しています。通常はランチャーがアドレスのフラグメントで渡します。このページを手動で開いた場合は、次のオプションに渡したトークンをここに入力してください:", "access token": "アクセストークン", "Unlock": "ロック解除", "Node unreachable": "ノードに接続できません", "Wallet": "ウォレット", "— served by the same node, on the same port.": "— 同じノード、同じポートで提供されています。", "JSON-RPC API at": "JSON-RPC API:", "lists the available methods. Research code, not audited: it protects no real value.": "で利用できるメソッドを一覧できます。研究用のコードで未監査のため、実際の価値は一切保護しません。", "Loading…": "読み込み中…", "Chain": "チェーン", "Supply": "通貨", "Proof of work": "プルーフ・オブ・ワーク", "Network": "ネットワーク", "Latest blocks": "最新のブロック", "Mempool": "トランザクションプール", "What the protocol does not protect": "プロトコルが守らないもの", "Home": "ホーム", "→ block": "→ ブロック", "→ transaction": "→ トランザクション", "→ address": "→ アドレス", "→ amount": "→ 金額", "Block": "ブロック", "Transactions": "トランザクション", "Transaction": "トランザクション", "Address": "アドレス", "Movements": "入出金", "Search by amount": "金額で検索", "Outputs found": "見つかった出力", "Uncles": "アンクル", "Height": "高さ", "ID": "識別子", "IDs": "識別子", "Size": "サイズ", "Subsidy": "補助金", "Timestamp": "タイムスタンプ", "Type": "種類", "Inputs": "入力", "Outputs": "出力", "Output value": "出力額", "Weight": "重み", "Received": "受取", "Sent": "送金", "Conf.": "承認", "Amount": "金額", "Confirmations": "承認数", "Parent": "親ブロック", "Merkle root": "マークル・ルート", "Miner": "マイナー", "Nonce": "ナンス", "Difficulty": "難易度", "Tip": "先端", "Cumulative work": "累積ワーク", "expected attempts": "期待試行回数", "Peers": "ピア", "Known blocks": "既知のブロック", "including side branches": "側枝を含む", "Issued": "発行済み", "In the UTXO set": "UTXO内", "Cap": "上限", "under the cap ✓": "上限以内 ✓", "CAP EXCEEDED": "上限超過", "Share issued": "発行割合", "Unspent outputs": "未使用出力", "State commitment": "状態フィンガープリント", "Epoch": "エポック", "Table elements": "テーブル要素数", "Miner memory": "マイナーのメモリ", "Node memory": "ノードのメモリ", "Accesses per attempt": "試行あたりのアクセス数", "Growth": "増加", "Blocks received": "受信ブロック", "Blocks accepted": "受理したブロック", "Compact announcements": "コンパクト通知", "Rebuilt without a round trip": "往復なしで再構成", "Transactions received": "受信トランザクション", "Banned peers": "禁止されたピア", "Bytes": "バイト", "100% protection against a 51% attack: impossible": "51 % 攻撃に対する 100 % の防御:不可能", "100% protection against a 51% attack: yes": "51 % 攻撃に対する 100 % の防御:可能", "A majority attacker can:": "過半数を握る攻撃者にできること:", "Even with 99% of the hash power, it cannot:": "計算力の 99 % を握っていても、できないこと:", "Rolling finality:": "スライディング・ファイナリティ:", "Consensus defines the valid chain as the one carrying the most work. A majority produces more of it than everyone else, by definition. Refusing its chain would require knowing that it is them: an identity, hence an authority, hence the end of permissionlessness. This is a theorem, not an implementation gap.": "コンセンサスは、最も多くのワークを持つチェーンを正当なチェーンと定めます。過半数を握る者は、定義上、他の全員より多くのワークを生み出します。そのチェーンを拒むには、それが誰かを知る必要があります。それは身元、つまり権威を意味し、許可不要という性質の終わりです。これは実装の欠陥ではなく、定理です。", "reorganize recent blocks, and so undo its own payments": "最近のブロックを再編成し、自分自身の支払いを取り消すこと", "refuse to include certain transactions": "特定のトランザクションの取り込みを拒むこと", "steal a coin it holds no key for": "鍵を持たないコインを盗むこと", "create a single unit beyond the subsidy": "補助金を超えて 1 単位でも作り出すこと", "raise the cap of 21,000,001": "21 000 001 の上限を引き上げること", "change a rule: its blocks are simply rejected": "ルールを変えること:そのブロックは単に拒否されます", "mining": "マイニング", "transfer": "送金", "Fee": "手数料", "a coinbase collects fees, it pays none": "コインベースは手数料を受け取り、支払いはしません", "paid to the miner": "マイナーに支払い済み", "unresolved without an index": "インデックスなしでは未解決", "Status": "状態", "confirmed": "承認済み", "pending": "保留中", "in the mempool": "プール内", "Coin creation — this transaction consumes nothing": "通貨の発行 — このトランザクションは何も消費しません", "Mining transaction": "マイニング・トランザクション", "It creates the block subsidy and collects the fees of the other transactions. It consumes no earlier output, and what it produces can only be spent after the maturity delay — so that a block undone by a reorg cannot already have been used to pay someone.": "ブロックの補助金を生み出し、他のトランザクションの手数料を集めます。以前の出力は何も消費せず、生み出したものは成熟期間を過ぎるまで使えません。これにより、再編成で取り消されたブロックが、すでに誰かへの支払いに使われていたという事態を防ぎます。", "Fee unresolved": "手数料は未解決", "At least one input is outside this node's index — no index, or a coin too old for it. The fee is not computed from a partial sum: the page would rather stay silent than show a figure it has not verified.": "少なくとも 1 つの入力がこのノードのインデックスの対象外です(インデックスがないか、古すぎるコインです)。手数料は部分的な合計からは計算しません。検証していない数字を表示するより、何も表示しないことを選びます。", "Key hash": "鍵フィンガープリント", "Balance": "残高", "all shown": "すべて表示", "Received (shown)": "受取(表示分)", "Sent (shown)": "送金(表示分)", "Full history": "完全な履歴", "Bounded history": "範囲を限定した履歴", "Full history: the address index covers the whole chain.": "完全な履歴:アドレス・インデックスがチェーン全体をカバーしています。", "Bounded history: this node runs without an address index. Sends are not resolved, and the search stops at the floor shown. Restart it with --address-index for a complete answer.": "範囲を限定した履歴:このノードはアドレス・インデックスなしで動作しています。送金は解決されず、検索は表示された下限で止まります。完全な結果を得るには --address-index を付けて再起動してください。", "The balance, however, depends on no index: it comes from the set of unspent outputs this node validated itself. It is exact even when the history is not.": "一方、残高はインデックスに依存しません。このノード自身が検証した未使用出力の集合から得られるため、履歴が不完全なときでも正確です。", "sent": "送金", "received": "受取", "No movement within the search range.": "検索範囲内に入出金はありません。", "Amount searched": "検索した金額", "the 100 most recent": "最新の 100 件", "Window": "検索範囲", "Bounded search": "範囲を限定した検索", "No output of this amount in the window searched.": "検索した範囲に、この金額の出力はありません。", "empty search": "検索語が空です", "search too long": "検索語が長すぎます", "unreadable height": "高さを読み取れません", "unreadable amount: at most 8 decimals": "金額を読み取れません:小数点以下は最大 8 桁です", "neither a block nor a transaction known to this node": "このノードが知るブロックでもトランザクションでもありません", "neither a height, nor a 64-character hexadecimal identifier, nor a valid address": "高さでも、64 文字の 16 進識別子でも、有効なアドレスでもありません", "index unavailable": "インデックスを利用できません", "transaction not found": "トランザクションが見つかりません", "block not found": "ブロックが見つかりません", "too many searches in progress on this public service: try again in a minute": "この公開サービスでは検索が集中しています。1 分後にもう一度お試しください"}};
const I18N_PATTERNS = {
  "fr": [
    [/^Block (\d+)$/, "Bloc $1"],
    [/^(\d+) confirmation\(s\)$/, "$1 confirmation(s)"],
    [/^(\d+) unspent output\(s\)$/, "$1 sortie(s) non dépensée(s)"],
    [/^(\d+) shown$/, "$1 affiché(s)"],
    [/^(\d+)% witness data$/, "$1 % de témoin"],
    [/^Inputs \((\d+)\)$/, "Entrées ($1)"],
    [/^Outputs \((\d+)\)$/, "Sorties ($1)"],
    [/^(\d+) \(capped\)$/, "$1 (plafonné)"],
    [/^blocks (\d+) → (\d+)$/, "blocs $1 → $2"],
    [/^at most (\d+) blocks$/, "$1 blocs au plus"],
    [/^\+([\d\s.,]+)% \/ ([\d\s.,]+) blocks$/, "+$1 % / $2 blocs"],
    [/^([\d.]+) MiB — verification does not need it$/, "$1 Mio — la vérification n'en a pas besoin"],
    [/^([\d.]+) KiB — verification does not need it$/, "$1 Kio — la vérification n'en a pas besoin"],
    [/^(\d+) B — verification does not need it$/, "$1 o — la vérification n'en a pas besoin"],
    [/^([\d.]+) MiB$/, "$1 Mio"],
    [/^([\d.]+) KiB$/, "$1 Kio"],
    [/^(\d+) B$/, "$1 o"],
    [/^(\d+) blocks \((\d+) h\)\. It does not remove the attack, it changes its nature\. A prolonged network partition produces two chains that will not reconcile on their own\. A silent rewrite is traded for a visible split\.$/, "$1 blocs ($2 h). Elle ne supprime pas l'attaque, elle en change la nature. Une partition reseau prolongee produit deux chaines qui ne se reconcilieront pas seules. On echange une reecriture silencieuse contre une scission visible."],
    [/^Search went back to block (\d+) of (\d+)\. The balance shown stays exact: it comes from the set of unspent outputs, not from this list\.$/, "Recherche remontée jusqu'au bloc $1 sur $2. Le solde affiché reste exact\u00a0: il vient de l'ensemble des sorties non dépensées, pas de cette liste."],
    [/^Without an amount index, the search goes back over a window of (\d+) blocks — here from (\d+) to (\d+)\. A common sum can appear thousands of times: the list is capped at the 100 most recent\. Fast, bounded, and the page says how far it went\.$/, "Sans index par montant, la recherche remonte une fenêtre de $1 blocs — ici de $2 à $3. Une somme courante peut apparaître des milliers de fois\u00a0: la liste est plafonnée aux 100 plus récentes. Rapide, bornée, et la page dit jusqu'où elle est allée."],
    [/^no block at height (\d+): the chain stops lower$/, "aucun bloc a la hauteur $1 : la chaine s'arrete plus bas"],
    [/^this address belongs to the (\w+) network, this node follows (\w+)$/, "cette adresse appartient au reseau $1, ce noeud suit $2"],
    [/^transaction not found in the last (\d+) blocks\. This node has no index by identifier: beyond that, the search is not carried out\.$/, "transaction introuvable dans les $1 derniers blocs. Ce noeud n'a pas d'index par identifiant : au-dela, la recherche n'est pas rendue."],
    [/^Could not query the node: (.*)\. If an access token is configured, the explorer will ask for it\.$/, "Impossible d'interroger le nœud : $1. Si un jeton d'accès est configuré, l'explorateur le demandera."],
    [/^([\d.]+)%$/, "$1 %"]
  ],
  "ja": [
    [/^Block (\d+)$/, "ブロック $1"],
    [/^(\d+) confirmation\(s\)$/, "$1 回承認"],
    [/^(\d+) unspent output\(s\)$/, "未使用出力 $1 件"],
    [/^(\d+) shown$/, "$1 件を表示"],
    [/^(\d+)% witness data$/, "証人データ $1 %"],
    [/^Inputs \((\d+)\)$/, "入力($1)"],
    [/^Outputs \((\d+)\)$/, "出力($1)"],
    [/^(\d+) \(capped\)$/, "$1(上限あり)"],
    [/^blocks (\d+) → (\d+)$/, "ブロック $1 → $2"],
    [/^at most (\d+) blocks$/, "最大 $1 ブロック"],
    [/^\+([\d\s.,]+)% \/ ([\d\s.,]+) blocks$/, "+$1 % / $2 ブロック"],
    [/^([\d.]+) MiB — verification does not need it$/, "$1 MiB — 検証には不要です"],
    [/^([\d.]+) KiB — verification does not need it$/, "$1 KiB — 検証には不要です"],
    [/^(\d+) B — verification does not need it$/, "$1 B — 検証には不要です"],
    [/^([\d.]+) MiB$/, "$1 MiB"],
    [/^([\d.]+) KiB$/, "$1 KiB"],
    [/^(\d+) B$/, "$1 B"],
    [/^(\d+) blocks \((\d+) h\)\. It does not remove the attack, it changes its nature\. A prolonged network partition produces two chains that will not reconcile on their own\. A silent rewrite is traded for a visible split\.$/, "$1 ブロック($2 時間)。攻撃をなくすのではなく、その性質を変えます。ネットワークの分断が長く続くと、自然には和解しない 2 本のチェーンが生まれます。気づかれない書き換えを、目に見える分裂と引き換えにするのです。"],
    [/^Search went back to block (\d+) of (\d+)\. The balance shown stays exact: it comes from the set of unspent outputs, not from this list\.$/, "検索はブロック $1(全 $2)まで遡りました。表示された残高は正確なままです。この一覧ではなく、未使用出力の集合から得られています。"],
    [/^Without an amount index, the search goes back over a window of (\d+) blocks — here from (\d+) to (\d+)\. A common sum can appear thousands of times: the list is capped at the 100 most recent\. Fast, bounded, and the page says how far it went\.$/, "金額のインデックスがないため、検索は $1 ブロックの範囲を遡ります(今回は $2 から $3 まで)。よくある金額は何千回も現れることがあるため、一覧は最新の 100 件に制限されます。速く、範囲が限られ、どこまで調べたかをページが示します。"],
    [/^no block at height (\d+): the chain stops lower$/, "高さ $1 のブロックはありません:チェーンはそれより手前で終わっています"],
    [/^this address belongs to the (\w+) network, this node follows (\w+)$/, "このアドレスは $1 ネットワークのもので、このノードは $2 を追っています"],
    [/^transaction not found in the last (\d+) blocks\. This node has no index by identifier: beyond that, the search is not carried out\.$/, "直近 $1 ブロック内にトランザクションが見つかりません。このノードには識別子のインデックスがないため、それ以上は検索しません。"],
    [/^Could not query the node: (.*)\. If an access token is configured, the explorer will ask for it\.$/, "ノードに問い合わせできません:$1。アクセストークンが設定されている場合は、エクスプローラーが入力を求めます。"]
  ]
};
const I18N_PREFIXES = {"fr": {"unreadable address: ": "adresse illisible : "}, "ja": {"unreadable address: ": "アドレスを読み取れません:"}};
let LANG = "en";

function q21Locale(){
  return LANG === "fr" ? "fr-FR" : (LANG === "ja" ? "ja-JP" : "en-US");
}

// Ordinary and no-break spaces collapse; the narrow no-break space that
// French puts in numbers ("51\u202f120") is kept, so that a translated
// number keeps its separator.
function q21Norm(s){ return s.replace(/[ \t\n\r\f\u00a0]+/g, " ").trim(); }

function q21Translate(src){
  const d = I18N[LANG];
  if (!d) return null;
  const n = q21Norm(src);
  let v = d[n];
  if (v === undefined){
    const pr = I18N_PREFIXES[LANG] || {};
    for (const k in pr){ if (n.startsWith(k)){ v = pr[k] + n.slice(k.length); break; } }
  }
  if (v === undefined){
    for (const [pattern, template] of (I18N_PATTERNS[LANG] || [])){
      if (pattern.test(n)){ v = n.replace(pattern, template); break; }
    }
  }
  if (v === undefined) return null;
  // A translation that brings its own space at an end (French puts a
  // no-break space before ":" after a closing tag) replaces the source's there.
  const before = /^\s/.test(v) ? "" : src.match(/^\s*/)[0];
  const after = /\s$/.test(v) ? "" : src.match(/\s*$/)[0];
  return before + v + after;
}

function q21TranslateText(n){
  // Same distinction as in the wallet: a value we set ourselves is not a new
  // source. Without it, a refresh would translate a translation.
  if (n.__q21set === undefined || n.nodeValue !== n.__q21set) n.__q21src = n.nodeValue;
  let v = n.__q21src;
  if (LANG !== "en"){ const t = q21Translate(n.__q21src); if (t !== null) v = t; }
  if (n.nodeValue !== v) n.nodeValue = v;
  n.__q21set = v;
}

const Q21_ATTRS = ["placeholder", "title", "aria-label"];

// Attributes follow the same rule as text: a value we did not set ourselves is
// a new source. The script changes some of them as it goes (the label of a
// switch says what a click will do), and a source cached once would keep
// translating the old label.
function q21TranslateAttrs(n){
  for (const a of Q21_ATTRS){
    if (!n.hasAttribute(a)) continue;
    const key = "__q21a_" + a, set = "__q21s_" + a;
    const cur = n.getAttribute(a);
    if (n[key] === undefined || cur !== n[set]) n[key] = cur;
    let v = n[key];
    if (LANG !== "en"){ const x = q21Translate(n[key]); if (x !== null) v = x; }
    if (cur !== v) n.setAttribute(a, v);
    n[set] = v;
  }
}

function q21TranslateNode(n){
  if (!n) return;
  if (n.nodeType === 3){ q21TranslateText(n); return; }
  if (n.nodeType !== 1) return;
  const t = n.tagName;
  if (t === "SCRIPT" || t === "STYLE") return;
  if (n.id === "languages") return;
  q21TranslateAttrs(n);
  for (const e of n.childNodes) q21TranslateNode(e);
}

let q21Title = null;

function q21ApplyLanguage(code){
  LANG = (code === "fr" || code === "ja") ? code : "en";
  document.documentElement.lang = LANG;
  try { sessionStorage.setItem("q21-language", LANG); } catch (e) {}
  if (q21Title === null) q21Title = document.title;
  const title = LANG === "en" ? null : q21Translate(q21Title);
  document.title = title === null ? q21Title : title;
  q21TranslateNode(document.body);
  const g = document.getElementById("languages");
  if (g) for (const b of g.querySelectorAll("button"))
    b.setAttribute("aria-pressed", b.dataset.lang === LANG ? "true" : "false");
}

(function q21InitLanguage(){
  // English unless a language was chosen earlier in this tab.
  let choice = null;
  try { choice = sessionStorage.getItem("q21-language"); } catch (e) {}
  const start = function(){
    const g = document.getElementById("languages");
    if (g) g.addEventListener("click", function(ev){
      const b = ev.target.closest("button[data-lang]");
      if (b) q21ApplyLanguage(b.dataset.lang);
    });
    q21ApplyLanguage(choice);
    // What the script writes afterwards — every view, every refresh of the
    // home page — must be translated too.
    new MutationObserver(function(ms){
      if (LANG === "en") return;
      for (const m of ms){
        if (m.type === "characterData") q21TranslateNode(m.target);
        else if (m.type === "attributes"){ if (!m.target.closest("#languages")) q21TranslateAttrs(m.target); }
        else for (const n of m.addedNodes) q21TranslateNode(n);
      }
    }).observe(document.body, {childList:true, subtree:true, characterData:true,
                               attributes:true, attributeFilter:Q21_ATTRS});
  };
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", start);
  else start();
})();

// ---------------------------------------------------------------------------
// The token, and the fragment it shares with routing
//
// The token does not travel in the request URL: an address ends up in the
// browser history, in the logs of any intermediary, and in the Referer header
// of the first external resource loaded. It arrives in the **fragment**, which
// the browser never sends to the server.
//
// That fragment also serves routing. The two are never confused: a route
// always starts with a slash, a token never does. The token is read once,
// stored under this origin, and the fragment is handed back to routing.
//
// The storage is `localStorage`, partitioned by port: since the launcher's
// link works only once, a closed tab must be able to reopen as long as the
// program runs. The token is drawn on each run and dies with it; what remains
// in the browser afterwards opens nothing, and the first 401 erases it.
// ---------------------------------------------------------------------------
const RPC = "/rpc";
const SESSION_KEY = "q21-explorer-token";
let token = null;
let counter = 0;

function storage(){
  try { return window.localStorage; } catch (e) { return null; }
}

function storedToken(){
  try { const r = storage(); return r ? r.getItem(SESSION_KEY) : null; } catch (e) { return null; }
}

function keepToken(v){
  token = v;
  try { const r = storage(); if (v && r) r.setItem(SESSION_KEY, v); } catch (e) {}
}

function forgetToken(){
  token = null;
  try { const r = storage(); if (r) r.removeItem(SESSION_KEY); } catch (e) {}
}

// What the launcher puts in the fragment is a one-time launch token, not the
// session token: the address goes through the browser's command line, which
// other accounts can read. The page exchanges it for the session token, and
// the calls wait until that is done. If the exchange fails — link already
// used — the page takes back the token stored under this origin if there is
// one; otherwise the 401 that follows opens the input panel, as for a page
// opened manually.
let exchange = null;

async function exchangeLaunchToken(launchToken){
  try {
    const r = await fetch("/session", {method:"POST",
      headers:{"Content-Type":"application/json", "Authorization":"Bearer " + launchToken}});
    if (r.ok){ const d = await r.json(); keepToken(d.token); return; }
  } catch (e) {}
  const kept = storedToken();
  if (kept) token = kept;
}

(function readToken(){
  const f = location.hash.slice(1);
  if (f && !f.startsWith("/")){
    // Erased at once: a screenshot or a shared tab must not carry the secret
    // away.
    history.replaceState(null, "", location.pathname + "#/");
    exchange = exchangeLaunchToken(decodeURIComponent(f));
    return;
  }
  const kept = storedToken();
  if (kept) token = kept;
})();

function headers(){
  const h = {"Content-Type":"application/json"};
  if (token) h["Authorization"] = "Bearer " + token;
  return h;
}

let tokenWait = null;
function askForToken(){
  if (tokenWait) return tokenWait;
  const panel = document.getElementById("token-panel");
  panel.hidden = false;
  document.getElementById("token-input").focus();
  tokenWait = new Promise(resolve => {
    document.getElementById("token-form").addEventListener("submit", ev => {
      ev.preventDefault();
      const v = document.getElementById("token-input").value.trim();
      if (!v) return;
      keepToken(v);
      panel.hidden = true;
      document.getElementById("token-input").value = "";
      tokenWait = null;
      resolve();
    }, {once:true});
  });
  return tokenWait;
}

async function call(method, params){
  if (exchange){ await exchange; exchange = null; }
  const r = await fetch(RPC, {
    method:"POST",
    headers: headers(),
    body: JSON.stringify({jsonrpc:"2.0", id:++counter, method:method, params:params||{}})
  });
  if (r.status === 401){
    forgetToken();
    await askForToken();
    return call(method, params);
  }
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

// ---------------------------------------------------------------------------
// Rendering
//
// `v` and `n` used to be inserted raw: the invariant held only through each
// caller's discipline. A field the explorer believes numeric can arrive as a
// string — `Json::u64` switches to a string above i64::MAX — and become an
// injection. We escape by default; an intended markup fragment declares itself.
// ---------------------------------------------------------------------------
const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const trunc = (h,n)=> h ? esc(h.slice(0,n||16))+"…" : "—";
const formatBytes = n => n>=1048576 ? (n/1048576).toFixed(2)+" MiB"
                 : n>=1024 ? (n/1024).toFixed(1)+" KiB" : n+" B";
const date = t => new Date(t*1000).toISOString().replace("T"," ").slice(0,19);
const raw = h => ({__html: h});
const render = x => (x && x.__html !== undefined) ? x.__html : esc(x);

// A navigation link. The target is escaped like everything else: an address or
// an identifier coming from the node remain data.
// Both halves are escaped: the route as well as the text. An identifier or an
// address comes from the node, but nothing forces a node to be honest — and
// this page is also the one that will one day be opened on someone else's
// chain.
const link = (route, text) =>
  `<a class="flat" href="#/${esc(route)}">${esc(text)}</a>`;
const blockLink = h => link("block/"+h, h);
const txLink = (id,n) => link("tx/"+id, (id||"").slice(0,n||16)+"…");
const addressLink = (a,n) => a ? link("address/"+a, n ? a.slice(0,n)+"…" : a) : "—";

// Label. Returns markup marked `raw` directly, because that is the only way
// not to get it wrong.
//
// The defect repaired here: the "Status" tile received its string `<span
// class="badge">confirmed</span>` as is. `tile` escapes by default — that is
// the right direction, the protective one — and so the page displayed its own
// markup in plain text, on screen, before the eyes of the first user who
// opened a transaction.
//
// Writing markup by hand in an argument is the mistake; it is not fixed by
// adding `raw` at that particular spot, but by providing a function that
// builds the label and takes care of the marking. A test checks that no call
// to `tile` contains markup without going through `raw`.
const badge = (text, gray) =>
  raw(`<span class="badge${gray ? " gray" : ""}">${esc(text)}</span>`);

function tile(k,v,n){
  return `<div class="tile"><div class="k">${esc(k)}</div>
          <div class="v">${render(v)}</div>${n?`<div class="n">${render(n)}</div>`:""}</div>`;
}
function rows(target, entries){
  document.getElementById(target).innerHTML =
    entries.map(([k,v])=>`<tr><th>${esc(k)}</th><td>${render(v)}</td></tr>`).join("");
}
function showError(message){
  document.getElementById("error").hidden = false;
  document.getElementById("error-detail").textContent = message;
}
function clearError(){ document.getElementById("error").hidden = true; }

// ---------------------------------------------------------------------------
// Routing
//
// Everything happens in the fragment: no request to the server to change
// pages, and the page remains a single file served as is. The browser's
// "back" button works without us having to write anything.
// ---------------------------------------------------------------------------
let heartbeat = null;

function show(view){
  for (const s of document.querySelectorAll(".view")) s.hidden = true;
  document.getElementById("view-" + view).hidden = false;
  // The home page refreshes itself; the detail pages stay still, because a
  // past block no longer changes, and a page that reloads under your eyes
  // while you read it is a nuisance.
  if (heartbeat){ clearInterval(heartbeat); heartbeat = null; }
  if (view === "home") heartbeat = setInterval(home, 4000);
}

async function router(){
  const f = location.hash.slice(1);
  if (f && !f.startsWith("/")) return; // a token, not a route
  const parts = f.replace(/^\//, "").split("/").filter(x => x.length);
  // The network label used to be filled only by the home page: arriving by a
  // direct link to a block or a transaction, one read "…" at the top of the
  // page. It is filled once, without making the view wait.
  const netTag = document.getElementById("network");
  if (netTag.textContent === "…")
    call("getinfo").then(i => { netTag.textContent = i.network; }).catch(() => {});
  try{
    if (!parts.length){ show("home"); await home(); return; }
    switch (parts[0]){
      case "block":   show("block");   await showBlock(decodeURIComponent(parts[1]||"")); break;
      case "tx":      show("tx");      await showTx(decodeURIComponent(parts[1]||"")); break;
      case "address": show("address"); await showAddress(decodeURIComponent(parts[1]||"")); break;
      case "amount":  show("amount");  await showAmount(decodeURIComponent(parts[1]||"")); break;
      default:        location.hash = "#/";
    }
  }catch(e){
    showError(e.message);
  }
}

window.addEventListener("hashchange", router);

document.getElementById("search-form").addEventListener("submit", async ev => {
  ev.preventDefault();
  const q = document.getElementById("search-input").value.trim();
  if (!q) return;
  const help = document.getElementById("search-help");
  help.textContent = "Searching…";
  try{
    const r = await call("search", {q});
    help.textContent = "One field: the node recognizes whatever you paste.";
    document.getElementById("search-input").value = "";
    if (r.kind === "block")            location.hash = "#/block/" + encodeURIComponent(r.value);
    else if (r.kind === "block-id")    location.hash = "#/block/" + encodeURIComponent(r.value);
    else if (r.kind === "transaction") location.hash = "#/tx/" + encodeURIComponent(r.value);
    else if (r.kind === "address")     location.hash = "#/address/" + encodeURIComponent(r.value);
    else if (r.kind === "amount")      location.hash = "#/amount/" + encodeURIComponent(r.value);
  }catch(e){
    help.innerHTML = `<span class="err">${esc(e.message)}</span>`;
  }
});

// ---------------------------------------------------------------------------
// Home
// ---------------------------------------------------------------------------

async function home(){
  try{
    const [info, supply, pow, sec, mem, commit] = await Promise.all([
      call("getinfo"), call("getsupply"), call("getpow"),
      call("getsecurity"), call("getmempool"), call("getutxocommitment")
    ]);
    clearError();
    document.getElementById("network").textContent = info.network;

    // The link to the wallet only appears if this node actually serves it.
    // `q21 explorer` exposes no wallet method: showing the link there would
    // lead to a page that could not ask for anything, and would look broken
    // when it was simply in the wrong place.
    const footer = document.getElementById("wallet-footer");
    if (info.wallet_enabled){
      footer.hidden = false;
      if (token) document.getElementById("wallet-link").href =
        "/wallet#" + encodeURIComponent(token);
    }

    document.getElementById("tiles").innerHTML =
      tile("Height", raw(blockLink(info.height))) +
      tile("Tip", raw(`<span class="clip">${link("block/"+info.tip, info.tip.slice(0,20)+"…")}</span>`)) +
      tile("Cumulative work", "2^" + info.cumulative_work_bits, "expected attempts") +
      tile("Difficulty", esc(info.difficulty_bits)) +
      tile("Peers", info.peers) +
      tile("Known blocks", info.known_blocks, "including side branches");

    const pct = (supply.issued.units * 100 / supply.cap.units);
    document.getElementById("supply").innerHTML =
      tile("Issued", esc(supply.issued.q21) + " Q21") +
      tile("In the UTXO set", esc(supply.in_utxo_set.q21) + " Q21") +
      tile("Cap", supply.cap_q21.toLocaleString(q21Locale()),
            supply.under_cap ? "under the cap ✓" : "CAP EXCEEDED") +
      tile("Share issued", pct.toFixed(6) + "%") +
      tile("Unspent outputs", info.utxo_total) +
      tile("State commitment", trunc(commit.commitment, 20), esc(commit.commitment));

    rows("pow", [
      ["Epoch", pow.epoch],
      ["Table elements", pow.table_elements.toLocaleString(q21Locale())],
      ["Miner memory", formatBytes(pow.miner_memory_bytes)],
      ["Node memory", formatBytes(pow.node_memory_bytes) + " — verification does not need it"],
      ["Accesses per attempt", pow.accesses_per_attempt],
      ["Growth", "+" + pow.growth_percent + "% / " + pow.blocks_per_epoch.toLocaleString(q21Locale()) + " blocks"]
    ]);

    const s = info.network_stats;
    rows("network-stats", [
      ["Blocks received", s.blocks_received],
      ["Blocks accepted", s.blocks_accepted],
      ["Compact announcements", s.compacts_received],
      ["Rebuilt without a round trip", s.compacts_without_round_trip],
      ["Transactions received", s.txs_received],
      ["Banned peers", s.peers_banned]
    ]);

    rows("mempool", [
      ["Transactions", mem.tx_count],
      ["Bytes", formatBytes(mem.bytes)],
      ["IDs", raw(mem.txids.length
          ? mem.txids.map(t=>txLink(t,12)).join(" ")
          : "—")]
    ]);

    const first = Math.max(0, info.height - 11);
    const blocks = await Promise.all(
      Array.from({length: info.height - first + 1}, (_,i)=>
        call("getblock", {height: info.height - i}))
    );
    document.getElementById("blocks").innerHTML = blocks.map(b=>`
      <tr>
        <td>${blockLink(b.header.height)}</td>
        <td><span class="clip">${link("block/"+b.header.id, b.header.id.slice(0,24)+"…")}</span></td>
        <td>${b.tx_count}</td>
        <td>${formatBytes(b.size_bytes)}</td>
        <td>${esc(b.subsidy.q21)}</td>
        <td>${date(b.header.timestamp)}</td>
      </tr>`).join("");

    document.getElementById("security").innerHTML = `
      <h3>${sec.full_protection_possible ? "100% protection against a 51% attack: yes"
                                          : "100% protection against a 51% attack: impossible"}</h3>
      <p>${esc(sec.reason)}</p>
      <p><strong>A majority attacker can:</strong></p>
      <ul>${sec.an_attacker_can.map(x=>`<li>${esc(x)}</li>`).join("")}</ul>
      <p><strong>Even with 99% of the hash power, it cannot:</strong></p>
      <ul>${sec.an_attacker_cannot.map(x=>`<li>${esc(x)}</li>`).join("")}</ul>
      <p><strong>Rolling finality:</strong> ${sec.defenses.rolling_finality_blocks}
         blocks (${sec.defenses.rolling_finality_hours} h).
         ${esc(sec.rolling_finality_cost)}</p>`;
  }catch(e){
    showError("Could not query the node: " + e.message +
      ". If an access token is configured, the explorer will ask for it.");
  }
}

// ---------------------------------------------------------------------------
// Block
// ---------------------------------------------------------------------------

const isHex = s => /^[0-9a-fA-F]{64}$/.test(s);

async function showBlock(key){
  clearError();
  const params = isHex(key) ? {id: key} : {height: Number(key)};
  const b = await call("getblock", params);
  const e = b.header;
  document.getElementById("block-title").textContent = "Block " + e.height;

  const info = await call("getinfo");
  const confirmations = info.height - e.height + 1;

  document.getElementById("block-tiles").innerHTML =
    tile("Height", raw(blockLink(e.height))) +
    tile("Transactions", b.tx_count) +
    tile("Size", formatBytes(b.size_bytes)) +
    tile("Subsidy", esc(b.subsidy.q21) + " Q21") +
    tile("Confirmations", confirmations) +
    tile("Uncles", b.uncles.length);

  rows("block-header", [
    ["ID", raw(`<span class="mono">${esc(e.id)}</span>`)],
    ["Parent", raw(e.height > 0 ? link("block/"+e.parent, e.parent) : "—")],
    ["Merkle root", raw(`<span class="mono">${esc(e.merkle)}</span>`)],
    ["Miner", raw(`<span class="mono">${esc(e.miner)}</span>`)],
    ["Timestamp", date(e.timestamp) + " UTC"],
    ["Difficulty", e.bits],
    ["Nonce", e.nonce]
  ]);

  document.getElementById("block-transactions").innerHTML = b.transactions.map((t,i)=>{
    const outSum = t.outputs.reduce((a,o)=>a + BigInt(o.value.units), 0n);
    return `<tr>
      <td>${esc(i)}</td>
      <td><span class="clip">${txLink(t.txid, 24)}</span></td>
      <td>${t.coinbase ? '<span class="badge">mining</span>' : '<span class="badge gray">transfer</span>'}</td>
      <td>${esc(t.inputs.length)}</td>
      <td>${esc(t.outputs.length)}</td>
      <td>${esc(q21(outSum))}</td>
      <td>${esc(t.weight)}</td>
    </tr>`;
  }).join("");

  document.getElementById("block-uncles").innerHTML = b.uncles.length
    ? `<h2>Uncles</h2><div class="scroll"><table><thead><tr><th>Height</th><th>ID</th><th>Miner</th></tr></thead><tbody>` +
      b.uncles.map(o=>`<tr><td>${esc(o.height)}</td><td><span class="clip">${esc(o.id)}</span></td><td><span class="clip">${trunc(o.miner,20)}</span></td></tr>`).join("") +
      `</tbody></table></div>`
    : "";
}

// Conversion from units to Q21, with integers only.
//
// An amount never goes through a float: 0.1 + 0.2 does not make 0.3 in binary
// floating point, and a blockchain that rounds a balance is no longer a
// blockchain.
function q21(units){
  const u = BigInt(units);
  const neg = u < 0n;
  const a = neg ? -u : u;
  const whole = a / 100000000n;
  const dec = (a % 100000000n).toString().padStart(8, "0");
  return (neg ? "-" : "") + whole.toString() + "." + dec;
}

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

async function showTx(txid){
  clearError();
  const r = await call("gettransaction", {txid});
  const t = r.transaction;
  const info = await call("getinfo");
  const outSum = t.outputs.reduce((a,o)=>a + BigInt(o.value.units), 0n);

  // The fee: what the inputs bring in minus what the outputs take away. The
  // node resolves it through its index; without one, or for a coin that is too
  // old, `fee_known` is false and no made-up figure is shown.
  const feeTile = t.coinbase
    ? tile("Fee", "—", "a coinbase collects fees, it pays none")
    : (r.fee_known
        ? tile("Fee", esc(r.fee.q21) + " Q21", "paid to the miner")
        : tile("Fee", "—", "unresolved without an index"));

  document.getElementById("tx-tiles").innerHTML =
    tile("ID", raw(`<span class="clip">${esc(t.txid.slice(0,20))}…</span>`), t.txid) +
    tile("Status", badge(r.confirmed ? "confirmed" : "pending", !r.confirmed),
      r.confirmed ? (info.height - r.height + 1) + " confirmation(s)" : "in the mempool") +
    tile("Block", raw(r.confirmed ? blockLink(r.height) : "—")) +
    tile("Output value", q21(outSum) + " Q21") +
    feeTile +
    tile("Size", formatBytes(t.size_bytes), t.witness_percent + "% witness data") +
    tile("Weight", t.weight.toLocaleString(q21Locale()));

  // Each input now carries the amount of the output it consumes, when the
  // index was able to find it. A "?" honestly says "unresolved".
  const amounts = r.input_amounts || [];
  document.getElementById("tx-inputs").innerHTML =
    `<div class="t">Inputs (${esc(t.inputs.length)})</div>` +
    (t.coinbase
      ? `<div class="l"><span class="g">Coin creation — this transaction consumes nothing</span></div>`
      : t.inputs.map((e,i)=>{
          const m = amounts[i] || {};
          const v = (m.known && m.value) ? m.value.q21 : "?";
          return `
        <div class="l">
          <span class="g">${txLink(e.txid, 18)}<span style="color:var(--muted)"> : ${esc(e.index)}</span></span>
          <span class="d">${esc(v)}</span>
        </div>`;}).join(""));

  document.getElementById("tx-outputs").innerHTML =
    `<div class="t">Outputs (${esc(t.outputs.length)})</div>` +
    t.outputs.map(o=>`
      <div class="l">
        <span class="g">${addressLink(o.address, 22)}</span>
        <span class="d">${esc(o.value.q21)}</span>
      </div>`).join("");

  document.getElementById("tx-note").innerHTML = t.coinbase
    ? `<div class="warn info"><h3>Mining transaction</h3>
       <p>It creates the block subsidy and collects the fees of the other
       transactions. It consumes no earlier output, and what it produces can
       only be spent after the maturity delay — so that a block undone by a
       reorg cannot already have been used to pay someone.</p></div>`
    : (r.fee_known
        ? ""
        : `<div class="warn info"><h3>Fee unresolved</h3>
       <p>At least one input is outside this node's index — no index, or a
       coin too old for it. The fee is not computed from a partial sum: the
       page would rather stay silent than show a figure it has not
       verified.</p></div>`);
}

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

async function showAddress(address){
  clearError();
  const a = await call("getaddress", {address: address, max: 100});

  rows("address-identity", [
    ["Address", raw(`<span class="mono" style="word-break:break-all;white-space:normal">${esc(a.address)}</span>`)],
    ["Key hash", raw(`<span class="mono" style="word-break:break-all;white-space:normal">${esc(a.key_hash)}</span>`)]
  ]);

  const received = a.movements.reduce((s,m)=>s + BigInt(m.received.units), 0n);
  const sent = a.movements.reduce((s,m)=>s + BigInt(m.sent.units), 0n);

  document.getElementById("address-tiles").innerHTML =
    tile("Balance", esc(a.balance.q21) + " Q21", a.unspent_outputs + " unspent output(s)") +
    tile("Movements", a.total_movements,
          a.movements.length < a.total_movements
            ? a.movements.length + " shown" : "all shown") +
    tile("Received (shown)", q21(received) + " Q21") +
    tile("Sent (shown)", a.amounts_out_all_resolved
            ? q21(sent) + " Q21" : "—",
          a.amounts_out_all_resolved ? null : "unresolved without an index");

  // How complete the answer is gets displayed, not guessed: otherwise an
  // address whose history is bounded looks like an address with no past.
  document.getElementById("address-note").innerHTML = a.complete_history
    ? `<div class="warn info"><h3>Full history</h3><p>${esc(a.note)}</p>
       <p>The balance, however, depends on no index: it comes from the set
       of unspent outputs this node validated itself. It is exact
       even when the history is not.</p></div>`
    : `<div class="warn"><h3>Bounded history</h3><p>${esc(a.note)}</p>
       <p>Search went back to block ${esc(a.floor)} of ${esc(a.height)}.
       The balance shown stays exact: it comes from the set of unspent
       outputs, not from this list.</p></div>`;

  document.getElementById("address-movements").innerHTML = a.movements.length
    ? a.movements.map(m=>`
      <tr>
        <td>${m.coinbase ? '<span class="badge">mining</span>'
             : (BigInt(m.sent.units) > 0n ? '<span class="badge gray">sent</span>'
                                             : '<span class="badge gray">received</span>')}</td>
        <td>${BigInt(m.received.units) > 0n ? esc(m.received.q21) : "—"}</td>
        <td>${!m.amount_out_known ? '<span style="color:var(--muted)">?</span>'
             : (BigInt(m.sent.units) > 0n ? esc(m.sent.q21) : "—")}</td>
        <td>${esc(m.confirmations)}</td>
        <td>${blockLink(m.height)}</td>
        <td>${date(m.timestamp)}</td>
        <td><span class="clip">${txLink(m.txid, 18)}</span></td>
      </tr>`).join("")
    : `<tr><td colspan="7" style="color:var(--muted)">No movement within the search range.</td></tr>`;
}

// ---------------------------------------------------------------------------
// Amount
// ---------------------------------------------------------------------------

async function showAmount(m){
  clearError();
  const r = await call("getamount", {amount: m});

  document.getElementById("amount-tiles").innerHTML =
    tile("Amount searched", esc(r.amount.q21) + " Q21") +
    tile("Outputs found", r.results.length + (r.capped ? " (capped)" : ""),
          r.capped ? "the 100 most recent" : null) +
    tile("Window", "blocks " + esc(r.since) + " → " + esc(r.height),
          "at most " + esc(r.window) + " blocks");

  // The same honest "this is how far I searched" as the rest of the page.
  document.getElementById("amount-note").innerHTML =
    `<div class="warn info"><h3>Bounded search</h3>
     <p>Without an amount index, the search goes back over a window of ${esc(r.window)}
     blocks — here from ${esc(r.since)} to ${esc(r.height)}. A common sum can
     appear thousands of times: the list is capped at the 100 most
     recent. Fast, bounded, and the page says how far it went.</p></div>`;

  document.getElementById("amount-rows").innerHTML = r.results.length
    ? r.results.map(s=>`
      <tr>
        <td><span class="clip">${txLink(s.txid, 18)}</span></td>
        <td>${blockLink(s.height)}</td>
        <td>${addressLink(s.address, 22)}</td>
        <td>${esc(s.value.q21)}</td>
      </tr>`).join("")
    : `<tr><td colspan="4" style="color:var(--muted)">No output of this amount in the window searched.</td></tr>`;
}

// ---------------------------------------------------------------------------

router();
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    /// Extracts the content of the page's `<script>` block.
    fn script() -> &'static str {
        let start = PAGE.find("<script>").expect("script block") + "<script>".len();
        let end = PAGE.find("</script>").expect("end of script block");
        &PAGE[start..end]
    }

    /// The source text of every exact key of the translation tables, keyed by
    /// language, decoded from the JSON line of `const I18N =`.
    fn table_keys(lang: &str) -> Vec<String> {
        let s = script();
        let start = s.find("const I18N = ").expect("table") + "const I18N = ".len();
        let end = start + s[start..].find('\n').expect("end of table");
        let json = s[start..end].trim_end_matches(';');
        let table = crate::json::parse(json).expect("the table is valid JSON");
        let obj = table.get(lang).expect("language present");
        match obj {
            crate::json::Json::Object(entries) => entries.keys().cloned().collect(),
            _ => panic!("the {lang} table is not an object"),
        }
    }

    /// The page's text, normalized as the engine normalizes it: `&nbsp;` is a
    /// space and runs of white space collapse to one.
    fn normalized_page() -> String {
        let start = PAGE.find("const I18N = ").expect("tables");
        let last = PAGE.find("const I18N_PREFIXES = ").expect("prefixes");
        let end = last + PAGE[last..].find('\n').expect("end of tables");
        let p = format!("{}{}", &PAGE[..start], &PAGE[end..])
            .replace("&nbsp;", " ")
            .replace('\u{a0}', " ");
        p.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn the_page_loads_no_external_resource() {
        // An explorer that calls a CDN hands that CDN the list of everything
        // one looks at. The check is crude but it catches the most likely
        // mistake: a font or a script added later.
        for forbidden in [
            "http://",
            "https://",
            "//cdn",
            "fonts.googleapis",
            "unpkg",
            "jsdelivr",
        ] {
            assert!(
                !PAGE.contains(forbidden),
                "the page references an external resource: {forbidden}"
            );
        }
    }

    #[test]
    fn the_page_is_well_formed() {
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
        assert!(
            !PAGE.contains("@@"),
            "a template marker was left in the page"
        );
    }

    /// The explorer translates like the wallet, and keeps the language.
    ///
    /// Regression v0.2.0: the language chosen in the wallet was lost when
    /// opening the explorer, which had no way to translate.
    #[test]
    fn the_explorer_translates_and_keeps_the_language() {
        let s = script();
        for piece in [
            "const I18N =",
            "const I18N_PATTERNS =",
            "const I18N_PREFIXES =",
            "function q21Translate(",
            "function q21ApplyLanguage(",
            "new MutationObserver(",
            r#"sessionStorage.getItem("q21-language")"#,
            r#"sessionStorage.setItem("q21-language", LANG)"#,
        ] {
            assert!(s.contains(piece), "translation engine incomplete: {piece}");
        }
        assert!(
            PAGE.contains(r#"id="languages""#),
            "language selector missing"
        );
        for code in ["en", "fr", "ja"] {
            assert!(
                PAGE.contains(&format!(r#"data-lang="{code}""#)),
                "language {code} missing from the selector"
            );
        }
        // English is the source and the default: nothing remembered means
        // English, whatever the browser's own language.
        assert!(PAGE.contains(r#"<html lang="en">"#));
        assert!(s.contains(r#"let LANG = "en";"#));
        assert!(s.contains(r#"LANG = (code === "fr" || code === "ja") ? code : "en";"#));
        assert!(
            !s.contains("navigator.language"),
            "the default language must not follow the browser"
        );
        // The main labels do have their translation in both languages.
        let fr = table_keys("fr");
        let ja = table_keys("ja");
        for key in [
            "Latest blocks",
            "Proof of work",
            "What the protocol does not protect",
            "Merkle root",
            "Full history",
        ] {
            assert!(
                fr.iter().any(|k| k == key),
                "{key} has no French translation"
            );
            assert!(
                ja.iter().any(|k| k == key),
                "{key} has no Japanese translation"
            );
        }
    }

    /// Every exact key of the tables is a text the page really writes, or a
    /// message the node really sends.
    ///
    /// A key that no longer matches any text is a translation that silently
    /// stopped working: the English source changed, the table did not. The
    /// node's messages cannot be found in the page; they are listed here, and
    /// each one is a message of `src/rpc.rs` — once translated, it must keep
    /// exactly this English wording for its French and Japanese to apply.
    #[test]
    fn every_table_key_appears_in_the_page() {
        const FROM_THE_NODE: [&str; 19] = [
            "Consensus defines the valid chain as the one carrying the most work. A majority produces more of it than everyone else, by definition. Refusing its chain would require knowing that it is them: an identity, hence an authority, hence the end of permissionlessness. This is a theorem, not an implementation gap.",
            "reorganize recent blocks, and so undo its own payments",
            "refuse to include certain transactions",
            "steal a coin it holds no key for",
            "create a single unit beyond the subsidy",
            "raise the cap of 21,000,001",
            "change a rule: its blocks are simply rejected",
            "Full history: the address index covers the whole chain.",
            "Bounded history: this node runs without an address index. Sends are not resolved, and the search stops at the floor shown. Restart it with --address-index for a complete answer.",
            "empty search",
            "search too long",
            "unreadable height",
            "unreadable amount: at most 8 decimals",
            "neither a block nor a transaction known to this node",
            "neither a height, nor a 64-character hexadecimal identifier, nor a valid address",
            "index unavailable",
            "transaction not found",
            "block not found",
            "too many searches in progress on this public service: try again in a minute",
        ];
        let page = normalized_page();
        assert!(
            !page.contains("const I18N"),
            "the tables must not be searched"
        );
        let keys = table_keys("fr");
        assert!(
            keys.len() > 100,
            "only {} keys: the table is missing",
            keys.len()
        );
        let missing: Vec<&String> = keys
            .iter()
            .filter(|k| !FROM_THE_NODE.contains(&k.as_str()) && !page.contains(k.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "table keys not found in the page source: {missing:#?}"
        );
        // And the node's messages are really not in the page: a key that
        // moved into the page belongs to the check above.
        for key in FROM_THE_NODE {
            assert!(
                !page.contains(key),
                "{key:?} is in the page, not from the node"
            );
            assert!(
                keys.iter().any(|k| k == key),
                "{key:?} has no French translation"
            );
        }
        // Every Japanese key also has a French translation.
        for key in table_keys("ja") {
            assert!(
                keys.contains(&key),
                "{key:?} is translated into Japanese only"
            );
        }
    }

    /// Selecting French gives back the French of the page as it was written
    /// before English became the source.
    #[test]
    fn the_french_table_gives_back_the_original_french() {
        let s = script();
        for (en, fr) in [
            ("Node unreachable", "Nœud injoignable"),
            ("Access token required", "Jeton d'accès requis"),
            (
                "What the protocol does not protect",
                "Ce que le protocole ne protège pas",
            ),
            ("Latest blocks", "Derniers blocs"),
            ("Mempool", "Réservoir de transactions"),
        ] {
            assert!(
                s.contains(&format!("\"{en}\": \"{fr}\"")),
                "{en} no longer gives {fr}"
            );
        }
    }

    /// The page reads the block header under the names the node gives it.
    ///
    /// Regression: the page read `prev_block` and `merkle_root`, while the
    /// node returns `parent` and `merkle`. The Parent and Merkle root rows
    /// displayed "undefined".
    #[test]
    fn the_block_header_is_read_under_the_node_names() {
        let s = script();
        for old in ["e.prev_block", "e.merkle_root"] {
            assert!(
                !s.contains(old),
                "field that does not exist on the node side: {old}"
            );
        }
        for new in ["e.parent", "e.merkle)", "e.miner)", "o.miner,"] {
            assert!(s.contains(new), "expected field: {new}");
        }
        let rpc = include_str!("rpc.rs");
        for field in [r#".set("parent""#, r#".set("merkle""#, r#".set("miner""#] {
            assert!(rpc.contains(field), "the node no longer returns {field}");
        }
    }

    #[test]
    fn the_page_provides_both_themes() {
        assert!(PAGE.contains("prefers-color-scheme: dark"));
    }

    #[test]
    fn the_page_escapes_what_it_shows() {
        // Identifiers and messages come from the node, but a peer may have
        // injected anything into them. Everything goes through an escaping
        // function.
        assert!(PAGE.contains("const esc ="));
        assert!(PAGE.contains("&amp;"));
        assert!(PAGE.contains("&lt;"));
    }

    /// What this page shows and public explorers keep quiet about.
    #[test]
    fn the_page_shows_what_is_not_protected() {
        assert!(PAGE.contains("What the protocol does not protect"));
        assert!(PAGE.contains("an_attacker_can"));
        assert!(PAGE.contains("rolling_finality_cost"));
    }

    /// The token is asked for; it no longer goes into the address.
    #[test]
    fn the_page_explains_the_token_on_failure() {
        assert!(PAGE.contains("the explorer will ask for it"));
        assert!(PAGE.contains("Authorization"));
        assert!(
            !PAGE.contains("location.search"),
            "the query string must no longer be copied to the RPC"
        );
    }

    /// The four views exist, and the router knows all of them.
    #[test]
    fn the_four_views_exist() {
        for v in ["home", "block", "tx", "address"] {
            assert!(
                PAGE.contains(&format!(r#"id="view-{v}""#)),
                "missing view: {v}"
            );
        }
        for r in ["case \"block\":", "case \"tx\":", "case \"address\":"] {
            assert!(PAGE.contains(r), "missing route: {r}");
        }
    }

    /// The token and the routing share the fragment without being confused.
    ///
    /// A route starts with a slash, a token never does. That is what lets the
    /// launcher pass the token in the fragment — where it is never sent to the
    /// server — without depriving the page of its routing.
    #[test]
    fn the_token_and_the_route_are_told_apart_in_the_fragment() {
        assert!(
            PAGE.contains(r#"if (f && !f.startsWith("/"))"#),
            "nothing tells a token from a route"
        );
        // And the fragment is erased as soon as it is read: a screenshot or a
        // shared tab must not carry the secret away.
        assert!(PAGE.contains("history.replaceState"));
    }

    /// The fragment is a one-time launch token, exchanged before any call.
    ///
    /// Same rule as for the wallet: what the launcher puts in the address goes
    /// through the browser's command line, and must therefore be good only
    /// once.
    #[test]
    fn the_fragment_is_a_launch_token_exchanged_before_any_call() {
        assert!(PAGE.contains("exchange = exchangeLaunchToken(decodeURIComponent(f));"));
        assert!(!PAGE.contains("keepToken(decodeURIComponent(f));"));
        assert!(PAGE.contains("fetch(\"/session\""));
        let wait = PAGE
            .find("if (exchange){ await exchange; exchange = null; }")
            .expect("wait");
        let call = PAGE.find("async function call(").expect("call");
        assert!(wait > call && wait - call < 80, "the wait must open `call`");
    }

    /// A closed tab reopens as long as the program runs.
    ///
    /// The launcher's link works only once. Reopened, the exchange fails and
    /// the page takes back the token stored under this origin —
    /// `localStorage`, partitioned by port, touched by a single access point.
    /// An expired token is erased by the 401 that follows, before the panel
    /// opens.
    #[test]
    fn a_reopened_tab_takes_back_the_stored_token() {
        assert_eq!(PAGE.matches("window.localStorage").count(), 1);
        assert!(!PAGE.contains("localStorage."));
        // `sessionStorage` carries only the chosen language, as in the wallet:
        // never the token. Each use targets `q21-language` and sits inside a
        // `try`, because a browser may refuse storage.
        for (i, _) in PAGE.match_indices("sessionStorage.") {
            let rest = &PAGE[i..(i + 60).min(PAGE.len())];
            assert!(
                rest.contains("q21-language"),
                "only the language choice goes through sessionStorage: {rest}"
            );
            // The `try` is read on the same line, before the access. We bound
            // it by the line rather than by a number of bytes: cutting in the
            // middle of an accented character would make the test itself
            // panic.
            let line = PAGE[..i].rfind('\n').map(|d| d + 1).unwrap_or(0);
            let before = &PAGE[line..i];
            assert!(
                before.contains("try {"),
                "unguarded storage access: {before}"
            );
        }
        assert!(PAGE.contains("r.setItem(SESSION_KEY"));
        assert!(PAGE.contains("r.removeItem(SESSION_KEY"));
        let failure = PAGE
            .find("} catch (e) {}\n  const kept = storedToken();\n  if (kept) token = kept;\n}")
            .expect("recovery after a failed exchange");
        assert!(
            failure
                > PAGE
                    .find("async function exchangeLaunchToken(")
                    .expect("exchange")
        );
        assert!(
            PAGE.contains("if (r.status === 401){\n    forgetToken();\n    await askForToken();"),
            "a 401 must erase the stored token before asking for it again"
        );
        for forbidden in ["indexedDB.open", "document.cookie ="] {
            assert!(!PAGE.contains(forbidden), "{forbidden}");
        }
    }

    /// The token is asked for in the page, not through a browser dialog.
    ///
    /// `window.prompt` blocks the whole tab, cannot be styled, and on some
    /// browsers simply does not show up.
    #[test]
    fn the_token_is_asked_for_in_the_page() {
        assert!(PAGE.contains(r#"id="token-panel""#));
        assert!(
            !PAGE.contains("window.prompt"),
            "the token is still asked for through a browser dialog"
        );
    }

    /// The page has a search field, and it goes through the node.
    ///
    /// Guessing on the page side what an input is would require
    /// reimplementing the reading of an address there — hence bech32, hence
    /// its checksum. The node already knows how to do it, and a single
    /// implementation cannot diverge from itself.
    #[test]
    fn search_goes_through_the_node() {
        assert!(PAGE.contains(r#"id="search-form""#));
        assert!(PAGE.contains(r#"call("search", {q})"#));
    }

    /// No amount goes through a float.
    ///
    /// The page adds up amounts — the outputs of a transaction, what an
    /// address has received. In binary floating point, these sums drift. A
    /// blockchain that rounds a balance is no longer a blockchain.
    #[test]
    fn no_float_on_an_amount() {
        let script = {
            let d = PAGE.find("<script>").expect("script block") + "<script>".len();
            let f = PAGE.find("</script>").expect("end of script");
            &PAGE[d..f]
        };
        assert!(script.contains("BigInt("), "amounts are not integers");
        assert!(
            script.contains("100000000n"),
            "the conversion to Q21 must be done with integers"
        );
        for forbidden in ["parseFloat", "Number(o.value", "toFixed(8)"] {
            assert!(
                !script.contains(forbidden),
                "an amount goes through a float: {forbidden}"
            );
        }
    }

    /// A detail page does not reload under the eyes of whoever is reading it.
    #[test]
    fn only_the_home_page_refreshes() {
        assert!(PAGE.contains("clearInterval(heartbeat)"));
        assert!(PAGE.contains(r#"if (view === "home") heartbeat = setInterval"#));
    }

    /// Numbers follow the language: the locale comes from the engine, never a
    /// fixed one.
    #[test]
    fn numbers_follow_the_language() {
        let s = script();
        assert!(s.contains("function q21Locale"));
        for tag in ["en-US", "ja-JP", "fr-FR"] {
            assert!(s.contains(tag), "missing locale: {tag}");
        }
        assert!(!s.contains("toLocaleString(\"fr-FR\")"));
        assert!(s.contains("toLocaleString(q21Locale())"));
    }

    /// No call to `tile` carries markup without going through `raw`.
    ///
    /// # The defect this test locks out
    ///
    /// A transaction's "Status" tile received its string as is:
    ///
    /// ```text
    ///     tile("Status", r.confirmed ? '<span class="badge">confirmed</span>' : ...)
    /// ```
    ///
    /// `tile` escapes by default — that is the right direction, the one that
    /// protects against injection — and so the page displayed its own markup in
    /// plain text, on screen. The first user to open a transaction saw it.
    ///
    /// No test could catch it: the existing ones looked for the opposite
    /// defect, markup inserted **without** escaping. One had to look the other
    /// way.
    ///
    /// The fix is not to add `raw` at that spot, but to provide a function —
    /// `badge` — that builds the label and takes care of the marking. This test
    /// checks that we do not go back.
    #[test]
    fn no_tile_carries_unmarked_markup() {
        let s = script();
        let mut rest = s;
        let mut examined = 0;
        while let Some(i) = rest.find("tile(") {
            rest = &rest[i + "tile(".len()..];
            // Balanced closing parenthesis: the arguments themselves contain
            // function calls.
            let mut depth = 1usize;
            let mut end = rest.len();
            for (j, c) in rest.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = j;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let args = &rest[..end];
            examined += 1;

            // Markup is a chevron followed by a letter or a slash. A
            // comparison — `a.length < b` — carries a space, and must not be
            // mistaken for a tag.
            let bytes = args.as_bytes();
            let markup = bytes
                .windows(2)
                .any(|f| f[0] == b'<' && (f[1].is_ascii_alphabetic() || f[1] == b'/'));
            assert!(
                !markup || args.contains("raw("),
                "a tile carries markup without marking it: it will be escaped \
                 and displayed as plain text on screen.\n\n    tile({})\n\n\
                 Use badge(), or wrap the value in raw().",
                args.trim()
            );
        }
        assert!(
            examined >= 10,
            "the scan only found {examined} tiles: the page changed shape and \
             the test no longer checks anything"
        );
    }

    /// The `innerHTML` insertion points escape by default.
    #[test]
    fn values_are_escaped_by_default() {
        assert!(PAGE.contains("const render ="));
        assert!(PAGE.contains("${render(v)}"));
    }
}
