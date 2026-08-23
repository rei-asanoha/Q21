//! Portefeuille de bureau, page unique servie par le noeud.
//!
//! # Ce que cette page est
//!
//! L'ecran que voit quelqu'un qui double-clique sur l'application. Il doit
//! pouvoir recevoir et envoyer du Q21 sans jamais ouvrir un terminal. Rien de
//! plus : cinq vues — solde, reception, envoi, historique, informations — et
//! aucune fonction qui ne serve directement l'une des cinq.
//!
//! # Trois decisions qui expliquent le reste du fichier
//!
//! **Aucune ressource externe.** Ni police, ni feuille de style, ni script
//! distant. Une page de portefeuille qui appelle un CDN annonce a ce CDN chaque
//! fois que son porteur ouvre son portefeuille, et lui donne le pouvoir de
//! remplacer le code qui manipule les fonds. La regle est verifiee par une
//! epreuve, pas par la vigilance.
//!
//! **Presque aucun stockage navigateur.** Le seul objet conserve est le jeton
//! de session, dans `sessionStorage` : il est cloisonne par origine — donc par
//! port, tire au hasard a chaque lancement — et meurt avec l'onglet. Sans lui,
//! un simple rafraichissement rendait le portefeuille inutilisable.
//!
//! `localStorage`, `indexedDB` et les cookies restent interdits : ils survivent
//! a la fermeture, et rien ici ne doit survivre a la session. La graine et la
//! phrase secrete, elles, ne quittent jamais le noeud — le navigateur ne les
//! voit a aucun moment.
//!
//! **Aucun flottant sur un montant.** `0.1 + 0.2 != 0.3` en IEEE 754, et un
//! `parseFloat` sur un solde perd des unites. Toute l'arithmetique monetaire de
//! cette page passe par `BigInt`, et le corps de la requete d'envoi est
//! assemble a la main pour que les chiffres partent tels quels — `JSON.stringify`
//! d'un grand entier serait deja une conversion de trop.
//!
//! # Le jeton d'acces
//!
//! Le lanceur ouvre le navigateur sur `127.0.0.1:PORT/#<jeton>`. Le fragment
//! n'est jamais transmis au serveur : il n'apparait ni dans les journaux d'un
//! mandataire, ni dans l'en-tete `Referer`. La page le lit, **efface
//! immediatement le fragment de la barre d'adresse**, et le presente ensuite en
//! `Authorization: Bearer`. S'il manque, elle le demande par un champ de la
//! page — jamais par une boite de dialogue du navigateur, qui n'a ni le style
//! ni la discretion d'un champ de mot de passe.

/// Page complete du portefeuille. Aucune ressource externe, par construction.
pub const PAGE: &str = r##"<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Q21 — portefeuille</title>
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
[hidden]{display:none !important}
body{
  margin:0;background:var(--fond);color:var(--texte);
  font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  -webkit-text-size-adjust:100%;
}
.enveloppe{max-width:900px;margin:0 auto;padding:1.1rem .9rem 3rem}
header{border-bottom:2px solid var(--texte);padding-bottom:.8rem;margin-bottom:1rem}
h1{margin:0;font-size:1.35rem;letter-spacing:-.02em}
.sous{color:var(--doux);font-size:.85rem;margin-top:.3rem}
.etat{display:inline-block;padding:.12rem .5rem;border-radius:3px;font-size:.72rem;
  font-family:ui-monospace,monospace;background:var(--accent-fond);color:var(--accent);
  margin-left:.4rem;vertical-align:middle}
h2{font-size:.92rem;text-transform:uppercase;letter-spacing:.08em;color:var(--doux);
  margin:1.6rem 0 .7rem;font-weight:600}
h2:first-child{margin-top:.4rem}

/* Onglets : la barre defile lateralement sur telephone plutot que de se replier
   en deux lignes, ce qui deplacerait le contenu a chaque changement de vue. */
.onglets{display:flex;gap:.3rem;overflow-x:auto;margin-bottom:1.2rem;
  border-bottom:1px solid var(--bord);scrollbar-width:none}
.onglets::-webkit-scrollbar{display:none}
.onglets button{
  flex:0 0 auto;appearance:none;background:none;border:none;border-bottom:2px solid transparent;
  color:var(--doux);font:inherit;font-size:.88rem;padding:.55rem .7rem;cursor:pointer;
  white-space:nowrap;margin-bottom:-1px;
}
.onglets button:hover{color:var(--texte)}
.onglets button.actif{color:var(--accent);border-bottom-color:var(--accent);font-weight:600}

.grille{display:grid;gap:.7rem;grid-template-columns:1fr}
@media(min-width:560px){.grille{grid-template-columns:repeat(auto-fit,minmax(210px,1fr))}}
.tuile{background:var(--carte);border:1px solid var(--bord);border-radius:6px;padding:.8rem .95rem}
.tuile .k{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--tenu)}
.tuile .v{font-size:1.15rem;font-family:ui-monospace,monospace;margin-top:.2rem;
  font-variant-numeric:tabular-nums;word-break:break-all}
.tuile .n{font-size:.75rem;color:var(--doux);margin-top:.25rem}
.tuile.forte{border-color:var(--bord-fort)}
.gros{font-family:ui-monospace,monospace;font-size:2rem;line-height:1.15;letter-spacing:-.02em;
  font-variant-numeric:tabular-nums;display:inline-block;word-break:break-all}
@media(min-width:560px){.gros{font-size:2.4rem}}
.gros .centimes{font-size:.55em;color:var(--doux)}
.unite{font-size:.85rem;color:var(--doux);margin-left:.35rem}

table{width:100%;border-collapse:collapse;font-family:ui-monospace,monospace;font-size:.8rem}
th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--bord);
  font-variant-numeric:tabular-nums;white-space:nowrap}
th{color:var(--tenu);font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;
  border-bottom:1px solid var(--bord-fort)}
tbody tr:hover{background:var(--accent-fond)}
.defile{overflow-x:auto;background:var(--carte);border:1px solid var(--bord);border-radius:6px}
.mono{font-family:ui-monospace,monospace}
.coupe{max-width:18ch;overflow:hidden;text-overflow:ellipsis;display:inline-block;vertical-align:bottom}
/* Une case sans valeur porte un tiret, pas un zero : un zero se lirait comme
   un chiffre mesure. Un montant minore porte la couleur d'alerte, pour qu'on
   ne le lise pas comme un fait. */
.vide{color:var(--tenu)}
.minore{color:var(--alerte)}

.avert{background:var(--carte);border:1px solid var(--bord);border-left:3px solid var(--alerte);
  border-radius:5px;padding:.85rem .95rem;margin:.8rem 0}
.avert h3{margin:0 0 .4rem;font-size:.76rem;text-transform:uppercase;letter-spacing:.06em;color:var(--alerte)}
.avert p{margin:0 0 .5rem;font-size:.88rem;color:var(--doux)}
.avert p:last-child{margin-bottom:0}
.note{background:var(--carte);border:1px solid var(--bord);border-left:3px solid var(--accent);
  border-radius:5px;padding:.85rem .95rem;margin:.8rem 0;font-size:.88rem;color:var(--doux)}
.note h3{margin:0 0 .4rem;font-size:.76rem;text-transform:uppercase;letter-spacing:.06em;color:var(--accent)}
.note p{margin:0 0 .5rem}
.note p:last-child{margin-bottom:0}

label{display:block;font-size:.74rem;text-transform:uppercase;letter-spacing:.05em;
  color:var(--tenu);margin:.9rem 0 .3rem}
input{
  width:100%;background:var(--carte);color:var(--texte);border:1px solid var(--bord-fort);
  border-radius:5px;padding:.6rem .7rem;font:inherit;font-family:ui-monospace,monospace;
  font-size:.92rem;
}
input:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:var(--accent)}
.aide{font-size:.78rem;color:var(--tenu);margin-top:.25rem}
button.action{
  appearance:none;background:var(--accent);color:var(--fond);border:1px solid var(--accent);
  border-radius:5px;padding:.6rem 1rem;font:inherit;font-size:.9rem;font-weight:600;
  cursor:pointer;margin-top:1rem;width:100%;
}
@media(min-width:560px){button.action{width:auto}}
button.action:hover{filter:brightness(1.08)}
button.action:disabled{opacity:.5;cursor:not-allowed}
button.discret{
  appearance:none;background:var(--carte);color:var(--texte);border:1px solid var(--bord-fort);
  border-radius:5px;padding:.6rem 1rem;font:inherit;font-size:.9rem;cursor:pointer;
  margin-top:1rem;width:100%;
}
@media(min-width:560px){button.discret{width:auto}}
.boutons{display:flex;flex-direction:column;gap:.5rem}
@media(min-width:560px){.boutons{flex-direction:row;align-items:center}}

.adresse{background:var(--carte);border:1px solid var(--bord);border-radius:6px;
  padding:1rem;margin-top:.8rem}
.adresse .champs{font-family:ui-monospace,monospace;font-size:1.02rem;line-height:1.9;
  word-break:break-all;letter-spacing:.01em}
@media(min-width:560px){.adresse .champs{font-size:1.2rem}}
.adresse .champs .groupe{display:inline-block;margin-right:.55em;background:var(--accent-fond);
  color:var(--accent);padding:.05em .3em;border-radius:3px}
button.copier{
  appearance:none;background:none;border:1px solid var(--bord-fort);color:var(--doux);
  border-radius:4px;padding:.3rem .7rem;font:inherit;font-size:.78rem;cursor:pointer;margin-top:.7rem;
}
button.copier:hover{color:var(--texte);border-color:var(--texte)}

.recap{background:var(--carte);border:1px solid var(--bord-fort);border-radius:6px;
  padding:.2rem .95rem;margin-top:.8rem}
.recap .l{display:flex;justify-content:space-between;gap:1rem;padding:.6rem 0;
  border-bottom:1px solid var(--bord);font-size:.88rem;align-items:baseline}
.recap .l:last-child{border-bottom:none}
.recap .l .k{color:var(--tenu);flex:0 0 auto;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em}
.recap .l .v{font-family:ui-monospace,monospace;text-align:right;word-break:break-all;
  font-variant-numeric:tabular-nums}
.recap .l.total .v{font-weight:700;font-size:1.05rem}

.badge{display:inline-block;padding:.05rem .4rem;border-radius:3px;font-size:.72rem;
  background:var(--accent-fond);color:var(--accent)}
.badge.attente{background:var(--alerte-fond);color:var(--alerte)}
footer{margin-top:2.5rem;padding-top:.9rem;border-top:1px solid var(--bord);
  color:var(--tenu);font-size:.76rem}
code{background:var(--accent-fond);color:var(--accent);padding:.1em .35em;border-radius:3px;
  font-size:.85em;font-family:ui-monospace,monospace}
.err{color:var(--alerte)}
.ok{color:var(--accent)}
</style>
</head>
<body>
<div class="enveloppe">

<header>
  <h1>Q21 <span class="etat" id="reseau">…</span></h1>
  <div class="sous">
    Portefeuille servi par <strong>votre nœud</strong>, en local. Aucune ressource
    externe n'est chargée, et rien n'est écrit dans le navigateur.
  </div>
</header>

<div id="panneau-jeton" class="avert" hidden>
  <h3>Jeton d'accès requis</h3>
  <p>
    Le nœud exige un jeton. Il est normalement transmis par le lanceur dans le
    fragment de l'adresse&nbsp;; si vous avez ouvert cette page à la main,
    saisissez ici le jeton passé à <code>--rpc-token</code>.
  </p>
  <form id="forme-jeton" class="boutons" autocomplete="off">
    <input type="password" id="saisie-jeton" placeholder="jeton d'accès" autocomplete="off" spellcheck="false">
    <button type="submit" class="action" style="margin-top:0">Déverrouiller</button>
  </form>
</div>

<div id="erreur" class="avert" hidden>
  <h3>Nœud injoignable</h3>
  <p id="erreur-detail"></p>
</div>

<div id="bandeau-sync" class="avert" hidden>
  <h3>Le solde affiché est incomplet</h3>
  <p id="sync-note"></p>
  <p id="sync-detail"></p>
</div>

<nav class="onglets" id="onglets">
  <button type="button" data-vue="solde" class="actif">Solde</button>
  <button type="button" data-vue="recevoir">Recevoir</button>
  <button type="button" data-vue="envoyer">Envoyer</button>
  <button type="button" data-vue="historique">Historique</button>
  <button type="button" data-vue="infos">Informations</button>
</nav>

<section class="vue" id="vue-solde">
  <h2>Dépensable</h2>
  <div class="tuile forte">
    <div class="v" id="solde-gros">…</div>
    <div class="n" id="solde-note">Chargement…</div>
  </div>
  <h2>Détail</h2>
  <div class="grille" id="tuiles-solde"></div>
  <div class="note">
    <h3>Pourquoi une part du solde est immature</h3>
    <p>
      Une récompense de minage n'est dépensable qu'après un long délai de
      maturation. Tant qu'il n'est pas écoulé, la somme existe, elle vous
      appartient, mais aucune transaction ne peut la dépenser. Elle est comptée
      séparément plutôt que fondue dans un total qui serait faux.
    </p>
  </div>
</section>

<section class="vue" id="vue-recevoir" hidden>
  <h2>Adresse de réception</h2>
  <p class="aide">
    Chaque paiement mérite une adresse neuve. Réutiliser une adresse ne coûte
    rien au protocole, mais relie publiquement vos paiements entre eux.
  </p>
  <button type="button" class="action" id="bouton-adresse">Créer une adresse de réception</button>
  <div id="zone-adresse"></div>
</section>

<section class="vue" id="vue-envoyer" hidden>
  <h2>Envoyer du Q21</h2>
  <form id="forme-envoi" autocomplete="off">
    <label for="champ-adresse">Adresse du destinataire</label>
    <input type="text" id="champ-adresse" placeholder="tq21…" spellcheck="false" autocomplete="off">
    <div class="aide">L'adresse porte une somme de contrôle&nbsp;: une faute de frappe sera détectée par le nœud, pas subie.</div>

    <label for="champ-montant">Montant, en Q21</label>
    <input type="text" id="champ-montant" placeholder="0.00000000" inputmode="decimal" spellcheck="false" autocomplete="off">
    <div class="aide" id="aide-montant">Huit décimales au maximum. Une unité vaut 0.00000001&nbsp;Q21.</div>

    <label for="champ-frais">Frais, en Q21</label>
    <input type="text" id="champ-frais" placeholder="0.00000000" inputmode="decimal" spellcheck="false" autocomplete="off">
    <div class="aide" id="aide-frais">Suggestion du nœud, modifiable.</div>

    <label for="champ-entrees">Entrées supposées, pour l'estimation des frais</label>
    <input type="text" id="champ-entrees" value="2" inputmode="numeric" spellcheck="false" autocomplete="off">
    <div class="aide">
      Avec ML-DSA-87 le témoin pèse la quasi-totalité d'une transaction&nbsp;: les
      frais dépendent surtout du <em>nombre d'entrées</em> consommées, que le nœud
      ne choisit qu'au moment de construire la transaction. Si l'envoi est refusé
      pour taux de frais trop bas, augmentez ce nombre et recalculez.
    </div>
    <div class="boutons">
      <button type="button" class="discret" id="bouton-estimer">Recalculer les frais</button>
      <button type="submit" class="action" id="bouton-verifier">Vérifier</button>
    </div>
  </form>

  <div id="confirmation" hidden>
    <h2>Confirmer l'envoi</h2>
    <div class="avert">
      <h3>Un envoi est définitif</h3>
      <p>
        Aucune autorité ne peut annuler une transaction acceptée. Relisez
        l'adresse caractère par caractère&nbsp;: c'est la seule vérification qui
        vous reste.
      </p>
    </div>
    <div class="recap" id="recap"></div>
    <div class="boutons">
      <button type="button" class="discret" id="bouton-annuler">Revenir</button>
      <button type="button" class="action" id="bouton-envoyer">Envoyer définitivement</button>
    </div>
  </div>

  <div id="resultat-envoi"></div>
</section>

<section class="vue" id="vue-historique" hidden>
  <h2>Mouvements</h2>
  <div id="note-historique"></div>
  <div class="defile">
    <table>
      <thead><tr><th>Genre</th><th>Reçu</th><th>Sorti</th><th>Conf.</th><th>Hauteur</th><th>Horodatage</th><th>Identifiant</th></tr></thead>
      <tbody id="mouvements"></tbody>
    </table>
  </div>
  <div id="note-colonnes"></div>
</section>

<section class="vue" id="vue-infos" hidden>
  <h2>Portefeuille</h2>
  <div class="grille" id="tuiles-infos"></div>
  <div class="note">
    <h3>ML-DSA-87 — FIPS&nbsp;204, niveau NIST&nbsp;5</h3>
    <p>
      Les signatures de ce portefeuille reposent sur ML-DSA, le schéma à réseaux
      euclidiens normalisé par le NIST en 2024 sous le nom FIPS&nbsp;204. Q21
      retient le paramétrage le plus élevé, ML-DSA-87, dont la sécurité visée
      correspond au niveau&nbsp;5 — de l'ordre d'AES-256.
    </p>
    <p>
      C'est le point qui distingue ce projet. Les signatures ECDSA que protègent
      aujourd'hui la plupart des chaînes tombent devant l'algorithme de Shor dès
      qu'une machine quantique suffisante existe&nbsp;; celles-ci ne reposent sur
      aucun problème que Shor résout. Le prix se lit dans les chiffres
      ci-dessus&nbsp;: une clef publique de 2&nbsp;592 octets, une signature de
      4&nbsp;627 octets, là où ECDSA tient en quelques dizaines.
    </p>
    <p>
      Le noyau n'implémente pas lui-même ce schéma&nbsp;: écrire soi-même une
      signature à réseaux euclidiens est une faute professionnelle. Il branche
      une implémentation auditée.
    </p>
  </div>
  <h2>Chaîne</h2>
  <div class="grille" id="tuiles-chaine"></div>

  <h2>Fermer</h2>
  <div class="note">
    <p>
      Ce portefeuille est servi par un nœud qui tourne dans la fenêtre noire
      ouverte par le lanceur. Ce bouton lui demande de s'arrêter proprement&nbsp;:
      il écrit le réservoir de transactions en attente, l'instantané de l'état et
      le portefeuille, puis rend la main. La fenêtre se referme d'elle-même.
    </p>
    <p>
      C'est la façon recommandée d'arrêter. Fermer la fenêtre noire fonctionne
      aussi. <strong>Ctrl-C</strong> fonctionne également, mais Windows pose
      alors sa propre question — «&nbsp;Terminer le programme de commandes
      (O/N)&nbsp;?&nbsp;»&nbsp;: répondez <strong>O</strong>, tout est déjà
      enregistré à ce moment-là.
    </p>
    <div class="boutons">
      <button type="button" class="action" id="bouton-fermer" style="margin-top:0">Fermer le portefeuille</button>
    </div>
    <p id="note-fermer" class="aide"></p>
  </div>
</section>

<footer>
  <p style="margin:0 0 .6rem">
    <a class="plat" id="lien-explorateur" href="/">Explorateur de la chaîne</a> —
    blocs, transactions et adresses, servis par le même nœud, sur le même port.
  </p>
  API JSON-RPC sur <code>POST /rpc</code> — <code>listmethods</code> énumère les
  méthodes disponibles. Le jeton d'accès ne quitte pas cette page&nbsp;: rien
  n'est écrit dans le navigateur. Code de recherche, non audité&nbsp;: ne protège
  aucune valeur réelle.
</footer>

</div>
<script>
"use strict";

// ---------------------------------------------------------------------------
// Jeton d'acces
// ---------------------------------------------------------------------------
//
// Le lanceur ouvre le navigateur sur .../#<jeton>. Le fragment n'est jamais
// transmis au serveur : ni journal de mandataire, ni en-tete Referer. On le lit
// une fois, on efface aussitot la barre d'adresse — une capture d'ecran, un
// partage d'onglet ou une saisie automatique ne doivent pas emporter le secret —
// puis il vit dans une variable, et nulle part ailleurs.

const RPC = "/rpc";
const UNITES_PAR_Q21 = 100000000n;

let jeton = null;
let compteur = 0;
let adresseCourante = null;
let envoiPrepare = null;
let enCours = false;

// Le jeton survit a un rafraichissement, et a rien d'autre.
//
// La premiere version le gardait dans une simple variable. Un F5 — le reflexe
// de tout le monde devant une page qui semble figee — le perdait, et le
// portefeuille devenait inutilisable jusqu'a relancer le lanceur. C'est
// exactement ce qui est arrive au premier utilisateur.
//
// `sessionStorage` est le compromis retenu, et il merite d'etre justifie :
//
// - il est **cloisonne par origine**, et l'origine contient le port, que le
//   lanceur tire au hasard a chaque demarrage. Ce qu'on y ecrit ne vaut donc
//   que pour cette execution-la ;
// - il **meurt avec l'onglet**, contrairement a `localStorage` ;
// - le jeton lui-meme est ephemere : le lanceur en tire un neuf de trente-deux
//   octets a chaque lancement, et l'ancien n'ouvre plus rien.
//
// Ce qu'on refuse toujours : que le jeton reste dans la **barre d'adresse**,
// donc dans l'historique du navigateur, dans les journaux d'un mandataire et
// dans l'en-tete `Referer`. Le fragment est efface aussitot lu.
//
// Aucun secret du portefeuille — ni graine, ni phrase — ne passe par la. Un
// jeton de session n'est pas une clef.
const CLEF_SESSION = "q21-jeton";

function retenirJeton(v){
  jeton = v;
  try { if (v) sessionStorage.setItem(CLEF_SESSION, v); } catch (e) { /* refus du navigateur : tant pis */ }
}

function oublierJeton(){
  jeton = null;
  try { sessionStorage.removeItem(CLEF_SESSION); } catch (e) { /* rien a faire */ }
}

(function lireJeton(){
  const f = location.hash.slice(1);
  if (f) {
    history.replaceState(null, "", location.pathname);
    let v = f;
    try { v = decodeURIComponent(f); } catch (e) { v = f; }
    retenirJeton(v);
    return;
  }
  // Pas de fragment : un rafraichissement, ou une ouverture a la main.
  try {
    const garde = sessionStorage.getItem(CLEF_SESSION);
    if (garde) jeton = garde;
  } catch (e) { /* stockage refuse : le panneau de saisie prendra le relais */ }
})();

function entetes(){
  const h = {"Content-Type":"application/json"};
  if (jeton) h["Authorization"] = "Bearer " + jeton;
  return h;
}

function demanderJeton(){
  const p = document.getElementById("panneau-jeton");
  p.hidden = false;
  document.getElementById("saisie-jeton").focus();
}

// Le corps est assemble a la main plutot que par JSON.stringify sur un objet :
// un montant est un entier exact, et le seul moyen sur de l'ecrire est de
// concatener ses chiffres. Passer par un `Number` intermediaire, c'est accepter
// qu'au-dela de 2^53 la valeur envoyee ne soit plus celle qui a ete confirmee.
function corpsRequete(methode, params){
  const p = (typeof params === "string") ? params : JSON.stringify(params || {});
  return '{"jsonrpc":"2.0","id":' + (++compteur) +
         ',"method":' + JSON.stringify(methode) + ',"params":' + p + '}';
}

async function appel(methode, params){
  const r = await fetch(RPC, {method:"POST", headers: entetes(), body: corpsRequete(methode, params)});
  // Un 401 rend du texte brut, pas du JSON : le lire comme du JSON masquerait
  // la vraie cause derriere une erreur d'analyse.
  if (r.status === 401){
    oublierJeton();
    demanderJeton();
    throw new Error("jeton d'accès manquant ou refusé");
  }
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

// ---------------------------------------------------------------------------
// Echappement
// ---------------------------------------------------------------------------
//
// Tout ce qui vient du noeud est traite comme hostile : une adresse, un message
// d'erreur, un genre de transaction. `rendu` echappe par defaut ; le fragment de
// balisage voulu doit se declarer par `brut`. L'invariant ne tient pas a la
// discipline de chaque appelant, il tient au type.

const ech = s => String(s).replace(/[&<>"']/g, c =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const brut = h => ({__html: h});
const rendu = x => (x && x.__html !== undefined) ? x.__html : ech(x);

// Un fragment de balisage assemble ici meme, dont chaque valeur variable est
// deja passee par `ech`. Il se declare : une interpolation qui ne nomme ni
// `ech`, ni `rendu`, ni `html` est une interpolation oubliee, et une epreuve le
// verifie sur la page servie.
const html = f => rendu(brut(f));

const court = (h,n)=> h ? ech(String(h).slice(0, n||16))+"…" : "—";
const date = t => new Date(Number(t) * 1000).toISOString().replace("T"," ").slice(0,19);

function tuile(k,v,n){
  const bas = n ? `<div class="n">${rendu(n)}</div>` : "";
  return `<div class="tuile"><div class="k">${ech(k)}</div>
          <div class="v">${rendu(v)}</div>${html(bas)}</div>`;
}

// ---------------------------------------------------------------------------
// Montants : aucun flottant, jamais
// ---------------------------------------------------------------------------
//
// Il y a 100 000 000 unites indivisibles par Q21. Lire un solde en virgule
// flottante en perd des unites en silence, et une monnaie qui arrondit ment. Toute
// l'arithmetique se fait sur des entiers arbitrairement grands, et la
// conversion depuis une saisie humaine decoupe la chaine sur le point decimal
// sans jamais la faire passer par un nombre a virgule flottante.

function unitesDepuisQ21(saisie){
  let t = String(saisie).trim().replace(/[   _]/g, "").replace(",", ".");
  if (t === "" || t === ".") return null;
  if (!/^[0-9]*\.?[0-9]*$/.test(t)) return null;
  const p = t.split(".");
  const entier = p[0] === "" ? "0" : p[0];
  const frac = p.length > 1 ? p[1] : "";
  if (frac.length > 8) return null;
  const comble = (frac + "00000000").slice(0, 8);
  return BigInt(entier) * UNITES_PAR_Q21 + BigInt(comble);
}

function q21DepuisUnites(u){
  const n = BigInt(u);
  const e = n / UNITES_PAR_Q21;
  const f = n % UNITES_PAR_Q21;
  return e.toString() + "." + f.toString().padStart(8, "0");
}

// Les montants arrivent du noeud en deux champs : `unites` (entier) et `q21`
// (chaine deja formatee). On prend les unites, seule valeur sur laquelle on
// peut calculer. `Json::u64` bascule en chaine au-dela de i64::MAX : `BigInt`
// accepte les deux formes, un `Number` en perdrait la moitie.
function unitesDe(m){
  return BigInt((m && typeof m === "object") ? m.unites : m);
}

function gros(q21){
  const s = String(q21);
  const i = s.indexOf(".");
  if (i < 0) return `<span class="gros">${ech(s)}</span><span class="unite">Q21</span>`;
  return `<span class="gros">${ech(s.slice(0,i))}<span class="centimes">${ech(s.slice(i))}</span></span>` +
         `<span class="unite">Q21</span>`;
}

// ---------------------------------------------------------------------------
// Onglets
// ---------------------------------------------------------------------------

const VUES = ["solde","recevoir","envoyer","historique","infos"];

function montrer(nom){
  for (const v of VUES){
    document.getElementById("vue-" + v).hidden = (v !== nom);
  }
  for (const b of document.querySelectorAll("#onglets button")){
    b.classList.toggle("actif", b.dataset.vue === nom);
  }
  if (nom === "envoyer" && !document.getElementById("champ-frais").value) estimer();
  if (nom === "historique") historique();
  if (nom === "infos") infos();
}

document.getElementById("onglets").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-vue]");
  if (b) montrer(b.dataset.vue);
});

document.getElementById("forme-jeton").addEventListener("submit", ev => {
  ev.preventDefault();
  const champ = document.getElementById("saisie-jeton");
  const v = champ.value.trim();
  if (!v) return;
  retenirJeton(v);
  champ.value = "";
  document.getElementById("panneau-jeton").hidden = true;
  rafraichir();
});

// ---------------------------------------------------------------------------
// Solde et synchronisation
// ---------------------------------------------------------------------------
//
// Un portefeuille qui affiche un chiffre faux sans le dire est un portefeuille
// qui ment. Tant que le noeud n'est pas synchronise, le bandeau reste visible :
// il ne se referme pas tout seul et ne se referme pas a la main.

function signalerErreur(message){
  document.getElementById("erreur").hidden = false;
  document.getElementById("erreur-detail").textContent = message;
}

async function rafraichir(){
  if (enCours) return;
  enCours = true;
  try{
    const [sync, solde, info] = await Promise.all([
      appel("getsyncstatus"), appel("getbalance"), appel("getinfo")
    ]);
    document.getElementById("erreur").hidden = true;
    document.getElementById("reseau").textContent = info.reseau;

    const bandeau = document.getElementById("bandeau-sync");
    if (sync.synchronise){
      bandeau.hidden = true;
    } else {
      bandeau.hidden = false;
      document.getElementById("sync-note").textContent = sync.note;
      document.getElementById("sync-detail").textContent =
        "Hauteur locale " + sync.hauteur + ", hauteur annoncée par le réseau " +
        sync.hauteur_reseau + " — " + sync.blocs_restants + " bloc(s) restant(s), " +
        sync.pairs + " pair(s) connecté(s). Ce qui est affiché ci-dessous ne " +
        "compte que les blocs déjà validés par cette machine.";
    }

    document.getElementById("solde-gros").innerHTML = gros(solde.depensable.q21);
    document.getElementById("solde-note").textContent =
      solde.sorties_depensables + " sortie(s) dépensable(s)" +
      (sync.synchronise ? "" : " — chiffre incomplet, voir l'avertissement ci-dessus");

    const total = unitesDe(solde.depensable) + unitesDe(solde.immature);
    document.getElementById("tuiles-solde").innerHTML =
      tuile("Immature", ech(solde.immature.q21) + " Q21", "récompenses de minage pas encore dépensables") +
      tuile("Total détenu", ech(q21DepuisUnites(total)) + " Q21", "dépensable et immature réunis") +
      tuile("Adresses dérivées", solde.adresses_derivees) +
      tuile("Hauteur", info.hauteur, info.pairs + " pair(s), " + info.mempool + " transaction(s) en attente");
  }catch(e){
    signalerErreur("Impossible d'interroger le nœud : " + e.message);
  }finally{
    enCours = false;
  }
}

// ---------------------------------------------------------------------------
// Recevoir
// ---------------------------------------------------------------------------

function groupes(a, n){
  const t = String(a);
  const taille = n || 8;
  const out = [];
  for (let i = 0; i < t.length; i += taille) out.push(t.slice(i, i + taille));
  return out;
}

document.getElementById("bouton-adresse").addEventListener("click", async () => {
  const zone = document.getElementById("zone-adresse");
  zone.innerHTML = `<p class="aide">Demande en cours…</p>`;
  try{
    const a = await appel("getnewaddress");
    adresseCourante = a.adresse;
    const avert = a.usage_unique
      ? `<div class="avert"><h3>Adresse à usage unique</h3><p>${ech(a.avertissement)}</p></div>`
      : `<div class="note"><h3>Réutilisation</h3><p>${ech(a.avertissement)}</p></div>`;
    zone.innerHTML = `
      <div class="adresse">
        <div class="champs">${groupes(a.adresse, 8).map(g=>`<span class="groupe">${ech(g)}</span>`).join("")}</div>
        <button type="button" class="copier" id="bouton-copier">copier</button>
      </div>
      ${html(avert)}
      <div class="note"><h3>Schéma</h3><p>${ech(a.schema)} — cette adresse ne peut être dépensée que par une signature de ce schéma.</p></div>`;
    document.getElementById("bouton-copier").addEventListener("click", ev => copier(adresseCourante, ev.target));
  }catch(e){
    zone.innerHTML = `<div class="avert"><h3>Adresse non créée</h3><p>${ech(e.message)}</p></div>`;
  }
});

async function copier(texte, bouton){
  const remettre = () => setTimeout(()=>{ bouton.textContent = "copier"; }, 2000);
  try{
    if (navigator.clipboard && navigator.clipboard.writeText){
      await navigator.clipboard.writeText(texte);
    } else {
      const z = document.createElement("textarea");
      z.value = texte;
      document.body.appendChild(z);
      z.select();
      document.execCommand("copy");
      z.remove();
    }
    bouton.textContent = "copié";
  }catch(e){
    bouton.textContent = "copie refusée par le navigateur";
  }
  remettre();
}

// ---------------------------------------------------------------------------
// Envoyer
// ---------------------------------------------------------------------------

async function estimer(){
  const aide = document.getElementById("aide-frais");
  const n = document.getElementById("champ-entrees").value.trim();
  const entrees = /^[0-9]+$/.test(n) ? Math.min(Math.max(parseInt(n, 10), 1), 100) : 2;
  try{
    const f = await appel("estimatefee", '{"entrees":' + entrees + ',"sorties":2}');
    document.getElementById("champ-frais").value = f.frais_suggeres.q21;
    aide.textContent =
      "Suggestion du nœud pour " + f.entrees + " entrée(s) et " + f.sorties +
      " sortie(s) : environ " + f.taille_estimee_octets + " octets, poids " +
      f.poids_estime + ", au taux de " + f.taux_par_millier_de_poids +
      " unité(s) par millier de poids. Modifiable.";
  }catch(e){
    aide.textContent = "Frais non estimés : " + e.message;
  }
}

document.getElementById("bouton-estimer").addEventListener("click", estimer);

document.getElementById("forme-envoi").addEventListener("submit", async ev => {
  ev.preventDefault();
  document.getElementById("resultat-envoi").innerHTML = "";

  const adresse = document.getElementById("champ-adresse").value.trim();
  const montant = unitesDepuisQ21(document.getElementById("champ-montant").value);
  const frais = unitesDepuisQ21(document.getElementById("champ-frais").value);

  const refus = m => {
    document.getElementById("resultat-envoi").innerHTML =
      `<div class="avert"><h3>Envoi non préparé</h3><p>${ech(m)}</p></div>`;
  };
  if (!adresse) return refus("Aucune adresse de destination.");
  if (montant === null) return refus("Montant illisible. Attendu : un nombre en Q21, huit décimales au maximum.");
  if (montant <= 0n) return refus("Le montant doit être strictement positif.");
  if (frais === null) return refus("Frais illisibles. Attendu : un nombre en Q21, huit décimales au maximum.");
  if (frais < 0n) return refus("Les frais ne peuvent pas être négatifs.");

  // Le solde est relu maintenant, pas au chargement de la page : entre les
  // deux, un bloc a pu arriver.
  let depensable = null;
  try{
    depensable = unitesDe((await appel("getbalance")).depensable);
  }catch(e){
    return refus("Solde non relu, envoi interrompu : " + e.message);
  }
  const total = montant + frais;
  if (total > depensable){
    return refus("Fonds insuffisants : " + q21DepuisUnites(total) +
                 " Q21 demandés, " + q21DepuisUnites(depensable) + " Q21 dépensables.");
  }

  envoiPrepare = {adresse: adresse, montant: montant, frais: frais};
  document.getElementById("recap").innerHTML = `
    <div class="l"><span class="k">Destinataire</span><span class="v">${ech(adresse)}</span></div>
    <div class="l"><span class="k">Montant</span><span class="v">${ech(q21DepuisUnites(montant))} Q21</span></div>
    <div class="l"><span class="k">Frais</span><span class="v">${ech(q21DepuisUnites(frais))} Q21</span></div>
    <div class="l total"><span class="k">Débité au total</span><span class="v">${ech(q21DepuisUnites(total))} Q21</span></div>
    <div class="l"><span class="k">Solde après</span><span class="v">${ech(q21DepuisUnites(depensable - total))} Q21</span></div>`;
  document.getElementById("forme-envoi").hidden = true;
  document.getElementById("confirmation").hidden = false;
});

document.getElementById("bouton-annuler").addEventListener("click", () => {
  envoiPrepare = null;
  document.getElementById("confirmation").hidden = true;
  document.getElementById("forme-envoi").hidden = false;
});

document.getElementById("bouton-envoyer").addEventListener("click", async () => {
  if (!envoiPrepare) return;
  const b = document.getElementById("bouton-envoyer");
  b.disabled = true;
  b.textContent = "Envoi…";
  const p = envoiPrepare;
  // Les entiers partent en chiffres, sans passer par un `Number` : c'est la
  // seule facon d'etre certain que la somme envoyee est celle qui a ete
  // affichee sur l'ecran de confirmation.
  const params = '{"adresse":' + JSON.stringify(p.adresse) +
                 ',"unites":' + p.montant.toString() +
                 ',"frais":' + p.frais.toString() + '}';
  try{
    const r = await appel("sendtoaddress", params);
    envoiPrepare = null;
    document.getElementById("confirmation").hidden = true;
    document.getElementById("forme-envoi").hidden = false;
    document.getElementById("champ-montant").value = "";
    document.getElementById("champ-adresse").value = "";
    document.getElementById("resultat-envoi").innerHTML = `
      <div class="note">
        <h3>Transaction émise</h3>
        <p>Identifiant : <code>${ech(r.txid)}</code></p>
        <p>
          Elle est dans le réservoir de ce nœud et annoncée à ses pairs. Elle
          n'est <strong>pas encore confirmée</strong> : tant qu'aucun bloc ne la
          contient, elle peut être remplacée ou oubliée.
        </p>
        <p>Taille ${ech(r.transaction.taille_octets)} octets, dont ${ech(r.transaction.temoin_pourcent)} % de témoin.</p>
      </div>`;
    rafraichir();
  }catch(e){
    let indice = "";
    if (/TauxDeFraisTropBas|frais/i.test(e.message)){
      indice = " Les frais suffisent rarement quand la transaction consomme plus " +
               "d'entrées que prévu : augmentez le nombre d'entrées supposées, " +
               "recalculez, et recommencez.";
    } else if (/ConflitDeDepense/i.test(e.message)){
      // Constate sur un noeud reel : un envoi encore en attente immobilise les
      // pieces qu'il consomme, et le suivant retombe dessus. Le message du noeud
      // est exact mais illisible pour qui n'a pas la structure en tete.
      indice = " Un envoi précédent est encore en attente et immobilise les mêmes " +
               "pièces. Attendez qu'un bloc le confirme avant d'en émettre un autre.";
    }
    document.getElementById("confirmation").hidden = true;
    document.getElementById("forme-envoi").hidden = false;
    document.getElementById("resultat-envoi").innerHTML =
      `<div class="avert"><h3>Envoi refusé</h3><p>${ech(e.message)}${ech(indice)}</p>
       <p>Aucun fonds n'a bougé.</p></div>`;
  }finally{
    b.disabled = false;
    b.textContent = "Envoyer définitivement";
  }
});

// ---------------------------------------------------------------------------
// Historique
// ---------------------------------------------------------------------------

// La case « sorti » d'une ligne.
//
// Le noeud ne porte `sorti` que sur un envoi : ailleurs il n'y a rien a
// afficher, et un zero se lirait comme une mesure. Quand la piece ouverte est
// anterieure a la fenetre examinee, `montant_sortant_connu` est faux : la somme
// est alors un plancher, elle se donne precedee de « ≥ » et non comme un fait.
// Le montant vient de `q21`, chaine deja formatee par le noeud — aucune
// arithmetique ici, donc aucun flottant.
function celluleSortie(m){
  if (!m.sorti) return brut(`<span class="vide">—</span>`);
  if (m.montant_sortant_connu === false){
    return brut(`<span class="minore">${ech("≥ " + m.sorti.q21)}</span>`);
  }
  return m.sorti.q21;
}

// Ce qu'il faut dire sous le tableau, et seulement quand il y a lieu de le dire.
function notesColonnes(h){
  let t = "";
  if (h.mouvements.some(m => m.genre === "envoi")){
    t += `<div class="note"><h3>Reçu et sorti sur une même ligne</h3>
      <p>Un envoi n'ouvre presque jamais une pièce de la taille exacte&nbsp;: le
      portefeuille en ouvre une plus grosse, et la différence lui revient en
      monnaie sur une adresse neuve, comme un billet rendu. La colonne
      <strong>reçu</strong> porte cette monnaie, la colonne <strong>sorti</strong>
      ce qui a réellement quitté le portefeuille — montant versé et frais compris.</p></div>`;
  }
  if (h.montants_sortants_tous_resolus === false){
    t += `<div class="avert"><h3>Sommes sorties incomplètes</h3>
      <p>Pour au moins un envoi, la pièce ouverte est antérieure à la fenêtre
      examinée&nbsp;: sa valeur n'a pas été retrouvée, et la somme sortie ne peut
      donc pas être établie. Ces montants s'affichent précédés de «&nbsp;≥&nbsp;»
      — un minimum, pas un fait.</p></div>`;
  }
  return t;
}

async function historique(){
  const corps = document.getElementById("mouvements");
  const zone = document.getElementById("note-historique");
  const sous = document.getElementById("note-colonnes");
  try{
    const h = await appel("listtransactions", '{"limite":100}');
    // Un historique tronque qui ne se declare pas fait croire a des fonds
    // disparus. Le noeud dit jusqu'ou il a regarde ; on le repete.
    zone.innerHTML = h.historique_complet
      ? `<div class="note"><h3>Historique complet</h3><p>${ech(h.note)}</p></div>`
      : `<div class="avert"><h3>Historique partiel</h3><p>${ech(h.note)}</p>
         <p>Recherche effectuée de la hauteur ${ech(h.regarde_depuis_hauteur)} à ${ech(h.hauteur)}. Ce qui est antérieur n'est pas affiché, et n'est pas perdu pour autant.</p></div>`;
    sous.innerHTML = notesColonnes(h);

    if (!h.mouvements.length){
      corps.innerHTML = `<tr><td colspan="7">Aucun mouvement dans la fenêtre examinée.</td></tr>`;
      return;
    }
    corps.innerHTML = h.mouvements.map(m => {
      const attente = m.mature ? "" : " attente";
      const marque = m.mature ? "" : ` <span class="badge attente">immature</span>`;
      return `
      <tr>
        <td><span class="badge${ech(attente)}">${ech(m.genre)}</span></td>
        <td>${ech(m.recu.q21)}</td>
        <td>${rendu(celluleSortie(m))}</td>
        <td>${ech(m.confirmations)}${html(marque)}</td>
        <td>${ech(m.hauteur)}</td>
        <td>${ech(date(m.horodatage))}</td>
        <td><span class="coupe">${court(m.txid, 20)}</span></td>
      </tr>`;
    }).join("");
  }catch(e){
    zone.innerHTML = `<div class="avert"><h3>Historique indisponible</h3><p>${ech(e.message)}</p></div>`;
    corps.innerHTML = "";
    sous.innerHTML = "";
  }
}

// ---------------------------------------------------------------------------
// Informations
// ---------------------------------------------------------------------------

async function infos(){
  try{
    const [w, info, adresses] = await Promise.all([
      appel("getwalletinfo"), appel("getinfo"), appel("listaddresses")
    ]);
    document.getElementById("tuiles-infos").innerHTML =
      tuile("Schéma de signature", w.schema, "identifiant " + w.schema_id + " dans le protocole") +
      tuile("Réseau", w.reseau) +
      tuile("Adresses connues", adresses.length, w.adresses_derivees + " dérivée(s) depuis la graine") +
      tuile("Clefs consommées", w.clefs_consommees,
            w.usage_unique ? "usage unique : une clef ne signe qu'une fois" : "clefs réutilisables sans affaiblissement") +
      tuile("Clef publique", w.clef_publique_octets + " o") +
      tuile("Signature", w.signature_octets + " o");

    document.getElementById("tuiles-chaine").innerHTML =
      tuile("Hauteur", info.hauteur) +
      tuile("Tête", brut(`<span class="coupe">${court(info.tete, 20)}</span>`)) +
      tuile("Difficulté", info.difficulte_bits) +
      tuile("Émis", ech(info.emis.q21) + " Q21") +
      tuile("Sorties non dépensées", info.utxo_total) +
      tuile("Pairs", info.pairs);
  }catch(e){
    signalerErreur("Informations indisponibles : " + e.message);
  }
}

// ---------------------------------------------------------------------------
// Fermer le portefeuille
//
// Le seul moyen d'arreter etait Ctrl-C dans la fenetre noire. Sur Windows,
// l'interpreteur pose alors sa propre question — « Terminer le programme de
// commandes (O/N) ? » — a laquelle les deux reponses ferment la fenetre. Le
// premier utilisateur l'a lue comme une panne. Une application se ferme par un
// bouton ; celui-ci demande au noeud de s'arreter proprement.
//
// Deux clics, pas un : arreter le portefeuille pendant qu'on regarde son solde
// n'est pas grave, mais le faire par megarde au milieu d'un envoi non confirme
// oblige a relancer. La confirmation coute une seconde et se retire toute
// seule au bout de cinq.
// ---------------------------------------------------------------------------

// Le lien vers l'explorateur emporte le jeton dans le **fragment**, jamais
// dans la requete : c'est la meme regle que pour l'ouverture du portefeuille,
// et pour la meme raison — une adresse finit dans un historique, un fragment
// non. Sans jeton connu, le lien pointe quand meme : l'explorateur le demandera
// lui-meme.
(function relierExplorateur(){
  const a = document.getElementById("lien-explorateur");
  if (a && jeton) a.href = "/#" + encodeURIComponent(jeton);
})();

let battement = setInterval(rafraichir, 6000);
let confirmeFermeture = false;
let minuterieFermeture = null;

function noteFermeture(texte, classe){
  const n = document.getElementById("note-fermer");
  n.className = "aide" + (classe ? " " + classe : "");
  n.textContent = texte;
}

document.getElementById("bouton-fermer").addEventListener("click", async () => {
  const b = document.getElementById("bouton-fermer");
  if (!confirmeFermeture){
    confirmeFermeture = true;
    b.textContent = "Confirmer la fermeture";
    noteFermeture("Cliquez une seconde fois pour arrêter le portefeuille.");
    if (minuterieFermeture) clearTimeout(minuterieFermeture);
    minuterieFermeture = setTimeout(() => {
      confirmeFermeture = false;
      b.textContent = "Fermer le portefeuille";
      noteFermeture("");
    }, 5000);
    return;
  }
  if (minuterieFermeture) clearTimeout(minuterieFermeture);
  b.disabled = true;
  b.textContent = "Fermeture…";
  try{
    await appel("arreter");
  }catch(e){
    // Le noeud peut couper la connexion avant de repondre : c'est justement ce
    // qu'on lui a demande de faire. On ne presente donc pas cela comme un
    // echec — on le presente comme ce que c'est, une fermeture en cours.
  }
  // Plus rien a interroger : sans cela, la page afficherait « Nœud injoignable »
  // trois secondes apres une fermeture reussie.
  clearInterval(battement);
  oublierJeton();
  document.getElementById("erreur").hidden = true;
  b.textContent = "Portefeuille fermé";
  noteFermeture(
    "Le nœud a écrit son état et s'est arrêté. Vous pouvez fermer cet onglet ; " +
    "la fenêtre noire se referme d'elle-même.", "ok");
});

rafraichir();
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
        // Une page de portefeuille qui appelle un CDN lui annonce chaque ouverture
        // du portefeuille, et lui donne le pouvoir de remplacer le code qui
        // manipule les fonds. La verification est grossiere mais elle attrape
        // l'erreur la plus probable : une police ou un script ajoute plus tard.
        for interdit in [
            "http://",
            "https://",
            "//cdn",
            "fonts.googleapis",
            "unpkg",
            "jsdelivr",
            "<img",
            "<iframe",
            "@import",
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

    #[test]
    fn la_page_prevoit_les_deux_themes() {
        // Theme clair sur `:root`, theme sombre sous la preference du systeme.
        assert!(PAGE.contains(":root{"));
        assert!(PAGE.contains("prefers-color-scheme: dark"));
    }

    /// Ce que le portefeuille a le droit d'ecrire dans le navigateur, et ce
    /// qu'il n'a pas le droit d'y ecrire.
    ///
    /// # Ce qui a change, et pourquoi
    ///
    /// La regle etait « aucun stockage, jamais ». Elle avait le merite d'etre
    /// simple, et elle rendait le portefeuille inutilisable au premier
    /// rafraichissement : le jeton vivait dans une variable, un F5 l'effacait,
    /// et il fallait relancer le lanceur. C'est arrive au premier utilisateur,
    /// devant une page qui semblait figee — le reflexe de tout le monde.
    ///
    /// Le jeton de session est donc admis dans `sessionStorage`, et lui seul.
    /// Il est cloisonne par origine — donc par port, tire au hasard a chaque
    /// lancement — et meurt avec l'onglet. Ce n'est pas une clef : la graine et
    /// la phrase secrete ne quittent jamais le noeud.
    ///
    /// `localStorage`, `indexedDB` et les cookies restent interdits : ils
    /// survivent a la fermeture, et rien ici ne doit survivre a la session.
    #[test]
    fn la_page_ne_persiste_que_le_jeton_de_session() {
        // On cherche des **appels**, pas des mentions : les commentaires du
        // fichier nomment `localStorage` pour expliquer pourquoi il est ecarte,
        // et une epreuve qui interdirait jusqu'au mot interdirait d'expliquer.
        for interdit in [
            "localStorage.setItem",
            "localStorage.getItem",
            "localStorage[",
            "indexedDB.open",
            "document.cookie =",
        ] {
            assert!(
                !PAGE.contains(interdit),
                "le portefeuille persiste au-dela de la session : {interdit}"
            );
        }
        let s = script();
        assert!(
            s.contains("sessionStorage.setItem(CLEF_SESSION"),
            "le jeton doit survivre a un rafraichissement"
        );
        assert!(
            s.contains("sessionStorage.removeItem(CLEF_SESSION"),
            "un jeton refuse doit etre oublie, pas reessaye indefiniment"
        );
        // Toute lecture ou ecriture est gardee : un navigateur peut refuser le
        // stockage, et la page doit alors fonctionner sans, pas s'arreter.
        let occurrences = s.matches("sessionStorage").count();
        let gardes = s.matches("try {").count();
        assert!(
            gardes >= occurrences,
            "chaque acces au stockage doit etre garde : {occurrences} acces, {gardes} gardes"
        );
    }

    /// Le fragment porte le jeton, et ne doit pas survivre a sa lecture.
    #[test]
    fn le_fragment_est_efface_apres_lecture() {
        let s = script();
        assert!(s.contains("location.hash.slice(1)"));
        assert!(s.contains(r#"history.replaceState(null, "", location.pathname)"#));
        // L'effacement suit immediatement la lecture : rien ne doit pouvoir
        // s'intercaler et sortir avant que la barre d'adresse soit nettoyee.
        let lecture = s
            .find("location.hash.slice(1)")
            .expect("lecture du fragment");
        let effacement = s.find("history.replaceState").expect("effacement");
        assert!(
            effacement > lecture && effacement - lecture < 120,
            "l'effacement du fragment ne suit pas immediatement sa lecture"
        );
    }

    /// Le jeton se saisit dans la page, jamais dans une boite du navigateur.
    #[test]
    fn le_jeton_se_demande_dans_la_page() {
        assert!(PAGE.contains(r#"id="saisie-jeton""#));
        assert!(PAGE.contains(r#"type="password""#));
        assert!(PAGE.contains("Authorization"));
        assert!(PAGE.contains("Bearer"));
        assert!(
            !PAGE.contains("window.prompt") && !PAGE.contains("prompt("),
            "le jeton doit se saisir dans un champ de la page"
        );
        assert!(
            !PAGE.contains("location.search"),
            "la chaine de requete ne doit jamais porter le jeton"
        );
    }

    /// Les points d'insertion `innerHTML` echappent par defaut.
    #[test]
    fn les_valeurs_sont_echappees_par_defaut() {
        assert!(PAGE.contains("const ech ="));
        assert!(PAGE.contains("const brut ="));
        assert!(PAGE.contains("const rendu ="));
        assert!(PAGE.contains("const html ="));
        assert!(PAGE.contains("&amp;"));
        assert!(PAGE.contains("&lt;"));
        assert!(PAGE.contains("${rendu(v)}"));
    }

    /// Chaque interpolation d'un litteral de gabarit se declare.
    ///
    /// Elle echappe (`ech`, `court`), elle rend une valeur dont le type dit si
    /// elle est du balisage (`rendu`), elle assemble un fragment deja echappe
    /// (`html`), ou elle decoupe une adresse (`groupes`). Rien d'autre. Un champ
    /// insere tel quel serait une injection le jour ou le noeud rendrait une
    /// chaine la ou l'interface attendait un nombre.
    #[test]
    fn aucune_interpolation_n_est_brute() {
        let s = script();
        let permis = ["ech(", "rendu(", "html(", "court(", "groupes("];
        let octets = s.as_bytes();
        let mut i = 0usize;
        let mut vues = 0usize;
        while let Some(p) = s[i..].find("${") {
            let debut = i + p + 2;
            // Les gabarits s'imbriquent : la fin de l'interpolation est
            // l'accolade qui equilibre, pas la premiere rencontree.
            let mut profondeur = 1usize;
            let mut q = debut;
            while q < octets.len() && profondeur > 0 {
                match octets[q] {
                    b'{' => profondeur += 1,
                    b'}' => profondeur -= 1,
                    _ => {}
                }
                q += 1;
            }
            assert_eq!(profondeur, 0, "interpolation non fermee");
            let expr = s[debut..q - 1].trim();
            vues += 1;
            assert!(
                permis.iter().any(|p| expr.starts_with(p)),
                "interpolation non echappee : {expr}"
            );
            i = debut;
        }
        assert!(vues > 30, "trop peu d'interpolations examinees : {vues}");
    }

    /// L'arithmetique monetaire ne touche jamais un flottant.
    #[test]
    fn aucun_flottant_sur_un_montant() {
        let s = script();
        for interdit in ["parseFloat", "Number(m.", "toFixed", "+ 0.5"] {
            assert!(
                !s.contains(interdit),
                "un montant passe par un flottant : {interdit}"
            );
        }
        assert!(s.contains("BigInt"));
        assert!(s.contains("const UNITES_PAR_Q21 = 100000000n;"));
    }

    /// La conversion d'une saisie en Q21 vers des unites, verifiee deux fois.
    ///
    /// # Pourquoi les deux
    ///
    /// Reimplementer l'algorithme en Rust et le tester ne prouve rien sur le
    /// JavaScript reellement servi : les deux copies peuvent diverger sans que
    /// rien ne le signale. Comparer le texte de la fonction JavaScript a un
    /// litteral attendu prouve l'inverse — que la page contient bien cet
    /// algorithme — mais ne dit rien de sa justesse.
    ///
    /// On fait donc les deux : [`unites_depuis_q21`] est la specification,
    /// eprouvee sur des vecteurs ; et le test suivant verifie que le JavaScript
    /// servi en est la transcription exacte, caractere pour caractere. Une
    /// retouche de l'un sans l'autre casse une des deux epreuves.
    fn unites_depuis_q21(saisie: &str) -> Option<u128> {
        const UNITES_PAR_Q21: u128 = 100_000_000;
        let t: String = saisie
            .trim()
            .chars()
            .filter(|c| !matches!(c, ' ' | '\u{a0}' | '\u{202f}' | '_'))
            .map(|c| if c == ',' { '.' } else { c })
            .collect();
        if t.is_empty() || t == "." {
            return None;
        }
        let mut points = 0;
        for c in t.chars() {
            match c {
                '0'..='9' => {}
                '.' => points += 1,
                _ => return None,
            }
        }
        if points > 1 {
            return None;
        }
        let (entier, frac) = match t.split_once('.') {
            Some((e, f)) => (if e.is_empty() { "0" } else { e }, f),
            None => (t.as_str(), ""),
        };
        if frac.len() > 8 {
            return None;
        }
        let comble = format!("{frac:0<8}");
        let e: u128 = entier.parse().ok()?;
        let f: u128 = comble.parse().ok()?;
        Some(e * UNITES_PAR_Q21 + f)
    }

    #[test]
    fn la_conversion_q21_vers_unites_est_exacte() {
        // Les cas ou un flottant se trompe : 0.1, 0.2, 0.3 n'ont pas de
        // representation exacte en IEEE 754, et 2 100 000 100 000 000 depasse la
        // precision entiere d'un `double`.
        assert_eq!(unites_depuis_q21("0.1"), Some(10_000_000));
        assert_eq!(unites_depuis_q21("0.2"), Some(20_000_000));
        assert_eq!(unites_depuis_q21("0.3"), Some(30_000_000));
        assert_eq!(unites_depuis_q21("1"), Some(100_000_000));
        assert_eq!(unites_depuis_q21("1."), Some(100_000_000));
        assert_eq!(unites_depuis_q21(".5"), Some(50_000_000));
        assert_eq!(unites_depuis_q21("0.00000001"), Some(1));
        assert_eq!(unites_depuis_q21("0"), Some(0));
        assert_eq!(unites_depuis_q21("0.00000000"), Some(0));
        assert_eq!(unites_depuis_q21("13.847118"), Some(1_384_711_800));
        assert_eq!(unites_depuis_q21("0.03802539"), Some(3_802_539));
        assert_eq!(unites_depuis_q21("21000001"), Some(2_100_000_100_000_000));
        assert_eq!(
            unites_depuis_q21("21000001.00000000"),
            Some(2_100_000_100_000_000)
        );
        // Un separateur de milliers ou une virgule decimale ne doivent pas
        // fabriquer un montant different de celui qui a ete tape.
        assert_eq!(unites_depuis_q21("1 000.5"), Some(100_050_000_000));
        assert_eq!(unites_depuis_q21("0,25"), Some(25_000_000));

        // Refus, plutot qu'un montant devine.
        assert_eq!(unites_depuis_q21(""), None);
        assert_eq!(unites_depuis_q21("."), None);
        assert_eq!(unites_depuis_q21("abc"), None);
        assert_eq!(unites_depuis_q21("1.2.3"), None);
        assert_eq!(unites_depuis_q21("-1"), None);
        assert_eq!(unites_depuis_q21("1e8"), None);
        // Neuf decimales : plus fin que l'unite indivisible. Tronquer
        // silencieusement reviendrait a envoyer autre chose que ce qui est ecrit.
        assert_eq!(unites_depuis_q21("0.000000001"), None);
    }

    /// La page contient bien cet algorithme, et pas une variante.
    #[test]
    fn le_javascript_contient_l_algorithme_de_conversion() {
        const ATTENDU: &str = r#"function unitesDepuisQ21(saisie){
  let t = String(saisie).trim().replace(/[   _]/g, "").replace(",", ".");
  if (t === "" || t === ".") return null;
  if (!/^[0-9]*\.?[0-9]*$/.test(t)) return null;
  const p = t.split(".");
  const entier = p[0] === "" ? "0" : p[0];
  const frac = p.length > 1 ? p[1] : "";
  if (frac.length > 8) return null;
  const comble = (frac + "00000000").slice(0, 8);
  return BigInt(entier) * UNITES_PAR_Q21 + BigInt(comble);
}"#;
        assert!(
            script().contains(ATTENDU),
            "la fonction de conversion servie n'est plus celle qui est eprouvee ci-dessus"
        );

        const RETOUR: &str = r#"function q21DepuisUnites(u){
  const n = BigInt(u);
  const e = n / UNITES_PAR_Q21;
  const f = n % UNITES_PAR_Q21;
  return e.toString() + "." + f.toString().padStart(8, "0");
}"#;
        assert!(script().contains(RETOUR), "le formatage inverse a change");
    }

    /// Un envoi ne peut pas se faire en un seul clic.
    #[test]
    fn l_envoi_passe_par_un_ecran_de_confirmation() {
        assert!(PAGE.contains(r#"id="confirmation""#));
        assert!(PAGE.contains("Confirmer l'envoi"));
        assert!(PAGE.contains("Envoyer définitivement"));
        assert!(PAGE.contains(r#"id="recap""#));
        // Le recapitulatif repete les trois grandeurs avant l'envoi definitif.
        assert!(PAGE.contains("Destinataire"));
        assert!(PAGE.contains("Montant"));
        assert!(PAGE.contains("Frais"));
    }

    /// Les entiers d'un envoi partent en chiffres, sans conversion.
    #[test]
    fn le_montant_envoye_est_celui_qui_est_confirme() {
        let s = script();
        assert!(s.contains(r#"',"unites":' + p.montant.toString() +"#));
        assert!(s.contains(r#"',"frais":' + p.frais.toString() +"#));
    }

    /// Un solde incomplet doit se declarer.
    #[test]
    fn un_solde_non_synchronise_est_annonce() {
        assert!(PAGE.contains("Le solde affiché est incomplet"));
        assert!(PAGE.contains("sync.synchronise"));
        assert!(PAGE.contains("sync.blocs_restants"));
    }

    /// Un historique tronque doit se declarer.
    #[test]
    fn un_historique_partiel_est_annonce() {
        assert!(PAGE.contains("historique_complet"));
        assert!(PAGE.contains("Historique partiel"));
        assert!(PAGE.contains("regarde_depuis_hauteur"));
        // La note du noeud est affichee telle quelle, pas resumee.
        assert!(PAGE.contains("ech(h.note)"));
    }

    /// L'encadre de l'historique explique la monnaie rendue, et rien d'autre.
    ///
    /// # Ce qu'il disait avant
    ///
    /// « Ce que cette colonne ne dit pas » : la somme sortie n'etait pas
    /// calculee. Le noeud la calcule desormais, et l'encadre qui l'affirmait
    /// encore mentait a son porteur. Ce qui reste a expliquer est l'inverse :
    /// pourquoi « recu » et « sorti » figurent tous deux sur la ligne d'un
    /// envoi.
    #[test]
    fn l_encadre_explique_la_monnaie_rendue() {
        assert!(
            !PAGE.contains("Ce que cette colonne ne dit pas"),
            "l'ancien encadre affirme encore que la somme sortie n'est pas calculee"
        );
        assert!(!PAGE.contains("la somme sortie n'est pas calculée"));
        assert!(PAGE.contains("Reçu et sorti sur une même ligne"));
        assert!(PAGE.contains("comme un billet rendu"));
        // Il ne s'affiche que s'il y a un envoi a expliquer.
        assert!(PAGE.contains(r#"h.mouvements.some(m => m.genre === "envoi")"#));
        // Une resolution partielle se declare, plutot que de passer pour exacte.
        assert!(PAGE.contains("montants_sortants_tous_resolus === false"));
        assert!(PAGE.contains("Sommes sorties incomplètes"));
    }

    /// La colonne « sorti » existe, et ne donne pas un plancher pour un fait.
    #[test]
    fn la_colonne_sortie_existe_et_avoue_son_incertitude() {
        assert!(PAGE.contains("<th>Sorti</th>"));
        // La case est alimentee par le champ du noeud, pas devinee.
        assert!(PAGE.contains("m.sorti.q21"));
        assert!(PAGE.contains("rendu(celluleSortie(m))"));
        // Sans envoi, pas de chiffre : un tiret, jamais un zero.
        assert!(PAGE.contains(r#"if (!m.sorti) return brut(`<span class="vide">—</span>`);"#));
        // Le drapeau du noeud est consulte, et il decide de la marque affichee.
        assert!(
            PAGE.contains("m.montant_sortant_connu === false"),
            "la page affiche la somme sortie sans verifier qu'elle est complete"
        );
        assert!(PAGE.contains(r#"ech("≥ " + m.sorti.q21)"#));
        // Le tableau compte bien une colonne de plus qu'avant.
        let entete = PAGE
            .find("<thead><tr><th>Genre</th>")
            .expect("entete de l'historique");
        let fin = PAGE[entete..].find("</tr>").expect("fin de l'entete");
        assert_eq!(PAGE[entete..entete + fin].matches("<th>").count(), 7);
        assert!(PAGE.contains(r#"colspan="7""#));
    }

    /// Le schema post-quantique est nomme, avec sa norme et son niveau.
    #[test]
    fn la_page_nomme_le_schema_de_signature() {
        assert!(PAGE.contains("ML-DSA-87"));
        assert!(PAGE.contains("FIPS&nbsp;204"));
        assert!(PAGE.contains("niveau NIST&nbsp;5"));
        assert!(PAGE.contains("getwalletinfo"));
    }

    /// Les cinq vues existent et sont atteignables.
    #[test]
    fn les_cinq_vues_existent() {
        for v in ["solde", "recevoir", "envoyer", "historique", "infos"] {
            assert!(
                PAGE.contains(&format!(r#"id="vue-{v}""#)),
                "vue manquante : {v}"
            );
            assert!(
                PAGE.contains(&format!(r#"data-vue="{v}""#)),
                "onglet manquant : {v}"
            );
        }
    }

    /// Le portefeuille se ferme par un bouton, pas seulement par Ctrl-C.
    ///
    /// Le defaut verrouille ici : le seul arret possible etait Ctrl-C dans la
    /// fenetre du lanceur. Sur Windows, l'interpreteur pose alors sa propre
    /// question — « Terminer le programme de commandes (O/N) ? » — que le
    /// premier utilisateur a lue comme une panne, au point de ne plus oser
    /// arreter son portefeuille.
    #[test]
    fn le_portefeuille_se_ferme_par_un_bouton() {
        assert!(
            PAGE.contains(r#"id="bouton-fermer""#),
            "aucun bouton de fermeture dans la page"
        );
        let s = script();
        assert!(
            s.contains(r#"appel("arreter")"#),
            "le bouton n'appelle pas la methode d'arret"
        );
        // Sans cela, la page afficherait « Nœud injoignable » quelques secondes
        // apres une fermeture reussie : le battement continuerait d'interroger
        // un noeud qu'on vient soi-meme d'eteindre.
        assert!(
            s.contains("clearInterval(battement)"),
            "le battement de rafraichissement survit a la fermeture"
        );
        // Deux clics : arreter par megarde oblige a tout relancer.
        assert!(
            s.contains("confirmeFermeture"),
            "la fermeture se fait en un seul clic"
        );
        // La question de Windows est expliquee la ou elle se pose.
        assert!(
            PAGE.contains("Terminer le programme de commandes"),
            "la page n'explique pas la question que pose Windows apres un Ctrl-C"
        );
    }

    /// La page est utilisable sur telephone avant de l'etre ailleurs.
    #[test]
    fn la_page_est_pensee_pour_le_telephone_d_abord() {
        assert!(PAGE.contains(r#"name="viewport""#));
        assert!(PAGE.contains("width=device-width, initial-scale=1"));
        // Les elargissements sont des `min-width` : la mise en page etroite est
        // celle qui s'applique sans condition.
        assert!(PAGE.contains("@media(min-width:560px)"));
        assert!(
            !PAGE.contains("@media(max-width"),
            "une regle en max-width trahit une mise en page pensee pour l'ecran large"
        );
    }
}
