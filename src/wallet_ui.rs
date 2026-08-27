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
//! phrase secrete, elles, ne quittent jamais le noeud — **cette page-ci** ne
//! les voit a aucun moment.
//!
//! La precision compte depuis que `installation.rs` existe. La page
//! d'installation, elle, recoit la phrase secrete a la saisie et affiche le code
//! de sauvegarde pour qu'il soit recopie ; elle ne vit que le temps de cet
//! echange, et l'en-tete de ce module-la dit ce que cela coute. Ce fichier-ci
//! garde sa propriete intacte : une fois le portefeuille ouvert, plus aucun
//! secret ne traverse le navigateur.
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
/* =========================================================================
   Q21 — portefeuille de bureau
   =========================================================================

   Le parti pris : ceci doit ressembler a une application, pas a un document.
   Une barre en haut qui ne bouge jamais, une colonne de navigation a gauche
   sur grand ecran et une barre en bas sur telephone, des cartes posees sur un
   fond sombre. Les couleurs restent celles du projet — le vert de Q21 pousse
   vers une menthe plus vive, le violet pour ce qui touche au post-quantique —
   et rien n'est charge de l'exterieur : ni police, ni image, ni feuille.
   ========================================================================= */

:root{
  color-scheme: light dark;
  /* Le theme clair est la valeur de base : un jeton qui n'existe que dans un
     media query ne s'applique jamais dans l'etat non marque. */
  --fond:#f4f6f5; --voile:transparent;
  --carte:#ffffff; --carte-2:#f9fbfa;
  --bord:#dfe5e3; --bord-fort:#c6d0cd;
  --texte:#0d1211; --doux:#4a5654; --tenu:#7b8785;
  --accent:#00875f; --accent-vif:#00a273; --accent-fond:#e2f4ee;
  --quantum:#6b5bd6; --quantum-fond:#ece9fb;
  --alerte:#a35a10; --alerte-fond:#fbeeda;
  --danger:#b03626; --danger-fond:#fae4e1;
  --ombre:0 1px 2px rgba(13,18,17,.05), 0 8px 24px -12px rgba(13,18,17,.12);
  --rail:236px;
  --sans:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI Variable Text",
    "Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme: dark){
  :root{
    --fond:#07090a; --voile:radial-gradient(1200px 620px at 18% -12%,rgba(34,229,166,.10),transparent 62%),
                           radial-gradient(900px 520px at 92% 4%,rgba(139,123,255,.09),transparent 60%);
    --carte:#101416; --carte-2:#151a1c;
    --bord:#1f2729; --bord-fort:#2f3a3c;
    --texte:#e9f0ee; --doux:#9aa8a5; --tenu:#6d7a78;
    --accent:#22e5a6; --accent-vif:#5cf3c0; --accent-fond:#0d2a22;
    --quantum:#8b7bff; --quantum-fond:#1b1832;
    --alerte:#ffb65c; --alerte-fond:#2e2312;
    --danger:#ff6b5a; --danger-fond:#2e1613;
    --ombre:0 1px 0 rgba(255,255,255,.03) inset, 0 18px 40px -24px rgba(0,0,0,.9);
  }
}

*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0;background:var(--fond);color:var(--texte);
  font-family:var(--sans);font-size:15px;line-height:1.55;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;
}
body::before{
  content:"";position:fixed;inset:0;background:var(--voile);pointer-events:none;z-index:0;
}
.enveloppe{position:relative;z-index:1;min-height:100%;display:flex;flex-direction:column}

/* ---- Barre du haut ---------------------------------------------------- */
header{
  position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--fond) 86%,transparent);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border-bottom:1px solid var(--bord);
}
.barre{max-width:1180px;margin:0 auto;padding:.7rem 1rem;display:flex;align-items:center;gap:.9rem}
.logo{display:flex;align-items:center;gap:.55rem;font-weight:700;letter-spacing:-.02em;font-size:1.05rem}
.pastille{width:1.7rem;height:1.7rem;border-radius:9px;flex:0 0 auto;
  background:linear-gradient(135deg,var(--accent),var(--quantum));
  display:grid;place-items:center;color:#04120d;font-size:.72rem;font-weight:800;
  font-family:var(--mono);letter-spacing:-.04em}
h1{font-size:inherit;font-weight:inherit;margin:0;letter-spacing:inherit}
.etat{margin-left:.15rem;font-family:var(--mono);font-size:.66rem;font-weight:600;
  letter-spacing:.08em;text-transform:uppercase;color:var(--accent);
  background:var(--accent-fond);padding:.18rem .45rem;border-radius:5px;white-space:nowrap}
.barre .pousse{margin-left:auto}
.pouls{display:flex;align-items:center;gap:.45rem;font-size:.76rem;color:var(--doux);
  font-variant-numeric:tabular-nums;white-space:nowrap}
.point{width:.5rem;height:.5rem;border-radius:50%;background:var(--tenu);flex:0 0 auto}
.point.vert{background:var(--accent);box-shadow:0 0 0 3px var(--accent-fond)}
.point.orange{background:var(--alerte);box-shadow:0 0 0 3px var(--alerte-fond)}
.jauge-sync{height:2px;background:var(--bord)}
.jauge-sync i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--quantum));
  transition:width .4s ease}

/* ---- Corps : rail + contenu ------------------------------------------- */
.corps{max-width:1180px;width:100%;margin:0 auto;padding:1.1rem 1rem 5.5rem;
  display:grid;gap:1.4rem;grid-template-columns:1fr;flex:1}
@media(min-width:900px){
  .corps{grid-template-columns:var(--rail) 1fr;padding-bottom:2.5rem;gap:2rem}
}

/* La navigation : barre du bas sur telephone, colonne a gauche au-dela. */
nav.onglets{
  position:fixed;left:0;right:0;bottom:0;z-index:30;display:flex;
  background:color-mix(in srgb,var(--fond) 92%,transparent);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border-top:1px solid var(--bord);padding:.3rem .3rem calc(.3rem + env(safe-area-inset-bottom));
}
nav.onglets button{
  flex:1;display:flex;flex-direction:column;align-items:center;gap:.15rem;
  background:none;border:none;color:var(--tenu);font:inherit;font-size:.68rem;
  padding:.45rem .2rem;border-radius:10px;cursor:pointer;letter-spacing:.01em}
nav.onglets button svg{width:1.25rem;height:1.25rem;stroke:currentColor;fill:none;
  stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
nav.onglets button:hover{color:var(--doux)}
nav.onglets button.actif{color:var(--accent)}
@media(min-width:900px){
  nav.onglets{position:sticky;top:4.6rem;align-self:start;flex-direction:column;
    background:none;backdrop-filter:none;-webkit-backdrop-filter:none;
    border:none;padding:0;gap:.15rem}
  nav.onglets button{flex-direction:row;justify-content:flex-start;gap:.7rem;
    font-size:.9rem;padding:.6rem .8rem;width:100%}
  nav.onglets button.actif{background:var(--accent-fond);font-weight:600}
}

main{min-width:0}
section.vue{animation:entree .18s ease}
@keyframes entree{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
@media(prefers-reduced-motion:reduce){section.vue{animation:none}}

h2{font-size:.74rem;text-transform:uppercase;letter-spacing:.1em;color:var(--tenu);
  font-weight:600;margin:1.8rem 0 .7rem}
h2:first-child{margin-top:0}
h3{font-size:.95rem;margin:0 0 .4rem;font-weight:600}
p{margin:0 0 .8rem}
.aide{font-size:.82rem;color:var(--tenu);margin:.35rem 0 0}

/* ---- Cartes ------------------------------------------------------------ */
.carte{background:var(--carte);border:1px solid var(--bord);border-radius:16px;
  padding:1.15rem 1.25rem;box-shadow:var(--ombre)}
.carte+.carte{margin-top:.8rem}

/* Le solde : le seul endroit ou l'on se permet un degrade. */
.heros{background:var(--carte);border:1px solid var(--bord);border-radius:20px;
  padding:1.6rem 1.5rem;box-shadow:var(--ombre);position:relative;overflow:hidden}
.heros::after{content:"";position:absolute;inset:auto -30% -70% auto;width:70%;aspect-ratio:1;
  background:radial-gradient(circle,var(--accent-fond),transparent 70%);opacity:.7;pointer-events:none}
.heros .k{font-size:.7rem;text-transform:uppercase;letter-spacing:.11em;color:var(--tenu);
  font-weight:600}
.gros{font-family:var(--mono);font-size:clamp(2.2rem,9vw,3.4rem);line-height:1.02;
  letter-spacing:-.045em;font-variant-numeric:tabular-nums;display:inline-block;
  word-break:break-all;font-weight:600;
  background:linear-gradient(100deg,var(--texte) 30%,var(--accent));
  -webkit-background-clip:text;background-clip:text;color:transparent}
/* Le degre de texte se peint sur `.gros` : un enfant laisse a
   `color:transparent` n'aurait aucun fond a decouper et disparaitrait. Les
   centimes reprennent donc une couleur pleine, explicitement. */
.centimes{font-size:.52em;letter-spacing:-.02em;color:var(--tenu);
  -webkit-text-fill-color:var(--tenu)}
.unite{font-family:var(--mono);font-size:.78rem;color:var(--tenu);margin-left:.5rem;
  letter-spacing:.08em;font-weight:600}
.heros .n{color:var(--doux);font-size:.86rem;margin-top:.5rem;position:relative;z-index:1}

.grille{display:grid;gap:.7rem;grid-template-columns:1fr}
@media(min-width:560px){.grille{grid-template-columns:repeat(auto-fit,minmax(196px,1fr))}}
.tuile{background:var(--carte);border:1px solid var(--bord);border-radius:14px;
  padding:.85rem 1rem;box-shadow:var(--ombre)}
.tuile .k{font-size:.66rem;text-transform:uppercase;letter-spacing:.09em;color:var(--tenu);
  font-weight:600}
.tuile .v{font-size:1.1rem;font-family:var(--mono);margin-top:.25rem;font-weight:600;
  font-variant-numeric:tabular-nums;word-break:break-all;letter-spacing:-.02em}
.tuile .n{font-size:.75rem;color:var(--doux);margin-top:.3rem}
.tuile.forte{border-color:var(--accent);background:var(--carte-2)}
.tuile.forte .v{color:var(--accent)}

/* ---- Le minage --------------------------------------------------------- */
.mineur{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
.mineur .titre{flex:1;min-width:11rem}
.mineur .titre h3{margin:0}
.mineur .titre p{margin:.15rem 0 0;color:var(--tenu);font-size:.83rem}
.bascule{position:relative;width:3.4rem;height:1.95rem;border-radius:999px;flex:0 0 auto;
  border:1px solid var(--bord-fort);background:var(--carte-2);cursor:pointer;padding:0;
  transition:background .18s,border-color .18s}
.bascule i{position:absolute;top:.22rem;left:.24rem;width:1.4rem;height:1.4rem;border-radius:50%;
  background:var(--tenu);transition:transform .18s,background .18s}
.bascule[aria-pressed="true"]{background:var(--accent);border-color:var(--accent)}
.bascule[aria-pressed="true"] i{transform:translateX(1.42rem);background:#04120d}
.bascule:disabled{opacity:.4;cursor:not-allowed}
.bascule:focus-visible{outline:3px solid var(--accent-fond);outline-offset:2px}
@media(prefers-reduced-motion:reduce){.bascule,.bascule i{transition:none}}

.debit{display:flex;align-items:baseline;gap:.4rem;margin-top:1rem}
.debit .n{font-family:var(--mono);font-size:2rem;font-weight:600;letter-spacing:-.04em;
  font-variant-numeric:tabular-nums;color:var(--accent)}
.debit .u{font-size:.8rem;color:var(--tenu)}
.courbe{width:100%;height:52px;margin-top:.5rem;display:block}
.courbe path{fill:none;stroke:var(--accent);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.courbe .aire{fill:var(--accent-fond);stroke:none}

/* ---- Adresses ---------------------------------------------------------- */
.adresse{background:var(--carte);border:1px solid var(--bord);border-radius:14px;
  padding:.8rem .95rem;display:flex;gap:.75rem;align-items:center;box-shadow:var(--ombre)}
.adresse+.adresse{margin-top:.55rem}
.adresse .txt{flex:1;min-width:0;font-family:var(--mono);font-size:.82rem;
  word-break:break-all;line-height:1.45}
.adresse .rang{font-family:var(--mono);font-size:.68rem;color:var(--tenu);
  border:1px solid var(--bord);border-radius:7px;padding:.15rem .4rem;flex:0 0 auto}
.adresse.neuve{border-color:var(--accent);background:var(--carte-2)}

/* ---- Controles --------------------------------------------------------- */
label{display:block;font-size:.8rem;font-weight:600;margin:1rem 0 .35rem;color:var(--doux)}
input[type=text],input[type=password]{
  width:100%;padding:.7rem .85rem;font:inherit;font-family:var(--mono);font-size:.9rem;
  color:var(--texte);background:var(--carte-2);border:1.5px solid var(--bord);
  border-radius:11px;outline:none}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-fond)}
.boutons{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1rem}
button.action,button.discret,button.plat{
  font:inherit;font-weight:600;font-size:.9rem;border-radius:11px;cursor:pointer;
  padding:.68rem 1.1rem;border:1.5px solid transparent;transition:filter .15s}
button.action{background:var(--accent);color:#04120d;border-color:var(--accent)}
button.action:hover:not(:disabled){filter:brightness(1.08)}
button.action:disabled{opacity:.45;cursor:not-allowed}
button.discret{background:transparent;color:var(--doux);border-color:var(--bord-fort)}
button.discret:hover{color:var(--texte);border-color:var(--tenu)}
button.plat{background:var(--carte-2);color:var(--doux);border-color:var(--bord);
  padding:.42rem .7rem;font-size:.78rem}
button.plat:hover{color:var(--texte)}
button:focus-visible{outline:3px solid var(--accent-fond);outline-offset:2px}
a.plat{color:var(--accent);text-decoration:none;border-bottom:1px solid var(--accent-fond)}
a.plat:hover{border-bottom-color:var(--accent)}

/* ---- Encarts ----------------------------------------------------------- */
.note,.avert{border-radius:14px;padding:.9rem 1.05rem;margin:1rem 0;font-size:.87rem}
.note{background:var(--carte-2);border:1px solid var(--bord);color:var(--doux)}
.avert{background:var(--alerte-fond);border-left:3px solid var(--alerte);color:var(--doux)}
.avert h3{color:var(--alerte)}
.note h3{color:var(--texte)}
.note p:last-child,.avert p:last-child{margin-bottom:0}

/* ---- Tableau ----------------------------------------------------------- */
.defile{overflow-x:auto;border:1px solid var(--bord);border-radius:14px;background:var(--carte);
  box-shadow:var(--ombre)}
table{width:100%;border-collapse:collapse;font-size:.83rem}
th,td{text-align:left;padding:.6rem .8rem;border-bottom:1px solid var(--bord);white-space:nowrap}
thead th{font-size:.66rem;text-transform:uppercase;letter-spacing:.08em;color:var(--tenu);
  font-weight:600;background:var(--carte-2)}
tbody tr:last-child td{border-bottom:none}
td{font-family:var(--mono);font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:.1rem .45rem;border-radius:6px;font-size:.7rem;
  font-weight:600;background:var(--accent-fond);color:var(--accent);font-family:var(--sans)}
.badge.attente{background:var(--alerte-fond);color:var(--alerte)}
.badge.gris{background:var(--carte-2);color:var(--tenu)}

.recap{background:var(--carte-2);border:1px solid var(--bord);border-radius:14px;
  padding:1rem;font-family:var(--mono);font-size:.85rem;word-break:break-all}
footer{margin-top:2.4rem;padding-top:1rem;border-top:1px solid var(--bord);
  color:var(--tenu);font-size:.76rem}
code{background:var(--quantum-fond);color:var(--quantum);padding:.12em .38em;border-radius:5px;
  font-size:.85em;font-family:var(--mono)}
.err{color:var(--danger)}
.ok{color:var(--accent)}
</style>
</head>
<body>
<div class="enveloppe">

<header>
  <div class="barre">
    <div class="logo">
      <span class="pastille" aria-hidden="true">Q21</span>
      <h1>Portefeuille <span class="etat" id="reseau">…</span></h1>
    </div>
    <div class="pousse pouls">
      <span class="point" id="point-sync"></span>
      <span id="pouls-texte">connexion…</span>
    </div>
  </div>
  <div class="jauge-sync"><i id="jauge-sync"></i></div>
</header>

<div class="corps">

<nav class="onglets" id="onglets" aria-label="Sections du portefeuille">
  <button type="button" data-vue="solde" class="actif">
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7h18v12H3z"/><path d="M3 7l4-3h10l4 3"/><circle cx="16" cy="13" r="1.6"/></svg>
    Solde</button>
  <button type="button" data-vue="miner">
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M13 2L4 14h6l-1 8 9-12h-6z"/></svg>
    Miner</button>
  <button type="button" data-vue="recevoir">
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v13"/><path d="M6 12l6 6 6-6"/><path d="M4 20h16"/></svg>
    Recevoir</button>
  <button type="button" data-vue="envoyer">
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20V7"/><path d="M6 12l6-6 6 6"/><path d="M4 4h16"/></svg>
    Envoyer</button>
  <button type="button" data-vue="historique">
    <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
    Activité</button>
  <button type="button" data-vue="infos">
    <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/></svg>
    Infos</button>
</nav>

<main>

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

<section class="vue" id="vue-solde">
  <div class="heros">
    <div class="k">Dépensable</div>
    <div id="solde-gros">…</div>
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

<section class="vue" id="vue-miner" hidden>
  <h2>Minage</h2>
  <div class="carte">
    <div class="mineur">
      <div class="titre">
        <h3 id="minage-titre">Votre machine ne cherche pas</h3>
        <p id="minage-sous">Le minage cherche le prochain bloc. Il utilise tous les cœurs.</p>
      </div>
      <button type="button" class="bascule" id="bascule-minage" aria-pressed="false"
              aria-label="Activer le minage"><i></i></button>
    </div>
    <div class="debit">
      <span class="n" id="minage-debit">0</span>
      <span class="u">tentatives par seconde</span>
    </div>
    <svg class="courbe" id="courbe-minage" viewBox="0 0 300 52" preserveAspectRatio="none"
         role="img" aria-label="Débit de minage des dernières minutes"></svg>
    <div class="grille" style="margin-top:1rem">
      <div class="tuile"><div class="k">Blocs trouvés</div><div class="v" id="minage-blocs">0</div>
        <div class="n">depuis le lancement</div></div>
      <div class="tuile"><div class="k">Tentatives</div><div class="v" id="minage-total">0</div>
        <div class="n">depuis le lancement</div></div>
      <div class="tuile"><div class="k">Blocs reçus</div><div class="v" id="vitesse-sync">0</div>
        <div class="n">par seconde, depuis le réseau</div></div>
    </div>
  </div>
  <div class="note">
    <h3>Ce que fait votre machine quand ce bouton est allumé</h3>
    <p>
      Elle fouille une table de deux gigaoctets en mémoire, des centaines de
      milliers de fois par seconde, à la recherche d'une valeur qui satisfasse
      la difficulté du moment. C'est une loterie&nbsp;: on ne gagne pas à tous
      les coups, on gagne d'autant plus souvent qu'on cherche vite.
    </p>
    <p>
      La récompense d'un bloc trouvé est versée à une adresse de ce
      portefeuille. Elle n'est dépensable qu'après le délai de maturation.
    </p>
  </div>
</section>

<section class="vue" id="vue-recevoir" hidden>
  <h2>Recevoir</h2>
  <p class="aide">
    Chaque paiement mérite une adresse neuve. Réutiliser une adresse ne coûte
    rien au protocole, mais relie publiquement vos paiements entre eux.
  </p>
  <div class="boutons">
    <button type="button" class="action" id="bouton-adresse">Nouvelle adresse</button>
  </div>
  <div id="zone-adresse"></div>
  <h2>Vos adresses</h2>
  <div id="liste-adresses"></div>
</section>

<section class="vue" id="vue-envoyer" hidden>
  <h2>Envoyer du Q21</h2>
  <div class="carte">
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
  </div>

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
  <h2>Activité</h2>
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
      Ce portefeuille est servi par un nœud qui tourne dans la fenêtre ouverte
      par le lanceur. Ce bouton lui demande de s'arrêter proprement&nbsp;: il
      écrit le réservoir de transactions en attente, l'instantané de l'état et
      le portefeuille, puis rend la main.
    </p>
    <p>
      C'est la façon recommandée d'arrêter. Fermer la fenêtre du lanceur
      fonctionne aussi. <strong>Ctrl-C</strong> fonctionne également, mais
      Windows pose alors sa propre question —
      «&nbsp;Terminer le programme de commandes (O/N)&nbsp;?&nbsp;»&nbsp;:
      répondez <strong>O</strong>, tout est déjà enregistré à ce moment-là.
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
  n'est écrit dans le navigateur en dehors de lui. Code de recherche, non
  audité&nbsp;: ne protège aucune valeur réelle.
</footer>

</main>
</div>
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

const VUES = ["solde","miner","recevoir","envoyer","historique","infos"];

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
  if (nom === "recevoir") listerAdresses();
  if (nom === "miner") minage();
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
    pouls(sync);

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

// ---------------------------------------------------------------------------
// Le pouls : etat du reseau et vitesse de synchronisation
// ---------------------------------------------------------------------------
//
// La vitesse de reception se calcule ici, et non dans le noeud : c'est une
// derivee de deux mesures de hauteur, et le navigateur en a deja deux sous la
// main. Demander au noeud de la tenir aurait ajoute de l'etat partage a un
// programme qui manipule des fonds, pour afficher un chiffre.

let derniereHauteur = null, derniereMesure = 0, vitesseBlocs = 0;

function pouls(sync){
  const t = Date.now();
  if (derniereHauteur !== null && t > derniereMesure){
    const dh = Number(sync.hauteur) - derniereHauteur;
    const dt = (t - derniereMesure) / 1000;
    // Une moyenne glissante : sans elle le chiffre saute a chaque tour.
    if (dt > 0) vitesseBlocs = vitesseBlocs * 0.6 + (dh / dt) * 0.4;
  }
  derniereHauteur = Number(sync.hauteur);
  derniereMesure = t;

  const pt = document.getElementById("point-sync");
  const tx = document.getElementById("pouls-texte");
  const jauge = document.getElementById("jauge-sync");
  const cible = Number(sync.hauteur_reseau) || 1;
  const part = Math.max(0, Math.min(100, (Number(sync.hauteur) / cible) * 100));
  jauge.style.width = (sync.synchronise ? 100 : part) + "%";

  pt.className = "point " + (sync.synchronise ? "vert" : (Number(sync.pairs) > 0 ? "orange" : ""));
  tx.textContent = sync.synchronise
    ? Number(sync.pairs) + " pair(s) · à jour · bloc " + sync.hauteur
    : (Number(sync.pairs) === 0
        ? "aucun pair · bloc " + sync.hauteur
        : sync.blocs_restants + " bloc(s) à rattraper");

  const v = document.getElementById("vitesse-sync");
  if (v) v.textContent = (vitesseBlocs < 0.05 ? "0" : vitesseBlocs.toFixed(1));
}

// ---------------------------------------------------------------------------
// Miner
// ---------------------------------------------------------------------------
//
// Le noeud tient l'interrupteur et les compteurs ; cette vue ne fait que les
// lire et les basculer. Le debit affiche est celui que le noeud mesure sur une
// fenetre d'une seconde — pas une moyenne depuis le lancement, qui mettrait
// plusieurs minutes a refleter un arret.

const HISTO_DEBIT = [];
let minageEnCours = false, minageTimer = null;

function formatDebit(n){
  n = Number(n) || 0;
  if (n >= 1000000) return (n / 1000000).toFixed(2) + " M";
  if (n >= 1000) return (n / 1000).toFixed(1) + " k";
  return String(Math.round(n));
}

function courbe(valeurs){
  const svg = document.getElementById("courbe-minage");
  if (!svg) return;
  const L = 300, H = 52, n = valeurs.length;
  if (n < 2){ svg.innerHTML = ""; return; }
  const max = Math.max.apply(null, valeurs) || 1;
  let d = "";
  for (let i = 0; i < n; i++){
    const x = (i / (n - 1)) * L;
    const y = H - 3 - (valeurs[i] / max) * (H - 8);
    d += (i ? " L " : "M ") + x.toFixed(1) + " " + y.toFixed(1);
  }
  const aire = d + " L " + L + " " + H + " L 0 " + H + " Z";
  // Deux chemins construits ici, a partir de nombres : rien de ce qui vient du
  // noeud n'entre dans ce balisage autrement que comme coordonnee calculee.
  svg.innerHTML = '<path class="aire" d="' + aire + '"></path><path d="' + d + '"></path>';
}

function peindreMinage(etat){
  const actif = !!etat.actif;
  const b = document.getElementById("bascule-minage");
  b.setAttribute("aria-pressed", actif ? "true" : "false");
  b.disabled = !etat.possible;
  b.setAttribute("aria-label", actif ? "Arrêter le minage" : "Activer le minage");
  document.getElementById("minage-titre").textContent = etat.possible
    ? (actif ? "Votre machine cherche un bloc" : "Votre machine ne cherche pas")
    : "Ce nœud ne peut pas miner";
  document.getElementById("minage-sous").textContent = etat.possible
    ? (actif ? "Elle utilise tous les cœurs disponibles."
             : "Le minage cherche le prochain bloc. Il utilise tous les cœurs.")
    : "Miner demande un portefeuille : sans lui, la récompense n'irait nulle part.";
  document.getElementById("minage-debit").textContent = formatDebit(etat.essais_par_seconde);
  document.getElementById("minage-blocs").textContent = String(etat.blocs_trouves);
  document.getElementById("minage-total").textContent = formatDebit(etat.essais_total);
  HISTO_DEBIT.push(Number(etat.essais_par_seconde) || 0);
  while (HISTO_DEBIT.length > 60) HISTO_DEBIT.shift();
  courbe(HISTO_DEBIT);
}

async function minage(){
  try{
    peindreMinage(await appel("getminage"));
  }catch(e){ /* le rafraichissement general signale deja la panne */ }
}

document.getElementById("bascule-minage").addEventListener("click", async () => {
  if (minageEnCours) return;
  minageEnCours = true;
  const b = document.getElementById("bascule-minage");
  const vers = b.getAttribute("aria-pressed") !== "true";
  try{
    peindreMinage(await appel("setminage", {actif: vers}));
  }catch(e){
    signalerErreur("Le minage n'a pas pu être " + (vers ? "activé" : "arrêté") + " : " + e.message);
  }finally{
    minageEnCours = false;
  }
});

// La vue du minage se rafraichit plus souvent que le reste : un debit qui
// bouge toutes les cinq secondes ne ressemble pas a une mesure.
minageTimer = setInterval(() => {
  if (!document.getElementById("vue-miner").hidden) minage();
}, 1000);

// ---------------------------------------------------------------------------
// Toutes les adresses
// ---------------------------------------------------------------------------

// `listaddresses` rend un **tableau** d'objets `{adresse, indice, consommee}`,
// et non un objet portant une liste de chaines. La premiere version de cette
// fonction supposait la seconde forme : elle affichait « aucune adresse » sur un
// portefeuille qui en comptait cent quarante-neuf. C'est le genre de defaut
// qu'aucune relecture ne trouve et qu'un essai contre un vrai noeud sort en
// trois secondes.
const ADRESSES_MONTREES = 25;

async function listerAdresses(){
  const zone = document.getElementById("liste-adresses");
  try{
    const r = await appel("listaddresses");
    const liste = Array.isArray(r) ? r : (r.adresses || []);
    if (!liste.length){
      zone.innerHTML = '<div class="note"><p>Aucune adresse encore dérivée. ' +
        'Le bouton ci-dessus en crée une.</p></div>';
      return;
    }
    // Les plus recentes en tete : c'est celle qu'on vient de creer qu'on cherche.
    const recentes = liste.slice().reverse();
    const lignes = recentes.slice(0, ADRESSES_MONTREES).map(e => {
      const a = (e && typeof e === "object") ? e.adresse : e;
      const indice = (e && typeof e === "object" && e.indice !== undefined) ? e.indice : "";
      const servie = !!(e && typeof e === "object" && e.consommee);
      return '<div class="adresse">' +
        '<span class="rang">#' + ech(String(indice)) + '</span>' +
        '<span class="txt">' + ech(String(a)) + '</span>' +
        (servie ? '<span class="badge gris">servie</span>' : '') +
        '<button type="button" class="plat" data-copier="' + ech(String(a)) + '">Copier</button>' +
        '</div>';
    });
    if (recentes.length > ADRESSES_MONTREES){
      lignes.push('<p class="aide">' + ech(String(recentes.length - ADRESSES_MONTREES)) +
        ' adresse(s) plus ancienne(s) ne sont pas affichée(s). Elles restent ' +
        'valides et leur solde est compté.</p>');
    }
    zone.innerHTML = lignes.join("");
  }catch(e){
    zone.innerHTML = '<div class="avert"><p>' + ech(e.message) + '</p></div>';
  }
}

// Un seul ecouteur pour toute la liste : attacher un gestionnaire par ligne
// laisse des fuites a chaque rafraichissement.
document.getElementById("liste-adresses").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-copier]");
  if (b) copier(b.dataset.copier, b);
});

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
    ///
    /// # Pourquoi l'epreuve a du s'affiner
    ///
    /// Elle bannissait `toFixed` du script entier. C'etait juste tant que la
    /// page n'affichait que de la monnaie ; le debit de minage et la vitesse de
    /// reception des blocs sont des grandeurs continues, mesurees, et les
    /// arrondir est exactement ce qu'il faut faire — les compter en entiers ne
    /// dirait rien de plus et se lirait moins bien.
    ///
    /// L'invariant reel n'a pas bouge : **aucun flottant ne touche un montant**.
    /// L'epreuve le verifie maintenant a la ligne, en cherchant un `toFixed` qui
    /// cotoie un mot du vocabulaire monetaire. Un `parseFloat` reste interdit
    /// partout : il n'a aucun usage legitime ici.
    #[test]
    fn aucun_flottant_sur_un_montant() {
        let s = script();
        for interdit in ["parseFloat", "Number(m.", "+ 0.5"] {
            assert!(
                !s.contains(interdit),
                "un montant passe par un flottant : {interdit}"
            );
        }
        const MONNAIE: [&str; 8] = [
            "unites", "q21", "solde", "montant", "frais", "depensable", "immature", "recu",
        ];
        let mut vus = 0;
        for (n, ligne) in s.lines().enumerate() {
            if !ligne.contains("toFixed") {
                continue;
            }
            vus += 1;
            let bas = ligne.to_lowercase();
            for mot in MONNAIE {
                assert!(
                    !bas.contains(mot),
                    "ligne {} : un montant passe par toFixed — {}",
                    n + 1,
                    ligne.trim()
                );
            }
        }
        assert!(vus > 0, "aucun toFixed : l'epreuve ne verifie plus rien");
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

    /// Les six vues existent, et le minage en fait partie.
    ///
    /// L'epreuve precedente en comptait cinq. Elle a ete elargie, pas
    /// remplacee : une vue qui disparait est une regression, une vue qui
    /// s'ajoute doit etre declaree ici.
    #[test]
    fn les_six_vues_existent() {
        for v in ["solde", "miner", "recevoir", "envoyer", "historique", "infos"] {
            assert!(
                PAGE.contains(&format!(r#"id="vue-{v}""#)),
                "vue absente du balisage : {v}"
            );
            assert!(
                PAGE.contains(&format!(r#"data-vue="{v}""#)),
                "vue absente de la navigation : {v}"
            );
        }
        assert!(
            script().contains(r#"const VUES = ["solde","miner","recevoir","envoyer","historique","infos"];"#),
            "la liste des vues du script ne correspond pas au balisage"
        );
    }

    /// Le minage se commande, et rien d'autre ne peut le commander.
    #[test]
    fn le_minage_se_commande_depuis_la_page() {
        let s = script();
        assert!(s.contains(r#"appel("setminage", {actif: vers})"#), "pas de bascule");
        assert!(s.contains(r#"appel("getminage")"#), "pas de lecture d'etat");
        // Le bouton reflete l'etat rendu par le nœud, jamais l'etat suppose :
        // afficher « actif » sur la foi d'un clic ferait mentir la page si le
        // nœud refusait.
        assert!(
            s.contains("peindreMinage(await appel(\"setminage\""),
            "l'affichage du minage ne suit pas la reponse du nœud"
        );
        // Un nœud sans portefeuille ne peut pas miner : le bouton se desactive.
        assert!(s.contains("b.disabled = !etat.possible"), "bouton toujours actif");
    }

    /// Le trace du debit ne construit son balisage qu'a partir de nombres.
    ///
    /// C'est le seul endroit de la page ou l'on ecrit du SVG a la volee. Si une
    /// valeur venue du nœud pouvait s'y glisser telle quelle, elle y entrerait
    /// comme balisage.
    #[test]
    fn la_courbe_ne_recoit_que_des_nombres() {
        let s = script();
        let d = s.find("function courbe(").expect("la fonction courbe");
        let f = s[d..].find("\n}").expect("sa fin") + d;
        let corps = &s[d..f];
        assert!(
            corps.contains("toFixed(1)"),
            "les coordonnees ne sont pas forcees en nombre"
        );
        for interdit in ["ech(", "etat.", "adresse"] {
            assert!(!corps.contains(interdit), "valeur non numerique dans la courbe : {interdit}");
        }
    }

    /// La liste des adresses echappe chaque adresse, deux fois.
    ///
    /// Une adresse arrive du nœud. Elle est ecrite dans le texte visible **et**
    /// dans un attribut `data-`, et les deux voies doivent etre echappees : un
    /// attribut mal ferme est une injection au meme titre qu'un element.
    #[test]
    fn la_liste_des_adresses_echappe_tout() {
        let s = script();
        let d = s.find("async function listerAdresses(").expect("la fonction");
        let f = s[d..].find("\n}").expect("sa fin") + d;
        let corps = &s[d..f];
        assert_eq!(
            corps.matches("ech(String(a))").count(),
            2,
            "une adresse entre dans la page sans passer par ech"
        );
        assert!(
            corps.contains("ech(e.message)"),
            "un message d'erreur du nœud entre sans echappement"
        );
    }

    /// La vitesse de reception se calcule dans la page, pas dans le nœud.
    #[test]
    fn la_vitesse_de_synchronisation_est_une_derivee_locale() {
        let s = script();
        assert!(s.contains("function pouls(sync)"), "pas de calcul de pouls");
        assert!(
            s.contains("vitesseBlocs = vitesseBlocs * 0.6"),
            "la vitesse n'est pas lissee : elle sauterait a chaque tour"
        );
        // Elle ne doit pas etre reclamee au nœud : ce serait de l'etat partage
        // de plus dans un programme qui manipule des fonds.
        assert!(
            !s.contains("vitesse_reseau") && !s.contains("getvitesse"),
            "la vitesse est demandee au nœud alors qu'elle se derive ici"
        );
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
