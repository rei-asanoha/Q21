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
.point.rouge{background:var(--danger);box-shadow:0 0 0 3px var(--danger-fond)}
/* Le point vert respire quand tout va bien : un indicateur fige ne se
   distingue pas d'une page morte. */
.point.vert{animation:battement 2.6s ease-in-out infinite}
@keyframes battement{0%,100%{opacity:1}50%{opacity:.45}}
@media(prefers-reduced-motion:reduce){.point.vert{animation:none}}
.pouls b{font-weight:600;color:var(--texte)}
.pouls.hors b{color:var(--danger)}
.pouls.sync b{color:var(--alerte)}
.pouls.ok b{color:var(--accent)}

/* --- Le bandeau de recuperation ---------------------------------------- */
.recup{background:var(--carte);border:1px solid var(--alerte);border-radius:16px;
  padding:1.15rem 1.25rem;margin-bottom:1rem;box-shadow:var(--ombre)}
.recup .tete{display:flex;align-items:center;gap:.75rem}
.recup h3{margin:0;flex:1}
.rotor{width:1.15rem;height:1.15rem;border:2px solid var(--bord-fort);
  border-top-color:var(--alerte);border-radius:50%;flex:0 0 auto;
  animation:tourne .8s linear infinite}
@keyframes tourne{to{transform:rotate(360deg)}}
@media(prefers-reduced-motion:reduce){.rotor{animation:none;border-top-color:var(--bord-fort)}}
.recup .barre-p{height:6px;border-radius:3px;background:var(--carte-2);
  margin:.9rem 0 .5rem;overflow:hidden;border:1px solid var(--bord)}
.recup .barre-p i{display:block;height:100%;width:0;border-radius:3px;
  background:linear-gradient(90deg,var(--alerte),var(--accent));transition:width .5s ease}
.recup .chiffres{display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;
  font-family:var(--mono);font-size:.78rem;color:var(--doux);
  font-variant-numeric:tabular-nums}
.recup p{margin:.7rem 0 0;font-size:.86rem;color:var(--doux)}
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

/* --- Les gestes rapides du solde ---------------------------------------- */
.gestes{display:flex;gap:.7rem;margin-top:1.2rem;position:relative;z-index:1}
.gestes button{flex:1;display:flex;align-items:center;justify-content:center;gap:.5rem;
  font:inherit;font-weight:600;font-size:.9rem;padding:.75rem 1rem;cursor:pointer;
  border-radius:12px;border:1.5px solid var(--bord);background:var(--carte-2);
  color:var(--texte);transition:border-color .15s}
.gestes button:hover{border-color:var(--accent)}
.gestes button svg{width:1.1rem;height:1.1rem;stroke:var(--accent);fill:none;
  stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.gestes button:focus-visible{outline:3px solid var(--accent-fond);outline-offset:2px}

/* --- Le journal des trouvailles ----------------------------------------- */
.trouvaille{display:flex;align-items:center;gap:.85rem;padding:.7rem .9rem;
  border:1px solid var(--bord);border-radius:12px;background:var(--carte);
  box-shadow:var(--ombre)}
.trouvaille+.trouvaille{margin-top:.5rem}
.trouvaille .pic{width:2.1rem;height:2.1rem;border-radius:10px;flex:0 0 auto;
  display:grid;place-items:center;background:var(--accent-fond)}
.trouvaille .pic svg{width:1.15rem;height:1.15rem;stroke:var(--accent);fill:none;
  stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.trouvaille .quoi{flex:1;min-width:0}
.trouvaille .quoi a{color:var(--texte);font-weight:600;text-decoration:none;
  border-bottom:1px solid var(--bord-fort)}
.trouvaille .quoi a:hover{border-bottom-color:var(--accent);color:var(--accent)}
.trouvaille .quoi .quand{font-size:.76rem;color:var(--tenu);margin-top:.1rem}
.trouvaille .gain{font-family:var(--mono);font-weight:600;color:var(--accent);
  font-variant-numeric:tabular-nums;white-space:nowrap}
.trouvaille.neuve{animation:atterrit .5s ease}
@keyframes atterrit{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
@media(prefers-reduced-motion:reduce){.trouvaille.neuve{animation:none}}

/* --- L'activite : des lignes qui se lisent d'un regard ------------------- */
td .sens{display:inline-grid;place-items:center;width:1.6rem;height:1.6rem;
  border-radius:8px;vertical-align:middle}
td .sens svg{width:.95rem;height:.95rem;fill:none;stroke-width:2;
  stroke-linecap:round;stroke-linejoin:round}
td .sens.recu{background:var(--accent-fond)}td .sens.recu svg{stroke:var(--accent)}
td .sens.envoi{background:var(--danger-fond)}td .sens.envoi svg{stroke:var(--danger)}
td .sens.mine{background:var(--quantum-fond)}td .sens.mine svg{stroke:var(--quantum)}
td.plus{color:var(--accent);font-weight:600}
td.moins{color:var(--danger);font-weight:600}

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
/* Une ligne de carnet porte deux etages : le nom donne par le porteur, puis
   l'adresse elle-meme. Le nom passe devant parce que c'est lui qu'on cherche
   des yeux — l'adresse, on la copie, on ne la lit pas. */
.adresse{flex-wrap:wrap}
.adresse .corps{flex:1;min-width:0}
.adresse .nom{font-family:var(--sans);font-size:.85rem;font-weight:600;color:var(--texte);
  margin-bottom:.15rem}
.adresse .nom.vide{font-weight:400;color:var(--tenu);font-style:italic}
.adresse .edition{flex:0 0 100%;display:flex;gap:.5rem;margin-top:.5rem}
.adresse .edition input{flex:1;font-family:var(--sans);font-size:.85rem}
/* Les filtres de l'activite. Un seul actif a la fois, et le mot porte l'etat :
   la couleur ne fait que le repeter, pour qui la distingue mal. */
.filtres{display:flex;flex-wrap:wrap;gap:.4rem;margin:.9rem 0}
.filtres button.actif{background:var(--accent-fond);color:var(--accent);
  border-color:var(--accent)}
.chercheur{margin:1rem 0}
.chercheur input[type=search]{width:100%;padding:.7rem .85rem;font:inherit;font-size:.9rem;
  color:var(--texte);background:var(--carte-2);border:1.5px solid var(--bord);
  border-radius:11px;outline:none}
.chercheur input[type=search]:focus{border-color:var(--accent)}

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
/* La colonne des references porte l'empreinte entiere. Elle deroge au
   `nowrap` du tableau : soixante-quatre caracteres sur une seule ligne
   pousseraient toutes les autres colonnes hors de l'ecran, alors qu'ici la
   coupure au caractere est sans danger — une empreinte n'a ni mots ni sens de
   lecture. */
td.ref{white-space:normal;word-break:break-all;max-width:23ch;font-size:.72rem;
  line-height:1.4}
td.ref .entier{display:block;color:var(--doux)}
td.ref button.plat{margin-top:.3rem;padding:.2rem .5rem;font-size:.7rem}
/* Meme empreinte entiere dans une tuile, ou la police des valeurs est grande. */
.tuile .entier{display:block;font-family:var(--mono);font-size:.7rem;line-height:1.4;
  word-break:break-all;color:var(--doux)}
.tuile button.plat{margin-top:.35rem;padding:.2rem .5rem;font-size:.7rem}
td{font-family:var(--mono);font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:.1rem .45rem;border-radius:6px;font-size:.7rem;
  font-weight:600;background:var(--accent-fond);color:var(--accent);font-family:var(--sans)}
.badge.attente{background:var(--alerte-fond);color:var(--alerte)}
.badge.gris{background:var(--carte-2);color:var(--tenu)}
/* Le disque qui tourne d'une transaction encore au reservoir. Il vit dans le
   badge, prend la couleur du texte, et disparait avec lui des qu'un bloc
   confirme. Une machine reglee pour limiter les animations n'en verra qu'un
   arc immobile — l'information reste portee par le mot, pas par le mouvement. */
.tourne{display:inline-block;width:.62em;height:.62em;margin-right:.3em;
  vertical-align:-.05em;border:2px solid currentColor;border-right-color:transparent;
  border-radius:50%;animation:tourner .9s linear infinite}
@keyframes tourner{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion: reduce){.tourne{animation:none}}

details.pli{background:var(--carte-2);border:1px solid var(--bord);border-radius:14px;
  padding:.85rem 1.05rem;margin:1rem 0;font-size:.87rem;color:var(--doux)}
details.pli summary{cursor:pointer;font-weight:600;color:var(--texte);
  list-style-position:inside}
details.pli summary:hover{color:var(--accent)}
details.pli[open] summary{margin-bottom:.5rem}
details.pli p{margin:0 0 .6rem}
details.pli p:last-child{margin-bottom:0}

.recap{background:var(--carte-2);border:1px solid var(--bord);border-radius:14px;
  padding:1rem;font-family:var(--mono);font-size:.85rem;word-break:break-all}
footer{margin-top:2.4rem;padding-top:1rem;border-top:1px solid var(--bord);
  color:var(--tenu);font-size:.76rem}
code{background:var(--quantum-fond);color:var(--quantum);padding:.12em .38em;border-radius:5px;
  font-size:.85em;font-family:var(--mono)}
.err{color:var(--danger)}
.ok{color:var(--accent)}

/* --- Choix de la langue -------------------------------------------------
   Trois drapeaux dans l'en-tete. Un clic suffit : la page se traduit sur
   place, sans rechargement et sans aller-retour avec le noeud. */
.langues{display:flex;gap:.25rem;align-items:center;margin-left:.75rem}
.langues button{background:transparent;border:1px solid transparent;border-radius:.4rem;
  cursor:pointer;font-size:1.05rem;line-height:1;padding:.22rem .3rem;opacity:.5;
  transition:opacity .15s,border-color .15s,background .15s}
.langues button:hover{opacity:.9;background:rgba(255,255,255,.07)}
.langues button[aria-pressed="true"]{opacity:1;border-color:rgba(255,255,255,.28);
  background:rgba(255,255,255,.10)}
.langues button:focus-visible{outline:2px solid #4ade80;outline-offset:1px}
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
    <div class="pousse pouls" id="pouls" role="status" aria-live="polite">
      <span class="point" id="point-sync"></span>
      <b id="pouls-etat">Connexion…</b>
      <span id="pouls-texte"></span>
    </div>
    <div class="langues" id="langues" role="group" aria-label="Langue / Language">
      <button type="button" data-langue="fr" aria-pressed="true" title="Français">&#127467;&#127479;</button>
      <button type="button" data-langue="en" aria-pressed="false" title="English">&#127468;&#127463;</button>
      <button type="button" data-langue="ja" aria-pressed="false" title="&#26085;&#26412;&#35486;">&#127471;&#127477;</button>
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
  <button type="button" data-vue="reseau">
    <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18"/></svg>
    Réseau</button>
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

<div id="bandeau-sync" class="recup" hidden>
  <div class="tete">
    <span class="rotor" aria-hidden="true"></span>
    <h3 id="recup-titre">Récupération de l'historique de la chaîne</h3>
  </div>
  <div id="recup-mesure">
    <div class="barre-p"><i id="recup-barre"></i></div>
    <div class="chiffres">
      <span id="recup-position">—</span>
      <span id="recup-vitesse">—</span>
    </div>
  </div>
  <p id="sync-note"></p>
  <p id="recup-restaure" hidden>
    <strong>Si vous venez de restaurer un portefeuille</strong>, vos fonds
    réapparaîtront à la fin de cette étape&nbsp;: ils sont dans la chaîne, et
    votre machine ne les a pas encore lus. Le solde affiché est incomplet
    jusque-là.
  </p>
  <p id="sync-detail"></p>
</div>

<section class="vue" id="vue-solde">
  <div class="heros">
    <div class="k">Disponible</div>
    <div id="solde-gros">…</div>
    <div class="n" id="solde-note">Chargement…</div>
    <div class="gestes">
      <button type="button" data-aller="recevoir">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v13"/><path d="M6 12l6 6 6-6"/><path d="M4 20h16"/></svg>
        Recevoir</button>
      <button type="button" data-aller="envoyer">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20V7"/><path d="M6 12l6-6 6 6"/><path d="M4 4h16"/></svg>
        Envoyer</button>
      <button type="button" data-aller="miner">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M13 2L4 14h6l-1 8 9-12h-6z"/></svg>
        Miner</button>
    </div>
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
      <div class="tuile forte"><div class="k">Gagné en minant</div><div class="v" id="minage-gagne">0</div>
        <div class="n">depuis le lancement — maturité comprise</div></div>
      <div class="tuile"><div class="k">Blocs trouvés</div><div class="v" id="minage-blocs">0</div>
        <div class="n">depuis le lancement</div></div>
      <div class="tuile"><div class="k">Tentatives</div><div class="v" id="minage-total">0</div>
        <div class="n">depuis le lancement</div></div>
      <div class="tuile"><div class="k">Rythme de la chaîne</div><div class="v" id="vitesse-sync">—</div>
        <div class="n" id="vitesse-note">cible : un bloc toutes les 2 minutes</div></div>
      <div class="tuile"><div class="k">Mémoire occupée</div><div class="v" id="minage-memoire">—</div>
        <div class="n" id="minage-memoire-note">la table de calcul, en mémoire vive</div></div>
    </div>
  </div>

  <h2>Vos blocs</h2>
  <div id="minage-trouves"></div>
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
  <div class="note">
    <h3>Pourquoi vous en avez plusieurs</h3>
    <p>
      Votre portefeuille ne contient <strong>qu'un seul secret</strong>&nbsp;: la
      graine, celle du code de sauvegarde que vous avez recopié. Toutes vos
      adresses en sont <em>fabriquées</em> par un calcul — la première, la
      deuxième, la millième. C'est ce qu'on appelle les <strong>dériver</strong>.
    </p>
    <p>
      Conséquence rassurante&nbsp;: <strong>ce code sauve tout</strong>. Pas
      besoin de sauvegarder chaque adresse&nbsp;; elles se recalculent toutes à
      partir de lui.
    </p>
    <p>
      Conséquence utile&nbsp;: en donner une neuve à chaque personne qui vous
      paie ne coûte rien, et évite qu'un curieux relie tous vos encaissements
      entre eux en lisant la chaîne. Votre solde est la somme de toutes.
    </p>
  </div>
  <div class="chercheur">
    <label for="filtre-adresses">Chercher dans votre carnet</label>
    <input id="filtre-adresses" type="search" autocomplete="off" spellcheck="false"
           placeholder="un nom, un numéro (#12) ou un morceau d'adresse">
    <p class="aide" id="compte-adresses"></p>
  </div>
  <div id="liste-adresses"></div>
  <div class="boutons" id="zone-plus" hidden>
    <button type="button" class="plat" id="bouton-plus">Afficher les suivantes</button>
  </div>
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

    <div id="destinataires-plus"></div>
    <div class="boutons">
      <button type="button" class="discret" id="bouton-ajouter-destinataire">+ Ajouter un destinataire</button>
    </div>
    <div class="aide">Un seul envoi peut payer plusieurs destinataires à la fois&nbsp;: c'est une transaction unique, aux frais partagés, plutôt que plusieurs envois séparés.</div>

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

<section class="vue" id="vue-reseau" hidden>
  <h2>Le réseau</h2>
  <div class="heros">
    <div class="k">Puissance de calcul du réseau</div>
    <div id="reseau-gros">…</div>
    <div class="n" id="reseau-note">Mesure en cours…</div>
  </div>
  <div class="grille" style="margin-top:.8rem">
    <div class="tuile"><div class="k">Votre machine</div>
      <div class="v" id="reseau-mien">—</div>
      <div class="n" id="reseau-part">mesurée chez vous, en direct</div></div>
    <div class="tuile"><div class="k">Machines comme la vôtre</div>
      <div class="v" id="reseau-equiv">—</div>
      <div class="n">équivalence, pas un décompte</div></div>
    <div class="tuile"><div class="k">Machines connues du réseau</div>
      <div class="v" id="reseau-carnet">—</div>
      <div class="n">adresses apprises, présentes ou passées</div></div>
    <div class="tuile"><div class="k">Ordinateurs reliés au vôtre</div>
      <div class="v" id="reseau-pairs">0</div>
      <div class="n">vos voisins directs, pas le réseau entier</div></div>
    <div class="tuile"><div class="k">Mesuré sur</div>
      <div class="v" id="reseau-fenetre">—</div>
      <div class="n">les blocs les plus récents</div></div>
  </div>
  <div class="note">
    <h3>Pourquoi on ne vous dit pas «&nbsp;combien de mineurs&nbsp;»</h3>
    <p>
      Parce que personne ne peut le savoir, et qu'un chiffre inventé serait pire
      que pas de chiffre. Un mineur ne s'annonce pas&nbsp;: il pose des blocs.
      Rien ne distingue mille machines d'une personne qui en possède mille.
    </p>
    <p>
      Et Q21 rend le comptage encore plus impossible, volontairement&nbsp;: votre
      portefeuille utilise <strong>une adresse différente pour chaque
      récompense</strong>, pour qu'on ne puisse pas relier vos gains entre eux.
      Compter les adresses de mineurs reviendrait donc à compter les blocs.
    </p>
    <p>
      Ce qui se mesure, en revanche, ne se truque pas&nbsp;: <strong>le travail
      réellement dépensé</strong>. Il se lit dans la difficulté, qui s'ajuste
      pour qu'un bloc tombe toutes les deux minutes. Divisé par ce que fait
      <em>votre</em> machine, il donne l'équivalence ci-dessus.
    </p>
  </div>
</section>

<section class="vue" id="vue-historique" hidden>
  <h2>Activité</h2>
  <div id="note-historique"></div>
  <div class="filtres" id="filtres-activite" role="group" aria-label="Ne montrer que">
    <button type="button" class="plat actif" data-filtre="tout">Tout</button>
    <button type="button" class="plat" data-filtre="minage">Minage</button>
    <button type="button" class="plat" data-filtre="reception">Reçu</button>
    <button type="button" class="plat" data-filtre="envoi">Envoyé</button>
  </div>
  <div class="defile">
    <table>
      <thead><tr><th>Quoi</th><th>Reçu</th><th>Envoyé</th><th>Confirmations</th><th>Bloc n°</th><th>Date</th><th>Référence</th></tr></thead>
      <tbody id="mouvements"></tbody>
    </table>
  </div>
  <div id="note-colonnes"></div>
</section>

<section class="vue" id="vue-infos" hidden>
  <h2>Votre sécurité</h2>
  <div class="carte">
    <div class="mineur">
      <div class="titre">
        <h3>Le code de sauvegarde est votre portefeuille</h3>
        <p>Le fichier sur ce disque n'est qu'une copie de travail.</p>
      </div>
    </div>
    <p style="margin-top:.8rem">
      Tout votre portefeuille — chaque adresse, chaque fonds — se refabrique à
      partir du seul code de sauvegarde que vous avez recopié à la création.
      <strong>Sur n'importe quelle machine&nbsp;: Windows, Mac Intel, Mac Apple
      Silicon, Linux, Raspberry Pi.</strong> Vous l'y saisissez via
      «&nbsp;J'ai déjà un code de sauvegarde&nbsp;», et la chaîne fait le
      reste — vérifié par une épreuve de restauration complète, sur les cinq
      systèmes construits.
    </p>
    <div class="note avert" style="margin-bottom:0">
      <h3>Deux choses à ne jamais faire</h3>
      <p>Ne photographiez pas le code, ne le collez pas dans un nuage&nbsp;:
      qui le lit détient vos fonds, définitivement. Et ne confondez pas le code
      avec votre <strong>phrase secrète</strong>&nbsp;— elle, ne protège que le
      fichier de <em>cette</em> machine, et peut être différente ailleurs.</p>
    </div>
  </div>

  <h2>Portefeuille</h2>
  <div class="grille" id="tuiles-infos"></div>
  <details class="pli">
    <summary>ML-DSA-87 (FIPS&nbsp;204, niveau NIST&nbsp;5) — pourquoi ça résiste au quantique</summary>
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
  </details>
  <h2>Chaîne</h2>
  <div class="grille" id="tuiles-chaine"></div>

  <details class="pli">
    <summary>Pour les développeurs</summary>
    <p>
      Le nœud sert une API JSON-RPC sur <code>POST /rpc</code> —
      <code>listmethods</code> énumère les méthodes. Le jeton d'accès de la
      session s'envoie en <code>Authorization: Bearer</code> ; il ne quitte
      jamais cette page. Rien d'autre n'est écrit dans le navigateur que lui et
      le choix de langue, tous deux effacés à la fermeture de l'onglet.
      L'explorateur et le portefeuille sont servis par le même processus, sur le
      même port, sans aucune ressource externe.
    </p>
  </details>

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
    tout ce que votre nœud a vérifié, consultable sans faire confiance à personne.
  </p>
  Réseau d'essai — les Q21 qui s'y minent n'ont aucune valeur, et n'en auront
  jamais. Logiciel de recherche, non audité de l'extérieur.
</footer>

</main>
</div>
</div>

<script>
/* =======================================================================
   Langues — francais, anglais, japonais
   =======================================================================

   La page a ete ecrite en francais. Plutot que de semer des identifiants de
   traduction dans plusieurs centaines d'endroits — ce qui aurait manque tout
   le texte que le script fabrique a l'execution — on traduit par
   correspondance du texte source.

   Chaque noeud de texte garde son original francais. Changer de langue le
   remplace ; revenir au francais le restaure. Un observateur de mutations
   couvre ce que le script ecrit ensuite, de sorte qu'une traduction ne se
   perd pas au premier rafraichissement des donnees.

   Ce qui n'est pas traduit reste en francais, jamais vide : une phrase dans
   la mauvaise langue se comprend, une phrase absente ne se comprend pas.

   Rien ne sort de la page : aucun service de traduction, aucune requete.
*/
const I18N = {"en": {"Portefeuille": "Wallet", "Connexion…": "Connecting…", "Solde": "Balance", "Miner": "Mine", "Recevoir": "Receive", "Envoyer": "Send", "Réseau": "Network", "Activité": "Activity", "Infos": "Info", "Chargement…": "Loading…", "Détail": "Details", "Fermer": "Close", "Revenir": "Back", "Tout": "All", "Reçu": "Received", "Envoyé": "Sent", "Quoi": "What", "Date": "Date", "Référence": "Reference", "Confirmations": "Confirmations", "Bloc n°": "Block no.", "Disponible": "Available", "Minage": "Mining", "Chaîne": "Chain", "Vos blocs": "Your blocks", "Vos adresses": "Your addresses", "Le réseau": "The network", "Votre sécurité": "Your security", "Votre machine": "Your machine", "Mesure en cours…": "Measuring…", "Nœud injoignable": "Node unreachable", "Déverrouiller": "Unlock", "Nouvelle adresse": "New address", "Afficher les suivantes": "Show more", "Chercher dans votre carnet": "Search your address book", "+ Ajouter un destinataire": "+ Add a recipient", "Recalculer les frais": "Recalculate fee", "Vérifier": "Review", "Envoyer définitivement": "Send for good", "Fermer le portefeuille": "Close the wallet", "Envoyer du Q21": "Send Q21", "Adresse du destinataire": "Recipient address", "Montant, en Q21": "Amount, in Q21", "Frais, en Q21": "Fee, in Q21", "Suggestion du nœud, modifiable.": "Suggested by the node, editable.", "Confirmer l'envoi": "Confirm the send", "Un envoi est définitif": "A send is final", "Entrées supposées, pour l'estimation des frais": "Assumed inputs, for the fee estimate", "L'adresse porte une somme de contrôle : une faute de frappe sera détectée par le nœud, pas subie.": "The address carries a checksum: a typo is caught by the node, not suffered.", "Huit décimales au maximum. Une unité vaut 0.00000001 Q21.": "Eight decimals at most. One unit is 0.00000001 Q21.", "Aucune autorité ne peut annuler une transaction acceptée. Relisez l'adresse caractère par caractère : c'est la seule vérification qui vous reste.": "No authority can reverse an accepted transaction. Re-read the address character by character: it is the only check you have left.", "Un seul envoi peut payer plusieurs destinataires à la fois : c'est une transaction unique, aux frais partagés, plutôt que plusieurs envois séparés.": "One send can pay several recipients at once: a single transaction with shared fees, rather than several separate sends.", "Votre machine ne cherche pas": "Your machine is not searching", "Le minage cherche le prochain bloc. Il utilise tous les cœurs.": "Mining looks for the next block. It uses every core.", "tentatives par seconde": "attempts per second", "Gagné en minant": "Earned by mining", "depuis le lancement — maturité comprise": "since launch — maturing included", "Blocs trouvés": "Blocks found", "depuis le lancement": "since launch", "Tentatives": "Attempts", "Rythme de la chaîne": "Chain pace", "cible : un bloc toutes les 2 minutes": "target: one block every 2 minutes", "Mémoire occupée": "Memory in use", "la table de calcul, en mémoire vive": "the computation table, in RAM", "Puissance de calcul du réseau": "Network computing power", "mesurée chez vous, en direct": "measured on your machine, live", "Machines comme la vôtre": "Machines like yours", "équivalence, pas un décompte": "an equivalence, not a count", "Machines connues du réseau": "Machines known to the network", "adresses apprises, présentes ou passées": "addresses learned, present or past", "Ordinateurs reliés au vôtre": "Computers connected to yours", "vos voisins directs, pas le réseau entier": "your direct neighbours, not the whole network", "Mesuré sur": "Measured over", "les blocs les plus récents": "the most recent blocks", "Le code de sauvegarde est votre portefeuille": "The backup code is your wallet", "Le fichier sur ce disque n'est qu'une copie de travail.": "The file on this disk is only a working copy.", "Deux choses à ne jamais faire": "Two things never to do", "Pour les développeurs": "For developers", "Explorateur de la chaîne": "Chain explorer", "Jeton d'accès requis": "Access token required", "Récupération de l'historique de la chaîne": "Catching up on chain history", "Pourquoi une part du solde est immature": "Why part of the balance is immature", "Pourquoi vous en avez plusieurs": "Why you have several", "Ce que fait votre machine quand ce bouton est allumé": "What your machine does when this switch is on", "Chaque paiement mérite une adresse neuve. Réutiliser une adresse ne coûte rien au protocole, mais relie publiquement vos paiements entre eux.": "Every payment deserves a fresh address. Reusing one costs the protocol nothing, but publicly links your payments together.", "Réseau d'essai — les Q21 qui s'y minent n'ont aucune valeur, et n'en auront jamais. Logiciel de recherche, non audité de l'extérieur.": "Test network — the Q21 mined here have no value, and never will. Research software, not externally audited.", "Activer le minage": "Turn mining on", "Arrêter le minage": "Turn mining off", "Ce nœud ne peut pas miner": "This node cannot mine", "Connecté": "Connected", "Fermeture…": "Shutting down…", "Confirmer la fermeture": "Confirm shutdown", "Cliquez une seconde fois pour arrêter le portefeuille.": "Click once more to stop the wallet.", "Adresses connues": "Known addresses", "Blocs vérifiés": "Blocks verified", "Dernier bloc": "Latest block", "Destinataire": "Recipient", "Difficulté": "Difficulty", "En attente de maturité": "Awaiting maturity", "Empreinte de l'état": "State fingerprint", "Clef publique": "Public key", "Clefs consommées": "Keys consumed", "En attente d'un ordinateur à qui demander la chaîne": "Waiting for a computer to ask for the chain", "Débit de minage des dernières minutes": "Mining rate over the last minutes", "Elle utilise tous les cœurs disponibles.": "It uses every available core.", "Aucune adresse de destination.": "No destination address.", "Chaque montant doit être strictement positif.": "Every amount must be strictly positive.", "Le montant minimal est 0,0001 Q21 : en dessous, le réseau refuse la sortie comme poussière.": "The minimum amount is 0.0001 Q21: below that, the network rejects the output as dust.", "Chaque montant doit valoir au moins 0,0001 Q21 : en dessous, le réseau refuse la sortie comme poussière.": "Every amount must be at least 0.0001 Q21: below that, the network rejects the output as dust.", "Frais illisibles. Attendu : un nombre en Q21, huit décimales au maximum.": "Unreadable fee. Expected: a number in Q21, eight decimals at most.", "Le nœud exige un jeton. Il est normalement transmis par le lanceur dans le fragment de l'adresse ; si vous avez ouvert cette page à la main, saisissez ici le jeton passé à": "The node requires a token. The launcher normally passes it in the address fragment; if you opened this page by hand, enter here the token given to", "Si vous venez de restaurer un portefeuille": "If you have just restored a wallet", ", vos fonds réapparaîtront à la fin de cette étape : ils sont dans la chaîne, et votre machine ne les a pas encore lus. Le solde affiché est incomplet jusque-là.": ", your funds will reappear at the end of this step: they are in the chain, and your machine has not read them yet. The displayed balance is incomplete until then.", "Une récompense de minage n'est dépensable qu'après un long délai de maturation. Tant qu'il n'est pas écoulé, la somme existe, elle vous appartient, mais aucune transaction ne peut la dépenser. Elle est comptée séparément plutôt que fondue dans un total qui serait faux.": "A mining reward is only spendable after a long maturation delay. Until it has elapsed, the amount exists and belongs to you, but no transaction can spend it. It is counted separately rather than folded into a total that would be wrong.", "Elle fouille une table de deux gigaoctets en mémoire, des centaines de milliers de fois par seconde, à la recherche d'une valeur qui satisfasse la difficulté du moment. C'est une loterie : on ne gagne pas à tous les coups, on gagne d'autant plus souvent qu'on cherche vite.": "It searches a two-gigabyte table in memory, hundreds of thousands of times per second, looking for a value that satisfies the current difficulty. It is a lottery: you do not win every time, you win more often the faster you search.", "La récompense d'un bloc trouvé est versée à une adresse de ce portefeuille. Elle n'est dépensable qu'après le délai de maturation.": "The reward for a block found is paid to an address of this wallet. It is only spendable after the maturation delay.", "Votre portefeuille ne contient": "Your wallet holds", "qu'un seul secret": "only one secret", ": la graine, celle du code de sauvegarde que vous avez recopié. Toutes vos adresses en sont": ": the seed, the one behind the backup code you copied down. All your addresses are", "fabriquées": "built from it", "par un calcul — la première, la deuxième, la millième. C'est ce qu'on appelle les": "by computation — the first, the second, the thousandth. This is what is meant by", "dériver": "deriving them", "Conséquence rassurante :": "A reassuring consequence:", "ce code sauve tout": "this code saves everything", ". Pas besoin de sauvegarder chaque adresse ; elles se recalculent toutes à partir de lui.": ". No need to back up each address; they are all recomputed from it.", "Conséquence utile : en donner une neuve à chaque personne qui vous paie ne coûte rien, et évite qu'un curieux relie tous vos encaissements entre eux en lisant la chaîne. Votre solde est la somme de toutes.": "A useful consequence: giving a fresh one to each person who pays you costs nothing, and stops an onlooker from linking all your receipts together by reading the chain. Your balance is the sum of them all.", "Avec ML-DSA-87 le témoin pèse la quasi-totalité d'une transaction : les frais dépendent surtout du": "With ML-DSA-87 the witness accounts for almost all of a transaction: the fee depends mostly on the", "nombre d'entrées": "number of inputs", "consommées, que le nœud ne choisit qu'au moment de construire la transaction. Si l'envoi est refusé pour taux de frais trop bas, augmentez ce nombre et recalculez.": "consumed, which the node only picks when it builds the transaction. If the send is refused for too low a fee rate, raise this number and recalculate.", "Pourquoi on ne vous dit pas « combien de mineurs »": "Why we do not tell you \"how many miners\"", "Parce que personne ne peut le savoir, et qu'un chiffre inventé serait pire que pas de chiffre. Un mineur ne s'annonce pas : il pose des blocs. Rien ne distingue mille machines d'une personne qui en possède mille.": "Because nobody can know it, and an invented figure would be worse than none. A miner does not announce itself: it lays down blocks. Nothing distinguishes a thousand machines from one person who owns a thousand.", "Et Q21 rend le comptage encore plus impossible, volontairement : votre portefeuille utilise": "And Q21 makes counting even more impossible, deliberately: your wallet uses", "une adresse différente pour chaque récompense": "a different address for each reward", ", pour qu'on ne puisse pas relier vos gains entre eux. Compter les adresses de mineurs reviendrait donc à compter les blocs.": ", so that your earnings cannot be linked together. Counting miner addresses would therefore amount to counting blocks.", "Ce qui se mesure, en revanche, ne se truque pas :": "What can be measured, on the other hand, cannot be faked:", "le travail réellement dépensé": "the work actually spent", ". Il se lit dans la difficulté, qui s'ajuste pour qu'un bloc tombe toutes les deux minutes. Divisé par ce que fait": ". It is read from the difficulty, which adjusts so that a block falls every two minutes. Divided by what", "votre": "your", "machine, il donne l'équivalence ci-dessus.": "your machine does, it gives the equivalence above.", "Tout votre portefeuille — chaque adresse, chaque fonds — se refabrique à partir du seul code de sauvegarde que vous avez recopié à la création.": "Your entire wallet — every address, every fund — is rebuilt from the single backup code you copied down at creation.", "Sur n'importe quelle machine : Windows, Mac Intel, Mac Apple Silicon, Linux, Raspberry Pi.": "On any machine: Windows, Intel Mac, Apple Silicon Mac, Linux, Raspberry Pi.", "Vous l'y saisissez via « J'ai déjà un code de sauvegarde », et la chaîne fait le reste — vérifié par une épreuve de restauration complète, sur les cinq systèmes construits.": "You enter it there via \"I already have a backup code\", and the chain does the rest — verified by a full restoration test on all five systems built.", "Ne photographiez pas le code, ne le collez pas dans un nuage : qui le lit détient vos fonds, définitivement. Et ne confondez pas le code avec votre": "Do not photograph the code, do not paste it into a cloud: whoever reads it holds your funds, for good. And do not confuse the code with your", "phrase secrète": "passphrase", "— elle, ne protège que le fichier de": "— that one only protects the file on", "cette": "this", "machine, et peut être différente ailleurs.": "machine, and may be different elsewhere.", "ML-DSA-87 (FIPS 204, niveau NIST 5) — pourquoi ça résiste au quantique": "ML-DSA-87 (FIPS 204, NIST level 5) — why it resists quantum attack", "Les signatures de ce portefeuille reposent sur ML-DSA, le schéma à réseaux euclidiens normalisé par le NIST en 2024 sous le nom FIPS 204. Q21 retient le paramétrage le plus élevé, ML-DSA-87, dont la sécurité visée correspond au niveau 5 — de l'ordre d'AES-256.": "This wallet's signatures rest on ML-DSA, the lattice scheme standardised by NIST in 2024 under the name FIPS 204. Q21 takes the highest parameter set, ML-DSA-87, whose target security matches level 5 — on the order of AES-256.", "C'est le point qui distingue ce projet. Les signatures ECDSA que protègent aujourd'hui la plupart des chaînes tombent devant l'algorithme de Shor dès qu'une machine quantique suffisante existe ; celles-ci ne reposent sur aucun problème que Shor résout. Le prix se lit dans les chiffres ci-dessus : une clef publique de 2 592 octets, une signature de 4 627 octets, là où ECDSA tient en quelques dizaines.": "This is what sets this project apart. The ECDSA signatures that protect most chains today fall to Shor's algorithm as soon as a sufficient quantum machine exists; these rest on no problem that Shor solves. The price is in the figures above: a 2,592-byte public key, a 4,627-byte signature, where ECDSA fits in a few dozen.", "Le noyau n'implémente pas lui-même ce schéma : écrire soi-même une signature à réseaux euclidiens est une faute professionnelle. Il branche une implémentation auditée.": "The core does not implement this scheme itself: writing your own lattice signature is professional malpractice. It plugs in an audited implementation.", "Le nœud sert une API JSON-RPC sur": "The node serves a JSON-RPC API on", "énumère les méthodes. Le jeton d'accès de la session s'envoie en": "lists the methods. The session access token is sent as", "; il ne quitte jamais cette page. Rien d'autre n'est écrit dans le navigateur que lui et le choix de langue, tous deux effacés à la fermeture de l'onglet. L'explorateur et le portefeuille sont servis par le même processus, sur le même port, sans aucune ressource externe.": "; it never leaves this page. Nothing else is written in the browser but it and the language choice, both erased when the tab closes. The explorer and the wallet are served by the same process, on the same port, with no external resource.", "Ce portefeuille est servi par un nœud qui tourne dans la fenêtre ouverte par le lanceur. Ce bouton lui demande de s'arrêter proprement : il écrit le réservoir de transactions en attente, l'instantané de l'état et le portefeuille, puis rend la main.": "This wallet is served by a node running in the window opened by the launcher. This button asks it to stop cleanly: it writes the pool of pending transactions, the state snapshot and the wallet, then hands back control.", "C'est la façon recommandée d'arrêter. Fermer la fenêtre du lanceur fonctionne aussi.": "This is the recommended way to stop. Closing the launcher window also works.", "fonctionne également, mais Windows pose alors sa propre question — « Terminer le programme de commandes (O/N) ? » : répondez": "also works, but Windows then asks its own question — \"Terminate batch job (Y/N)?\": answer", ", tout est déjà enregistré à ce moment-là.": ", everything is already saved by then.", "— tout ce que votre nœud a vérifié, consultable sans faire confiance à personne.": "— everything your node has verified, browsable without trusting anyone.", "Copier": "Copy", "copier": "copy", "Enregistrer": "Save", "Nommer": "Name it", "Renommer": "Rename", "sans nom": "unnamed", "servie": "used", "Historique complet": "Full history", "Q21 créés à ce jour": "Q21 created to date", "Schéma de signature": "Signature scheme", "Signature": "Signature", "Sommes non dépensées": "Unspent amounts", "Total détenu": "Total held", "disponible et en attente réunis": "available and pending combined", "clefs réutilisables sans affaiblissement": "keys reusable without weakening", "usage unique : une clef ne signe qu'une fois": "single use: a key signs only once", "engagement MuHash sur le jeu d'UTXO — identique sur tout nœud à cette hauteur": "MuHash commitment over the UTXO set — identical on every node at this height", "sur toute la chaîne, tous porteurs confondus": "across the whole chain, all holders together", "aucun bloc depuis le lancement de cet écran": "no block since this screen was opened", "Miner demande un portefeuille : sans lui, la récompense n'irait nulle part.": "Mining requires a wallet: without one, the reward would go nowhere.", "réseau d'essai": "test network", "minage": "mining", "tentatives/s": "attempts/s", "votre portefeuille en fabrique une nouvelle à chaque encaissement": "your wallet makes a new one for each payment received", "Portefeuille fermé": "Wallet closed", "Le nœud a écrit son état et s'est arrêté. Vous pouvez fermer cet onglet ;": "The node has written its state and stopped. You may close this tab;", "la fenêtre noire se referme d'elle-même.": "the black window closes by itself.", "Le montant doit être strictement positif.": "The amount must be strictly positive.", "Les frais ne peuvent pas être négatifs.": "The fee cannot be negative.", "Montant illisible. Attendu : un nombre en Q21, huit décimales au maximum.": "Unreadable amount. Expected: a number in Q21, eight decimals at most.", "Un montant supplémentaire est illisible. Attendu : un nombre en Q21.": "An additional amount is unreadable. Expected: a number in Q21.", "Un destinataire supplémentaire est sans adresse. Retirez la ligne ou remplissez-la.": "An additional recipient has no address. Remove the row or fill it in.", "Il en faut au moins deux, séparés dans le temps.": "At least two are needed, spread over time.", "Pas encore assez de blocs pour mesurer quoi que ce soit.": "Not enough blocks yet to measure anything.", "le réseau n'est pas encore mesurable": "the network is not measurable yet", "allumez le minage pour vous situer": "turn mining on to place yourself", "vitesse en cours de mesure": "speed being measured", "durée inconnue": "unknown duration", "activé": "on", "arrêté": "off", "à l'arrêt": "stopped", "· aucun ordinateur joignable": "· no computer reachable", "copie refusée par le navigateur": "copy refused by the browser", "copié": "copied", "jeton d'accès manquant ou refusé": "access token missing or refused", "Le solde affiché est donc peut-être incomplet.": "The displayed balance may therefore be incomplete.", "Votre machine cherche un bloc": "Your machine is looking for a block", "Le minage n'a pas pu être": "Mining could not be", "Nom non enregistré :": "Name not saved:", "Suggestion du nœud pour": "Node suggestion for", "Les frais suffisent rarement quand la transaction consomme plus": "Fees are rarely enough when the transaction consumes more", "Un envoi précédent est encore en attente et immobilise les mêmes": "A previous send is still pending and ties up the same", "pièces. Attendez qu'un bloc le confirme avant d'en émettre un autre.": "coins. Wait for a block to confirm it before sending another."}, "ja": {"Portefeuille": "ウォレット", "Connexion…": "接続中…", "Solde": "残高", "Miner": "マイニング", "Recevoir": "受け取る", "Envoyer": "送る", "Réseau": "ネットワーク", "Activité": "履歴", "Infos": "情報", "Chargement…": "読み込み中…", "Détail": "詳細", "Fermer": "閉じる", "Revenir": "戻る", "Tout": "すべて", "Reçu": "受取", "Envoyé": "送金", "Quoi": "種別", "Date": "日付", "Référence": "参照", "Confirmations": "承認数", "Bloc n°": "ブロック番号", "Disponible": "利用可能", "Minage": "マイニング", "Chaîne": "チェーン", "Vos blocs": "あなたのブロック", "Vos adresses": "あなたのアドレス", "Le réseau": "ネットワーク", "Votre sécurité": "セキュリティ", "Votre machine": "あなたのマシン", "Mesure en cours…": "測定中…", "Nœud injoignable": "ノードに接続できません", "Déverrouiller": "ロック解除", "Nouvelle adresse": "新しいアドレス", "Afficher les suivantes": "さらに表示", "Chercher dans votre carnet": "アドレス帳を検索", "+ Ajouter un destinataire": "+ 宛先を追加", "Recalculer les frais": "手数料を再計算", "Vérifier": "確認", "Envoyer définitivement": "確定して送る", "Fermer le portefeuille": "ウォレットを終了", "Envoyer du Q21": "Q21 を送る", "Adresse du destinataire": "宛先アドレス", "Montant, en Q21": "金額 (Q21)", "Frais, en Q21": "手数料 (Q21)", "Suggestion du nœud, modifiable.": "ノードの提案値です。変更できます。", "Confirmer l'envoi": "送金の確認", "Un envoi est définitif": "送金は取り消せません", "Entrées supposées, pour l'estimation des frais": "手数料見積り用の入力数", "L'adresse porte une somme de contrôle : une faute de frappe sera détectée par le nœud, pas subie.": "アドレスにはチェックサムがあります。打ち間違いはノードが検出します。", "Huit décimales au maximum. Une unité vaut 0.00000001 Q21.": "小数点以下は最大 8 桁。1 単位は 0.00000001 Q21 です。", "Aucune autorité ne peut annuler une transaction acceptée. Relisez l'adresse caractère par caractère : c'est la seule vérification qui vous reste.": "承認された取引を取り消せる権威は存在しません。アドレスを一文字ずつ読み直してください。それが最後の確認です。", "Un seul envoi peut payer plusieurs destinataires à la fois : c'est une transaction unique, aux frais partagés, plutôt que plusieurs envois séparés.": "一度の送金で複数の宛先に支払えます。手数料を分け合う単一の取引になります。", "Votre machine ne cherche pas": "マシンは探索していません", "Le minage cherche le prochain bloc. Il utilise tous les cœurs.": "マイニングは次のブロックを探します。全コアを使います。", "tentatives par seconde": "秒あたりの試行", "Gagné en minant": "マイニング報酬", "depuis le lancement — maturité comprise": "起動以降 — 成熟待ちを含む", "Blocs trouvés": "発見ブロック", "depuis le lancement": "起動以降", "Tentatives": "試行回数", "Rythme de la chaîne": "チェーンの速度", "cible : un bloc toutes les 2 minutes": "目標: 2 分に 1 ブロック", "Mémoire occupée": "使用メモリ", "la table de calcul, en mémoire vive": "計算テーブル (RAM 上)", "Puissance de calcul du réseau": "ネットワークの計算力", "mesurée chez vous, en direct": "あなたのマシンでの実測値", "Machines comme la vôtre": "あなたと同等のマシン", "équivalence, pas un décompte": "換算値であり実数ではありません", "Machines connues du réseau": "ネットワークが知るマシン", "adresses apprises, présentes ou passées": "学習済みアドレス (現在・過去)", "Ordinateurs reliés au vôtre": "接続中のコンピュータ", "vos voisins directs, pas le réseau entier": "直接の隣接ノードのみ", "Mesuré sur": "測定範囲", "les blocs les plus récents": "直近のブロック", "Le code de sauvegarde est votre portefeuille": "バックアップコードがあなたのウォレットです", "Le fichier sur ce disque n'est qu'une copie de travail.": "このディスク上のファイルは作業用の複製にすぎません。", "Deux choses à ne jamais faire": "絶対にしてはいけない二つのこと", "Pour les développeurs": "開発者向け", "Explorateur de la chaîne": "チェーンエクスプローラ", "Jeton d'accès requis": "アクセストークンが必要です", "Récupération de l'historique de la chaîne": "チェーン履歴を取得中", "Pourquoi une part du solde est immature": "残高の一部が未成熟な理由", "Pourquoi vous en avez plusieurs": "複数ある理由", "Ce que fait votre machine quand ce bouton est allumé": "このスイッチが入っているとき、マシンは何をするか", "Chaque paiement mérite une adresse neuve. Réutiliser une adresse ne coûte rien au protocole, mais relie publiquement vos paiements entre eux.": "支払いごとに新しいアドレスを。再利用はプロトコル上は無料ですが、支払い同士が公に結び付きます。", "Réseau d'essai — les Q21 qui s'y minent n'ont aucune valeur, et n'en auront jamais. Logiciel de recherche, non audité de l'extérieur.": "テストネット — ここで採掘される Q21 に価値はなく、今後もありません。外部監査を受けていない研究用ソフトウェアです。", "Activer le minage": "マイニングを開始", "Arrêter le minage": "マイニングを停止", "Ce nœud ne peut pas miner": "このノードはマイニングできません", "Connecté": "接続済み", "Fermeture…": "終了中…", "Confirmer la fermeture": "終了の確認", "Cliquez une seconde fois pour arrêter le portefeuille.": "もう一度クリックするとウォレットを停止します。", "Adresses connues": "既知のアドレス", "Blocs vérifiés": "検証済みブロック", "Dernier bloc": "最新ブロック", "Destinataire": "宛先", "Difficulté": "難易度", "En attente de maturité": "成熟待ち", "Empreinte de l'état": "状態フィンガープリント", "Clef publique": "公開鍵", "Clefs consommées": "使用済みの鍵", "En attente d'un ordinateur à qui demander la chaîne": "チェーンを要求する相手を待っています", "Débit de minage des dernières minutes": "直近数分のマイニング速度", "Elle utilise tous les cœurs disponibles.": "利用可能な全コアを使用します。", "Aucune adresse de destination.": "宛先アドレスがありません。", "Chaque montant doit être strictement positif.": "金額は必ず正の値である必要があります。", "Le montant minimal est 0,0001 Q21 : en dessous, le réseau refuse la sortie comme poussière.": "最小金額は 0.0001 Q21 です。それ未満の出力はダストとしてネットワークに拒否されます。", "Chaque montant doit valoir au moins 0,0001 Q21 : en dessous, le réseau refuse la sortie comme poussière.": "各金額は 0.0001 Q21 以上である必要があります。それ未満の出力はダストとしてネットワークに拒否されます。", "Frais illisibles. Attendu : un nombre en Q21, huit décimales au maximum.": "手数料を解釈できません。Q21 の数値 (小数点以下 8 桁まで) を入力してください。", "Le nœud exige un jeton. Il est normalement transmis par le lanceur dans le fragment de l'adresse ; si vous avez ouvert cette page à la main, saisissez ici le jeton passé à": "ノードはトークンを要求します。通常はランチャーがアドレスのフラグメントで渡します。このページを手動で開いた場合は、次に渡したトークンをここに入力してください:", "Si vous venez de restaurer un portefeuille": "ウォレットを復元した直後の場合", ", vos fonds réapparaîtront à la fin de cette étape : ils sont dans la chaîne, et votre machine ne les a pas encore lus. Le solde affiché est incomplet jusque-là.": "、資金はこの工程の終わりに再表示されます。資金はチェーン上にあり、あなたのマシンがまだ読み終えていないだけです。それまで表示残高は不完全です。", "Une récompense de minage n'est dépensable qu'après un long délai de maturation. Tant qu'il n'est pas écoulé, la somme existe, elle vous appartient, mais aucune transaction ne peut la dépenser. Elle est comptée séparément plutôt que fondue dans un total qui serait faux.": "マイニング報酬は長い成熟期間を経てはじめて使用できます。期間が終わるまで、その金額は存在しあなたのものですが、どの取引でも使えません。誤った合計に紛れ込ませず、別枠で数えています。", "Elle fouille une table de deux gigaoctets en mémoire, des centaines de milliers de fois par seconde, à la recherche d'une valeur qui satisfasse la difficulté du moment. C'est une loterie : on ne gagne pas à tous les coups, on gagne d'autant plus souvent qu'on cherche vite.": "メモリ上の 2 ギガバイトのテーブルを毎秒何十万回も探索し、その時点の難易度を満たす値を探します。これは宝くじです。毎回当たるわけではなく、速く探すほど当たりやすくなります。", "La récompense d'un bloc trouvé est versée à une adresse de ce portefeuille. Elle n'est dépensable qu'après le délai de maturation.": "発見したブロックの報酬は、このウォレットのアドレスに支払われます。成熟期間の経過後にのみ使用できます。", "Votre portefeuille ne contient": "あなたのウォレットが持つ秘密は", "qu'un seul secret": "ただ一つだけです", ": la graine, celle du code de sauvegarde que vous avez recopié. Toutes vos adresses en sont": ": 書き写したバックアップコードのもとになる種です。すべてのアドレスは計算によって", "fabriquées": "作られます", "par un calcul — la première, la deuxième, la millième. C'est ce qu'on appelle les": "— 1 番目も 2 番目も 1000 番目も。これを", "dériver": "導出という", "Conséquence rassurante :": "安心できる帰結:", "ce code sauve tout": "このコードがすべてを救う", ". Pas besoin de sauvegarder chaque adresse ; elles se recalculent toutes à partir de lui.": "。個々のアドレスを保存する必要はありません。すべてそこから再計算されます。", "Conséquence utile : en donner une neuve à chaque personne qui vous paie ne coûte rien, et évite qu'un curieux relie tous vos encaissements entre eux en lisant la chaîne. Votre solde est la somme de toutes.": "実用的な帰結: 支払う人ごとに新しいアドレスを渡しても費用はかからず、チェーンを読む者があなたの入金を結び付けることを防げます。残高はそれらすべての合計です。", "Avec ML-DSA-87 le témoin pèse la quasi-totalité d'une transaction : les frais dépendent surtout du": "ML-DSA-87 では証人データが取引のほぼ全体を占めます。手数料は主に消費される", "nombre d'entrées": "入力の数", "consommées, que le nœud ne choisit qu'au moment de construire la transaction. Si l'envoi est refusé pour taux de frais trop bas, augmentez ce nombre et recalculez.": "に依存し、ノードは取引を組み立てる時にはじめてそれを決めます。手数料率が低すぎて送金が拒否された場合は、この数を増やして再計算してください。", "Pourquoi on ne vous dit pas « combien de mineurs »": "「マイナーの数」をお伝えしない理由", "Parce que personne ne peut le savoir, et qu'un chiffre inventé serait pire que pas de chiffre. Un mineur ne s'annonce pas : il pose des blocs. Rien ne distingue mille machines d'une personne qui en possède mille.": "誰にも知りようがなく、でっち上げた数字は数字がないより悪いからです。マイナーは名乗らず、ただブロックを置きます。千台のマシンと、千台を所有する一人とを区別する手立てはありません。", "Et Q21 rend le comptage encore plus impossible, volontairement : votre portefeuille utilise": "さらに Q21 は意図的に集計を不可能にしています。ウォレットは報酬ごとに", "une adresse différente pour chaque récompense": "異なるアドレスを使います", ", pour qu'on ne puisse pas relier vos gains entre eux. Compter les adresses de mineurs reviendrait donc à compter les blocs.": "。そのため収益同士を結び付けられません。マイナーのアドレスを数えることは、ブロックを数えることと同じになります。", "Ce qui se mesure, en revanche, ne se truque pas :": "一方、測定できるものは偽装できません:", "le travail réellement dépensé": "実際に費やされた仕事量", ". Il se lit dans la difficulté, qui s'ajuste pour qu'un bloc tombe toutes les deux minutes. Divisé par ce que fait": "。これは 2 分に 1 ブロックとなるよう調整される難易度から読み取れます。それを", "votre": "あなたの", "machine, il donne l'équivalence ci-dessus.": "マシンの性能で割ると、上の換算値になります。", "Tout votre portefeuille — chaque adresse, chaque fonds — se refabrique à partir du seul code de sauvegarde que vous avez recopié à la création.": "ウォレット全体 — すべてのアドレス、すべての資金 — は、作成時に書き写した唯一のバックアップコードから復元されます。", "Sur n'importe quelle machine : Windows, Mac Intel, Mac Apple Silicon, Linux, Raspberry Pi.": "どのマシンでも: Windows、Intel Mac、Apple Silicon Mac、Linux、Raspberry Pi。", "Vous l'y saisissez via « J'ai déjà un code de sauvegarde », et la chaîne fait le reste — vérifié par une épreuve de restauration complète, sur les cinq systèmes construits.": "「バックアップコードを持っています」から入力すれば、あとはチェーンが行います — 構築される 5 つのシステムすべてで、完全な復元テストにより検証済みです。", "Ne photographiez pas le code, ne le collez pas dans un nuage : qui le lit détient vos fonds, définitivement. Et ne confondez pas le code avec votre": "コードを撮影せず、クラウドに貼り付けないでください。読んだ者が資金を永久に手にします。また、このコードを", "phrase secrète": "パスフレーズ", "— elle, ne protège que le fichier de": "と混同しないでください。パスフレーズが守るのは", "cette": "この", "machine, et peut être différente ailleurs.": "マシンのファイルだけで、他の場所では異なる場合があります。", "ML-DSA-87 (FIPS 204, niveau NIST 5) — pourquoi ça résiste au quantique": "ML-DSA-87 (FIPS 204、NIST レベル 5) — 量子計算に耐える理由", "Les signatures de ce portefeuille reposent sur ML-DSA, le schéma à réseaux euclidiens normalisé par le NIST en 2024 sous le nom FIPS 204. Q21 retient le paramétrage le plus élevé, ML-DSA-87, dont la sécurité visée correspond au niveau 5 — de l'ordre d'AES-256.": "このウォレットの署名は、NIST が 2024 年に FIPS 204 として標準化した格子ベース方式 ML-DSA に基づきます。Q21 は最上位のパラメータ ML-DSA-87 を採用し、目標とする安全性はレベル 5 — AES-256 に相当します。", "C'est le point qui distingue ce projet. Les signatures ECDSA que protègent aujourd'hui la plupart des chaînes tombent devant l'algorithme de Shor dès qu'une machine quantique suffisante existe ; celles-ci ne reposent sur aucun problème que Shor résout. Le prix se lit dans les chiffres ci-dessus : une clef publique de 2 592 octets, une signature de 4 627 octets, là où ECDSA tient en quelques dizaines.": "これがこのプロジェクトを際立たせる点です。今日ほとんどのチェーンを守る ECDSA 署名は、十分な量子計算機が現れれば Shor のアルゴリズムに屈します。こちらは Shor が解ける問題に依存していません。その代償は上の数字に表れます: 公開鍵 2,592 バイト、署名 4,627 バイト。ECDSA なら数十バイトです。", "Le noyau n'implémente pas lui-même ce schéma : écrire soi-même une signature à réseaux euclidiens est une faute professionnelle. Il branche une implémentation auditée.": "コア自身はこの方式を実装しません。格子署名を自作することは専門家として許されない過ちです。監査済みの実装を組み込んでいます。", "Le nœud sert une API JSON-RPC sur": "ノードは次の場所で JSON-RPC API を提供します:", "énumère les méthodes. Le jeton d'accès de la session s'envoie en": "がメソッドを列挙します。セッションのアクセストークンは次の形式で送ります:", "; il ne quitte jamais cette page. Rien d'autre n'est écrit dans le navigateur que lui et le choix de langue, tous deux effacés à la fermeture de l'onglet. L'explorateur et le portefeuille sont servis par le même processus, sur le même port, sans aucune ressource externe.": "。これはこのページから外に出ません。ブラウザに書き込まれるのはこれと言語の選択だけで、どちらもタブを閉じると消えます。エクスプローラとウォレットは同一プロセス・同一ポートで提供され、外部リソースは一切使いません。", "Ce portefeuille est servi par un nœud qui tourne dans la fenêtre ouverte par le lanceur. Ce bouton lui demande de s'arrêter proprement : il écrit le réservoir de transactions en attente, l'instantané de l'état et le portefeuille, puis rend la main.": "このウォレットは、ランチャーが開いたウィンドウで動くノードが提供しています。このボタンはノードに正常終了を求めます: 保留中の取引プール、状態のスナップショット、ウォレットを書き出してから制御を返します。", "C'est la façon recommandée d'arrêter. Fermer la fenêtre du lanceur fonctionne aussi.": "これが推奨される停止方法です。ランチャーのウィンドウを閉じても構いません。", "fonctionne également, mais Windows pose alors sa propre question — « Terminer le programme de commandes (O/N) ? » : répondez": "も使えますが、その場合 Windows が独自の確認 —「バッチ ジョブを終了しますか (Y/N)?」— を出します。次のように答えてください:", ", tout est déjà enregistré à ce moment-là.": "。その時点ですべて保存済みです。", "— tout ce que votre nœud a vérifié, consultable sans faire confiance à personne.": "— あなたのノードが検証したすべてを、誰も信頼することなく閲覧できます。", "Copier": "コピー", "copier": "コピー", "Enregistrer": "保存", "Nommer": "名前を付ける", "Renommer": "名前を変更", "sans nom": "名前なし", "servie": "使用済み", "Historique complet": "完全な履歴", "Q21 créés à ce jour": "これまでに発行された Q21", "Schéma de signature": "署名方式", "Signature": "署名", "Sommes non dépensées": "未使用額", "Total détenu": "保有総額", "disponible et en attente réunis": "利用可能分と待機分の合計", "clefs réutilisables sans affaiblissement": "再利用しても弱くならない鍵", "usage unique : une clef ne signe qu'une fois": "使い捨て: 鍵は一度しか署名しません", "engagement MuHash sur le jeu d'UTXO — identique sur tout nœud à cette hauteur": "UTXO 集合に対する MuHash コミットメント — この高さのすべてのノードで同一", "sur toute la chaîne, tous porteurs confondus": "チェーン全体、全保有者の合計", "aucun bloc depuis le lancement de cet écran": "この画面を開いてからブロックはありません", "Miner demande un portefeuille : sans lui, la récompense n'irait nulle part.": "マイニングにはウォレットが必要です。ないと報酬の宛先がありません。", "réseau d'essai": "テストネット", "minage": "マイニング", "tentatives/s": "回試行/秒", "votre portefeuille en fabrique une nouvelle à chaque encaissement": "入金ごとにウォレットが新しいものを作ります", "Portefeuille fermé": "ウォレットを終了しました", "Le nœud a écrit son état et s'est arrêté. Vous pouvez fermer cet onglet ;": "ノードは状態を書き出して停止しました。このタブを閉じて構いません。", "la fenêtre noire se referme d'elle-même.": "黒いウィンドウは自動的に閉じます。", "Le montant doit être strictement positif.": "金額は正の値である必要があります。", "Les frais ne peuvent pas être négatifs.": "手数料を負の値にはできません。", "Montant illisible. Attendu : un nombre en Q21, huit décimales au maximum.": "金額を解釈できません。Q21 の数値 (小数点以下 8 桁まで) を入力してください。", "Un montant supplémentaire est illisible. Attendu : un nombre en Q21.": "追加の金額を解釈できません。Q21 の数値を入力してください。", "Un destinataire supplémentaire est sans adresse. Retirez la ligne ou remplissez-la.": "追加の宛先にアドレスがありません。行を削除するか入力してください。", "Il en faut au moins deux, séparés dans le temps.": "時間を空けた 2 つ以上が必要です。", "Pas encore assez de blocs pour mesurer quoi que ce soit.": "測定に足るブロックがまだありません。", "le réseau n'est pas encore mesurable": "ネットワークはまだ測定できません", "allumez le minage pour vous situer": "自分の位置を知るにはマイニングを開始してください", "vitesse en cours de mesure": "速度を測定中", "durée inconnue": "所要時間は不明", "activé": "有効", "arrêté": "停止", "à l'arrêt": "停止中", "· aucun ordinateur joignable": "· 接続可能なコンピュータなし", "copie refusée par le navigateur": "ブラウザがコピーを拒否しました", "copié": "コピーしました", "jeton d'accès manquant ou refusé": "アクセストークンがないか拒否されました", "Le solde affiché est donc peut-être incomplet.": "そのため表示残高は不完全な可能性があります。", "Votre machine cherche un bloc": "マシンがブロックを探しています", "Le minage n'a pas pu être": "マイニングを次にできませんでした:", "Nom non enregistré :": "名前を保存できませんでした:", "Suggestion du nœud pour": "ノードの提案:", "Les frais suffisent rarement quand la transaction consomme plus": "取引がより多くを消費する場合、手数料が足りないことがあります", "Un envoi précédent est encore en attente et immobilise les mêmes": "前回の送金がまだ保留中で、同じ資金を拘束しています", "pièces. Attendez qu'un bloc le confirme avant d'en émettre un autre.": "。別の送金の前に、ブロックによる承認をお待ちください。"}};
const I18N_MOTIFS = {
  "en": [
    [/^(.+) adresse\(s\) au total$/, "$1 address(es) in total"],
    [/^(.+) trouvaille\(s\) plus ancienne\(s\) — toutes comptées dans le total gagné\.$/, "$1 older find(s) — all counted in the total earned."],
    [/^(.+) somme\(s\) utilisable\(s\) tout de suite$/, "$1 amount(s) usable right now"],
    [/^(.+) dérivée\(s\) depuis la graine$/, "$1 derived from the seed"],
    [/^(.+) adresse\(s\) trouvée\(s\) sur (.+)$/, "$1 address(es) found out of $2"],
    [/^Bloc (.+)$/, "Block $1"],
    [/^(.+) blocs$/, "$1 blocks"],
    [/^Mesuré sur (.+) bloc\(s\), soit (.+) heure\(s\) de chaîne\. Ce chiffre ne se déclare pas : il se déduit du travail réellement dépensé pour les produire\.$/, "Measured over $1 block(s), i.e. $2 hour(s) of chain. This figure is not declared: it is deduced from the work actually spent to produce them."],
    [/^mûrit dans environ (.+)$/, "matures in about $1"],
    [/^prochaine libération : (.+) Q21 dans (.+) bloc\(s\), soit environ (.+) — au bloc (.+)$/, "next release: $1 Q21 in $2 block(s), about $3 — at block $4"],
    [/^soit environ (.+) % du réseau$/, "about $1 % of the network"],
    [/^table de l'époque (.+) — elle grandit de (.+) % tous les (.+) jours$/, "epoch $1 table — it grows by $2 % every $3 days"],
    [/^identifiant (.+) dans le protocole$/, "identifier $1 in the protocol"],
    [/^votre machine les a tous recalculés elle-même — (.+) transaction\(s\) en attente d'être inscrite\(s\)$/, "your machine recomputed them all itself — $1 transaction(s) waiting to be recorded"],
    [/^(.+) transaction\(s\) en attente d'être inscrite\(s\)$/, "$1 transaction(s) waiting to be recorded"],
    [/^(.+) ordinateur\(s\) relié\(s\)\.(.*)$/, "$1 computer(s) connected.$2"],
    [/^(.+) tentatives\/s$/, "$1 attempts/s"],
    [/^· (.+) pair\(s\) · bloc (.+)$/, "· $1 peer(s) · block $2"],
    [/^(.+) Gio$/, "$1 GiB"],
    [/^environ (.+)$/, "about $1"]
  ],
  "ja": [
    [/^(.+) adresse\(s\) au total$/, "合計 $1 件のアドレス"],
    [/^(.+) trouvaille\(s\) plus ancienne\(s\) — toutes comptées dans le total gagné\.$/, "$1 件の古い発見 — すべて獲得合計に含まれます。"],
    [/^(.+) somme\(s\) utilisable\(s\) tout de suite$/, "今すぐ使える $1 件"],
    [/^(.+) dérivée\(s\) depuis la graine$/, "種から導出済み $1 件"],
    [/^(.+) adresse\(s\) trouvée\(s\) sur (.+)$/, "$2 件中 $1 件のアドレスが該当"],
    [/^Bloc (.+)$/, "ブロック $1"],
    [/^(.+) blocs$/, "$1 ブロック"],
    [/^Mesuré sur (.+) bloc\(s\), soit (.+) heure\(s\) de chaîne\. Ce chiffre ne se déclare pas : il se déduit du travail réellement dépensé pour les produire\.$/, "$1 ブロック (チェーン $2 時間分) で測定。この数値は申告されるものではなく、それらを生み出すために実際に費やされた仕事量から導かれます。"],
    [/^mûrit dans environ (.+)$/, "約 $1 で成熟します"],
    [/^prochaine libération : (.+) Q21 dans (.+) bloc\(s\), soit environ (.+) — au bloc (.+)$/, "次の解放: $2 ブロック後 (約 $3) に $1 Q21 — ブロック $4"],
    [/^soit environ (.+) % du réseau$/, "ネットワークの約 $1 %"],
    [/^table de l'époque (.+) — elle grandit de (.+) % tous les (.+) jours$/, "エポック $1 のテーブル — $3 日ごとに $2 % 増加します"],
    [/^identifiant (.+) dans le protocole$/, "プロトコル上の識別子 $1"],
    [/^votre machine les a tous recalculés elle-même — (.+) transaction\(s\) en attente d'être inscrite\(s\)$/, "あなたのマシンがすべて自ら再計算しました — 記録待ちの取引 $1 件"],
    [/^(.+) transaction\(s\) en attente d'être inscrite\(s\)$/, "記録待ちの取引 $1 件"],
    [/^(.+) ordinateur\(s\) relié\(s\)\.(.*)$/, "接続中のコンピュータ $1 台。$2"],
    [/^(.+) tentatives\/s$/, "$1 回試行/秒"],
    [/^· (.+) pair\(s\) · bloc (.+)$/, "· $1 ピア · ブロック $2"],
    [/^(.+) Gio$/, "$1 GiB"],
    [/^environ (.+)$/, "約 $1"]
  ]
};
const I18N_PREFIXES = {"en": {"Impossible d'interroger le nœud : ": "Cannot reach the node: ", "Fonds insuffisants : ": "Insufficient funds: ", "Frais non estimés : ": "Fee not estimated: "}, "ja": {"Impossible d'interroger le nœud : ": "ノードに問い合わせできません: ", "Fonds insuffisants : ": "残高不足: ", "Frais non estimés : ": "手数料を見積れません: "}};
let LANGUE = "fr";

// Les dates et les nombres suivent aussi la langue : « 12/08/2025 » ne se lit
// pas comme « 8/12/2025 », et un Japonais attend « 2025/08/12 ». Traduire les
// mots en laissant les chiffres dans un autre usage serait un travail a moitie
// fait.
function q21Locale(){
  return LANGUE === "en" ? "en-US" : (LANGUE === "ja" ? "ja-JP" : "fr-FR");
}

function q21Norm(s){ return s.replace(/\u00a0/g, " ").replace(/\s+/g, " ").trim(); }

function q21Trad(src){
  const d = I18N[LANGUE];
  if (!d) return null;
  const n = q21Norm(src);
  let v = d[n];
  if (v === undefined){
    // Certains messages portent une queue variable — une erreur, un montant.
    // On traduit alors la partie fixe et on garde la queue telle quelle :
    // mieux vaut une phrase a moitie traduite qu'une phrase absente.
    const pr = I18N_PREFIXES[LANGUE] || {};
    for (const k in pr){ if (n.startsWith(k)){ v = pr[k] + n.slice(k.length); break; } }
  }
  if (v === undefined){
    // Derniere chance : les phrases baties autour d'un nombre. L'appariement
    // exact ne peut rien pour elles — le nombre change a chaque affichage — donc
    // on capture les parties variables et on ne traduit que le reste.
    for (const [motif, modele] of (I18N_MOTIFS[LANGUE] || [])){
      if (motif.test(n)){ v = n.replace(motif, modele); break; }
    }
  }
  if (v === undefined) return null;
  // On conserve l'espacement d'origine : le texte est souvent colle a une
  // balise voisine, et le manger deplacerait la mise en page.
  const av = src.match(/^\s*/)[0], ap = src.match(/\s*$/)[0];
  return av + v + ap;
}

function q21TraduireTexte(n){
  // Si la valeur courante est exactement ce que nous avions ecrit, c'est
  // notre propre ecriture : l'original reste l'original. Sinon, c'est le
  // script de la page qui vient d'ecrire, et cette nouvelle valeur devient
  // la source a traduire. Sans cette distinction, un rafraichissement
  // ferait traduire une traduction, ou ecraserait la donnee fraiche.
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
  // Le selecteur lui-meme garde ses intitules : le nom d'une langue s'ecrit
  // dans cette langue, pas dans celle de la page.
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

function q21AppliquerLangue(code){
  LANGUE = (code === "en" || code === "ja") ? code : "fr";
  document.documentElement.lang = LANGUE;
  try { sessionStorage.setItem("q21-langue", LANGUE); } catch (e) {}
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
    // Ce que le script ecrit ensuite doit etre traduit aussi, sans quoi la
    // langue choisie se perdrait au premier rafraichissement des donnees.
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

// `court` tronquait les empreintes a l'affichage. Plus rien ne l'appelle : une
// empreinte qu'on ne peut pas emporter dans la recherche de l'explorateur ne
// sert a rien, et les deux endroits qui l'employaient rendent desormais
// l'empreinte entiere avec un bouton de copie. La fonction reste ecrite ici
// parce que la regle d'echappement de cette page la nomme parmi les sorties
// sures, et qu'un futur affichage tronque doit passer par elle plutot que par
// un `slice` improvise.
const court = (h,n)=> h ? ech(String(h).slice(0, n||16))+"…" : "—";
const date = t => new Date(Number(t) * 1000).toISOString().replace("T"," ").slice(0,19);

// Une quantite d'octets, dans l'unite ou un humain la reconnait. Les puissances
// de 1024 et non de 1000 : c'est ainsi qu'une barrette de memoire se compte, et
// c'est de memoire qu'il s'agit ici.
// Une attente en blocs, traduite dans le temps des humains.
//
// Le nœud donne l'intervalle visé par le protocole ; on ne le recopie pas ici,
// pour qu'il n'y ait qu'un seul endroit au monde où ce chiffre soit écrit.
function dureeBlocs(blocs, info){
  const t = Number(info && info.intervalle_cible_secondes) || 120;
  const sec = Math.max(0, Number(blocs) || 0) * t;
  if (sec < 90) return "environ " + Math.round(sec) + " s";
  if (sec < 5400) return "environ " + Math.round(sec / 60) + " min";
  if (sec < 172800) return "environ " + (sec / 3600).toFixed(1) + " h";
  return "environ " + (sec / 86400).toFixed(1) + " jours";
}

function octets(n){
  n = Number(n) || 0;
  if (n >= 1073741824) return (n / 1073741824).toFixed(2) + " Gio";
  if (n >= 1048576)    return (n / 1048576).toFixed(0) + " Mio";
  if (n >= 1024)       return (n / 1024).toFixed(0) + " Kio";
  return String(Math.round(n)) + " o";
}

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

const VUES = ["solde","miner","recevoir","reseau","envoyer","historique","infos"];

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
  if (nom === "reseau") reseau();
}

document.getElementById("onglets").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-vue]");
  if (b) montrer(b.dataset.vue);
});

// Les gestes rapides du solde : les trois actions qu'on vient chercher neuf
// fois sur dix, a un geste du chiffre qu'on vient de lire.
document.addEventListener("click", ev => {
  const b = ev.target.closest("button[data-aller]");
  if (b) montrer(b.dataset.aller);
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
    // Le nœud annonce « Testnet » (nom Debug de l'enum). On compare donc en
    // minuscules : la premiere version comparait a "testnet" exact et le badge
    // affichait le jargon anglais qu'elle croyait traduire.
    document.getElementById("reseau").textContent =
      String(info.reseau).toLowerCase() === "testnet" ? "réseau d'essai" : info.reseau;
    pouls(sync);

    // --- Le bandeau de recuperation.
    //
    // Il n'annonce pas « restauration en cours » : le nœud ne le sait pas, et
    // l'affirmer serait inventer. Il annonce ce qui se passe reellement — la
    // chaine se recupere — puis ajoute une ligne **conditionnelle** pour qui
    // vient de restaurer. La conditionnelle est vraie dans les deux cas.
    const bandeau = document.getElementById("bandeau-sync");
    if (sync.synchronise){
      bandeau.hidden = true;
    } else {
      bandeau.hidden = false;
      const ici = Number(sync.hauteur), la = Number(sync.hauteur_reseau) || 1;
      const seul = Number(sync.pairs) === 0;

      // --- Sans pair, il n'y a rien a mesurer.
      //
      // La barre affichait « 210 sur 210 » et se remplissait entierement sous
      // un titre d'attente : une progression achevee pour une operation qui
      // n'avait pas commence. Un nœud sans pair ne connait pas la hauteur du
      // reseau ; il connait la sienne, et c'est tout. On cache donc la mesure
      // plutot que d'en montrer une fausse.
      document.getElementById("recup-mesure").hidden = seul;
      document.getElementById("recup-titre").textContent = seul
        ? "En attente d'un ordinateur à qui demander la chaîne"
        : "Récupération de l'historique de la chaîne";
      if (!seul){
        const pct = Math.max(0, Math.min(100, (ici / la) * 100));
        document.getElementById("recup-barre").style.width = pct.toFixed(1) + "%";
        document.getElementById("recup-position").textContent =
          ici.toLocaleString(q21Locale()) + " sur " + la.toLocaleString(q21Locale()) + " blocs";
        // La vitesse vient de la meme derivee que celle du reseau ; sans elle on
        // n'annonce pas de duree, plutot que d'en inventer une.
        document.getElementById("recup-vitesse").textContent =
          vitesseBlocs > 0.05
            ? vitesseBlocs.toFixed(1) + " blocs/s · " + resteEnTemps(Number(sync.blocs_restants))
            : "vitesse en cours de mesure";
      }
      document.getElementById("sync-note").textContent = sync.note;
      // Un portefeuille qui n'a presque rien derive et qui rattrape la chaine
      // est très probablement une restauration. On ne l'affirme pas : on
      // s'adresse a lui par une condition qu'il reconnaitra.
      document.getElementById("recup-restaure").hidden =
        Number(solde.adresses_derivees) > 2;
      document.getElementById("sync-detail").textContent = seul
        ? "Votre machine a vérifié " + ici.toLocaleString(q21Locale()) + " bloc(s), mais " +
          "sans personne à qui parler elle ne peut pas savoir s'il en existe d'autres. " +
          "Le solde affiché est donc peut-être incomplet."
        : sync.pairs + " ordinateur(s) relié(s). Ce qui est affiché ci-dessous ne " +
          "compte que les blocs déjà vérifiés par cette machine.";
    }

    document.getElementById("solde-gros").innerHTML = gros(solde.depensable.q21);
    document.getElementById("solde-note").textContent =
      solde.sorties_depensables + " somme(s) utilisable(s) tout de suite" +
      (sync.synchronise ? "" : " — chiffre incomplet, voir l'avertissement ci-dessus");

    const total = unitesDe(solde.depensable) + unitesDe(solde.immature);
    // --- « Quand ? » : la seule question qu'on se pose devant un solde bloqué.
    //
    // La tuile annonçait une somme en attente sans jamais dire quand elle se
    // libérerait. Un mineur voyait son gain monter et son disponible rester à
    // zéro pendant des heures, sans repère : plusieurs y ont vu une panne. On
    // annonce donc le prochain déblocage, en blocs et en temps.
    const attenteNote = solde.prochaine_maturite_blocs !== undefined
      ? "prochaine libération : " + ech(solde.prochaine_maturite_montant.q21) +
        " Q21 dans " + ech(String(solde.prochaine_maturite_blocs)) + " bloc(s), soit " +
        dureeBlocs(solde.prochaine_maturite_blocs, info) + " — au bloc " +
        ech(String(solde.prochaine_maturite_hauteur))
      : "récompenses de minage : elles vous appartiennent, mais ne sont pas encore utilisables";
    document.getElementById("tuiles-solde").innerHTML =
      tuile("En attente de maturité", ech(solde.immature.q21) + " Q21", attenteNote) +
      tuile("Total détenu", ech(q21DepuisUnites(total)) + " Q21", "disponible et en attente réunis") +
      tuile("Vos adresses", solde.adresses_derivees,
            "votre portefeuille en fabrique une nouvelle à chaque encaissement") +
      tuile("Blocs vérifiés", info.hauteur,
            "votre machine les a tous recalculés elle-même — " + info.mempool +
            " transaction(s) en attente d'être inscrite(s)");
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
  // Une sortie par destinataire, plus la monnaie : les frais suivent le nombre
  // de destinataires quand l'envoi en compte plusieurs.
  const dest = 1 + document.querySelectorAll("#destinataires-plus .dest-plus").length;
  const sorties = dest + 1;
  try{
    const f = await appel("estimatefee", '{"entrees":' + entrees + ',"sorties":' + sorties + '}');
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

// Ajoute une ligne « destinataire supplémentaire ». Le gabarit est statique —
// aucune donnée n'y est interpolée — pour rester hors de portée de toute
// injection : les champs partent vides, l'utilisateur les remplit ensuite.
document.getElementById("bouton-ajouter-destinataire").addEventListener("click", () => {
  const zone = document.getElementById("destinataires-plus");
  const ligne = document.createElement("div");
  ligne.className = "dest-plus";
  ligne.style.marginTop = ".6rem";
  ligne.innerHTML =
    '<label>Adresse d\'un autre destinataire</label>'
  + '<input type="text" class="dest-adresse" placeholder="tq21…" spellcheck="false" autocomplete="off">'
  + '<label>Montant, en Q21</label>'
  + '<input type="text" class="dest-montant" placeholder="0.00000000" inputmode="decimal" spellcheck="false" autocomplete="off">'
  + '<div class="boutons"><button type="button" class="discret dest-retirer">Retirer</button></div>';
  zone.appendChild(ligne);
  ligne.querySelector(".dest-retirer").addEventListener("click", () => ligne.remove());
});

document.getElementById("forme-envoi").addEventListener("submit", async ev => {
  ev.preventDefault();
  document.getElementById("resultat-envoi").innerHTML = "";

  const refus = m => {
    document.getElementById("resultat-envoi").innerHTML =
      `<div class="avert"><h3>Envoi non préparé</h3><p>${ech(m)}</p></div>`;
  };

  // Le destinataire principal, puis les éventuels destinataires ajoutés. Un
  // seul chemin de validation pour tous : chaque montant est un entier d'unités.
  const destinations = [];
  const a0 = document.getElementById("champ-adresse").value.trim();
  const m0 = unitesDepuisQ21(document.getElementById("champ-montant").value);
  if (!a0) return refus("Aucune adresse de destination.");
  if (m0 === null) return refus("Montant illisible. Attendu : un nombre en Q21, huit décimales au maximum.");
  if (m0 <= 0n) return refus("Le montant doit être strictement positif.");
  if (m0 < 10000n) return refus("Le montant minimal est 0,0001 Q21 : en dessous, le réseau refuse la sortie comme poussière.");
  destinations.push({adresse: a0, montant: m0});

  for (const ligne of document.querySelectorAll("#destinataires-plus .dest-plus")) {
    const a = ligne.querySelector(".dest-adresse").value.trim();
    const mm = unitesDepuisQ21(ligne.querySelector(".dest-montant").value);
    if (!a) return refus("Un destinataire supplémentaire est sans adresse. Retirez la ligne ou remplissez-la.");
    if (mm === null) return refus("Un montant supplémentaire est illisible. Attendu : un nombre en Q21.");
    if (mm <= 0n) return refus("Chaque montant doit être strictement positif.");
    if (mm < 10000n) return refus("Chaque montant doit valoir au moins 0,0001 Q21 : en dessous, le réseau refuse la sortie comme poussière.");
    destinations.push({adresse: a, montant: mm});
  }

  const frais = unitesDepuisQ21(document.getElementById("champ-frais").value);
  if (frais === null) return refus("Frais illisibles. Attendu : un nombre en Q21, huit décimales au maximum.");
  if (frais < 0n) return refus("Les frais ne peuvent pas être négatifs.");

  let somme = 0n;
  for (const d of destinations) somme += d.montant;
  const total = somme + frais;

  // Le solde est relu maintenant, pas au chargement de la page : entre les
  // deux, un bloc a pu arriver.
  let depensable = null;
  try{
    depensable = unitesDe((await appel("getbalance")).depensable);
  }catch(e){
    return refus("Solde non relu, envoi interrompu : " + e.message);
  }
  if (total > depensable){
    return refus("Fonds insuffisants : " + q21DepuisUnites(total) +
                 " Q21 demandés, " + q21DepuisUnites(depensable) + " Q21 dépensables.");
  }

  const lignesRecap = destinations.map(d =>
      `<div class="l"><span class="k">Destinataire</span><span class="v">${ech(d.adresse)}</span></div>`
    + `<div class="l"><span class="k">Montant</span><span class="v">${ech(q21DepuisUnites(d.montant))} Q21</span></div>`
    ).join("");
  document.getElementById("recap").innerHTML = lignesRecap
    + `<div class="l"><span class="k">Frais</span><span class="v">${ech(q21DepuisUnites(frais))} Q21</span></div>`
    + `<div class="l total"><span class="k">Débité au total</span><span class="v">${ech(q21DepuisUnites(total))} Q21</span></div>`
    + `<div class="l"><span class="k">Solde après</span><span class="v">${ech(q21DepuisUnites(depensable - total))} Q21</span></div>`;

  // Un seul destinataire garde la forme d'origine — et le chemin sendtoaddress
  // qui va avec ; plusieurs portent la liste, envoyée par sendmany.
  if (destinations.length === 1) {
    envoiPrepare = {adresse: a0, montant: m0, frais: frais};
  } else {
    envoiPrepare = {destinations: destinations, frais: frais};
  }
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
  // affichee sur l'ecran de confirmation. Un destinataire prend sendtoaddress ;
  // plusieurs prennent sendmany, avec la meme rigueur sur chaque montant.
  let methode, params;
  if (p.destinations) {
    const items = p.destinations.map(d =>
      '{"adresse":' + JSON.stringify(d.adresse) + ',"unites":' + d.montant.toString() + '}'
    ).join(",");
    methode = "sendmany";
    params = '{"destinations":[' + items + '],"frais":' + p.frais.toString() + '}';
  } else {
    methode = "sendtoaddress";
    params = '{"adresse":' + JSON.stringify(p.adresse) +
             ',"unites":' + p.montant.toString() +
             ',"frais":' + p.frais.toString() + '}';
  }
  try{
    const r = await appel(methode, params);
    envoiPrepare = null;
    document.getElementById("confirmation").hidden = true;
    document.getElementById("forme-envoi").hidden = false;
    document.getElementById("champ-montant").value = "";
    document.getElementById("champ-adresse").value = "";
    document.getElementById("destinataires-plus").innerHTML = "";
    document.getElementById("resultat-envoi").innerHTML = `
      <div class="note">
        <h3>✓ Envoi transmis au réseau</h3>
        <p>
          Il est annoncé aux pairs et attend d'entrer dans un bloc — comptez
          l'ordre de deux minutes. Tant qu'aucun bloc ne le contient, il n'est
          <strong>pas encore confirmé</strong>.
        </p>
        <p>
          <a class="plat" href="/#/tx/${ech(r.txid)}" target="_blank" rel="noopener">Suivre
          cette transaction dans l'explorateur</a>
        </p>
        <p class="aide">Référence : <span class="coupe">${ech(r.txid)}</span> —
        ${ech(r.transaction.taille_octets)} octets.</p>
      </div>`;
    rafraichir();
    // --- Puis on emmene l'utilisateur voir sa transaction.
    //
    // Une confirmation ecrite sur l'ecran d'envoi laissait le doute entier :
    // le solde avait baisse, et l'onglet Activite — le seul endroit ou l'on
    // verifie qu'un paiement existe — restait vide jusqu'au bloc suivant. On
    // l'y conduit donc, ou la ligne est desormais deja la, marquee « en
    // attente ». Voir vaut mieux que lire qu'on aurait pu voir.
    //
    // Le delai laisse le temps de lire la carte verte avant que l'ecran ne
    // change : basculer dans la seconde donnerait l'impression d'un ecran qui
    // saute.
    setTimeout(() => montrer("historique"), 1200);
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

// L'icone d'un mouvement : trois dessins en dur, choisis par le genre que le
// nœud annonce. Un genre inconnu retombe sur la fleche de reception — un
// dessin faux serait pire qu'un dessin generique.
function iconeGenre(m){
  const g = String(m.genre);
  if (g === "minage"){
    return brut('<span class="sens mine"><svg viewBox="0 0 24 24" aria-hidden="true">' +
      '<path d="M13 2L4 14h6l-1 8 9-12h-6z"></path></svg></span>');
  }
  if (m.sorti){
    return brut('<span class="sens envoi"><svg viewBox="0 0 24 24" aria-hidden="true">' +
      '<path d="M12 20V7"></path><path d="M6 12l6-6 6 6"></path></svg></span>');
  }
  return brut('<span class="sens recu"><svg viewBox="0 0 24 24" aria-hidden="true">' +
    '<path d="M12 4v13"></path><path d="M6 12l6 6 6-6"></path></svg></span>');
}

// Le petit disque qui tourne, pour ce qui est parti mais pas encore grave.
//
// Un badge immobile disant « en attente » se lit comme un etat fige ; un
// mouvement dit « ca travaille ». C'est la difference entre patienter et
// craindre. L'animation est en CSS pur, sans image ni script : rien a charger,
// et elle s'arrete d'elle-meme quand la ligne bascule en confirmee.
function sablier(){
  return brut('<span class="tourne" aria-hidden="true"></span>');
}

// --- La reference se copie, elle ne se recopie pas a la main.
//
// Elle etait tronquee a vingt caracteres suivis de points de suspension. Pour
// la lire, c'etait assez ; pour la **porter** dans la recherche de
// l'explorateur, il en manquait quarante-quatre, et rien ne le disait. Une
// reference qu'on ne peut pas emporter ne sert a rien.
//
// L'ecoute est posee une fois sur le corps du tableau, et non sur chaque
// bouton : les lignes sont refaites a chaque rafraichissement, et des ecoutes
// posees ligne par ligne s'accumuleraient a chaque tour.
for (const zone of ["mouvements", "tuiles-chaine"]){
  document.getElementById(zone).addEventListener("click", ev => {
    const b = ev.target.closest("button.copie[data-ref]");
    if (b) copier(b.dataset.ref, b);
  });
}

// --- L'activite se rafraichit d'elle-meme, et se filtre.
//
// Deux manques signales a l'usage. Une transaction recue apparaissait « en
// attente » et **y restait** : il fallait changer d'onglet et revenir pour la
// voir confirmee. Et avec quelques dizaines de recompenses de minage, le seul
// virement de la journee se perdait au milieu.
//
// Le rafraichissement est volontairement plus lent que celui du solde : chaque
// appel fait relire des blocs au nœud, et l'activite n'a pas besoin de la
// seconde pres. Dix secondes suffisent a ce qu'une confirmation apparaisse
// « toute seule », ce qui est la seule chose qu'on demande.
let filtreActivite = "tout";
let historiqueEnCours = false;

function correspondFiltre(m){
  if (filtreActivite === "tout") return true;
  return String(m.genre) === filtreActivite;
}

async function historique(){
  // Deux tours qui se chevauchent liraient la chaine deux fois pour rien, et
  // le second ecraserait le premier a l'arrivee.
  if (historiqueEnCours) return;
  historiqueEnCours = true;
  const corps = document.getElementById("mouvements");
  const zone = document.getElementById("note-historique");
  const sous = document.getElementById("note-colonnes");
  try{
    // Les deux appels partent ensemble : l'historique, et les constantes du
    // protocole qui permettent de traduire une attente en blocs en une durée.
    const [h, infoChaine] = await Promise.all([
      appel("listtransactions", '{"limite":100}'),
      appel("getinfo")
    ]);
    const maturite = Number(infoChaine.maturite_coinbase) || 200;
    // Un historique tronque qui ne se declare pas fait croire a des fonds
    // disparus. Le noeud dit jusqu'ou il a regarde ; on le repete.
    // Un bloc de la chaîne dont le corps est illisible n'est pas la même chose
    // qu'un historique tronqué par la fenêtre de recherche : le premier est un
    // incident, le second un réglage. Les confondre a fait croire à un
    // virement disparu ; on les distingue, et on dit quoi faire.
    const illisibles = Number(h.blocs_illisibles) || 0;
    zone.innerHTML = illisibles > 0
      ? `<div class="avert"><h3>${ech(String(illisibles))} bloc(s) illisible(s) — historique incomplet</h3>
         <p>${ech(h.note)}</p>
         <p><strong>Vos fonds ne sont pas perdus</strong> : le solde reste juste.
         Fermez puis rouvrez le portefeuille&nbsp;: il redemandera ces blocs au réseau.</p></div>`
      : h.historique_complet
      ? `<div class="note"><h3>Historique complet</h3><p>${ech(h.note)}</p></div>`
      : `<div class="avert"><h3>Historique partiel</h3><p>${ech(h.note)}</p>
         <p>Recherche effectuée de la hauteur ${ech(h.regarde_depuis_hauteur)} à ${ech(h.hauteur)}. Ce qui est antérieur n'est pas affiché, et n'est pas perdu pour autant.</p></div>`;
    sous.innerHTML = notesColonnes(h);

    if (!h.mouvements.length){
      corps.innerHTML = `<tr><td colspan="7">Rien pour l'instant. Vos premiers
        mouvements apparaîtront ici — recevez du Q21 depuis l'onglet Recevoir,
        ou trouvez un bloc depuis l'onglet Miner.</td></tr>`;
      return;
    }
    const vus = h.mouvements.filter(correspondFiltre);
    if (!vus.length){
      corps.innerHTML = `<tr><td colspan="7">Aucun mouvement de ce type parmi les
        ${ech(String(h.mouvements.length))} derniers. Choisissez « Tout » pour
        les voir tous.</td></tr>`;
      return;
    }
    corps.innerHTML = vus.map(m => {
      // Trois etats, trois marques. « en attente » l'emporte sur « immature » :
      // une transaction qui n'est dans aucun bloc n'a pas encore de maturite a
      // discuter.
      // Une récompense immature dit désormais **dans combien de temps** elle
      // sera utilisable. « Immature » seul est un état, pas une information :
      // il laisse entière la question qu'on se pose en le lisant.
      let marque;
      if (m.en_attente){
        marque = ` <span class="badge attente">${rendu(sablier())} en attente</span>`;
      } else if (!m.mature){
        // Ni `Number()` ni conversion : ces deux champs sont des entiers de
        // comptage rendus par le nœud, jamais des montants. La règle « aucun
        // flottant sur un montant » reste entière, et l'épreuve qui la garde
        // interdit toute conversion numérique sur un champ de mouvement, par
        // principe — on ne la contourne pas, on n'en a pas besoin.
        const reste = maturite - m.confirmations;
        marque = ` <span class="badge attente" title="utilisable au bloc ${ech(String(m.hauteur + maturite))}">`
               + `mûrit dans ${ech(dureeBlocs(reste > 0 ? reste : 0, infoChaine))}</span>`;
      } else {
        marque = "";
      }
      // L'icone dit le sens avant que le mot soit lu ; la couleur du montant
      // le repete. Les trois dessins sont en dur, le genre choisit lequel.
      const recuQqc = BigInt(m.recu.unites) > 0n;
      return `
      <tr>
        <td>${rendu(iconeGenre(m))} ${ech(m.genre)}</td>
        <td${html(recuQqc ? ' class="plus"' : '')}>${ech(recuQqc ? "+ " + m.recu.q21 : "—")}</td>
        <td${html(m.sorti ? ' class="moins"' : '')}>${rendu(celluleSortie(m))}</td>
        <td>${ech(m.confirmations)}${html(marque)}</td>
        <td>${ech(m.en_attente ? "—" : m.hauteur)}</td>
        <td>${ech(date(m.horodatage))}</td>
        <td class="ref"><span class="entier">${ech(m.txid)}</span>
          <button type="button" class="plat copie" data-ref="${ech(m.txid)}">copier</button></td>
      </tr>`;
    }).join("");
  }catch(e){
    zone.innerHTML = `<div class="avert"><h3>Historique indisponible</h3><p>${ech(e.message)}</p></div>`;
    corps.innerHTML = "";
    sous.innerHTML = "";
  }finally{
    historiqueEnCours = false;
  }
}

// Un seul écouteur pour les quatre boutons. Le filtre ne redemande rien au
// nœud : il rejoue l'affichage sur ce qu'on a déjà, donc il est instantané.
document.getElementById("filtres-activite").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-filtre]");
  if (!b) return;
  filtreActivite = b.dataset.filtre;
  for (const autre of document.querySelectorAll("#filtres-activite button")){
    autre.classList.toggle("actif", autre === b);
  }
  historique();
});

// Tant que l'écran est visible, il se tient à jour. Caché, il ne coûte rien :
// un portefeuille ouvert sur le solde ne doit pas faire relire la chaîne.
setInterval(() => {
  if (!document.getElementById("vue-historique").hidden) historique();
}, 10000);

// ---------------------------------------------------------------------------
// Informations
// ---------------------------------------------------------------------------

async function infos(){
  try{
    const [w, info, adresses, emp] = await Promise.all([
      appel("getwalletinfo"), appel("getinfo"), appel("listaddresses"),
      appel("getempreinteutxo")
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
      tuile("Blocs vérifiés", info.hauteur) +
      // Meme raison que dans l'historique : une empreinte tronquee ne se porte
      // pas dans la recherche de l'explorateur.
      tuile("Dernier bloc", brut(
        `<span class="entier">${ech(info.tete)}</span>` +
        `<button type="button" class="plat copie" data-ref="${ech(info.tete)}">copier</button>`)) +
      tuile("Difficulté", info.difficulte_bits) +
      tuile("Q21 créés à ce jour", ech(info.emis.q21) + " Q21") +
      tuile("Sommes non dépensées", info.utxo_total, "sur toute la chaîne, tous porteurs confondus") +
      // L'empreinte de l'etat : deux noeuds a la meme hauteur la portent
      // identique. On la donne entiere, avec un bouton de copie, pour qu'elle se
      // compare a celle de l'explorateur — c'est tout son usage.
      tuile("Empreinte de l'état", brut(
        `<span class="entier">${ech(emp.empreinte)}</span>` +
        `<button type="button" class="plat copie" data-ref="${ech(emp.empreinte)}">copier</button>`),
        "engagement MuHash sur le jeu d'UTXO — identique sur tout nœud à cette hauteur") +
      tuile("Ordinateurs reliés au vôtre", info.pairs);
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

  const jauge = document.getElementById("jauge-sync");
  const cible = Number(sync.hauteur_reseau) || 1;
  const part = Math.max(0, Math.min(100, (Number(sync.hauteur) / cible) * 100));
  jauge.style.width = (sync.synchronise ? 100 : part) + "%";

  // --- Trois etats, nommes, et de couleurs distinctes.
  //
  // Un point de couleur seul n'est pas lisible par tout le monde : environ un
  // homme sur douze distingue mal le vert du rouge. Le mot porte donc l'etat,
  // la couleur ne fait que le repeter — et la zone est annoncee `aria-live`,
  // pour qu'un lecteur d'ecran signale le passage hors connexion.
  const pairs = Number(sync.pairs);
  const etat = pairs === 0 ? "hors" : (sync.synchronise ? "ok" : "sync");
  const pouls = document.getElementById("pouls");
  const pt = document.getElementById("point-sync");
  const nom = document.getElementById("pouls-etat");
  const tx = document.getElementById("pouls-texte");

  pouls.className = "pousse pouls " + etat;
  pt.className = "point " + (etat === "ok" ? "vert" : etat === "sync" ? "orange" : "rouge");
  nom.textContent = etat === "ok" ? "Connecté"
                  : etat === "sync" ? "Synchronisation"
                  : "Hors connexion";
  tx.textContent = etat === "ok"
    ? "· " + pairs + " pair(s) · bloc " + sync.hauteur
    : etat === "sync"
      ? "· " + sync.blocs_restants + " bloc(s) restants"
      : "· aucun ordinateur joignable";

  // --- Le rythme se dit dans l'unite ou on le vit.
  //
  // Cette tuile annoncait « blocs reçus par seconde ». Sur une chaine en bonne
  // sante, un bloc toutes les deux minutes fait 0,008 par seconde : elle
  // affichait donc « 0 » en permanence, et deux utilisateurs y ont lu que leur
  // machine ne recevait rien alors que tout allait bien. Un chiffre qui vaut
  // toujours zero n'informe pas, il inquiete.
  //
  // On affiche donc la **cadence** — un bloc toutes les tant de minutes —, qui
  // est la grandeur que le protocole vise et que l'œil compare d'un coup. Le
  // rattrapage garde les blocs par seconde : la, ils se comptent par dizaines
  // et c'est bien l'unite utile.
  const v = document.getElementById("vitesse-sync");
  const vn = document.getElementById("vitesse-note");
  if (v){
    if (vitesseBlocs >= 1){
      v.textContent = vitesseBlocs.toFixed(1) + " blocs/s";
      if (vn) vn.textContent = "rattrapage en cours";
    } else if (vitesseBlocs > 0.0005){
      const min = 1 / (vitesseBlocs * 60);
      v.textContent = "1 bloc / " + (min < 10 ? min.toFixed(1) : Math.round(min)) + " min";
      if (vn) vn.textContent = "cadence observée — cible : 2 minutes";
    } else {
      v.textContent = "—";
      if (vn) vn.textContent = "aucun bloc depuis le lancement de cet écran";
    }
  }
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
  document.getElementById("minage-gagne").textContent =
    (etat.gagne ? etat.gagne.q21 : "0.00000000") + " Q21";
  // La mémoire est ce qui fait tout l'intérêt de cette preuve de travail :
  // une machine spécialisée ne sert à rien face à une table qui doit tenir en
  // mémoire vive, et qui grossit avec le temps. Le chiffre méritait un écran.
  document.getElementById("minage-memoire").textContent = octets(etat.memoire_octets);
  document.getElementById("minage-memoire-note").textContent =
    "table de l'époque " + ech(String(etat.memoire_epoque)) +
    " — elle grandit de 5 % tous les 71 jours";
  peindreTrouves(etat.trouves || [], Number(etat.blocs_trouves) || 0);
  HISTO_DEBIT.push(Number(etat.essais_par_seconde) || 0);
  while (HISTO_DEBIT.length > 60) HISTO_DEBIT.shift();
  courbe(HISTO_DEBIT);
}

// Le journal des blocs trouves. Chaque ligne : quel bloc, quand, combien —
// et la hauteur est un lien vers l'explorateur, servi par le meme nœud sur le
// meme port. Le pic de mineur est un dessin en dur ; tout ce qui vient du
// nœud passe par `ech`.
let dernierTrouve = null;

function quandCourt(ts){
  const d = new Date(Number(ts) * 1000);
  return d.toLocaleDateString(q21Locale()) + " " + d.toLocaleTimeString(q21Locale(),
    {hour: "2-digit", minute: "2-digit"});
}

function peindreTrouves(liste, total){
  const zone = document.getElementById("minage-trouves");
  if (!liste.length){
    zone.innerHTML = '<div class="note"><p>Aucun bloc trouvé pour l\'instant. ' +
      'C\'est une loterie : le bouton ci-dessus achète des tentatives, la ' +
      'chance décide du moment.</p></div>';
    dernierTrouve = null;
    return;
  }
  const pic = '<svg viewBox="0 0 24 24" aria-hidden="true">' +
    '<path d="M13 2L4 14h6l-1 8 9-12h-6z"></path></svg>';
  const lignes = liste.map((t, i) => {
    const neuve = i === 0 && dernierTrouve !== null &&
      String(t.hauteur) !== dernierTrouve ? " neuve" : "";
    return '<div class="trouvaille' + neuve + '">' +
      '<span class="pic">' + pic + '</span>' +
      '<span class="quoi">' +
        '<a href="/#/bloc/' + ech(String(t.hauteur)) + '" target="_blank" rel="noopener">' +
          'Bloc ' + ech(String(t.hauteur)) + '</a>' +
        '<div class="quand">' + ech(quandCourt(t.horodatage)) + '</div>' +
      '</span>' +
      '<span class="gain">+ ' + ech(t.recompense.q21) + ' Q21</span>' +
      '</div>';
  });
  if (total > liste.length){
    lignes.push('<p class="aide">' + ech(String(total - liste.length)) +
      ' trouvaille(s) plus ancienne(s) — toutes comptées dans le total gagné.</p>');
  }
  zone.innerHTML = lignes.join("");
  dernierTrouve = String(liste[0].hauteur);
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
// Le reseau
// ---------------------------------------------------------------------------
//
// Cette vue ne repond pas a « combien de mineurs ? » : personne ne le peut, et
// Q21 moins que d'autres puisque le mineur change d'adresse a chaque bloc. Elle
// repond a « combien de travail le reseau depense-t-il », qui se mesure, puis
// le traduit en machines equivalentes — une division, presentee comme telle.

function formatDebitLong(n){
  n = Number(n) || 0;
  if (n >= 1e12) return (n / 1e12).toFixed(2) + " T";
  if (n >= 1e9)  return (n / 1e9).toFixed(2) + " G";
  if (n >= 1e6)  return (n / 1e6).toFixed(2) + " M";
  if (n >= 1e3)  return (n / 1e3).toFixed(1) + " k";
  return String(Math.round(n));
}

// Duree restante, a partir de la vitesse mesuree. Aucune estimation n'est
// donnee tant que la vitesse ne l'est pas : « calcul en cours » vaut mieux
// qu'un nombre tire d'un echantillon d'une seconde.
function resteEnTemps(blocs){
  if (!(vitesseBlocs > 0.05) || !(blocs > 0)) return "durée inconnue";
  const sec = blocs / vitesseBlocs;
  if (sec < 90) return "environ " + Math.round(sec) + " s";
  if (sec < 5400) return "environ " + Math.round(sec / 60) + " min";
  return "environ " + (sec / 3600).toFixed(1) + " h";
}

function duree(sec){
  sec = Number(sec) || 0;
  if (sec >= 86400) return (sec / 86400).toFixed(1) + " jour(s)";
  if (sec >= 3600)  return (sec / 3600).toFixed(1) + " heure(s)";
  if (sec >= 60)    return Math.round(sec / 60) + " minute(s)";
  return Math.round(sec) + " seconde(s)";
}

async function reseau(){
  try{
    const r = await appel("getreseau");
    document.getElementById("reseau-pairs").textContent = String(r.pairs);
    document.getElementById("reseau-carnet").textContent = String(r.carnet);
    document.getElementById("reseau-fenetre").textContent =
      String(r.blocs_examines) + " blocs";

    // Ce que fait *votre* machine, a cote de ce que fait le reseau. Les deux
    // chiffres cote a cote repondent a la question qu'on se pose vraiment :
    // « quelle part est la mienne ». Le minage eteint, on ne l'invente pas.
    let mien = 0;
    try { mien = Number((await appel("getminage")).essais_par_seconde) || 0; } catch (e) { mien = 0; }
    document.getElementById("reseau-mien").textContent =
      mien > 0 ? formatDebitLong(mien) + " tentatives/s" : "à l'arrêt";

    if (!r.mesurable){
      document.getElementById("reseau-gros").innerHTML =
        '<span class="gros">—</span>';
      document.getElementById("reseau-note").textContent =
        "Pas encore assez de blocs pour mesurer quoi que ce soit. " +
        "Il en faut au moins deux, séparés dans le temps.";
      document.getElementById("reseau-equiv").textContent = "—";
      document.getElementById("reseau-part").textContent =
        "le réseau n'est pas encore mesurable";
      return;
    }

    // `debit_reseau` arrive en chaine : il peut depasser ce qu'un Number
    // represente exactement. On l'affiche depuis la chaine, et l'on ne convertit
    // que pour la division en machines equivalentes, ou l'ordre de grandeur
    // suffit et ou l'on annonce d'ailleurs un « environ ».
    // Le nœud rend des milliemes : sous une unite de travail par seconde, une
    // division entiere aurait rendu zero, et zero se lit « reseau arrete ».
    const debit = Number(r.debit_reseau_milli) / 1000;
    document.getElementById("reseau-gros").innerHTML =
      '<span class="gros">' + ech(formatDebitLong(debit)) + '</span>' +
      '<span class="unite">tentatives/s</span>';
    document.getElementById("reseau-note").textContent =
      "Mesuré sur " + r.blocs_examines + " bloc(s), soit " + duree(r.secondes_examinees) +
      " de chaîne. Ce chiffre ne se déclare pas : il se déduit du travail " +
      "réellement dépensé pour les produire.";

    // L'equivalence en machines : le debit du reseau divise par celui de la
    // votre. Sans mesure locale — le minage est eteint — on ne l'invente pas.
    const eq = document.getElementById("reseau-equiv");
    const part = document.getElementById("reseau-part");
    if (mien > 0 && debit > 0){
      const n = debit / mien;
      eq.textContent = n < 1.5 ? "environ 1" : "environ " + formatDebitLong(n);
      // La part se calcule sur la mesure de l'instant chez vous, contre une
      // moyenne du reseau sur une fenetre de blocs : elle peut donc depasser
      // cent pour cent quand vous venez d'allumer, le temps que la fenetre
      // rattrape. On l'ecrete a cent plutot que d'afficher une absurdite.
      const p = Math.min(100, Math.round((mien / debit) * 100));
      part.textContent = "soit environ " + p + " % du réseau";
    } else {
      eq.textContent = "—";
      part.textContent = "allumez le minage pour vous situer";
    }
  }catch(e){ /* la boucle generale signale deja une panne du nœud */ }
}

// La vue du reseau se rafraichit au meme rythme que celle du minage tant
// qu'elle est visible.
setInterval(() => {
  if (!document.getElementById("vue-reseau").hidden) reseau();
}, 4000);

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

// --- Le carnet.
//
// Q21 pousse a donner une adresse differente a chaque correspondant : c'est ce
// qui empeche de relier les paiements entre eux. Le prix a payer se voit au
// bout d'un mois — quatre cents suites de caracteres, et aucune idee de qui est
// qui. Trois choses le rendent : un nom libre par adresse, une recherche, et de
// quoi remonter au-dela des vingt-cinq dernieres.
//
// La liste complete est gardee ici plutot que redemandee a chaque frappe : le
// nœud derive les adresses, et rappeler quatre cents derivations a chaque
// lettre tapee rendrait la recherche poussive.
let carnet = [];
let carnetMontrees = ADRESSES_MONTREES;
let carnetFiltre = "";

async function listerAdresses(){
  const zone = document.getElementById("liste-adresses");
  try{
    const r = await appel("listaddresses");
    const liste = Array.isArray(r) ? r : (r.adresses || []);
    // Les plus recentes en tete : c'est celle qu'on vient de creer qu'on cherche.
    carnet = liste.slice().reverse();
    rendreCarnet();
  }catch(e){
    zone.innerHTML = '<div class="avert"><p>' + ech(e.message) + '</p></div>';
  }
}

// Une adresse correspond a la recherche par son nom, son numero ou un morceau
// de son adresse. Le numero se cherche aussi bien « 12 » que « #12 » : on ne
// fait pas deviner a l'utilisateur la forme attendue.
function correspond(e, f){
  if (!f) return true;
  const nom = String(e.etiquette || "").toLowerCase();
  const adr = String(e.adresse || "").toLowerCase();
  const num = String(e.indice);
  return nom.includes(f) || adr.includes(f) || num === f || ("#" + num) === f;
}

function rendreCarnet(){
  const zone = document.getElementById("liste-adresses");
  const compte = document.getElementById("compte-adresses");
  const plus = document.getElementById("zone-plus");
  if (!carnet.length){
    zone.innerHTML = '<div class="note"><p>Aucune adresse encore dérivée. ' +
      'Le bouton ci-dessus en crée une.</p></div>';
    compte.textContent = "";
    plus.hidden = true;
    return;
  }
  const f = carnetFiltre.trim().toLowerCase();
  const vues = carnet.filter(e => correspond(e, f));
  if (!vues.length){
    zone.innerHTML = '<div class="note"><p>Aucune adresse ne correspond à ' +
      '« ' + ech(carnetFiltre.trim()) + ' ». Vos ' + ech(String(carnet.length)) +
      ' adresses restent toutes valides.</p></div>';
    compte.textContent = "";
    plus.hidden = true;
    return;
  }
  const tranche = vues.slice(0, carnetMontrees);
  zone.innerHTML = tranche.map(e => {
    const a = String(e.adresse);
    const indice = String(e.indice);
    const nom = e.etiquette ? ech(String(e.etiquette)) : "sans nom";
    return '<div class="adresse">' +
      '<span class="rang">#' + ech(indice) + '</span>' +
      '<span class="corps">' +
        '<span class="nom' + (e.etiquette ? '' : ' vide') + '">' + nom + '</span>' +
        '<span class="txt">' + ech(a) + '</span>' +
      '</span>' +
      (e.consommee ? '<span class="badge gris">servie</span>' : '') +
      '<button type="button" class="plat" data-copier="' + ech(a) + '">Copier</button>' +
      '<button type="button" class="plat" data-nommer="' + ech(indice) + '">' +
        (e.etiquette ? 'Renommer' : 'Nommer') + '</button>' +
      '<span class="edition" hidden data-edition="' + ech(indice) + '">' +
        '<input type="text" maxlength="64" value="' + ech(String(e.etiquette || "")) + '" ' +
        'placeholder="pour qui, ou pourquoi — visible de vous seul">' +
        '<button type="button" class="action" data-enregistrer="' + ech(indice) + '">Enregistrer</button>' +
      '</span>' +
      '</div>';
  }).join("");
  compte.textContent = f
    ? vues.length + " adresse(s) trouvée(s) sur " + carnet.length
    : carnet.length + " adresse(s) au total";
  plus.hidden = vues.length <= tranche.length;
}

document.getElementById("filtre-adresses").addEventListener("input", ev => {
  carnetFiltre = ev.target.value;
  // Une recherche repart du debut : garder une pagination heritee de la
  // recherche precedente ferait disparaitre des resultats sans raison visible.
  carnetMontrees = ADRESSES_MONTREES;
  rendreCarnet();
});

document.getElementById("bouton-plus").addEventListener("click", () => {
  carnetMontrees += ADRESSES_MONTREES;
  rendreCarnet();
});

// Un seul ecouteur pour toute la liste : attacher un gestionnaire par ligne
// laisse des fuites a chaque rafraichissement.
document.getElementById("liste-adresses").addEventListener("click", async ev => {
  const c = ev.target.closest("button[data-copier]");
  if (c){ copier(c.dataset.copier, c); return; }

  const n = ev.target.closest("button[data-nommer]");
  if (n){
    const z = document.querySelector('[data-edition="' + n.dataset.nommer + '"]');
    if (z){ z.hidden = !z.hidden; if (!z.hidden) z.querySelector("input").focus(); }
    return;
  }

  const s = ev.target.closest("button[data-enregistrer]");
  if (s){
    const indice = s.dataset.enregistrer;
    const z = document.querySelector('[data-edition="' + indice + '"]');
    const texte = z ? z.querySelector("input").value : "";
    s.disabled = true;
    try{
      await appel("setaddresslabel",
        '{"indice":' + Number(indice) + ',"etiquette":' + JSON.stringify(texte) + '}');
      // On relit le carnet plutot que de corriger la ligne a la main : le nœud
      // a pu tailler le texte, et l'ecran doit montrer ce qui est enregistre,
      // pas ce qui a ete tape.
      await listerAdresses();
    }catch(e){
      signalerErreur("Nom non enregistré : " + e.message);
      s.disabled = false;
    }
  }
});

// Entree vaut Enregistrer : personne ne va chercher le bouton a la souris
// apres avoir tape un nom.
document.getElementById("liste-adresses").addEventListener("keydown", ev => {
  if (ev.key !== "Enter") return;
  const z = ev.target.closest("[data-edition]");
  if (!z) return;
  ev.preventDefault();
  z.querySelector("button[data-enregistrer]").click();
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
            "unites",
            "q21",
            "solde",
            "montant",
            "frais",
            "depensable",
            "immature",
            "recu",
        ];
        // Le mot doit etre un mot, pas une sous-chaine : « recu » se cache dans
        // « recuperation », et l'epreuve refusait une barre de progression au
        // motif qu'elle parlait d'argent.
        fn contient_mot(ligne: &str, mot: &str) -> bool {
            let borne = |c: char| !c.is_alphanumeric() && c != '_';
            let mut depuis = 0;
            while let Some(i) = ligne[depuis..].find(mot) {
                let d = depuis + i;
                let f = d + mot.len();
                let avant = ligne[..d].chars().next_back().is_none_or(borne);
                let apres = ligne[f..].chars().next().is_none_or(borne);
                if avant && apres {
                    return true;
                }
                depuis = d + 1;
            }
            false
        }

        let mut vus = 0;
        for (n, ligne) in s.lines().enumerate() {
            if !ligne.contains("toFixed") {
                continue;
            }
            vus += 1;
            let bas = ligne.to_lowercase();
            for mot in MONNAIE {
                assert!(
                    !contient_mot(&bas, mot),
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

    /// L'etat de connexion se lit sans distinguer les couleurs.
    ///
    /// Environ un homme sur douze distingue mal le vert du rouge. Un point de
    /// couleur seul ne dit donc rien a tout le monde ; le mot porte l'etat, la
    /// couleur ne fait que le repeter.
    #[test]
    fn l_etat_de_connexion_est_ecrit_en_toutes_lettres() {
        let s = script();
        for mot in ["\"Connecté\"", "\"Synchronisation\"", "\"Hors connexion\""] {
            assert!(s.contains(mot), "etat sans nom : {mot}");
        }
        // Les trois etats mènent a trois couleurs distinctes, et rouge existe.
        for classe in ["vert", "orange", "rouge"] {
            assert!(
                PAGE.contains(&format!(".point.{classe}{{")),
                "couleur absente de la feuille de style : {classe}"
            );
        }
        // La zone est annoncee : un passage hors connexion doit se dire, pas
        // seulement se voir.
        assert!(PAGE.contains(r#"role="status" aria-live="polite""#));
        // Et l'etat vient du nombre de pairs, pas d'une supposition.
        assert!(s.contains("const pairs = Number(sync.pairs);"));
        assert!(s.contains(r#"pairs === 0 ? "hors""#));
    }

    /// La recuperation de la chaine se montre, avec une progression reelle.
    #[test]
    fn la_recuperation_de_la_chaine_se_voit() {
        let s = script();
        assert!(PAGE.contains("Récupération de l'historique de la chaîne"));
        assert!(
            PAGE.contains(r#"class="rotor""#),
            "rien ne tourne pendant l'attente"
        );
        // La barre suit la hauteur reelle, elle n'est pas decorative.
        assert!(s.contains(r#"document.getElementById("recup-barre").style.width"#));
        assert!(s.contains("(ici / la) * 100"));
        // Sans vitesse mesuree, aucune duree n'est annoncee.
        assert!(
            s.contains(r#"return "durée inconnue""#),
            "une duree est annoncee avant d'avoir ete mesuree"
        );
        // Le cas « personne a qui demander » a son propre titre : une barre qui
        // n'avance pas sans explication se lit comme une panne.
        assert!(PAGE.contains("En attente d'un ordinateur à qui demander la chaîne"));
    }

    /// La page ne pretend jamais savoir qu'une restauration est en cours.
    ///
    /// Le nœud ne le sait pas. La ligne qui s'adresse a qui vient de restaurer
    /// est donc formulee en condition, et elle reste vraie dans les deux cas.
    #[test]
    fn la_restauration_est_evoquee_sans_etre_affirmee() {
        assert!(PAGE.contains("Si vous venez de restaurer un portefeuille"));
        assert!(
            !PAGE.contains("Restauration en cours") || PAGE.contains("Si vous venez de"),
            "la page affirme une restauration qu'elle ne peut pas constater"
        );
        // Elle ne s'adresse qu'a un portefeuille qui n'a presque rien derive.
        assert!(script().contains("Number(solde.adresses_derivees) > 2"));
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
        assert!(PAGE.contains("<th>Envoyé</th>"));
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
            .find("<thead><tr><th>Quoi</th>")
            .expect("entete de l'historique");
        let fin = PAGE[entete..].find("</tr>").expect("fin de l'entete");
        assert_eq!(PAGE[entete..entete + fin].matches("<th>").count(), 7);
        assert!(PAGE.contains(r#"colspan="7""#));
    }

    /// Un envoi se voit sur-le-champ, et se dit non confirme.
    ///
    /// Le silence entre l'envoi et le bloc etait le pire moment du
    /// portefeuille : le solde baissait, l'activite restait vide, et
    /// l'utilisateur croyait son argent perdu. Trois choses le comblent, et
    /// cette epreuve les fige : la ligne porte une marque « en attente », un
    /// disque tourne pour dire que ca travaille, et la hauteur reste un tiret
    /// plutot qu'un zero qui designerait le bloc de genese.
    #[test]
    fn une_transaction_en_attente_se_voit_et_se_dit_non_confirmee() {
        assert!(
            PAGE.contains("m.en_attente"),
            "l'historique ignore le reservoir"
        );
        assert!(
            PAGE.contains("en attente</span>"),
            "pas de marque « en attente »"
        );
        assert!(
            PAGE.contains("function sablier()"),
            "aucun indicateur de progression"
        );
        assert!(PAGE.contains(".tourne{"), "le disque n'a pas de style");
        assert!(
            PAGE.contains("@keyframes tourner"),
            "le disque ne tourne pas"
        );
        // Une animation permanente doit pouvoir etre desactivee : c'est une
        // exigence d'accessibilite, pas une preference.
        assert!(
            PAGE.contains("prefers-reduced-motion"),
            "l'animation ne respecte pas le reglage systeme"
        );
        // La hauteur d'une transaction qui n'est dans aucun bloc n'existe pas.
        assert!(
            PAGE.contains(r#"ech(m.en_attente ? "—" : m.hauteur)"#),
            "une transaction en attente afficherait une hauteur qu'elle n'a pas"
        );
    }

    /// La memoire du minage est affichee : c'est tout l'interet du procede.
    ///
    /// Q21 mine avec une table qui doit tenir en memoire vive et qui grandit de
    /// 5 % toutes les 71 journees. C'est elle qui rend une machine specialisee
    /// sans interet — on ne grave pas de la memoire. Ne pas l'afficher revenait
    /// a cacher la seule grandeur qui explique pourquoi ce minage reste a la
    /// portee de tous.
    #[test]
    fn l_ecran_de_minage_montre_la_memoire_occupee() {
        assert!(PAGE.contains("Mémoire occupée"), "tuile de memoire absente");
        assert!(PAGE.contains("minage-memoire"), "valeur de memoire absente");
        assert!(
            PAGE.contains("etat.memoire_octets"),
            "la memoire n'est pas lue depuis le nœud"
        );
        // En gibioctets, pas en gigaoctets : c'est ainsi qu'une barrette de
        // memoire se compte.
        assert!(
            PAGE.contains("Gio"),
            "l'unite de memoire n'est pas la bonne"
        );
        assert!(
            PAGE.contains("tous les 71 jours"),
            "rien ne dit que la table grandit"
        );
    }

    /// L'activite se filtre, et se tient a jour toute seule.
    ///
    /// Deux manques signales a l'usage. Une transaction recue apparaissait
    /// « en attente » et **y restait** : il fallait changer d'onglet et revenir
    /// pour la voir confirmee. Et avec quelques dizaines de recompenses de
    /// minage, le seul virement de la journee se perdait au milieu.
    #[test]
    fn l_activite_se_filtre_et_se_rafraichit_seule() {
        for attendu in [
            "filtres-activite",
            r#"data-filtre="minage""#,
            r#"data-filtre="reception""#,
            r#"data-filtre="envoi""#,
            "function correspondFiltre(",
        ] {
            assert!(
                PAGE.contains(attendu),
                "element de filtre absent : {attendu}"
            );
        }
        // Le rafraichissement ne tourne que si l'ecran est visible : un
        // portefeuille ouvert sur le solde ne doit pas faire relire la chaine.
        assert!(
            PAGE.contains(
                r#"if (!document.getElementById("vue-historique").hidden) historique();"#
            ),
            "l'activite se rafraichit meme cachee, ou pas du tout"
        );
        // Deux tours qui se chevauchent liraient la chaine deux fois pour rien.
        assert!(
            PAGE.contains("if (historiqueEnCours) return;"),
            "rien n'empeche deux lectures simultanees"
        );
        // Le filtre ne redemande rien au nœud : il rejoue l'affichage.
        assert!(PAGE.contains("h.mouvements.filter(correspondFiltre)"));
    }

    /// Une somme immature dit **quand** elle se liberera.
    ///
    /// # Ce que l'absence de cette reponse a coute
    ///
    /// La tuile annoncait « en attente de maturite : 3,05 Q21 » et s'arretait
    /// la. Un mineur voyait donc son gain monter pendant une demi-heure et son
    /// solde disponible rester a zero, sans le moindre reperage temporel. La
    /// question qu'on se pose devant un solde bloque n'est pas « combien »,
    /// c'est « quand » — et la page n'y repondait pas.
    #[test]
    fn une_somme_immature_annonce_sa_date_de_liberation() {
        assert!(
            PAGE.contains("prochaine_maturite_blocs"),
            "le solde ne lit pas la prochaine liberation"
        );
        assert!(
            PAGE.contains("prochaine libération"),
            "le solde ne l'annonce pas"
        );
        assert!(
            PAGE.contains("mûrit dans"),
            "l'historique n'annonce pas l'echeance"
        );
        assert!(
            PAGE.contains("function dureeBlocs("),
            "aucune traduction des blocs en temps"
        );
        // L'intervalle vient du nœud : le recopier dans la page le figerait a
        // la main, et le ferait mentir le jour ou il changerait.
        assert!(
            PAGE.contains("info.intervalle_cible_secondes"),
            "l'intervalle de bloc est recopie au lieu d'etre demande"
        );
        assert!(
            PAGE.contains("infoChaine.maturite_coinbase"),
            "la maturite est recopiee au lieu d'etre demandee"
        );
    }

    /// Le rythme de la chaine ne s'affiche pas dans une unite ou il vaut zero.
    ///
    /// La tuile annoncait « blocs reçus par seconde ». Un bloc toutes les deux
    /// minutes fait 0,008 par seconde : elle affichait donc « 0 » en
    /// permanence, sur un reseau parfaitement sain. Deux utilisateurs y ont lu
    /// que leur machine ne recevait rien. Un chiffre qui vaut toujours zero
    /// n'informe pas, il inquiete.
    #[test]
    fn le_rythme_de_la_chaine_se_dit_en_minutes_par_bloc() {
        assert!(
            PAGE.contains("Rythme de la chaîne"),
            "la tuile n'est pas renommee"
        );
        assert!(
            PAGE.contains(r#""1 bloc / ""#),
            "la cadence ne s'exprime pas en minutes par bloc"
        );
        assert!(
            !PAGE.contains("par seconde, depuis le réseau"),
            "l'ancienne unite, toujours nulle, est encore la"
        );
        // Le rattrapage garde les blocs par seconde : la, ils se comptent par
        // dizaines et c'est l'unite utile.
        assert!(PAGE.contains("rattrapage en cours"));
        assert!(PAGE.contains("cible : 2 minutes"));
    }

    /// Un bloc illisible se signale, et se distingue d'un historique tronque.
    ///
    /// Les confondre a fait croire a un virement disparu : l'un est un
    /// incident a reparer, l'autre un reglage sans consequence.
    #[test]
    fn un_bloc_illisible_ne_se_confond_pas_avec_une_fenetre_trop_courte() {
        assert!(PAGE.contains("blocs_illisibles"), "le compte n'est pas lu");
        assert!(
            PAGE.contains("historique incomplet"),
            "l'incident n'est pas nomme"
        );
        assert!(
            PAGE.contains("Vos fonds ne sont pas perdus"),
            "rien ne rassure sur le point qui compte"
        );
        assert!(
            PAGE.contains("redemandera ces blocs au réseau"),
            "rien ne dit quoi faire"
        );
    }

    /// Le carnet : chercher, nommer, et remonter au-dela des dernieres.
    ///
    /// Avec quatre cents adresses derivees, une liste tronquee aux vingt-cinq
    /// plus recentes n'est plus une liste : c'est un mur. Trois choses la
    /// rouvrent, et cette epreuve les fige.
    #[test]
    fn le_carnet_se_cherche_se_nomme_et_se_deroule() {
        for attendu in [
            "filtre-adresses",
            "Chercher dans votre carnet",
            "bouton-plus",
            "Afficher les suivantes",
            "function correspond(",
            "function rendreCarnet(",
            "data-nommer=",
            "data-enregistrer=",
            "setaddresslabel",
        ] {
            assert!(
                PAGE.contains(attendu),
                "element du carnet absent : {attendu}"
            );
        }
        // Le numero se cherche aussi bien « 12 » que « #12 » : on ne fait pas
        // deviner a l'utilisateur la forme attendue.
        assert!(
            PAGE.contains(r##"("#" + num) === f"##),
            "le numero ne se cherche pas avec son diese"
        );
        // Une nouvelle recherche repart du debut : garder la pagination de la
        // precedente ferait disparaitre des resultats sans raison visible.
        assert!(
            PAGE.contains("carnetMontrees = ADRESSES_MONTREES;"),
            "la pagination ne se remet pas a zero quand la recherche change"
        );
        // Le nom est local : la page doit le dire, sinon on croira qu'il
        // accompagne le paiement.
        assert!(
            PAGE.contains("visible de vous seul"),
            "rien ne dit que le nom reste sur cette machine"
        );
        // Une seule ecoute pour toute la liste : les lignes sont refaites a
        // chaque rafraichissement.
        assert!(PAGE.contains(r#"document.getElementById("liste-adresses").addEventListener"#));
    }

    /// Une reference s'affiche entiere, et se copie d'un clic.
    ///
    /// Elle etait tronquee a vingt caracteres. Assez pour la reconnaitre, pas
    /// pour la porter dans la recherche de l'explorateur — et rien ne
    /// signalait qu'il en manquait quarante-quatre.
    #[test]
    fn une_reference_est_entiere_et_copiable() {
        assert!(
            PAGE.contains("${ech(m.txid)}"),
            "la reference de l'historique est encore tronquee"
        );
        assert!(
            !PAGE.contains("court(m.txid"),
            "l'historique coupe encore la reference"
        );
        assert!(
            !PAGE.contains("court(info.tete"),
            "l'empreinte du dernier bloc est encore coupee"
        );
        assert!(
            PAGE.contains(r#"button.copie[data-ref]"#),
            "aucun bouton de copie"
        );
        assert!(
            PAGE.contains("td.ref{"),
            "la colonne des references n'a pas de style"
        );
        // Le tableau interdit le retour a la ligne partout ailleurs : sans
        // derogation explicite, une empreinte entiere pousserait les autres
        // colonnes hors de l'ecran.
        assert!(
            PAGE.contains("white-space:normal;word-break:break-all"),
            "l'empreinte ne peut pas revenir a la ligne"
        );
        // L'ecoute est posee une fois sur le conteneur, pas par ligne : les
        // lignes sont refaites a chaque rafraichissement.
        assert!(
            PAGE.contains(r#"for (const zone of ["mouvements", "tuiles-chaine"])"#),
            "les ecoutes de copie s'accumuleraient a chaque rafraichissement"
        );
    }

    /// Apres un envoi, on conduit l'utilisateur a sa transaction.
    #[test]
    fn l_envoi_reussi_emmene_vers_l_activite() {
        assert!(
            PAGE.contains(r#"montrer("historique")"#),
            "l'envoi ne bascule pas vers l'activite"
        );
    }

    /// La page du reseau situe la machine de l'utilisateur dans l'ensemble.
    ///
    /// « Puissance du reseau » seule ne repond pas a la question qu'on se pose,
    /// qui est « quelle part est la mienne ». Les deux chiffres cote a cote y
    /// repondent d'un coup d'œil.
    #[test]
    fn la_page_reseau_montre_la_machine_et_l_ensemble() {
        for attendu in [
            "Votre machine",
            "reseau-mien",
            "reseau-part",
            "Machines connues du réseau",
            "reseau-carnet",
            "Ordinateurs reliés au vôtre",
        ] {
            assert!(PAGE.contains(attendu), "tuile absente : {attendu}");
        }
        // Le carnet est une liste d'adresses apprises, pas un decompte du
        // reseau, et la page doit le dire — sinon elle ment par raccourci.
        assert!(
            PAGE.contains("adresses apprises, présentes ou passées"),
            "le carnet est presente comme un decompte du reseau"
        );
        // Le refus de compter les mineurs, lui, ne bouge pas.
        assert!(PAGE.contains("Pourquoi on ne vous dit pas"));
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

    /// Les sept vues existent, et le minage comme le reseau en font partie.
    ///
    /// L'epreuve precedente en comptait cinq. Elle a ete elargie, pas
    /// remplacee : une vue qui disparait est une regression, une vue qui
    /// s'ajoute doit etre declaree ici.
    #[test]
    fn les_sept_vues_existent() {
        for v in [
            "solde",
            "miner",
            "recevoir",
            "reseau",
            "envoyer",
            "historique",
            "infos",
        ] {
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
            script().contains(r#"const VUES = ["solde","miner","recevoir","reseau","envoyer","historique","infos"];"#),
            "la liste des vues du script ne correspond pas au balisage"
        );
    }

    /// Le minage se commande, et rien d'autre ne peut le commander.
    #[test]
    fn le_minage_se_commande_depuis_la_page() {
        let s = script();
        assert!(
            s.contains(r#"appel("setminage", {actif: vers})"#),
            "pas de bascule"
        );
        assert!(s.contains(r#"appel("getminage")"#), "pas de lecture d'etat");
        // Le bouton reflete l'etat rendu par le nœud, jamais l'etat suppose :
        // afficher « actif » sur la foi d'un clic ferait mentir la page si le
        // nœud refusait.
        assert!(
            s.contains("peindreMinage(await appel(\"setminage\""),
            "l'affichage du minage ne suit pas la reponse du nœud"
        );
        // Un nœud sans portefeuille ne peut pas miner : le bouton se desactive.
        assert!(
            s.contains("b.disabled = !etat.possible"),
            "bouton toujours actif"
        );
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
            assert!(
                !corps.contains(interdit),
                "valeur non numerique dans la courbe : {interdit}"
            );
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
        let d = s
            .find("function rendreCarnet(")
            .expect("la fonction de rendu");
        let f = s[d..].find("\n}").expect("sa fin") + d;
        let corps = &s[d..f];
        // Deux fois : dans le texte visible, et dans l'attribut du bouton de
        // copie. Un attribut mal ferme est une injection au meme titre qu'un
        // element.
        assert_eq!(
            corps.matches("ech(a)").count(),
            2,
            "une adresse entre dans la page sans passer par ech"
        );
        assert!(
            corps.contains("const a = String(e.adresse)"),
            "l'adresse doit etre convertie en chaine avant d'etre echappee"
        );
        // Le nom vient de l'utilisateur, mais il a pu etre saisi ailleurs — un
        // portefeuille restaure, un fichier recopie. Il s'echappe comme tout le
        // reste, dans le texte et dans la valeur du champ.
        assert!(
            corps.contains("ech(String(e.etiquette))"),
            "une etiquette entre dans le texte sans echappement"
        );
        assert!(
            corps.contains(r#"ech(String(e.etiquette || ""))"#),
            "une etiquette entre dans un attribut sans echappement"
        );
        let dl = s
            .find("async function listerAdresses(")
            .expect("la fonction de chargement");
        let fl = s[dl..].find("\n}").expect("sa fin") + dl;
        assert!(
            s[dl..fl].contains("ech(e.message)"),
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

    /// La vue du reseau ne pretend jamais compter les mineurs.
    ///
    /// C'est une propriete de fond, pas de presentation : un chiffre invente
    /// serait pire qu'une absence de chiffre, et la tentation reviendra.
    #[test]
    fn la_vue_du_reseau_ne_compte_pas_les_mineurs() {
        let s = script();
        assert!(
            s.contains(r#"appel("getreseau")"#),
            "la vue n'interroge pas le nœud"
        );
        // Aucune tuile ne doit s'intituler « mineurs » : la seule traduction
        // offerte est une equivalence en machines, et elle est nommee ainsi.
        assert!(
            PAGE.contains("Machines comme la vôtre"),
            "l'equivalence n'est pas presentee comme telle"
        );
        assert!(
            PAGE.contains("équivalence, pas un décompte"),
            "l'equivalence n'avoue pas qu'elle n'est pas un compte"
        );
        assert!(
            PAGE.contains("Pourquoi on ne vous dit pas"),
            "la page ne dit pas pourquoi elle ne compte pas les mineurs"
        );
        // Et sans mesure locale, on n'invente pas de division.
        assert!(
            s.contains("mien > 0 && debit > 0"),
            "l'equivalence se calcule meme sans debit local connu"
        );
    }

    /// Le vocabulaire de la page est celui de quelqu'un qui debute.
    ///
    /// « Hauteur », « adresses derivees », « depensable », « immature » sont les
    /// mots du protocole. Ils sont justes et ils ne disent rien a personne. Cette
    /// epreuve fige les traductions : les reintroduire demanderait de la
    /// modifier, donc de le decider.
    #[test]
    fn la_page_parle_la_langue_de_tout_le_monde() {
        for jargon in ["Hauteur", "Adresses dérivées", "Dépensable"] {
            assert!(
                !PAGE.contains(&format!(">{jargon}<")) && !PAGE.contains(&format!("\"{jargon}\"")),
                "jargon reintroduit comme etiquette : {jargon}"
            );
        }
        for clair in [
            "Blocs vérifiés",
            "Vos adresses",
            "Disponible",
            "En attente de maturité",
        ] {
            assert!(PAGE.contains(clair), "traduction perdue : {clair}");
        }
        // Et le mot « dériver » est explique la ou il apparait, pas ailleurs.
        assert!(
            PAGE.contains("dériver</strong>") || PAGE.contains("<strong>dériver"),
            "le mot du protocole est employe sans etre explique"
        );
    }

    /// Le journal des trouvailles dit quel bloc, quand, et combien.
    ///
    /// C'est ce qu'un mineur vient regarder : pas un compteur abstrait, ses
    /// blocs a lui, avec le gain de chacun et un lien vers l'explorateur.
    #[test]
    fn le_journal_des_trouvailles_est_complet_et_echappe() {
        let s = script();
        assert!(s.contains("function peindreTrouves"), "pas de journal");
        // Chaque champ venu du nœud traverse `ech` — hauteur comprise, car elle
        // entre aussi dans un attribut href.
        for e in [
            "ech(String(t.hauteur))",
            "ech(quandCourt(t.horodatage))",
            "ech(t.recompense.q21)",
        ] {
            assert!(s.contains(e), "champ non echappe : {e}");
        }
        // La hauteur mene a l'explorateur du meme nœud, jamais ailleurs.
        assert!(
            s.contains(r#"href="/#/bloc/"#),
            "pas de lien vers l'explorateur"
        );
        assert!(s.contains(r#"rel="noopener""#));
        // Le gain total s'affiche, et vient du nœud — pas d'une addition JS.
        assert!(s.contains("etat.gagne"), "le gain n'est pas celui du nœud");
        // L'etat vide explique la loterie au lieu de montrer une liste nue.
        assert!(s.contains("est une loterie"));
    }

    /// Les gestes rapides du solde menent aux trois actions principales.
    #[test]
    fn le_solde_porte_les_gestes_rapides() {
        for v in ["recevoir", "envoyer", "miner"] {
            assert!(
                PAGE.contains(&format!(r#"data-aller="{v}""#)),
                "geste rapide absent : {v}"
            );
        }
        assert!(script().contains(r#"button[data-aller]"#));
    }

    /// L'activite se lit d'un regard : une icone par sens, un montant signe.
    #[test]
    fn l_activite_porte_des_icones_et_des_signes() {
        let s = script();
        assert!(
            s.contains("function iconeGenre"),
            "pas d'icones de mouvement"
        );
        // Trois sens, trois dessins — et le genre inconnu retombe sur un dessin
        // generique plutot que sur rien.
        for cl in ["sens mine", "sens envoi", "sens recu"] {
            assert!(s.contains(cl), "sens absent : {cl}");
        }
        // Le montant recu s'affiche signe et colore ; l'absence reste un tiret.
        assert!(s.contains(r#""+ " + m.recu.q21"#));
        assert!(PAGE.contains("td.plus{color:var(--accent)"));
        assert!(PAGE.contains("td.moins{color:var(--danger)"));
    }

    /// La carte de securite promet la restauration partout, et distingue le
    /// code de la phrase secrete.
    ///
    /// La confusion entre les deux est la premiere cause de fonds crus perdus :
    /// quelqu'un retient sa phrase, perd son code, et decouvre trop tard que la
    /// phrase ne refabrique rien.
    #[test]
    fn la_carte_de_securite_dit_ce_qui_sauve_et_ce_qui_ne_sauve_pas() {
        assert!(PAGE.contains("Le code de sauvegarde est votre portefeuille"));
        for os in [
            "Windows",
            "Mac Intel",
            "Mac Apple
      Silicon",
            "Linux",
            "Raspberry Pi",
        ] {
            assert!(PAGE.contains(os), "systeme absent de la promesse : {os}");
        }
        assert!(PAGE.contains(
            "ne protège que le
      fichier de <em>cette</em> machine"
        ));
        assert!(PAGE.contains("Ne photographiez pas le code"));
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

    /// Le portefeuille se lit en francais, en anglais et en japonais, et le
    /// choix tient en un clic.
    ///
    /// La traduction se fait par correspondance du texte source plutot que par
    /// des identifiants semes dans la page : c'est ce qui permet de couvrir
    /// aussi le texte que le script fabrique a l'execution. Cette epreuve fige
    /// le mecanisme et quelques traductions temoins — les perdre passerait
    /// autrement inapercu jusqu'a ce qu'un utilisateur tombe sur une page a
    /// moitie traduite.
    #[test]
    fn le_portefeuille_se_traduit_en_trois_langues() {
        // Le selecteur, et ses trois drapeaux.
        assert!(
            PAGE.contains(r#"id="langues""#),
            "selecteur de langue absent"
        );
        for l in ["fr", "en", "ja"] {
            assert!(
                PAGE.contains(&format!(r#"data-langue="{l}""#)),
                "langue absente du selecteur : {l}"
            );
        }

        let s = script();
        // Le moteur.
        for f in [
            "function q21Norm",
            "function q21Trad",
            "function q21TraduireTexte",
            "function q21AppliquerLangue",
            "MutationObserver",
        ] {
            assert!(s.contains(f), "moteur de traduction incomplet : {f}");
        }

        // Quelques traductions temoins, dans les deux langues.
        for (fr, en, ja) in [
            ("Solde", "Balance", "残高"),
            ("Envoyer", "Send", "送る"),
            ("Reseau", "Network", "ネットワーク"),
        ] {
            let _ = fr;
            assert!(s.contains(en), "traduction anglaise perdue : {en}");
            assert!(s.contains(ja), "traduction japonaise perdue : {ja}");
        }

        // Ce qui n'est pas traduit doit rester en francais, jamais vide.
        assert!(
            s.contains("if (t !== null) v = t;"),
            "le repli sur le texte d'origine a disparu"
        );

        // --- Les trois couches d'appariement.
        //
        // L'exact ne suffit pas : une phrase batie autour d'un nombre change a
        // chaque affichage, et resterait donc en francais pour toujours. Les
        // motifs capturent la partie variable ; les prefixes traitent les
        // messages a queue variable. Perdre une couche laisserait une part de
        // l'interface non traduite sans qu'aucune epreuve ne tombe.
        for couche in [
            "const I18N =",
            "const I18N_MOTIFS =",
            "const I18N_PREFIXES =",
        ] {
            assert!(
                s.contains(couche),
                "couche de traduction absente : {couche}"
            );
        }
        assert!(
            s.contains("motif.test(n)"),
            "les motifs ne sont plus appliques"
        );

        // Les dates et les nombres suivent la langue : traduire les mots en
        // laissant « 12/08/2025 » a un lecteur japonais serait un travail a
        // moitie fait.
        assert!(
            s.contains("function q21Locale"),
            "le format local a disparu"
        );
        for etiquette in ["en-US", "ja-JP", "fr-FR"] {
            assert!(s.contains(etiquette), "format local manquant : {etiquette}");
        }
        assert!(
            !s.contains("toLocaleDateString(\"fr-FR\")"),
            "une date reste figee en francais"
        );
    }
}
