//! La premiere fois : creer ou ouvrir un portefeuille, sans terminal.
//!
//! # Le defaut que ce fichier ferme
//!
//! Jusqu'ici, un nouveau venu devait taper deux commandes avant de voir quoi que
//! ce soit : `q21 init testnet`, qui demande une phrase secrete dans une fenetre
//! noire et y fait defiler un code de sauvegarde, puis `q21 wallet`, qui
//! redemande la phrase. Le lanceur a double-cliquer masquait la premiere en
//! l'enchainant, mais la fenetre noire restait, et avec elle la question posee
//! sans decor : « Phrase secrete du portefeuille : ».
//!
//! Aucune application de bureau ne demande cela. Ce module remplace ces deux
//! moments par des ecrans.
//!
//! # Ce que cela change au modele de confiance, dit franchement
//!
//! Ce n'est pas neutre, et le passer sous silence serait malhonnete.
//!
//! **Avant**, la phrase secrete se tapait dans un terminal et la graine
//! s'affichait dans ce meme terminal. Le navigateur ne voyait ni l'une ni
//! l'autre — c'est ce qu'affirme encore, a juste titre pour lui, l'en-tete de
//! `wallet_ui.rs` : la page du portefeuille ne recoit jamais de secret.
//!
//! **Desormais**, pour cette page-ci et pour elle seule : la phrase secrete
//! voyage du navigateur vers le nœud, et le code de sauvegarde — qui *est* la
//! graine — voyage du nœud vers le navigateur pour etre recopie.
//!
//! Ce que cela coute exactement : le navigateur entre dans la frontiere de
//! confiance de la graine, alors qu'il n'y etait pas. Une extension de
//! navigateur autorisee sur `127.0.0.1` peut lire le contenu d'une page ; elle
//! pourrait donc lire le code de sauvegarde pendant les quelques secondes ou il
//! est affiche.
//!
//! Ce que cela ne coute pas : cette extension pouvait **deja** vider le
//! portefeuille. La page du portefeuille dispose de `sendtoaddress`, et c'est
//! le cas depuis le premier jour. La frontiere s'elargit du droit de depenser
//! au droit de connaitre la graine ; elle ne s'ouvre pas a quelqu'un qui etait
//! dehors.
//!
//! Ce qui est fait pour reduire la surface :
//!
//! - le serveur n'ecoute que sur la boucle locale, et exige le jeton de la
//!   session pour tout ce qui n'est pas la coquille HTML ; ce jeton n'est
//!   jamais dans l'adresse ouverte par le navigateur — celle-ci porte une
//!   amorce a usage unique, echangee au chargement (voir
//!   `http::serve_avec_amorce`) ;
//! - la phrase ne part qu'en corps de requete `POST`, jamais dans une adresse ;
//! - la page interdit `localStorage`, `sessionStorage`, les cookies : rien de ce
//!   qu'elle manipule ne survit a l'onglet ;
//! - les champs portent `autocomplete="off"`, pour que le gestionnaire de mots
//!   de passe du navigateur ne propose pas d'enregistrer la phrase ;
//! - le code de sauvegarde ne s'affiche qu'a l'ecran, pour etre recopie sur
//!   papier : aucun bouton ne l'envoie au presse-papier, dont l'historique
//!   survit a la page et se synchronise parfois entre appareils ;
//! - le code de sauvegarde est efface de la page des qu'il a ete confirme.
//!
//! Ce qui ne serait resolu que par une vraie fenetre native, avec une
//! bibliotheque d'interface — donc par une dependance de plus dans un programme
//! qui garde des clefs privees. Le choix a ete fait dans l'autre sens, en
//! connaissance de cause.
//!
//! # Pourquoi un second serveur, et non le nœud lui-meme
//!
//! Le nœud sert deja une page et un RPC ; il aurait pu servir celle-ci. Mais
//! `RpcContext` porte `wallet: Option<Arc<Mutex<Wallet>>>`, fixe a sa
//! construction : adopter un portefeuille en cours de route demanderait de
//! renverser cette structure en `Arc<Mutex<Option<Wallet>>>`, donc de toucher
//! chaque appel qui manipule des fonds.
//!
//! Un petit serveur distinct, qui vit le temps de l'installation et rend la main,
//! ne touche rien de tout cela. Il ecoute sur **son propre port**, jamais sur
//! celui du nœud : reprendre un port qu'on vient de liberer est une course qui
//! echoue sur certains systemes, et il n'y a aucune raison de la courir.

/// Page d'installation. Aucune ressource externe, comme les deux autres.
pub const PAGE: &str = r##"<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Q21 — bienvenue</title>
<style>
:root{
  --fond:#f5f4f0; --carte:#fffefb; --bord:#dcd8cf; --bord-fort:#c3bdb1;
  --texte:#1a1a18; --doux:#57554d; --tenu:#8b887d;
  --accent:#1d6f66; --accent-fond:#e2eeeb; --alerte:#8a5a1e; --alerte-fond:#f4e9d8;
  --danger:#9b3025; --danger-fond:#f6e3e0;
}
@media (prefers-color-scheme: dark){
  :root{
    --fond:#131410; --carte:#1c1e18; --bord:#32352b; --bord-fort:#454940;
    --texte:#ecebe0; --doux:#aca99a; --tenu:#7b786b;
    --accent:#62bfb2; --accent-fond:#16302c; --alerte:#d9a75f; --alerte-fond:#312716;
    --danger:#e08a7d; --danger-fond:#33201d;
  }
}
*{box-sizing:border-box}
body{
  margin:0;background:var(--fond);color:var(--texte);
  font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem}
.cadre{width:100%;max-width:560px}

/* --- Le fil des etapes ------------------------------------------------ */
.fil{display:flex;gap:.5rem;margin-bottom:1.6rem;align-items:center;
  justify-content:center;flex-wrap:wrap}
.fil .pas{display:flex;align-items:center;gap:.5rem;font-size:.8rem;color:var(--tenu)}
.fil .rond{width:1.55rem;height:1.55rem;border-radius:50%;display:grid;place-items:center;
  border:1.5px solid var(--bord-fort);font-size:.75rem;font-weight:600;
  font-variant-numeric:tabular-nums;flex:0 0 auto}
.fil .pas.ici{color:var(--texte);font-weight:600}
.fil .pas.ici .rond{border-color:var(--accent);background:var(--accent);color:var(--fond)}
.fil .pas.fait .rond{border-color:var(--accent);color:var(--accent)}
.fil .trait{width:1.4rem;height:1.5px;background:var(--bord)}

/* --- La carte --------------------------------------------------------- */
.carte{background:var(--carte);border:1px solid var(--bord);border-radius:12px;
  padding:2rem 2rem 1.7rem}
@media(max-width:520px){.carte{padding:1.4rem 1.2rem}}
.marque{font-size:.72rem;letter-spacing:.16em;text-transform:uppercase;
  color:var(--accent);font-weight:600;margin-bottom:.5rem}
h1{font-size:1.55rem;line-height:1.2;margin:0 0 .6rem;letter-spacing:-.015em;
  text-wrap:balance}
h2{font-size:1.05rem;margin:1.6rem 0 .5rem}
p{margin:0 0 1rem;color:var(--doux)}
p.serre{margin-bottom:.5rem}
strong{color:var(--texte);font-weight:600}

/* --- Champs ----------------------------------------------------------- */
label{display:block;font-size:.85rem;font-weight:600;margin:1.1rem 0 .35rem}
.champ{position:relative}
input[type=password],input[type=text],textarea{
  width:100%;padding:.7rem .8rem;font:inherit;color:var(--texte);
  background:var(--fond);border:1.5px solid var(--bord-fort);border-radius:7px;
  outline:none}
input:focus,textarea:focus{border-color:var(--accent);
  box-shadow:0 0 0 3px var(--accent-fond)}
textarea{resize:vertical;min-height:5.2rem;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9rem}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.oeil{position:absolute;right:.5rem;top:50%;transform:translateY(-50%);
  background:none;border:none;color:var(--tenu);font-size:.78rem;cursor:pointer;
  padding:.3rem .4rem;border-radius:4px}
.oeil:hover{color:var(--texte);background:var(--fond)}
.aide{font-size:.8rem;color:var(--tenu);margin:.35rem 0 0}

/* --- Force de la phrase ----------------------------------------------- */
.jauge{height:4px;border-radius:2px;background:var(--bord);margin-top:.5rem;
  overflow:hidden}
.jauge i{display:block;height:100%;width:0;background:var(--alerte);
  transition:width .18s,background .18s}
.jauge.b i{background:var(--accent)}
.verdict{font-size:.8rem;margin-top:.35rem;color:var(--tenu);min-height:1.2em}

/* --- Boutons ---------------------------------------------------------- */
.actions{display:flex;gap:.7rem;margin-top:1.6rem;flex-wrap:wrap}
button.p,button.s{padding:.7rem 1.2rem;font:inherit;font-weight:600;
  border-radius:7px;cursor:pointer;border:1.5px solid transparent}
button.p{background:var(--accent);color:var(--fond);border-color:var(--accent);flex:1}
button.p:hover:not(:disabled){filter:brightness(1.08)}
button.p:disabled{opacity:.45;cursor:not-allowed}
button.s{background:transparent;color:var(--doux);border-color:var(--bord-fort)}
button.s:hover{color:var(--texte);border-color:var(--tenu)}
button:focus-visible{outline:3px solid var(--accent-fond);outline-offset:1px}
.lien{background:none;border:none;color:var(--accent);font:inherit;font-size:.85rem;
  cursor:pointer;padding:.2rem 0;text-decoration:underline;text-underline-offset:3px}

/* --- Encarts ---------------------------------------------------------- */
.note{border-left:3px solid var(--accent);background:var(--accent-fond);
  border-radius:0 7px 7px 0;padding:.8rem 1rem;font-size:.88rem;margin:1.1rem 0}
.note.avert{border-color:var(--alerte);background:var(--alerte-fond)}
.note.mal{border-color:var(--danger);background:var(--danger-fond)}
.note p{margin:0;color:var(--doux)}
.note p+p{margin-top:.5rem}
.note b{color:var(--texte)}

/* --- Le code de sauvegarde -------------------------------------------- */
.code{background:var(--fond);border:1.5px dashed var(--bord-fort);border-radius:9px;
  padding:1.1rem;margin:1rem 0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:1.02rem;line-height:1.75;word-break:break-all;letter-spacing:.02em}
.code b{color:var(--accent);font-weight:600}

/* --- Divers ----------------------------------------------------------- */
.coche{display:flex;gap:.6rem;align-items:flex-start;margin:1.1rem 0;
  font-size:.9rem;color:var(--doux);cursor:pointer}
.coche input{margin:.3rem 0 0;flex:0 0 auto;width:1.05rem;height:1.05rem;
  accent-color:var(--accent)}
.attente{display:flex;gap:.7rem;align-items:center;color:var(--doux);
  font-size:.92rem;margin-top:1.2rem}
.rotor{width:1.05rem;height:1.05rem;border:2px solid var(--bord-fort);
  border-top-color:var(--accent);border-radius:50%;animation:t .8s linear infinite;
  flex:0 0 auto}
@keyframes t{to{transform:rotate(360deg)}}
@media(prefers-reduced-motion:reduce){.rotor{animation:none}}
.pied{text-align:center;font-size:.78rem;color:var(--tenu);margin-top:1.2rem}
.cache{display:none}
</style>
</head>
<body>
<div class="cadre">
  <div class="fil" id="fil"></div>
  <div class="carte" id="carte"></div>
  <div class="pied" id="pied"></div>
</div>
<script>
"use strict";
// Cette page ne conserve rien : aucun stockage de navigateur n'est employe, et
// une epreuve le verifie en cherchant les noms de ces interfaces dans ce script.
// Ce qui transite ici est la phrase secrete et la graine ; rien de tout cela ne
// doit pouvoir etre relu apres la fermeture de l'onglet.

var JETON = "", AMORCE = "", ETAT = null, PHRASE = null, CODE = null;

function $(id){ return document.getElementById(id); }
function ech(s){
  return String(s).replace(/[&<>"']/g, function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];
  });
}

// Le fragment porte une amorce, pas le jeton : l'adresse est passee au
// navigateur en argument de ligne de commande, que d'autres comptes de la
// machine peuvent lire. L'amorce s'echange une fois contre le jeton de
// session, puis ne vaut plus rien. Elle est effacee de la barre d'adresse
// aussitot lue : un secret qu'on peut photographier n'en est plus un.
(function(){
  var f = location.hash.slice(1);
  if(f){ AMORCE = f; history.replaceState(null, "", location.pathname); }
})();

function echanger(){
  return fetch("/session", {
    method: "POST",
    headers: {"Content-Type":"application/json","Authorization":"Bearer " + AMORCE}
  }).then(function(r){
    if(!r.ok) throw new Error("lien déjà servi ou expiré");
    return r.json();
  }).then(function(d){ JETON = d.jeton; AMORCE = ""; });
}

function appel(m, p){
  return fetch("/installation", {
    method: "POST",
    headers: {"Content-Type":"application/json","Authorization":"Bearer " + JETON},
    body: JSON.stringify({methode: m, params: p || {}})
  }).then(function(r){ return r.json(); }).then(function(d){
    if(d && d.erreur) throw new Error(d.erreur);
    return d;
  });
}

// --- Le fil des etapes ---------------------------------------------------
function fil(etapes, ici){
  if(!etapes){ $("fil").innerHTML = ""; return; }
  var h = "";
  for(var i = 0; i < etapes.length; i++){
    if(i) h += '<span class="trait"></span>';
    var cl = i === ici ? " ici" : (i < ici ? " fait" : "");
    h += '<span class="pas' + cl + '"><span class="rond">'
       + (i < ici ? "&#10003;" : (i + 1)) + '</span>' + ech(etapes[i]) + '</span>';
  }
  $("fil").innerHTML = h;
}

function pied(t){ $("pied").textContent = t || ""; }

// --- Force de la phrase --------------------------------------------------
//
// Une estimation, pas une mesure : elle compte la longueur et la variete, ce
// qui suffit a distinguer « soleil » de « soleil-de-mars-1998 ». Elle ne
// pretend pas evaluer une entropie reelle, et ne bloque jamais : c'est un
// conseil, pas une regle. Les regles de composition rendent les phrases plus
// courtes, pas plus sures.
function force(p){
  if(!p) return {n:0, mot:""};
  var v = 0;
  if(/[a-z]/.test(p)) v++;
  if(/[A-Z]/.test(p)) v++;
  if(/[0-9]/.test(p)) v++;
  if(/[^a-zA-Z0-9]/.test(p)) v++;
  var n = Math.min(100, (p.length / 20) * 70 + v * 7.5);
  var mot = n < 35 ? "Courte — quelques mots de plus vaudraient mieux"
          : n < 65 ? "Correcte"
          : "Solide";
  return {n:n, mot:mot};
}

// --- Ecran : choix de depart --------------------------------------------
function ecranChoix(){
  fil(null);
  pied("Réseau d'essai — aucun Q21 n'a de valeur");
  $("carte").innerHTML =
    '<div class="marque">Q21</div>'
  + '<h1>Bienvenue</h1>'
  + '<p>Ce programme est un portefeuille <strong>et</strong> un nœud : il vérifie '
  + 'lui-même chaque bloc, au lieu de croire quelqu\'un sur parole. Tout reste sur '
  + 'cette machine.</p>'
  + '<div class="actions">'
  + '<button class="p" id="b-creer">Créer un portefeuille</button>'
  + '</div>'
  + '<p style="margin:1.1rem 0 0;text-align:center">'
  + '<button class="lien" id="b-restaurer">J\'ai déjà un code de sauvegarde</button></p>';
  $("b-creer").onclick = function(){ ecranPhrase(false); };
  $("b-restaurer").onclick = ecranRestaurer;
}

// --- Ecran : la phrase secrete ------------------------------------------
// Les deux chemins n'ont pas les memes etapes, et le fil doit le dire. Il
// affichait celui de la creation pendant une restauration : on venait de saisir
// son code, et l'ecran annoncait qu'il restait a le decouvrir.
function etapes(restauration){
  return restauration
    ? ["Code de sauvegarde", "Phrase secrète", "Prêt"]
    : ["Phrase secrète", "Code de sauvegarde", "Prêt"];
}

function ecranPhrase(restauration){
  fil(etapes(restauration), restauration ? 1 : 0);
  pied("");
  $("carte").innerHTML =
    '<div class="marque">Étape ' + (restauration ? 2 : 1) + ' sur 3</div>'
  + '<h1>Choisissez une phrase secrète</h1>'
  + (restauration
      ? '<p>Cette phrase protège le portefeuille <strong>sur cette machine-ci</strong>. '
      + 'Elle peut être différente de celle que vous aviez ailleurs : elle ne fait pas '
      + 'partie de votre code de sauvegarde, elle ne fait que chiffrer ce disque.</p>'
      : '')
  + '<p>Elle chiffre votre portefeuille sur ce disque. Sans elle, quiconque lit le '
  + 'fichier — une sauvegarde, un disque revendu — détient les fonds pour toujours.</p>'
  + '<div class="note"><p><b>Elle ne se récupère pas.</b> Aucun serveur ne la connaît, '
  + 'personne ne peut la réinitialiser. Choisissez plusieurs mots dont vous vous '
  + 'souviendrez, et notez-la ailleurs qu\'ici.</p></div>'
  + '<label for="p1">Phrase secrète</label>'
  + '<div class="champ">'
  + '<input type="password" id="p1" autocomplete="off" autocapitalize="off" '
  + 'autocorrect="off" spellcheck="false">'
  + '<button class="oeil" id="voir" type="button">afficher</button></div>'
  + '<div class="jauge" id="jauge"><i></i></div>'
  + '<div class="verdict" id="verdict"></div>'
  + '<label for="p2">Retapez-la</label>'
  + '<div class="champ"><input type="password" id="p2" autocomplete="off" '
  + 'autocapitalize="off" autocorrect="off" spellcheck="false"></div>'
  + '<div class="verdict" id="pareil"></div>'
  + '<div class="actions">'
  + '<button class="s" id="retour">Retour</button>'
  + '<button class="p" id="suite" disabled>Continuer</button></div>'
  + '<p style="margin:1.1rem 0 0;text-align:center">'
  + '<button class="lien" id="sans">Continuer sans phrase secrète</button></p>';

  var p1 = $("p1"), p2 = $("p2"), suite = $("suite");
  function juger(){
    var f = force(p1.value);
    $("jauge").firstChild.style.width = f.n + "%";
    $("jauge").className = "jauge" + (f.n >= 65 ? " b" : "");
    $("verdict").textContent = f.mot;
    var ok = p1.value.length > 0 && p1.value === p2.value;
    $("pareil").textContent = p2.value && !ok ? "Les deux ne correspondent pas." : "";
    suite.disabled = !ok;
  }
  p1.oninput = juger; p2.oninput = juger;
  p2.onkeydown = function(e){ if(e.key === "Enter" && !suite.disabled) suite.click(); };
  $("voir").onclick = function(){
    var t = p1.type === "password" ? "text" : "password";
    p1.type = t; p2.type = t;
    $("voir").textContent = t === "text" ? "masquer" : "afficher";
  };
  $("retour").onclick = restauration ? ecranRestaurer : ecranChoix;
  suite.onclick = function(){ PHRASE = p1.value; creer(); };
  $("sans").onclick = ecranSansPhrase;
  p1.focus();
}

function ecranSansPhrase(){
  fil(etapes(false), 0);
  $("carte").innerHTML =
    '<div class="marque">Étape 1 sur 3</div>'
  + '<h1>Sans phrase secrète ?</h1>'
  + '<div class="note mal">'
  + '<p><b>Votre graine sera écrite en clair sur ce disque.</b></p>'
  + '<p>N\'importe quel programme, n\'importe quelle sauvegarde, n\'importe qui '
  + 'ayant accès à ce fichier pourra dépenser vos fonds — définitivement, sans '
  + 'que vous puissiez rien y faire.</p></div>'
  + '<p>C\'est un choix raisonnable sur un réseau d\'essai où rien n\'a de valeur. '
  + 'Il ne l\'est nulle part ailleurs.</p>'
  + '<label class="coche"><input type="checkbox" id="jaicompris">'
  + '<span>J\'ai compris : ma graine sera stockée sans protection.</span></label>'
  + '<div class="actions">'
  + '<button class="s" id="retour">Mettre une phrase</button>'
  + '<button class="p" id="suite" disabled>Continuer sans protection</button></div>';
  $("jaicompris").onchange = function(){ $("suite").disabled = !this.checked; };
  $("retour").onclick = function(){ ecranPhrase(false); };
  $("suite").onclick = function(){ PHRASE = ""; creer(); };
}

// --- Ecran : restauration ------------------------------------------------
function ecranRestaurer(){
  fil(etapes(true), 0);
  pied("");
  $("carte").innerHTML =
    '<div class="marque">Restauration</div>'
  + '<h1>Votre code de sauvegarde</h1>'
  + '<p>Recopiez-le tel quel. Il porte une somme de contrôle : une faute de frappe '
  + 'sera détectée, pas subie.</p>'
  + '<label for="c">Code de sauvegarde</label>'
  + '<textarea id="c" autocomplete="off" autocapitalize="off" autocorrect="off" '
  + 'spellcheck="false"></textarea>'
  + '<p class="aide">L\'alphabet employé ne contient ni <span class="mono">1</span>, '
  + 'ni <span class="mono">b</span>, ni <span class="mono">i</span>, ni '
  + '<span class="mono">o</span> — pour qu\'aucun caractère ne puisse être confondu.</p>'
  + '<div class="actions">'
  + '<button class="s" id="retour">Retour</button>'
  + '<button class="p" id="suite" disabled>Continuer</button></div>';
  var c = $("c");
  c.oninput = function(){ $("suite").disabled = c.value.trim().length < 20; };
  $("retour").onclick = ecranChoix;
  $("suite").onclick = function(){ CODE = c.value.trim(); ecranPhrase(true); };
  c.focus();
}

// --- Creation ------------------------------------------------------------
function creer(){
  fil(["Phrase secrète", "Code de sauvegarde", "Prêt"], 1);
  $("carte").innerHTML =
    '<div class="marque">Un instant</div>'
  + '<h1>Création en cours</h1>'
  + '<p>Le programme tire une graine du générateur d\'aléa du système, écrit le bloc '
  + 'de genèse et scelle le portefeuille.</p>'
  + '<div class="attente"><span class="rotor"></span><span>Quelques secondes…</span></div>';

  appel("creer", {phrase: PHRASE, code: CODE})
    .then(function(d){
      // Restaurer n'est pas creer. On ne demande pas de recopier un code que
      // l'on vient de taper ; on montre qu'il a ete compris, ce qui est la
      // seule chose que la personne veut verifier a cet instant.
      if (CODE) ecranRetrouve(d.code, d.adresse); else ecranCode(d.code, d.adresse);
    })
    .catch(function(e){ echec(e.message, CODE ? ecranRestaurer : function(){ ecranPhrase(false); }); });
}

// --- Ecran : le code de sauvegarde --------------------------------------
function ecranCode(code, adresse){
  fil(etapes(false), 1);
  pied("");
  // Le code s'affiche en deux moities : l'œil recopie mieux ce qui est
  // decoupe, et la separation ne fait pas partie du code.
  var m = Math.ceil(code.length / 2);
  $("carte").innerHTML =
    '<div class="marque">Étape 2 sur 3</div>'
  + '<h1>Recopiez ceci sur papier</h1>'
  + '<p>C\'est le <strong>seul</strong> moyen de retrouver vos fonds si ce disque '
  + 'disparaît. Il ne sera plus jamais affiché.</p>'
  + '<div class="code" id="lecode">' + ech(code.slice(0, m)) + '<br>'
  + ech(code.slice(m)) + '</div>'
  + '<div class="note avert"><p><b>Sur papier, à la main, et nulle part ailleurs.</b> '
  + 'Un fichier sur cette machine disparaît avec elle, un fichier dans un nuage se lit '
  + 'à distance, et le presse-papier garde un historique — parfois synchronisé entre '
  + 'vos appareils. Ce code donne les fonds à qui le détient.</p></div>'
  + '<div class="actions"><button class="p" id="suite">Je l\'ai recopié</button></div>';
  $("suite").onclick = function(){ ecranVerif(code, adresse); };
}

// --- Ecran : le portefeuille est retrouve --------------------------------
//
// Le code affiche est celui que le nœud a redecode. Qu'il soit identique a
// celui qui vient d'etre tape est la preuve, visible sans rien expliquer, que
// la bonne graine a ete chargee.
function ecranRetrouve(code, adresse){
  fil(etapes(true), 2);
  pied("");
  var m = Math.ceil(code.length / 2);
  $("carte").innerHTML =
    '<div class="marque">Étape 3 sur 3</div>'
  + '<h1>Portefeuille retrouvé</h1>'
  + '<p>Le code a été compris et votre graine est chargée. Vérifiez qu\'il s\'agit '
  + 'bien du vôtre&nbsp;:</p>'
  + '<div class="code">' + ech(code.slice(0, m)) + '<br>' + ech(code.slice(m)) + '</div>'
  + '<div class="note"><p><b>Vos fonds réapparaîtront à mesure que la chaîne '
  + 'arrive.</b> Le portefeuille redérive vos adresses et y retrouve ce qui leur '
  + 'appartient — rien n\'est perdu, mais il faut que la synchronisation ait eu '
  + 'lieu. Sur une chaîne longue, comptez quelques minutes.</p></div>'
  + '<div class="actions"><button class="p" id="suite">Ouvrir mon portefeuille</button></div>';
  $("suite").onclick = function(){ termine(adresse); };
}

// --- Ecran : verification de la recopie ---------------------------------
//
// Demander de retaper le code entier serait plus sur, et personne ne le ferait :
// on le selectionnerait a l'ecran, on le collerait, et la verification n'aurait
// rien verifie. Les huit derniers caracteres suffisent a prouver qu'on a la
// feuille sous les yeux, et se retapent sans lassitude.
function ecranVerif(code, adresse){
  fil(etapes(false), 1);
  var n = 8, fin = code.slice(-n);
  $("carte").innerHTML =
    '<div class="marque">Étape 2 sur 3</div>'
  + '<h1>Vérifions la recopie</h1>'
  + '<p>Sans regarder l\'écran : quels sont les <strong>' + n + ' derniers '
  + 'caractères</strong> du code que vous venez d\'écrire ?</p>'
  + '<label for="v">Les ' + n + ' derniers caractères</label>'
  + '<div class="champ"><input type="text" id="v" class="mono" autocomplete="off" '
  + 'autocapitalize="off" autocorrect="off" spellcheck="false" maxlength="' + n + '"></div>'
  + '<div class="verdict" id="dit"></div>'
  + '<div class="actions">'
  + '<button class="s" id="revoir">Revoir le code</button>'
  + '<button class="p" id="suite" disabled>Terminer</button></div>';
  var v = $("v");
  v.oninput = function(){
    var s = v.value.trim().toLowerCase();
    $("suite").disabled = s !== fin.toLowerCase();
    $("dit").textContent = s.length >= n && s !== fin.toLowerCase()
      ? "Ce n'est pas la fin du code. Revoyez-le." : "";
  };
  v.onkeydown = function(e){ if(e.key === "Enter" && !$("suite").disabled) $("suite").click(); };
  $("revoir").onclick = function(){ ecranCode(code, adresse); };
  $("suite").onclick = function(){ termine(adresse); };
  v.focus();
}

// --- Ecran : ouverture d'un portefeuille existant ------------------------
function ecranOuvrir(erreur){
  fil(null);
  pied("Réseau d'essai — aucun Q21 n'a de valeur");
  $("carte").innerHTML =
    '<div class="marque">Q21</div>'
  + '<h1>Ouvrir votre portefeuille</h1>'
  + '<p>Ce portefeuille est chiffré. Votre phrase secrète le déchiffre sur cette '
  + 'machine — elle n\'est envoyée nulle part.</p>'
  + (erreur ? '<div class="note mal"><p>' + ech(erreur) + '</p></div>' : '')
  + '<label for="p">Phrase secrète</label>'
  + '<div class="champ">'
  + '<input type="password" id="p" autocomplete="off" autocapitalize="off" '
  + 'autocorrect="off" spellcheck="false">'
  + '<button class="oeil" id="voir" type="button">afficher</button></div>'
  + '<div class="actions"><button class="p" id="suite" disabled>Ouvrir</button></div>';
  var p = $("p");
  p.oninput = function(){ $("suite").disabled = p.value.length === 0; };
  p.onkeydown = function(e){ if(e.key === "Enter" && !$("suite").disabled) $("suite").click(); };
  $("voir").onclick = function(){
    p.type = p.type === "password" ? "text" : "password";
    $("voir").textContent = p.type === "text" ? "masquer" : "afficher";
  };
  $("suite").onclick = function(){
    $("suite").disabled = true;
    $("suite").textContent = "Ouverture…";
    appel("ouvrir", {phrase: p.value})
      .then(function(d){ termine(d.adresse); })
      .catch(function(e){ ecranOuvrir(e.message); });
  };
  p.focus();
}

// --- Ecran : c'est pret --------------------------------------------------
//
// Le nœud n'ecoute pas encore : le serveur d'installation doit d'abord rendre
// la main. On sonde donc sa page jusqu'a ce qu'elle reponde, puis on y va. Une
// attente fixe serait toujours trop courte sur une machine chargee.
function termine(adresse){
  fil(etapes(!!CODE), 2);
  pied("");
  $("carte").innerHTML =
    '<div class="marque">Étape 3 sur 3</div>'
  + '<h1>Votre portefeuille est prêt</h1>'
  + (adresse ? '<p class="serre">Votre première adresse de réception :</p>'
             + '<div class="code">' + ech(adresse) + '</div>' : '')
  + '<div class="attente"><span class="rotor"></span>'
  + '<span id="ou">Démarrage du nœud…</span></div>';

  // Le nœud a sa propre amorce, recue par `etat` : c'est elle qui va dans le
  // fragment, jamais le jeton de session. La page du portefeuille l'echangera
  // a son tour, une fois.
  var cible = "http://127.0.0.1:" + ETAT.port_noeud + "/portefeuille#" + ETAT.amorce_noeud;

  // --- Pourquoi on ne sonde pas le nœud directement.
  //
  // Il ecoute sur un autre port, donc sur une autre origine. Une requete
  // ordinaire y serait refusee par la politique de meme origine, et le refus se
  // confondrait avec « pas encore demarre ». Le mode `no-cors` semblait la
  // reponse : la reponse est opaque, mais son arrivee prouverait que quelqu'un
  // ecoute.
  //
  // Mesure faite : elle est **rejetee quand meme**. Le navigateur refuse les
  // reponses opaques dont le type est du HTML — c'est la protection dite ORB,
  // qui empeche une page d'aller lire un document d'une autre origine. Le
  // sondage echouait donc indefiniment alors que le nœud repondait a `curl`.
  //
  // On demande donc au serveur d'installation, qui est de la meme origine que
  // cette page, d'aller regarder pour nous. C'est lui qui tente la connexion.
  var essais = 0;
  (function sonder(){
    essais++;
    appel("noeud", {})
      .then(function(d){
        if(d.pret){ location.replace(cible); return; }
        if(essais > 600){
          $("ou").innerHTML = 'Le nœud met du temps. <a href="' + ech(cible)
            + '">Ouvrir le portefeuille</a>';
          return;
        }
        setTimeout(sonder, 200);
      })
      .catch(function(){
        // Le serveur d'installation ne s'arrete qu'une fois le nœud debout :
        // ne plus lui parler signifie donc que la place est libre.
        location.replace(cible);
      });
  })();

  appel("commencer", {}).catch(function(){});
}

// --- Echec ---------------------------------------------------------------
function echec(message, retour){
  fil(null);
  $("carte").innerHTML =
    '<div class="marque">Q21</div>'
  + '<h1>Ça n\'a pas marché</h1>'
  + '<div class="note mal"><p>' + ech(message) + '</p></div>'
  + '<div class="actions"><button class="p" id="retour">Recommencer</button></div>';
  $("retour").onclick = retour;
}

// --- Demarrage -----------------------------------------------------------
function demarrer(){
  appel("etat", {}).then(function(d){
    ETAT = d;
    if(d.portefeuille === "scelle") ecranOuvrir(null);
    else ecranChoix();
  }).catch(function(e){
    echec("Le programme n'a pas répondu : " + e.message, demarrer);
  });
}

function lienInutilisable(titre, texte){
  fil(null);
  $("carte").innerHTML =
    '<div class="marque">Q21</div><h1>' + ech(titre) + '</h1>'
  + '<p>' + ech(texte) + ' Fermez cet onglet et relancez le portefeuille.</p>';
}

if(!AMORCE){
  lienInutilisable("Jeton manquant",
    "Cette page s'ouvre depuis le programme, avec un jeton dans l'adresse.");
}else{
  // L'amorce ne vaut qu'une fois : si l'echange echoue, c'est que ce lien a
  // deja servi — ou qu'il a expire. Recommencer ne servirait a rien, on le dit.
  echanger().then(demarrer).catch(function(){
    lienInutilisable("Ce lien a déjà servi",
      "Le lien d'ouverture ne vaut qu'une fois, et il a été utilisé — ou il a expiré.");
  });
}
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    /// Extrait le bloc `<script>` pour les epreuves qui parlent du code.
    fn script() -> &'static str {
        let d = PAGE.find("<script>").expect("un script");
        let f = PAGE.find("</script>").expect("une fin de script");
        &PAGE[d..f]
    }

    #[test]
    fn aucune_ressource_externe() {
        // La regle du portefeuille vaut ici, et davantage : cette page-ci voit
        // la phrase secrete et la graine.
        for interdit in ["http://", "https://", "//cdn", "src=\"//", "@import"] {
            let occurrences = PAGE.matches(interdit).count();
            if interdit == "http://" {
                // Seules sont admises les adresses de boucle locale construites
                // par le script lui-meme.
                assert!(
                    PAGE.matches("http://127.0.0.1:").count() == occurrences,
                    "une adresse http qui n'est pas la boucle locale"
                );
            } else {
                assert_eq!(occurrences, 0, "ressource externe : {interdit}");
            }
        }
    }

    #[test]
    fn aucun_stockage_qui_survit_a_l_onglet() {
        // Cette page manipule la phrase secrete et la graine. Rien de ce qu'elle
        // touche ne doit pouvoir etre relu apres la fermeture.
        for interdit in [
            "localStorage",
            "sessionStorage",
            "document.cookie",
            "indexedDB",
        ] {
            assert!(
                !script().contains(interdit),
                "{interdit} n'a rien a faire dans la page d'installation"
            );
        }
    }

    #[test]
    fn le_jeton_est_efface_de_la_barre_d_adresse() {
        assert!(script().contains("history.replaceState"));
        assert!(script().contains("location.hash"));
    }

    #[test]
    fn la_phrase_ne_part_jamais_dans_une_adresse() {
        // Elle ne doit voyager qu'en corps de POST. Une phrase dans une requete
        // entre dans l'historique du navigateur et dans les journaux.
        assert!(script().contains("method: \"POST\""));
        for interdit in [
            "?phrase=",
            "phrase=\" +",
            "+ phrase",
            "encodeURIComponent(p",
        ] {
            assert!(
                !script().contains(interdit),
                "phrase dans une adresse : {interdit}"
            );
        }
    }

    #[test]
    fn les_champs_de_secret_refusent_le_remplissage_automatique() {
        // Sans cela, le gestionnaire de mots de passe du navigateur propose
        // d'enregistrer la phrase secrete du portefeuille.
        let mots_de_passe = script().matches("type=\"password\"").count();
        assert!(mots_de_passe >= 3, "au moins trois champs de phrase");
        // Chaque champ de **saisie libre** porte autocomplete="off". Les cases a
        // cocher sont exclues : elles ne portent aucun secret, et le
        // gestionnaire de mots de passe ne s'y interesse pas.
        let champs = script().matches("<input type=\"password\"").count()
            + script().matches("<input type=\"text\"").count()
            + script().matches("<textarea id=").count();
        let sans_completion = script().matches("autocomplete=\"off\"").count();
        assert!(
            champs >= 5,
            "le compte de champs est tombe a {champs} : l'epreuve ne verifie plus rien"
        );
        assert!(
            sans_completion >= champs,
            "{sans_completion} autocomplete=off pour {champs} champs de saisie"
        );
    }

    #[test]
    fn le_code_de_sauvegarde_est_confirme_avant_de_poursuivre() {
        // Afficher le code puis passer a la suite d'un clic ne prouve rien. Une
        // verification existe, et le bouton final en depend.
        assert!(script().contains("function ecranVerif"));
        assert!(script().contains("code.slice(-n)"));
    }

    /// Le code de sauvegarde ne part jamais dans le presse-papier.
    ///
    /// Un bouton « Copier » l'y envoyait, avec le conseil de le vider ensuite.
    /// Vider le presse-papier courant ne retire rien de son historique —
    /// Win+V, Klipper, le presse-papier universel d'Apple — ni de ce que le
    /// « presse-papier dans le nuage » de Windows a deja synchronise. La page
    /// dit « sur papier » ; un bouton qui la contredisait n'existe plus.
    #[test]
    fn le_code_de_sauvegarde_ne_passe_pas_par_le_presse_papier() {
        assert!(
            !PAGE.contains("clipboard"),
            "la page ecrit dans le presse-papier"
        );
        assert!(!PAGE.contains("execCommand"), "copie par l'ancienne API");
        // Et la consigne reste : sur papier, et rien d'autre.
        assert!(script().contains("Sur papier"));
        assert!(script().contains("presse-papier garde un historique"));
    }

    /// Le fragment porte une amorce, echangee une fois contre le jeton.
    ///
    /// L'adresse ouverte par le lanceur passe par la ligne de commande du
    /// navigateur ; ce qu'elle porte ne doit valoir qu'une fois. La page
    /// n'appelle rien avant l'echange, et renvoie vers le nœud avec l'amorce
    /// du nœud, jamais avec le jeton de session.
    #[test]
    fn le_fragment_est_une_amorce_echangee_avant_tout_appel() {
        let s = script();
        assert!(
            s.contains("AMORCE = f;"),
            "le fragment doit etre lu comme amorce"
        );
        assert!(
            !s.contains("JETON = f;"),
            "le fragment ne doit plus etre le jeton"
        );
        assert!(s.contains("fetch(\"/session\""));
        assert!(s.contains("echanger().then(demarrer)"));
        assert!(s.contains("/portefeuille#\" + ETAT.amorce_noeud"));
        assert!(!s.contains("/portefeuille#\" + JETON"));
    }

    #[test]
    fn le_choix_de_ne_pas_proteger_est_explicite() {
        // Un portefeuille sans phrase secrete ecrit la graine en clair. Ce n'est
        // pas un defaut d'inattention : il faut cocher une case qui le dit.
        assert!(script().contains("function ecranSansPhrase"));
        assert!(script().contains("jaicompris"));
        assert!(script().contains("en clair"));
    }

    #[test]
    fn tout_ce_qui_vient_du_noeud_est_echappe() {
        // Les messages d'erreur, le code et l'adresse traversent `ech`.
        for brut in [
            "ech(message)",
            "ech(code.slice",
            "ech(adresse)",
            "ech(erreur)",
        ] {
            assert!(script().contains(brut), "non echappe : {brut}");
        }
    }

    #[test]
    fn le_theme_sombre_est_prevu() {
        assert!(PAGE.contains(":root{"));
        assert!(PAGE.contains("@media (prefers-color-scheme: dark)"));
    }

    #[test]
    fn le_mouvement_se_desactive_a_la_demande() {
        assert!(PAGE.contains("prefers-reduced-motion"));
    }
}
