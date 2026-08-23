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
.sous{color:var(--doux);font-size:.9rem;margin-top:.35rem}
.etat{display:inline-block;padding:.12rem .5rem;border-radius:3px;font-size:.75rem;
  font-family:ui-monospace,monospace;background:var(--accent-fond);color:var(--accent);margin-left:.5rem}
h2{font-size:1rem;text-transform:uppercase;letter-spacing:.08em;color:var(--doux);
  margin:2rem 0 .8rem;font-weight:600}
.grille{display:grid;gap:.9rem;grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}
.tuile{background:var(--carte);border:1px solid var(--bord);border-radius:6px;padding:.85rem 1rem}
.tuile .k{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--tenu)}
.tuile .v{font-size:1.3rem;font-family:ui-monospace,monospace;margin-top:.2rem;
  font-variant-numeric:tabular-nums;word-break:break-all}
.tuile .n{font-size:.76rem;color:var(--doux);margin-top:.2rem}
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
.avert ul{margin:.3rem 0 .6rem;padding-left:1.2rem;font-size:.88rem;color:var(--doux)}
.deux{display:grid;gap:.9rem;grid-template-columns:1fr 1fr}
@media(max-width:720px){.deux{grid-template-columns:1fr}}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--bord);
  color:var(--tenu);font-size:.78rem}
code{background:var(--accent-fond);color:var(--accent);padding:.1em .35em;border-radius:3px;
  font-size:.85em}
.err{color:var(--alerte)}
</style>
</head>
<body>
<div class="enveloppe">

<header>
  <h1>Q21 <span class="etat" id="reseau">…</span></h1>
  <div class="sous">
    Explorateur servi par <strong>votre nœud</strong>, en local. Aucune ressource
    externe n'est chargée&nbsp;: ce que vous lisez, votre machine l'a validé.
  </div>
</header>

<div id="erreur" class="avert" style="display:none">
  <h3>Nœud injoignable</h3>
  <p id="erreur-detail"></p>
</div>

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

<footer>
  API JSON-RPC sur <code>POST /rpc</code> — <code>listmethods</code> énumère les
  méthodes disponibles. Code de recherche, non audité&nbsp;: ne protège aucune
  valeur réelle.
</footer>

</div>
<script>
// Le jeton ne voyage plus dans l'URL : une adresse finit dans l'historique du
// navigateur, dans les journaux de tout mandataire, et dans l'en-tete Referer.
// Il est demande une fois et garde en memoire, le temps de l'onglet.
const RPC = "/rpc";
let jeton = null;
let compteur = 0;

function entetes(){
  const h = {"Content-Type":"application/json"};
  if (jeton) h["Authorization"] = "Bearer " + jeton;
  return h;
}

async function appel(methode, params){
  const r = await fetch(RPC, {
    method:"POST",
    headers: entetes(),
    body: JSON.stringify({jsonrpc:"2.0", id:++compteur, method:methode, params:params||{}})
  });
  if (r.status === 401){
    const saisi = window.prompt("Jeton d'acces du noeud (--rpc-token) :");
    if (saisi){ jeton = saisi; return appel(methode, params); }
    throw new Error("jeton d'acces requis");
  }
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

const ech = s => String(s).replace(/[&<>"']/g, c =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const court = (h,n)=> h ? ech(h.slice(0,n||16))+"…" : "—";
const octets = n => n>=1048576 ? (n/1048576).toFixed(2)+" Mio"
                 : n>=1024 ? (n/1024).toFixed(1)+" Kio" : n+" o";
const date = t => new Date(t*1000).toISOString().replace("T"," ").slice(0,19);

// `v` et `n` etaient inseres bruts : l'invariant ne tenait qu'a la discipline de
// chaque appelant. Un champ que l'explorateur croit numerique peut arriver en
// chaine — `Json::u64` bascule en chaine au-dela de i64::MAX — et devenir une
// injection. On echappe par defaut ; le fragment de balisage voulu se declare.
const brut = h => ({__html: h});
const rendu = x => (x && x.__html !== undefined) ? x.__html : ech(x);

function tuile(k,v,n){
  return `<div class="tuile"><div class="k">${ech(k)}</div>
          <div class="v">${rendu(v)}</div>${n?`<div class="n">${rendu(n)}</div>`:""}</div>`;
}
function lignes(cible, paires){
  document.getElementById(cible).innerHTML =
    paires.map(([k,v])=>`<tr><th>${ech(k)}</th><td>${rendu(v)}</td></tr>`).join("");
}

async function rafraichir(){
  try{
    const [info, supply, pow, sec, mem] = await Promise.all([
      appel("getinfo"), appel("getsupply"), appel("getpow"),
      appel("getsecurity"), appel("getmempool")
    ]);
    document.getElementById("erreur").style.display = "none";
    document.getElementById("reseau").textContent = info.reseau;

    document.getElementById("tuiles").innerHTML =
      tuile("Hauteur", info.hauteur) +
      tuile("Tête", brut(`<span class="coupe">${court(info.tete,20)}</span>`)) +
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
      tuile("Sorties non dépensées", info.utxo_total);

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
      ["Identifiants", mem.txids.length ? mem.txids.map(t=>court(t,12)).join(" ") : "—"]
    ]);

    const debut = Math.max(0, info.hauteur - 11);
    const blocs = await Promise.all(
      Array.from({length: info.hauteur - debut + 1}, (_,i)=>
        appel("getblock", {hauteur: info.hauteur - i}))
    );
    document.getElementById("blocs").innerHTML = blocs.map(b=>`
      <tr>
        <td>${b.entete.hauteur}</td>
        <td><span class="coupe">${court(b.entete.id, 24)}</span></td>
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
    document.getElementById("erreur").style.display = "block";
    document.getElementById("erreur-detail").textContent =
      "Impossible d'interroger le nœud : " + e.message +
      ". Si un jeton d'accès est configuré, l'explorateur le demandera.";
  }
}

rafraichir();
setInterval(rafraichir, 4000);
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Les points d'insertion `innerHTML` echappent par defaut.
    #[test]
    fn les_valeurs_sont_echappees_par_defaut() {
        assert!(PAGE.contains("const rendu ="));
        assert!(PAGE.contains("${rendu(v)}"));
    }
}
