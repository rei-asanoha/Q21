//! Desktop wallet, a single page served by the node.
//!
//! # What this page is
//!
//! The screen someone sees after double-clicking the application. They must be
//! able to receive and send Q21 without ever opening a terminal. Nothing more:
//! five views — balance, receive, send, history, information — and no feature
//! that does not directly serve one of the five.
//!
//! # Three decisions that explain the rest of the file
//!
//! **No external resource.** No font, no stylesheet, no remote script. A
//! wallet page that calls a CDN tells that CDN every time its owner opens the
//! wallet, and gives it the power to replace the code that handles the funds.
//! The rule is enforced by a test, not by vigilance.
//!
//! **Almost no browser storage.** The only thing kept is the session token,
//! in `localStorage`, partitioned by origin — hence by port, drawn at random
//! on each launch. Without it, a simple refresh made the wallet unusable; and
//! since the launcher's link works only once, a tab closed by mistake could no
//! longer be reopened until the program was restarted. What is stored there
//! outlives nothing useful: the token is drawn on each run and dies with it.
//! What a browser keeps after the node stops is an inert string, erased at the
//! first refusal.
//!
//! `indexedDB` and cookies remain forbidden, and nothing but that token is
//! stored. The seed and the passphrase never leave the node — **this page**
//! never sees them at any point.
//!
//! The distinction matters since `setup.rs` exists. The setup page does
//! receive the passphrase as it is typed, and shows the backup code so that it
//! can be written down; it lives only for the duration of that exchange, and
//! the header of that module states what this costs. This file keeps its
//! property intact: once the wallet is open, no secret crosses the browser
//! any more.
//!
//! **No float on an amount.** `0.1 + 0.2 != 0.3` in IEEE 754, and a
//! `parseFloat` on a balance loses units. All the monetary arithmetic of this
//! page goes through `BigInt`, and the body of the send request is assembled
//! by hand so that the digits go out as they are — `JSON.stringify` of a big
//! integer would already be one conversion too many.
//!
//! # The access token
//!
//! The launcher opens the browser on `127.0.0.1:PORT/#<token>`. The fragment
//! is never sent to the server: it appears neither in an intermediary's logs
//! nor in the `Referer` header. The page reads it, **immediately erases the
//! fragment from the address bar**, and then presents it as
//! `Authorization: Bearer`. If it is missing, the page asks for it in a field
//! of the page — never in a browser dialog, which has neither the style nor
//! the discretion of a password field.
//!
//! # Languages
//!
//! The page is written in American English, which is the source language: all
//! the text in the HTML and the script is English. French and Japanese are
//! translations, selectable from the header. They are applied in the browser
//! by matching the displayed English text against tables keyed by that text
//! (`I18N`, exact matches; `I18N_PREFIXES`, messages with a variable tail;
//! `I18N_PATTERNS`, sentences built around numbers). A text missing from the
//! tables is shown in English.

/// The complete wallet page. No external resource, by construction.
pub const PAGE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Q21 — wallet</title>
<style>
/* =========================================================================
   Q21 — desktop wallet
   =========================================================================

   The approach: this must look like an application, not a document. A bar
   at the top that never moves, a navigation column on the left on a large
   screen and a bar at the bottom on a phone, cards laid on a dark
   background. The colors remain the project's own — Q21 green pushed toward
   a brighter mint, violet for anything post-quantum — and nothing is loaded
   from outside: no font, no image, no stylesheet.
   ========================================================================= */

:root{
  color-scheme: light dark;
  /* The light theme is the base value: a token that exists only in a media
     query never applies in the unmarked state. */
  --bg:#f4f6f5; --veil:transparent;
  --card:#ffffff; --card-2:#f9fbfa;
  --border:#dfe5e3; --border-strong:#c6d0cd;
  --text:#0d1211; --soft:#4a5654; --muted:#7b8785;
  --accent:#00875f; --accent-bright:#00a273; --accent-bg:#e2f4ee;
  --quantum:#6b5bd6; --quantum-bg:#ece9fb;
  --warn:#a35a10; --warn-bg:#fbeeda;
  --danger:#b03626; --danger-bg:#fae4e1;
  --shadow:0 1px 2px rgba(13,18,17,.05), 0 8px 24px -12px rgba(13,18,17,.12);
  --rail:236px;
  --sans:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI Variable Text",
    "Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#07090a; --veil:radial-gradient(1200px 620px at 18% -12%,rgba(34,229,166,.10),transparent 62%),
                           radial-gradient(900px 520px at 92% 4%,rgba(139,123,255,.09),transparent 60%);
    --card:#101416; --card-2:#151a1c;
    --border:#1f2729; --border-strong:#2f3a3c;
    --text:#e9f0ee; --soft:#9aa8a5; --muted:#6d7a78;
    --accent:#22e5a6; --accent-bright:#5cf3c0; --accent-bg:#0d2a22;
    --quantum:#8b7bff; --quantum-bg:#1b1832;
    --warn:#ffb65c; --warn-bg:#2e2312;
    --danger:#ff6b5a; --danger-bg:#2e1613;
    --shadow:0 1px 0 rgba(255,255,255,.03) inset, 0 18px 40px -24px rgba(0,0,0,.9);
  }
}

*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0;background:var(--bg);color:var(--text);
  font-family:var(--sans);font-size:15px;line-height:1.55;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;
}
body::before{
  content:"";position:fixed;inset:0;background:var(--veil);pointer-events:none;z-index:0;
}
.shell{position:relative;z-index:1;min-height:100%;display:flex;flex-direction:column}

/* ---- Top bar ----------------------------------------------------------- */
header{
  position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--bg) 86%,transparent);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border-bottom:1px solid var(--border);
}
.bar{max-width:1180px;margin:0 auto;padding:.7rem 1rem;display:flex;align-items:center;gap:.9rem}
.logo{display:flex;align-items:center;gap:.55rem;font-weight:700;letter-spacing:-.02em;font-size:1.05rem}
.mark{width:1.7rem;height:1.7rem;border-radius:9px;flex:0 0 auto;
  background:linear-gradient(135deg,var(--accent),var(--quantum));
  display:grid;place-items:center;color:#04120d;font-size:.72rem;font-weight:800;
  font-family:var(--mono);letter-spacing:-.04em}
h1{font-size:inherit;font-weight:inherit;margin:0;letter-spacing:inherit}
.net-tag{margin-left:.15rem;font-family:var(--mono);font-size:.66rem;font-weight:600;
  letter-spacing:.08em;text-transform:uppercase;color:var(--accent);
  background:var(--accent-bg);padding:.18rem .45rem;border-radius:5px;white-space:nowrap}
.bar .push{margin-left:auto}
.pulse{display:flex;align-items:center;gap:.45rem;font-size:.76rem;color:var(--soft);
  font-variant-numeric:tabular-nums;white-space:nowrap}
.dot{width:.5rem;height:.5rem;border-radius:50%;background:var(--muted);flex:0 0 auto}
.dot.green{background:var(--accent);box-shadow:0 0 0 3px var(--accent-bg)}
.dot.orange{background:var(--warn);box-shadow:0 0 0 3px var(--warn-bg)}
.dot.red{background:var(--danger);box-shadow:0 0 0 3px var(--danger-bg)}
/* The green dot breathes when all is well: a frozen indicator cannot be told
   apart from a dead page. */
.dot.green{animation:breathe 2.6s ease-in-out infinite}
@keyframes breathe{0%,100%{opacity:1}50%{opacity:.45}}
@media(prefers-reduced-motion:reduce){.dot.green{animation:none}}
.pulse b{font-weight:600;color:var(--text)}
.pulse.off b{color:var(--danger)}
.pulse.sync b{color:var(--warn)}
.pulse.ok b{color:var(--accent)}

/* --- The catch-up banner ------------------------------------------------ */
.catchup{background:var(--card);border:1px solid var(--warn);border-radius:16px;
  padding:1.15rem 1.25rem;margin-bottom:1rem;box-shadow:var(--shadow)}
.catchup .head{display:flex;align-items:center;gap:.75rem}
.catchup h3{margin:0;flex:1}
.spinner{width:1.15rem;height:1.15rem;border:2px solid var(--border-strong);
  border-top-color:var(--warn);border-radius:50%;flex:0 0 auto;
  animation:turn .8s linear infinite}
@keyframes turn{to{transform:rotate(360deg)}}
@media(prefers-reduced-motion:reduce){.spinner{animation:none;border-top-color:var(--border-strong)}}
.catchup .progress{height:6px;border-radius:3px;background:var(--card-2);
  margin:.9rem 0 .5rem;overflow:hidden;border:1px solid var(--border)}
.catchup .progress i{display:block;height:100%;width:0;border-radius:3px;
  background:linear-gradient(90deg,var(--warn),var(--accent));transition:width .5s ease}
.catchup .figures{display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;
  font-family:var(--mono);font-size:.78rem;color:var(--soft);
  font-variant-numeric:tabular-nums}
.catchup p{margin:.7rem 0 0;font-size:.86rem;color:var(--soft)}
.sync-gauge{height:2px;background:var(--border)}
.sync-gauge i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--quantum));
  transition:width .4s ease}

/* ---- Body: rail + content ---------------------------------------------- */
.content{max-width:1180px;width:100%;margin:0 auto;padding:1.1rem 1rem 5.5rem;
  display:grid;gap:1.4rem;grid-template-columns:1fr;flex:1}
@media(min-width:900px){
  .content{grid-template-columns:var(--rail) 1fr;padding-bottom:2.5rem;gap:2rem}
}

/* Navigation: a bottom bar on a phone, a column on the left beyond that. */
nav.tabs{
  position:fixed;left:0;right:0;bottom:0;z-index:30;display:flex;
  background:color-mix(in srgb,var(--bg) 92%,transparent);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border-top:1px solid var(--border);padding:.3rem .3rem calc(.3rem + env(safe-area-inset-bottom));
}
nav.tabs button{
  flex:1;display:flex;flex-direction:column;align-items:center;gap:.15rem;
  background:none;border:none;color:var(--muted);font:inherit;font-size:.68rem;
  padding:.45rem .2rem;border-radius:10px;cursor:pointer;letter-spacing:.01em}
nav.tabs button svg{width:1.25rem;height:1.25rem;stroke:currentColor;fill:none;
  stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
nav.tabs button:hover{color:var(--soft)}
nav.tabs button.active{color:var(--accent)}
@media(min-width:900px){
  nav.tabs{position:sticky;top:4.6rem;align-self:start;flex-direction:column;
    background:none;backdrop-filter:none;-webkit-backdrop-filter:none;
    border:none;padding:0;gap:.15rem}
  nav.tabs button{flex-direction:row;justify-content:flex-start;gap:.7rem;
    font-size:.9rem;padding:.6rem .8rem;width:100%}
  nav.tabs button.active{background:var(--accent-bg);font-weight:600}
}

main{min-width:0}
section.view{animation:enter .18s ease}
@keyframes enter{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
@media(prefers-reduced-motion:reduce){section.view{animation:none}}

h2{font-size:.74rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);
  font-weight:600;margin:1.8rem 0 .7rem}
h2:first-child{margin-top:0}
h3{font-size:.95rem;margin:0 0 .4rem;font-weight:600}
p{margin:0 0 .8rem}
.help{font-size:.82rem;color:var(--muted);margin:.35rem 0 0}

/* ---- Cards -------------------------------------------------------------- */
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;
  padding:1.15rem 1.25rem;box-shadow:var(--shadow)}
.card+.card{margin-top:.8rem}

/* The balance: the only place where a gradient is allowed. */
.hero{background:var(--card);border:1px solid var(--border);border-radius:20px;
  padding:1.6rem 1.5rem;box-shadow:var(--shadow);position:relative;overflow:hidden}
.hero::after{content:"";position:absolute;inset:auto -30% -70% auto;width:70%;aspect-ratio:1;
  background:radial-gradient(circle,var(--accent-bg),transparent 70%);opacity:.7;pointer-events:none}
.hero .k{font-size:.7rem;text-transform:uppercase;letter-spacing:.11em;color:var(--muted);
  font-weight:600}
.big{font-family:var(--mono);font-size:clamp(2.2rem,9vw,3.4rem);line-height:1.02;
  letter-spacing:-.045em;font-variant-numeric:tabular-nums;display:inline-block;
  word-break:break-all;font-weight:600;
  background:linear-gradient(100deg,var(--text) 30%,var(--accent));
  -webkit-background-clip:text;background-clip:text;color:transparent}
/* The text gradient is painted on `.big`: a child left with
   `color:transparent` would have no background to clip and would vanish. The
   decimals therefore take back a solid color, explicitly. */
.cents{font-size:.52em;letter-spacing:-.02em;color:var(--muted);
  -webkit-text-fill-color:var(--muted)}
.unit{font-family:var(--mono);font-size:.78rem;color:var(--muted);margin-left:.5rem;
  letter-spacing:.08em;font-weight:600}
.hero .n{color:var(--soft);font-size:.86rem;margin-top:.5rem;position:relative;z-index:1}

.grid{display:grid;gap:.7rem;grid-template-columns:1fr}
@media(min-width:560px){.grid{grid-template-columns:repeat(auto-fit,minmax(196px,1fr))}}
.tile{background:var(--card);border:1px solid var(--border);border-radius:14px;
  padding:.85rem 1rem;box-shadow:var(--shadow)}
.tile .k{font-size:.66rem;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
  font-weight:600}
.tile .v{font-size:1.1rem;font-family:var(--mono);margin-top:.25rem;font-weight:600;
  font-variant-numeric:tabular-nums;word-break:break-all;letter-spacing:-.02em}
.tile .n{font-size:.75rem;color:var(--soft);margin-top:.3rem}
.tile.highlight{border-color:var(--accent);background:var(--card-2)}
.tile.highlight .v{color:var(--accent)}

/* ---- Mining ------------------------------------------------------------- */
.switch-row{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
.switch-row .title{flex:1;min-width:11rem}
.switch-row .title h3{margin:0}
.switch-row .title p{margin:.15rem 0 0;color:var(--muted);font-size:.83rem}
.switch{position:relative;width:3.4rem;height:1.95rem;border-radius:999px;flex:0 0 auto;
  border:1px solid var(--border-strong);background:var(--card-2);cursor:pointer;padding:0;
  transition:background .18s,border-color .18s}
.switch i{position:absolute;top:.22rem;left:.24rem;width:1.4rem;height:1.4rem;border-radius:50%;
  background:var(--muted);transition:transform .18s,background .18s}
.switch[aria-pressed="true"]{background:var(--accent);border-color:var(--accent)}
.switch[aria-pressed="true"] i{transform:translateX(1.42rem);background:#04120d}
.switch:disabled{opacity:.4;cursor:not-allowed}
.switch:focus-visible{outline:3px solid var(--accent-bg);outline-offset:2px}
@media(prefers-reduced-motion:reduce){.switch,.switch i{transition:none}}

/* --- The balance's quick actions ----------------------------------------- */
.quick{display:flex;gap:.7rem;margin-top:1.2rem;position:relative;z-index:1}
.quick button{flex:1;display:flex;align-items:center;justify-content:center;gap:.5rem;
  font:inherit;font-weight:600;font-size:.9rem;padding:.75rem 1rem;cursor:pointer;
  border-radius:12px;border:1.5px solid var(--border);background:var(--card-2);
  color:var(--text);transition:border-color .15s}
.quick button:hover{border-color:var(--accent)}
.quick button svg{width:1.1rem;height:1.1rem;stroke:var(--accent);fill:none;
  stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.quick button:focus-visible{outline:3px solid var(--accent-bg);outline-offset:2px}

/* --- The log of blocks found --------------------------------------------- */
.find{display:flex;align-items:center;gap:.85rem;padding:.7rem .9rem;
  border:1px solid var(--border);border-radius:12px;background:var(--card);
  box-shadow:var(--shadow)}
.find+.find{margin-top:.5rem}
.find .icon{width:2.1rem;height:2.1rem;border-radius:10px;flex:0 0 auto;
  display:grid;place-items:center;background:var(--accent-bg)}
.find .icon svg{width:1.15rem;height:1.15rem;stroke:var(--accent);fill:none;
  stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.find .what{flex:1;min-width:0}
.find .what a{color:var(--text);font-weight:600;text-decoration:none;
  border-bottom:1px solid var(--border-strong)}
.find .what a:hover{border-bottom-color:var(--accent);color:var(--accent)}
.find .what .when{font-size:.76rem;color:var(--muted);margin-top:.1rem}
.find .gain{font-family:var(--mono);font-weight:600;color:var(--accent);
  font-variant-numeric:tabular-nums;white-space:nowrap}
.find.fresh{animation:land .5s ease}
@keyframes land{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
@media(prefers-reduced-motion:reduce){.find.fresh{animation:none}}

/* --- Activity: rows that read at a glance -------------------------------- */
td .dir{display:inline-grid;place-items:center;width:1.6rem;height:1.6rem;
  border-radius:8px;vertical-align:middle}
td .dir svg{width:.95rem;height:.95rem;fill:none;stroke-width:2;
  stroke-linecap:round;stroke-linejoin:round}
td .dir.in{background:var(--accent-bg)}td .dir.in svg{stroke:var(--accent)}
td .dir.out{background:var(--danger-bg)}td .dir.out svg{stroke:var(--danger)}
td .dir.mine{background:var(--quantum-bg)}td .dir.mine svg{stroke:var(--quantum)}
td.plus{color:var(--accent);font-weight:600}
td.minus{color:var(--danger);font-weight:600}

.rate{display:flex;align-items:baseline;gap:.4rem;margin-top:1rem}
.rate .n{font-family:var(--mono);font-size:2rem;font-weight:600;letter-spacing:-.04em;
  font-variant-numeric:tabular-nums;color:var(--accent)}
.rate .u{font-size:.8rem;color:var(--muted)}
.sparkline{width:100%;height:52px;margin-top:.5rem;display:block}
.sparkline path{fill:none;stroke:var(--accent);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.sparkline .area{fill:var(--accent-bg);stroke:none}

/* ---- Addresses ---------------------------------------------------------- */
.address{background:var(--card);border:1px solid var(--border);border-radius:14px;
  padding:.8rem .95rem;display:flex;gap:.75rem;align-items:center;box-shadow:var(--shadow)}
.address+.address{margin-top:.55rem}
.address .txt{flex:1;min-width:0;font-family:var(--mono);font-size:.82rem;
  word-break:break-all;line-height:1.45}
.address .index{font-family:var(--mono);font-size:.68rem;color:var(--muted);
  border:1px solid var(--border);border-radius:7px;padding:.15rem .4rem;flex:0 0 auto}
.address.fresh{border-color:var(--accent);background:var(--card-2)}
/* The address to give, on its own: one unbroken line of text, so that a
   selection by hand copies it whole, without the spaces of a grouped display. */
#my-address .address{border-color:var(--accent);background:var(--card-2)}
#my-address .txt{font-size:.9rem;user-select:all}
#my-address .buttons{margin-top:.6rem;align-items:center}
/* An address book row has two levels: the name given by the owner, then the
   address itself. The name comes first because it is what the eye looks for
   — the address gets copied, not read. */
.address{flex-wrap:wrap}
.address .content{flex:1;min-width:0}
.address .name{font-family:var(--sans);font-size:.85rem;font-weight:600;color:var(--text);
  margin-bottom:.15rem}
.address .name.empty{font-weight:400;color:var(--muted);font-style:italic}
.address .edit{flex:0 0 100%;display:flex;gap:.5rem;margin-top:.5rem}
[hidden]{display:none !important}
.address .edit input{flex:1;font-family:var(--sans);font-size:.85rem}
/* The activity filters. Only one is active at a time, and the word carries
   the state: the color only repeats it, for those who cannot tell it apart. */
.filters{display:flex;flex-wrap:wrap;gap:.4rem;margin:.9rem 0}
.filters button.active{background:var(--accent-bg);color:var(--accent);
  border-color:var(--accent)}
.search-box{margin:1rem 0}
.search-box input[type=search]{width:100%;padding:.7rem .85rem;font:inherit;font-size:.9rem;
  color:var(--text);background:var(--card-2);border:1.5px solid var(--border);
  border-radius:11px;outline:none}
.search-box input[type=search]:focus{border-color:var(--accent)}

/* ---- Controls ----------------------------------------------------------- */
label{display:block;font-size:.8rem;font-weight:600;margin:1rem 0 .35rem;color:var(--soft)}
input[type=text],input[type=password]{
  width:100%;padding:.7rem .85rem;font:inherit;font-family:var(--mono);font-size:.9rem;
  color:var(--text);background:var(--card-2);border:1.5px solid var(--border);
  border-radius:11px;outline:none}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-bg)}
.buttons{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1rem}
button.action,button.secondary,button.flat{
  font:inherit;font-weight:600;font-size:.9rem;border-radius:11px;cursor:pointer;
  padding:.68rem 1.1rem;border:1.5px solid transparent;transition:filter .15s}
button.action{background:var(--accent);color:#04120d;border-color:var(--accent)}
button.action:hover:not(:disabled){filter:brightness(1.08)}
button.action:disabled{opacity:.45;cursor:not-allowed}
button.secondary{background:transparent;color:var(--soft);border-color:var(--border-strong)}
button.secondary:hover{color:var(--text);border-color:var(--muted)}
button.flat{background:var(--card-2);color:var(--soft);border-color:var(--border);
  padding:.42rem .7rem;font-size:.78rem}
button.flat:hover{color:var(--text)}
button:focus-visible{outline:3px solid var(--accent-bg);outline-offset:2px}
a.flat{color:var(--accent);text-decoration:none;border-bottom:1px solid var(--accent-bg)}
a.flat:hover{border-bottom-color:var(--accent)}

/* ---- Callouts ----------------------------------------------------------- */
.note,.warn{border-radius:14px;padding:.9rem 1.05rem;margin:1rem 0;font-size:.87rem}
.note{background:var(--card-2);border:1px solid var(--border);color:var(--soft)}
.warn{background:var(--warn-bg);border-left:3px solid var(--warn);color:var(--soft)}
.warn h3{color:var(--warn)}
.note h3{color:var(--text)}
.note p:last-child,.warn p:last-child{margin-bottom:0}

/* ---- Table -------------------------------------------------------------- */
.scroll{overflow-x:auto;border:1px solid var(--border);border-radius:14px;background:var(--card);
  box-shadow:var(--shadow)}
table{width:100%;border-collapse:collapse;font-size:.83rem}
th,td{text-align:left;padding:.6rem .8rem;border-bottom:1px solid var(--border);white-space:nowrap}
thead th{font-size:.66rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
  font-weight:600;background:var(--card-2)}
tbody tr:last-child td{border-bottom:none}
/* The reference column carries the full hash. It overrides the table's
   `nowrap`: sixty-four characters on a single line would push every other
   column off the screen, whereas here breaking at any character is harmless
   — a hash has neither words nor reading direction. */
td.ref{white-space:normal;word-break:break-all;max-width:23ch;font-size:.72rem;
  line-height:1.4}
td.ref .full{display:block;color:var(--soft)}
td.ref button.flat{margin-top:.3rem;padding:.2rem .5rem;font-size:.7rem}
/* The same full hash in a tile, where the value font is large. */
.tile .full{display:block;font-family:var(--mono);font-size:.7rem;line-height:1.4;
  word-break:break-all;color:var(--soft)}
.tile button.flat{margin-top:.35rem;padding:.2rem .5rem;font-size:.7rem}
td{font-family:var(--mono);font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:.1rem .45rem;border-radius:6px;font-size:.7rem;
  font-weight:600;background:var(--accent-bg);color:var(--accent);font-family:var(--sans)}
.badge.pending{background:var(--warn-bg);color:var(--warn)}
.badge.gray{background:var(--card-2);color:var(--muted)}
/* The spinning disc of a transaction still in the mempool. It lives in the
   badge, takes the text color, and disappears with it as soon as a block
   confirms. A machine set to reduce animations will only see a still arc —
   the information is carried by the word, not by the motion. */
.spin-dot{display:inline-block;width:.62em;height:.62em;margin-right:.3em;
  vertical-align:-.05em;border:2px solid currentColor;border-right-color:transparent;
  border-radius:50%;animation:spinning .9s linear infinite}
@keyframes spinning{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion: reduce){.spin-dot{animation:none}}

details.fold{background:var(--card-2);border:1px solid var(--border);border-radius:14px;
  padding:.85rem 1.05rem;margin:1rem 0;font-size:.87rem;color:var(--soft)}
details.fold summary{cursor:pointer;font-weight:600;color:var(--text);
  list-style-position:inside}
details.fold summary:hover{color:var(--accent)}
details.fold[open] summary{margin-bottom:.5rem}
details.fold p{margin:0 0 .6rem}
details.fold p:last-child{margin-bottom:0}

.recap{background:var(--card-2);border:1px solid var(--border);border-radius:14px;
  padding:1rem;font-family:var(--mono);font-size:.85rem;word-break:break-all}
footer{margin-top:2.4rem;padding-top:1rem;border-top:1px solid var(--border);
  color:var(--muted);font-size:.76rem}
code{background:var(--quantum-bg);color:var(--quantum);padding:.12em .38em;border-radius:5px;
  font-size:.85em;font-family:var(--mono)}
.err{color:var(--danger)}
.ok{color:var(--accent)}

/* --- Language choice -----------------------------------------------------
   Three flags in the header. One click is enough: the page translates in
   place, without reloading and without a round trip to the node. */
.languages{display:flex;gap:.25rem;align-items:center;margin-left:.75rem}
.languages button{background:transparent;border:1px solid transparent;border-radius:.4rem;
  cursor:pointer;font-size:1.05rem;line-height:1;padding:.22rem .3rem;opacity:.5;
  transition:opacity .15s,border-color .15s,background .15s}
.languages button:hover{opacity:.9;background:rgba(255,255,255,.07)}
.languages button[aria-pressed="true"]{opacity:1;border-color:rgba(255,255,255,.28);
  background:rgba(255,255,255,.10)}
.languages button:focus-visible{outline:2px solid #4ade80;outline-offset:1px}
</style>
</head>
<body>
<div class="shell">

<header>
  <div class="bar">
    <div class="logo">
      <span class="mark" aria-hidden="true">Q21</span>
      <h1>Wallet <span class="net-tag" id="network">…</span></h1>
    </div>
    <div class="push pulse" id="pulse" role="status" aria-live="polite">
      <span class="dot" id="sync-dot"></span>
      <b id="pulse-state">Connecting…</b>
      <span id="pulse-text"></span>
    </div>
    <div class="languages" id="languages" role="group" aria-label="Language">
      <button type="button" data-lang="en" aria-pressed="true" title="English">&#127482;&#127480;</button>
      <button type="button" data-lang="fr" aria-pressed="false" title="Français">&#127467;&#127479;</button>
      <button type="button" data-lang="ja" aria-pressed="false" title="&#26085;&#26412;&#35486;">&#127471;&#127477;</button>
    </div>
  </div>
  <div class="sync-gauge"><i id="sync-gauge"></i></div>
</header>

<div class="content">

<nav class="tabs" id="tabs" aria-label="Wallet sections">
  <button type="button" data-view="balance" class="active">
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7h18v12H3z"/><path d="M3 7l4-3h10l4 3"/><circle cx="16" cy="13" r="1.6"/></svg>
    Balance</button>
  <button type="button" data-view="mine">
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M13 2L4 14h6l-1 8 9-12h-6z"/></svg>
    Mine</button>
  <button type="button" data-view="receive">
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v13"/><path d="M6 12l6 6 6-6"/><path d="M4 20h16"/></svg>
    Receive</button>
  <button type="button" data-view="send">
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20V7"/><path d="M6 12l6-6 6 6"/><path d="M4 4h16"/></svg>
    Send</button>
  <button type="button" data-view="network">
    <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18"/></svg>
    Network</button>
  <button type="button" data-view="activity">
    <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
    Activity</button>
  <button type="button" data-view="info">
    <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/></svg>
    Info</button>
</nav>

<main>

<div id="token-panel" class="warn" hidden>
  <h3>Access token required</h3>
  <p>
    The node requires a token. The launcher normally passes it in the address
    fragment; if you opened this page manually, enter the token given to
    <code>--rpc-token</code>.
  </p>
  <form id="token-form" class="buttons" autocomplete="off">
    <input type="password" id="token-input" placeholder="access token" autocomplete="off" spellcheck="false">
    <button type="submit" class="action" style="margin-top:0">Unlock</button>
  </form>
</div>

<div id="error" class="warn" hidden>
  <h3>Node unreachable</h3>
  <p id="error-detail"></p>
</div>

<div id="sync-banner" class="catchup" hidden>
  <div class="head">
    <span class="spinner" aria-hidden="true"></span>
    <h3 id="catchup-title">Catching up on chain history</h3>
  </div>
  <div id="catchup-measure">
    <div class="progress"><i id="catchup-bar"></i></div>
    <div class="figures">
      <span id="catchup-position">—</span>
      <span id="catchup-speed">—</span>
    </div>
  </div>
  <p id="sync-note"></p>
  <p id="catchup-restored" hidden>
    <strong>If you have just restored a wallet</strong>, your funds will
    reappear at the end of this step: they are in the chain, and your machine
    has not read them yet. The displayed balance is incomplete until then.
  </p>
  <p id="sync-detail"></p>
</div>

<section class="view" id="view-balance">
  <div class="hero">
    <div class="k">Available</div>
    <div id="balance-big">…</div>
    <div class="n" id="balance-note">Loading…</div>
    <div class="quick">
      <button type="button" data-go="receive">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v13"/><path d="M6 12l6 6 6-6"/><path d="M4 20h16"/></svg>
        Receive</button>
      <button type="button" data-go="send">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20V7"/><path d="M6 12l6-6 6 6"/><path d="M4 4h16"/></svg>
        Send</button>
      <button type="button" data-go="mine">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M13 2L4 14h6l-1 8 9-12h-6z"/></svg>
        Mine</button>
    </div>
  </div>
  <h2>Details</h2>
  <div class="grid" id="balance-tiles"></div>
  <div class="note">
    <h3>Why part of the balance is immature</h3>
    <p>
      A mining reward can only be spent after a long maturity period. Until it
      has elapsed, the amount exists and belongs to you, but no transaction can
      spend it. It is counted separately rather than folded into a total that
      would be wrong.
    </p>
  </div>
</section>

<section class="view" id="view-mine" hidden>
  <h2>Mining</h2>
  <div class="card">
    <div class="switch-row">
      <div class="title">
        <h3 id="mining-title">Your machine is not mining</h3>
        <p id="mining-sub">Mining searches for the next block. It uses all CPU cores.</p>
      </div>
      <button type="button" class="switch" id="mining-switch" aria-pressed="false"
              aria-label="Turn mining on"><i></i></button>
    </div>
    <div class="rate">
      <span class="n" id="mining-rate">0</span>
      <span class="u">attempts per second</span>
    </div>
    <svg class="sparkline" id="mining-sparkline" viewBox="0 0 300 52" preserveAspectRatio="none"
         role="img" aria-label="Mining rate over the last few minutes"></svg>
    <div class="grid" style="margin-top:1rem">
      <div class="tile highlight"><div class="k">Earned by mining</div><div class="v" id="mining-earned">0</div>
        <div class="n">since launch, including immature rewards</div></div>
      <div class="tile"><div class="k">Blocks found</div><div class="v" id="mining-blocks">0</div>
        <div class="n">since launch</div></div>
      <div class="tile"><div class="k">Attempts</div><div class="v" id="mining-total">0</div>
        <div class="n">since launch</div></div>
      <div class="tile"><div class="k">Chain pace</div><div class="v" id="sync-speed">—</div>
        <div class="n" id="speed-note">target: one block every 2 minutes</div></div>
      <div class="tile"><div class="k">Memory in use</div><div class="v" id="mining-memory">—</div>
        <div class="n" id="mining-memory-note">the computation table, in RAM</div></div>
    </div>
  </div>

  <h2>Your blocks</h2>
  <div id="mining-finds"></div>
  <div class="note">
    <h3>What your machine does when this switch is on</h3>
    <p>
      It searches a two-gigabyte table in memory, hundreds of thousands of
      times per second, looking for a value that meets the current difficulty.
      It is a lottery: you do not win every time, and you win more often the
      faster you search.
    </p>
    <p>
      The reward for a block found is paid to an address in this wallet. It
      can only be spent after the maturity period.
    </p>
  </div>
</section>

<section class="view" id="view-receive" hidden>
  <h2>Receive</h2>
  <div class="card" id="my-address-card">
    <h3>Your address</h3>
    <p class="help">This is what you give to someone who wants to send you Q21 —
      what is usually called your “wallet address”.</p>
    <div id="my-address"><p class="help">Loading…</p></div>
  </div>
  <div class="note">
    <h3>Which address should I give?</h3>
    <p>
      The one above. Every address of this wallet stays valid forever: a
      payment sent to an older one still arrives here, even years later.
    </p>
    <p>
      To check that a payment has arrived, open the address in the explorer:
      it shows what it received, even before the next block.
    </p>
  </div>
  <p class="help">
    Every payment deserves a fresh address. Reusing one costs the protocol
    nothing, but publicly links your payments together.
  </p>
  <div class="buttons">
    <button type="button" class="action" id="new-address-button">New address</button>
  </div>
  <div id="new-address-zone"></div>
  <h2>Your addresses</h2>
  <div class="note">
    <h3>Why you have several</h3>
    <p>
      Your wallet holds <strong>only one secret</strong>: the seed, the one
      behind the backup code you wrote down. All your addresses are
      <em>built</em> from it by computation — the first, the second, the
      thousandth. This is called <strong>derivation</strong>.
    </p>
    <p>
      A reassuring consequence: <strong>this code restores everything</strong>.
      No need to back up each address; they can all be recomputed from it.
    </p>
    <p>
      A useful consequence: giving a fresh one to each person who pays you
      costs nothing, and keeps an onlooker from linking all your incoming
      payments together by reading the chain. Your balance is the sum of them
      all.
    </p>
    <p>
      Mining also derives one per block found, for the same reason. Those
      addresses have already received their reward and need not be handed
      out: they are tucked away below, and only the ones you requested or
      named are shown.
    </p>
  </div>
  <div class="search-box">
    <label for="address-filter">Search your address book</label>
    <input id="address-filter" type="search" autocomplete="off" spellcheck="false"
           placeholder="a name, a number (#12) or part of an address">
    <p class="help" id="address-count"></p>
    <div class="buttons" id="mining-zone" hidden>
      <button type="button" class="flat" id="mining-addresses-button">Also show the mining addresses</button>
    </div>
  </div>
  <div id="address-list"></div>
  <div class="buttons" id="more-zone" hidden>
    <button type="button" class="flat" id="more-button">Show more</button>
  </div>
</section>

<section class="view" id="view-send" hidden>
  <h2>Send Q21</h2>
  <div class="card">
  <form id="send-form" autocomplete="off">
    <label for="address-field">Recipient address</label>
    <input type="text" id="address-field" placeholder="tq21…" spellcheck="false" autocomplete="off">
    <div class="help">The address has a checksum: a typo will be caught by the node, not silently accepted.</div>

    <label for="amount-field">Amount (Q21)</label>
    <input type="text" id="amount-field" placeholder="0.00000000" inputmode="decimal" spellcheck="false" autocomplete="off">
    <div class="help" id="amount-help">At most eight decimal places. One unit is 0.00000001 Q21.</div>

    <div id="extra-recipients"></div>
    <div class="buttons">
      <button type="button" class="secondary" id="add-recipient-button">+ Add a recipient</button>
    </div>
    <div class="help">One payment can go to several recipients at once: a single transaction with a shared fee, rather than several separate payments.</div>

    <label for="fee-field">Fee (Q21)</label>
    <input type="text" id="fee-field" placeholder="0.00000000" inputmode="decimal" spellcheck="false" autocomplete="off">
    <div class="help" id="fee-help">Suggested by the node; you can change it.</div>

    <label for="inputs-field">Expected inputs, for the fee estimate</label>
    <input type="text" id="inputs-field" value="2" inputmode="numeric" spellcheck="false" autocomplete="off">
    <div class="help">
      With ML-DSA-87 the witness makes up almost all of a transaction: the
      fee depends mostly on the <em>number of inputs</em> consumed, which the
      node only picks when it builds the transaction. If the payment is
      rejected because the fee rate is too low, increase this number and
      recalculate.
    </div>
    <div class="buttons">
      <button type="button" class="secondary" id="estimate-button">Recalculate fee</button>
      <button type="submit" class="action" id="review-button">Review</button>
    </div>
  </form>
  </div>

  <div id="confirmation" hidden>
    <h2>Confirm the payment</h2>
    <div class="warn">
      <h3>A payment is final</h3>
      <p>
        No authority can reverse an accepted transaction. Re-read the address
        character by character: it is the only check you have left.
      </p>
    </div>
    <div class="recap" id="recap"></div>
    <div class="buttons">
      <button type="button" class="secondary" id="cancel-button">Back</button>
      <button type="button" class="action" id="send-button">Send now</button>
    </div>
  </div>

  <div id="send-result"></div>
</section>

<section class="view" id="view-network" hidden>
  <h2>The network</h2>
  <div class="card">
    <div class="switch-row">
      <div class="title">
        <h3 id="reachable-title">Your wallet helps the network</h3>
        <p id="reachable-sub">It accepts connections from others, so the network does not rely on a single machine.</p>
      </div>
      <button type="button" class="switch" id="reachable-switch" aria-pressed="false"
              aria-label="Make this node reachable"><i></i></button>
    </div>
    <div class="n" id="reachable-state" style="margin-top:.4rem"></div>
    <div class="note">
      <h3>What this setting does</h3>
      <p>
        When it is on, your wallet asks your router to open its port, and
        becomes an entry point to the network: others can connect to you. This
        is what lets the network live without depending on a single server.
        Most routers open the port on their own.
      </p>
      <p>
        In return, your <strong>IP address becomes visible</strong> to other
        nodes — that is how a peer-to-peer network normally works. If you would
        rather stay a plain client, turn it off: your wallet works exactly the
        same, using the nodes that others keep open.
      </p>
      <p>It is off by default: turn it on only if you accept that other nodes see your address.</p>
      <p>A change <strong>takes effect the next time</strong> the wallet starts.</p>
    </div>
  </div>
  <div class="hero">
    <div class="k">Network hash rate</div>
    <div id="network-big">…</div>
    <div class="n" id="network-note">Measuring…</div>
  </div>
  <div class="grid" style="margin-top:.8rem">
    <div class="tile"><div class="k">Your machine</div>
      <div class="v" id="network-mine">—</div>
      <div class="n" id="network-share">measured on your machine, live</div></div>
    <div class="tile"><div class="k">Computers connected to yours</div>
      <div class="v" id="network-peers">0</div>
      <div class="n">your direct neighbors, not the whole network</div></div>
  </div>
  <div class="note">
    <h3>Why we don't tell you “how many miners”</h3>
    <p>
      Because nobody can know, and a made-up figure would be worse than no
      figure at all. A miner does not announce itself: it just produces
      blocks. Nothing distinguishes a thousand machines from one person who
      owns a thousand.
    </p>
    <p>
      And Q21 makes counting even harder, on purpose: your wallet uses
      <strong>a different address for each reward</strong>, so that your
      earnings cannot be linked together. Counting miner addresses would
      amount to counting blocks.
    </p>
    <p>
      What can be measured, on the other hand, cannot be faked: <strong>the
      work actually spent</strong>. It can be read from the difficulty, which
      adjusts so that a block is found every two minutes. Compared with what
      <em>your</em> machine does, it gives your share, shown above.
    </p>
  </div>
</section>

<section class="view" id="view-activity" hidden>
  <h2>Activity</h2>
  <div id="activity-note"></div>
  <div class="filters" id="activity-filters" role="group" aria-label="Show only">
    <button type="button" class="flat active" data-filter="all">All</button>
    <button type="button" class="flat" data-filter="mining">Mining</button>
    <button type="button" class="flat" data-filter="receive">Received</button>
    <button type="button" class="flat" data-filter="send">Sent</button>
  </div>
  <div class="scroll">
    <table>
      <thead><tr><th>Type</th><th>Received</th><th>Sent</th><th>Confirmations</th><th>Block</th><th>Date</th><th>Reference</th></tr></thead>
      <tbody id="movements"></tbody>
    </table>
  </div>
  <div class="buttons" id="activity-more-zone" hidden>
    <button type="button" class="flat" id="activity-more-button">Show older movements</button>
  </div>
  <div id="columns-note"></div>
</section>

<section class="view" id="view-info" hidden>
  <h2>Your security</h2>
  <div class="card">
    <div class="switch-row">
      <div class="title">
        <h3>The backup code is your wallet</h3>
        <p>The file on this disk is only a working copy.</p>
      </div>
    </div>
    <p style="margin-top:.8rem">
      Your entire wallet — every address, all your funds — can be rebuilt
      from the single backup code you wrote down when you created it.
      <strong>On any machine: Windows, Intel Mac, Apple
      Silicon Mac, Linux, Raspberry Pi.</strong> You enter it there with
      “I already have a backup code”, and the chain does the rest —
      verified by a full restore test on all five platforms we build for.
    </p>
    <div class="note warn" style="margin-bottom:0">
      <h3>Two things you must never do</h3>
      <p>Do not photograph the code, and do not paste it into a cloud service:
      whoever reads it holds your funds, for good. And do not confuse the code
      with your <strong>passphrase</strong> — which only protects the
      file on <em>this</em> machine, and can be different elsewhere.</p>
    </div>
  </div>

  <h2>Wallet</h2>
  <div class="grid" id="info-tiles"></div>
  <details class="fold">
    <summary>ML-DSA-87 (FIPS&nbsp;204, NIST level&nbsp;5) — why it resists quantum computers</summary>
    <p>
      This wallet's signatures rest on ML-DSA, the lattice-based scheme
      standardized by NIST in 2024 as FIPS&nbsp;204. Q21 uses the strongest
      parameter set, ML-DSA-87, whose target security matches level&nbsp;5 —
      on the order of AES-256.
    </p>
    <p>
      This is what sets the project apart. The ECDSA signatures that protect
      most chains today fall to Shor's algorithm as soon as a large enough
      quantum computer exists; these rest on no problem that Shor's algorithm
      solves. The price shows in the figures above: a 2,592-byte public key
      and a 4,627-byte signature, where ECDSA needs a few dozen bytes.
    </p>
    <p>
      The core does not implement this scheme itself: writing your own
      lattice-based signature would be professional malpractice. It plugs in
      an audited implementation.
    </p>
  </details>
  <h2>Chain</h2>
  <div class="grid" id="chain-tiles"></div>

  <details class="fold">
    <summary>For developers</summary>
    <p>
      The node serves a JSON-RPC API at <code>POST /rpc</code> —
      <code>listmethods</code> lists the methods. The session access token
      is sent as <code>Authorization: Bearer</code>; it never leaves
      this page. Nothing else is written to the browser except the token and
      the language choice, both cleared when the tab closes. The explorer
      and the wallet are served by the same process, on the same port, with
      no external resource.
    </p>
  </details>

  <h2>Close</h2>
  <div class="note">
    <p>
      This wallet is served by a node running in the window the launcher
      opened. This button asks it to shut down cleanly: it writes out the
      mempool, the state snapshot and the wallet, then exits.
    </p>
    <p>
      This is the recommended way to stop. Closing the launcher window also
      works. <strong>Ctrl-C</strong> works too, but Windows then asks its own
      question — “Terminate batch job (Y/N)?”: answer <strong>Y</strong>;
      everything has already been saved by then.
    </p>
    <div class="buttons">
      <button type="button" class="action" id="close-button" style="margin-top:0">Close the wallet</button>
    </div>
    <p id="close-note" class="help"></p>
  </div>
</section>

<footer>
  <p style="margin:0 0 .6rem">
    <a class="flat" id="explorer-link" href="/">Chain explorer</a> —
    everything your node has verified, browsable without trusting anyone.
  </p>
  Testnet — the Q21 mined here have no value, and never will. Research
  software, not externally audited.
</footer>

</main>
</div>
</div>

<script>
/* =======================================================================
   Languages — English (source), French, Japanese
   =======================================================================

   The page is written in English. Rather than scatter translation
   identifiers across several hundred places — which would have missed all
   the text the script builds at run time — it is translated by matching the
   source text.

   Each text node keeps its English original. Switching language replaces
   it; going back to English restores it. A mutation observer covers what the
   script writes afterwards, so that a translation is not lost at the first
   data refresh.

   What is not translated stays in English, never empty: a sentence in the
   wrong language can be understood, a missing sentence cannot.

   Nothing leaves the page: no translation service, no request.
*/
const I18N = {"fr": {"Your router did not open the port: your wallet stays a client.": "Votre box n'a pas ouvert l'accès\u00a0: votre portefeuille reste un simple client.", "Your router opened the port (NAT-PMP).": "Votre box a ouvert l'accès (NAT-PMP).", "Your router opened the port (UPnP).": "Votre box a ouvert l'accès (UPnP).", "Your router opened the port.": "Votre box a ouvert l'accès.", "It is off by default: turn it on only if you accept that other nodes see your address.": "Il est éteint par défaut\u00a0: ne l'allumez que si vous acceptez que les autres nœuds voient votre adresse.", "Syncing": "Synchronisation", "Offline": "Hors connexion", "Your wallet helps the network": "Votre portefeuille aide le réseau", "Your wallet is client-only": "Votre portefeuille est un simple client", "It accepts connections from others, so the network does not rely on a single machine.": "Il accepte les connexions des autres, pour que le réseau ne dépende pas d'une seule machine.", "It reaches out to the network but does not accept incoming connections.": "Il sort vers le réseau, mais n'accepte pas de connexions entrantes.", "Make this node reachable": "Rendre ce nœud joignable", "Stop being reachable": "Ne plus être joignable", "What this setting does": "Ce que fait ce réglage", "Your node will be reachable the next time the wallet starts.": "Votre nœud sera joignable au prochain lancement du portefeuille.", "Your node will be client-only the next time the wallet starts.": "Votre nœud sera un simple client au prochain lancement du portefeuille.", "No bootstrap address: this node is not looking for anyone": "Aucune adresse de départ : ce nœud ne cherche personne", "The program contains no server address, and that is deliberate: an address hard-coded into distributed software would become a permanent dependency on whoever controls it. It is provided separately, in a file you can edit. Create q21-data/bootstrap.txt next to the program, add the line bootstrap.q21.dev:21121 to it, then restart. JOIN.md, which ships with the program, explains this step and how to add more entry points.": "Le programme ne contient l'adresse d'aucun serveur, et c'est voulu : une adresse gravée dans un logiciel distribué deviendrait une dépendance permanente envers celui qui la tient. Elle se donne à côté, dans un fichier que vous pouvez modifier. Créez q21-data/bootstrap.txt auprès du programme, écrivez-y la ligne bootstrap.q21.dev:21121, puis relancez. JOIN.md, livré avec le programme, détaille ce geste et la façon d'ajouter d'autres points d'entrée.", "Hide the mining addresses": "Ranger les adresses de minage", "Mining also derives one per block found, for the same reason. Those addresses have already received their reward and need not be handed out: they are tucked away below, and only the ones you requested or named are shown.": "Le minage en dérive aussi une par bloc trouvé, pour la même raison. Ces adresses-là ont déjà reçu leur récompense et n'ont pas besoin d'être distribuées\u00a0: elles sont rangées ci-dessous, et seules celles que vous avez demandées ou nommées sont montrées.", "Wallet": "Portefeuille", "Connecting…": "Connexion…", "Balance": "Solde", "Mine": "Miner", "Receive": "Recevoir", "Send": "Envoyer", "Network": "Réseau", "Activity": "Activité", "Info": "Infos", "Loading…": "Chargement…", "Details": "Détail", "Close": "Fermer", "Back": "Revenir", "All": "Tout", "Received": "Reçu", "Sent": "Envoyé", "Type": "Quoi", "Date": "Date", "Reference": "Référence", "Confirmations": "Confirmations", "Block": "Bloc n°", "Available": "Disponible", "Mining": "Minage", "Chain": "Chaîne", "Your blocks": "Vos blocs", "Your addresses": "Vos adresses", "The network": "Le réseau", "Your security": "Votre sécurité", "Your machine": "Votre machine", "Measuring…": "Mesure en cours…", "Node unreachable": "Nœud injoignable", "Unlock": "Déverrouiller", "New address": "Nouvelle adresse", "Show more": "Afficher les suivantes", "Search your address book": "Chercher dans votre carnet", "+ Add a recipient": "+ Ajouter un destinataire", "Recalculate fee": "Recalculer les frais", "Review": "Vérifier", "Send now": "Envoyer définitivement", "Close the wallet": "Fermer le portefeuille", "Send Q21": "Envoyer du Q21", "Recipient address": "Adresse du destinataire", "Amount (Q21)": "Montant, en Q21", "Fee (Q21)": "Frais, en Q21", "Suggested by the node; you can change it.": "Suggestion du nœud, modifiable.", "Confirm the payment": "Confirmer l'envoi", "A payment is final": "Un envoi est définitif", "Expected inputs, for the fee estimate": "Entrées supposées, pour l'estimation des frais", "The address has a checksum: a typo will be caught by the node, not silently accepted.": "L'adresse porte une somme de contrôle\u00a0: une faute de frappe sera détectée par le nœud, pas subie.", "At most eight decimal places. One unit is 0.00000001 Q21.": "Huit décimales au maximum. Une unité vaut 0.00000001\u00a0Q21.", "No authority can reverse an accepted transaction. Re-read the address character by character: it is the only check you have left.": "Aucune autorité ne peut annuler une transaction acceptée. Relisez l'adresse caractère par caractère\u00a0: c'est la seule vérification qui vous reste.", "One payment can go to several recipients at once: a single transaction with a shared fee, rather than several separate payments.": "Un seul envoi peut payer plusieurs destinataires à la fois\u00a0: c'est une transaction unique, aux frais partagés, plutôt que plusieurs envois séparés.", "Your machine is not mining": "Votre machine ne cherche pas", "Mining searches for the next block. It uses all CPU cores.": "Le minage cherche le prochain bloc. Il utilise tous les cœurs.", "attempts per second": "tentatives par seconde", "Earned by mining": "Gagné en minant", "since launch, including immature rewards": "depuis le lancement — maturité comprise", "Blocks found": "Blocs trouvés", "since launch": "depuis le lancement", "Attempts": "Tentatives", "Chain pace": "Rythme de la chaîne", "target: one block every 2 minutes": "cible : un bloc toutes les 2 minutes", "Memory in use": "Mémoire occupée", "the computation table, in RAM": "la table de calcul, en mémoire vive", "Network hash rate": "Puissance de calcul du réseau", "measured on your machine, live": "mesurée chez vous, en direct", "Computers connected to yours": "Ordinateurs reliés au vôtre", "your direct neighbors, not the whole network": "vos voisins directs, pas le réseau entier", "The backup code is your wallet": "Le code de sauvegarde est votre portefeuille", "The file on this disk is only a working copy.": "Le fichier sur ce disque n'est qu'une copie de travail.", "Two things you must never do": "Deux choses à ne jamais faire", "For developers": "Pour les développeurs", "Chain explorer": "Explorateur de la chaîne", "Access token required": "Jeton d'accès requis", "Catching up on chain history": "Récupération de l'historique de la chaîne", "Why part of the balance is immature": "Pourquoi une part du solde est immature", "Why you have several": "Pourquoi vous en avez plusieurs", "What your machine does when this switch is on": "Ce que fait votre machine quand ce bouton est allumé", "Every payment deserves a fresh address. Reusing one costs the protocol nothing, but publicly links your payments together.": "Chaque paiement mérite une adresse neuve. Réutiliser une adresse ne coûte rien au protocole, mais relie publiquement vos paiements entre eux.", "Testnet — the Q21 mined here have no value, and never will. Research software, not externally audited.": "Réseau d'essai — les Q21 qui s'y minent n'ont aucune valeur, et n'en auront jamais. Logiciel de recherche, non audité de l'extérieur.", "Turn mining on": "Activer le minage", "Turn mining off": "Arrêter le minage", "This node cannot mine": "Ce nœud ne peut pas miner", "Connected": "Connecté", "Shutting down…": "Fermeture…", "Confirm shutdown": "Confirmer la fermeture", "Click again to stop the wallet.": "Cliquez une seconde fois pour arrêter le portefeuille.", "Blocks verified": "Blocs vérifiés", "Latest block": "Dernier bloc", "Recipient": "Destinataire", "Awaiting maturity": "En attente de maturité", "State commitment": "Empreinte de l'état", "Waiting for a computer to ask for the chain": "En attente d'un ordinateur à qui demander la chaîne", "Mining rate over the last few minutes": "Débit de minage des dernières minutes", "It uses all available cores.": "Elle utilise tous les cœurs disponibles.", "No recipient address.": "Aucune adresse de destination.", "Each amount must be greater than zero.": "Chaque montant doit être strictement positif.", "The minimum amount is 0.0001 Q21: below that, the network rejects the output as dust.": "Le montant minimal est 0,0001 Q21 : en dessous, le réseau refuse la sortie comme poussière.", "Each amount must be at least 0.0001 Q21: below that, the network rejects the output as dust.": "Chaque montant doit valoir au moins 0,0001 Q21 : en dessous, le réseau refuse la sortie comme poussière.", "Invalid fee. Expected a number in Q21, with at most eight decimal places.": "Frais illisibles. Attendu : un nombre en Q21, huit décimales au maximum.", "The node requires a token. The launcher normally passes it in the address fragment; if you opened this page manually, enter the token given to": "Le nœud exige un jeton. Il est normalement transmis par le lanceur dans le fragment de l'adresse\u00a0; si vous avez ouvert cette page à la main, saisissez ici le jeton passé à", "If you have just restored a wallet": "Si vous venez de restaurer un portefeuille", ", your funds will reappear at the end of this step: they are in the chain, and your machine has not read them yet. The displayed balance is incomplete until then.": ", vos fonds réapparaîtront à la fin de cette étape\u00a0: ils sont dans la chaîne, et votre machine ne les a pas encore lus. Le solde affiché est incomplet jusque-là.", "A mining reward can only be spent after a long maturity period. Until it has elapsed, the amount exists and belongs to you, but no transaction can spend it. It is counted separately rather than folded into a total that would be wrong.": "Une récompense de minage n'est dépensable qu'après un long délai de maturation. Tant qu'il n'est pas écoulé, la somme existe, elle vous appartient, mais aucune transaction ne peut la dépenser. Elle est comptée séparément plutôt que fondue dans un total qui serait faux.", "It searches a two-gigabyte table in memory, hundreds of thousands of times per second, looking for a value that meets the current difficulty. It is a lottery: you do not win every time, and you win more often the faster you search.": "Elle fouille une table de deux gigaoctets en mémoire, des centaines de milliers de fois par seconde, à la recherche d'une valeur qui satisfasse la difficulté du moment. C'est une loterie\u00a0: on ne gagne pas à tous les coups, on gagne d'autant plus souvent qu'on cherche vite.", "The reward for a block found is paid to an address in this wallet. It can only be spent after the maturity period.": "La récompense d'un bloc trouvé est versée à une adresse de ce portefeuille. Elle n'est dépensable qu'après le délai de maturation.", "Your wallet holds": "Votre portefeuille ne contient", "only one secret": "qu'un seul secret", ": the seed, the one behind the backup code you wrote down. All your addresses are": "\u00a0: la graine, celle du code de sauvegarde que vous avez recopié. Toutes vos adresses en sont", "built": "fabriquées", "from it by computation — the first, the second, the thousandth. This is called": "par un calcul — la première, la deuxième, la millième. C'est ce qu'on appelle les", "derivation": "dériver", "A reassuring consequence:": "Conséquence rassurante\u00a0:", "this code restores everything": "ce code sauve tout", ". No need to back up each address; they can all be recomputed from it.": ". Pas besoin de sauvegarder chaque adresse\u00a0; elles se recalculent toutes à partir de lui.", "A useful consequence: giving a fresh one to each person who pays you costs nothing, and keeps an onlooker from linking all your incoming payments together by reading the chain. Your balance is the sum of them all.": "Conséquence utile\u00a0: en donner une neuve à chaque personne qui vous paie ne coûte rien, et évite qu'un curieux relie tous vos encaissements entre eux en lisant la chaîne. Votre solde est la somme de toutes.", "With ML-DSA-87 the witness makes up almost all of a transaction: the fee depends mostly on the": "Avec ML-DSA-87 le témoin pèse la quasi-totalité d'une transaction\u00a0: les frais dépendent surtout du", "number of inputs": "nombre d'entrées", "consumed, which the node only picks when it builds the transaction. If the payment is rejected because the fee rate is too low, increase this number and recalculate.": "consommées, que le nœud ne choisit qu'au moment de construire la transaction. Si l'envoi est refusé pour taux de frais trop bas, augmentez ce nombre et recalculez.", "Why we don't tell you “how many miners”": "Pourquoi on ne vous dit pas «\u00a0combien de mineurs\u00a0»", "Because nobody can know, and a made-up figure would be worse than no figure at all. A miner does not announce itself: it just produces blocks. Nothing distinguishes a thousand machines from one person who owns a thousand.": "Parce que personne ne peut le savoir, et qu'un chiffre inventé serait pire que pas de chiffre. Un mineur ne s'annonce pas\u00a0: il pose des blocs. Rien ne distingue mille machines d'une personne qui en possède mille.", "And Q21 makes counting even harder, on purpose: your wallet uses": "Et Q21 rend le comptage encore plus impossible, volontairement\u00a0: votre portefeuille utilise", "a different address for each reward": "une adresse différente pour chaque récompense", ", so that your earnings cannot be linked together. Counting miner addresses would amount to counting blocks.": ", pour qu'on ne puisse pas relier vos gains entre eux. Compter les adresses de mineurs reviendrait donc à compter les blocs.", "What can be measured, on the other hand, cannot be faked:": "Ce qui se mesure, en revanche, ne se truque pas\u00a0:", "the work actually spent": "le travail réellement dépensé", ". It can be read from the difficulty, which adjusts so that a block is found every two minutes. Compared with what": ". Il se lit dans la difficulté, qui s'ajuste pour qu'un bloc tombe toutes les deux minutes. Comparé à ce que fait", "your": "votre", "machine does, it gives your share, shown above.": "machine, il donne la part qu'elle représente, indiquée ci-dessus.", "Your entire wallet — every address, all your funds — can be rebuilt from the single backup code you wrote down when you created it.": "Tout votre portefeuille — chaque adresse, chaque fonds — se refabrique à partir du seul code de sauvegarde que vous avez recopié à la création.", "On any machine: Windows, Intel Mac, Apple Silicon Mac, Linux, Raspberry Pi.": "Sur n'importe quelle machine\u00a0: Windows, Mac Intel, Mac Apple Silicon, Linux, Raspberry Pi.", "You enter it there with “I already have a backup code”, and the chain does the rest — verified by a full restore test on all five platforms we build for.": "Vous l'y saisissez via «\u00a0J'ai déjà un code de sauvegarde\u00a0», et la chaîne fait le reste — vérifié par une épreuve de restauration complète, sur les cinq systèmes construits.", "Do not photograph the code, and do not paste it into a cloud service: whoever reads it holds your funds, for good. And do not confuse the code with your": "Ne photographiez pas le code, ne le collez pas dans un nuage\u00a0: qui le lit détient vos fonds, définitivement. Et ne confondez pas le code avec votre", "passphrase": "phrase secrète", "— which only protects the file on": "\u00a0— elle, ne protège que le fichier de", "this": "cette", "machine, and can be different elsewhere.": "machine, et peut être différente ailleurs.", "ML-DSA-87 (FIPS 204, NIST level 5) — why it resists quantum computers": "ML-DSA-87 (FIPS\u00a0204, niveau NIST\u00a05) — pourquoi ça résiste au quantique", "This wallet's signatures rest on ML-DSA, the lattice-based scheme standardized by NIST in 2024 as FIPS 204. Q21 uses the strongest parameter set, ML-DSA-87, whose target security matches level 5 — on the order of AES-256.": "Les signatures de ce portefeuille reposent sur ML-DSA, le schéma à réseaux euclidiens normalisé par le NIST en 2024 sous le nom FIPS\u00a0204. Q21 retient le paramétrage le plus élevé, ML-DSA-87, dont la sécurité visée correspond au niveau\u00a05 — de l'ordre d'AES-256.", "This is what sets the project apart. The ECDSA signatures that protect most chains today fall to Shor's algorithm as soon as a large enough quantum computer exists; these rest on no problem that Shor's algorithm solves. The price shows in the figures above: a 2,592-byte public key and a 4,627-byte signature, where ECDSA needs a few dozen bytes.": "C'est le point qui distingue ce projet. Les signatures ECDSA que protègent aujourd'hui la plupart des chaînes tombent devant l'algorithme de Shor dès qu'une machine quantique suffisante existe\u00a0; celles-ci ne reposent sur aucun problème que Shor résout. Le prix se lit dans les chiffres ci-dessus\u00a0: une clef publique de 2\u00a0592 octets, une signature de 4\u00a0627 octets, là où ECDSA tient en quelques dizaines.", "The core does not implement this scheme itself: writing your own lattice-based signature would be professional malpractice. It plugs in an audited implementation.": "Le noyau n'implémente pas lui-même ce schéma\u00a0: écrire soi-même une signature à réseaux euclidiens est une faute professionnelle. Il branche une implémentation auditée.", "The node serves a JSON-RPC API at": "Le nœud sert une API JSON-RPC sur", "lists the methods. The session access token is sent as": "énumère les méthodes. Le jeton d'accès de la session s'envoie en", "; it never leaves this page. Nothing else is written to the browser except the token and the language choice, both cleared when the tab closes. The explorer and the wallet are served by the same process, on the same port, with no external resource.": "; il ne quitte jamais cette page. Rien d'autre n'est écrit dans le navigateur que lui et le choix de langue, tous deux effacés à la fermeture de l'onglet. L'explorateur et le portefeuille sont servis par le même processus, sur le même port, sans aucune ressource externe.", "This wallet is served by a node running in the window the launcher opened. This button asks it to shut down cleanly: it writes out the mempool, the state snapshot and the wallet, then exits.": "Ce portefeuille est servi par un nœud qui tourne dans la fenêtre ouverte par le lanceur. Ce bouton lui demande de s'arrêter proprement\u00a0: il écrit le réservoir de transactions en attente, l'instantané de l'état et le portefeuille, puis rend la main.", "This is the recommended way to stop. Closing the launcher window also works.": "C'est la façon recommandée d'arrêter. Fermer la fenêtre du lanceur fonctionne aussi.", "works too, but Windows then asks its own question — “Terminate batch job (Y/N)?”: answer": "fonctionne également, mais Windows pose alors sa propre question — «\u00a0Terminer le programme de commandes (O/N)\u00a0?\u00a0»\u00a0: répondez", "; everything has already been saved by then.": ", tout est déjà enregistré à ce moment-là.", "— everything your node has verified, browsable without trusting anyone.": "— tout ce que votre nœud a vérifié, consultable sans faire confiance à personne.", "Copy": "Copier", "copy": "copier", "Save": "Enregistrer", "Name": "Nommer", "Rename": "Renommer", "unnamed": "sans nom", "used": "servie", "Full history": "Historique complet", "Q21 issued to date": "Q21 créés à ce jour", "Signature scheme": "Schéma de signature", "Unspent outputs": "Sommes non dépensées", "Total held": "Total détenu", "available and pending combined": "disponible et en attente réunis", "across the whole chain, all holders combined": "sur toute la chaîne, tous porteurs confondus", "no block since this screen was opened": "aucun bloc depuis le lancement de cet écran", "Mining requires a wallet: without one, the reward would go nowhere.": "Miner demande un portefeuille : sans lui, la récompense n'irait nulle part.", "testnet": "réseau d'essai", "mining": "minage", "attempts/s": "tentatives/s", "Wallet closed": "Portefeuille fermé", "The amount must be greater than zero.": "Le montant doit être strictement positif.", "The fee cannot be negative.": "Les frais ne peuvent pas être négatifs.", "Invalid amount. Expected a number in Q21, with at most eight decimal places.": "Montant illisible. Attendu : un nombre en Q21, huit décimales au maximum.", "An additional amount is invalid. Expected a number in Q21.": "Un montant supplémentaire est illisible. Attendu : un nombre en Q21.", "An additional recipient has no address. Remove the row or fill it in.": "Un destinataire supplémentaire est sans adresse. Retirez la ligne ou remplissez-la.", "the network cannot be measured yet": "le réseau n'est pas encore mesurable", "at this rate, you produce most of the recent blocks": "à ce rythme, vous produisez l'essentiel des blocs récents", "resistant to quantum computers — see below": "résistant à l'ordinateur quantique — voir ci-dessous", "a unique fingerprint of all the money in existence: two nodes at the same height show the same value — your proof that you are on the real chain, without trusting anyone": "une signature unique de tout l'argent qui existe : deux nœuds à la même hauteur l'affichent identique — votre preuve d'être sur la vraie chaîne, sans faire confiance à personne", "incomplete figure, see the warning above": "chiffre incomplet, voir l'avertissement ci-dessus", "turn mining on to see your share": "allumez le minage pour vous situer", "measuring speed": "vitesse en cours de mesure", "time left unknown": "durée inconnue", "stopped": "à l'arrêt", "· no computer reachable": "· aucun ordinateur joignable", "the browser blocked copying": "copie refusée par le navigateur", "copied": "copié", "access token missing or rejected": "jeton d'accès manquant ou refusé", "Your machine is looking for a block": "Votre machine cherche un bloc", "Q21 — wallet": "Q21 — portefeuille", "Wallet sections": "Sections du portefeuille", "access token": "jeton d'accès", "a name, a number (#12) or part of an address": "un nom, un numéro (#12) ou un morceau d'adresse", "Also show the mining addresses": "Afficher aussi les adresses de minage", "When it is on, your wallet asks your router to open its port, and becomes an entry point to the network: others can connect to you. This is what lets the network live without depending on a single server. Most routers open the port on their own.": "Quand il est allumé, votre portefeuille demande à votre box d'ouvrir son accès, et devient un point d'entrée du réseau\u00a0: les autres peuvent se connecter à vous. C'est ce qui permet au réseau de vivre sans dépendre d'un serveur unique. La plupart des box ouvrent l'accès toutes seules.", "In return, your": "En échange, votre", "IP address becomes visible": "adresse internet devient visible", "to other nodes — that is how a peer-to-peer network normally works. If you would rather stay a plain client, turn it off: your wallet works exactly the same, using the nodes that others keep open.": "des autres nœuds — c'est le fonctionnement normal d'un réseau pair-à-pair. Si vous préférez rester un simple client, éteignez\u00a0: votre portefeuille marche exactement pareil, il profite des nœuds ouverts par les autres.", "A change": "Un changement", "takes effect the next time": "prend effet au prochain lancement", "the wallet starts.": "du portefeuille.", "Show only": "Ne montrer que", "who or what it is for — visible only to you": "pour qui, ou pourquoi — visible de vous seul", "Received and sent on the same row": "Reçu et sorti sur une même ligne", "A payment almost never spends a coin of the exact size: the wallet spends a bigger one, and the difference comes back to it as change, on a fresh address, like a bill handed back. The": "Un envoi n'ouvre presque jamais une pièce de la taille exacte\u00a0: le portefeuille en ouvre une plus grosse, et la différence lui revient en monnaie sur une adresse neuve, comme un billet rendu. La colonne", "received": "reçu", "column holds that change; the": "porte cette monnaie, la colonne", "sent": "sorti", "column, what actually left the wallet — amount paid and fee included.": "ce qui a réellement quitté le portefeuille — montant versé et frais compris.", "Amounts sent incomplete": "Sommes sorties incomplètes", "For at least one payment, the coin spent predates the window examined: its value was not found, so the amount sent cannot be established. These amounts are shown preceded by “≥” — a minimum, not a fact.": "Pour au moins un envoi, la pièce ouverte est antérieure à la fenêtre examinée\u00a0: sa valeur n'a pas été retrouvée, et la somme sortie ne peut donc pas être établie. Ces montants s'affichent précédés de «\u00a0≥\u00a0» — un minimum, pas un fait.", "Program version": "Version du programme", "the one you are running — compare it with the version announced in the release": "celle que vous exécutez — à comparer à la version annoncée par la livraison", "Single-use address": "Adresse à usage unique", "Reuse": "Réutilisation", "Scheme": "Schéma", "Requesting…": "Demande en cours…", "Address not created": "Adresse non créée", "Payment not prepared": "Envoi non préparé", "Address of another recipient": "Adresse d'un autre destinataire", "Remove": "Retirer", "Amount": "Montant", "Fee": "Frais", "Total debited": "Débité au total", "Balance after": "Solde après", "✓ Payment sent to the network": "✓ Envoi transmis au réseau", "It has been announced to peers and is waiting to enter a block — expect about two minutes. Until a block contains it, it is": "Il est annoncé aux pairs et attend d'entrer dans un bloc — comptez l'ordre de deux minutes. Tant qu'aucun bloc ne le contient, il n'est", "not confirmed yet": "pas encore confirmé", "Follow this transaction in the explorer": "Suivre cette transaction dans l'explorateur", "Reference:": "Référence :", "Payment rejected": "Envoi refusé", "No funds have moved.": "Aucun fonds n'a bougé.", "Sending…": "Envoi…", "pending": "en attente", "Partial history": "Historique partiel", "Your funds are not lost": "Vos fonds ne sont pas perdus", ": the balance is still correct. Close and reopen the wallet: it will request these blocks from the network again.": ": le solde reste juste. Fermez puis rouvrez le portefeuille\u00a0: il redemandera ces blocs au réseau.", "History unavailable": "Historique indisponible", "No address derived yet. The button above creates one.": "Aucune adresse encore dérivée. Le bouton ci-dessus en crée une.", "Nothing yet. Your first movements will appear here — receive Q21 from the Receive tab, or find a block from the Mine tab.": "Rien pour l'instant. Vos premiers mouvements apparaîtront ici — recevez du Q21 depuis l'onglet Recevoir, ou trouvez un bloc depuis l'onglet Miner.", "mining rewards: they belong to you, but cannot be used yet": "récompenses de minage : elles vous appartiennent, mais ne sont pas encore utilisables", "No block found yet. It is a lottery: the switch above buys attempts, and luck decides when.": "Aucun bloc trouvé pour l'instant. C'est une loterie : le bouton ci-dessus achète des tentatives, la chance décide du moment.", "Not enough blocks yet to measure anything. At least two are needed, spread out in time.": "Pas encore assez de blocs pour mesurer quoi que ce soit. Il en faut au moins deux, séparés dans le temps.", "catching up": "rattrapage en cours", "observed pace — target: 2 minutes": "cadence observée — cible : 2 minutes", "The node has saved its state and stopped. You can close this tab; the black window will close by itself.": "Le nœud a écrit son état et s'est arrêté. Vous pouvez fermer cet onglet ; la fenêtre noire se referme d'elle-même.", "This link has already been used, or has expired. Start the wallet again to get a new one.": "Ce lien a déjà servi, ou a expiré. Relancez le portefeuille pour en obtenir un neuf.", "Could not reach the node: access token missing or rejected": "Impossible d'interroger le nœud : jeton d'accès manquant ou refusé", "Y": "O", "outgoing": "envoi", "incoming": "reception", "No movement of this type in the history searched.": "Aucun mouvement de ce type dans l'historique parcouru.", "Your address": "Votre adresse", "This is what you give to someone who wants to send you Q21 — what is usually called your “wallet address”.": "C'est ce que vous donnez à quelqu'un qui veut vous envoyer des Q21 — ce qu'on appelle couramment votre «\u00a0adresse de portefeuille\u00a0».", "Which address should I give?": "Quelle adresse donner\u00a0?", "The one above. Every address of this wallet stays valid forever: a payment sent to an older one still arrives here, even years later.": "Celle ci-dessus. Toutes les adresses de ce portefeuille restent valables pour toujours\u00a0: un paiement envoyé à une ancienne arrive quand même ici, même des années plus tard.", "To check that a payment has arrived, open the address in the explorer: it shows what it received, even before the next block.": "Pour vérifier qu'un paiement est arrivé, ouvrez l'adresse dans l'explorateur\u00a0: il montre ce qu'elle a reçu, même avant le bloc suivant.", "Copy the address": "Copier l'adresse", "See it in the explorer": "La voir dans l'explorateur", "Explorer": "Explorateur", "The “New address” button below creates one.": "Le bouton «\u00a0Nouvelle adresse\u00a0» ci-dessous en crée une.", "Show older movements": "Afficher les mouvements plus anciens"}, "ja": {"Your router did not open the port: your wallet stays a client.": "ルーターはポートを開きませんでした。ウォレットはクライアントのままです。", "Your router opened the port (NAT-PMP).": "ルーターがポートを開きました（NAT-PMP）。", "Your router opened the port (UPnP).": "ルーターがポートを開きました（UPnP）。", "Your router opened the port.": "ルーターがポートを開きました。", "It is off by default: turn it on only if you accept that other nodes see your address.": "初期設定ではオフです。他のノードにあなたのアドレスが見えることを受け入れる場合にのみオンにしてください。", "Syncing": "同期中", "Offline": "オフライン", "Your wallet helps the network": "あなたのウォレットはネットワークを支えています", "Your wallet is client-only": "あなたのウォレットは単なるクライアントです", "It accepts connections from others, so the network does not rely on a single machine.": "他のノードからの接続を受け入れ、ネットワークが一台のマシンに依存しないようにします。", "It reaches out to the network but does not accept incoming connections.": "ネットワークへは接続しますが、着信接続は受け付けません。", "Make this node reachable": "このノードを到達可能にする", "Stop being reachable": "到達可能をやめる", "What this setting does": "この設定の働き", "Your node will be reachable the next time the wallet starts.": "次回ウォレットを起動したときにノードは到達可能になります。", "Your node will be client-only the next time the wallet starts.": "次回ウォレットを起動したときにノードは単なるクライアントになります。", "No bootstrap address: this node is not looking for anyone": "開始アドレスがありません：このノードは誰も探していません", "The program contains no server address, and that is deliberate: an address hard-coded into distributed software would become a permanent dependency on whoever controls it. It is provided separately, in a file you can edit. Create q21-data/bootstrap.txt next to the program, add the line bootstrap.q21.dev:21121 to it, then restart. JOIN.md, which ships with the program, explains this step and how to add more entry points.": "プログラムにはサーバーのアドレスが含まれていません。これは意図的です：配布されるソフトウェアに刻まれたアドレスは、それを保持する者への恒久的な依存になります。アドレスは隣に置かれた、編集可能なファイルで与えます。プログラムの隣に q21-data/bootstrap.txt を作成し、bootstrap.q21.dev:21121 の行を書いてから、再起動してください。プログラムに同梱の JOIN.md（英語）に、この手順と他の入口の追加方法が書かれています。", "Hide the mining addresses": "マイニング用アドレスを畳む", "Mining also derives one per block found, for the same reason. Those addresses have already received their reward and need not be handed out: they are tucked away below, and only the ones you requested or named are shown.": "マイニングも同じ理由で、発見したブロックごとにアドレスを 1 つ導出します。それらはすでに報酬を受け取っており、誰かに渡す必要はありません。下に畳まれており、あなたが要求または命名したものだけが表示されます。", "Wallet": "ウォレット", "Connecting…": "接続中…", "Balance": "残高", "Mine": "マイニング", "Receive": "受け取る", "Send": "送る", "Network": "ネットワーク", "Activity": "履歴", "Info": "情報", "Loading…": "読み込み中…", "Details": "詳細", "Close": "閉じる", "Back": "戻る", "All": "すべて", "Received": "受取", "Sent": "送金", "Type": "種別", "Date": "日付", "Reference": "参照", "Confirmations": "承認数", "Block": "ブロック番号", "Available": "利用可能", "Mining": "マイニング", "Chain": "チェーン", "Your blocks": "あなたのブロック", "Your addresses": "あなたのアドレス", "The network": "ネットワーク", "Your security": "セキュリティ", "Your machine": "あなたのマシン", "Measuring…": "測定中…", "Node unreachable": "ノードに接続できません", "Unlock": "ロック解除", "New address": "新しいアドレス", "Show more": "さらに表示", "Search your address book": "アドレス帳を検索", "+ Add a recipient": "+ 宛先を追加", "Recalculate fee": "手数料を再計算", "Review": "確認", "Send now": "確定して送る", "Close the wallet": "ウォレットを終了", "Send Q21": "Q21 を送る", "Recipient address": "宛先アドレス", "Amount (Q21)": "金額 (Q21)", "Fee (Q21)": "手数料 (Q21)", "Suggested by the node; you can change it.": "ノードの提案値です。変更できます。", "Confirm the payment": "送金の確認", "A payment is final": "送金は取り消せません", "Expected inputs, for the fee estimate": "手数料見積り用の入力数", "The address has a checksum: a typo will be caught by the node, not silently accepted.": "アドレスにはチェックサムがあります。打ち間違いはノードが検出します。", "At most eight decimal places. One unit is 0.00000001 Q21.": "小数点以下は最大 8 桁。1 単位は 0.00000001 Q21 です。", "No authority can reverse an accepted transaction. Re-read the address character by character: it is the only check you have left.": "承認された取引を取り消せる権威は存在しません。アドレスを一文字ずつ読み直してください。それが最後の確認です。", "One payment can go to several recipients at once: a single transaction with a shared fee, rather than several separate payments.": "一度の送金で複数の宛先に支払えます。手数料を分け合う単一の取引になります。", "Your machine is not mining": "マシンは探索していません", "Mining searches for the next block. It uses all CPU cores.": "マイニングは次のブロックを探します。全コアを使います。", "attempts per second": "秒あたりの試行", "Earned by mining": "マイニング報酬", "since launch, including immature rewards": "起動以降 — 成熟待ちを含む", "Blocks found": "発見ブロック", "since launch": "起動以降", "Attempts": "試行回数", "Chain pace": "チェーンの速度", "target: one block every 2 minutes": "目標: 2 分に 1 ブロック", "Memory in use": "使用メモリ", "the computation table, in RAM": "計算テーブル (RAM 上)", "Network hash rate": "ネットワークの計算力", "measured on your machine, live": "あなたのマシンでの実測値", "Computers connected to yours": "接続中のコンピュータ", "your direct neighbors, not the whole network": "直接の隣接ノードのみ", "The backup code is your wallet": "バックアップコードがあなたのウォレットです", "The file on this disk is only a working copy.": "このディスク上のファイルは作業用の複製にすぎません。", "Two things you must never do": "絶対にしてはいけない二つのこと", "For developers": "開発者向け", "Chain explorer": "チェーンエクスプローラ", "Access token required": "アクセストークンが必要です", "Catching up on chain history": "チェーン履歴を取得中", "Why part of the balance is immature": "残高の一部が未成熟な理由", "Why you have several": "複数ある理由", "What your machine does when this switch is on": "このスイッチが入っているとき、マシンは何をするか", "Every payment deserves a fresh address. Reusing one costs the protocol nothing, but publicly links your payments together.": "支払いごとに新しいアドレスを。再利用はプロトコル上は無料ですが、支払い同士が公に結び付きます。", "Testnet — the Q21 mined here have no value, and never will. Research software, not externally audited.": "テストネット — ここで採掘される Q21 に価値はなく、今後もありません。外部監査を受けていない研究用ソフトウェアです。", "Turn mining on": "マイニングを開始", "Turn mining off": "マイニングを停止", "This node cannot mine": "このノードはマイニングできません", "Connected": "接続済み", "Shutting down…": "終了中…", "Confirm shutdown": "終了の確認", "Click again to stop the wallet.": "もう一度クリックするとウォレットを停止します。", "Blocks verified": "検証済みブロック", "Latest block": "最新ブロック", "Recipient": "宛先", "Awaiting maturity": "成熟待ち", "State commitment": "状態フィンガープリント", "Waiting for a computer to ask for the chain": "チェーンを要求する相手を待っています", "Mining rate over the last few minutes": "直近数分のマイニング速度", "It uses all available cores.": "利用可能な全コアを使用します。", "No recipient address.": "宛先アドレスがありません。", "Each amount must be greater than zero.": "金額は必ず正の値である必要があります。", "The minimum amount is 0.0001 Q21: below that, the network rejects the output as dust.": "最小金額は 0.0001 Q21 です。それ未満の出力はダストとしてネットワークに拒否されます。", "Each amount must be at least 0.0001 Q21: below that, the network rejects the output as dust.": "各金額は 0.0001 Q21 以上である必要があります。それ未満の出力はダストとしてネットワークに拒否されます。", "Invalid fee. Expected a number in Q21, with at most eight decimal places.": "手数料を解釈できません。Q21 の数値 (小数点以下 8 桁まで) を入力してください。", "The node requires a token. The launcher normally passes it in the address fragment; if you opened this page manually, enter the token given to": "ノードはトークンを要求します。通常はランチャーがアドレスのフラグメントで渡します。このページを手動で開いた場合は、次に渡したトークンをここに入力してください:", "If you have just restored a wallet": "ウォレットを復元した直後の場合", ", your funds will reappear at the end of this step: they are in the chain, and your machine has not read them yet. The displayed balance is incomplete until then.": "、資金はこの工程の終わりに再表示されます。資金はチェーン上にあり、あなたのマシンがまだ読み終えていないだけです。それまで表示残高は不完全です。", "A mining reward can only be spent after a long maturity period. Until it has elapsed, the amount exists and belongs to you, but no transaction can spend it. It is counted separately rather than folded into a total that would be wrong.": "マイニング報酬は長い成熟期間を経てはじめて使用できます。期間が終わるまで、その金額は存在しあなたのものですが、どの取引でも使えません。誤った合計に紛れ込ませず、別枠で数えています。", "It searches a two-gigabyte table in memory, hundreds of thousands of times per second, looking for a value that meets the current difficulty. It is a lottery: you do not win every time, and you win more often the faster you search.": "メモリ上の 2 ギガバイトのテーブルを毎秒何十万回も探索し、その時点の難易度を満たす値を探します。これは宝くじです。毎回当たるわけではなく、速く探すほど当たりやすくなります。", "The reward for a block found is paid to an address in this wallet. It can only be spent after the maturity period.": "発見したブロックの報酬は、このウォレットのアドレスに支払われます。成熟期間の経過後にのみ使用できます。", "Your wallet holds": "あなたのウォレットが持つ秘密は", "only one secret": "ただ一つだけです", ": the seed, the one behind the backup code you wrote down. All your addresses are": ": 書き写したバックアップコードのもとになる種です。すべてのアドレスは計算によって", "built": "作られます", "from it by computation — the first, the second, the thousandth. This is called": "— 1 番目も 2 番目も 1000 番目も。これを", "derivation": "導出という", "A reassuring consequence:": "安心できる帰結:", "this code restores everything": "このコードがすべてを救う", ". No need to back up each address; they can all be recomputed from it.": "。個々のアドレスを保存する必要はありません。すべてそこから再計算されます。", "A useful consequence: giving a fresh one to each person who pays you costs nothing, and keeps an onlooker from linking all your incoming payments together by reading the chain. Your balance is the sum of them all.": "実用的な帰結: 支払う人ごとに新しいアドレスを渡しても費用はかからず、チェーンを読む者があなたの入金を結び付けることを防げます。残高はそれらすべての合計です。", "With ML-DSA-87 the witness makes up almost all of a transaction: the fee depends mostly on the": "ML-DSA-87 では証人データが取引のほぼ全体を占めます。手数料は主に消費される", "number of inputs": "入力の数", "consumed, which the node only picks when it builds the transaction. If the payment is rejected because the fee rate is too low, increase this number and recalculate.": "に依存し、ノードは取引を組み立てる時にはじめてそれを決めます。手数料率が低すぎて送金が拒否された場合は、この数を増やして再計算してください。", "Why we don't tell you “how many miners”": "「マイナーの数」をお伝えしない理由", "Because nobody can know, and a made-up figure would be worse than no figure at all. A miner does not announce itself: it just produces blocks. Nothing distinguishes a thousand machines from one person who owns a thousand.": "誰にも知りようがなく、でっち上げた数字は数字がないより悪いからです。マイナーは名乗らず、ただブロックを置きます。千台のマシンと、千台を所有する一人とを区別する手立てはありません。", "And Q21 makes counting even harder, on purpose: your wallet uses": "さらに Q21 は意図的に集計を不可能にしています。ウォレットは報酬ごとに", "a different address for each reward": "異なるアドレスを使います", ", so that your earnings cannot be linked together. Counting miner addresses would amount to counting blocks.": "。そのため収益同士を結び付けられません。マイナーのアドレスを数えることは、ブロックを数えることと同じになります。", "What can be measured, on the other hand, cannot be faked:": "一方、測定できるものは偽装できません:", "the work actually spent": "実際に費やされた仕事量", ". It can be read from the difficulty, which adjusts so that a block is found every two minutes. Compared with what": "。これは 2 分に 1 ブロックとなるよう調整される難易度から読み取れます。それを", "your": "あなたの", "machine does, it gives your share, shown above.": "マシンと比べると、その占める割合（上に表示）になります。", "Your entire wallet — every address, all your funds — can be rebuilt from the single backup code you wrote down when you created it.": "ウォレット全体 — すべてのアドレス、すべての資金 — は、作成時に書き写した唯一のバックアップコードから復元されます。", "On any machine: Windows, Intel Mac, Apple Silicon Mac, Linux, Raspberry Pi.": "どのマシンでも: Windows、Intel Mac、Apple Silicon Mac、Linux、Raspberry Pi。", "You enter it there with “I already have a backup code”, and the chain does the rest — verified by a full restore test on all five platforms we build for.": "「バックアップコードを持っています」から入力すれば、あとはチェーンが行います — 構築される 5 つのシステムすべてで、完全な復元テストにより検証済みです。", "Do not photograph the code, and do not paste it into a cloud service: whoever reads it holds your funds, for good. And do not confuse the code with your": "コードを撮影せず、クラウドに貼り付けないでください。読んだ者が資金を永久に手にします。また、このコードを", "passphrase": "パスフレーズ", "— which only protects the file on": "と混同しないでください。パスフレーズが守るのは", "this": "この", "machine, and can be different elsewhere.": "マシンのファイルだけで、他の場所では異なる場合があります。", "ML-DSA-87 (FIPS 204, NIST level 5) — why it resists quantum computers": "ML-DSA-87 (FIPS 204、NIST レベル 5) — 量子計算に耐える理由", "This wallet's signatures rest on ML-DSA, the lattice-based scheme standardized by NIST in 2024 as FIPS 204. Q21 uses the strongest parameter set, ML-DSA-87, whose target security matches level 5 — on the order of AES-256.": "このウォレットの署名は、NIST が 2024 年に FIPS 204 として標準化した格子ベース方式 ML-DSA に基づきます。Q21 は最上位のパラメータ ML-DSA-87 を採用し、目標とする安全性はレベル 5 — AES-256 に相当します。", "This is what sets the project apart. The ECDSA signatures that protect most chains today fall to Shor's algorithm as soon as a large enough quantum computer exists; these rest on no problem that Shor's algorithm solves. The price shows in the figures above: a 2,592-byte public key and a 4,627-byte signature, where ECDSA needs a few dozen bytes.": "これがこのプロジェクトを際立たせる点です。今日ほとんどのチェーンを守る ECDSA 署名は、十分な量子計算機が現れれば Shor のアルゴリズムに屈します。こちらは Shor が解ける問題に依存していません。その代償は上の数字に表れます: 公開鍵 2,592 バイト、署名 4,627 バイト。ECDSA なら数十バイトです。", "The core does not implement this scheme itself: writing your own lattice-based signature would be professional malpractice. It plugs in an audited implementation.": "コア自身はこの方式を実装しません。格子署名を自作することは専門家として許されない過ちです。監査済みの実装を組み込んでいます。", "The node serves a JSON-RPC API at": "ノードは次の場所で JSON-RPC API を提供します:", "lists the methods. The session access token is sent as": "がメソッドを列挙します。セッションのアクセストークンは次の形式で送ります:", "; it never leaves this page. Nothing else is written to the browser except the token and the language choice, both cleared when the tab closes. The explorer and the wallet are served by the same process, on the same port, with no external resource.": "。これはこのページから外に出ません。ブラウザに書き込まれるのはこれと言語の選択だけで、どちらもタブを閉じると消えます。エクスプローラとウォレットは同一プロセス・同一ポートで提供され、外部リソースは一切使いません。", "This wallet is served by a node running in the window the launcher opened. This button asks it to shut down cleanly: it writes out the mempool, the state snapshot and the wallet, then exits.": "このウォレットは、ランチャーが開いたウィンドウで動くノードが提供しています。このボタンはノードに正常終了を求めます: 保留中の取引プール、状態のスナップショット、ウォレットを書き出してから制御を返します。", "This is the recommended way to stop. Closing the launcher window also works.": "これが推奨される停止方法です。ランチャーのウィンドウを閉じても構いません。", "works too, but Windows then asks its own question — “Terminate batch job (Y/N)?”: answer": "も使えますが、その場合 Windows が独自の確認 —「バッチ ジョブを終了しますか (Y/N)?」— を出します。次のように答えてください:", "; everything has already been saved by then.": "。その時点ですべて保存済みです。", "— everything your node has verified, browsable without trusting anyone.": "— あなたのノードが検証したすべてを、誰も信頼することなく閲覧できます。", "Copy": "コピー", "copy": "コピー", "Save": "保存", "Name": "名前を付ける", "Rename": "名前を変更", "unnamed": "名前なし", "used": "使用済み", "Full history": "完全な履歴", "Q21 issued to date": "これまでに発行された Q21", "Signature scheme": "署名方式", "Unspent outputs": "未使用額", "Total held": "保有総額", "available and pending combined": "利用可能分と待機分の合計", "across the whole chain, all holders combined": "チェーン全体、全保有者の合計", "no block since this screen was opened": "この画面を開いてからブロックはありません", "Mining requires a wallet: without one, the reward would go nowhere.": "マイニングにはウォレットが必要です。ないと報酬の宛先がありません。", "testnet": "テストネット", "mining": "マイニング", "attempts/s": "回試行/秒", "Wallet closed": "ウォレットを終了しました", "The amount must be greater than zero.": "金額は正の値である必要があります。", "The fee cannot be negative.": "手数料を負の値にはできません。", "Invalid amount. Expected a number in Q21, with at most eight decimal places.": "金額を解釈できません。Q21 の数値 (小数点以下 8 桁まで) を入力してください。", "An additional amount is invalid. Expected a number in Q21.": "追加の金額を解釈できません。Q21 の数値を入力してください。", "An additional recipient has no address. Remove the row or fill it in.": "追加の宛先にアドレスがありません。行を削除するか入力してください。", "the network cannot be measured yet": "ネットワークはまだ測定できません", "at this rate, you produce most of the recent blocks": "このペースでは、最近のブロックの大半をあなたが生成しています", "resistant to quantum computers — see below": "量子コンピュータに耐性 — 下記を参照", "a unique fingerprint of all the money in existence: two nodes at the same height show the same value — your proof that you are on the real chain, without trusting anyone": "存在するすべての通貨の一意な署名。同じ高さの二つのノードは同一の値を示します — 誰も信用せずに本物のチェーン上にいるという証拠です", "incomplete figure, see the warning above": "不完全な数値です。上の警告を参照してください", "turn mining on to see your share": "自分の位置を知るにはマイニングを開始してください", "measuring speed": "速度を測定中", "time left unknown": "所要時間は不明", "stopped": "停止中", "· no computer reachable": "· 接続可能なコンピュータなし", "the browser blocked copying": "ブラウザがコピーを拒否しました", "copied": "コピーしました", "access token missing or rejected": "アクセストークンがないか拒否されました", "Your machine is looking for a block": "マシンがブロックを探しています", "Q21 — wallet": "Q21 — ウォレット", "access token": "アクセストークン", "Fee": "手数料", "pending": "保留中", "Not enough blocks yet to measure anything. At least two are needed, spread out in time.": "測定に足るブロックがまだありません。時間を空けた 2 つ以上が必要です。", "The node has saved its state and stopped. You can close this tab; the black window will close by itself.": "ノードは状態を書き出して停止しました。このタブを閉じて構いません。黒いウィンドウは自動的に閉じます。", "This link has already been used, or has expired. Start the wallet again to get a new one.": "このリンクはすでに使用済みか、期限切れです。ウォレットを再起動して新しいリンクを取得してください。", "Could not reach the node: access token missing or rejected": "ノードに問い合わせできません: アクセストークンがないか拒否されました", "No movement of this type in the history searched.": "検索した履歴に、この種類の入出金はありません。", "Your address": "あなたのアドレス", "This is what you give to someone who wants to send you Q21 — what is usually called your “wallet address”.": "Q21 を送ってもらうときに相手に伝えるのがこれです。一般に「ウォレットのアドレス」と呼ばれるものです。", "Which address should I give?": "どのアドレスを伝えればよいですか?", "The one above. Every address of this wallet stays valid forever: a payment sent to an older one still arrives here, even years later.": "上に表示されているものです。このウォレットのアドレスはすべて永久に有効です。古いアドレスに送られた支払いも、何年後であってもここに届きます。", "To check that a payment has arrived, open the address in the explorer: it shows what it received, even before the next block.": "支払いが届いたか確かめるには、エクスプローラーでアドレスを開いてください。次のブロックを待たずに、受け取った内容が表示されます。", "Copy the address": "アドレスをコピー", "See it in the explorer": "エクスプローラーで見る", "Explorer": "エクスプローラー", "The “New address” button below creates one.": "下の「新しいアドレス」ボタンで作成できます。", "Show older movements": "それ以前の入出金を表示"}};
const I18N_PATTERNS = {
  "fr": [
    [/^(.+) address\(es\) in total$/, "$1 adresse(s) au total"],
    [/^(.+) requested address\(es\) · (.+) from mining, tucked away$/, "$1 adresse(s) demandée(s) · $2 de minage rangée(s)"],
    [/^(.+) requested address\(es\)$/, "$1 adresse(s) demandée(s)"],
    [/^(.+) address\(es\) in total, (.+) of them from mining$/, "$1 adresse(s) au total, dont $2 de minage"],
    [/^Also show the (.+) mining address\(es\)$/, "Afficher aussi les $1 adresse(s) de minage"],
    [/^No requested address yet\. The “New address” button creates one, which you can name\. Your (.+) mining address\(es\) are tucked away: they received your rewards and count in your balance\.$/, "Aucune adresse demandée pour l'instant. Le bouton « Nouvelle adresse » en crée une, que vous pourrez nommer. Vos $1 adresse(s) de minage sont rangées\u00a0: elles ont reçu vos récompenses et comptent dans votre solde."],
    [/^(.+) earlier block\(s\) found — all counted in the total earned\.$/, "$1 trouvaille(s) plus ancienne(s) — toutes comptées dans le total gagné."],
    [/^(.+) address\(es\) found out of (.+)$/, "$1 adresse(s) trouvée(s) sur $2"],
    [/^Block (.+)$/, "Bloc $1"],
    [/^Measured over (.+) block\(s\), or (.+) day\(s\) of chain time\. This figure is not declared by anyone: it is derived from the work actually spent to produce them\.$/, "Mesuré sur $1 bloc(s), soit $2 jour(s) de chaîne. Ce chiffre ne se déclare pas : il se déduit du travail réellement dépensé pour les produire."],
    [/^Measured over (.+) block\(s\), or (.+) minute\(s\) of chain time\. This figure is not declared by anyone: it is derived from the work actually spent to produce them\.$/, "Mesuré sur $1 bloc(s), soit $2 minute(s) de chaîne. Ce chiffre ne se déclare pas : il se déduit du travail réellement dépensé pour les produire."],
    [/^Measured over (.+) block\(s\), or (.+) second\(s\) of chain time\. This figure is not declared by anyone: it is derived from the work actually spent to produce them\.$/, "Mesuré sur $1 bloc(s), soit $2 seconde(s) de chaîne. Ce chiffre ne se déclare pas : il se déduit du travail réellement dépensé pour les produire."],
    [/^Measured over (.+) block\(s\), or (.+) hour\(s\) of chain time\. This figure is not declared by anyone: it is derived from the work actually spent to produce them\.$/, "Mesuré sur $1 bloc(s), soit $2 heure(s) de chaîne. Ce chiffre ne se déclare pas : il se déduit du travail réellement dépensé pour les produire."],
    [/^matures in about (.+) days$/, "mûrit dans environ $1 jours"],
    [/^matures in about (.+)$/, "mûrit dans environ $1"],
    [/^next release: (.+) Q21 in (.+) block\(s\), about (.+) days — at block (.+)$/, "prochaine libération : $1 Q21 dans $2 bloc(s), soit environ $3 jours — au bloc $4"],
    [/^next release: (.+) Q21 in (.+) block\(s\), about (.+) — at block (.+)$/, "prochaine libération : $1 Q21 dans $2 bloc(s), soit environ $3 — au bloc $4"],
    [/^about (.+)% of the network's measured power$/, "soit environ $1 % de la puissance mesurée du réseau"],
    [/^epoch (.+) table — it grows by (.+)% every (.+) days$/, "table de l'époque $1 — elle grandit de $2 % tous les $3 jours"],
    [/^your machine recomputed every one of them itself — (.+) transaction\(s\) waiting to be included$/, "votre machine les a tous recalculés elle-même — $1 transaction(s) en attente d'être inscrite(s)"],
    [/^(.+) computer\(s\) connected\. What is shown below only counts blocks already verified by this machine\.$/, "$1 ordinateur(s) relié(s). Ce qui est affiché ci-dessous ne compte que les blocs déjà vérifiés par cette machine."],
    [/^(.+) attempts\/s$/, "$1 tentatives/s"],
    [/^· (.+) peer\(s\) · block (.+)$/, "· $1 pair(s) · bloc $2"],
    [/^(.+) GiB$/, "$1 Gio"],
    [/^· (.+) block\(s\) left$/, "· $1 bloc(s) restants"],
    [/^(.+) of (.+) blocks$/, "$1 sur $2 blocs"],
    [/^([\d.]+) blocks\/s · about (.+)$/, "$1 blocs/s · environ $2"],
    [/^([\d.]+) blocks\/s · time left unknown$/, "$1 blocs/s · durée inconnue"],
    [/^([\d.]+) blocks\/s$/, "$1 blocs/s"],
    [/^1 block \/ (.+) min$/, "1 bloc / $1 min"],
    [/^Your machine has verified (.+) block\(s\), but with no one to talk to it cannot know whether there are more\. The displayed balance may therefore be incomplete\.$/, "Votre machine a vérifié $1 bloc(s), mais sans personne à qui parler elle ne peut pas savoir s'il en existe d'autres. Le solde affiché est donc peut-être incomplet."],
    [/^Node suggestion for (.+) input\(s\) and (.+) output\(s\): about (.+) bytes, weight (.+), at a rate of (.+) unit\(s\) per thousand weight units\. You can change it\.$/, "Suggestion du nœud pour $1 entrée(s) et $2 sortie(s) : environ $3 octets, poids $4, au taux de $5 unité(s) par millier de poids. Modifiable."],
    [/^Insufficient funds: (.+) Q21 requested, (.+) Q21 spendable\.$/, "Fonds insuffisants : $1 Q21 demandés, $2 Q21 dépensables."],
    [/^(.+) — this address can only be spent by a signature of this scheme\.$/, "$1 — cette adresse ne peut être dépensée que par une signature de ce schéma."],
    [/^No address matches “(.*)”\. All (.+) of your addresses remain valid\.$/, "Aucune adresse ne correspond à « $1 ». Vos $2 adresses restent toutes valides."],
    [/^— (.+) bytes\.$/, "— $1 octets."],
    [/^(.+) unreadable block\(s\) — history incomplete$/, "$1 bloc(s) illisible(s) — historique incomplet"],
    [/^Searched from height (.+) to (.+)\. Anything earlier is not shown, but it is not lost either\.$/, "Recherche effectuée de la hauteur $1 à $2. Ce qui est antérieur n'est pas affiché, et n'est pas perdu pour autant."],
    [/^usable at block (.+)$/, "utilisable au bloc $1"],
    [/^(.*) The fee is rarely enough when the transaction consumes more inputs than expected: increase the number of expected inputs, recalculate, and try again\.$/, "$1 Les frais suffisent rarement quand la transaction consomme plus d'entrées que prévu : augmentez le nombre d'entrées supposées, recalculez, et recommencez."],
    [/^(.*) A previous payment is still pending and ties up the same coins\. Wait for a block to confirm it before sending another\.$/, "$1 Un envoi précédent est encore en attente et immobilise les mêmes pièces. Attendez qu'un bloc le confirme avant d'en émettre un autre."],
    [/^(.+) MiB$/, "$1 Mio"],
    [/^(.+) KiB$/, "$1 Kio"],
    [/^(\d+) B$/, "$1 o"]
  ],
  "ja": [
    [/^(.+) address\(es\) in total$/, "合計 $1 件のアドレス"],
    [/^(.+) requested address\(es\) · (.+) from mining, tucked away$/, "要求したアドレス $1 件 · マイニング用 $2 件は畳まれています"],
    [/^(.+) requested address\(es\)$/, "要求したアドレス $1 件"],
    [/^(.+) address\(es\) in total, (.+) of them from mining$/, "合計 $1 件のアドレス (うちマイニング用 $2 件)"],
    [/^Also show the (.+) mining address\(es\)$/, "マイニング用アドレス $1 件も表示する"],
    [/^No requested address yet\. The “New address” button creates one, which you can name\. Your (.+) mining address\(es\) are tucked away: they received your rewards and count in your balance\.$/, "要求したアドレスはまだありません。「新しいアドレス」ボタンで作成し、名前を付けられます。マイニング用アドレス $1 件は畳まれています。報酬を受け取っており、残高に含まれます。"],
    [/^(.+) earlier block\(s\) found — all counted in the total earned\.$/, "$1 件の古い発見 — すべて獲得合計に含まれます。"],
    [/^(.+) address\(es\) found out of (.+)$/, "$2 件中 $1 件のアドレスが該当"],
    [/^Block (.+)$/, "ブロック $1"],
    [/^Measured over (.+) block\(s\), or (.+) day\(s\) of chain time\. This figure is not declared by anyone: it is derived from the work actually spent to produce them\.$/, "$1 ブロック (チェーン $2 日分) で測定。この数値は申告されるものではなく、それらを生み出すために実際に費やされた仕事量から導かれます。"],
    [/^Measured over (.+) block\(s\), or (.+) hour\(s\) of chain time\. This figure is not declared by anyone: it is derived from the work actually spent to produce them\.$/, "$1 ブロック (チェーン $2 時間分) で測定。この数値は申告されるものではなく、それらを生み出すために実際に費やされた仕事量から導かれます。"],
    [/^matures in about (.+) days$/, "約 $1 日で成熟します"],
    [/^matures in about (.+)$/, "約 $1 で成熟します"],
    [/^next release: (.+) Q21 in (.+) block\(s\), about (.+) days — at block (.+)$/, "次の解放: $2 ブロック後 (約 $3 日) に $1 Q21 — ブロック $4"],
    [/^next release: (.+) Q21 in (.+) block\(s\), about (.+) — at block (.+)$/, "次の解放: $2 ブロック後 (約 $3) に $1 Q21 — ブロック $4"],
    [/^about (.+)% of the network's measured power$/, "ネットワークの測定パワーの約 $1 %"],
    [/^epoch (.+) table — it grows by (.+)% every (.+) days$/, "エポック $1 のテーブル — $3 日ごとに $2 % 増加します"],
    [/^your machine recomputed every one of them itself — (.+) transaction\(s\) waiting to be included$/, "あなたのマシンがすべて自ら再計算しました — 記録待ちの取引 $1 件"],
    [/^(.+) attempts\/s$/, "$1 回試行/秒"],
    [/^· (.+) peer\(s\) · block (.+)$/, "· $1 ピア · ブロック $2"],
    [/^(.+) GiB$/, "$1 GiB"],
    [/^(.+) of (.+) blocks$/, "$1 / $2 ブロック"],
    [/^(.+) MiB$/, "$1 MiB"],
    [/^(.+) KiB$/, "$1 KiB"],
    [/^(\d+) B$/, "$1 B"]
  ]
};
const I18N_PREFIXES = {"fr": {"Could not reach the node: ": "Impossible d'interroger le nœud : ", "Fee estimate failed: ": "Frais non estimés : ", "Information unavailable: ": "Informations indisponibles : ", "Could not read the balance again; payment stopped: ": "Solde non relu, envoi interrompu : ", "Name not saved: ": "Nom non enregistré : ", "The setting could not be changed: ": "Le réglage n'a pas pu être changé : ", "Mining could not be turned on: ": "Le minage n'a pas pu être activé : ", "Mining could not be turned off: ": "Le minage n'a pas pu être arrêté : "}, "ja": {"Could not reach the node: ": "ノードに問い合わせできません: ", "Fee estimate failed: ": "手数料を見積れません: ", "Insufficient funds: ": "残高不足: ", "Name not saved: ": "名前を保存できませんでした: "}};
let LANG = "en";

// Dates and numbers follow the language too: "08/12/2025" does not read like
// "12/08/2025", and a Japanese reader expects "2025/08/12". Translating the
// words while leaving the numbers in another convention would be a job half
// done.
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
    // Some messages carry a variable tail — an error, an amount. The fixed
    // part is then translated and the tail kept as is: better a half
    // translated sentence than a missing one.
    const pr = I18N_PREFIXES[LANG] || {};
    for (const k in pr){ if (n.startsWith(k)){ v = pr[k] + n.slice(k.length); break; } }
  }
  if (v === undefined){
    // Last chance: sentences built around a number. Exact matching can do
    // nothing for them — the number changes with every display — so the
    // variable parts are captured and only the rest is translated.
    for (const [pattern, template] of (I18N_PATTERNS[LANG] || [])){
      if (pattern.test(n)){ v = n.replace(pattern, template); break; }
    }
  }
  if (v === undefined) return null;
  // The original spacing is kept: the text is often stuck to a neighboring
  // tag, and eating it would shift the layout. A translation that brings its
  // own space at an end (French puts a no-break space before ":" after a
  // closing tag) replaces the source's there.
  const before = /^\s/.test(v) ? "" : src.match(/^\s*/)[0];
  const after = /\s$/.test(v) ? "" : src.match(/\s*$/)[0];
  return before + v + after;
}

function q21TranslateText(n){
  // If the current value is exactly what we wrote, it is our own writing: the
  // original stays the original. Otherwise the page's script has just
  // written, and that new value becomes the source to translate. Without this
  // distinction, a refresh would translate a translation, or overwrite fresh
  // data.
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
  // The selector itself keeps its labels: the name of a language is written
  // in that language, not in the page's.
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
    // What the script writes afterwards must be translated too, or the chosen
    // language would be lost at the first data refresh.
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
"use strict";

// ---------------------------------------------------------------------------
// Access token
// ---------------------------------------------------------------------------
//
// The launcher opens the browser on .../#<token>. The fragment is never sent
// to the server: no intermediary's log, no Referer header. It is read once,
// the address bar is erased at once — a screenshot, a shared tab or an
// autocompletion must not carry the secret away — and then it lives in a
// variable, and nowhere else.

const RPC = "/rpc";
const UNITS_PER_Q21 = 100000000n;

let token = null;
let counter = 0;
let currentAddress = null;
let preparedSend = null;
let refreshing = false;

// The token survives a refresh and the closing of the tab, as long as the
// program runs — and nothing else.
//
// The first version kept it in a plain variable. An F5 — everyone's reflex in
// front of a page that seems frozen — lost it, and the wallet became unusable
// until the launcher was restarted. That is exactly what happened to the
// first user. The second one stored it in `sessionStorage`, which dies with
// the tab: that was enough as long as the launcher's link could be reopened.
// It no longer can — it works only once — and closing the tab then cut the
// user off from their own wallet until the restart.
//
// `localStorage` is what remains, and it deserves a justification:
//
// - it is **partitioned by origin**, and the origin contains the port, which
//   the launcher draws at random on each start. What is written there is
//   therefore only good for that run;
// - the token itself is short-lived: the launcher draws a fresh one of
//   thirty-two bytes on each launch, and the old one no longer opens
//   anything. What remains in the browser after shutdown is an inert string,
//   erased at the first 401;
// - only the user's browser profile contains it — not the command line, not
//   the history, not a log.
//
// What is still refused: the token staying in the **address bar**, hence in
// the browser history, in an intermediary's logs and in the `Referer` header.
// The fragment is erased as soon as it is read.
//
// No wallet secret — neither seed nor passphrase — goes through there. A
// session token is not a key.
const SESSION_KEY = "q21-token";

// Every access to storage goes through here, and through the single key above.
function storage(){
  try { return window.localStorage; } catch (e) { return null; }
}

function storedToken(){
  try { const r = storage(); return r ? r.getItem(SESSION_KEY) : null; } catch (e) { return null; }
}

function keepToken(v){
  token = v;
  try { const r = storage(); if (v && r) r.setItem(SESSION_KEY, v); } catch (e) { /* refused by the browser: never mind */ }
}

function forgetToken(){
  token = null;
  try { const r = storage(); if (r) r.removeItem(SESSION_KEY); } catch (e) { /* nothing to do */ }
}

// --- The fragment no longer carries the token: it carries a launch token.
//
// The address opened by the launcher goes through the browser's command line,
// which other accounts on the machine can read. What it carries is therefore
// good only once: the page exchanges it, here, for the session token, and the
// node destroys it. Until the exchange is done, the calls wait — otherwise the
// first one would leave without a token.
let exchange = null;

async function exchangeLaunchToken(launchToken){
  try {
    const r = await fetch("/session", {method:"POST",
      headers:{"Content-Type":"application/json", "Authorization":"Bearer " + launchToken}});
    if (r.ok){ const d = await r.json(); keepToken(d.token); return; }
  } catch (e) { /* the node does not answer yet: the 401 that follows will open the panel */ }
  // The link has already been used. If this origin kept the token of the
  // current session — the tab was closed and then reopened from the history
  // — it resumes without asking anything. If it has expired, the 401 that
  // follows erases it and opens the panel.
  const kept = storedToken();
  if (kept){ token = kept; return; }
  showError("This link has already been used, or has expired. Start the wallet again to get a new one.");
}

(function readToken(){
  const f = location.hash.slice(1);
  if (f) {
    history.replaceState(null, "", location.pathname);
    let v = f;
    try { v = decodeURIComponent(f); } catch (e) { v = f; }
    exchange = exchangeLaunchToken(v);
    return;
  }
  // No fragment: a refresh, a page opened manually, or a tab reopened while
  // the program is still running.
  const kept = storedToken();
  if (kept) token = kept;
})();

function headers(){
  const h = {"Content-Type":"application/json"};
  if (token) h["Authorization"] = "Bearer " + token;
  return h;
}

function askForToken(){
  const p = document.getElementById("token-panel");
  p.hidden = false;
  document.getElementById("token-input").focus();
}

// The body is assembled by hand rather than by JSON.stringify on an object:
// an amount is an exact integer, and the only safe way to write it is to
// concatenate its digits. Going through an intermediate `Number` means
// accepting that above 2^53 the value sent is no longer the one that was
// confirmed.
function requestBody(method, params){
  const p = (typeof params === "string") ? params : JSON.stringify(params || {});
  return '{"jsonrpc":"2.0","id":' + (++counter) +
         ',"method":' + JSON.stringify(method) + ',"params":' + p + '}';
}

async function call(method, params){
  if (exchange){ await exchange; exchange = null; }
  const r = await fetch(RPC, {method:"POST", headers: headers(), body: requestBody(method, params)});
  // A 401 returns plain text, not JSON: reading it as JSON would hide the
  // real cause behind a parse error.
  if (r.status === 401){
    forgetToken();
    askForToken();
    throw new Error("access token missing or rejected");
  }
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------
//
// Everything that comes from the node is treated as hostile: an address, an
// error message, a transaction kind. `render` escapes by default; an intended
// markup fragment must declare itself through `raw`. The invariant does not
// rest on each caller's discipline, it rests on the type.

const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const raw = h => ({__html: h});
const render = x => (x && x.__html !== undefined) ? x.__html : esc(x);

// A markup fragment assembled right here, in which every variable value has
// already gone through `esc`. It declares itself: an interpolation that names
// neither `esc`, nor `render`, nor `html` is a forgotten interpolation, and a
// test checks it on the served page.
const html = f => render(raw(f));

// `trunc` shortened hashes for display. Nothing calls it any more: a hash that
// cannot be carried into the explorer's search is useless, and the two places
// that used it now show the full hash with a copy button. The function stays
// written here because this page's escaping rule names it among the safe
// outputs, and a future truncated display must go through it rather than
// through an improvised `slice`.
const trunc = (h,n)=> h ? esc(String(h).slice(0, n||16))+"…" : "—";
const date = t => new Date(Number(t) * 1000).toISOString().replace("T"," ").slice(0,19);

// A waiting time in blocks, translated into human time.
//
// The node gives the interval targeted by the protocol; it is not copied here,
// so that there is only one place in the world where that figure is written.
function blocksDuration(blocks, info){
  const t = Number(info && info.target_interval_seconds) || 120;
  const sec = Math.max(0, Number(blocks) || 0) * t;
  if (sec < 90) return "about " + Math.round(sec) + " s";
  if (sec < 5400) return "about " + Math.round(sec / 60) + " min";
  if (sec < 172800) return "about " + (sec / 3600).toFixed(1) + " h";
  return "about " + (sec / 86400).toFixed(1) + " days";
}

// A quantity of bytes, in the unit in which a human recognizes it. Powers of
// 1024, not of 1000: that is how a memory stick is counted, and memory is what
// this is about.
function formatBytes(n){
  n = Number(n) || 0;
  if (n >= 1073741824) return (n / 1073741824).toFixed(2) + " GiB";
  if (n >= 1048576)    return (n / 1048576).toFixed(0) + " MiB";
  if (n >= 1024)       return (n / 1024).toFixed(0) + " KiB";
  return String(Math.round(n)) + " B";
}

function tile(k,v,n){
  const foot = n ? `<div class="n">${render(n)}</div>` : "";
  return `<div class="tile"><div class="k">${esc(k)}</div>
          <div class="v">${render(v)}</div>${html(foot)}</div>`;
}

// ---------------------------------------------------------------------------
// Amounts: no float, ever
// ---------------------------------------------------------------------------
//
// There are 100,000,000 indivisible units per Q21. Reading a balance in
// floating point silently loses units, and a currency that rounds lies. All
// the arithmetic is done on arbitrarily large integers, and the conversion
// from human input splits the string on the decimal point without ever
// passing it through a floating-point number.

function unitsFromQ21(input){
  let t = String(input).trim().replace(/[ \u00a0\u202f_]/g, "").replace(",", ".");
  if (t === "" || t === ".") return null;
  if (!/^[0-9]*\.?[0-9]*$/.test(t)) return null;
  const p = t.split(".");
  const whole = p[0] === "" ? "0" : p[0];
  const frac = p.length > 1 ? p[1] : "";
  if (frac.length > 8) return null;
  const padded = (frac + "00000000").slice(0, 8);
  return BigInt(whole) * UNITS_PER_Q21 + BigInt(padded);
}

function q21FromUnits(u){
  const n = BigInt(u);
  const e = n / UNITS_PER_Q21;
  const f = n % UNITS_PER_Q21;
  return e.toString() + "." + f.toString().padStart(8, "0");
}

// Amounts arrive from the node in two fields: `units` (integer) and `q21`
// (string already formatted). The units are taken, the only value one can
// compute with. `Json::u64` switches to a string above i64::MAX: `BigInt`
// accepts both forms, a `Number` would lose half of them.
function unitsOf(m){
  return BigInt((m && typeof m === "object") ? m.units : m);
}

function bigAmount(q21){
  const s = String(q21);
  const i = s.indexOf(".");
  if (i < 0) return `<span class="big">${esc(s)}</span><span class="unit">Q21</span>`;
  return `<span class="big">${esc(s.slice(0,i))}<span class="cents">${esc(s.slice(i))}</span></span>` +
         `<span class="unit">Q21</span>`;
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

const VIEWS = ["balance","mine","receive","network","send","activity","info"];

function show(name){
  for (const v of VIEWS){
    document.getElementById("view-" + v).hidden = (v !== name);
  }
  for (const b of document.querySelectorAll("#tabs button")){
    b.classList.toggle("active", b.dataset.view === name);
  }
  if (name === "send" && !document.getElementById("fee-field").value) estimateFee();
  if (name === "activity") loadActivity();
  if (name === "info") loadInfo();
  if (name === "receive") listAddresses();
  if (name === "mine") loadMining();
  if (name === "network") loadNetwork();
}

document.getElementById("tabs").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-view]");
  if (b) show(b.dataset.view);
});

// The balance's quick actions: the three things people come for nine times
// out of ten, one gesture away from the figure they just read.
document.addEventListener("click", ev => {
  const b = ev.target.closest("button[data-go]");
  if (b) show(b.dataset.go);
});

document.getElementById("token-form").addEventListener("submit", ev => {
  ev.preventDefault();
  const field = document.getElementById("token-input");
  const v = field.value.trim();
  if (!v) return;
  keepToken(v);
  field.value = "";
  document.getElementById("token-panel").hidden = true;
  refresh();
});

// ---------------------------------------------------------------------------
// Balance and syncing
// ---------------------------------------------------------------------------
//
// A wallet that shows a wrong figure without saying so is a wallet that lies.
// As long as the node is not synced, the banner stays visible: it does not
// close by itself and cannot be closed by hand.

function showError(message){
  document.getElementById("error").hidden = false;
  document.getElementById("error-detail").textContent = message;
}

async function refresh(){
  if (refreshing) return;
  refreshing = true;
  try{
    const [sync, balance, info] = await Promise.all([
      call("getsyncstatus"), call("getbalance"), call("getinfo")
    ]);
    document.getElementById("error").hidden = true;
    // The node announces "Testnet" (the Debug name of the enum). So the
    // comparison is done in lowercase: the first version compared with an
    // exact "testnet" and the badge showed the raw value it believed it was
    // translating.
    document.getElementById("network").textContent =
      String(info.network).toLowerCase() === "testnet" ? "testnet" : info.network;
    pulse(sync);

    // --- The catch-up banner.
    //
    // It does not announce "restore in progress": the node does not know
    // that, and claiming it would be making it up. It announces what is
    // really happening — the chain is being caught up — and then adds a
    // **conditional** line for whoever has just restored. The conditional is
    // true in both cases.
    const banner = document.getElementById("sync-banner");
    if (sync.synced){
      banner.hidden = true;
    } else {
      banner.hidden = false;
      const here = Number(sync.height), there = Number(sync.network_height) || 1;
      const alone = Number(sync.peers) === 0;

      // --- Alone for two opposite reasons, which used to look the same.
      //
      // A node without peers either has nobody's address, or it knocked and
      // nobody opened. The first case is fixed in two lines; the second
      // requires looking at the server or the network. As long as both said
      // "no computer reachable", the newcomer concluded that the network was
      // dead — when a file was all that was missing. That is the most likely
      // way to give up on a first launch, and the only one the page could
      // prevent on its own.
      const blind = alone && Number(info.configured_bootstrap) === 0;

      // --- Without peers, there is nothing to measure.
      //
      // The bar showed "210 of 210" and filled up entirely under a waiting
      // title: a finished progress for an operation that had not started. A
      // node without peers does not know the network's height; it knows its
      // own, and that is all. So the measure is hidden rather than showing a
      // false one.
      document.getElementById("catchup-measure").hidden = alone;
      document.getElementById("catchup-title").textContent = blind
        ? "No bootstrap address: this node is not looking for anyone"
        : alone
        ? "Waiting for a computer to ask for the chain"
        : "Catching up on chain history";
      if (!alone){
        const pct = Math.max(0, Math.min(100, (here / there) * 100));
        document.getElementById("catchup-bar").style.width = pct.toFixed(1) + "%";
        document.getElementById("catchup-position").textContent =
          here.toLocaleString(q21Locale()) + " of " + there.toLocaleString(q21Locale()) + " blocks";
        // The speed comes from the same derivative as the network's; without
        // it, no duration is announced, rather than making one up.
        document.getElementById("catchup-speed").textContent =
          blockSpeed > 0.05
            ? blockSpeed.toFixed(1) + " blocks/s · " + timeLeft(Number(sync.blocks_remaining))
            : "measuring speed";
      }
      document.getElementById("sync-note").textContent = sync.note;
      // A wallet that has derived almost nothing and is catching up with the
      // chain is very probably a restore. It is not claimed: the line speaks
      // to the user through a condition they will recognize. Except when the
      // node is blind: promising that the funds will come back "at the end of
      // this step" would be false reassurance, since the step cannot start.
      document.getElementById("catchup-restored").hidden =
        blind || Number(balance.derived_addresses) > 2;
      document.getElementById("sync-detail").textContent = blind
        ? "The program contains no server address, and that is deliberate: " +
          "an address hard-coded into distributed software would become a permanent " +
          "dependency on whoever controls it. It is provided separately, in a file " +
          "you can edit. Create q21-data/bootstrap.txt next to the program, " +
          "add the line bootstrap.q21.dev:21121 to it, then restart. JOIN.md, which ships " +
          "with the program, explains this step and how to add more entry points."
        : alone
        ? "Your machine has verified " + here.toLocaleString(q21Locale()) + " block(s), but " +
          "with no one to talk to it cannot know whether there are more. " +
          "The displayed balance may therefore be incomplete."
        : sync.peers + " computer(s) connected. What is shown below only " +
          "counts blocks already verified by this machine.";
    }

    document.getElementById("balance-big").innerHTML = bigAmount(balance.spendable.q21);
    document.getElementById("balance-note").textContent =
      sync.synced ? "" : "incomplete figure, see the warning above";

    const total = unitsOf(balance.spendable) + unitsOf(balance.immature);
    // --- "When?": the only question one asks in front of a locked balance.
    //
    // The tile announced a pending amount without ever saying when it would be
    // released. A miner saw their earnings rise and their available balance
    // stay at zero for hours, with nothing to go by: several took it for a
    // fault. So the next release is announced, in blocks and in time.
    const pendingNote = balance.next_maturity_blocks !== undefined
      ? "next release: " + esc(balance.next_maturity_amount.q21) +
        " Q21 in " + esc(String(balance.next_maturity_blocks)) + " block(s), " +
        blocksDuration(balance.next_maturity_blocks, info) + " — at block " +
        esc(String(balance.next_maturity_height))
      : "mining rewards: they belong to you, but cannot be used yet";
    document.getElementById("balance-tiles").innerHTML =
      tile("Awaiting maturity", esc(balance.immature.q21) + " Q21", pendingNote) +
      tile("Total held", esc(q21FromUnits(total)) + " Q21", "available and pending combined") +
      tile("Blocks verified", info.height,
            "your machine recomputed every one of them itself — " + info.mempool +
            " transaction(s) waiting to be included");
  }catch(e){
    showError("Could not reach the node: " + e.message);
  }finally{
    refreshing = false;
  }
}

// ---------------------------------------------------------------------------
// Receive
// ---------------------------------------------------------------------------

function chunks(a, n){
  const t = String(a);
  const size = n || 8;
  const out = [];
  for (let i = 0; i < t.length; i += size) out.push(t.slice(i, i + size));
  return out;
}

document.getElementById("new-address-button").addEventListener("click", async () => {
  const zone = document.getElementById("new-address-zone");
  zone.innerHTML = `<p class="help">Requesting…</p>`;
  try{
    const a = await call("getnewaddress");
    currentAddress = a.address;
    const warning = a.one_time
      ? `<div class="warn"><h3>Single-use address</h3><p>${esc(a.warning)}</p></div>`
      : `<div class="note"><h3>Reuse</h3><p>${esc(a.warning)}</p></div>`;
    zone.innerHTML = `
      <div class="address">
        <div class="chunks">${chunks(a.address, 8).map(g=>`<span class="chunk">${esc(g)}</span>`).join("")}</div>
        <button type="button" class="copy-address" id="copy-button">copy</button>
      </div>
      ${html(warning)}
      <div class="note"><h3>Scheme</h3><p>${esc(a.scheme)} — this address can only be spent by a signature of this scheme.</p></div>`;
    document.getElementById("copy-button").addEventListener("click", ev => copyText(currentAddress, ev.target));
    // The new address joins the address book right away, and its name field
    // opens: this is the moment when one still knows who it is for.
    try{
      bookFilter = "";
      document.getElementById("address-filter").value = "";
      await listAddresses();
      const fresh = book.find(e => e.address === a.address);
      if (fresh){
        const z = document.querySelector('[data-edit="' + fresh.key_index + '"]');
        if (z){ z.hidden = false; z.querySelector("input").focus(); }
      }
    }catch(_){}
  }catch(e){
    zone.innerHTML = `<div class="warn"><h3>Address not created</h3><p>${esc(e.message)}</p></div>`;
  }
});

async function copyText(text, button){
  // The label comes back as it was: "Copy", "copy" or "Copy the address".
  const label = button.textContent;
  const reset = () => setTimeout(()=>{ button.textContent = label; }, 2000);
  try{
    if (navigator.clipboard && navigator.clipboard.writeText){
      await navigator.clipboard.writeText(text);
    } else {
      const z = document.createElement("textarea");
      z.value = text;
      document.body.appendChild(z);
      z.select();
      document.execCommand("copy");
      z.remove();
    }
    button.textContent = "copied";
  }catch(e){
    button.textContent = "the browser blocked copying";
  }
  reset();
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

async function estimateFee(){
  const help = document.getElementById("fee-help");
  const n = document.getElementById("inputs-field").value.trim();
  const inputs = /^[0-9]+$/.test(n) ? Math.min(Math.max(parseInt(n, 10), 1), 100) : 2;
  // One output per recipient, plus the change: the fee follows the number of
  // recipients when the payment has several.
  const recipients = 1 + document.querySelectorAll("#extra-recipients .extra-recipient").length;
  const outputs = recipients + 1;
  try{
    const f = await call("estimatefee", '{"inputs":' + inputs + ',"outputs":' + outputs + '}');
    document.getElementById("fee-field").value = f.suggested_fee.q21;
    help.textContent =
      "Node suggestion for " + f.inputs + " input(s) and " + f.outputs +
      " output(s): about " + f.estimated_size_bytes + " bytes, weight " +
      f.estimated_weight + ", at a rate of " + f.rate_per_kilo_weight +
      " unit(s) per thousand weight units. You can change it.";
  }catch(e){
    help.textContent = "Fee estimate failed: " + e.message;
  }
}

document.getElementById("estimate-button").addEventListener("click", estimateFee);

// Adds an "additional recipient" row. The template is static — no data is
// interpolated into it — to stay out of reach of any injection: the fields
// start empty, and the user fills them in afterwards.
document.getElementById("add-recipient-button").addEventListener("click", () => {
  const zone = document.getElementById("extra-recipients");
  const row = document.createElement("div");
  row.className = "extra-recipient";
  row.style.marginTop = ".6rem";
  row.innerHTML =
    '<label>Address of another recipient</label>'
  + '<input type="text" class="extra-address" placeholder="tq21…" spellcheck="false" autocomplete="off">'
  + '<label>Amount (Q21)</label>'
  + '<input type="text" class="extra-amount" placeholder="0.00000000" inputmode="decimal" spellcheck="false" autocomplete="off">'
  + '<div class="buttons"><button type="button" class="secondary extra-remove">Remove</button></div>';
  zone.appendChild(row);
  row.querySelector(".extra-remove").addEventListener("click", () => row.remove());
});

document.getElementById("send-form").addEventListener("submit", async ev => {
  ev.preventDefault();
  document.getElementById("send-result").innerHTML = "";

  const refuse = m => {
    document.getElementById("send-result").innerHTML =
      `<div class="warn"><h3>Payment not prepared</h3><p>${esc(m)}</p></div>`;
  };

  // The main recipient, then any added recipients. A single validation path
  // for all of them: each amount is an integer number of units.
  const destinations = [];
  const a0 = document.getElementById("address-field").value.trim();
  const m0 = unitsFromQ21(document.getElementById("amount-field").value);
  if (!a0) return refuse("No recipient address.");
  if (m0 === null) return refuse("Invalid amount. Expected a number in Q21, with at most eight decimal places.");
  if (m0 <= 0n) return refuse("The amount must be greater than zero.");
  if (m0 < 10000n) return refuse("The minimum amount is 0.0001 Q21: below that, the network rejects the output as dust.");
  destinations.push({address: a0, amount: m0});

  for (const row of document.querySelectorAll("#extra-recipients .extra-recipient")) {
    const a = row.querySelector(".extra-address").value.trim();
    const mm = unitsFromQ21(row.querySelector(".extra-amount").value);
    if (!a) return refuse("An additional recipient has no address. Remove the row or fill it in.");
    if (mm === null) return refuse("An additional amount is invalid. Expected a number in Q21.");
    if (mm <= 0n) return refuse("Each amount must be greater than zero.");
    if (mm < 10000n) return refuse("Each amount must be at least 0.0001 Q21: below that, the network rejects the output as dust.");
    destinations.push({address: a, amount: mm});
  }

  const fee = unitsFromQ21(document.getElementById("fee-field").value);
  if (fee === null) return refuse("Invalid fee. Expected a number in Q21, with at most eight decimal places.");
  if (fee < 0n) return refuse("The fee cannot be negative.");

  let sum = 0n;
  for (const d of destinations) sum += d.amount;
  const total = sum + fee;

  // The balance is read again now, not when the page was loaded: a block may
  // have arrived in between.
  let spendable = null;
  try{
    spendable = unitsOf((await call("getbalance")).spendable);
  }catch(e){
    return refuse("Could not read the balance again; payment stopped: " + e.message);
  }
  if (total > spendable){
    return refuse("Insufficient funds: " + q21FromUnits(total) +
                 " Q21 requested, " + q21FromUnits(spendable) + " Q21 spendable.");
  }

  const recapRows = destinations.map(d =>
      `<div class="l"><span class="k">Recipient</span><span class="v">${esc(d.address)}</span></div>`
    + `<div class="l"><span class="k">Amount</span><span class="v">${esc(q21FromUnits(d.amount))} Q21</span></div>`
    ).join("");
  document.getElementById("recap").innerHTML = recapRows
    + `<div class="l"><span class="k">Fee</span><span class="v">${esc(q21FromUnits(fee))} Q21</span></div>`
    + `<div class="l total"><span class="k">Total debited</span><span class="v">${esc(q21FromUnits(total))} Q21</span></div>`
    + `<div class="l"><span class="k">Balance after</span><span class="v">${esc(q21FromUnits(spendable - total))} Q21</span></div>`;

  // A single recipient keeps the original form — and the sendtoaddress path
  // that goes with it; several carry the list, sent by sendmany.
  if (destinations.length === 1) {
    preparedSend = {address: a0, amount: m0, fee: fee};
  } else {
    preparedSend = {destinations: destinations, fee: fee};
  }
  document.getElementById("send-form").hidden = true;
  document.getElementById("confirmation").hidden = false;
});

document.getElementById("cancel-button").addEventListener("click", () => {
  preparedSend = null;
  document.getElementById("confirmation").hidden = true;
  document.getElementById("send-form").hidden = false;
});

document.getElementById("send-button").addEventListener("click", async () => {
  if (!preparedSend) return;
  const b = document.getElementById("send-button");
  b.disabled = true;
  b.textContent = "Sending…";
  const p = preparedSend;
  // The integers go out as digits, without going through a `Number`: it is
  // the only way to be certain that the amount sent is the one that was shown
  // on the confirmation screen. One recipient takes sendtoaddress; several
  // take sendmany, with the same rigor on each amount.
  let method, params;
  if (p.destinations) {
    const items = p.destinations.map(d =>
      '{"address":' + JSON.stringify(d.address) + ',"units":' + d.amount.toString() + '}'
    ).join(",");
    method = "sendmany";
    params = '{"destinations":[' + items + '],"fee":' + p.fee.toString() + '}';
  } else {
    method = "sendtoaddress";
    params = '{"address":' + JSON.stringify(p.address) +
             ',"units":' + p.amount.toString() +
             ',"fee":' + p.fee.toString() + '}';
  }
  try{
    const r = await call(method, params);
    preparedSend = null;
    document.getElementById("confirmation").hidden = true;
    document.getElementById("send-form").hidden = false;
    document.getElementById("amount-field").value = "";
    document.getElementById("address-field").value = "";
    document.getElementById("extra-recipients").innerHTML = "";
    document.getElementById("send-result").innerHTML = `
      <div class="note">
        <h3>✓ Payment sent to the network</h3>
        <p>
          It has been announced to peers and is waiting to enter a block —
          expect about two minutes. Until a block contains it, it is
          <strong>not confirmed yet</strong>.
        </p>
        <p>
          <a class="flat" href="/#/tx/${esc(r.txid)}" target="_blank" rel="noopener">Follow
          this transaction in the explorer</a>
        </p>
        <p class="help">Reference: <span class="clip">${esc(r.txid)}</span> —
        ${esc(r.transaction.size_bytes)} bytes.</p>
      </div>`;
    refresh();
    // --- Then the user is taken to see their transaction.
    //
    // A confirmation written on the send screen left the doubt intact: the
    // balance had dropped, and the Activity tab — the only place where one
    // checks that a payment exists — stayed empty until the next block. So the
    // user is taken there, where the row is now already present, marked
    // "pending". Seeing beats reading that one could have seen.
    //
    // The delay leaves time to read the green card before the screen changes:
    // switching within the second would feel like a jumping screen.
    setTimeout(() => show("activity"), 1200);
  }catch(e){
    let hint = "";
    if (/FeeRateTooLow|fee/i.test(e.message)){
      hint = " The fee is rarely enough when the transaction consumes more " +
             "inputs than expected: increase the number of expected inputs, " +
             "recalculate, and try again.";
    } else if (/SpendConflict/i.test(e.message)){
      // Seen on a real node: a payment still pending ties up the coins it
      // consumes, and the next one runs into them. The node's message is
      // accurate but unreadable for someone who does not have the structure
      // in mind.
      hint = " A previous payment is still pending and ties up the same " +
             "coins. Wait for a block to confirm it before sending another.";
    }
    document.getElementById("confirmation").hidden = true;
    document.getElementById("send-form").hidden = false;
    document.getElementById("send-result").innerHTML =
      `<div class="warn"><h3>Payment rejected</h3><p>${esc(e.message)}${esc(hint)}</p>
       <p>No funds have moved.</p></div>`;
  }finally{
    b.disabled = false;
    b.textContent = "Send now";
  }
});

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

// The "sent" cell of a row.
//
// The node only carries `net_out` on a send: elsewhere there is nothing to
// show, and a zero would read as a measurement. When the coin spent predates
// the window examined, `amount_out_known` is false: the amount is then a
// floor, shown preceded by "≥" and not as a fact. The amount comes from
// `q21`, a string already formatted by the node — no arithmetic here, hence
// no float.
function outCell(m){
  if (!m.net_out) return raw(`<span class="empty">—</span>`);
  if (m.amount_out_known === false){
    return raw(`<span class="floor">${esc("≥ " + m.net_out.q21)}</span>`);
  }
  return m.net_out.q21;
}

// What needs saying under the table, and only when there is reason to say it.
function columnNotes(h){
  let t = "";
  if (h.movements.some(m => m.kind === "send")){
    t += `<div class="note"><h3>Received and sent on the same row</h3>
      <p>A payment almost never spends a coin of the exact size: the wallet
      spends a bigger one, and the difference comes back to it as change, on
      a fresh address, like a bill handed back. The
      <strong>received</strong> column holds that change; the <strong>sent</strong>
      column, what actually left the wallet — amount paid and fee included.</p></div>`;
  }
  if (h.amounts_out_all_resolved === false){
    t += `<div class="warn"><h3>Amounts sent incomplete</h3>
      <p>For at least one payment, the coin spent predates the window
      examined: its value was not found, so the amount sent cannot be
      established. These amounts are shown preceded by “≥” — a minimum,
      not a fact.</p></div>`;
  }
  return t;
}

// The kind of a movement as the node reports it, and the word this page shows
// for it. The translation tables then turn that word into the reader's
// language, as for any other text of the page.
const KIND_LABELS = {mining: "mining", send: "outgoing", receive: "incoming"};

// The icon of a movement: three hard-coded drawings, chosen by the kind the
// node announces. An unknown kind falls back on the receiving arrow — a wrong
// drawing would be worse than a generic one.
function kindIcon(m){
  const g = String(m.kind);
  if (g === "mining"){
    return raw('<span class="dir mine"><svg viewBox="0 0 24 24" aria-hidden="true">' +
      '<path d="M13 2L4 14h6l-1 8 9-12h-6z"></path></svg></span>');
  }
  if (m.net_out){
    return raw('<span class="dir out"><svg viewBox="0 0 24 24" aria-hidden="true">' +
      '<path d="M12 20V7"></path><path d="M6 12l6-6 6 6"></path></svg></span>');
  }
  return raw('<span class="dir in"><svg viewBox="0 0 24 24" aria-hidden="true">' +
    '<path d="M12 4v13"></path><path d="M6 12l6 6 6-6"></path></svg></span>');
}

// The small spinning disc, for what has left but is not yet written in a
// block.
//
// A still badge saying "pending" reads as a frozen state; motion says "it is
// working". That is the difference between waiting and worrying. The
// animation is pure CSS, with no image or script: nothing to load, and it
// stops by itself when the row switches to confirmed.
function spinner(){
  return raw('<span class="spin-dot" aria-hidden="true"></span>');
}

// --- The reference is copied, not retyped by hand.
//
// It used to be cut at twenty characters followed by an ellipsis. To read it,
// that was enough; to **carry** it into the explorer's search, forty-four were
// missing, and nothing said so. A reference that cannot be carried away is
// useless.
//
// The listener is attached once on the table body, not on each button: the
// rows are rebuilt on each refresh, and listeners attached row by row would
// pile up on every round.
for (const zone of ["movements", "chain-tiles"]){
  document.getElementById(zone).addEventListener("click", ev => {
    const b = ev.target.closest("button.copy[data-ref]");
    if (b) copyText(b.dataset.ref, b);
  });
}

// --- The activity refreshes itself, and can be filtered.
//
// Two gaps reported in use. A transaction received showed up as "pending" and
// **stayed there**: one had to switch tabs and come back to see it
// confirmed. And with a few dozen mining rewards, the day's only transfer got
// lost in the middle.
//
// The refresh is deliberately slower than the balance's: each call makes the
// node read blocks again, and the activity does not need to be accurate to
// the second. Ten seconds are enough for a confirmation to appear "on its
// own", which is the only thing asked.
let activityFilter = "all";
let activityLoading = false;

// What is asked of the node: the filter goes with the request, so that the
// limit counts rows of the chosen kind. In 0.4.1 the page filtered the last
// hundred rows itself, and a mining wallet's transfers never made it into
// them. Only the four known values can leave this page.
//
// "Show more" raises the limit by a hundred rows, up to what the node serves
// in one answer. The refresh keeps the limit chosen: rows already read do not
// vanish ten seconds later.
const ACTIVITY_STEP = 100;
const ACTIVITY_MAX = 2000;
let activityLimit = ACTIVITY_STEP;

function activityQuery(){
  const kind = ["send", "receive", "mining"].includes(activityFilter) ? activityFilter : "all";
  const limit = String(Math.min(Math.max(Number(activityLimit) || ACTIVITY_STEP, 1), ACTIVITY_MAX));
  return kind === "all" ? '{"limit":' + limit + '}' : '{"limit":' + limit + ',"kind":"' + kind + '"}';
}

function matchesFilter(m){
  if (activityFilter === "all") return true;
  return String(m.kind) === activityFilter;
}

async function loadActivity(){
  // Two overlapping rounds would read the chain twice for nothing, and the
  // second would overwrite the first on arrival.
  if (activityLoading) return;
  activityLoading = true;
  const tbody = document.getElementById("movements");
  const zone = document.getElementById("activity-note");
  const below = document.getElementById("columns-note");
  try{
    // Both calls go out together: the history, and the protocol constants
    // that turn a wait in blocks into a duration.
    const [h, chainInfo] = await Promise.all([
      call("listtransactions", activityQuery()),
      call("getinfo")
    ]);
    const maturity = Number(chainInfo.coinbase_maturity) || 200;
    // A truncated history that does not say so suggests missing funds. The
    // node says how far it looked; we repeat it.
    // A block of the chain whose body is unreadable is not the same thing as
    // a history truncated by the search window: the first is an incident, the
    // second a setting. Confusing them made someone believe a transfer had
    // vanished; we tell them apart, and say what to do.
    const unreadable = Number(h.unreadable_blocks) || 0;
    zone.innerHTML = unreadable > 0
      ? `<div class="warn"><h3>${esc(String(unreadable))} unreadable block(s) — history incomplete</h3>
         <p>${esc(h.note)}</p>
         <p><strong>Your funds are not lost</strong>: the balance is still correct.
         Close and reopen the wallet: it will request these blocks from the network again.</p></div>`
      : h.complete_history
      ? `<div class="note"><h3>Full history</h3><p>${esc(h.note)}</p></div>`
      : `<div class="warn"><h3>Partial history</h3><p>${esc(h.note)}</p>
         <p>Searched from height ${esc(h.scanned_from_height)} to ${esc(h.height)}. Anything earlier is not shown, but it is not lost either.</p></div>`;
    below.innerHTML = columnNotes(h);

    // The node filters before its limit (since 0.4.2): what is shown here
    // is already the right kind, and an empty answer means there is none.
    const shown = h.movements.filter(matchesFilter);
    // A full page means there may be more: the button offers them.
    document.getElementById("activity-more-zone").hidden =
      h.movements.length < activityLimit || activityLimit >= ACTIVITY_MAX;
    if (!shown.length){
      tbody.innerHTML = activityFilter !== "all"
        ? `<tr><td colspan="7">No movement of this type in the history searched.</td></tr>`
        : `<tr><td colspan="7">Nothing yet. Your first
        movements will appear here — receive Q21 from the Receive tab,
        or find a block from the Mine tab.</td></tr>`;
      return;
    }
    tbody.innerHTML = shown.map(m => {
      // Three states, three marks. "pending" wins over "immature": a
      // transaction that is in no block has no maturity to discuss yet.
      // An immature reward now says **how long** until it can be used.
      // "Immature" alone is a state, not information: it leaves untouched the
      // question one asks on reading it.
      let mark;
      if (m.pending){
        mark = ` <span class="badge pending">${render(spinner())} pending</span>`;
      } else if (!m.mature){
        // Neither `Number()` nor any conversion: these two fields are counting
        // integers returned by the node, never amounts. The rule "no float on
        // an amount" stays whole, and the test that guards it forbids any
        // numeric conversion on a movement field, on principle — we do not
        // work around it, we do not need to.
        const left = maturity - m.confirmations;
        mark = ` <span class="badge pending" title="usable at block ${esc(String(m.height + maturity))}">`
               + `matures in ${esc(blocksDuration(left > 0 ? left : 0, chainInfo))}</span>`;
      } else {
        mark = "";
      }
      // The icon says the direction before the word is read; the color of the
      // amount repeats it. The three drawings are hard-coded, the kind picks
      // one.
      const gotSome = BigInt(m.received.units) > 0n;
      return `
      <tr>
        <td>${render(kindIcon(m))} ${esc(KIND_LABELS[m.kind] || m.kind)}</td>
        <td${html(gotSome ? ' class="plus"' : '')}>${esc(gotSome ? "+ " + m.received.q21 : "—")}</td>
        <td${html(m.net_out ? ' class="minus"' : '')}>${render(outCell(m))}</td>
        <td>${esc(m.confirmations)}${html(mark)}</td>
        <td>${esc(m.pending ? "—" : m.height)}</td>
        <td>${esc(date(m.timestamp))}</td>
        <td class="ref"><span class="full">${esc(m.txid)}</span>
          <button type="button" class="flat copy" data-ref="${esc(m.txid)}">copy</button></td>
      </tr>`;
    }).join("");
  }catch(e){
    zone.innerHTML = `<div class="warn"><h3>History unavailable</h3><p>${esc(e.message)}</p></div>`;
    tbody.innerHTML = "";
    below.innerHTML = "";
  }finally{
    activityLoading = false;
  }
}

// A single listener for the four buttons. The filter asks nothing new of the
// node: it replays the display on what is already there, so it is instant.
document.getElementById("activity-filters").addEventListener("click", ev => {
  const b = ev.target.closest("button[data-filter]");
  if (!b) return;
  activityFilter = b.dataset.filter;
  activityLimit = ACTIVITY_STEP;
  for (const other of document.querySelectorAll("#activity-filters button")){
    other.classList.toggle("active", other === b);
  }
  loadActivity();
});

document.getElementById("activity-more-button").addEventListener("click", () => {
  activityLimit = Math.min(activityLimit + ACTIVITY_STEP, ACTIVITY_MAX);
  loadActivity();
});

// As long as the screen is visible, it keeps itself up to date. Hidden, it
// costs nothing: a wallet left open on the balance must not make the node
// read the chain again.
setInterval(() => {
  if (!document.getElementById("view-activity").hidden) loadActivity();
}, 10000);

// ---------------------------------------------------------------------------
// Information
// ---------------------------------------------------------------------------

async function loadInfo(){
  try{
    const [w, info, commit] = await Promise.all([
      call("getwalletinfo"), call("getinfo"), call("getutxocommitment")
    ]);
    document.getElementById("info-tiles").innerHTML =
      tile("Program version", "q21 " + info.version,
            "the one you are running — compare it with the version announced in the release") +
      tile("Signature scheme", w.scheme, "resistant to quantum computers — see below") +
      tile("Network", w.network);

    document.getElementById("chain-tiles").innerHTML =
      tile("Blocks verified", info.height) +
      // Same reason as in the history: a truncated hash cannot be carried
      // into the explorer's search.
      tile("Latest block", raw(
        `<span class="full">${esc(info.tip)}</span>` +
        `<button type="button" class="flat copy" data-ref="${esc(info.tip)}">copy</button>`)) +
      tile("Q21 issued to date", esc(info.issued.q21) + " Q21") +
      tile("Unspent outputs", info.utxo_total, "across the whole chain, all holders combined") +
      // The state commitment: two nodes at the same height carry it
      // identical. It is given in full, with a copy button, so that it can be
      // compared with the explorer's — that is its whole purpose.
      tile("State commitment", raw(
        `<span class="full">${esc(commit.commitment)}</span>` +
        `<button type="button" class="flat copy" data-ref="${esc(commit.commitment)}">copy</button>`),
        "a unique fingerprint of all the money in existence: two nodes at the same height show the same value — your proof that you are on the real chain, without trusting anyone");
  }catch(e){
    showError("Information unavailable: " + e.message);
  }
}

// ---------------------------------------------------------------------------
// Closing the wallet
//
// The only way to stop it used to be Ctrl-C in the black window. On Windows,
// the command interpreter then asks its own question — "Terminate batch job
// (Y/N)?" — and both answers close the window. The first user read it as a
// crash. An application closes with a button; this one asks the node to shut
// down cleanly.
//
// Two clicks, not one: stopping the wallet while looking at the balance is not
// serious, but doing it by mistake in the middle of an unconfirmed payment
// forces a restart. The confirmation costs a second and withdraws itself after
// five.
// ---------------------------------------------------------------------------

// The link to the explorer carries no token at all. The explorer is served by
// the same node on the same port - the same origin - and reads the token this
// page stored. Until 0.4.1 the link put the session token in the fragment; the
// explorer took it for a launch token, the exchange failed, and the page asked
// for a token the user had never seen.

let heartbeat = setInterval(refresh, 6000);
let closeConfirmed = false;
let closeTimer = null;

function closeNote(text, cls){
  const n = document.getElementById("close-note");
  n.className = "help" + (cls ? " " + cls : "");
  n.textContent = text;
}

document.getElementById("close-button").addEventListener("click", async () => {
  const b = document.getElementById("close-button");
  if (!closeConfirmed){
    closeConfirmed = true;
    b.textContent = "Confirm shutdown";
    closeNote("Click again to stop the wallet.");
    if (closeTimer) clearTimeout(closeTimer);
    closeTimer = setTimeout(() => {
      closeConfirmed = false;
      b.textContent = "Close the wallet";
      closeNote("");
    }, 5000);
    return;
  }
  if (closeTimer) clearTimeout(closeTimer);
  b.disabled = true;
  b.textContent = "Shutting down…";
  try{
    await call("stop");
  }catch(e){
    // The node may cut the connection before answering: that is precisely
    // what it was asked to do. So this is not presented as a failure — it is
    // presented as what it is, a shutdown in progress.
  }
  // Nothing left to query: without this, the page would show "Node
  // unreachable" three seconds after a successful shutdown.
  clearInterval(heartbeat);
  forgetToken();
  document.getElementById("error").hidden = true;
  b.textContent = "Wallet closed";
  closeNote(
    "The node has saved its state and stopped. You can close this tab; " +
    "the black window will close by itself.", "ok");
});

refresh();

// ---------------------------------------------------------------------------
// The pulse: network state and sync speed
// ---------------------------------------------------------------------------
//
// The receiving speed is computed here, not in the node: it is a derivative
// of two height measurements, and the browser already has two at hand.
// Asking the node to keep it would have added shared state to a program that
// handles funds, in order to display a figure.

let lastHeight = null, lastSample = 0, blockSpeed = 0;

function pulse(sync){
  const t = Date.now();
  if (lastHeight !== null && t > lastSample){
    const dh = Number(sync.height) - lastHeight;
    const dt = (t - lastSample) / 1000;
    // A moving average: without it the figure jumps at every round.
    if (dt > 0) blockSpeed = blockSpeed * 0.6 + (dh / dt) * 0.4;
  }
  lastHeight = Number(sync.height);
  lastSample = t;

  const gauge = document.getElementById("sync-gauge");
  const target = Number(sync.network_height) || 1;
  const share = Math.max(0, Math.min(100, (Number(sync.height) / target) * 100));
  gauge.style.width = (sync.synced ? 100 : share) + "%";

  // --- Three states, named, and in distinct colors.
  //
  // A colored dot alone cannot be read by everyone: about one man in twelve
  // has trouble telling green from red. So the word carries the state, the
  // color only repeats it — and the area is announced `aria-live`, so that a
  // screen reader reports going offline.
  const peers = Number(sync.peers);
  const state = peers === 0 ? "off" : (sync.synced ? "ok" : "sync");
  const box = document.getElementById("pulse");
  const dot = document.getElementById("sync-dot");
  const label = document.getElementById("pulse-state");
  const tx = document.getElementById("pulse-text");

  box.className = "push pulse " + state;
  dot.className = "dot " + (state === "ok" ? "green" : state === "sync" ? "orange" : "red");
  label.textContent = state === "ok" ? "Connected"
                    : state === "sync" ? "Syncing"
                    : "Offline";
  tx.textContent = state === "ok"
    ? "· " + peers + " peer(s) · block " + sync.height
    : state === "sync"
      ? "· " + sync.blocks_remaining + " block(s) left"
      : "· no computer reachable";

  // --- The pace is given in the unit in which it is felt.
  //
  // This tile used to announce "blocks received per second". On a healthy
  // chain, one block every two minutes makes 0.008 per second: so it showed
  // "0" permanently, and two users read it as their machine receiving
  // nothing when all was well. A figure that is always zero does not inform,
  // it worries.
  //
  // So the **cadence** is shown — one block every so many minutes —, which is
  // the quantity the protocol targets and which the eye compares at once.
  // Catching up keeps blocks per second: there, they come by the dozen and it
  // is indeed the useful unit.
  const v = document.getElementById("sync-speed");
  const vn = document.getElementById("speed-note");
  if (v){
    if (blockSpeed >= 1){
      v.textContent = blockSpeed.toFixed(1) + " blocks/s";
      if (vn) vn.textContent = "catching up";
    } else if (blockSpeed > 0.0005){
      const min = 1 / (blockSpeed * 60);
      v.textContent = "1 block / " + (min < 10 ? min.toFixed(1) : Math.round(min)) + " min";
      if (vn) vn.textContent = "observed pace — target: 2 minutes";
    } else {
      v.textContent = "—";
      if (vn) vn.textContent = "no block since this screen was opened";
    }
  }
}

// ---------------------------------------------------------------------------
// Mining
// ---------------------------------------------------------------------------
//
// The node holds the switch and the counters; this view only reads them and
// toggles them. The rate shown is the one the node measures over a one-second
// window — not an average since launch, which would take several minutes to
// reflect a stop.

const RATE_HISTORY = [];
let miningBusy = false, miningTimer = null;

function formatRate(n){
  n = Number(n) || 0;
  if (n >= 1000000) return (n / 1000000).toFixed(2) + " M";
  if (n >= 1000) return (n / 1000).toFixed(1) + " k";
  return String(Math.round(n));
}

function sparkline(values){
  const svg = document.getElementById("mining-sparkline");
  if (!svg) return;
  const L = 300, H = 52, n = values.length;
  if (n < 2){ svg.innerHTML = ""; return; }
  const max = Math.max.apply(null, values) || 1;
  let d = "";
  for (let i = 0; i < n; i++){
    const x = (i / (n - 1)) * L;
    const y = H - 3 - (values[i] / max) * (H - 8);
    d += (i ? " L " : "M ") + x.toFixed(1) + " " + y.toFixed(1);
  }
  const area = d + " L " + L + " " + H + " L 0 " + H + " Z";
  // Two paths built here, from numbers: nothing that comes from the node
  // enters this markup other than as a computed coordinate.
  svg.innerHTML = '<path class="area" d="' + area + '"></path><path d="' + d + '"></path>';
}

function paintMining(state){
  const active = !!state.active;
  const b = document.getElementById("mining-switch");
  b.setAttribute("aria-pressed", active ? "true" : "false");
  b.disabled = !state.possible;
  b.setAttribute("aria-label", active ? "Turn mining off" : "Turn mining on");
  document.getElementById("mining-title").textContent = state.possible
    ? (active ? "Your machine is looking for a block" : "Your machine is not mining")
    : "This node cannot mine";
  document.getElementById("mining-sub").textContent = state.possible
    ? (active ? "It uses all available cores."
              : "Mining searches for the next block. It uses all CPU cores.")
    : "Mining requires a wallet: without one, the reward would go nowhere.";
  document.getElementById("mining-rate").textContent = formatRate(state.attempts_per_second);
  document.getElementById("mining-blocks").textContent = String(state.blocks_found);
  document.getElementById("mining-total").textContent = formatRate(state.total_attempts);
  document.getElementById("mining-earned").textContent =
    (state.earned ? state.earned.q21 : "0.00000000") + " Q21";
  // Memory is what makes this proof of work worthwhile: a specialized machine
  // is useless against a table that must fit in RAM, and that grows over
  // time. The figure deserved a screen.
  document.getElementById("mining-memory").textContent = formatBytes(state.memory_bytes);
  document.getElementById("mining-memory-note").textContent =
    "epoch " + esc(String(state.epoch_memory)) +
    " table — it grows by 5% every 71 days";
  paintFinds(state.found || [], Number(state.blocks_found) || 0);
  RATE_HISTORY.push(Number(state.attempts_per_second) || 0);
  while (RATE_HISTORY.length > 60) RATE_HISTORY.shift();
  sparkline(RATE_HISTORY);
}

// The log of blocks found. Each row: which block, when, how much — and the
// height is a link to the explorer, served by the same node on the same port.
// The mining pick is a hard-coded drawing; everything that comes from the
// node goes through `esc`.
let lastFound = null;

function shortWhen(ts){
  const d = new Date(Number(ts) * 1000);
  return d.toLocaleDateString(q21Locale()) + " " + d.toLocaleTimeString(q21Locale(),
    {hour: "2-digit", minute: "2-digit"});
}

function paintFinds(list, total){
  const zone = document.getElementById("mining-finds");
  if (!list.length){
    zone.innerHTML = '<div class="note"><p>No block found yet. ' +
      'It is a lottery: the switch above buys attempts, and luck ' +
      'decides when.</p></div>';
    lastFound = null;
    return;
  }
  const icon = '<svg viewBox="0 0 24 24" aria-hidden="true">' +
    '<path d="M13 2L4 14h6l-1 8 9-12h-6z"></path></svg>';
  const rows = list.map((t, i) => {
    const fresh = i === 0 && lastFound !== null &&
      String(t.height) !== lastFound ? " fresh" : "";
    return '<div class="find' + fresh + '">' +
      '<span class="icon">' + icon + '</span>' +
      '<span class="what">' +
        '<a href="/#/block/' + esc(String(t.height)) + '" target="_blank" rel="noopener">' +
          'Block ' + esc(String(t.height)) + '</a>' +
        '<div class="when">' + esc(shortWhen(t.timestamp)) + '</div>' +
      '</span>' +
      '<span class="gain">+ ' + esc(t.reward.q21) + ' Q21</span>' +
      '</div>';
  });
  if (total > list.length){
    rows.push('<p class="help">' + esc(String(total - list.length)) +
      ' earlier block(s) found — all counted in the total earned.</p>');
  }
  zone.innerHTML = rows.join("");
  lastFound = String(list[0].height);
}

async function loadMining(){
  try{
    paintMining(await call("getmining"));
  }catch(e){ /* the general refresh already reports the failure */ }
}

document.getElementById("mining-switch").addEventListener("click", async () => {
  if (miningBusy) return;
  miningBusy = true;
  const b = document.getElementById("mining-switch");
  const want = b.getAttribute("aria-pressed") !== "true";
  try{
    paintMining(await call("setmining", {active: want}));
  }catch(e){
    showError((want ? "Mining could not be turned on: "
                    : "Mining could not be turned off: ") + e.message);
  }finally{
    miningBusy = false;
  }
});

let reachableBusy = false;
document.getElementById("reachable-switch").addEventListener("click", async () => {
  if (reachableBusy) return;
  reachableBusy = true;
  const b = document.getElementById("reachable-switch");
  const want = b.getAttribute("aria-pressed") !== "true";
  try{
    const res = await call("setreachable", {active: want});
    // The setting is written and becomes the wanted choice on the node side:
    // the following refreshes will paint it identically. Listening, on the
    // other hand, is decided at launch; `paintReachable` says so when needed.
    paintReachable({
      reachable: !!res.reachable,
      reachable_session: res.reachable_session,
      port_mapping: ""
    });
  }catch(e){
    showError("The setting could not be changed: " + e.message);
  }finally{
    reachableBusy = false;
  }
});

// The mining view refreshes more often than the rest: a rate that moves every
// five seconds does not look like a measurement.
miningTimer = setInterval(() => {
  if (!document.getElementById("view-mine").hidden) loadMining();
}, 1000);

// ---------------------------------------------------------------------------
// The network
// ---------------------------------------------------------------------------
//
// This view does not answer "how many miners?": nobody can, and Q21 less than
// others since the miner changes address with every block. It answers "how
// much work does the network spend", which can be measured, and then turns it
// into equivalent machines — a division, presented as such.

function formatRateLong(n){
  n = Number(n) || 0;
  if (n >= 1e12) return (n / 1e12).toFixed(2) + " T";
  if (n >= 1e9)  return (n / 1e9).toFixed(2) + " G";
  if (n >= 1e6)  return (n / 1e6).toFixed(2) + " M";
  if (n >= 1e3)  return (n / 1e3).toFixed(1) + " k";
  return String(Math.round(n));
}

// Time left, from the measured speed. No estimate is given until the speed
// has been measured: "still computing" is better than a number drawn from a
// one-second sample.
function timeLeft(blocks){
  if (!(blockSpeed > 0.05) || !(blocks > 0)) return "time left unknown";
  const sec = blocks / blockSpeed;
  if (sec < 90) return "about " + Math.round(sec) + " s";
  if (sec < 5400) return "about " + Math.round(sec / 60) + " min";
  return "about " + (sec / 3600).toFixed(1) + " h";
}

function duration(sec){
  sec = Number(sec) || 0;
  if (sec >= 86400) return (sec / 86400).toFixed(1) + " day(s)";
  if (sec >= 3600)  return (sec / 3600).toFixed(1) + " hour(s)";
  if (sec >= 60)    return Math.round(sec / 60) + " minute(s)";
  return Math.round(sec) + " second(s)";
}

function paintReachable(info){
  const active = !!info.reachable;
  const b = document.getElementById("reachable-switch");
  b.setAttribute("aria-pressed", active ? "true" : "false");
  b.setAttribute("aria-label", active ? "Stop being reachable" : "Make this node reachable");
  document.getElementById("reachable-title").textContent =
    active ? "Your wallet helps the network" : "Your wallet is client-only";
  document.getElementById("reachable-sub").textContent = active
    ? "It accepts connections from others, so the network does not rely on a single machine."
    : "It reaches out to the network but does not accept incoming connections.";
  // The wanted choice and the current session may differ: listening is
  // decided at launch. We say so, rather than show a router state that no
  // longer matches the choice displayed.
  const state = document.getElementById("reachable-state");
  const session = info.reachable_session === undefined ? active : !!info.reachable_session;
  if (active !== session){
    state.textContent = active
      ? "Your node will be reachable the next time the wallet starts."
      : "Your node will be client-only the next time the wallet starts.";
    return;
  }
  // The real state of the router port opening, honestly: what the router
  // answered, never a "reachable" that cannot be proven from here.
  // The node sends a short code, never the public address: a screenshot of
  // this tab must not reveal where its owner lives.
  const mapping = (info.port_mapping || "").trim();
  let text = "";
  if (active && mapping === "failed") text = "Your router did not open the port: your wallet stays a client.";
  else if (active && mapping === "open NAT-PMP") text = "Your router opened the port (NAT-PMP).";
  else if (active && mapping === "open UPnP") text = "Your router opened the port (UPnP).";
  else if (active && mapping.startsWith("open")) text = "Your router opened the port.";
  state.textContent = text;
}

async function loadNetwork(){
  try{
    const r = await call("getnetworkhashrate");
    document.getElementById("network-peers").textContent = String(r.peers);
    try{ paintReachable(await call("getinfo")); }catch(e){ /* the tab stays useful without this detail */ }

    // What *your* machine does, next to what the network does. The two
    // figures side by side answer the question one really asks: "what share
    // is mine". With mining off, it is not made up.
    let mine = 0;
    try { mine = Number((await call("getmining")).attempts_per_second) || 0; } catch (e) { mine = 0; }
    document.getElementById("network-mine").textContent =
      mine > 0 ? formatRateLong(mine) + " attempts/s" : "stopped";

    if (!r.measurable){
      document.getElementById("network-big").innerHTML =
        '<span class="big">—</span>';
      document.getElementById("network-note").textContent =
        "Not enough blocks yet to measure anything. " +
        "At least two are needed, spread out in time.";
      document.getElementById("network-share").textContent =
        "the network cannot be measured yet";
      return;
    }

    // `network_rate_milli` arrives as a string: it can exceed what a Number
    // represents exactly. It is displayed from the string, and only converted
    // for the division into equivalent machines, where the order of magnitude
    // is enough and where an "about" is announced anyway.
    // The node returns thousandths: below one unit of work per second, an
    // integer division would have returned zero, and zero reads as "network
    // stopped".
    const rate = Number(r.network_rate_milli) / 1000;
    document.getElementById("network-big").innerHTML =
      '<span class="big">' + esc(formatRateLong(rate)) + '</span>' +
      '<span class="unit">attempts/s</span>';
    document.getElementById("network-note").textContent =
      "Measured over " + r.blocks_examined + " block(s), or " + duration(r.seconds_examined) +
      " of chain time. This figure is not declared by anyone: it is derived from the work " +
      "actually spent to produce them.";

    // The share your machine carries, under its rate. Without a local measure
    // — mining is off — it is not made up.
    const share = document.getElementById("network-share");
    if (mine > 0 && rate > 0){
      if (mine >= rate){
        // The pace measured on your machine right now exceeds the network's
        // average over its window of blocks: either you produce most of the
        // recent blocks, or you just sped up and the average has not caught
        // up. A percentage that compares two different bases would lie.
        share.textContent = "at this rate, you produce most of the recent blocks";
      } else {
        const p = Math.round((mine / rate) * 100);
        share.textContent = "about " + p + "% of the network's measured power";
      }
    } else {
      share.textContent = "turn mining on to see your share";
    }
  }catch(e){ /* the general loop already reports a node failure */ }
}

// The network view refreshes at the same pace as the mining view as long as
// it is visible.
setInterval(() => {
  if (!document.getElementById("view-network").hidden) loadNetwork();
}, 4000);

// ---------------------------------------------------------------------------
// All addresses
// ---------------------------------------------------------------------------

// `listaddresses` returns an **array** of `{address, key_index, consumed}`
// objects, not an object carrying a list of strings. The first version of
// this function assumed the second form: it showed "no address" on a wallet
// that had a hundred and forty-nine. That is the kind of defect no review
// finds and a test against a real node brings out in three seconds.
const ADDRESSES_SHOWN = 25;

// --- The address book.
//
// Q21 encourages giving a different address to each correspondent: that is
// what prevents payments from being linked together. The price shows after a
// month — four hundred strings of characters, and no idea who is who. Three
// things restore it: a free name per address, a search, and a way to go back
// beyond the last twenty-five.
//
// The full list is kept here rather than requested again at each keystroke:
// the node derives the addresses, and redoing four hundred derivations at each
// letter typed would make the search sluggish.
let book = [];
let bookShown = ADDRESSES_SHOWN;
let bookFilter = "";
// Addresses derived by mining are tucked away by default: they have already
// received their reward and need not be handed out. The owner can unfold
// them, and a search always goes through them.
let bookAll = false;

async function listAddresses(){
  const zone = document.getElementById("address-list");
  try{
    const r = await call("listaddresses");
    const list = Array.isArray(r) ? r : (r.addresses || []);
    // Most recent first: the one just created is the one being looked for.
    book = list.slice().reverse();
    renderBook();
    renderMyAddress();
  }catch(e){
    zone.innerHTML = '<div class="warn"><p>' + esc(e.message) + '</p></div>';
  }
}

// --- The address to give.
//
// "Give me your wallet address" had no answer on this screen: an address only
// appeared after pressing "New address", among a list of derived ones. A
// newcomer did not know which to copy. The answer is now at the top: the most
// recent address the owner requested and has not used to sign. If there is
// none yet, one is requested, once.
let myAddressAsked = false;

async function renderMyAddress(){
  const zone = document.getElementById("my-address");
  const e = book.find(x => isShown(x) && !x.consumed);
  if (!e && !myAddressAsked){
    myAddressAsked = true;
    try{
      await call("getnewaddress");
      await listAddresses();
    }catch(err){
      zone.innerHTML = '<div class="warn"><p>' + esc(err.message) + '</p></div>';
    }
    return;
  }
  if (!e){
    zone.innerHTML = '<p class="help">The “New address” button below creates one.</p>';
    return;
  }
  const a = String(e.address);
  zone.innerHTML =
    '<div class="address"><span class="txt">' + esc(a) + '</span></div>' +
    '<div class="buttons">' +
      '<button type="button" class="action" data-copy="' + esc(a) + '">Copy the address</button>' +
      '<a class="flat" href="/#/address/' + esc(a) + '" target="_blank" rel="noopener">See it in the explorer</a>' +
    '</div>';
}

document.getElementById("my-address").addEventListener("click", ev => {
  const c = ev.target.closest("button[data-copy]");
  if (c) copyText(c.dataset.copy, c);
});

// An address matches the search by its name, its number or part of its
// address. The number can be searched as "12" as well as "#12": the user is
// not made to guess the expected form.
function matches(e, f){
  if (!f) return true;
  const name = String(e.label || "").toLowerCase();
  const adr = String(e.address || "").toLowerCase();
  const num = String(e.key_index);
  return name.includes(f) || adr.includes(f) || num === f || ("#" + num) === f;
}

// An address is "to be shown" if the owner requested it or named it. The
// others are those from mining and from restores.
function isShown(e){
  return !!(e.requested || e.label);
}

function renderBook(){
  const zone = document.getElementById("address-list");
  const count = document.getElementById("address-count");
  const more = document.getElementById("more-zone");
  const mining = document.getElementById("mining-zone");
  const miningButton = document.getElementById("mining-addresses-button");
  if (!book.length){
    zone.innerHTML = '<div class="note"><p>No address derived yet. ' +
      'The button above creates one.</p></div>';
    count.textContent = "";
    more.hidden = true;
    mining.hidden = true;
    return;
  }
  const f = bookFilter.trim().toLowerCase();
  const tucked = book.filter(e => !isShown(e)).length;
  // A search goes through everything: whoever types "#12" wants the twelfth,
  // whether it comes from mining or not. Without a search, only the requested
  // ones are shown.
  const base = (f || bookAll) ? book : book.filter(isShown);
  miningButton.textContent = bookAll
    ? "Hide the mining addresses"
    : "Also show the " + tucked + " mining address(es)";
  mining.hidden = !tucked || !!f;
  const visible = base.filter(e => matches(e, f));
  if (!visible.length && !f && !bookAll){
    zone.innerHTML = '<div class="note"><p>No requested address yet. ' +
      'The “New address” button creates one, which you ' +
      'can name. Your ' + esc(String(tucked)) + ' mining address(es) ' +
      'are tucked away: they received your rewards and count in ' +
      'your balance.</p></div>';
    count.textContent = "";
    more.hidden = true;
    return;
  }
  if (!visible.length){
    zone.innerHTML = '<div class="note"><p>No address matches ' +
      '“' + esc(bookFilter.trim()) + '”. All ' + esc(String(book.length)) +
      ' of your addresses remain valid.</p></div>';
    count.textContent = "";
    more.hidden = true;
    return;
  }
  const page = visible.slice(0, bookShown);
  zone.innerHTML = page.map(e => {
    const a = String(e.address);
    const index = String(e.key_index);
    const name = e.label ? esc(String(e.label)) : "unnamed";
    return '<div class="address">' +
      '<span class="index">#' + esc(index) + '</span>' +
      '<span class="content">' +
        '<span class="name' + (e.label ? '' : ' empty') + '">' + name + '</span>' +
        '<span class="txt">' + esc(a) + '</span>' +
      '</span>' +
      (e.consumed ? '<span class="badge gray">used</span>' : '') +
      '<button type="button" class="flat" data-copy="' + esc(a) + '">Copy</button>' +
      '<a class="flat" href="/#/address/' + esc(a) + '" target="_blank" rel="noopener">Explorer</a>' +
      '<button type="button" class="flat" data-name="' + esc(index) + '">' +
        (e.label ? 'Rename' : 'Name') + '</button>' +
      '<span class="edit" hidden data-edit="' + esc(index) + '">' +
        '<input type="text" maxlength="64" value="' + esc(String(e.label || "")) + '" ' +
        'placeholder="who or what it is for — visible only to you">' +
        '<button type="button" class="action" data-save="' + esc(index) + '">Save</button>' +
      '</span>' +
      '</div>';
  }).join("");
  count.textContent = f
    ? visible.length + " address(es) found out of " + book.length
    : (bookAll
        ? book.length + " address(es) in total, " + tucked + " of them from mining"
        : visible.length + " requested address(es)" +
          (tucked ? " · " + tucked + " from mining, tucked away" : ""));
  more.hidden = visible.length <= page.length;
}

document.getElementById("mining-addresses-button").addEventListener("click", () => {
  bookAll = !bookAll;
  bookShown = ADDRESSES_SHOWN;
  renderBook();
});

document.getElementById("address-filter").addEventListener("input", ev => {
  bookFilter = ev.target.value;
  // A search starts over from the top: keeping a pagination inherited from
  // the previous search would make results disappear for no visible reason.
  bookShown = ADDRESSES_SHOWN;
  renderBook();
});

document.getElementById("more-button").addEventListener("click", () => {
  bookShown += ADDRESSES_SHOWN;
  renderBook();
});

// A single listener for the whole list: attaching a handler per row leaks at
// every refresh.
document.getElementById("address-list").addEventListener("click", async ev => {
  const c = ev.target.closest("button[data-copy]");
  if (c){ copyText(c.dataset.copy, c); return; }

  const n = ev.target.closest("button[data-name]");
  if (n){
    const z = document.querySelector('[data-edit="' + n.dataset.name + '"]');
    if (z){ z.hidden = !z.hidden; if (!z.hidden) z.querySelector("input").focus(); }
    return;
  }

  const s = ev.target.closest("button[data-save]");
  if (s){
    const index = s.dataset.save;
    const z = document.querySelector('[data-edit="' + index + '"]');
    const text = z ? z.querySelector("input").value : "";
    s.disabled = true;
    try{
      await call("setaddresslabel",
        '{"key_index":' + Number(index) + ',"label":' + JSON.stringify(text) + '}');
      // The address book is read again rather than patching the row by hand:
      // the node may have trimmed the text, and the screen must show what is
      // saved, not what was typed.
      await listAddresses();
    }catch(e){
      showError("Name not saved: " + e.message);
      s.disabled = false;
    }
  }
});

// Enter means Save: nobody reaches for the button with the mouse after typing
// a name.
document.getElementById("address-list").addEventListener("keydown", ev => {
  if (ev.key !== "Enter") return;
  const z = ev.target.closest("[data-edit]");
  if (!z) return;
  ev.preventDefault();
  z.querySelector("button[data-save]").click();
});

</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Extracts the content of the page's `<script>` block.
    fn script() -> &'static str {
        let start = PAGE.find("<script>").expect("script block") + "<script>".len();
        let end = PAGE.find("</script>").expect("end of script block");
        &PAGE[start..end]
    }

    /// One JSON line of the script, `const <name> = {...};`, decoded.
    fn json_constant(name: &str) -> crate::json::Json {
        let s = script();
        let head = format!("const {name} = ");
        let start = s.find(&head).expect("constant") + head.len();
        let end = start + s[start..].find('\n').expect("end of line");
        crate::json::parse(s[start..end].trim_end_matches(';')).expect("valid JSON")
    }

    /// The exact-match table of one language: English source -> translation.
    fn table(name: &str, lang: &str) -> BTreeMap<String, String> {
        match json_constant(name).get(lang) {
            Some(crate::json::Json::Object(entries)) => entries
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().expect("a string").to_string()))
                .collect(),
            _ => panic!("no {lang} table in {name}"),
        }
    }

    /// The page source as the engine sees its text: `&nbsp;` is a space, runs
    /// of white space collapse to one, and the joins of JavaScript string
    /// literals (`" + "`) disappear, so that a sentence split over several
    /// source lines reads in one piece.
    fn normalized_page() -> String {
        let p = page_without_tables()
            .replace("&nbsp;", " ")
            .replace('\u{a0}', " ");
        let p = p.split_whitespace().collect::<Vec<_>>().join(" ");
        p.replace("\" + \"", "")
            .replace("' + '", "")
            .replace("' + \"", "")
    }

    /// The page with its translation tables cut out.
    fn page_without_tables() -> String {
        let start = PAGE.find("const I18N = ").expect("tables");
        let last = PAGE.find("const I18N_PREFIXES = ").expect("prefixes");
        let end = last + PAGE[last..].find('\n').expect("end of tables");
        format!("{}{}", &PAGE[..start], &PAGE[end..])
    }

    #[test]
    fn the_page_loads_no_external_resource() {
        // A wallet page that calls a CDN tells it every time the wallet is
        // opened, and gives it the power to replace the code that handles the
        // funds. The check is crude but it catches the most likely mistake: a
        // font or a script added later.
        for forbidden in [
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

    #[test]
    fn the_page_provides_both_themes() {
        // Light theme on `:root`, dark theme under the system preference.
        assert!(PAGE.contains(":root{"));
        assert!(PAGE.contains("prefers-color-scheme: dark"));
    }

    /// What the wallet may write in the browser, and what it may not.
    ///
    /// # What changed, and why
    ///
    /// The rule was "no storage, ever". It had the merit of being simple, and
    /// it made the wallet unusable at the first refresh: the token lived in a
    /// variable, an F5 erased it, and the launcher had to be restarted. It
    /// happened to the first user, in front of a page that seemed frozen —
    /// everyone's reflex.
    ///
    /// So the session token is allowed in the browser's storage, and it alone.
    /// It is partitioned there by origin — hence by port, drawn at random on
    /// each launch — and it dies with the process that drew it: what the
    /// browser keeps afterwards opens nothing. It is not a key: the seed and
    /// the passphrase never leave the node.
    ///
    /// Since the launcher's link works only once, this storage must outlive
    /// the tab, or else closing it cuts the user off from their wallet until
    /// the restart: that is `localStorage`, through a single access point,
    /// under a single key. `indexedDB` and cookies remain forbidden.
    #[test]
    fn the_page_stores_only_the_session_token() {
        for forbidden in ["indexedDB.open", "document.cookie =", "localStorage["] {
            assert!(
                !PAGE.contains(forbidden),
                "the wallet stores something other than the token: {forbidden}"
            );
        }
        let s = script();
        // A single access point to durable storage, and a single key.
        assert_eq!(
            s.matches("window.localStorage").count(),
            1,
            "`localStorage` must only be touched by `storage()`"
        );
        assert!(
            !s.contains("localStorage."),
            "no direct access: everything goes through `storage()`"
        );
        assert!(s.contains("function storage(){"));
        assert!(
            s.contains("r.setItem(SESSION_KEY"),
            "the token must survive a refresh and the tab"
        );
        assert!(
            s.contains("r.removeItem(SESSION_KEY"),
            "a rejected token must be forgotten, not retried forever"
        );
        // The only other use of `sessionStorage` is the chosen language: it is
        // not a secret, and it need not outlive the tab.
        for occ in s.match_indices("sessionStorage.") {
            let rest = &s[occ.0..(occ.0 + 60).min(s.len())];
            assert!(
                rest.contains("q21-language"),
                "only the language choice goes through sessionStorage: {rest}"
            );
        }
        // Every read or write is guarded: a browser may refuse storage, and the
        // page must then work without it, not stop.
        let occurrences = s.matches("Storage.").count()
            + s.matches(".getItem(").count()
            + s.matches(".setItem(").count()
            + s.matches(".removeItem(").count();
        let guards = s.matches("try {").count();
        assert!(
            guards >= occurrences,
            "every storage access must be guarded: {occurrences} accesses, {guards} guards"
        );
    }

    /// A closed tab reopens as long as the program runs.
    ///
    /// The launcher's link works only once. Reopened from the history, the
    /// exchange fails: the page must then take back the token stored under
    /// this origin, without asking anything, and only show "this link has
    /// already been used" when there is none. An expired token is erased by
    /// the 401 that follows.
    #[test]
    fn a_reopened_tab_takes_back_the_stored_token() {
        let s = script();
        let failure = s
            .find("const kept = storedToken();\n  if (kept){ token = kept; return; }")
            .expect("recovery of the stored token");
        let message = s
            .find("showError(\"This link has already been used")
            .expect("message");
        assert!(failure < message, "the recovery comes before the message");
        assert!(
            s.contains("if (r.status === 401){\n    forgetToken();"),
            "a 401 must erase the stored token"
        );
    }

    /// The fragment carries the token, and must not survive being read.
    #[test]
    fn the_fragment_is_erased_after_reading() {
        let s = script();
        assert!(s.contains("location.hash.slice(1)"));
        assert!(s.contains(r#"history.replaceState(null, "", location.pathname)"#));
        // The erasing immediately follows the reading: nothing must be able to
        // slip in between and leave before the address bar is cleaned.
        let reading = s
            .find("location.hash.slice(1)")
            .expect("reading of the fragment");
        let erasing = s.find("history.replaceState").expect("erasing");
        assert!(
            erasing > reading && erasing - reading < 120,
            "erasing the fragment does not immediately follow reading it"
        );
    }

    /// The fragment is a one-time launch token, exchanged before any call.
    ///
    /// What the launcher puts in the address goes through the browser's
    /// command line: so it is no longer the session token, but a launch token
    /// that the page exchanges once. No call leaves before the exchange is
    /// done, or else the first one would leave without a token.
    #[test]
    fn the_fragment_is_a_launch_token_exchanged_before_any_call() {
        let s = script();
        assert!(s.contains("exchange = exchangeLaunchToken(v);"));
        assert!(
            !s.contains("keepToken(v);\n    return;"),
            "the fragment must no longer be kept as is"
        );
        assert!(s.contains("fetch(\"/session\""));
        let wait = s
            .find("if (exchange){ await exchange; exchange = null; }")
            .expect("wait");
        let call = s.find("async function call(").expect("call");
        assert!(wait > call && wait - call < 80, "the wait must open `call`");
    }

    /// The token is typed into the page, never into a browser dialog.
    #[test]
    fn the_token_is_asked_for_in_the_page() {
        assert!(PAGE.contains(r#"id="token-input""#));
        assert!(PAGE.contains(r#"type="password""#));
        assert!(PAGE.contains("Authorization"));
        assert!(PAGE.contains("Bearer"));
        assert!(
            !PAGE.contains("window.prompt") && !PAGE.contains("prompt("),
            "the token must be typed into a field of the page"
        );
        assert!(
            !PAGE.contains("location.search"),
            "the query string must never carry the token"
        );
    }

    /// The `innerHTML` insertion points escape by default.
    #[test]
    fn values_are_escaped_by_default() {
        assert!(PAGE.contains("const esc ="));
        assert!(PAGE.contains("const raw ="));
        assert!(PAGE.contains("const render ="));
        assert!(PAGE.contains("const html ="));
        assert!(PAGE.contains("&amp;"));
        assert!(PAGE.contains("&lt;"));
        assert!(PAGE.contains("${render(v)}"));
    }

    /// Every interpolation of a template literal declares itself.
    ///
    /// It escapes (`esc`, `trunc`), it renders a value whose type says whether
    /// it is markup (`render`), it assembles an already escaped fragment
    /// (`html`), or it splits an address (`chunks`). Nothing else. A field
    /// inserted as is would be an injection the day the node returned a string
    /// where the interface expected a number.
    #[test]
    fn no_interpolation_is_raw() {
        let s = script();
        let allowed = ["esc(", "render(", "html(", "trunc(", "chunks("];
        let bytes = s.as_bytes();
        let mut i = 0usize;
        let mut seen = 0usize;
        while let Some(p) = s[i..].find("${") {
            let start = i + p + 2;
            // Templates nest: the end of the interpolation is the brace that
            // balances, not the first one met.
            let mut depth = 1usize;
            let mut q = start;
            while q < bytes.len() && depth > 0 {
                match bytes[q] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                q += 1;
            }
            assert_eq!(depth, 0, "unclosed interpolation");
            let expr = s[start..q - 1].trim();
            seen += 1;
            assert!(
                allowed.iter().any(|p| expr.starts_with(p)),
                "unescaped interpolation: {expr}"
            );
            i = start;
        }
        assert!(seen > 30, "too few interpolations examined: {seen}");
    }

    /// Monetary arithmetic never touches a float.
    ///
    /// # Why the test had to be refined
    ///
    /// It banned `toFixed` from the whole script. That was right as long as
    /// the page only displayed money; the mining rate and the block receiving
    /// speed are continuous, measured quantities, and rounding them is exactly
    /// what should be done — counting them in integers would say nothing more
    /// and read less well.
    ///
    /// The real invariant has not moved: **no float touches an amount**. The
    /// test now checks it line by line, looking for a `toFixed` next to a word
    /// of the monetary vocabulary. A `parseFloat` remains forbidden
    /// everywhere: it has no legitimate use here.
    #[test]
    fn no_float_on_an_amount() {
        let s = script();
        for forbidden in ["parseFloat", "Number(m.", "+ 0.5"] {
            assert!(
                !s.contains(forbidden),
                "an amount goes through a float: {forbidden}"
            );
        }
        // JSON field names and the page's own variable names.
        const MONEY: [&str; 9] = [
            "units",
            "q21",
            "balance",
            "amount",
            "fee",
            "spendable",
            "immature",
            "received",
            "sum",
        ];
        // The word must be a word, not a substring: "fee" hides in "feed",
        // and a test that refused a progress bar on the grounds that it talked
        // about money would be worse than useless.
        fn contains_word(line: &str, word: &str) -> bool {
            let boundary = |c: char| !c.is_alphanumeric() && c != '_';
            let mut from = 0;
            while let Some(i) = line[from..].find(word) {
                let d = from + i;
                let f = d + word.len();
                let before = line[..d].chars().next_back().is_none_or(boundary);
                let after = line[f..].chars().next().is_none_or(boundary);
                if before && after {
                    return true;
                }
                from = d + 1;
            }
            false
        }

        let mut seen = 0;
        for (n, line) in s.lines().enumerate() {
            if !line.contains("toFixed") {
                continue;
            }
            seen += 1;
            let low = line.to_lowercase();
            for word in MONEY {
                assert!(
                    !contains_word(&low, word),
                    "line {}: an amount goes through toFixed — {}",
                    n + 1,
                    line.trim()
                );
            }
        }
        assert!(seen > 0, "no toFixed: the test no longer checks anything");
        assert!(s.contains("BigInt"));
        assert!(s.contains("const UNITS_PER_Q21 = 100000000n;"));
    }

    /// The conversion of a Q21 input into units, checked twice.
    ///
    /// # Why both
    ///
    /// Reimplementing the algorithm in Rust and testing it proves nothing
    /// about the JavaScript actually served: the two copies can diverge
    /// without anything reporting it. Comparing the text of the JavaScript
    /// function with an expected literal proves the opposite — that the page
    /// does contain this algorithm — but says nothing of its correctness.
    ///
    /// So both are done: [`units_from_q21`] is the specification, tested on
    /// vectors; and the following test checks that the JavaScript served is
    /// its exact transcription, character for character. Touching one without
    /// the other breaks one of the two tests.
    fn units_from_q21(input: &str) -> Option<u128> {
        const UNITS_PER_Q21: u128 = 100_000_000;
        let t: String = input
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
        let (whole, frac) = match t.split_once('.') {
            Some((e, f)) => (if e.is_empty() { "0" } else { e }, f),
            None => (t.as_str(), ""),
        };
        if frac.len() > 8 {
            return None;
        }
        let padded = format!("{frac:0<8}");
        let e: u128 = whole.parse().ok()?;
        let f: u128 = padded.parse().ok()?;
        Some(e * UNITS_PER_Q21 + f)
    }

    #[test]
    fn the_q21_to_units_conversion_is_exact() {
        // The cases where a float gets it wrong: 0.1, 0.2, 0.3 have no exact
        // representation in IEEE 754, and 2,100,000,100,000,000 exceeds the
        // integer precision of a `double`.
        assert_eq!(units_from_q21("0.1"), Some(10_000_000));
        assert_eq!(units_from_q21("0.2"), Some(20_000_000));
        assert_eq!(units_from_q21("0.3"), Some(30_000_000));
        assert_eq!(units_from_q21("1"), Some(100_000_000));
        assert_eq!(units_from_q21("1."), Some(100_000_000));
        assert_eq!(units_from_q21(".5"), Some(50_000_000));
        assert_eq!(units_from_q21("0.00000001"), Some(1));
        assert_eq!(units_from_q21("0"), Some(0));
        assert_eq!(units_from_q21("0.00000000"), Some(0));
        assert_eq!(units_from_q21("13.847118"), Some(1_384_711_800));
        assert_eq!(units_from_q21("0.03802539"), Some(3_802_539));
        assert_eq!(units_from_q21("21000001"), Some(2_100_000_100_000_000));
        assert_eq!(
            units_from_q21("21000001.00000000"),
            Some(2_100_000_100_000_000)
        );
        // A thousands separator or a decimal comma must not produce an amount
        // different from the one that was typed.
        assert_eq!(units_from_q21("1 000.5"), Some(100_050_000_000));
        assert_eq!(units_from_q21("0,25"), Some(25_000_000));

        // Refusal, rather than a guessed amount.
        assert_eq!(units_from_q21(""), None);
        assert_eq!(units_from_q21("."), None);
        assert_eq!(units_from_q21("abc"), None);
        assert_eq!(units_from_q21("1.2.3"), None);
        assert_eq!(units_from_q21("-1"), None);
        assert_eq!(units_from_q21("1e8"), None);
        // Nine decimals: finer than the indivisible unit. Truncating silently
        // would mean sending something other than what is written.
        assert_eq!(units_from_q21("0.000000001"), None);
    }

    /// The page does contain this algorithm, and not a variant.
    #[test]
    fn the_javascript_contains_the_conversion_algorithm() {
        const EXPECTED: &str = r#"function unitsFromQ21(input){
  let t = String(input).trim().replace(/[ \u00a0\u202f_]/g, "").replace(",", ".");
  if (t === "" || t === ".") return null;
  if (!/^[0-9]*\.?[0-9]*$/.test(t)) return null;
  const p = t.split(".");
  const whole = p[0] === "" ? "0" : p[0];
  const frac = p.length > 1 ? p[1] : "";
  if (frac.length > 8) return null;
  const padded = (frac + "00000000").slice(0, 8);
  return BigInt(whole) * UNITS_PER_Q21 + BigInt(padded);
}"#;
        assert!(
            script().contains(EXPECTED),
            "the conversion function served is no longer the one tested above"
        );

        const BACK: &str = r#"function q21FromUnits(u){
  const n = BigInt(u);
  const e = n / UNITS_PER_Q21;
  const f = n % UNITS_PER_Q21;
  return e.toString() + "." + f.toString().padStart(8, "0");
}"#;
        assert!(script().contains(BACK), "the reverse formatting changed");
    }

    /// A payment cannot be made in a single click.
    #[test]
    fn a_payment_goes_through_a_confirmation_screen() {
        assert!(PAGE.contains(r#"id="confirmation""#));
        assert!(PAGE.contains("Confirm the payment"));
        assert!(PAGE.contains("Send now"));
        assert!(PAGE.contains(r#"id="recap""#));
        // The summary repeats the three quantities before the final send.
        assert!(PAGE.contains("Recipient"));
        assert!(PAGE.contains("Amount"));
        assert!(PAGE.contains("Fee"));
    }

    /// The integers of a payment leave as digits, without conversion.
    #[test]
    fn the_amount_sent_is_the_one_confirmed() {
        let s = script();
        assert!(s.contains(r#"',"units":' + p.amount.toString() +"#));
        assert!(s.contains(r#"',"fee":' + p.fee.toString() +"#));
    }

    /// An incomplete balance must say so.
    #[test]
    fn an_unsynced_balance_is_announced() {
        assert!(PAGE.contains("The displayed balance is incomplete"));
        assert!(PAGE.contains("sync.synced"));
        assert!(PAGE.contains("sync.blocks_remaining"));
    }

    /// The connection state can be read without telling colors apart.
    ///
    /// About one man in twelve has trouble telling green from red. A colored
    /// dot alone therefore says nothing to everyone; the word carries the
    /// state, the color only repeats it.
    #[test]
    fn the_connection_state_is_written_out() {
        let s = script();
        for word in ["\"Connected\"", "\"Syncing\"", "\"Offline\""] {
            assert!(s.contains(word), "state without a name: {word}");
        }
        // And that name is translated: once only "Connected" was, and the
        // badge of a wallet in another language showed the untranslated
        // "offline" state.
        let fr = table("I18N", "fr");
        let ja = table("I18N", "ja");
        for (en, ja_word) in [
            ("Offline", "オフライン"),
            ("Syncing", "同期中"),
            ("Connected", "接続済み"),
        ] {
            assert!(fr.contains_key(en), "no French for the state {en}");
            assert_eq!(
                ja.get(en).map(String::as_str),
                Some(ja_word),
                "Japanese for {en}"
            );
        }
        // The three states lead to three distinct colors, and red exists.
        for class in ["green", "orange", "red"] {
            assert!(
                PAGE.contains(&format!(".dot.{class}{{")),
                "color missing from the stylesheet: {class}"
            );
        }
        // The area is announced: going offline must be said, not only seen.
        assert!(PAGE.contains(r#"role="status" aria-live="polite""#));
        // And the state comes from the number of peers, not from a guess.
        assert!(s.contains("const peers = Number(sync.peers);"));
        assert!(s.contains(r#"peers === 0 ? "off""#));
    }

    /// Catching up with the chain shows, with real progress.
    #[test]
    fn catching_up_with_the_chain_is_visible() {
        let s = script();
        assert!(PAGE.contains("Catching up on chain history"));
        assert!(
            PAGE.contains(r#"class="spinner""#),
            "nothing spins while waiting"
        );
        // The bar follows the real height, it is not decorative.
        assert!(s.contains(r#"document.getElementById("catchup-bar").style.width"#));
        assert!(s.contains("(here / there) * 100"));
        // Without a measured speed, no duration is announced.
        assert!(
            s.contains(r#"return "time left unknown""#),
            "a duration is announced before it has been measured"
        );
        // The "nobody to ask" case has its own title: a bar that does not move
        // without explanation reads as a failure.
        assert!(PAGE.contains("Waiting for a computer to ask for the chain"));
    }

    /// The page never claims to know that a restore is in progress.
    ///
    /// The node does not know it. The line that speaks to whoever has just
    /// restored is therefore phrased as a condition, and it stays true in both
    /// cases.
    #[test]
    fn a_restore_is_mentioned_without_being_claimed() {
        assert!(PAGE.contains("If you have just restored a wallet"));
        assert!(
            !PAGE.contains("Restore in progress") || PAGE.contains("If you have just"),
            "the page claims a restore it cannot observe"
        );
        // It only speaks to a wallet that has derived almost nothing.
        assert!(script().contains("Number(balance.derived_addresses) > 2"));
    }

    /// A truncated history must say so.
    #[test]
    fn a_partial_history_is_announced() {
        assert!(PAGE.contains("complete_history"));
        assert!(PAGE.contains("Partial history"));
        assert!(PAGE.contains("scanned_from_height"));
        // The node's note is shown as is, not summarized.
        assert!(PAGE.contains("esc(h.note)"));
    }

    /// The history box explains the change given back, and nothing else.
    ///
    /// # What it used to say
    ///
    /// "What this column does not say": the amount sent was not computed. The
    /// node now computes it, and the box that still claimed otherwise was
    /// lying to its reader. What remains to explain is the opposite: why
    /// "received" and "sent" both appear on the row of a payment.
    #[test]
    fn the_box_explains_the_change() {
        assert!(
            !PAGE.contains("What this column does not say"),
            "the old box still claims the amount sent is not computed"
        );
        assert!(!PAGE.contains("the amount sent is not computed"));
        assert!(PAGE.contains("Received and sent on the same row"));
        assert!(PAGE.contains("like a bill handed back"));
        // It only shows when there is a payment to explain.
        assert!(PAGE.contains(r#"h.movements.some(m => m.kind === "send")"#));
        // A partial resolution says so, rather than passing for exact.
        assert!(PAGE.contains("amounts_out_all_resolved === false"));
        assert!(PAGE.contains("Amounts sent incomplete"));
    }

    /// The "sent" column exists, and does not give a floor for a fact.
    #[test]
    fn the_sent_column_exists_and_admits_its_uncertainty() {
        assert!(PAGE.contains("<th>Sent</th>"));
        // The cell is fed by the node's field, not guessed.
        assert!(PAGE.contains("m.net_out.q21"));
        assert!(PAGE.contains("render(outCell(m))"));
        // Without a payment, no figure: a dash, never a zero.
        assert!(PAGE.contains(r#"if (!m.net_out) return raw(`<span class="empty">—</span>`);"#));
        // The node's flag is consulted, and it decides the mark shown.
        assert!(
            PAGE.contains("m.amount_out_known === false"),
            "the page shows the amount sent without checking it is complete"
        );
        assert!(PAGE.contains(r#"esc("≥ " + m.net_out.q21)"#));
        // The table does have one more column than before.
        let head = PAGE
            .find("<thead><tr><th>Type</th>")
            .expect("header of the history");
        let end = PAGE[head..].find("</tr>").expect("end of the header");
        assert_eq!(PAGE[head..head + end].matches("<th>").count(), 7);
        assert!(PAGE.contains(r#"colspan="7""#));
    }

    /// A payment shows at once, and says it is not confirmed.
    ///
    /// The silence between the payment and the block was the worst moment of
    /// the wallet: the balance dropped, the activity stayed empty, and the
    /// user believed their money lost. Three things fill it, and this test
    /// locks them in: the row carries a "pending" mark, a disc spins to say
    /// that work is going on, and the height stays a dash rather than a zero
    /// that would designate the genesis block.
    #[test]
    fn a_pending_transaction_shows_and_says_it_is_unconfirmed() {
        assert!(
            PAGE.contains("m.pending"),
            "the history ignores the mempool"
        );
        assert!(PAGE.contains("pending</span>"), "no \"pending\" mark");
        assert!(PAGE.contains("function spinner()"), "no progress indicator");
        assert!(PAGE.contains(".spin-dot{"), "the disc has no style");
        assert!(
            PAGE.contains("@keyframes spinning"),
            "the disc does not spin"
        );
        // A permanent animation must be able to be turned off: it is an
        // accessibility requirement, not a preference.
        assert!(
            PAGE.contains("prefers-reduced-motion"),
            "the animation ignores the system setting"
        );
        // The height of a transaction that is in no block does not exist.
        assert!(
            PAGE.contains(r#"esc(m.pending ? "—" : m.height)"#),
            "a pending transaction would show a height it does not have"
        );
    }

    /// Mining memory is shown: it is the whole point of the method.
    ///
    /// Q21 mines with a table that must fit in RAM and that grows by 5%
    /// every 71 days. It is what makes a specialized machine pointless — one
    /// does not etch memory into silicon. Not showing it amounted to hiding
    /// the only quantity that explains why this mining stays within everyone's
    /// reach.
    #[test]
    fn the_mining_screen_shows_the_memory_in_use() {
        assert!(PAGE.contains("Memory in use"), "memory tile missing");
        assert!(PAGE.contains("mining-memory"), "memory value missing");
        assert!(
            PAGE.contains("state.memory_bytes"),
            "the memory is not read from the node"
        );
        // In gibibytes, not gigabytes: that is how a memory stick is counted.
        assert!(PAGE.contains("GiB"), "the memory unit is not the right one");
        assert!(
            PAGE.contains("every 71 days"),
            "nothing says the table grows"
        );
    }

    /// The activity can be filtered, and keeps itself up to date.
    ///
    /// Two gaps reported in use. A transaction received showed as "pending"
    /// and **stayed there**: one had to switch tabs and come back to see it
    /// confirmed. And with a few dozen mining rewards, the day's only
    /// transfer got lost in the middle.
    #[test]
    fn the_activity_filters_and_refreshes_itself() {
        for expected in [
            "activity-filters",
            r#"data-filter="mining""#,
            r#"data-filter="receive""#,
            r#"data-filter="send""#,
            "function matchesFilter(",
        ] {
            assert!(
                PAGE.contains(expected),
                "filter element missing: {expected}"
            );
        }
        // The refresh only runs if the screen is visible: a wallet left open on
        // the balance must not make the node read the chain again.
        assert!(
            PAGE.contains(
                r#"if (!document.getElementById("view-activity").hidden) loadActivity();"#
            ),
            "the activity refreshes even when hidden, or not at all"
        );
        // Two overlapping rounds would read the chain twice for nothing.
        assert!(
            PAGE.contains("if (activityLoading) return;"),
            "nothing prevents two simultaneous reads"
        );
        // The filter asks nothing new of the node: it replays the display.
        assert!(PAGE.contains("h.movements.filter(matchesFilter)"));
    }

    /// An immature amount says **when** it will be released.
    ///
    /// # What the lack of this answer cost
    ///
    /// The tile announced "awaiting maturity: 3.05 Q21" and stopped there. A
    /// miner thus saw their earnings rise for half an hour and their available
    /// balance stay at zero, with no time reference at all. The question one
    /// asks in front of a locked balance is not "how much", it is "when" —
    /// and the page did not answer it.
    #[test]
    fn an_immature_amount_announces_its_release_date() {
        assert!(
            PAGE.contains("next_maturity_blocks"),
            "the balance does not read the next release"
        );
        assert!(
            PAGE.contains("next release"),
            "the balance does not announce it"
        );
        assert!(
            PAGE.contains("matures in"),
            "the history does not announce the due date"
        );
        assert!(
            PAGE.contains("function blocksDuration("),
            "no translation of blocks into time"
        );
        // The interval comes from the node: copying it into the page would
        // freeze it by hand, and make it lie the day it changes.
        assert!(
            PAGE.contains("info.target_interval_seconds"),
            "the block interval is copied instead of being asked for"
        );
        assert!(
            PAGE.contains("chainInfo.coinbase_maturity"),
            "the maturity is copied instead of being asked for"
        );
    }

    /// The "Receive" page tucks away the mining addresses.
    ///
    /// A miner owns a thousand of them after a few days, and has handed out
    /// only two. Showing them all at the same level drowned the two that
    /// matter; two users asked "why do I have so many addresses". Only the
    /// requested or named ones are shown, a search goes through everything,
    /// and a button unfolds the rest.
    #[test]
    fn the_receive_page_tucks_away_mining_addresses() {
        assert!(
            PAGE.contains("function isShown(e)"),
            "no requested/mining sorting"
        );
        assert!(
            PAGE.contains("e.requested || e.label"),
            "the criterion is not the right one"
        );
        assert!(
            PAGE.contains("mining-addresses-button"),
            "no button to unfold the mining addresses"
        );
        assert!(
            PAGE.contains("(f || bookAll) ? book : book.filter(isShown)"),
            "a search must go through the whole address book"
        );
        // A new address joins the address book and opens its name field.
        assert!(
            PAGE.contains("const fresh = book.find(e => e.address === a.address)"),
            "the new address is not taken into the address book"
        );
    }

    /// The chain's pace is not shown in a unit where it is worth zero.
    ///
    /// The tile announced "blocks received per second". One block every two
    /// minutes makes 0.008 per second: so it showed "0" permanently, on a
    /// perfectly healthy network. Two users read it as their machine receiving
    /// nothing. A figure that is always zero does not inform, it worries.
    #[test]
    fn the_chain_pace_is_given_in_minutes_per_block() {
        assert!(PAGE.contains("Chain pace"), "the tile is not renamed");
        assert!(
            PAGE.contains(r#""1 block / ""#),
            "the cadence is not expressed in minutes per block"
        );
        assert!(
            !PAGE.contains("per second, from the network"),
            "the old unit, always zero, is still there"
        );
        // Catching up keeps blocks per second: there, they come by the dozen
        // and it is the useful unit.
        assert!(PAGE.contains("catching up"));
        assert!(PAGE.contains("target: 2 minutes"));
    }

    /// An unreadable block is reported, and told apart from a truncated
    /// history.
    ///
    /// Confusing them made someone believe a transfer had vanished: one is an
    /// incident to repair, the other a harmless setting.
    #[test]
    fn an_unreadable_block_is_not_confused_with_a_short_window() {
        assert!(PAGE.contains("unreadable_blocks"), "the count is not read");
        assert!(
            PAGE.contains("history incomplete"),
            "the incident is not named"
        );
        assert!(
            PAGE.contains("Your funds are not lost"),
            "nothing reassures on the point that matters"
        );
        assert!(
            PAGE.contains("request these blocks from the network again"),
            "nothing says what to do"
        );
    }

    /// The address book: search, name, and go back beyond the latest ones.
    ///
    /// With four hundred derived addresses, a list cut to the twenty-five
    /// most recent is no longer a list: it is a wall. Three things open it up
    /// again, and this test locks them in.
    #[test]
    fn the_address_book_can_be_searched_named_and_unrolled() {
        for expected in [
            "address-filter",
            "Search your address book",
            "more-button",
            "Show more",
            "function matches(",
            "function renderBook(",
            "data-name=",
            "data-save=",
            "setaddresslabel",
        ] {
            assert!(
                PAGE.contains(expected),
                "address book element missing: {expected}"
            );
        }
        // The number can be searched as "12" as well as "#12": the user is
        // not made to guess the expected form.
        assert!(
            PAGE.contains(r##"("#" + num) === f"##),
            "the number cannot be searched with its hash sign"
        );
        // A new search starts over from the top: keeping the previous one's
        // pagination would make results disappear for no visible reason.
        assert!(
            PAGE.contains("bookShown = ADDRESSES_SHOWN;"),
            "the pagination is not reset when the search changes"
        );
        // The name is local: the page must say so, or one will believe it goes
        // along with the payment.
        assert!(
            PAGE.contains("visible only to you"),
            "nothing says the name stays on this machine"
        );
        // A single listener for the whole list: the rows are rebuilt on each
        // refresh.
        assert!(PAGE.contains(r#"document.getElementById("address-list").addEventListener"#));
    }

    /// A reference is shown in full, and copied with one click.
    ///
    /// It used to be cut at twenty characters. Enough to recognize it, not
    /// to carry it into the explorer's search — and nothing said that
    /// forty-four were missing.
    #[test]
    fn a_reference_is_full_and_copyable() {
        assert!(
            PAGE.contains("${esc(m.txid)}"),
            "the history reference is still truncated"
        );
        assert!(
            !PAGE.contains("trunc(m.txid"),
            "the history still cuts the reference"
        );
        assert!(
            !PAGE.contains("trunc(info.tip"),
            "the hash of the latest block is still cut"
        );
        assert!(PAGE.contains(r#"button.copy[data-ref]"#), "no copy button");
        assert!(
            PAGE.contains("td.ref{"),
            "the reference column has no style"
        );
        // The table forbids line breaks everywhere else: without an explicit
        // exception, a full hash would push the other columns off the screen.
        assert!(
            PAGE.contains("white-space:normal;word-break:break-all"),
            "the hash cannot wrap"
        );
        // The listener is attached once on the container, not per row: the
        // rows are rebuilt on each refresh.
        assert!(
            PAGE.contains(r#"for (const zone of ["movements", "chain-tiles"])"#),
            "the copy listeners would pile up on each refresh"
        );
    }

    /// After a successful payment, the user is taken to their transaction.
    #[test]
    fn a_successful_payment_leads_to_the_activity() {
        assert!(
            PAGE.contains(r#"show("activity")"#),
            "the payment does not switch to the activity"
        );
    }

    /// The network page places the user's machine within the whole.
    ///
    /// "Network power" alone does not answer the question one asks, which is
    /// "what share is mine". The two figures side by side answer it at a
    /// glance.
    #[test]
    fn the_network_page_shows_the_machine_and_the_whole() {
        for expected in [
            "Your machine",
            "network-mine",
            "network-share",
            "Computers connected to yours",
        ] {
            assert!(PAGE.contains(expected), "missing tile: {expected}");
        }
        // The address book of peers, once shown as "machines known to the
        // network", was removed: it was a list of learned addresses, not a
        // count of the network, and presenting it that way lied by shortcut.
        // Its tile's absence is checked by its identifier, not by its label.
        for removed in ["network-book", "network-window"] {
            assert!(
                !PAGE.contains(removed),
                "a tile removed from the network view is back: {removed}"
            );
        }
        // The refusal to count miners does not move.
        assert!(PAGE.contains("Why we don't tell you"));
    }

    /// The post-quantum scheme is named, with its standard and its level.
    #[test]
    fn the_page_names_the_signature_scheme() {
        assert!(PAGE.contains("ML-DSA-87"));
        assert!(PAGE.contains("FIPS&nbsp;204"));
        assert!(PAGE.contains("NIST level&nbsp;5"));
        assert!(PAGE.contains("getwalletinfo"));
    }

    /// The five views exist and can be reached.
    #[test]
    fn the_five_views_exist() {
        for v in ["balance", "receive", "send", "activity", "info"] {
            assert!(
                PAGE.contains(&format!(r#"id="view-{v}""#)),
                "missing view: {v}"
            );
            assert!(
                PAGE.contains(&format!(r#"data-view="{v}""#)),
                "missing tab: {v}"
            );
        }
    }

    /// The wallet closes with a button, not only with Ctrl-C.
    ///
    /// The defect locked out here: the only possible stop was Ctrl-C in the
    /// launcher's window. On Windows, the command interpreter then asks its
    /// own question — "Terminate batch job (Y/N)?" — which the first user
    /// read as a crash, to the point of no longer daring to stop their wallet.
    #[test]
    fn the_wallet_closes_with_a_button() {
        assert!(
            PAGE.contains(r#"id="close-button""#),
            "no close button in the page"
        );
        let s = script();
        assert!(
            s.contains(r#"call("stop")"#),
            "the button does not call the shutdown method"
        );
        // Without this, the page would show "Node unreachable" a few seconds
        // after a successful shutdown: the heartbeat would keep querying a
        // node one has just turned off oneself.
        assert!(
            s.contains("clearInterval(heartbeat)"),
            "the refresh heartbeat survives the shutdown"
        );
        // Two clicks: stopping by mistake forces a restart of everything.
        assert!(
            s.contains("closeConfirmed"),
            "the wallet closes in a single click"
        );
        // Windows' question is explained where it comes up.
        assert!(
            PAGE.contains("Terminate batch job"),
            "the page does not explain the question Windows asks after a Ctrl-C"
        );
    }

    /// The seven views exist, and mining as well as the network are among
    /// them.
    ///
    /// The previous test counted five. It was extended, not replaced: a view
    /// that disappears is a regression, a view that is added must be declared
    /// here.
    #[test]
    fn the_seven_views_exist() {
        for v in [
            "balance", "mine", "receive", "network", "send", "activity", "info",
        ] {
            assert!(
                PAGE.contains(&format!(r#"id="view-{v}""#)),
                "view missing from the markup: {v}"
            );
            assert!(
                PAGE.contains(&format!(r#"data-view="{v}""#)),
                "view missing from the navigation: {v}"
            );
        }
        assert!(
            script().contains(
                r#"const VIEWS = ["balance","mine","receive","network","send","activity","info"];"#
            ),
            "the script's list of views does not match the markup"
        );
    }

    /// The version shown comes from the node, not from the page.
    ///
    /// A version written into the markup would be right the day it was
    /// written and wrong at the next release — and it is precisely when it is
    /// wrong that one looks it up. It must come from `getinfo`, the only
    /// source entitled to say what the program is.
    #[test]
    fn the_version_shown_comes_from_the_node() {
        let s = script();
        assert!(
            s.contains(r#"tile("Program version", "q21 " + info.version"#),
            "the version is no longer read from the node's answer"
        );
        assert!(
            !PAGE.contains(&format!("q21 {}", env!("CARGO_PKG_VERSION"))),
            "the version is hard-coded in the page: it will lie at the next \
             release"
        );
    }

    /// A node without peers says **why**, and what to do.
    ///
    /// Two opposite states used to look the same: "I have nobody's address"
    /// and "I knocked, nobody opened". The first is fixed in two lines, the
    /// second is not — and the newcomer, not knowing which one is in front of
    /// them, concludes that the network is dead. The page must therefore read
    /// `configured_bootstrap` and say, when it applies, which file to create
    /// and what it must contain.
    #[test]
    fn a_node_without_bootstrap_says_what_to_do() {
        let s = script();
        assert!(
            s.contains("Number(info.configured_bootstrap) === 0"),
            "the page no longer tells \"no address\" from \"nobody opens\""
        );
        assert!(
            s.contains("No bootstrap address: this node is not looking for anyone"),
            "the title naming the cause is gone"
        );
        // The instruction must be complete: the file, the line to put in it,
        // and the guide. A message that names the problem without giving the
        // action is hardly better than the old one.
        for piece in [
            "q21-data/bootstrap.txt",
            "bootstrap.q21.dev:21121",
            "JOIN.md",
        ] {
            assert!(
                s.contains(piece),
                "the help message no longer contains: {piece}"
            );
        }
        // And it does not promise the return of the funds at the end of a step
        // that cannot start.
        assert!(
            s.contains("blind || Number(balance.derived_addresses) > 2"),
            "the restore line still promises funds to a blind node"
        );
    }

    /// Mining is controlled from the page, and nothing else can control it.
    #[test]
    fn mining_is_controlled_from_the_page() {
        let s = script();
        assert!(
            s.contains(r#"call("setmining", {active: want})"#),
            "no switch"
        );
        assert!(s.contains(r#"call("getmining")"#), "no state reading");
        // The button reflects the state returned by the node, never the
        // assumed state: showing "on" on the strength of a click would make
        // the page lie if the node refused.
        assert!(
            s.contains("paintMining(await call(\"setmining\""),
            "the mining display does not follow the node's answer"
        );
        // A node without a wallet cannot mine: the button is disabled.
        assert!(
            s.contains("b.disabled = !state.possible"),
            "button always enabled"
        );
    }

    /// The rate chart builds its markup only from numbers.
    ///
    /// It is the only place in the page where SVG is written on the fly. If a
    /// value coming from the node could slip in as is, it would enter as
    /// markup.
    #[test]
    fn the_sparkline_only_receives_numbers() {
        let s = script();
        let d = s
            .find("function sparkline(")
            .expect("the sparkline function");
        let f = s[d..].find("\n}").expect("its end") + d;
        let body = &s[d..f];
        assert!(
            body.contains("toFixed(1)"),
            "the coordinates are not forced to numbers"
        );
        for forbidden in ["esc(", "state.", "address"] {
            assert!(
                !body.contains(forbidden),
                "non-numeric value in the sparkline: {forbidden}"
            );
        }
    }

    /// The address list escapes every address, twice.
    ///
    /// An address arrives from the node. It is written in the visible text
    /// **and** in a `data-` attribute, and both paths must be escaped: a badly
    /// closed attribute is an injection just like an element.
    #[test]
    fn the_address_list_escapes_everything() {
        let s = script();
        let d = s
            .find("function renderBook(")
            .expect("the rendering function");
        let f = s[d..].find("\n}").expect("its end") + d;
        let body = &s[d..f];
        // Three times: in the visible text, in the copy button's attribute,
        // and in the explorer link. A badly closed attribute is an injection
        // just like an element.
        assert_eq!(
            body.matches("esc(a)").count(),
            3,
            "an address enters the page without going through esc"
        );
        assert!(
            body.contains("const a = String(e.address)"),
            "the address must be converted to a string before being escaped"
        );
        // The name comes from the user, but it may have been typed elsewhere —
        // a restored wallet, a copied file. It is escaped like everything else,
        // in the text and in the field's value.
        assert!(
            body.contains("esc(String(e.label))"),
            "a label enters the text without escaping"
        );
        assert!(
            body.contains(r#"esc(String(e.label || ""))"#),
            "a label enters an attribute without escaping"
        );
        let dl = s
            .find("async function listAddresses(")
            .expect("the loading function");
        let fl = s[dl..].find("\n}").expect("its end") + dl;
        assert!(
            s[dl..fl].contains("esc(e.message)"),
            "an error message from the node enters without escaping"
        );
    }

    /// The receiving speed is computed in the page, not in the node.
    #[test]
    fn the_sync_speed_is_a_local_derivative() {
        let s = script();
        assert!(s.contains("function pulse(sync)"), "no pulse computation");
        assert!(
            s.contains("blockSpeed = blockSpeed * 0.6"),
            "the speed is not smoothed: it would jump at every round"
        );
        // It must not be asked of the node: that would be more shared state in
        // a program that handles funds.
        assert!(
            !s.contains("network_speed") && !s.contains("getspeed"),
            "the speed is asked of the node when it is derived here"
        );
    }

    /// The network view never claims to count the miners.
    ///
    /// It is a property of substance, not of presentation: a made-up figure
    /// would be worse than no figure, and the temptation will come back.
    #[test]
    fn the_network_view_does_not_count_miners() {
        let s = script();
        assert!(
            s.contains(r#"call("getnetworkhashrate")"#),
            "the view does not query the node"
        );
        // The page shows what your machine does and why it does not count the
        // miners — never a made-up number of miners.
        assert!(
            PAGE.contains("Your machine"),
            "the page does not show what your machine does"
        );
        assert!(
            PAGE.contains("Why we don't tell you"),
            "the page does not say why it does not count miners"
        );
        // And without a local measure, no share is made up.
        assert!(
            s.contains("mine > 0 && rate > 0"),
            "the share is computed even without a known local rate"
        );
    }

    /// The page's vocabulary is that of a beginner.
    ///
    /// "Height", "derived addresses", "spendable", "immature" are the
    /// protocol's words. They are accurate and they mean nothing to anyone.
    /// This test locks in the plain-language labels: bringing the jargon back
    /// would require changing it, hence deciding to.
    #[test]
    fn the_page_speaks_everyone_s_language() {
        for jargon in ["Height", "Derived addresses", "Spendable"] {
            assert!(
                !PAGE.contains(&format!(">{jargon}<")) && !PAGE.contains(&format!("\"{jargon}\"")),
                "jargon brought back as a label: {jargon}"
            );
        }
        for plain in [
            "Blocks verified",
            "Your addresses",
            "Available",
            "Awaiting maturity",
        ] {
            assert!(PAGE.contains(plain), "plain label lost: {plain}");
        }
        // And the word "derivation" is explained where it appears, not
        // elsewhere.
        assert!(
            PAGE.contains("derivation</strong>") || PAGE.contains("<strong>derivation"),
            "the protocol's word is used without being explained"
        );
    }

    /// The log of blocks found says which block, when, and how much.
    ///
    /// That is what a miner comes to look at: not an abstract counter, their
    /// own blocks, with each one's gain and a link to the explorer.
    #[test]
    fn the_log_of_blocks_found_is_complete_and_escaped() {
        let s = script();
        assert!(s.contains("function paintFinds"), "no log");
        // Every field coming from the node goes through `esc` — the height
        // included, since it also enters an href attribute.
        for e in [
            "esc(String(t.height))",
            "esc(shortWhen(t.timestamp))",
            "esc(t.reward.q21)",
        ] {
            assert!(s.contains(e), "field not escaped: {e}");
        }
        // The height leads to the explorer of the same node, never elsewhere.
        assert!(s.contains(r#"href="/#/block/"#), "no link to the explorer");
        assert!(s.contains(r#"rel="noopener""#));
        // The total earned is shown, and comes from the node — not from a JS
        // addition.
        assert!(
            s.contains("state.earned"),
            "the earnings are not the node's"
        );
        // The empty state explains the lottery instead of showing a bare list.
        assert!(s.contains("It is a lottery"));
    }

    /// The balance's quick actions lead to the three main actions.
    #[test]
    fn the_balance_carries_the_quick_actions() {
        for v in ["receive", "send", "mine"] {
            assert!(
                PAGE.contains(&format!(r#"data-go="{v}""#)),
                "quick action missing: {v}"
            );
        }
        assert!(script().contains(r#"button[data-go]"#));
    }

    /// The activity reads at a glance: an icon per direction, a signed amount.
    #[test]
    fn the_activity_carries_icons_and_signs() {
        let s = script();
        assert!(s.contains("function kindIcon"), "no movement icons");
        // Three directions, three drawings — and an unknown kind falls back on
        // a generic drawing rather than on nothing.
        for cl in ["dir mine", "dir out", "dir in"] {
            assert!(s.contains(cl), "missing direction: {cl}");
        }
        // The amount received is shown signed and colored; absence stays a
        // dash.
        assert!(s.contains(r#""+ " + m.received.q21"#));
        assert!(PAGE.contains("td.plus{color:var(--accent)"));
        assert!(PAGE.contains("td.minus{color:var(--danger)"));
    }

    /// The security card promises restoration everywhere, and tells the code
    /// apart from the passphrase.
    ///
    /// Confusing the two is the first cause of funds believed lost: someone
    /// remembers their passphrase, loses their code, and discovers too late
    /// that the passphrase rebuilds nothing.
    #[test]
    fn the_security_card_says_what_saves_and_what_does_not() {
        assert!(PAGE.contains("The backup code is your wallet"));
        for os in [
            "Windows",
            "Intel Mac",
            "Apple
      Silicon Mac",
            "Linux",
            "Raspberry Pi",
        ] {
            assert!(PAGE.contains(os), "system missing from the promise: {os}");
        }
        assert!(PAGE.contains(
            "which only protects the
      file on <em>this</em> machine"
        ));
        assert!(PAGE.contains("Do not photograph the code"));
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
    /// protects against injection — and so the page displayed its own markup
    /// in plain text, on screen. The first user to open a transaction saw it.
    ///
    /// No test could catch it: the existing ones looked for the opposite
    /// defect, markup inserted **without** escaping. One had to look the other
    /// way.
    ///
    /// The fix is not to add `raw` at that spot, but to provide a function —
    /// `badge` — that builds the label and takes care of the marking. This
    /// test checks that we do not go back.
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

    /// The page is usable on a phone before anywhere else.
    #[test]
    fn the_page_is_designed_for_the_phone_first() {
        assert!(PAGE.contains(r#"name="viewport""#));
        assert!(PAGE.contains("width=device-width, initial-scale=1"));
        // The widenings are `min-width`: the narrow layout is the one that
        // applies unconditionally.
        assert!(PAGE.contains("@media(min-width:560px)"));
        assert!(
            !PAGE.contains("@media(max-width"),
            "a max-width rule betrays a layout designed for the wide screen"
        );
    }

    /// The wallet reads in English, French and Japanese, and the choice takes
    /// one click.
    ///
    /// Translation works by matching the source text rather than through
    /// identifiers scattered in the page: that is what makes it possible to
    /// cover the text the script builds at run time too. This test locks in
    /// the mechanism and a few witness translations — losing them would
    /// otherwise go unnoticed until a user landed on a half-translated page.
    #[test]
    fn the_wallet_translates_into_three_languages() {
        // The selector, and its three flags.
        assert!(
            PAGE.contains(r#"id="languages""#),
            "language selector missing"
        );
        for l in ["en", "fr", "ja"] {
            assert!(
                PAGE.contains(&format!(r#"data-lang="{l}""#)),
                "language missing from the selector: {l}"
            );
        }

        let s = script();
        // The engine.
        for f in [
            "function q21Norm",
            "function q21Translate",
            "function q21TranslateText",
            "function q21ApplyLanguage",
            "MutationObserver",
        ] {
            assert!(s.contains(f), "translation engine incomplete: {f}");
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

        // A few witness translations, in both languages.
        let fr = table("I18N", "fr");
        let ja = table("I18N", "ja");
        for (en, fr_word, ja_word) in [
            ("Balance", "Solde", "残高"),
            ("Send", "Envoyer", "送る"),
            ("Network", "Réseau", "ネットワーク"),
        ] {
            assert_eq!(
                fr.get(en).map(String::as_str),
                Some(fr_word),
                "French lost: {en}"
            );
            assert_eq!(
                ja.get(en).map(String::as_str),
                Some(ja_word),
                "Japanese lost: {en}"
            );
        }

        // What is not translated must stay in English, never empty.
        assert!(
            s.contains("if (t !== null) v = t;"),
            "the fallback on the original text is gone"
        );

        // --- The three matching layers.
        //
        // Exact matching is not enough: a sentence built around a number
        // changes with every display, and would therefore never be
        // translated. The patterns capture the variable part; the prefixes
        // handle messages with a variable tail. Losing a layer would leave part
        // of the interface untranslated without any test failing.
        for layer in [
            "const I18N =",
            "const I18N_PATTERNS =",
            "const I18N_PREFIXES =",
        ] {
            assert!(s.contains(layer), "translation layer missing: {layer}");
        }
        assert!(
            s.contains("pattern.test(n)"),
            "the patterns are no longer applied"
        );

        // Dates and numbers follow the language: translating the words while
        // leaving "08/12/2025" to a Japanese reader would be a job half done.
        assert!(s.contains("function q21Locale"), "the locale is gone");
        for tag in ["en-US", "ja-JP", "fr-FR"] {
            assert!(s.contains(tag), "missing locale: {tag}");
        }
        assert!(
            !s.contains("toLocaleDateString(\"fr-FR\")"),
            "a date stays frozen in French"
        );
    }

    /// Every key of the translation tables is a text the page really writes.
    ///
    /// The tables are keyed by the English source. A key that no longer
    /// matches any text of the page is a translation that silently stopped
    /// working: the English changed, the table did not.
    #[test]
    fn every_table_key_appears_in_the_page() {
        let page = normalized_page();
        assert!(
            !page.contains("const I18N"),
            "the tables must not be searched"
        );
        let fr = table("I18N", "fr");
        assert!(
            fr.len() > 200,
            "only {} keys: the table is missing",
            fr.len()
        );
        // A key may also be a message the page builds from one of its prefixes
        // and another of its texts: "Could not reach the node: " followed by
        // the error the page itself raises.
        let prefixes = table("I18N_PREFIXES", "fr");
        let written = |k: &str| {
            page.contains(k)
                || prefixes
                    .keys()
                    .any(|p| k.starts_with(p.as_str()) && page.contains(&k[p.len()..]))
        };
        let missing: Vec<&String> = fr.keys().filter(|k| !written(k)).collect();
        assert!(
            missing.is_empty(),
            "table keys not found in the page source: {missing:#?}"
        );
        for key in table("I18N", "ja").keys() {
            assert!(
                fr.contains_key(key),
                "{key:?} is translated into Japanese only"
            );
        }
        for lang in ["fr", "ja"] {
            for key in table("I18N_PREFIXES", lang).keys() {
                assert!(
                    page.contains(key.trim_end()),
                    "prefix not found in the page source: {key:?}"
                );
            }
        }
    }

    /// Selecting French gives back, word for word, the French the page was
    /// written in before English became the source — checked here for the
    /// messages that matter for the safety of the funds: the connection badge,
    /// the backup code warnings, and the help shown when the node has no
    /// server address.
    #[test]
    fn the_french_table_gives_back_the_original_french() {
        let fr = table("I18N", "fr");
        // The wording is compared; where today's page used a no-break space
        // (French typography before ":" or after a closing tag), so does the
        // table, and the browser comparison checks those to the character.
        let french = |en: &str| -> String {
            fr.get(en)
                .unwrap_or_else(|| panic!("no French for {en:?}"))
                .replace('\u{a0}', " ")
                .trim()
                .to_string()
        };
        for (en, original) in [
            // The connection badge.
            ("Connected", "Connecté"),
            ("Syncing", "Synchronisation"),
            ("Offline", "Hors connexion"),
            ("· no computer reachable", "· aucun ordinateur joignable"),
            // The backup code warnings.
            ("The backup code is your wallet", "Le code de sauvegarde est votre portefeuille"),
            (
                "The file on this disk is only a working copy.",
                "Le fichier sur ce disque n'est qu'une copie de travail.",
            ),
            (
                "Your entire wallet — every address, all your funds — can be rebuilt from the single backup code you wrote down when you created it.",
                "Tout votre portefeuille — chaque adresse, chaque fonds — se refabrique à partir du seul code de sauvegarde que vous avez recopié à la création.",
            ),
            ("Two things you must never do", "Deux choses à ne jamais faire"),
            (
                "Do not photograph the code, and do not paste it into a cloud service: whoever reads it holds your funds, for good. And do not confuse the code with your",
                "Ne photographiez pas le code, ne le collez pas dans un nuage : qui le lit détient vos fonds, définitivement. Et ne confondez pas le code avec votre",
            ),
            ("passphrase", "phrase secrète"),
            (
                "— which only protects the file on",
                "— elle, ne protège que le fichier de",
            ),
            ("this", "cette"),
            (
                "machine, and can be different elsewhere.",
                "machine, et peut être différente ailleurs.",
            ),
            // The help for a node without a server address.
            (
                "No bootstrap address: this node is not looking for anyone",
                "Aucune adresse de départ : ce nœud ne cherche personne",
            ),
            (
                "The program contains no server address, and that is deliberate: an address hard-coded into distributed software would become a permanent dependency on whoever controls it. It is provided separately, in a file you can edit. Create q21-data/bootstrap.txt next to the program, add the line bootstrap.q21.dev:21121 to it, then restart. JOIN.md, which ships with the program, explains this step and how to add more entry points.",
                "Le programme ne contient l'adresse d'aucun serveur, et c'est voulu : une adresse gravée dans un logiciel distribué deviendrait une dépendance permanente envers celui qui la tient. Elle se donne à côté, dans un fichier que vous pouvez modifier. Créez q21-data/bootstrap.txt auprès du programme, écrivez-y la ligne bootstrap.q21.dev:21121, puis relancez. JOIN.md, livré avec le programme, détaille ce geste et la façon d'ajouter d'autres points d'entrée.",
            ),
        ] {
            assert_eq!(french(en), original, "the French for {en:?} changed");
        }
    }

    /// English is the source: outside the translation tables, the page has no
    /// French left.
    #[test]
    fn english_is_the_source_language() {
        let rest = page_without_tables().replace(r#"title="Français""#, "");
        for c in rest.chars() {
            assert!(
                !"àâäçéèêëîïôöùûüÿœæÀÂÇÉÈÊÎÔÙÛŒ«»".contains(c),
                "French character {c:?} outside the translation tables"
            );
        }
        assert!(!rest.contains(" nœud"), "French left in the page");
    }

    /// The explorer reads this page's token under its key: renaming one
    /// without the other brings back the token panel of 0.4.1. And the link
    /// carries no token: the explorer would take it for a launch token.
    #[test]
    fn the_explorer_link_relies_on_the_shared_origin() {
        assert!(PAGE.contains(r#"const SESSION_KEY = "q21-token";"#));
        assert!(crate::explorer::PAGE.contains(r#"const WALLET_KEY = "q21-token";"#));
        assert!(PAGE.contains(r#"<a class="flat" id="explorer-link" href="/">"#));
        assert!(!PAGE.contains("linkExplorer"));
    }

    /// "Give me your wallet address" has an answer on arrival: the Receive
    /// screen shows one address, whole, with a copy button and a link to the
    /// explorer - escaped on all three paths.
    #[test]
    fn the_receive_screen_shows_the_address_to_give() {
        assert!(PAGE.contains(r#"<div id="my-address">"#));
        assert!(PAGE.contains("<h3>Which address should I give?</h3>"));
        let s = script();
        let d = s
            .find("async function renderMyAddress(")
            .expect("the function");
        let f = s[d..].find("\n}").expect("its end") + d;
        let body = &s[d..f];
        assert_eq!(body.matches("esc(a)").count(), 3);
        assert!(
            body.contains("isShown(x) && !x.consumed"),
            "never a used key"
        );
        assert!(
            body.contains("myAddressAsked = true"),
            "one request at most"
        );
        assert!(script().contains("renderBook();\n    renderMyAddress();"));
    }

    /// The Activity tab can go further back than its first hundred rows,
    /// and the filter travels with the request.
    #[test]
    fn the_activity_can_show_older_movements() {
        assert!(PAGE.contains(r#"id="activity-more-button""#));
        let s = script();
        assert!(s.contains("const ACTIVITY_MAX = 2000;"));
        assert!(s.contains(r#"call("listtransactions", activityQuery())"#));
        assert!(
            s.contains("activityLimit = ACTIVITY_STEP;"),
            "a new filter starts again at a hundred"
        );
        // Only the four known kinds can leave the page.
        assert!(s.contains(r#"["send", "receive", "mining"].includes(activityFilter)"#));
    }
}
