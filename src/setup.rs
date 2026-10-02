//! First run: create or open a wallet, without a terminal.
//!
//! # The defect this file closes
//!
//! Until now, a newcomer had to type two commands before seeing anything at
//! all: `q21 init testnet`, which asks for a passphrase in a black window and
//! scrolls a backup code through it, then `q21 wallet`, which asks for the
//! passphrase again. The double-click launcher hid the first one by chaining
//! it, but the black window remained, and with it the question asked with no
//! context at all: "Wallet passphrase: ".
//!
//! No desktop application asks for that. This module replaces those two
//! moments with screens.
//!
//! # What this changes in the trust model, said plainly
//!
//! It is not neutral, and keeping quiet about it would be dishonest.
//!
//! **Before**, the passphrase was typed in a terminal and the seed was shown
//! in that same terminal. The browser saw neither one — which is what the
//! header of `wallet_ui.rs` still states, rightly for that page: the wallet
//! page never receives a secret.
//!
//! **From now on**, for this page and this page alone: the passphrase travels
//! from the browser to the node, and the backup code — which *is* the seed —
//! travels from the node to the browser to be written down.
//!
//! What this costs, exactly: the browser enters the seed's trust boundary,
//! where it was not before. A browser extension allowed on `127.0.0.1` can
//! read the content of a page; it could therefore read the backup code during
//! the few seconds it is on screen.
//!
//! What this does not cost: that extension could **already** empty the
//! wallet. The wallet page has `sendtoaddress`, and has had it since day one.
//! The boundary widens from the right to spend to the right to know the seed;
//! it does not open to someone who was outside.
//!
//! What is done to reduce the surface:
//!
//! - the server listens only on the loopback interface, and requires the
//!   session token for everything except the HTML shell; that token is never
//!   in the address the browser opens — that address carries a one-time
//!   launch token, exchanged on load (see `http::serve_with_launch_token`);
//! - the passphrase only leaves in the body of a `POST` request, never in an
//!   address;
//! - the page forbids `localStorage`, `sessionStorage` and cookies: nothing it
//!   handles outlives the tab;
//! - the fields carry `autocomplete="off"`, so that the browser's password
//!   manager does not offer to save the passphrase;
//! - the backup code is only shown on screen, to be copied onto paper: no
//!   button sends it to the clipboard, whose history outlives the page and is
//!   sometimes synced between devices;
//! - the backup code is removed from the page as soon as it has been
//!   confirmed.
//!
//! What only a real native window would solve, with a UI library — that is,
//! with one more dependency in a program that holds private keys. The choice
//! was made the other way, knowingly.
//!
//! # Why a second server, and not the node itself
//!
//! The node already serves a page and an RPC; it could have served this one.
//! But `RpcContext` carries `wallet: Option<Arc<Mutex<Wallet>>>`, fixed when it
//! is built: adopting a wallet midway would require turning that structure
//! into `Arc<Mutex<Option<Wallet>>>`, and so touching every call that handles
//! funds.
//!
//! A small separate server, which lives for the duration of the setup and then
//! hands back control, touches none of that. It listens on **its own port**,
//! never on the node's: taking back a port that was just released is a race
//! that fails on some systems, and there is no reason to run it.

/// Setup page. No external resource, like the other two.
pub const PAGE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Q21 — welcome</title>
<style>
:root{
  --bg:#f5f4f0; --card:#fffefb; --border:#dcd8cf; --border-strong:#c3bdb1;
  --text:#1a1a18; --soft:#57554d; --muted:#8b887d;
  --accent:#1d6f66; --accent-bg:#e2eeeb; --warn:#8a5a1e; --warn-bg:#f4e9d8;
  --danger:#9b3025; --danger-bg:#f6e3e0;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#131410; --card:#1c1e18; --border:#32352b; --border-strong:#454940;
    --text:#ecebe0; --soft:#aca99a; --muted:#7b786b;
    --accent:#62bfb2; --accent-bg:#16302c; --warn:#d9a75f; --warn-bg:#312716;
    --danger:#e08a7d; --danger-bg:#33201d;
  }
}
*{box-sizing:border-box}
body{
  margin:0;background:var(--bg);color:var(--text);
  font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem}
.frame{width:100%;max-width:560px}

/* --- The step trail ------------------------------------------------------ */
.steps{display:flex;gap:.5rem;margin-bottom:1.6rem;align-items:center;
  justify-content:center;flex-wrap:wrap}
.steps .step{display:flex;align-items:center;gap:.5rem;font-size:.8rem;color:var(--muted)}
.steps .num{width:1.55rem;height:1.55rem;border-radius:50%;display:grid;place-items:center;
  border:1.5px solid var(--border-strong);font-size:.75rem;font-weight:600;
  font-variant-numeric:tabular-nums;flex:0 0 auto}
.steps .step.current{color:var(--text);font-weight:600}
.steps .step.current .num{border-color:var(--accent);background:var(--accent);color:var(--bg)}
.steps .step.done .num{border-color:var(--accent);color:var(--accent)}
.steps .line{width:1.4rem;height:1.5px;background:var(--border)}

/* --- The card ------------------------------------------------------------ */
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;
  padding:2rem 2rem 1.7rem}
@media(max-width:520px){.card{padding:1.4rem 1.2rem}}
.eyebrow{font-size:.72rem;letter-spacing:.16em;text-transform:uppercase;
  color:var(--accent);font-weight:600;margin-bottom:.5rem}
h1{font-size:1.55rem;line-height:1.2;margin:0 0 .6rem;letter-spacing:-.015em;
  text-wrap:balance}
h2{font-size:1.05rem;margin:1.6rem 0 .5rem}
p{margin:0 0 1rem;color:var(--soft)}
p.tight{margin-bottom:.5rem}
strong{color:var(--text);font-weight:600}

/* --- Fields -------------------------------------------------------------- */
label{display:block;font-size:.85rem;font-weight:600;margin:1.1rem 0 .35rem}
.field{position:relative}
input[type=password],input[type=text],textarea{
  width:100%;padding:.7rem .8rem;font:inherit;color:var(--text);
  background:var(--bg);border:1.5px solid var(--border-strong);border-radius:7px;
  outline:none}
input:focus,textarea:focus{border-color:var(--accent);
  box-shadow:0 0 0 3px var(--accent-bg)}
textarea{resize:vertical;min-height:5.2rem;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9rem}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.reveal{position:absolute;right:.5rem;top:50%;transform:translateY(-50%);
  background:none;border:none;color:var(--muted);font-size:.78rem;cursor:pointer;
  padding:.3rem .4rem;border-radius:4px}
.reveal:hover{color:var(--text);background:var(--bg)}
.help{font-size:.8rem;color:var(--muted);margin:.35rem 0 0}

/* --- Passphrase strength ------------------------------------------------- */
.meter{height:4px;border-radius:2px;background:var(--border);margin-top:.5rem;
  overflow:hidden}
.meter i{display:block;height:100%;width:0;background:var(--warn);
  transition:width .18s,background .18s}
.meter.good i{background:var(--accent)}
.verdict{font-size:.8rem;margin-top:.35rem;color:var(--muted);min-height:1.2em}

/* --- Buttons ------------------------------------------------------------- */
.actions{display:flex;gap:.7rem;margin-top:1.6rem;flex-wrap:wrap}
button.p,button.s{padding:.7rem 1.2rem;font:inherit;font-weight:600;
  border-radius:7px;cursor:pointer;border:1.5px solid transparent}
button.p{background:var(--accent);color:var(--bg);border-color:var(--accent);flex:1}
button.p:hover:not(:disabled){filter:brightness(1.08)}
button.p:disabled{opacity:.45;cursor:not-allowed}
button.s{background:transparent;color:var(--soft);border-color:var(--border-strong)}
button.s:hover{color:var(--text);border-color:var(--muted)}
button:focus-visible{outline:3px solid var(--accent-bg);outline-offset:1px}
.link{background:none;border:none;color:var(--accent);font:inherit;font-size:.85rem;
  cursor:pointer;padding:.2rem 0;text-decoration:underline;text-underline-offset:3px}

/* --- Callouts ------------------------------------------------------------ */
.note{border-left:3px solid var(--accent);background:var(--accent-bg);
  border-radius:0 7px 7px 0;padding:.8rem 1rem;font-size:.88rem;margin:1.1rem 0}
.note.warn{border-color:var(--warn);background:var(--warn-bg)}
.note.bad{border-color:var(--danger);background:var(--danger-bg)}
.note p{margin:0;color:var(--soft)}
.note p+p{margin-top:.5rem}
.note b{color:var(--text)}

/* --- The backup code ----------------------------------------------------- */
.code{background:var(--bg);border:1.5px dashed var(--border-strong);border-radius:9px;
  padding:1.1rem;margin:1rem 0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:1.02rem;line-height:1.75;word-break:break-all;letter-spacing:.02em}
.code b{color:var(--accent);font-weight:600}

/* --- Miscellaneous ------------------------------------------------------- */
.check{display:flex;gap:.6rem;align-items:flex-start;margin:1.1rem 0;
  font-size:.9rem;color:var(--soft);cursor:pointer}
.check input{margin:.3rem 0 0;flex:0 0 auto;width:1.05rem;height:1.05rem;
  accent-color:var(--accent)}
.waiting{display:flex;gap:.7rem;align-items:center;color:var(--soft);
  font-size:.92rem;margin-top:1.2rem}
.spinner{width:1.05rem;height:1.05rem;border:2px solid var(--border-strong);
  border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;
  flex:0 0 auto}
@keyframes spin{to{transform:rotate(360deg)}}
@media(prefers-reduced-motion:reduce){.spinner{animation:none}}
.footer{text-align:center;font-size:.78rem;color:var(--muted);margin-top:1.2rem}
.hide{display:none}
</style>
</head>
<body>
<div class="frame">
  <div class="steps" id="steps"></div>
  <div class="card" id="card"></div>
  <div class="footer" id="footer"></div>
</div>
<script>
"use strict";
// This page keeps nothing: no browser storage is used, and a test checks it by
// looking for the names of those interfaces in this script. What passes
// through here is the passphrase and the seed; none of it may be readable
// once the tab is closed.

var TOKEN = "", LAUNCH_TOKEN = "", STATUS = null, PASSPHRASE = null, CODE = null;

function $(id){ return document.getElementById(id); }
function esc(s){
  return String(s).replace(/[&<>"']/g, function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];
  });
}

// The fragment carries a launch token, not the session token: the address is
// handed to the browser as a command-line argument, which other accounts on
// the machine can read. The launch token is exchanged once for the session
// token, and is worthless after that. It is erased from the address bar as
// soon as it is read: a secret that can be photographed is no longer one.
(function(){
  var f = location.hash.slice(1);
  if(f){ LAUNCH_TOKEN = f; history.replaceState(null, "", location.pathname); }
})();

function exchange(){
  return fetch("/session", {
    method: "POST",
    headers: {"Content-Type":"application/json","Authorization":"Bearer " + LAUNCH_TOKEN}
  }).then(function(r){
    if(!r.ok) throw new Error("link already used or expired");
    return r.json();
  }).then(function(d){ TOKEN = d.token; LAUNCH_TOKEN = ""; });
}

function call(m, p){
  return fetch("/setup", {
    method: "POST",
    headers: {"Content-Type":"application/json","Authorization":"Bearer " + TOKEN},
    body: JSON.stringify({method: m, params: p || {}})
  }).then(function(r){ return r.json(); }).then(function(d){
    if(d && d.error) throw new Error(d.error);
    return d;
  });
}

// --- The step trail ------------------------------------------------------
function drawSteps(names, current){
  if(!names){ $("steps").innerHTML = ""; return; }
  var h = "";
  for(var i = 0; i < names.length; i++){
    if(i) h += '<span class="line"></span>';
    var cl = i === current ? " current" : (i < current ? " done" : "");
    h += '<span class="step' + cl + '"><span class="num">'
       + (i < current ? "&#10003;" : (i + 1)) + '</span>' + esc(names[i]) + '</span>';
  }
  $("steps").innerHTML = h;
}

function footer(t){ $("footer").textContent = t || ""; }

// --- Passphrase strength -------------------------------------------------
//
// An estimate, not a measurement: it counts length and variety, which is
// enough to tell "sunshine" from "sunshine-in-march-1998". It does not claim
// to assess real entropy, and it never blocks: it is advice, not a rule.
// Composition rules make passphrases shorter, not safer.
function strength(p){
  if(!p) return {n:0, word:""};
  var v = 0;
  if(/[a-z]/.test(p)) v++;
  if(/[A-Z]/.test(p)) v++;
  if(/[0-9]/.test(p)) v++;
  if(/[^a-zA-Z0-9]/.test(p)) v++;
  var n = Math.min(100, (p.length / 20) * 70 + v * 7.5);
  var word = n < 35 ? "Short — a few more words would be better"
           : n < 65 ? "Fair"
           : "Strong";
  return {n:n, word:word};
}

// --- Screen: where to start ----------------------------------------------
function showWelcome(){
  drawSteps(null);
  footer("Testnet — no Q21 here has any value");
  $("card").innerHTML =
    '<div class="eyebrow">Q21</div>'
  + '<h1>Welcome</h1>'
  + '<p>This program is a wallet <strong>and</strong> a node: it checks every '
  + 'block itself instead of taking anyone\'s word for it. Everything stays on '
  + 'this machine.</p>'
  + '<div class="actions">'
  + '<button class="p" id="b-create">Create a wallet</button>'
  + '</div>'
  + '<p style="margin:1.1rem 0 0;text-align:center">'
  + '<button class="link" id="b-restore">I already have a backup code</button></p>';
  $("b-create").onclick = function(){ showPassphrase(false); };
  $("b-restore").onclick = showRestore;
}

// --- Screen: the passphrase ----------------------------------------------
// The two paths do not have the same steps, and the trail must say so. It used
// to show the creation path during a restore: the user had just typed their
// code, and the screen announced that it was still to be revealed.
function stepNames(restoring){
  return restoring
    ? ["Backup code", "Passphrase", "Ready"]
    : ["Passphrase", "Backup code", "Ready"];
}

function showPassphrase(restoring){
  drawSteps(stepNames(restoring), restoring ? 1 : 0);
  footer("");
  $("card").innerHTML =
    '<div class="eyebrow">Step ' + (restoring ? 2 : 1) + ' of 3</div>'
  + '<h1>Choose a passphrase</h1>'
  + (restoring
      ? '<p>This passphrase protects the wallet <strong>on this machine only</strong>. '
      + 'It can differ from the one you used elsewhere: it is not part of your '
      + 'backup code, it only encrypts this disk.</p>'
      : '')
  + '<p>It encrypts your wallet on this disk. Without it, anyone who reads the '
  + 'file — a backup, a resold disk — holds the funds forever.</p>'
  + '<div class="note"><p><b>It cannot be recovered.</b> No server knows it, '
  + 'and no one can reset it. Choose several words you will remember, and write '
  + 'it down somewhere other than here.</p></div>'
  + '<label for="p1">Passphrase</label>'
  + '<div class="field">'
  + '<input type="password" id="p1" autocomplete="off" autocapitalize="off" '
  + 'autocorrect="off" spellcheck="false">'
  + '<button class="reveal" id="reveal" type="button">show</button></div>'
  + '<div class="meter" id="meter"><i></i></div>'
  + '<div class="verdict" id="verdict"></div>'
  + '<label for="p2">Type it again</label>'
  + '<div class="field"><input type="password" id="p2" autocomplete="off" '
  + 'autocapitalize="off" autocorrect="off" spellcheck="false"></div>'
  + '<div class="verdict" id="match"></div>'
  + '<div class="actions">'
  + '<button class="s" id="back">Back</button>'
  + '<button class="p" id="next" disabled>Continue</button></div>'
  + '<p style="margin:1.1rem 0 0;text-align:center">'
  + '<button class="link" id="skip">Continue without a passphrase</button></p>';

  var p1 = $("p1"), p2 = $("p2"), next = $("next");
  function judge(){
    var f = strength(p1.value);
    $("meter").firstChild.style.width = f.n + "%";
    $("meter").className = "meter" + (f.n >= 65 ? " good" : "");
    $("verdict").textContent = f.word;
    var ok = p1.value.length > 0 && p1.value === p2.value;
    $("match").textContent = p2.value && !ok ? "The two do not match." : "";
    next.disabled = !ok;
  }
  p1.oninput = judge; p2.oninput = judge;
  p2.onkeydown = function(e){ if(e.key === "Enter" && !next.disabled) next.click(); };
  $("reveal").onclick = function(){
    var t = p1.type === "password" ? "text" : "password";
    p1.type = t; p2.type = t;
    $("reveal").textContent = t === "text" ? "hide" : "show";
  };
  $("back").onclick = restoring ? showRestore : showWelcome;
  next.onclick = function(){ PASSPHRASE = p1.value; create(); };
  $("skip").onclick = showNoPassphrase;
  p1.focus();
}

function showNoPassphrase(){
  drawSteps(stepNames(false), 0);
  $("card").innerHTML =
    '<div class="eyebrow">Step 1 of 3</div>'
  + '<h1>No passphrase?</h1>'
  + '<div class="note bad">'
  + '<p><b>Your seed will be written unencrypted to this disk.</b></p>'
  + '<p>Any program, any backup, anyone with access to this file will be able '
  + 'to spend your funds — permanently, with nothing you can do about it.</p></div>'
  + '<p>That is a reasonable choice on a testnet where nothing has value. '
  + 'It is not reasonable anywhere else.</p>'
  + '<label class="check"><input type="checkbox" id="understood">'
  + '<span>I understand: my seed will be stored without protection.</span></label>'
  + '<div class="actions">'
  + '<button class="s" id="back">Set a passphrase</button>'
  + '<button class="p" id="next" disabled>Continue without protection</button></div>';
  $("understood").onchange = function(){ $("next").disabled = !this.checked; };
  $("back").onclick = function(){ showPassphrase(false); };
  $("next").onclick = function(){ PASSPHRASE = ""; create(); };
}

// --- Screen: restore -----------------------------------------------------
function showRestore(){
  drawSteps(stepNames(true), 0);
  footer("");
  $("card").innerHTML =
    '<div class="eyebrow">Restore</div>'
  + '<h1>Your backup code</h1>'
  + '<p>Type it exactly as written. It carries a checksum: a typo will be '
  + 'caught, not silently accepted.</p>'
  + '<label for="c">Backup code</label>'
  + '<textarea id="c" autocomplete="off" autocapitalize="off" autocorrect="off" '
  + 'spellcheck="false"></textarea>'
  + '<p class="help">The alphabet it uses has no <span class="mono">1</span>, '
  + '<span class="mono">b</span>, <span class="mono">i</span> or '
  + '<span class="mono">o</span>, so that no character can be mistaken for another.</p>'
  + '<div class="actions">'
  + '<button class="s" id="back">Back</button>'
  + '<button class="p" id="next" disabled>Continue</button></div>';
  var c = $("c");
  // A copy and paste can slip a line break or a space into the middle of the
  // code — the code's alphabet contains neither. They are removed as the user
  // types, so that the field shows, and sends, a single continuous code,
  // whatever the original layout (see the screenshot of the fixed defect).
  function cleanCode(v){ return v.replace(/[\s\u200B\u200C\u200D\uFEFF\u00AD]/g, ''); }
  c.oninput = function(){
    var clean = cleanCode(c.value);
    if (clean !== c.value) c.value = clean;
    $("next").disabled = c.value.length < 20;
  };
  $("back").onclick = showWelcome;
  $("next").onclick = function(){ CODE = cleanCode(c.value); showPassphrase(true); };
  c.focus();
}

// --- Creation ------------------------------------------------------------
function create(){
  drawSteps(["Passphrase", "Backup code", "Ready"], 1);
  $("card").innerHTML =
    '<div class="eyebrow">One moment</div>'
  + '<h1>Creating your wallet</h1>'
  + '<p>The program draws a seed from the system\'s random number generator, '
  + 'writes the genesis block and seals the wallet.</p>'
  + '<div class="waiting"><span class="spinner"></span><span>A few seconds…</span></div>';

  call("create", {passphrase: PASSPHRASE, code: CODE})
    .then(function(d){
      // Restoring is not creating. We do not ask the user to copy down a code
      // they have just typed; we show that it was understood, which is the
      // only thing they want to check at this point.
      if (CODE) showRestored(d.code, d.address); else showCode(d.code, d.address);
    })
    .catch(function(e){ fail(e.message, CODE ? showRestore : function(){ showPassphrase(false); }); });
}

// --- Screen: the backup code ---------------------------------------------
function showCode(code, address){
  drawSteps(stepNames(false), 1);
  footer("");
  // The code is shown in two halves: the eye copies split text more
  // accurately, and the split is not part of the code.
  var m = Math.ceil(code.length / 2);
  $("card").innerHTML =
    '<div class="eyebrow">Step 2 of 3</div>'
  + '<h1>Write this down on paper</h1>'
  + '<p>It is the <strong>only</strong> way to recover your funds if this disk '
  + 'is lost. It will never be shown again.</p>'
  + '<div class="code" id="the-code">' + esc(code.slice(0, m)) + '<br>'
  + esc(code.slice(m)) + '</div>'
  + '<div class="note warn"><p><b>On paper, by hand, and nowhere else.</b> '
  + 'A file on this machine is lost with it, a file in the cloud can be read '
  + 'remotely, and the clipboard keeps a history — sometimes synced across '
  + 'your devices. Whoever holds this code holds the funds.</p></div>'
  + '<div class="actions"><button class="p" id="next">I\'ve written it down</button></div>';
  $("next").onclick = function(){ showVerify(code, address); };
}

// --- Screen: the wallet is restored --------------------------------------
//
// The code shown is the one the node decoded again. That it is identical to
// the one just typed is the proof, visible without any explanation, that the
// right seed was loaded.
function showRestored(code, address){
  drawSteps(stepNames(true), 2);
  footer("");
  var m = Math.ceil(code.length / 2);
  $("card").innerHTML =
    '<div class="eyebrow">Step 3 of 3</div>'
  + '<h1>Wallet restored</h1>'
  + '<p>The code was accepted and your seed is loaded. Check that this is '
  + 'yours:</p>'
  + '<div class="code">' + esc(code.slice(0, m)) + '<br>' + esc(code.slice(m)) + '</div>'
  + '<div class="note"><p><b>Your funds will reappear as the chain comes '
  + 'in.</b> The wallet derives your addresses again and finds what belongs to '
  + 'them — nothing is lost, but syncing has to finish first. On a long chain, '
  + 'allow a few minutes.</p></div>'
  + '<div class="actions"><button class="p" id="next">Open my wallet</button></div>';
  $("next").onclick = function(){ finish(address); };
}

// --- Screen: checking the copy -------------------------------------------
//
// Asking for the whole code to be typed again would be safer, and nobody would
// do it: they would select it on screen, paste it, and the check would have
// checked nothing. The last eight characters are enough to prove the sheet is
// in front of them, and can be typed again without weariness.
function showVerify(code, address){
  drawSteps(stepNames(false), 1);
  var n = 8, tail = code.slice(-n);
  $("card").innerHTML =
    '<div class="eyebrow">Step 2 of 3</div>'
  + '<h1>Let\'s check your copy</h1>'
  + '<p>Without looking at the screen: what are the <strong>last ' + n + ' '
  + 'characters</strong> of the code you just wrote down?</p>'
  + '<label for="v">The last ' + n + ' characters</label>'
  + '<div class="field"><input type="text" id="v" class="mono" autocomplete="off" '
  + 'autocapitalize="off" autocorrect="off" spellcheck="false" maxlength="' + n + '"></div>'
  + '<div class="verdict" id="said"></div>'
  + '<div class="actions">'
  + '<button class="s" id="again">Show the code again</button>'
  + '<button class="p" id="next" disabled>Finish</button></div>';
  var v = $("v");
  v.oninput = function(){
    var s = v.value.trim().toLowerCase();
    $("next").disabled = s !== tail.toLowerCase();
    $("said").textContent = s.length >= n && s !== tail.toLowerCase()
      ? "That is not the end of the code. Check it again." : "";
  };
  v.onkeydown = function(e){ if(e.key === "Enter" && !$("next").disabled) $("next").click(); };
  $("again").onclick = function(){ showCode(code, address); };
  $("next").onclick = function(){ finish(address); };
  v.focus();
}

// --- Screen: opening an existing wallet ----------------------------------
function showOpen(error){
  drawSteps(null);
  footer("Testnet — no Q21 here has any value");
  $("card").innerHTML =
    '<div class="eyebrow">Q21</div>'
  + '<h1>Open your wallet</h1>'
  + '<p>This wallet is encrypted. Your passphrase decrypts it on this '
  + 'machine — it is not sent anywhere.</p>'
  + (error ? '<div class="note bad"><p>' + esc(error) + '</p></div>' : '')
  + '<label for="p">Passphrase</label>'
  + '<div class="field">'
  + '<input type="password" id="p" autocomplete="off" autocapitalize="off" '
  + 'autocorrect="off" spellcheck="false">'
  + '<button class="reveal" id="reveal" type="button">show</button></div>'
  + '<div class="actions"><button class="p" id="next" disabled>Open</button></div>';
  var p = $("p");
  p.oninput = function(){ $("next").disabled = p.value.length === 0; };
  p.onkeydown = function(e){ if(e.key === "Enter" && !$("next").disabled) $("next").click(); };
  $("reveal").onclick = function(){
    p.type = p.type === "password" ? "text" : "password";
    $("reveal").textContent = p.type === "text" ? "hide" : "show";
  };
  $("next").onclick = function(){
    $("next").disabled = true;
    $("next").textContent = "Opening…";
    call("open", {passphrase: p.value})
      .then(function(d){ finish(d.address); })
      .catch(function(e){ showOpen(e.message); });
  };
  p.focus();
}

// --- Screen: ready -------------------------------------------------------
//
// The node is not listening yet: the setup server must first hand back
// control. So we poll its page until it answers, then go there. A fixed wait
// would always be too short on a busy machine.
function finish(address){
  drawSteps(stepNames(!!CODE), 2);
  footer("");
  $("card").innerHTML =
    '<div class="eyebrow">Step 3 of 3</div>'
  + '<h1>Your wallet is ready</h1>'
  + (address ? '<p class="tight">Your first receiving address:</p>'
             + '<div class="code">' + esc(address) + '</div>' : '')
  + '<div class="waiting"><span class="spinner"></span>'
  + '<span id="where">Starting the node…</span></div>';

  // The node has its own launch token, received through `status`: that is
  // what goes into the fragment, never the session token. The wallet page
  // will exchange it in turn, once.
  var target = "http://127.0.0.1:" + STATUS.node_port + "/wallet#" + STATUS.node_launch_token;

  // --- Why we do not poll the node directly.
  //
  // It listens on another port, hence on another origin. An ordinary request
  // would be refused there by the same-origin policy, and the refusal would
  // look the same as "not started yet". `no-cors` mode seemed to be the
  // answer: the response is opaque, but its arrival would prove that someone
  // is listening.
  //
  // Measured: it is **rejected anyway**. The browser refuses opaque responses
  // whose type is HTML — that is the protection called ORB, which stops a page
  // from reading a document from another origin. The poll therefore failed
  // forever while the node was answering `curl`.
  //
  // So we ask the setup server, which is on the same origin as this page, to
  // go and look for us. It is the one that attempts the connection.
  var tries = 0;
  (function poll(){
    tries++;
    call("node", {})
      .then(function(d){
        if(d.ready){ location.replace(target); return; }
        if(tries > 600){
          $("where").innerHTML = 'The node is taking a while. <a href="' + esc(target)
            + '">Open the wallet</a>';
          return;
        }
        setTimeout(poll, 200);
      })
      .catch(function(){
        // The setup server only stops once the node is up: no longer
        // reaching it therefore means the way is clear.
        location.replace(target);
      });
  })();

  call("start", {}).catch(function(){});
}

// --- Failure -------------------------------------------------------------
function fail(message, retry){
  drawSteps(null);
  $("card").innerHTML =
    '<div class="eyebrow">Q21</div>'
  + '<h1>That didn\'t work</h1>'
  + '<div class="note bad"><p>' + esc(message) + '</p></div>'
  + '<div class="actions"><button class="p" id="back">Try again</button></div>';
  $("back").onclick = retry;
}

// --- Startup -------------------------------------------------------------
function start(){
  call("status", {}).then(function(d){
    STATUS = d;
    if(d.wallet === "sealed") showOpen(null);
    else showWelcome();
  }).catch(function(e){
    fail("The program did not respond: " + e.message, start);
  });
}

function unusableLink(title, text){
  drawSteps(null);
  $("card").innerHTML =
    '<div class="eyebrow">Q21</div><h1>' + esc(title) + '</h1>'
  + '<p>' + esc(text) + ' Close this tab and start the wallet again.</p>';
}

if(!LAUNCH_TOKEN){
  unusableLink("Missing token",
    "This page opens from the program, with a token in the address.");
}else{
  // The launch token is good only once: if the exchange fails, this link has
  // already been used — or it has expired. Trying again would not help, so we
  // say so.
  exchange().then(start).catch(function(){
    unusableLink("This link has already been used",
      "The launch link works only once, and it has been used — or it has expired.");
  });
}
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    /// Extracts the `<script>` block, for the tests that are about the code.
    fn script() -> &'static str {
        let d = PAGE.find("<script>").expect("a script");
        let f = PAGE.find("</script>").expect("an end of script");
        &PAGE[d..f]
    }

    #[test]
    fn no_external_resource() {
        // The wallet's rule applies here, and more so: this page sees the
        // passphrase and the seed.
        for forbidden in ["http://", "https://", "//cdn", "src=\"//", "@import"] {
            let occurrences = PAGE.matches(forbidden).count();
            if forbidden == "http://" {
                // The only addresses allowed are loopback addresses built by
                // the script itself.
                assert!(
                    PAGE.matches("http://127.0.0.1:").count() == occurrences,
                    "an http address that is not the loopback"
                );
            } else {
                assert_eq!(occurrences, 0, "external resource: {forbidden}");
            }
        }
    }

    #[test]
    fn no_storage_that_outlives_the_tab() {
        // This page handles the passphrase and the seed. Nothing it touches
        // may be readable after the tab is closed.
        for forbidden in [
            "localStorage",
            "sessionStorage",
            "document.cookie",
            "indexedDB",
        ] {
            assert!(
                !script().contains(forbidden),
                "{forbidden} has no business in the setup page"
            );
        }
    }

    #[test]
    fn the_token_is_erased_from_the_address_bar() {
        assert!(script().contains("history.replaceState"));
        assert!(script().contains("location.hash"));
    }

    #[test]
    fn the_passphrase_never_goes_into_an_address() {
        // It may only travel in a POST body. A passphrase in a request URL
        // ends up in the browser history and in the logs.
        assert!(script().contains("method: \"POST\""));
        for forbidden in [
            "?passphrase=",
            "passphrase=\" +",
            "+ passphrase",
            "+ PASSPHRASE",
            "encodeURIComponent(p",
        ] {
            assert!(
                !script().contains(forbidden),
                "passphrase in an address: {forbidden}"
            );
        }
    }

    #[test]
    fn secret_fields_refuse_autofill() {
        // Without this, the browser's password manager offers to save the
        // wallet passphrase.
        let password_fields = script().matches("type=\"password\"").count();
        assert!(password_fields >= 3, "at least three passphrase fields");
        // Every **free-text** field carries autocomplete="off". Checkboxes are
        // excluded: they carry no secret, and the password manager takes no
        // interest in them.
        let fields = script().matches("<input type=\"password\"").count()
            + script().matches("<input type=\"text\"").count()
            + script().matches("<textarea id=").count();
        let without_autofill = script().matches("autocomplete=\"off\"").count();
        assert!(
            fields >= 5,
            "the field count dropped to {fields}: the test no longer checks anything"
        );
        assert!(
            without_autofill >= fields,
            "{without_autofill} autocomplete=off for {fields} input fields"
        );
    }

    #[test]
    fn the_backup_code_is_confirmed_before_moving_on() {
        // Showing the code and then moving on with one click proves nothing. A
        // check exists, and the final button depends on it.
        assert!(script().contains("function showVerify"));
        assert!(script().contains("code.slice(-n)"));
    }

    /// The backup code never goes to the clipboard.
    ///
    /// A "Copy" button used to put it there, with the advice to clear it
    /// afterwards. Clearing the current clipboard removes nothing from its
    /// history — Win+V, Klipper, Apple's Universal Clipboard — nor from what
    /// Windows' "cloud clipboard" has already synced. The page says "on
    /// paper"; a button that contradicted it no longer exists.
    #[test]
    fn the_backup_code_does_not_go_through_the_clipboard() {
        assert!(
            !PAGE.contains("clipboard."),
            "the page writes to the clipboard"
        );
        assert!(!PAGE.contains("navigator.clipboard"));
        assert!(!PAGE.contains("execCommand"), "copy through the old API");
        // And the instruction stays: on paper, and nothing else.
        assert!(script().contains("On paper"));
        assert!(script().contains("the clipboard keeps a history"));
    }

    /// The fragment carries a launch token, exchanged once for the session
    /// token.
    ///
    /// The address opened by the launcher goes through the browser's command
    /// line; what it carries must be good only once. The page calls nothing
    /// before the exchange, and sends the user on to the node with the node's
    /// launch token, never with the session token.
    #[test]
    fn the_fragment_is_a_launch_token_exchanged_before_any_call() {
        let s = script();
        assert!(
            s.contains("LAUNCH_TOKEN = f;"),
            "the fragment must be read as a launch token"
        );
        assert!(
            !s.contains(" TOKEN = f;"),
            "the fragment must no longer be the session token"
        );
        assert!(s.contains("fetch(\"/session\""));
        assert!(s.contains("exchange().then(start)"));
        assert!(s.contains("/wallet#\" + STATUS.node_launch_token"));
        assert!(!s.contains("/wallet#\" + TOKEN"));
    }

    #[test]
    fn choosing_no_protection_is_explicit() {
        // A wallet without a passphrase writes the seed unencrypted. That is
        // not an oversight: a box saying so has to be checked.
        assert!(script().contains("function showNoPassphrase"));
        assert!(script().contains("understood"));
        assert!(script().contains("unencrypted"));
    }

    #[test]
    fn everything_from_the_node_is_escaped() {
        // Error messages, the code and the address go through `esc`.
        for raw in [
            "esc(message)",
            "esc(code.slice",
            "esc(address)",
            "esc(error)",
        ] {
            assert!(script().contains(raw), "not escaped: {raw}");
        }
    }

    #[test]
    fn the_dark_theme_is_provided() {
        assert!(PAGE.contains(":root{"));
        assert!(PAGE.contains("@media (prefers-color-scheme: dark)"));
    }

    #[test]
    fn motion_can_be_turned_off() {
        assert!(PAGE.contains("prefers-reduced-motion"));
    }

    /// The page is written in English, end to end.
    ///
    /// It has no translation table: it is shown once, before the wallet
    /// exists, and only in English. Any accented letter in the page is
    /// therefore a leftover of an untranslated text.
    #[test]
    fn the_page_is_in_english() {
        assert!(PAGE.contains(r#"<html lang="en">"#));
        assert!(
            PAGE.chars().all(|c| c.is_ascii() || "—…✓".contains(c)),
            "non-ASCII text left in the setup page"
        );
        for phrase in [
            "Create a wallet",
            "I already have a backup code",
            "Choose a passphrase",
            "Write this down on paper",
            "Your wallet is ready",
        ] {
            assert!(PAGE.contains(phrase), "missing: {phrase}");
        }
    }
}
