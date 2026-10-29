# Security policy

Q21 is research code on a public **testnet**: its coins have no value, and
the binary refuses to start a mainnet. A flaw found now costs nobody money.
It also means a flaw reported now is the most useful kind: it gets fixed
before anything of value depends on the code.

## Reporting a flaw — privately

Use GitHub's private vulnerability reporting:

**<https://github.com/rei-asanoha/Q21/security/advisories/new>**

(Repository page → *Security* tab → *Report a vulnerability*.) Only the
maintainers see the report. Please do **not** open a public issue, a pull
request or a discussion for a flaw that could be used against running
nodes or wallets before it is fixed.

There is no email address and no other private channel. If the link above
does not work for you, open a public issue that says only "I have a security
report, please enable private reporting" — with no detail.

### What helps

- what is affected: the node, the wallet, the channels, the release process;
- the version (`q21 version`) or the commit;
- the steps, ideally a test or a script against a **local regtest** node;
- what you think the impact is.

Reports in English, please. A rough report is better than no report.

## What happens next

- **Acknowledgment** within 7 days. Q21 has very few maintainers; if you hear
  nothing after 7 days, send a short public issue asking for a look at the
  private report, with no detail.
- **Assessment and fix**: a fix, a regression test that carries your finding,
  and a release. Most past findings were fixed within days; a change of
  consensus rules takes longer, because it must be scheduled at a block
  height every node knows in advance.
- **Disclosure**: coordinated. The advisory is published once a fixed release
  is out, or after **90 days** at most, whichever comes first, unless we agree
  otherwise. You are credited by the name you choose, or not at all.

There is no bounty, no contract and no legal threat: only an answer, a fix,
and your finding kept as a test.

## Research ground rules

Test against your own nodes: a local `regtest`, or nodes you run on the
testnet. Do not attack nodes, servers or wallets that are not yours — the
testnet entry points included — and do not try to identify the people
behind them. Everything a test needs runs on one machine; see
`tests/` and the `RED-TEAM-*.md` campaigns for examples.

## Supported versions

Only the latest release. Fixes are not backported: the upgrade is the fix.
`UPGRADING.md` says what each upgrade asks of an operator.

## If the release signing key is ever compromised

Releases are signed offline with the key in `q21-release.pub`
(see `SIGNING.md`). If that key is lost or exposed:

1. A public issue and the README say so at once, with the date from which no
   signature by that key should be trusted, and the last release known good.
2. A new key is created offline. Its public half is published in the
   repository **and** through the channels listed in `SIGNING.md`, section 1,
   so that nobody has to take the repository's word for it alone.
3. Releases are signed again with the new key. Independent attestations
   (`attestations/`) of the binary hashes remain valid: they never depended
   on the release key.

Until then, the check that needs no key at all still works: rebuild the
binary yourself (`REPRODUCING.md`) and compare its hash.
