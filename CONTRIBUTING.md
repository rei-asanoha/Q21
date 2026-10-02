# Contributing to Q21

## Language: American English, everywhere

Everything published in this repository is written in **American English**:

- code identifiers, comments and doc comments;
- program output, error messages, logs and help text;
- test names and test messages;
- documentation, file and directory names;
- commit messages, tag and release titles and notes;
- workflow, job, step and artifact names.

Use American spelling (*optimize*, *behavior*, *center*, *license*, *defense*,
*analyze*) and keep the existing terminology: node, peer, bootstrap node,
address book, wallet, seed, backup code, passphrase, mempool, tip, reorg,
rolling finality, state commitment.

There are two kinds of exceptions, and only two:

1. **Translations of the web pages.** The wallet and explorer pages are written
   in English and carry French and Japanese translation tables
   (`src/wallet_ui.rs`, `src/explorer.rs`).
2. **Legacy names read by the migration of 0.3.x data directories**
   (`src/legacy.rs`, `tests/upgrade_from_0_3.rs` and the mapping tables of
   `UPGRADING.md`). They must keep their exact historical spelling, or
   existing installations would lose their settings and wallets. No other
   file may spell them: code refers to the constants of `src/legacy.rs`.

`tests/english_only.rs` enforces this policy on every build. If it fails, fix
the text rather than extend the list of exceptions; an exception needs a reason
as strong as the two above.

## Before you open a pull request

```bash
cargo fmt --check
RUSTFLAGS="-D warnings" cargo clippy --locked --all-targets --features audit
cargo test --locked --features audit
```

Consensus code changes need a test that fails before the change and passes
after it. Security reports go to the repository's Issues, as described at the
end of README.md.
