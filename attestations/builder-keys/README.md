# Builder public keys

One file per person who has rebuilt Q21 and filed at least one attestation:

```
<pseudonym>.pub
```

The content is a `minisign` public key — two lines, the second of which is
56 characters long:

```
untrusted comment: minisign public key 8F2A1C...
RWQf6lcT0yJ0Zm9uZGF0aW9uIHBvdXIgbGEgZGVtb25zdHJhdGlvbiBzZXVsZQ==
```

A **GPG** key is accepted instead (`<pseudonym>.gpg`, ASCII armor) if that is
the tool you already use; in that case the signature of your `SHA256SUMS` is
a detached `.asc` file. `minisign` is preferred because it fits in a single
executable and requires no infrastructure, but what matters is that the
result can be checked, not which tool was used.

---

## What filing a key here does not give you

No rights. Not publishing, not merging, not deciding, not voting. A key filed
here serves only to make it possible to see that the same person attests
several versions in a row — that is, to give meaning to the sentence "three
independent builders obtained the same hash".

There is no trusted key, no master key and no alert key in Q21, and there
never will be. See SUCCESSION.md.

---

## Changing or revoking your key

File the new key under a name that states the transition
(`<pseudonym>-2.pub`) and leave the old one in place: the attestations
already filed were signed with it and must remain verifiable. Deleting an
old key would make past attestations unverifiable, which is exactly the
opposite of the goal.

If your secret key is lost or compromised, say so in a public issue on the
repository, with the date from which it should no longer be trusted. A
`<pseudonym>-revoked.txt` file filed here, signed by the new key, makes the
declaration durable.

---

## Full procedure

See `../README.md`, section 3.
