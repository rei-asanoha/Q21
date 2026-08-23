# ML-DSA — comment il a été branché, et ce qu'il reste

## Le problème, tel qu'il était

L'environnement de développement a une liste blanche réseau qui ne contient pas
`index.crates.io` :

```
error: failed to get successful HTTP response from
       `https://index.crates.io/config.json`, got 403
       Host not in allowlist: index.crates.io.
```

Conséquence : l'adaptateur ML-DSA de `src/sig.rs` avait été écrit **sans avoir
jamais vu l'API réelle du crate**. C'était la seule partie du projet dont on ne
pouvait rien affirmer.

## Comment il a été résolu

Les sources ont été apportées depuis une machine connectée, en trois commandes :

```bash
mkdir q21-deps && cd q21-deps
cargo init --name q21-deps
cargo add ml-dsa
cargo vendor vendor-q21
```

L'archive a été extraite dans `vendor/`, et `.cargo/config.toml` redirige
`crates.io` vers ce répertoire :

```toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
```

Cargo vérifie les `.cargo-checksum.json` à chaque compilation : les sources ne
peuvent pas être modifiées en silence. La compilation est entièrement hors
ligne.

```bash
cargo test --features mldsa --offline
```

## Ce que l'API réelle a démenti

| supposé | réel |
|---|---|
| `signature` 2.x | **3.0.0** — génération de traits différente |
| `rand_core` avec feature `os_rng` | **0.10.1**, où cette feature n'existe plus |
| `Signature::decode(sig.try_into()?)` | `Signature::<P>::try_from(&[u8])` |
| `VerifyingKey::decode` faillible | **infaillible** — elle rend `Self` |

Le dernier point est le seul qui touche au consensus. Toute suite de 1952 octets
se décode en *une* clé ML-DSA-65 : une clé publique n'est jamais « invalide »,
elle est seulement bien ou mal formée en longueur. Q21 n'ajoute donc aucun rejet
supplémentaire — ce serait une règle de consensus que les autres
implémentations n'auraient pas, et une chaîne qui se scinde le jour où quelqu'un
en écrit une seconde.

## Ce qui est mesuré, et non plus annoncé

- clés et signatures : 1952 / 3309 (ML-DSA-65), 2592 / 4627 (ML-DSA-87) ;
- la clé dérivée de la graine `00 01 … 1f` est comparée octet pour octet au
  fichier PKCS#8 publié par RustCrypto ;
- un bit modifié dans la signature — début, milieu, fin — l'invalide ;
- une transaction ML-DSA passe le même `validate::check_transaction` que les
  autres, et un témoin falsifié y est refusé ;
- vérification : ~5 200/s (ML-DSA-65) et ~3 300/s (ML-DSA-87) sur un cœur.

## Ce qui reste ouvert, et compte davantage

**La cryptanalyse de la preuve de travail.** `memhard.rs` n'a reçu aucune
relecture externe. Sa première version affichait un rapport de 1,63× — la
promesse anti-ASIC était vide, et seule la mesure l'a révélé. La version
actuelle affiche 6,46×, mais aucune mesure faite par son auteur ne vaut une
relecture par quelqu'un dont le métier est de casser ces fonctions.

**La mesure sur 2 Gio.** Le verdict anti-ASIC se rendra sur la vraie table du
réseau principal, contre une implémentation optimisée — pas sur les 32 Mio du
testnet. C'est la phase 6.

**Les canaux auxiliaires de `ml-dsa` 0.1.1.** Le crate passe les vecteurs de
référence, mais c'est une version 0.x sans audit public de son comportement en
temps constant. Q21 limite l'exposition en ne compilant la signature que dans le
portefeuille : un nœud ne fait que vérifier, et vérifier ne manipule aucun
secret. Cela réduit le risque, cela ne l'annule pas.

Si vous connaissez quelqu'un dans ces trois domaines, leur avis vaudra plus que
tout ce qui peut encore être ajouté en code.

## Note sur l'archive livrée

L'archive `q21-phase5-mldsa.zip` **ne contient ni `vendor/` ni
`.cargo/config.toml`**. Ces deux éléments n'existent que pour permettre la
compilation hors ligne côté développement. Sur une machine ayant accès à
crates.io, il n'y a rien à configurer :

```bash
cargo test  --features mldsa
cargo build --release --features mldsa
```

Cargo télécharge `ml-dsa` 0.1.1 et ses dépendances lui-même.
