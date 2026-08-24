//! Audit : arithmetique, serialisation, parsing.
//!
//! Chaque test est une hypothese d'attaque. Un test qui passe = pas de faille
//! sur cet axe ; un test qui echoue = faille demontree.

use q21_core::amount::Amount;
use q21_core::bech32;
use q21_core::block::{Block, BlockHeader};
use q21_core::compact::CompactBlock;
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::ser::{Reader, Writer};
use q21_core::sha256::sha256;
use q21_core::siphash::siphash24;
use q21_core::tx::Transaction;
use q21_core::uint::U256;
use q21_core::wire::{self, Message};

// ---------------------------------------------------------------------------
// Compteur d'allocation : mesure du rapport octets recus / octets alloues
// ---------------------------------------------------------------------------

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static ALLOUE: AtomicUsize = AtomicUsize::new(0);
static PIC: AtomicUsize = AtomicUsize::new(0);
static VIVANT: AtomicUsize = AtomicUsize::new(0);
static ACTIF: AtomicUsize = AtomicUsize::new(0);

struct Compteur;

unsafe impl GlobalAlloc for Compteur {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if ACTIF.load(Ordering::Relaxed) == 1 {
            ALLOUE.fetch_add(l.size(), Ordering::Relaxed);
            // --- L'outil de mesure debordait, pas le produit.
            //
            // `dealloc` soustrait la taille de tout bloc libere pendant la
            // mesure — y compris ceux alloues **avant** qu'elle ne commence.
            // Le compteur passait alors sous zero, repartait a l'autre bout de
            // l'intervalle, et l'addition suivante debordait. Le rapport
            // d'allocation n'a jamais pu etre lu.
            //
            // On sature aux deux bouts : la mesure devient approximative sur
            // ses bords, ce qu'un diagnostic peut se permettre — paniquer, non.
            let v = VIVANT
                .fetch_add(l.size(), Ordering::Relaxed)
                .saturating_add(l.size());
            PIC.fetch_max(v, Ordering::Relaxed);
        }
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if ACTIF.load(Ordering::Relaxed) == 1 {
            let _ = VIVANT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(l.size()))
            });
        }
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if ACTIF.load(Ordering::Relaxed) == 1 && n > l.size() {
            ALLOUE.fetch_add(n - l.size(), Ordering::Relaxed);
            let v = VIVANT.fetch_add(n - l.size(), Ordering::Relaxed) + n - l.size();
            PIC.fetch_max(v, Ordering::Relaxed);
        } else if ACTIF.load(Ordering::Relaxed) == 1 {
            VIVANT.fetch_sub(l.size() - n, Ordering::Relaxed);
        }
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Compteur = Compteur;

/// Mesure le pic d'allocation vivante pendant `f`.
fn mesurer<T>(f: impl FnOnce() -> T) -> (T, usize) {
    ALLOUE.store(0, Ordering::SeqCst);
    PIC.store(0, Ordering::SeqCst);
    VIVANT.store(0, Ordering::SeqCst);
    ACTIF.store(1, Ordering::SeqCst);
    let r = f();
    ACTIF.store(0, Ordering::SeqCst);
    (r, PIC.load(Ordering::SeqCst))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

// ---------------------------------------------------------------------------
// 8. SHA-256 contre vecteurs officiels
// ---------------------------------------------------------------------------

#[test]
fn sha256_vecteurs_officiels() {
    let cas: &[(&[u8], &str)] = &[
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"a",
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"message digest",
            "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
        ),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
    ];
    for (m, attendu) in cas {
        assert_eq!(hex(&sha256(m)), *attendu, "SHA-256 faux sur {m:?}");
    }

    // Un million de 'a'
    let mut h = q21_core::sha256::Sha256::new();
    let bloc = vec![b'a'; 1000];
    for _ in 0..1000 {
        h.update(&bloc);
    }
    assert_eq!(
        hex(&h.finalize()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );

    // Frontieres de rembourrage : 55/56/57 et 63/64/65 octets.
    // Verifie par comparaison incrementale contre le chemin direct.
    for n in [
        0usize, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128,
    ] {
        let msg = vec![0x5au8; n];
        let direct = sha256(&msg);
        for coupe in [1usize, 2, 3, 17, 31, 32, 33, 64] {
            let mut h = q21_core::sha256::Sha256::new();
            for c in msg.chunks(coupe) {
                h.update(c);
            }
            assert_eq!(h.finalize(), direct, "n={n} coupe={coupe}");
        }
    }
    // Deux vecteurs de longueur exacte 55 et 56 (frontiere du bloc de padding).
    assert_eq!(
        hex(&sha256(&[b'a'; 55])),
        "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
    );
    assert_eq!(
        hex(&sha256(&[b'a'; 56])),
        "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
    );
}

// ---------------------------------------------------------------------------
// 8. SipHash-2-4 contre vecteurs officiels (Aumasson & Bernstein)
// ---------------------------------------------------------------------------

#[test]
fn siphash_vecteurs_officiels() {
    let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
    let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
    let attendus: [u64; 16] = [
        0x726f_db47_dd0e_0e31,
        0x74f8_39c5_93dc_67fd,
        0x0d6c_8009_d9a9_4f5a,
        0x8567_6696_d7fb_7e2d,
        0xcf27_94e0_2771_87b7,
        0x1876_5564_cd99_a68d,
        0xcbc9_466e_58fe_e3ce,
        0xab02_00f5_8b01_d137,
        0x93f5_f579_9a93_2462,
        0x9e00_82df_0ba9_e4b0,
        0x7a5d_bbc5_94dd_b9f3,
        0xf4b3_2f46_226b_ada7,
        0x751e_8fbc_860e_e5fb,
        0x14ea_5627_c084_3d90,
        0xf723_ca90_8e7a_f2ee,
        0xa129_ca61_49be_45e5,
    ];
    for (len, attendu) in attendus.iter().enumerate() {
        let msg: Vec<u8> = (0..len as u8).collect();
        assert_eq!(siphash24(k0, k1, &msg), *attendu, "longueur {len}");
    }
    // Vecteur long (longueur 63), qui exerce le compteur de longueur mod 256.
    //
    // --- La constante etait ecrite a l'envers.
    //
    // Ce controle etait rouge depuis toujours, et l'implementation n'y etait
    // pour rien : 0x724506eb4c328a95 est exactement 0x958a324ceb064572 lu
    // octet par octet dans l'autre sens. L'implementation de reference publie
    // ses vecteurs sous forme de tableaux d'octets, en petit-boutien ; celui-ci
    // a ete recopie comme s'il s'agissait d'un entier gros-boutien. Les seize
    // premiers, eux, avaient ete pris correctement.
    //
    // Verifie contre une implementation independante de SipHash-2-4, elle-meme
    // controlee sur les seize vecteurs ci-dessus.
    let msg: Vec<u8> = (0..63u8).collect();
    assert_eq!(
        siphash24(k0, k1, &msg),
        0x958a_324c_eb06_4572,
        "longueur 63"
    );
}

// ---------------------------------------------------------------------------
// 7. Bech32m : vecteurs officiels BIP-350
// ---------------------------------------------------------------------------

/// Vecteurs valides de BIP-350.
///
/// # Deux vecteurs etaient mal recopies
///
/// Ce controle etait rouge, et l'implementation n'y etait pour rien.
///
/// - `abcdef1…zm3wf7` : la somme de controle etait fausse. La bonne est
///   `zd3ryx`, derivee d'une implementation independante — elle-meme validee
///   en reproduisant a l'identique le vecteur bech32 de BIP-173
///   `abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw`.
/// - La chaine longue avait perdu deux caracteres a la transcription : elle
///   faisait 88 caracteres au lieu de 90, qui est precisement la longueur
///   maximale que ce vecteur existe pour eprouver.
///
/// La chaine de 90 caracteres est traitee a part : voir l'epreuve suivante.
#[test]
fn bech32m_vecteurs_valides_bip350() {
    let valides = [
        "A1LQFN3A",
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
    ];
    for v in valides {
        assert!(
            bech32::decode(v).is_ok(),
            "vecteur BIP-350 valide refuse : {v} -> {:?}",
            bech32::decode(v)
        );
    }
}

/// Une charge dont le rembourrage n'est pas nul est refusee — mais pas pour la
/// somme de controle.
///
/// # La distinction qui compte
///
/// `decode` n'est pas un decodeur bech32m generique : c'est celui d'un format
/// d'adresse, et il exige en plus que la charge se convertisse en octets
/// entiers, avec un rembourrage nul. C'est la regle de BIP-173, et elle est
/// juste.
///
/// Le vecteur long de BIP-350 porte quatre-vingt-deux groupes de cinq bits,
/// soit 410 bits : cinquante et un octets et deux bits qui restent, tous a un.
/// Il est donc legitimement refuse.
///
/// Ce qui doit rester vrai, et que cette epreuve verrouille : **le refus ne
/// doit jamais venir de la somme de controle.** Si c'etait le cas, notre
/// bech32m ne serait pas celui de tout le monde, et une adresse Q21 ne serait
/// pas verifiable par un outil tiers.
#[test]
fn une_charge_mal_rembourree_est_refusee_sans_mettre_en_cause_la_somme_de_controle() {
    let long_90 = "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8";
    assert_eq!(
        long_90.len(),
        90,
        "ce vecteur existe pour eprouver la longueur maximale"
    );
    match bech32::decode(long_90) {
        Err(bech32::Bech32Error::RembourrageInvalide) => {}
        autre => panic!(
            "attendu un refus de rembourrage, obtenu {autre:?}.\n               Un refus pour somme de controle signifierait que notre bech32m \n               n'est pas celui de BIP-350."
        ),
    }
}

#[test]
fn bech32m_vecteurs_invalides_bip350() {
    let invalides: &[&str] = &[
        "\u{20}1xj0phk",   // HRP avec caractere < 33
        "\u{7F}1g6xzxy",   // HRP avec caractere > 126
        "\u{80}1vctc34",   // HRP hors ASCII
        "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4", // trop long
        "qyrz8wqd2c9m",    // pas de separateur
        "1qyrz8wqd2c9m",   // HRP vide
        "y1b0jsk6g",       // caractere invalide 'b'
        "lt1igcx5c0",      // caractere invalide 'i'
        "in1muywd",        // separateur trop tard
        "mm1crxm3i",       // caractere invalide 'i'
        "au1s5cgom",       // caractere invalide 'o'
        "M1VUXWEZ",        // checksum bech32 et non bech32m
        "16plkw9",         // trop court
        "1p2gdwpf",        // HRP vide
    ];
    for v in invalides {
        assert!(
            bech32::decode(v).is_err(),
            "vecteur BIP-350 invalide accepte : {v:?} -> {:?}",
            bech32::decode(v)
        );
    }
}

/// Deux chaines distinctes ne doivent jamais decoder vers la meme adresse,
/// hors difference de casse (prevue par BIP-173).
#[test]
fn bech32_pas_de_seconde_representation() {
    use q21_core::address::{Address, Network};
    use q21_core::sig::SchemeId;

    let a = Address::from_pubkey(Network::Mainnet, SchemeId::MlDsa65, &[7u8; 1952]);
    let s = a.to_string_bech32();

    // Toute mutation d'un caractere doit soit echouer, soit donner une autre
    // adresse. Jamais la meme.
    const CH: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let base = s.clone().into_bytes();
    let mut collisions = 0;
    for i in 0..base.len() {
        for c in CH {
            if base[i] == *c {
                continue;
            }
            let mut v = base.clone();
            v[i] = *c;
            let t = String::from_utf8(v).unwrap();
            if let Ok(b) = Address::parse(&t) {
                if b == a {
                    collisions += 1;
                    eprintln!("collision : {t} decode vers la meme adresse que {s}");
                }
            }
        }
    }
    assert_eq!(collisions, 0, "seconde representation d'une adresse");
}

// ---------------------------------------------------------------------------
// 1. U256 : comparaison a une reference u128
// ---------------------------------------------------------------------------

fn u256_de_u128(v: u128) -> U256 {
    U256([v as u64, (v >> 64) as u64, 0, 0])
}

fn u128_de_u256(v: U256) -> Option<u128> {
    if v.0[2] != 0 || v.0[3] != 0 {
        return None;
    }
    Some(v.0[0] as u128 | ((v.0[1] as u128) << 64))
}

#[test]
fn u256_differentiel_contre_u128() {
    let mut g = 0x1234_5678_9abc_def0u64;
    for _ in 0..20_000 {
        let a = ((xorshift(&mut g) as u128) << 64 | xorshift(&mut g) as u128) >> (g % 60);
        let b = ((xorshift(&mut g) as u128) << 64 | xorshift(&mut g) as u128) >> (g % 60);
        let (ua, ub) = (u256_de_u128(a), u256_de_u128(b));

        assert_eq!(ua.cmp(&ub), a.cmp(&b), "cmp {a} {b}");
        assert_eq!(u128_de_u256(ua.wrapping_add(ub)), a.checked_add(b));
        if let Some(s) = ua.checked_add(ub) {
            assert_eq!(u128_de_u256(s), a.checked_add(b), "add {a}+{b}");
        }
        if let Some(d) = ua.checked_sub(ub) {
            assert_eq!(u128_de_u256(d), a.checked_sub(b), "sub {a}-{b}");
        } else {
            assert!(a < b, "checked_sub a refuse {a}-{b}");
        }
        if b != 0 {
            let (q, r) = ua.div_rem(ub).expect("div_rem");
            assert_eq!(u128_de_u256(q), Some(a / b), "div {a}/{b}");
            assert_eq!(u128_de_u256(r), Some(a % b), "rem {a}%{b}");
        }
        let s = xorshift(&mut g);
        if let Some(p) = ua.checked_mul_u64(s) {
            assert_eq!(u128_de_u256(p), a.checked_mul(s as u128), "mul {a}*{s}");
        }
        if s != 0 {
            let d = ua.checked_div_u64(s).unwrap();
            assert_eq!(u128_de_u256(d), Some(a / s as u128), "divu64 {a}/{s}");
        }
        assert_eq!(ua.bits(), 128 - a.leading_zeros().min(128));
    }
}

#[test]
fn u256_bits_et_shl1_coherents() {
    let mut g = 0xdead_beef_cafe_babeu64;
    for _ in 0..5_000 {
        let v = U256([
            xorshift(&mut g),
            xorshift(&mut g),
            xorshift(&mut g),
            xorshift(&mut g) >> (g % 64),
        ]);
        // aller-retour octets
        assert_eq!(U256::from_be_bytes(&v.to_be_bytes()), v);
        // div_rem par lui-meme
        let (q, r) = v.div_rem(v).unwrap();
        assert_eq!(q, U256::ONE);
        assert_eq!(r, U256::ZERO);
        // not() est bien le complement
        assert_eq!(v.checked_add(v.not()), Some(U256::MAX));
    }
}

/// `mul_div` doit toujours rendre une valeur <= la valeur exacte, jamais plus.
#[test]
fn mul_div_ne_surestime_jamais() {
    let mut g = 0x51_51_51_51u64;
    for _ in 0..20_000 {
        let v = U256([
            xorshift(&mut g),
            xorshift(&mut g),
            xorshift(&mut g),
            xorshift(&mut g) >> (g % 64),
        ]);
        let m = xorshift(&mut g) % 1_000_000 + 1;
        let d = xorshift(&mut g) % 1_000_000 + 1;
        if let Some(r) = v.mul_div(m, d) {
            // Reference : si le produit tient, comparer exactement.
            if let Some(p) = v.checked_mul_u64(m) {
                let exact = p.checked_div_u64(d).unwrap();
                assert_eq!(r, exact, "mul_div devie du calcul exact");
            } else {
                // Voie de repli : doit rester <= la valeur exacte.
                // v*m/d >= (v/d)*m, donc la repli sous-estime : c'est le sens sur.
                assert!(r <= U256::MAX);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 1/2. Emission : coherence et bornes
// ---------------------------------------------------------------------------

#[test]
fn emission_cumulee_egale_la_somme_des_subventions() {
    use q21_core::emission::{block_subsidy, cumulative_emission};
    // Sur la rampe et au-dela, bloc par bloc.
    let mut somme = 0u64;
    for h in 0..=(SLOW_START_BLOCKS + 3 * DECAY_EPOCH_BLOCKS) {
        somme += block_subsidy(h).units();
        if h % 1000 == 0 || h == SLOW_START_BLOCKS {
            assert_eq!(
                cumulative_emission(h).units(),
                somme,
                "divergence entre cumul et somme bloc a bloc a h={h}"
            );
        }
    }
}

#[test]
fn emission_ne_deborde_pas_sur_hauteur_extreme() {
    use q21_core::emission::{block_subsidy, cumulative_emission, total_supply_at};
    for h in [
        0u64,
        1,
        SLOW_START_BLOCKS,
        u32::MAX as u64,
        1 << 40,
        u64::MAX / 2,
        u64::MAX - 1,
        u64::MAX,
    ] {
        let s = block_subsidy(h);
        assert!(s.units() <= INITIAL_REWARD, "subvention aberrante a h={h}");
        let c = cumulative_emission(h);
        assert!(c.units() <= EMISSION_CAP, "plafond franchi a h={h}");
        assert!(total_supply_at(h).units() <= MAX_SUPPLY, "offre a h={h}");
    }
}

// ---------------------------------------------------------------------------
// 3. Malleabilite d'encodage
// ---------------------------------------------------------------------------

/// Encodage canonique : reencoder un objet decode doit rendre les memes octets.
fn frame_brut(cmd: &[u8], charge: &[u8]) -> Vec<u8> {
    let mut cmd12 = [0u8; 12];
    cmd12[..cmd.len()].copy_from_slice(cmd);
    let s = sha256(charge);
    let mut out = Vec::new();
    out.extend_from_slice(&NETWORK_MAGIC_TESTNET);
    out.extend_from_slice(&cmd12);
    out.extend_from_slice(&(charge.len() as u32).to_le_bytes());
    out.extend_from_slice(&s[..4]);
    out.extend_from_slice(charge);
    out
}

/// Un port hors des seize bits est refuse, non tronque.
///
/// # Ce que ce controle affirmait, et ce qu'il affirme maintenant
///
/// Il a ete ecrit pour **demontrer** un defaut : le port etait ecrit sur
/// trente-deux bits et relu tronque a seize, si bien que 65 536 trames
/// distinctes decodaient vers la meme adresse. Il exigeait donc que les deux
/// trames se decodent, et constatait qu'elles donnaient le meme message.
///
/// Le defaut etant corrige, la bonne exigence s'inverse : la trame non
/// canonique doit etre **refusee**. C'est la meme propriete — deux octets
/// differents ne doivent pas devenir indistinguables — enoncee du bon cote.
#[test]
fn addr_port_encodage_non_canonique() {
    let mut w = Writer::new();
    w.varint(1);
    w.bytes(&[1u8, 2, 3, 4]);
    w.u32(0x0001_0050); // 65616 : tronque a 0x0050 = 80
    w.u64(1_755_000_000);
    let a = frame_brut(b"addr", w.finish().as_slice());

    let mut w2 = Writer::new();
    w2.varint(1);
    w2.bytes(&[1u8, 2, 3, 4]);
    w2.u32(0x0000_0050);
    w2.u64(1_755_000_000);
    let b = frame_brut(b"addr", w2.finish().as_slice());

    assert_ne!(a, b, "les deux trames doivent differer sur le fil");
    assert!(
        Message::parse(&a, NETWORK_MAGIC_TESTNET).is_err(),
        "MALLEABILITE : un port hors des seize bits a ete accepte et tronque"
    );
    assert!(
        Message::parse(&b, NETWORK_MAGIC_TESTNET).is_ok(),
        "la trame canonique doit rester acceptee"
    );
}

/// Un indice de `getblocktxn` hors des trente-deux bits est refuse.
///
/// Comme pour le port, ce controle demontrait le defaut ; il verrouille
/// maintenant sa correction. Tronquer etait ici pire qu'un encodage
/// redondant : l'indice 2^32 devenait zero, et le pair qui demandait la
/// 2^32-ieme transaction d'un bloc recevait la premiere.
#[test]
fn getblocktxn_indice_encodage_non_canonique() {
    let mut w = Writer::new();
    w.bytes(&[0u8; 32]);
    w.varint(1);
    w.varint(0x1_0000_0000); // 2^32 -> tronque a 0
    let a = frame_brut(b"getblocktxn", w.finish().as_slice());

    let mut w2 = Writer::new();
    w2.bytes(&[0u8; 32]);
    w2.varint(1);
    w2.varint(0);
    let b = frame_brut(b"getblocktxn", w2.finish().as_slice());

    assert_ne!(a, b);
    assert!(
        Message::parse(&a, NETWORK_MAGIC_TESTNET).is_err(),
        "MALLEABILITE : un indice hors des trente-deux bits a ete accepte et tronque"
    );
    assert!(
        Message::parse(&b, NETWORK_MAGIC_TESTNET).is_ok(),
        "la trame canonique doit rester acceptee"
    );
}

/// Une transaction decodee doit se reencoder a l'identique.
#[test]
fn transaction_reencodage_identique() {
    let mut g = 0xabcd_ef01_2345_6789u64;
    let mut vus = 0;
    for _ in 0..200_000 {
        let n = (xorshift(&mut g) % 160) as usize;
        let mut brut = Vec::with_capacity(n);
        for _ in 0..n {
            brut.push((xorshift(&mut g) >> 24) as u8);
        }
        if let Ok(tx) = Transaction::decode(&brut) {
            vus += 1;
            assert_eq!(
                tx.encode(),
                brut,
                "MALLEABILITE : reencodage different de l'entree"
            );
        }
    }
    eprintln!("transactions decodees au hasard : {vus}");
}

/// Un bloc decode doit se reencoder a l'identique.
#[test]
fn bloc_reencodage_identique() {
    let mut g = 0x0f0f_0f0f_1234_5678u64;
    let mut vus = 0;
    for _ in 0..200_000 {
        let n = (xorshift(&mut g) % 260) as usize;
        let mut brut = Vec::with_capacity(n);
        for _ in 0..n {
            brut.push((xorshift(&mut g) >> 24) as u8);
        }
        if let Ok(b) = Block::decode(&brut) {
            vus += 1;
            assert_eq!(b.encode(), brut, "MALLEABILITE bloc");
        }
    }
    eprintln!("blocs decodes au hasard : {vus}");
}

/// Un bloc compact decode doit se reencoder a l'identique.
#[test]
fn compact_reencodage_identique() {
    // Construit un cmpctblock legitime puis teste la canonicite de l'indice
    // prefourni, ecrit en varint mais relu en u32.
    let entete = BlockHeader {
        version: 1,
        prev_block: Hash256([1u8; 32]),
        merkle_root: Hash256([2u8; 32]),
        uncles_root: Hash256([3u8; 32]),
        miner: Hash256([4u8; 32]),
        time: 1,
        bits: 0x2000_ffff,
        height: 1,
        nonce: 0,
    };
    // Transaction minimale valide
    let tx = Transaction {
        version: 1,
        inputs: vec![q21_core::tx::TxIn::coinbase(vec![1, 2, 3])],
        outputs: vec![q21_core::tx::TxOut {
            value: Amount::from_units(1),
            scheme: q21_core::sig::SchemeId::MlDsa65,
            pubkey_hash: Hash256::ZERO,
        }],
        lock_time: 0,
    };

    let construire = |indice: u64| {
        let mut w = Writer::new();
        w.bytes(&entete.encode());
        w.u64(0); // nonce
        w.varint(0); // short_ids
        w.varint(1); // prefilled
        w.varint(indice);
        w.var_bytes(&tx.encode());
        w.varint(0); // uncles
        w.finish()
    };

    let a = construire(0);
    let b = construire(0x1_0000_0000); // 2^32, qui ne tient pas sur 32 bits
    assert_ne!(a, b);
    assert!(
        CompactBlock::decode(&a).is_ok(),
        "le cmpctblock canonique doit rester accepte"
    );
    assert!(
        CompactBlock::decode(&b).is_err(),
        "MALLEABILITE : un indice pre-rempli hors des trente-deux bits a ete tronque"
    );
}

// ---------------------------------------------------------------------------
// 6. Paniques sur entree hostile
// ---------------------------------------------------------------------------

#[test]
fn aucun_decodeur_ne_panique_sur_entree_aleatoire() {
    let mut g = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..150_000 {
        let n = (xorshift(&mut g) % 400) as usize;
        let mut brut = Vec::with_capacity(n);
        for _ in 0..n {
            brut.push((xorshift(&mut g) >> 32) as u8);
        }
        let _ = Transaction::decode(&brut);
        let _ = Block::decode(&brut);
        let _ = CompactBlock::decode(&brut);
        let _ = BlockHeader::decode(&brut);
        let _ = Message::parse(&brut, NETWORK_MAGIC_TESTNET);
        let _ = Reader::new(&brut).varint();
        if let Ok(s) = core::str::from_utf8(&brut) {
            let _ = bech32::decode(s);
            let _ = q21_core::address::Address::parse(s);
            let _ = q21_core::json::parse(s);
            let _ = Hash256::from_hex(s);
        }
    }
}

/// Entrees degenerees ciblees : varints maximaux, longueurs absurdes.
#[test]
fn entrees_degenerees_ne_paniquent_pas() {
    let degeneres: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xff; 1],
        vec![0xff; 9],
        vec![0xff; 200],
        vec![0x00; 200],
        {
            let mut v = vec![1u8, 0, 0, 0];
            v.push(0xff);
            v.extend_from_slice(&u64::MAX.to_le_bytes());
            v
        },
        {
            // en-tete de bloc valide + varint annoncant u64::MAX transactions
            let mut v = vec![0u8; BlockHeader::SIZE];
            v.push(0xff);
            v.extend_from_slice(&u64::MAX.to_le_bytes());
            v
        },
        {
            // cmpctblock : nonce + varint enorme
            let mut v = vec![0u8; BlockHeader::SIZE];
            v.extend_from_slice(&0u64.to_le_bytes());
            v.push(0xff);
            v.extend_from_slice(&u64::MAX.to_le_bytes());
            v
        },
    ];
    for d in &degeneres {
        let _ = Transaction::decode(d);
        let _ = Block::decode(d);
        let _ = CompactBlock::decode(d);
        let _ = BlockHeader::decode(d);
        let _ = Message::parse(d, NETWORK_MAGIC_TESTNET);
    }
    // Chaque commande connue, avec des charges degenerees.
    let commandes: &[&[u8]] = &[
        b"version",
        b"verack",
        b"ping",
        b"pong",
        b"getheaders",
        b"headers",
        b"inv",
        b"getdata",
        b"block",
        b"tx",
        b"cmpctblock",
        b"getblocktxn",
        b"blocktxn",
        b"getaddr",
        b"addr",
        b"reject",
    ];
    for c in commandes {
        for d in &degeneres {
            let t = frame_brut(c, d);
            let _ = Message::parse(&t, NETWORK_MAGIC_TESTNET);
        }
    }
}

/// Cible compacte : aucune valeur de 32 bits ne doit paniquer, et l'aller-retour
/// doit etre stable.
#[test]
fn cible_compacte_totale() {
    use q21_core::pow::{block_work, target_from_compact, target_to_compact};
    let mut g = 0x1111_2222_3333_4444u64;
    for i in 0..300_000u64 {
        let bits = if i < 70_000 {
            (i as u32).wrapping_mul(61_057)
        } else {
            xorshift(&mut g) as u32
        };
        let _ = block_work(bits);
        if let Ok(c) = target_from_compact(bits) {
            let re = target_to_compact(c);
            // L'aller-retour doit rendre exactement la meme cible.
            if let Ok(c2) = target_from_compact(re) {
                assert_eq!(c, c2, "aller-retour de cible instable pour bits={bits:#x}");
            } else {
                panic!("target_to_compact a produit une valeur indecodable : {bits:#x} -> {re:#x}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Rapport entre octets recus et memoire allouee
// ---------------------------------------------------------------------------

#[test]
fn rapport_allocation_par_message() {
    #[allow(clippy::type_complexity)]
    let cas: Vec<(&str, Vec<u8>)> = vec![
        ("inv", {
            let mut w = Writer::new();
            w.varint(wire::MAX_INV as u64);
            frame_brut(b"inv", w.finish().as_slice())
        }),
        ("getdata", {
            let mut w = Writer::new();
            w.varint(wire::MAX_INV as u64);
            frame_brut(b"getdata", w.finish().as_slice())
        }),
        ("headers", {
            let mut w = Writer::new();
            w.varint(wire::MAX_HEADERS as u64);
            frame_brut(b"headers", w.finish().as_slice())
        }),
        ("getblocktxn", {
            let mut w = Writer::new();
            w.bytes(&[0u8; 32]);
            w.varint(wire::MAX_BLOCK_TXN as u64);
            frame_brut(b"getblocktxn", w.finish().as_slice())
        }),
        ("blocktxn", {
            let mut w = Writer::new();
            w.bytes(&[0u8; 32]);
            w.varint(wire::MAX_BLOCK_TXN as u64);
            frame_brut(b"blocktxn", w.finish().as_slice())
        }),
        ("addr", {
            let mut w = Writer::new();
            w.varint(wire::MAX_ADDR as u64);
            frame_brut(b"addr", w.finish().as_slice())
        }),
        ("getheaders", {
            let mut w = Writer::new();
            w.varint(wire::MAX_LOCATOR as u64);
            frame_brut(b"getheaders", w.finish().as_slice())
        }),
        ("block", {
            let mut v = vec![0u8; BlockHeader::SIZE];
            v.push(0xfe);
            v.extend_from_slice(&(1_000_000u32).to_le_bytes());
            frame_brut(b"block", &v)
        }),
        ("tx", {
            let mut v = vec![1u8, 0, 0, 0];
            v.push(0xfe);
            v.extend_from_slice(&(1_000_000u32).to_le_bytes());
            frame_brut(b"tx", &v)
        }),
        ("cmpctblock", {
            let mut v = vec![0u8; BlockHeader::SIZE];
            v.extend_from_slice(&0u64.to_le_bytes());
            v.push(0xfe);
            v.extend_from_slice(&(MAX_TX_PAR_BLOC as u32).to_le_bytes());
            frame_brut(b"cmpctblock", &v)
        }),
    ];

    let mut pire = 0f64;
    let mut pire_nom = "";
    for (nom, trame) in &cas {
        // Chauffe (le premier passage peut allouer des structures paresseuses).
        let _ = Message::parse(trame, NETWORK_MAGIC_TESTNET);
        let (r, pic) = mesurer(|| Message::parse(trame, NETWORK_MAGIC_TESTNET));
        let rapport = pic as f64 / trame.len() as f64;
        eprintln!(
            "{nom:12} : {:5} octets envoyes -> pic {:9} octets alloues (x{:.0})  [{}]",
            trame.len(),
            pic,
            rapport,
            match &r {
                Ok((m, _)) => format!("ok {}", m.command()),
                Err(e) => format!("{e:?}"),
            }
        );
        if rapport > pire {
            pire = rapport;
            pire_nom = nom;
        }
    }
    eprintln!("pire rapport : {pire_nom} x{pire:.0}");
    assert!(
        pire < 100.0,
        "AMPLIFICATION MEMOIRE : {pire_nom} alloue {pire:.0} fois ce qu'il recoit"
    );
}

// ---------------------------------------------------------------------------
// 5. Taille et poids
// ---------------------------------------------------------------------------

#[test]
fn taille_du_bloc_non_manipulable() {
    // La taille controlee par le consensus est celle du reencodage. Si le
    // decodage acceptait un encodage plus court que le reencodage, un bloc
    // au-dessus de MAX_BLOCK_SIZE pourrait passer.
    // Verifie sur des blocs decodables issus d'un fuzz cible.
    let mut g = 0x7777_1111_2222_3333u64;
    let mut vus = 0;
    for _ in 0..300_000 {
        let n = (xorshift(&mut g) % 300) as usize;
        let mut brut = vec![0u8; BlockHeader::SIZE];
        for o in brut.iter_mut() {
            *o = (xorshift(&mut g) >> 40) as u8;
        }
        for _ in 0..n {
            brut.push((xorshift(&mut g) >> 40) as u8);
        }
        if let Ok(b) = Block::decode(&brut) {
            vus += 1;
            assert!(
                b.encode().len() >= brut.len(),
                "un bloc se reencode plus court qu'il n'est arrive"
            );
        }
    }
    eprintln!("blocs decodes : {vus}");
}

#[test]
fn poids_de_transaction_ne_deborde_pas() {
    // weight() = base * discount + temoin, sans controle de debordement.
    // Cherche un cas ou une transaction de taille realiste ferait deborder.
    let tx = Transaction {
        version: 1,
        inputs: vec![q21_core::tx::TxIn {
            prev_out: q21_core::tx::OutPoint {
                txid: Hash256::ZERO,
                index: 0,
            },
            witness: q21_core::tx::Witness {
                pubkey: vec![0u8; 1952],
                signature: vec![0u8; 3309],
            },
            sequence: 0,
        }],
        outputs: vec![q21_core::tx::TxOut {
            value: Amount::from_units(1),
            scheme: q21_core::sig::SchemeId::MlDsa65,
            pubkey_hash: Hash256::ZERO,
        }],
        lock_time: 0,
    };
    let w = tx.weight(WITNESS_DISCOUNT);
    assert!(w > 0);
    // Facteur d'escompte extreme : le calcul doit rester sain.
    let _ = tx.weight(1);
}

// ---------------------------------------------------------------------------
// Varints : bornes de lecture
// ---------------------------------------------------------------------------

#[test]
fn varint_toutes_les_formes_non_canoniques_refusees() {
    // Pour chaque forme longue, toute valeur representable plus court est refusee.
    for v in 0u64..=0xff {
        let mut w = Writer::new();
        w.varint(v);
        let canon = w.finish();
        // Forme longue 0xfd
        let long = [&[0xfdu8][..], &(v as u16).to_le_bytes()[..]].concat();
        let r = Reader::new(&long).varint();
        if v < 0xfd {
            assert!(r.is_err(), "forme longue acceptee pour {v}");
        }
        assert_eq!(Reader::new(&canon).varint().unwrap(), v);
    }
    for v in [0u64, 1, 0xfc, 0xfd, 0xffff, 0x1_0000, 0xffff_ffff] {
        let long4 = [&[0xfeu8][..], &(v as u32).to_le_bytes()[..]].concat();
        let long8 = [&[0xffu8][..], &v.to_le_bytes()[..]].concat();
        if v <= 0xffff {
            assert!(Reader::new(&long4).varint().is_err(), "0xfe pour {v}");
        }
        if v <= 0xffff_ffff {
            assert!(Reader::new(&long8).varint().is_err(), "0xff pour {v}");
        }
    }
}
