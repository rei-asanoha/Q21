//! The testnet anchors (`validate::ANCHORS_TESTNET`) are real blocks of the
//! testnet: each id is rebuilt here from the header a node's explorer showed
//! for it when the release was prepared, and that header carries the work
//! its difficulty demands. A mistyped character in an anchor would make every
//! node refuse the real chain at that height; this test refuses it first.

use q21_core::block::BlockHeader;
use q21_core::hash::Hash256;
use q21_core::pow::{PowEngine, Q21Pow};
use q21_core::validate;
use q21_core::Network;

fn h(s: &str) -> Hash256 {
    Hash256::from_hex(s).expect("hex")
}

/// The headers of the anchored blocks, field by field as `getblockheader`
/// gave them on the France entry point (blocks 2,500 and 5,000 also read on
/// a wallet's own explorer, identical). None has an uncle.
fn headers() -> Vec<BlockHeader> {
    vec![
        BlockHeader {
            version: 1,
            prev_block: h("26b59a8f4e836a0a0b3c9e608e79f51605869b5b5c322c456c8ee5b423f0f4ed"),
            merkle_root: h("dc134f1079d32988c8b4bf05c97a60ef108a2ad3ed5d7eb6350b0839bfdfc484"),
            uncles_root: Hash256::ZERO,
            miner: h("755385b113fae07aff65a95fab9279cbb38516299790c5b07ee68951972fe7b3"),
            time: 1_791_228_496, // 2026-10-05 19:28:16 UTC
            bits: 0x1d12_4c0d,
            height: 1_000,
            nonce: 1_897_142,
        },
        BlockHeader {
            version: 1,
            prev_block: h("1307ca1e7a794f09787b1e678f7aac8221326edd5d378c374cc2d65b31301c69"),
            merkle_root: h("d459ef735fadd663016e02e4abe10d187b0b0dabdf99a7a8905926aa1549e7c4"),
            uncles_root: Hash256::ZERO,
            miner: h("8369f12e8e3ad396d51f8569167641aaf2d5685e740b0cb1f1861e9015682cd1"),
            time: 1_791_719_172, // 2026-10-11 11:46:12 UTC
            bits: 0x1d13_9afe,
            height: 2_000,
            nonce: 467_870,
        },
        BlockHeader {
            version: 1,
            prev_block: h("c725221f816b4c19f9bde1788f3ffe6484d790a03cf62a9861bfa5890f628502"),
            merkle_root: h("f714e0df9386da615ad4f338964bb9a644e6a218921e96f40550c8aec5d9edf5"),
            uncles_root: Hash256::ZERO,
            miner: h("e01885d8fcf5fe5e22d7a061472edd06290430fc77e2a83eafc1bd946665e7e6"),
            time: 1_792_338_314, // 2026-10-18 15:45:14 UTC
            bits: 0x1d18_8173,
            height: 2_500,
            nonce: 283_787,
        },
        BlockHeader {
            version: 1,
            prev_block: h("e853144af421c641bfa77c1e5489200b82c60ca20ed01f2407ae6a3835ba46c4"),
            merkle_root: h("634428b676585ea5c0053d4b9b03d4b55066d0e84c1b067b57d0578851c4a08f"),
            uncles_root: Hash256::ZERO,
            miner: h("caab36fe9818f7c9e57fb78cbe3cba1092bad6f329763c22f751e50584bc2016"),
            time: 1_792_401_400, // 2026-10-19 09:16:40 UTC
            bits: 0x1d17_59e4,
            height: 3_000,
            nonce: 731_226,
        },
        BlockHeader {
            version: 1,
            prev_block: h("5b8c420db08c82c01ab84ea60dc4f62f28e18c26c1f441b541685ebfcec31622"),
            merkle_root: h("b673e5b530385e3c3365722e7b15ee7decca46f007eac2bfa7f35f845a2c7edd"),
            uncles_root: Hash256::ZERO,
            miner: h("8a4f8d19fb8ea973838069b496da548ccce84b0bce99e600a15ec92877f13ddd"),
            time: 1_792_881_577, // 2026-10-24 22:39:37 UTC
            bits: 0x1d13_96df,
            height: 4_000,
            nonce: 709_665,
        },
        BlockHeader {
            version: 1,
            prev_block: h("ca826a840dd302f99490d3d3bbe9881e555779c6c665a8bb63dac819c43813f1"),
            merkle_root: h("271bbb93036d2b58988ced0b5ea6746cf41d74609c8208b99472778e3ce479f9"),
            uncles_root: Hash256::ZERO,
            miner: h("5aa605450a63198468d68765c56eccbd3931c1e8939ac173368a175494ed2133"),
            time: 1_793_112_150, // 2026-10-27 14:42:30 UTC
            bits: 0x1d14_dcdb,
            height: 5_000,
            nonce: 380_850,
        },
    ]
}

#[test]
fn each_testnet_anchor_is_a_mined_testnet_block() {
    let anchors = validate::anchors(Network::Testnet);
    let headers = headers();
    assert_eq!(anchors.len(), headers.len());
    let pow = Q21Pow::new(Network::Testnet);
    for ((height, id), header) in anchors.iter().zip(&headers) {
        assert_eq!(*height, header.height);
        assert_eq!(
            header.block_id(),
            *id,
            "anchor {height}: the id is its header's"
        );
        assert!(
            pow.check(header).is_ok(),
            "anchor {height}: the work is there"
        );
    }
}
