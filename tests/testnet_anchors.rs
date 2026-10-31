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

/// The headers of the anchored blocks, field by field as the explorer shows
/// them. Neither block has an uncle.
fn headers() -> Vec<BlockHeader> {
    vec![
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
