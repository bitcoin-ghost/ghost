//! Tests for the solo layer's pure parts. The coinbase on real channels is `tests/solo_jobs.rs`.

use super::*;
use ghost_common::coinbase_tags::{encode_node_tag, encode_payout_tag};

fn prefix(tags: bool) -> Vec<u8> {
    // BIP34 height 960,000 as ghost-mining encodes it: a 3-byte push.
    let mut p = vec![0x03, 0x00, 0xa6, 0x0e];
    if tags {
        p.extend(encode_payout_tag(&[0xC3; 16]));
        p.extend(encode_node_tag(&[0xD4; 20]));
    }
    p
}

#[test]
fn ghost_tags_come_out_of_the_prefix_and_nothing_else_does() {
    assert_eq!(strip_ghost_tags(&prefix(true)), prefix(false));
    assert_eq!(strip_ghost_tags(&prefix(false)), prefix(false));
    // Only one of the two, as an older template provider might send.
    let mut only_node = prefix(false);
    only_node.extend(encode_node_tag(&[0xD4; 20]));
    assert_eq!(strip_ghost_tags(&only_node), prefix(false));
    // Bytes after the tags stay.
    let mut more = prefix(true);
    more.extend([0x02, 0xAB, 0xCD]);
    let mut want = prefix(false);
    want.extend([0x02, 0xAB, 0xCD]);
    assert_eq!(strip_ghost_tags(&more), want);
    // A prefix with no readable height is left alone.
    assert_eq!(strip_ghost_tags(&[0x4c, 1, 2]), vec![0x4c, 1, 2]);
}

#[test]
fn a_block_is_header_count_coinbase_transactions() {
    let header = [1u8; 80];
    let raw = assemble_block(&header, &[2, 2], &[vec![3], vec![4, 4]]);
    let mut want = header.to_vec();
    want.extend([3, 2, 2, 3, 4, 4]);
    assert_eq!(raw, want);
    // 300 transactions plus the coinbase: a 3-byte count.
    let txs = vec![vec![9u8]; 300];
    let raw = assemble_block(&header, &[2], &txs);
    assert_eq!(&raw[80..83], &[0xfd, 0x2d, 0x01]);
    assert_eq!(raw.len(), 80 + 3 + 1 + 300);
}

#[test]
fn identities_and_payee_tlvs() {
    assert!(Solo::payee_for_identity("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.rig1").is_ok());
    assert_eq!(Solo::payee_for_identity(""), Err("no-payout-address"));
    assert_eq!(
        Solo::payee_for_identity("worker1"),
        Err("no-payout-address")
    );
    let tlv = Tlv::new(
        AGENT_TLV_EXTENSION_TYPE,
        PAYEE_TLV_FIELD_TYPE,
        b"a.b1".to_vec(),
    );
    assert_eq!(
        Solo::payee_from_tlvs(Some(&[tlv])),
        Some("a.b1".to_string())
    );
    assert_eq!(Solo::payee_from_tlvs(None), None);
}

#[test]
fn provisional_channels_wait_for_their_payee() {
    let solo = Solo::new(SoloNetwork::Regtest);
    solo.await_payee((1, 2));
    assert!(solo.awaits_payee((1, 2)));
    solo.on_downstream_removed(1);
    assert!(!solo.awaits_payee((1, 2)));
}
