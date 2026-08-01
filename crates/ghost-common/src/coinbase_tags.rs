//! Commitments stamped into the coinbase scriptsig.
//!
//! Two things need to be readable straight off a block, by a node that holds no local context:
//!
//! - **which payout a won block pays** (`GHPP`), so settlement is a lookup rather than an inference.
//!   It cannot be inferred from the outputs: the mined coinbase is built from a *fee-adjusted*
//!   proposal whose treasury and node amounts absorb each node's own fee drift, so it does not hash
//!   to what any stored proposal described.
//! - **which node a share was mined to** (`GHNT`), so credit for work cannot be re-attributed by a
//!   peer that merely relayed the proof.
//!
//! ## Budget
//!
//! The coinbase scriptsig has a 100-byte consensus ceiling. Measured on mainnet after the tag trim:
//!
//! ```text
//!   BIP34 height push                        4
//!   extranonce (4 pool + 16 client)         20
//!   "GHOST PublicPool"                      16   (was 24 before the trim)
//!   ------------------------------------------
//!   used                                   ~45
//!   payout tag   (1 push + 4 magic + 16)    21
//!   node tag     (1 push + 4 magic + 20)    25
//!   ------------------------------------------
//!   total                                  ~91,  leaving ~9 spare
//! ```
//!
//! Note the push opcode: a tag costs one byte more than its payload. Nine bytes is real but not
//! generous — before widening either tag, re-measure, and remember the miner-supplied portion of
//! `/pool_tag/miner_tag/` may vary.

/// Marks the payout identity a block pays.
pub const PAYOUT_TAG_MAGIC: &[u8; 4] = b"GHPP";

/// Marks the node a share was mined to.
pub const NODE_TAG_MAGIC: &[u8; 4] = b"GHNT";

/// Bytes of identity carried by a payout tag.
pub const PAYOUT_ID_LEN: usize = 16;

/// Bytes of identity carried by a node tag.
pub const NODE_ID_LEN: usize = 20;

/// Encode a tag as a single scriptsig push: `[len][magic][payload]`.
///
/// Data pushes of 75 bytes or fewer use the length itself as the opcode, so the whole tag is one
/// push and reads back as one — which is what lets extraction refuse a magic that merely appears
/// *inside* someone else's push.
fn encode_tag(magic: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + payload.len());
    out.push((4 + payload.len()) as u8);
    out.extend_from_slice(magic);
    out.extend_from_slice(payload);
    out
}

/// Scriptsig bytes committing to the payout a block pays.
///
/// The identity is deliberately generic. Before the batch-chain cutover it is the first 16 bytes of
/// the proposal hash; afterwards it is the batch identity. One field, one format, switched by
/// height — the coinbase is the one place where every node must change at the same block, so it is
/// worth not changing twice.
pub fn encode_payout_tag(payout_id: &[u8; PAYOUT_ID_LEN]) -> Vec<u8> {
    encode_tag(PAYOUT_TAG_MAGIC, payout_id)
}

/// Scriptsig bytes committing to the node that received a share.
pub fn encode_node_tag(node_commitment: &[u8; NODE_ID_LEN]) -> Vec<u8> {
    encode_tag(NODE_TAG_MAGIC, node_commitment)
}

/// Walk a scriptsig as a sequence of data pushes.
///
/// Only the small-push encodings are handled (opcodes 1..=75, plus `OP_PUSHDATA1`), which is all a
/// coinbase scriptsig legitimately uses inside 100 bytes. Anything else ends the walk rather than
/// guessing, because a misparse here would let a crafted scriptsig fake a tag.
fn pushes(scriptsig: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < scriptsig.len() {
        let opcode = scriptsig[i];
        let (len, header) = match opcode {
            0x01..=0x4b => (opcode as usize, 1usize),
            0x4c => {
                // OP_PUSHDATA1: next byte is the length.
                let Some(&n) = scriptsig.get(i + 1) else {
                    break;
                };
                (n as usize, 2usize)
            }
            _ => break,
        };
        let start = i + header;
        let Some(end) = start.checked_add(len) else {
            break;
        };
        if end > scriptsig.len() {
            break;
        }
        out.push(&scriptsig[start..end]);
        i = end;
    }
    out
}

/// Extract a tag payload of exactly `payload_len` bytes carried in its own push.
///
/// Deliberately push-aware rather than a byte scan. A scan for the magic would match the same four
/// bytes appearing inside the pool tag, the extranonce, or any other push — all attacker-influenced
/// — and would then read whatever followed as an identity.
fn extract_tag(scriptsig: &[u8], magic: &[u8; 4], payload_len: usize) -> Option<Vec<u8>> {
    pushes(scriptsig).into_iter().find_map(|push| {
        (push.len() == 4 + payload_len && &push[..4] == magic).then(|| push[4..].to_vec())
    })
}

/// Read the payout identity a coinbase commits to, if it carries one.
pub fn extract_payout_tag(scriptsig: &[u8]) -> Option<[u8; PAYOUT_ID_LEN]> {
    let payload = extract_tag(scriptsig, PAYOUT_TAG_MAGIC, PAYOUT_ID_LEN)?;
    payload.try_into().ok()
}

/// Read the node commitment a coinbase carries, if any.
pub fn extract_node_tag(scriptsig: &[u8]) -> Option<[u8; NODE_ID_LEN]> {
    let payload = extract_tag(scriptsig, NODE_TAG_MAGIC, NODE_ID_LEN)?;
    payload.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic scriptsig prefix: BIP34 height push, then the pool tag, then the extranonce.
    fn scriptsig_prefix() -> Vec<u8> {
        let mut s = Vec::new();
        s.push(0x03);
        s.extend_from_slice(&[0x40, 0x1f, 0x0e]); // height
        let tag = b"GHOST PublicPool";
        s.push(tag.len() as u8);
        s.extend_from_slice(tag);
        s.push(0x14);
        s.extend_from_slice(&[0xAB; 20]); // extranonce
        s
    }

    #[test]
    fn payout_tag_round_trips_within_a_realistic_scriptsig() {
        let id = [0x11u8; PAYOUT_ID_LEN];
        let mut s = scriptsig_prefix();
        s.extend_from_slice(&encode_payout_tag(&id));

        assert_eq!(extract_payout_tag(&s), Some(id));
        assert_eq!(extract_node_tag(&s), None, "a payout tag is not a node tag");
    }

    #[test]
    fn both_tags_coexist() {
        let payout = [0x22u8; PAYOUT_ID_LEN];
        let node = [0x33u8; NODE_ID_LEN];
        let mut s = scriptsig_prefix();
        s.extend_from_slice(&encode_payout_tag(&payout));
        s.extend_from_slice(&encode_node_tag(&node));

        assert_eq!(extract_payout_tag(&s), Some(payout));
        assert_eq!(extract_node_tag(&s), Some(node));
    }

    /// The whole point of parsing pushes rather than scanning bytes: the magic appearing inside
    /// someone else's push must not be read as a tag. The pool tag and the extranonce are both
    /// influenceable, so a scan would be forgeable.
    #[test]
    fn magic_hidden_inside_another_push_is_not_a_tag() {
        let mut s = Vec::new();
        s.push(0x03);
        s.extend_from_slice(&[0x40, 0x1f, 0x0e]);

        // One long push whose CONTENTS spell a well-formed-looking payout tag.
        let mut inner = Vec::new();
        inner.extend_from_slice(PAYOUT_TAG_MAGIC);
        inner.extend_from_slice(&[0x99; PAYOUT_ID_LEN]);
        s.push(inner.len() as u8 + 4);
        s.extend_from_slice(b"junk");
        s.extend_from_slice(&inner);

        assert_eq!(
            extract_payout_tag(&s),
            None,
            "magic embedded in another push must not be extracted"
        );
    }

    /// A tag whose payload is the wrong length is not a tag. Accepting it would mean reading an
    /// identity from a push that was never a commitment.
    #[test]
    fn a_wrong_length_payload_is_rejected() {
        let mut s = scriptsig_prefix();
        s.extend_from_slice(&encode_tag(PAYOUT_TAG_MAGIC, &[0x44; 8]));
        assert_eq!(extract_payout_tag(&s), None);
    }

    /// Truncated and malformed scriptsigs must return nothing rather than panic — this parses data
    /// straight off the chain, where anyone can put anything.
    #[test]
    fn malformed_scriptsigs_do_not_panic() {
        for s in [
            vec![],
            vec![0x14],                   // push claiming 20 bytes, none present
            vec![0x4c],                   // PUSHDATA1 with no length byte
            vec![0x4c, 0x20, 0x01, 0x02], // PUSHDATA1 overrunning the buffer
            vec![0xff, 0xff, 0xff],       // opcodes we do not handle
            encode_payout_tag(&[0u8; 16])[..8].to_vec(), // a tag cut in half
        ] {
            assert_eq!(extract_payout_tag(&s), None);
            assert_eq!(extract_node_tag(&s), None);
        }
    }

    /// The budget claim in the module docs must hold: both tags plus a realistic prefix have to fit
    /// inside the 100-byte consensus ceiling, with margin left over.
    #[test]
    fn both_tags_fit_the_consensus_ceiling() {
        let mut s = scriptsig_prefix();
        s.extend_from_slice(&encode_payout_tag(&[0u8; PAYOUT_ID_LEN]));
        s.extend_from_slice(&encode_node_tag(&[0u8; NODE_ID_LEN]));

        assert!(
            s.len() <= 100,
            "scriptsig would exceed the consensus ceiling at {} bytes",
            s.len()
        );
        assert!(
            s.len() <= 92,
            "less margin than the documented ~9 bytes: {} used",
            s.len()
        );
    }
}
