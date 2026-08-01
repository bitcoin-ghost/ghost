//! Telling ghost-pool which coinbase a share was mined against.
//!
//! A share's proof of work is over a header, and that header commits to a merkle root that commits
//! to the coinbase — which carries the node tag. So a validator can establish, from the share
//! alone, which node the work was really for. What it needs is the coinbase, and the only part it
//! cannot infer is the extranonce the miner chose.
//!
//! Rather than ship a ~29 KB coinbase per share (~10 GB/day at 200 payees), each share carries the
//! extranonce plus the **content address** of its skeleton, and the skeleton itself travels once
//! per job. The address is computed by [`CoinbaseSkeleton::id`] on both sides, so there is one
//! definition of what a skeleton is called.

use ghost_common::share_binding::CoinbaseSkeleton;

use crate::share_webhook::{ShareWebhookSender, SkeletonData};

/// Convert the raw parts into a skeleton, announce it, and return `(extranonce, skeleton_id)` hex
/// for the share that referenced it.
///
/// Announcing here, at the point of use, is deliberate: a skeleton is only worth sending because
/// some share names it, and tying the two together means there is no path that reports a share
/// whose skeleton was never offered.
pub fn announce(
    sender: &ShareWebhookSender,
    coinbase_prefix: Vec<u8>,
    coinbase_suffix: Vec<u8>,
    merkle_path: Vec<Vec<u8>>,
    full_extranonce: &[u8],
) -> (Option<String>, Option<String>) {
    // A merkle node that is not 32 bytes cannot be folded, and a skeleton that cannot fold proves
    // nothing. Better to report the share with no binding than with a binding that will not verify.
    let mut path = Vec::with_capacity(merkle_path.len());
    for node in &merkle_path {
        match <[u8; 32]>::try_from(node.as_slice()) {
            Ok(n) => path.push(n),
            Err(_) => return (Some(hex::encode(full_extranonce)), None),
        }
    }

    let skeleton = CoinbaseSkeleton {
        coinbase_prefix,
        coinbase_suffix,
        merkle_path: path,
    };
    let id = skeleton.id();

    sender.send_skeleton(SkeletonData {
        skeleton_id: hex::encode(id),
        coinbase_prefix: hex::encode(&skeleton.coinbase_prefix),
        coinbase_suffix: hex::encode(&skeleton.coinbase_suffix),
        merkle_path: skeleton.merkle_path.iter().map(hex::encode).collect(),
    });

    (Some(hex::encode(full_extranonce)), Some(hex::encode(id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ShareWebhookConfig;
    use crate::share_webhook::ShareWebhookWorker;

    fn a_sender() -> (ShareWebhookSender, ShareWebhookWorker) {
        ShareWebhookWorker::new(
            ShareWebhookConfig {
                url: "http://127.0.0.1:0/unused".to_string(),
                batch_size: 1,
                batch_timeout_ms: 1000,
                max_retries: 0,
            },
            1,
        )
    }

    /// The id a share carries must be the id the skeleton hashes to — that is the whole basis of
    /// the lookup on the other side.
    #[test]
    fn the_announced_id_is_the_skeletons_own_content_address() {
        let (sender, _worker) = a_sender();
        let skeleton = CoinbaseSkeleton {
            coinbase_prefix: vec![1, 2, 3],
            coinbase_suffix: vec![4, 5],
            merkle_path: vec![[9u8; 32]],
        };
        let (extranonce, id) = announce(
            &sender,
            skeleton.coinbase_prefix.clone(),
            skeleton.coinbase_suffix.clone(),
            skeleton.merkle_path.iter().map(|n| n.to_vec()).collect(),
            &[7u8; 8],
        );
        assert_eq!(extranonce.as_deref(), Some("0707070707070707"));
        assert_eq!(id, Some(hex::encode(skeleton.id())));
    }

    /// A merkle node of the wrong width cannot fold, so the share is reported with the extranonce
    /// but no binding — an absent claim rather than one that is guaranteed to fail.
    #[test]
    fn a_malformed_merkle_node_yields_no_binding() {
        let (sender, _worker) = a_sender();
        let (extranonce, id) = announce(&sender, vec![1], vec![2], vec![vec![0u8; 31]], &[7u8; 4]);
        assert_eq!(extranonce.as_deref(), Some("07070707"));
        assert_eq!(id, None);
    }
}
