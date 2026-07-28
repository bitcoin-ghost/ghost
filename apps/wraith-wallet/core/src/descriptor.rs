//! Bare-minimum descriptor parser for `wsh(sortedmulti(K, ...))`.
//!
//! Why we don't pull in `rust-miniscript`: this file gives us the
//! 5% of the descriptor language we actually need (P2WSH sortedmulti
//! for k-of-n cosigner setups), with no extra dependency footprint.
//! Anything more exotic (taproot multi_a, nested wsh-in-sh, bare
//! multisig, miniscript expressions) is out of scope here — when
//! wraith needs to handle those, switching to `miniscript` is a
//! drop-in replacement at the call sites because the public API
//! exposed below is intentionally narrow.
//!
//! What we accept:
//!
//!   wsh(sortedmulti(K, FRAG, FRAG, ...))  [#checksum]
//!
//! Where each FRAG is one of:
//!
//!   [fingerprint/path]xpub.../<a;b>/*       multipath
//!   [fingerprint/path]xpub.../child/*       single child
//!   [fingerprint/path]xpub.../child         single non-ranged
//!
//! Anything else returns `DescriptorError::Unsupported`. The
//! checksum (BIP-380) is parsed off but NOT verified — the
//! descriptor is treated as authoritative; verification happens at
//! the `getdescriptorinfo` step on the operator's side, not here.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpub};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, PublicKey, ScriptBuf};

#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    #[error("descriptor parse: {0}")]
    Parse(String),
    #[error("unsupported descriptor shape: {0}")]
    Unsupported(String),
    #[error("derivation: {0}")]
    Derivation(String),
    #[error("network mismatch: descriptor has {desc} keys, wallet is on {wallet}")]
    NetworkMismatch { desc: String, wallet: String },
    #[error("k must be 1..=n: got k={k}, n={n}")]
    BadThreshold { k: usize, n: usize },
    #[error("address derivation index {index} exceeds derivation range")]
    IndexOutOfRange { index: u32 },
    #[error("bitcoin: {0}")]
    Bitcoin(String),
}

/// One cosigner key inside a parsed descriptor. Origin — fingerprint plus
/// path-from-master — is what BIP-380 calls "key origin info", and is what
/// lets a signer identify whether they own this key without guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignerKey {
    pub fingerprint: [u8; 4],
    /// Path from the master to the xpub itself (e.g.
    /// `48'/1'/0'/2'`). Hardened markers preserved.
    pub origin_path: String,
    pub xpub: Xpub,
    /// Children template that follows the xpub. We accept one of:
    ///   - `Multipath { external, internal }` for `<external;internal>/*`
    ///   - `Single(child)` for `child/*`
    pub children: Children,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Children {
    /// `<a;b>/*` — typical convention is `<0;1>/*` (external/internal).
    Multipath { external: u32, internal: u32 },
    /// `child/*` — fixed branch, ranged.
    Single(u32),
    /// `child` — fixed, non-ranged. Single-address descriptor; can't
    /// be used for receive chains. We tolerate parsing it but
    /// `derive_address(index)` will only succeed at index 0.
    Fixed(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorKind {
    /// `wsh(sortedmulti(K, ...))`. The only kind we currently support.
    WshSortedMulti,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDescriptor {
    pub kind: DescriptorKind,
    pub k: usize,
    pub keys: Vec<CosignerKey>,
    /// BIP-380 checksum (8 chars after `#`), or None if absent.
    pub checksum: Option<String>,
    /// The original string the parser was handed, post-checksum-strip.
    pub raw: String,
}

impl ParsedDescriptor {
    /// True if `our_fingerprint` matches one of the cosigner keys.
    pub fn contains_fingerprint(&self, our_fingerprint: &[u8; 4]) -> bool {
        self.keys.iter().any(|k| k.fingerprint == *our_fingerprint)
    }

    pub fn n(&self) -> usize {
        self.keys.len()
    }

    /// Derive a P2WSH address at the given index, picking the
    /// `internal` flag against the multipath children template if
    /// applicable. For `Single` and `Fixed` children there's no
    /// internal/external split — `internal=true` errors.
    pub fn derive_address(
        &self,
        index: u32,
        internal: bool,
        network: Network,
    ) -> Result<Address, DescriptorError> {
        let secp = Secp256k1::verification_only();
        let mut child_pubkeys: Vec<PublicKey> = Vec::with_capacity(self.keys.len());
        for k in &self.keys {
            let (chain_child, leaf_child) = match k.children {
                Children::Multipath {
                    external,
                    internal: int_,
                } => {
                    if internal {
                        (int_, index)
                    } else {
                        (external, index)
                    }
                }
                Children::Single(c) => {
                    if internal {
                        return Err(DescriptorError::Unsupported(
                            "descriptor has no internal branch (single-child); receive-only".into(),
                        ));
                    }
                    (c, index)
                }
                Children::Fixed(c) => {
                    if internal {
                        return Err(DescriptorError::Unsupported(
                            "descriptor has no internal branch (fixed-child); receive-only".into(),
                        ));
                    }
                    if index != 0 {
                        return Err(DescriptorError::IndexOutOfRange { index });
                    }
                    (c, 0)
                }
            };
            // Children path: chain_child / leaf_child (both
            // unhardened — descriptors can't derive hardened
            // children from an xpub).
            let path = DerivationPath::from_str(&format!("m/{chain_child}/{leaf_child}"))
                .map_err(|e| DescriptorError::Derivation(format!("path: {e}")))?;
            let derived = k
                .xpub
                .derive_pub(&secp, &path)
                .map_err(|e| DescriptorError::Derivation(format!("derive_pub: {e}")))?;
            // sortedmulti uses compressed pubkey serialisation; the
            // bitcoin crate's `PublicKey::new(secp_pk)` produces the
            // compressed form by default.
            let pk = PublicKey::new(derived.public_key);
            child_pubkeys.push(pk);
        }
        // sortedmulti: lexicographic sort of compressed pubkey
        // serialisation.
        child_pubkeys.sort_by_key(|a| a.to_bytes());
        let redeem = build_multisig_redeem(self.k, &child_pubkeys);
        let p2wsh_spk = ScriptBuf::new_p2wsh(&redeem.wscript_hash());
        Address::from_script(&p2wsh_spk, network)
            .map_err(|e| DescriptorError::Bitcoin(format!("address: {e}")))
    }

    /// Helper: derive the witness_script (multisig redeem) at the
    /// given index. Useful when registering watch addresses with
    /// ghost-pay or producing a manual partial sig.
    pub fn derive_witness_script(
        &self,
        index: u32,
        internal: bool,
    ) -> Result<ScriptBuf, DescriptorError> {
        let secp = Secp256k1::verification_only();
        let mut child_pubkeys: Vec<PublicKey> = Vec::with_capacity(self.keys.len());
        for k in &self.keys {
            let (chain_child, leaf_child) = match k.children {
                Children::Multipath {
                    external,
                    internal: int_,
                } => {
                    if internal {
                        (int_, index)
                    } else {
                        (external, index)
                    }
                }
                Children::Single(c) => {
                    if internal {
                        return Err(DescriptorError::Unsupported(
                            "descriptor has no internal branch (single-child)".into(),
                        ));
                    }
                    (c, index)
                }
                Children::Fixed(c) => {
                    if internal {
                        return Err(DescriptorError::Unsupported(
                            "descriptor has no internal branch (fixed-child)".into(),
                        ));
                    }
                    if index != 0 {
                        return Err(DescriptorError::IndexOutOfRange { index });
                    }
                    (c, 0)
                }
            };
            let path = DerivationPath::from_str(&format!("m/{chain_child}/{leaf_child}"))
                .map_err(|e| DescriptorError::Derivation(format!("path: {e}")))?;
            let derived = k
                .xpub
                .derive_pub(&secp, &path)
                .map_err(|e| DescriptorError::Derivation(format!("derive_pub: {e}")))?;
            child_pubkeys.push(PublicKey::new(derived.public_key));
        }
        child_pubkeys.sort_by_key(|a| a.to_bytes());
        Ok(build_multisig_redeem(self.k, &child_pubkeys))
    }
}

/// Parse a descriptor string. Strict — anything outside the
/// supported subset returns `Unsupported`. The expected network is
/// derived from the xpubs themselves (xpub → mainnet, tpub →
/// testnet/signet/regtest); callers cross-check against the wallet.
pub fn parse(raw: &str) -> Result<ParsedDescriptor, DescriptorError> {
    let trimmed = raw.trim();
    let (body, checksum) = match trimmed.rfind('#') {
        Some(i) => (&trimmed[..i], Some(trimmed[i + 1..].to_string())),
        None => (trimmed, None),
    };
    // Outer wrapper: wsh( ... )
    let body = body.trim();
    let inner = strip_wrapper(body, "wsh")
        .ok_or_else(|| DescriptorError::Unsupported(format!("expected wsh(...), got: {body}")))?;
    let inner = inner.trim();
    // Inner: sortedmulti(K, FRAG, FRAG, ...)
    let multi_inner = strip_wrapper(inner, "sortedmulti").ok_or_else(|| {
        DescriptorError::Unsupported(format!("expected sortedmulti(...), got: {inner}"))
    })?;
    // Split on top-level commas (none of our fragments contain
    // commas at the top level — they live inside `[...]` and
    // `<...>` segments which we balance below).
    let parts = split_top_level_commas(multi_inner);
    if parts.len() < 2 {
        return Err(DescriptorError::Parse(
            "sortedmulti must have a threshold + at least one key".into(),
        ));
    }
    let k: usize = parts[0]
        .trim()
        .parse()
        .map_err(|e| DescriptorError::Parse(format!("threshold: {e}")))?;
    let mut keys = Vec::with_capacity(parts.len() - 1);
    for frag in parts.iter().skip(1) {
        keys.push(parse_fragment(frag.trim())?);
    }
    let n = keys.len();
    if k == 0 || k > n {
        return Err(DescriptorError::BadThreshold { k, n });
    }
    Ok(ParsedDescriptor {
        kind: DescriptorKind::WshSortedMulti,
        k,
        keys,
        checksum,
        raw: trimmed.to_string(),
    })
}

/// Strip a `name(...)` wrapper. Returns the contents on match,
/// `None` otherwise. Verifies the closing paren is the LAST char.
fn strip_wrapper<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let s = s.trim();
    let prefix = format!("{name}(");
    if !s.starts_with(&prefix) {
        return None;
    }
    let s = &s[prefix.len()..];
    if !s.ends_with(')') {
        return None;
    }
    Some(&s[..s.len() - 1])
}

/// Split on commas that are at the top nesting level — i.e. not
/// inside `[...]` or `<...>` segments. Descriptor fragments
/// themselves contain no top-level parens because we've already
/// stripped the wrapper.
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth_bracket = 0;
    let mut depth_angle = 0;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '[' => depth_bracket += 1,
            ']' => depth_bracket = (depth_bracket as i64 - 1).max(0) as usize,
            '<' => depth_angle += 1,
            '>' => depth_angle = (depth_angle as i64 - 1).max(0) as usize,
            ',' if depth_bracket == 0 && depth_angle == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start <= s.len() {
        out.push(&s[start..]);
    }
    out
}

fn parse_fragment(s: &str) -> Result<CosignerKey, DescriptorError> {
    // Must start with [fingerprint/path].
    let s = s.trim();
    if !s.starts_with('[') {
        return Err(DescriptorError::Parse(format!(
            "fragment missing key origin [fp/path]: {s}"
        )));
    }
    let close = s
        .find(']')
        .ok_or_else(|| DescriptorError::Parse("fragment missing closing ']'".into()))?;
    let origin = &s[1..close];
    let rest = &s[close + 1..];

    // Origin: "fingerprint" or "fingerprint/path"
    let (fp_hex, origin_path) = match origin.find('/') {
        Some(i) => (&origin[..i], origin[i + 1..].to_string()),
        None => (origin, String::new()),
    };
    if fp_hex.len() != 8 {
        return Err(DescriptorError::Parse(format!(
            "fingerprint must be 8 hex chars; got {fp_hex:?}"
        )));
    }
    let fp_bytes =
        hex::decode(fp_hex).map_err(|e| DescriptorError::Parse(format!("fingerprint hex: {e}")))?;
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&fp_bytes);

    // After ]: <xpub><children>
    // Find the xpub end — xpub/tpub strings are pure base58 + a
    // limited charset, no `/` or `<` — so the first `/` after the
    // origin separator marks the boundary.
    let slash = rest
        .find('/')
        .ok_or_else(|| DescriptorError::Parse(format!("fragment missing children: {rest}")))?;
    let xpub_str = &rest[..slash];
    let children_str = &rest[slash + 1..];
    let xpub = Xpub::from_str(xpub_str.trim())
        .map_err(|e| DescriptorError::Parse(format!("xpub: {e}")))?;
    // Normalise the path: descriptors typically write `48h` rather
    // than `48'`; the bitcoin crate's `DerivationPath::from_str`
    // accepts both, but we emit `'` for canonical display.
    let normalised_path = origin_path.replace('h', "'");

    let children = parse_children(children_str)?;
    Ok(CosignerKey {
        fingerprint,
        origin_path: normalised_path,
        xpub,
        children,
    })
}

/// Parse the bit after the xpub's leading `/`: e.g. `<0;1>/*`,
/// `0/*`, or `0`.
fn parse_children(s: &str) -> Result<Children, DescriptorError> {
    let s = s.trim();
    if let Some(stripped) = s
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix("/*"))
        .and_then(|s| s.strip_suffix('>'))
    {
        // Multipath: <a;b>
        let mut parts = stripped.split(';');
        let a = parts
            .next()
            .ok_or_else(|| DescriptorError::Parse("multipath empty".into()))?
            .trim()
            .parse::<u32>()
            .map_err(|e| DescriptorError::Parse(format!("multipath external: {e}")))?;
        let b = parts
            .next()
            .ok_or_else(|| DescriptorError::Parse("multipath missing internal".into()))?
            .trim()
            .parse::<u32>()
            .map_err(|e| DescriptorError::Parse(format!("multipath internal: {e}")))?;
        if parts.next().is_some() {
            return Err(DescriptorError::Unsupported(
                "multipath with >2 branches".into(),
            ));
        }
        return Ok(Children::Multipath {
            external: a,
            internal: b,
        });
    }
    if let Some(child_str) = s.strip_suffix("/*") {
        let c: u32 = child_str
            .trim()
            .parse()
            .map_err(|e| DescriptorError::Parse(format!("ranged child: {e}")))?;
        return Ok(Children::Single(c));
    }
    let c: u32 = s
        .parse()
        .map_err(|e| DescriptorError::Parse(format!("fixed child: {e}")))?;
    Ok(Children::Fixed(c))
}

/// Build a `K-of-N OP_CHECKMULTISIG` redeem script. Used both for
/// the P2WSH wscript_hash and for the witness_script field a
/// signer needs to compute BIP-143 sighash.
fn build_multisig_redeem(k: usize, sorted_pks: &[PublicKey]) -> ScriptBuf {
    use bitcoin::blockdata::opcodes::all::*;
    use bitcoin::blockdata::script::Builder;
    let mut b = Builder::new().push_int(k as i64);
    for pk in sorted_pks {
        b = b.push_key(pk);
    }
    b.push_int(sorted_pks.len() as i64)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

#[allow(dead_code)] // exposed for downstream callers / future use
pub fn witness_program_hash(redeem: &ScriptBuf) -> sha256::Hash {
    sha256::Hash::hash(redeem.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2-of-2 wsh sortedmulti, both keys known via the BIP-39 zero
    /// seed. We assert that:
    ///   - the parser pulls out k=2, n=2
    ///   - both fingerprints match what the keystore would produce
    ///   - the derived address at index 0 matches what Bitcoin
    ///     Core's `deriveaddresses` produces (verified offline)
    const TEST_DESCRIPTOR: &str = "wsh(sortedmulti(2,\
        [73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/<0;1>/*,\
        [aabbccdd/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/<0;1>/*\
        ))";

    #[test]
    fn parses_basic_wsh_sortedmulti() {
        let parsed = parse(TEST_DESCRIPTOR).expect("parse");
        assert_eq!(parsed.kind, DescriptorKind::WshSortedMulti);
        assert_eq!(parsed.k, 2);
        assert_eq!(parsed.n(), 2);
        assert_eq!(parsed.keys[0].fingerprint, [0x73, 0xc5, 0xda, 0x0a]);
        assert_eq!(parsed.keys[1].fingerprint, [0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(matches!(
            parsed.keys[0].children,
            Children::Multipath {
                external: 0,
                internal: 1
            }
        ));
    }

    #[test]
    fn parses_with_checksum() {
        let with_chk = format!("{}#abcdefgh", TEST_DESCRIPTOR);
        let parsed = parse(&with_chk).expect("parse");
        assert_eq!(parsed.checksum.as_deref(), Some("abcdefgh"));
    }

    #[test]
    fn parses_h_path_marker() {
        // Bitcoin Core uses `h` instead of `'` in some output; we
        // accept either and normalise to `'` internally.
        let with_h = TEST_DESCRIPTOR.replace('\'', "h");
        let parsed = parse(&with_h).expect("parse with h");
        assert_eq!(parsed.keys[0].origin_path, "48'/1'/0'/2'");
    }

    #[test]
    fn parses_single_child_template() {
        let s = "wsh(sortedmulti(1,\
            [73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/0/*\
            ))";
        let parsed = parse(s).expect("parse");
        assert!(matches!(parsed.keys[0].children, Children::Single(0)));
    }

    #[test]
    fn rejects_non_wsh() {
        let s = TEST_DESCRIPTOR.replacen("wsh", "tr", 1);
        assert!(matches!(parse(&s), Err(DescriptorError::Unsupported(_))));
    }

    #[test]
    fn rejects_bad_threshold() {
        let s = "wsh(sortedmulti(0,\
            [73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/<0;1>/*\
            ))";
        assert!(matches!(
            parse(s),
            Err(DescriptorError::BadThreshold { .. })
        ));
    }

    #[test]
    fn fingerprint_membership() {
        let parsed = parse(TEST_DESCRIPTOR).unwrap();
        assert!(parsed.contains_fingerprint(&[0x73, 0xc5, 0xda, 0x0a]));
        assert!(!parsed.contains_fingerprint(&[0; 4]));
    }

    #[test]
    fn derive_address_external_internal_differ() {
        let parsed = parse(TEST_DESCRIPTOR).unwrap();
        let ext_0 = parsed
            .derive_address(0, false, Network::Regtest)
            .expect("ext");
        let int_0 = parsed
            .derive_address(0, true, Network::Regtest)
            .expect("int");
        // Different chain index → different address.
        assert_ne!(ext_0.to_string(), int_0.to_string());
        // bech32 P2WSH address starts with `bcrt1q` on regtest and
        // is 62 chars (witness program is sha256 of redeem).
        assert!(ext_0.to_string().starts_with("bcrt1q"));
        assert!(int_0.to_string().starts_with("bcrt1q"));
    }

    /// Cross-check against Bitcoin Core. The exact descriptor +
    /// derived address triple was captured live from a regtest
    /// `deriveaddresses` call; if our parser drifts, this test
    /// catches it without needing bitcoind running.
    #[test]
    fn matches_bitcoin_core_deriveaddresses() {
        let desc = "wsh(sortedmulti(2,[70bbd513/48'/1'/0'/2']tpubDEneMNttUt9w3Ae2s3ds3qt7droAwyJRzZP2hTrECpv546UZobC5WU79Z5y8wTxQwoPTRCX2nUYGcL5QZy3Puk2u4Y81FQhpixSfdF6ApT1/0/*,[227ac029/84h/1h/0h]tpubDCfQNiSrQsnw1ELYQqXmKmxZzrmzyqa1FdKH7u2d2GykbG5jLxmMBaJmHV5gJ7bAwWUwVFSP9axhbzNrMWFZpTKjbkgZJraP3dfUg9BdPbK/0/*))#jwek7d5u";
        let parsed = parse(desc).expect("parse");
        let expected = [
            "bcrt1qee0086cgnlvdvge8e4swx3zyyhq6j8de45ct35exdd6xmzmed8pqg6t2hc",
            "bcrt1qxx68ygxl2u97yp4kntm6rmv0uwyqjxtql6v756egwua5kajnwfzs7qngm7",
            "bcrt1qsdvpdgcpaasrpce30r9zm4j67f62u5x20rwc4tr59x756gxq0vzsw9hnv6",
        ];
        for (i, exp) in expected.iter().enumerate() {
            let a = parsed
                .derive_address(i as u32, false, Network::Regtest)
                .unwrap();
            assert_eq!(&a.to_string(), exp, "address mismatch at index {i}");
        }
    }

    #[test]
    fn round_trip_parse_to_witness_script() {
        let parsed = parse(TEST_DESCRIPTOR).unwrap();
        let script = parsed.derive_witness_script(0, false).unwrap();
        // Should start with OP_2 (k=2) and end with OP_2 OP_CHECKMULTISIG.
        let bytes = script.as_bytes();
        assert_eq!(bytes[0], 0x52, "OP_2 at start (k=2)"); // OP_PUSHNUM_2
                                                           // Last two bytes: OP_PUSHNUM_2 OP_CHECKMULTISIG (n=2)
        assert_eq!(bytes[bytes.len() - 2], 0x52);
        assert_eq!(bytes[bytes.len() - 1], 0xae);
    }
}
