//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: node_pool_u256.rs                                                                                              |
//|======================================================================================================================|

//! A minimal unsigned 256-bit integer for the node pool's consensus arithmetic.
//!
//! Only what the payout rule, the share check and the anchor chain need: a widening multiply,
//! shifts that report lost bits, addition that reports overflow, division by a small divisor, and
//! ordering. Kept local rather than pulling a big-integer crate into every node binary; the
//! `bitcoin` crate's own `U256` is private.

use std::cmp::Ordering;

/// Unsigned 256-bit integer, four little-endian 64-bit limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct U256([u64; 4]);

impl U256 {
    /// Zero.
    pub const ZERO: U256 = U256([0; 4]);

    /// From a `u128`.
    pub const fn from_u128(v: u128) -> U256 {
        U256([v as u64, (v >> 64) as u64, 0, 0])
    }

    /// `2^bit`, or `None` when `bit >= 256`.
    pub fn pow2(bit: u32) -> Option<U256> {
        if bit >= 256 {
            return None;
        }
        let mut limbs = [0u64; 4];
        limbs[(bit / 64) as usize] = 1u64 << (bit % 64);
        Some(U256(limbs))
    }

    /// The full 256-bit product of two `u128`s. Never overflows.
    pub fn mul_u128(a: u128, b: u128) -> U256 {
        let a = [a as u64, (a >> 64) as u64];
        let b = [b as u64, (b >> 64) as u64];
        let mut out = [0u64; 4];
        for (i, &ai) in a.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &bj) in b.iter().enumerate() {
                let cur = out[i + j] as u128 + (ai as u128) * (bj as u128) + carry;
                out[i + j] = cur as u64;
                carry = cur >> 64;
            }
            out[i + 2] = carry as u64;
        }
        U256(out)
    }

    /// Big-endian bytes, as a hash is read for proof of work after reversing it.
    pub fn from_be_bytes(bytes: [u8; 32]) -> U256 {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = 32 - 8 * (i + 1);
            *limb = u64::from_be_bytes(bytes[start..start + 8].try_into().expect("8 bytes"));
        }
        U256(limbs)
    }

    /// Little-endian bytes: the numeric value of a Bitcoin hash in its internal byte order.
    pub fn from_le_bytes(bytes: [u8; 32]) -> U256 {
        let mut be = bytes;
        be.reverse();
        U256::from_be_bytes(be)
    }

    /// Big-endian bytes.
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            let start = 32 - 8 * (i + 1);
            out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// Number of significant bits.
    pub fn bits(self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return 64 * i as u32 + 64 - self.0[i].leading_zeros();
            }
        }
        0
    }

    /// `self << s`, or `None` if any set bit would be shifted out.
    pub fn checked_shl(self, s: u32) -> Option<U256> {
        if self == U256::ZERO {
            return Some(self);
        }
        if self.bits() + s > 256 {
            return None;
        }
        Some(self.shl_lossy(s))
    }

    fn shl_lossy(self, s: u32) -> U256 {
        if s >= 256 {
            return U256::ZERO;
        }
        let (limbs, bits) = ((s / 64) as usize, s % 64);
        let mut out = [0u64; 4];
        for i in (limbs..4).rev() {
            let src = i - limbs;
            out[i] = self.0[src] << bits;
            if bits > 0 && src > 0 {
                out[i] |= self.0[src - 1] >> (64 - bits);
            }
        }
        U256(out)
    }

    /// `self >> s`, flooring; zero when `s >= 256`.
    pub fn shr_floor(self, s: u32) -> U256 {
        if s >= 256 {
            return U256::ZERO;
        }
        let (limbs, bits) = ((s / 64) as usize, s % 64);
        let mut out = [0u64; 4];
        for (i, slot) in out.iter_mut().enumerate().take(4 - limbs) {
            let src = i + limbs;
            *slot = self.0[src] >> bits;
            if bits > 0 && src + 1 < 4 {
                *slot |= self.0[src + 1] << (64 - bits);
            }
        }
        U256(out)
    }

    /// `self + rhs`, or `None` on overflow.
    pub fn checked_add(self, rhs: U256) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut carry = false;
        for (i, slot) in out.iter_mut().enumerate() {
            let (s1, c1) = self.0[i].overflowing_add(rhs.0[i]);
            let (s2, c2) = s1.overflowing_add(carry as u64);
            *slot = s2;
            carry = c1 || c2;
        }
        (!carry).then_some(U256(out))
    }

    /// `floor(self / d)` for a non-zero 64-bit divisor.
    pub fn div_u64(self, d: u64) -> U256 {
        assert!(d != 0, "division by zero");
        let mut out = [0u64; 4];
        let mut rem = 0u128;
        for i in (0..4).rev() {
            let cur = (rem << 64) | self.0[i] as u128;
            out[i] = (cur / d as u128) as u64;
            rem = cur % d as u128;
        }
        U256(out)
    }

    /// The value as a `u128`, or `None` if it does not fit.
    pub fn to_u128(self) -> Option<u128> {
        (self.0[2] == 0 && self.0[3] == 0).then(|| self.0[0] as u128 | (self.0[1] as u128) << 64)
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_shift_div_round_trip() {
        let p = U256::mul_u128(u128::MAX, u128::MAX);
        // (2^128 - 1)^2 = 2^256 - 2^129 + 1
        assert_eq!(p.bits(), 256);
        assert_eq!(p.0[0], 1);
        assert_eq!(p.checked_shl(1), None);
        let x = U256::from_u128(0xFFFF_1234_5678_9ABC_DEF0);
        let y = x.checked_shl(100).expect("fits");
        assert_eq!(y.shr_floor(100), x);
        assert_eq!(y.shr_floor(300), U256::ZERO);
        assert_eq!(
            U256::from_u128(1_000_003).div_u64(1_000).to_u128(),
            Some(1_000)
        );
        assert_eq!(y.div_u64(0xFFFF).shr_floor(0).to_u128(), None);
    }

    #[test]
    fn byte_orders_and_ordering() {
        let mut le = [0u8; 32];
        le[31] = 1; // most significant byte last in internal order
        let v = U256::from_le_bytes(le);
        assert_eq!(v, U256::pow2(248).unwrap());
        assert_eq!(U256::from_be_bytes(v.to_be_bytes()), v);
        assert!(U256::pow2(10).unwrap() < U256::pow2(11).unwrap());
        assert!(U256::from_u128(u128::MAX) < U256::pow2(128).unwrap());
        assert_eq!(
            U256::pow2(255)
                .unwrap()
                .checked_add(U256::pow2(255).unwrap()),
            None
        );
        assert_eq!(U256::pow2(256), None);
    }
}
