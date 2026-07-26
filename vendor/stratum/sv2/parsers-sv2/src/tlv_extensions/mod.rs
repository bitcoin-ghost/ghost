//! TLV field implementations for known SV2 extensions.
//!
//! This module provides `TlvField` trait implementations for extension types
//! defined in the `extensions_sv2` crate, along with extension-specific error types.

mod error;

pub use error::{ExtensionError, UserIdentityError};

use super::{Tlv, TlvField};
use crate::ParserError;
use extensions_sv2::{
    UserIdentity, EXTENSION_TYPE_WORKER_HASHRATE_TRACKING, MAX_USER_IDENTITY_LENGTH,
    TLV_FIELD_TYPE_USER_IDENTITY,
};

extern crate alloc;
use alloc::vec::Vec;

// NOTE: `MAX_USER_IDENTITY_LENGTH` is imported from `extensions_sv2`, which owns
// `UserIdentity`, rather than redeclared here.
//
// This module previously kept its own `const MAX_USER_IDENTITY_LENGTH: usize = 32`. Two
// constants of the same name in different crates silently diverged: raising the one in
// `extensions_sv2` fixed `UserIdentity::new` but left this copy gating `to_tlv`/`from_tlv`,
// so an over-long identity still failed to encode — and because the caller discarded the
// error, the share went out with NO identity TLV and was credited to the channel's
// (possibly provisional) identity instead of the miner. Keeping a single owner of the limit
// makes that class of drift impossible.

/// Implementation of TlvField trait for UserIdentity.
///
/// This provides the standard interface for encoding/decoding UserIdentity
/// as a TLV field in the Worker-Specific Hashrate Tracking extension.
impl TlvField for UserIdentity {
    const EXTENSION_TYPE: u16 = EXTENSION_TYPE_WORKER_HASHRATE_TRACKING;
    const FIELD_TYPE: u8 = TLV_FIELD_TYPE_USER_IDENTITY;

    /// Decodes a TLV from raw bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Tlv, ParserError> {
        // TlvError auto-converts to ParserError::TlvError
        Tlv::decode(bytes).map_err(Into::into)
    }

    /// Encodes this UserIdentity as raw TLV bytes.
    fn to_bytes(&self) -> Result<Vec<u8>, ParserError> {
        let tlv = self.to_tlv()?;
        // TlvError auto-converts to ParserError::TlvError
        tlv.encode().map_err(Into::into)
    }

    /// Creates a UserIdentity from a parsed TLV.
    fn from_tlv(tlv: &Tlv) -> Result<Self, ParserError> {
        // Verify extension type
        if tlv.r#type.extension_type != Self::EXTENSION_TYPE {
            // UserIdentityError -> ExtensionError -> ParserError
            return Err(UserIdentityError::InvalidExtensionType(tlv.r#type.extension_type).into());
        }

        // Verify field type
        if tlv.r#type.field_type != Self::FIELD_TYPE {
            return Err(UserIdentityError::InvalidFieldType(tlv.r#type.field_type).into());
        }

        // Enforce the identity length cap (MAX_USER_IDENTITY_LENGTH, owned by
        // extensions_sv2). It was 32, which truncated a full `<address>.<worker>`.
        if tlv.value.len() > MAX_USER_IDENTITY_LENGTH {
            return Err(UserIdentityError::TooLong(tlv.value.len()).into());
        }

        // Create UserIdentity from raw bytes
        UserIdentity::from_bytes(&tlv.value)
            .map_err(|e| UserIdentityError::InvalidUtf8(e.into()).into())
    }

    /// Converts this UserIdentity into a TLV structure.
    fn to_tlv(&self) -> Result<Tlv, ParserError> {
        // Validate length
        if self.as_bytes().len() > MAX_USER_IDENTITY_LENGTH {
            return Err(UserIdentityError::TooLong(self.as_bytes().len()).into());
        }

        Ok(Tlv::new(
            Self::EXTENSION_TYPE,
            Self::FIELD_TYPE,
            self.as_bytes().to_vec(),
        ))
    }
}
