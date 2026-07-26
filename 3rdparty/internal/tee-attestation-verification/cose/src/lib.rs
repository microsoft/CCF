// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Sign1 verification backed by `tee-attestation-verification-crypto`.
//!
//! This crate is intentionally verification-only. It exposes:
//!
//! - [`CborValue`] for parsing CBOR/COSE envelopes;
//! - [`synchronous::cose_verify1`] for COSE_Sign1 signature verification when a
//!   synchronous crypto backend is selected;
//! - [`asynchronous::cose_verify1`] for COSE_Sign1 signature verification when
//!   an asynchronous crypto backend is selected.
//!
//! # Verifying a COSE_Sign1 envelope
//!
//! COSE_Sign1 is CBOR tag 18 over an array containing protected-header bytes,
//! an unprotected-header map, payload, and signature. Parse the envelope with
//! [`CborValue::from_bytes`], import the signer public key through the active
//! backend, then pass the envelope components to the verifier.
//!
//! ```no_run
//! use tee_attestation_verification_cose::{
//!     synchronous as tav_cose, CborValue, Key, KeyBackend, RsaPssSignatureKeyAlgorithm,
//!     SignatureKeyAlgorithm,
//! };
//!
//! # fn example(
//! #     cose_sign1: &[u8],
//! #     signer_spki_der: &[u8],
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let envelope = CborValue::from_bytes(cose_sign1)?;
//! let sign1 = match envelope {
//!     CborValue::Tagged { tag: 18, payload } => *payload,
//!     _ => return Err("expected COSE_Sign1 tag".into()),
//! };
//!
//! let protected_header = match sign1.array_at(0)? {
//!     CborValue::ByteString(bytes) => bytes,
//!     _ => return Err("protected header must be a byte string".into()),
//! };
//! let payload = match sign1.array_at(2)? {
//!     CborValue::ByteString(bytes) => bytes,
//!     _ => return Err("payload must be a byte string".into()),
//! };
//! let signature = match sign1.array_at(3)? {
//!     CborValue::ByteString(bytes) => bytes,
//!     _ => return Err("signature must be a byte string".into()),
//! };
//!
//! let algorithm = SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384);
//! let key = <Key as KeyBackend>::from_spki_der(signer_spki_der, algorithm)?;
//!
//! tav_cose::cose_verify1(&key, algorithm, protected_header, payload, signature)?;
//! # Ok(())
//! # }
//! ```

mod cbor;
mod cose;

pub use cbor::{CborValue, MAX_CBOR_NESTING_DEPTH};
pub use cose::*;

#[cfg(sync_crypto)]
pub mod synchronous {
    pub use crate::cose::cose_verify1;
}

#[cfg(async_crypto)]
pub mod asynchronous {
    pub use crate::cose::cose_verify1_async as cose_verify1;
}

pub use crypto::{
    EcSignatureKeyAlgorithm, Key, KeyBackend, RsaPssSignatureKeyAlgorithm, SignatureKeyAlgorithm,
};
