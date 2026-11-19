// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C ABI bindings for COSE_Sign1 validation and verification.
//!
//! Validated handles share their input's immutable CBOR document. Release each
//! owned handle with [`super::cbor::tav_cbor_free`]. Borrowed input must remain
//! alive and unchanged until all derived handles have been released.

use super::cbor::{into_view_handle, TavCborHandle};
use super::utils::{input_bytes, owned_out_ptr};
use crate::cbor_view::NativeCborValue;
use crate::{into_result, TavError, TavErrorCode};
use cose::{cose_sign1, signature_key_algorithm_for_cose_alg};
use crypto::{CryptoBackend, KeyBackend};

unsafe fn cbor_handle<'a>(
    value: *const TavCborHandle,
    name: &str,
) -> Result<&'a TavCborHandle, TavError> {
    unsafe { value.as_ref() }.ok_or_else(|| TavError::invalid_argument(format!("{name} is null")))
}

fn borrowed_bytes<'a>(value: &'a NativeCborValue, name: &str) -> Result<&'a [u8], TavError> {
    match value {
        NativeCborValue::ByteString(value) => Ok(value),
        _ => Err(TavError::new(
            TavErrorCode::CoseUnexpectedType,
            format!("{name} must be a byte string"),
        )),
    }
}

fn require_detached_payload(sign1: &NativeCborValue) -> Result<(), TavError> {
    match sign1_field(sign1, 2, "payload")? {
        NativeCborValue::Simple(22) => Ok(()),
        NativeCborValue::ByteString(_) => Err(TavError::new(
            TavErrorCode::CoseUnexpectedType,
            "detached payload verification requires nil COSE payload; use embedded verification for byte string payloads",
        )),
        _ => Err(TavError::new(
            TavErrorCode::CoseUnexpectedType,
            "detached payload verification requires nil COSE payload",
        )),
    }
}

fn sign1_field<'a>(
    sign1: &'a NativeCborValue,
    index: usize,
    name: &str,
) -> Result<&'a NativeCborValue, TavError> {
    sign1.array_at(index).map_err(|error| {
        TavError::new(
            TavErrorCode::CoseCbor,
            format!("Failed to read {name}: {error}"),
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_validate_cose_sign1(
    value: *const TavCborHandle,
    out_sign1: *mut *mut TavCborHandle,
) -> *mut TavError {
    into_result(|| {
        unsafe { owned_out_ptr(out_sign1, "out_sign1") }?;
        let handle = unsafe { cbor_handle(value, "value") }?;
        let [sign1] = handle.project(|value| {
            cose_sign1(value)
                .map(|sign1| [sign1])
                .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))
        })?;
        unsafe { *out_sign1 = into_view_handle(sign1) };
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_verify_cose_sign1_embedded(
    sign1: *const TavCborHandle,
    spki_der: *const u8,
    spki_der_len: usize,
    cose_alg: i32,
) -> *mut TavError {
    into_result(|| {
        let value = unsafe { cbor_handle(sign1, "sign1") }?.as_native();
        let sign1 =
            cose_sign1(value).map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        let payload = borrowed_bytes(sign1_field(sign1, 2, "payload")?, "payload")?;
        verify_sign1(sign1, payload, spki_der, spki_der_len, cose_alg)
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_verify_cose_sign1_detached(
    sign1: *const TavCborHandle,
    payload: *const u8,
    payload_len: usize,
    spki_der: *const u8,
    spki_der_len: usize,
    cose_alg: i32,
) -> *mut TavError {
    into_result(|| {
        let value = unsafe { cbor_handle(sign1, "sign1") }?.as_native();
        let sign1 =
            cose_sign1(value).map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        require_detached_payload(sign1)?;
        let payload = unsafe { input_bytes(payload, payload_len, "payload", true) }?;
        verify_sign1(sign1, payload, spki_der, spki_der_len, cose_alg)
    })
}

fn verify_sign1(
    sign1: &NativeCborValue,
    payload: &[u8],
    spki_der: *const u8,
    spki_der_len: usize,
    cose_alg: i32,
) -> Result<(), TavError> {
    let protected = borrowed_bytes(sign1_field(sign1, 0, "protected")?, "protected")?;
    let signature = borrowed_bytes(sign1_field(sign1, 3, "signature")?, "signature")?;
    let spki_der = unsafe { input_bytes(spki_der, spki_der_len, "SPKI DER", false) }?;
    let algorithm = signature_key_algorithm_for_cose_alg(cose_alg as i64)
        .map_err(|error| TavError::new(TavErrorCode::CoseUnsupportedAlgorithm, error))?;
    let key =
        <<crypto::Crypto as CryptoBackend>::Key as KeyBackend>::from_spki_der(spki_der, algorithm)
            .map_err(|error| TavError::new(TavErrorCode::CoseKeyImport, error.to_string()))?;
    cose::synchronous::cose_verify1(&key, algorithm, protected, payload, signature)
        .map_err(|error| TavError::new(TavErrorCode::CoseVerification, error))
}

#[cfg(test)]
mod tests {
    #[test]
    fn c_header_enums_match_rust_enums() {
        let header = include_str!("../../include/tav/cose.h");
        let expected = [
            ("TAV_COSE_ALG_ES256", cose::COSE_ALG_ES256 as i32),
            ("TAV_COSE_ALG_ES384", cose::COSE_ALG_ES384 as i32),
            ("TAV_COSE_ALG_ES512", cose::COSE_ALG_ES512 as i32),
            ("TAV_COSE_ALG_PS256", cose::COSE_ALG_PS256 as i32),
            ("TAV_COSE_ALG_PS384", cose::COSE_ALG_PS384 as i32),
            ("TAV_COSE_ALG_PS512", cose::COSE_ALG_PS512 as i32),
            ("TAV_COSE_TAG_SIGN1", cose::COSE_SIGN1_TAG as i32),
            (
                "TAV_COSE_SIGN1_PROTECTED",
                cose::COSE_SIGN1_PROTECTED as i32,
            ),
            (
                "TAV_COSE_SIGN1_UNPROTECTED",
                cose::COSE_SIGN1_UNPROTECTED as i32,
            ),
            ("TAV_COSE_SIGN1_PAYLOAD", cose::COSE_SIGN1_PAYLOAD as i32),
            (
                "TAV_COSE_SIGN1_SIGNATURE",
                cose::COSE_SIGN1_SIGNATURE as i32,
            ),
            ("TAV_COSE_HEADER_ALG", cose::COSE_HEADER_ALG as i32),
            (
                "TAV_COSE_HEADER_CWT_CLAIMS",
                cose::COSE_HEADER_CWT_CLAIMS as i32,
            ),
            ("TAV_COSE_HEADER_X5CHAIN", cose::COSE_HEADER_X5CHAIN as i32),
            (
                "TAV_COSE_HEADER_CONTENT_TYPE",
                cose::COSE_HEADER_CONTENT_TYPE as i32,
            ),
            (
                "TAV_COSE_HEADER_PREIMAGE_CONTENT_TYPE",
                cose::COSE_HEADER_PREIMAGE_CONTENT_TYPE as i32,
            ),
            ("TAV_CWT_CLAIMS_ISSUER", cose::CWT_CLAIMS_ISSUER as i32),
            ("TAV_CWT_CLAIMS_SUBJECT", cose::CWT_CLAIMS_SUBJECT as i32),
            ("TAV_CWT_CLAIMS_IAT", cose::CWT_CLAIMS_IAT as i32),
        ];
        let declared: Vec<(&str, i32)> = header
            .lines()
            .filter_map(|line| {
                let (name, value) = line.trim().split_once('=')?;
                let name = name.trim();
                (name.starts_with("TAV_COSE_") || name.starts_with("TAV_CWT_"))
                    .then(|| (name, value.trim().trim_end_matches(',').parse().unwrap()))
            })
            .collect();
        let actual: std::collections::BTreeMap<_, _> = declared.iter().copied().collect();
        assert_eq!(declared.len(), actual.len(), "duplicate C constants");
        assert_eq!(actual, expected.into_iter().collect());
    }
}
