// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C ABI bindings for CBOR navigation and COSE_Sign1 verification.
//!
//! This module exports the symbols declared in `ffi/include/tav/cose.h`.
//!
//! `TavCborValue` handles returned by [`tav_cbor_value_from_bytes`] are
//! owned and must be released with [`tav_cbor_value_free`]. Child accessors
//! return borrowed handles into the owned root. Borrowed handles must not be
//! freed and remain valid only while the ancestor owned handle is alive.

use std::os::raw::c_char;

use super::utils::{input_bytes, input_text, out_ptr, owned_out_ptr, TavByteBuffer};
use crate::{into_result, TavError, TavErrorCode};
use std::ptr;

use crypto::{CryptoBackend, KeyBackend};

use cose::{cose_sign1, signature_key_algorithm_for_cose_alg, CborValue as NativeCborValue};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TavCborKind {
    Int = 1,
    Simple = 2,
    Bytes = 3,
    Text = 4,
    Array = 5,
    Map = 6,
    Tagged = 7,
}

#[repr(transparent)]
pub struct TavCborValue {
    inner: NativeCborValue,
}

impl TavCborValue {
    fn from_native(inner: NativeCborValue) -> Self {
        Self { inner }
    }

    fn as_native(&self) -> &NativeCborValue {
        &self.inner
    }

    fn borrowed(value: &NativeCborValue) -> *const Self {
        value as *const NativeCborValue as *const Self
    }
}

unsafe fn scalar_out_ptr<T: Default>(out: *mut T, name: &str) -> Result<(), TavError> {
    unsafe { out_ptr(out, name) }?;
    unsafe {
        *out = T::default();
    }
    Ok(())
}

unsafe fn borrowed_out_ptr<T>(out: *mut *const T, name: &str) -> Result<(), TavError> {
    unsafe { out_ptr(out, name) }?;
    unsafe {
        *out = ptr::null();
    }
    Ok(())
}

unsafe fn cbor_value<'a>(
    value: *const TavCborValue,
    name: &str,
) -> Result<&'a NativeCborValue, TavError> {
    if value.is_null() {
        return Err(TavError::invalid_argument(format!("{name} is null")));
    }
    Ok(unsafe { (*value).as_native() })
}

fn kind(value: &NativeCborValue) -> TavCborKind {
    match value {
        NativeCborValue::Int(_) => TavCborKind::Int,
        NativeCborValue::Simple(_) => TavCborKind::Simple,
        NativeCborValue::ByteString(_) => TavCborKind::Bytes,
        NativeCborValue::TextString(_) => TavCborKind::Text,
        NativeCborValue::Array(_) => TavCborKind::Array,
        NativeCborValue::Map(_) => TavCborKind::Map,
        NativeCborValue::Tagged { .. } => TavCborKind::Tagged,
    }
}

fn borrowed_bytes<'a>(value: &'a NativeCborValue, name: &str) -> Result<&'a [u8], TavError> {
    match value {
        NativeCborValue::ByteString(bytes) => Ok(bytes),
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

fn map_entry_at(
    value: &NativeCborValue,
    index: usize,
) -> Result<(&NativeCborValue, &NativeCborValue), TavError> {
    match value {
        NativeCborValue::Map(entries) => entries
            .get(index)
            .map(|(key, value)| (key, value))
            .ok_or_else(|| {
                TavError::new(
                    TavErrorCode::CoseCbor,
                    format!("Index {index} out of bounds"),
                )
            }),
        _ => Err(TavError::new(
            TavErrorCode::CoseUnexpectedType,
            "value must be a map",
        )),
    }
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_from_bytes(
    bytes: *const u8,
    len: usize,
    out_value: *mut *mut TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { owned_out_ptr(out_value, "out_value") }?;
        let bytes = unsafe { input_bytes(bytes, len, "CBOR bytes", false) }?;
        let value = NativeCborValue::from_bytes(bytes)
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out_value = Box::into_raw(Box::new(TavCborValue::from_native(value)));
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_to_bytes(
    value: *const TavCborValue,
    out_bytes: *mut *mut TavByteBuffer,
) -> *mut TavError {
    into_result(|| {
        unsafe { owned_out_ptr(out_bytes, "out_bytes") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let bytes = value
            .to_bytes()
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out_bytes = Box::into_raw(TavByteBuffer::from_bytes(bytes));
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_kind(value: *const TavCborValue) -> TavCborKind {
    kind(unsafe { (*value).as_native() })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_int(
    value: *const TavCborValue,
    out: *mut i64,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let int = match value {
            NativeCborValue::Int(value) => *value,
            _ => {
                return Err(TavError::new(
                    TavErrorCode::CoseUnexpectedType,
                    "value must be an int",
                ))
            }
        };
        unsafe {
            *out = int;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_simple(
    value: *const TavCborValue,
    out: *mut u8,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let simple = match value {
            NativeCborValue::Simple(value) => *value,
            _ => {
                return Err(TavError::new(
                    TavErrorCode::CoseUnexpectedType,
                    "value must be simple",
                ))
            }
        };
        unsafe {
            *out = simple;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_bytes(
    value: *const TavCborValue,
    data: *mut *const u8,
    len: *mut usize,
) -> *mut TavError {
    into_result(|| {
        unsafe {
            borrowed_out_ptr(data, "data")?;
            scalar_out_ptr(len, "len")?;
        }
        let value = unsafe { cbor_value(value, "value") }?;
        let bytes = borrowed_bytes(value, "value")?;
        unsafe {
            *data = bytes.as_ptr();
            *len = bytes.len();
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_text(
    value: *const TavCborValue,
    text: *mut *const c_char,
    len: *mut usize,
) -> *mut TavError {
    into_result(|| {
        unsafe {
            borrowed_out_ptr(text, "text")?;
            scalar_out_ptr(len, "len")?;
        }
        let value = unsafe { cbor_value(value, "value") }?;
        let value = match value {
            NativeCborValue::TextString(value) => value.as_bytes(),
            _ => {
                return Err(TavError::new(
                    TavErrorCode::CoseUnexpectedType,
                    "value must be text",
                ))
            }
        };
        unsafe {
            *text = value.as_ptr().cast();
            *len = value.len();
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_tag(
    value: *const TavCborValue,
    out: *mut u64,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let tag = match value {
            NativeCborValue::Tagged { tag, .. } => *tag,
            _ => {
                return Err(TavError::new(
                    TavErrorCode::CoseUnexpectedType,
                    "value must be tagged",
                ))
            }
        };
        unsafe {
            *out = tag;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_tagged_payload(
    value: *const TavCborValue,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let payload = match value {
            NativeCborValue::Tagged { payload, .. } => payload.as_ref(),
            _ => {
                return Err(TavError::new(
                    TavErrorCode::CoseUnexpectedType,
                    "value must be tagged",
                ))
            }
        };
        unsafe {
            *out_value = TavCborValue::borrowed(payload);
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_len(
    value: *const TavCborValue,
    out: *mut usize,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let value_len = value
            .len()
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out = value_len;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_array_at(
    value: *const TavCborValue,
    index: usize,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let child = value
            .array_at(index)
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out_value = TavCborValue::borrowed(child);
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_at_int(
    value: *const TavCborValue,
    key: i64,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let child = value
            .map_at_int(key)
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out_value = TavCborValue::borrowed(child);
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_at_text(
    value: *const TavCborValue,
    key: *const c_char,
    key_len: usize,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let key = unsafe { input_text(key, key_len, "key", true) }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let child = value
            .map_at_str(key)
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out_value = TavCborValue::borrowed(child);
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_at(
    value: *const TavCborValue,
    key: *const TavCborValue,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let key = unsafe { cbor_value(key, "key") }?;
        let child = value
            .map_at(key)
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out_value = TavCborValue::borrowed(child);
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_has_int_key(
    value: *const TavCborValue,
    key: i64,
    out: *mut bool,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let has_key = value
            .map_has_int_key(key)
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out = has_key;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_has_text_key(
    value: *const TavCborValue,
    key: *const c_char,
    key_len: usize,
    out: *mut bool,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let key = unsafe { input_text(key, key_len, "key", true) }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let has_key = value
            .map_has_str_key(key)
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out = has_key;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_has_key(
    value: *const TavCborValue,
    key: *const TavCborValue,
    out: *mut bool,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let key = unsafe { cbor_value(key, "key") }?;
        let has_key = value
            .map_has_key(key)
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out = has_key;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_entry_at(
    value: *const TavCborValue,
    index: usize,
    out_key: *mut *const TavCborValue,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_key, "out_key") }?;
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let (key, child) = map_entry_at(value, index)?;
        unsafe {
            *out_key = TavCborValue::borrowed(key);
            *out_value = TavCborValue::borrowed(child);
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_key_at(
    value: *const TavCborValue,
    index: usize,
    out_key: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_key, "out_key") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let (key, _) = map_entry_at(value, index)?;
        unsafe {
            *out_key = TavCborValue::borrowed(key);
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_value_at(
    value: *const TavCborValue,
    index: usize,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let (_, child) = map_entry_at(value, index)?;
        unsafe {
            *out_value = TavCborValue::borrowed(child);
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_validate_cose_sign1(
    value: *const TavCborValue,
    out_sign1: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_sign1, "out_sign1") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let sign1 =
            cose_sign1(value).map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out_sign1 = TavCborValue::borrowed(sign1);
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_free(value: *mut TavCborValue) {
    if !value.is_null() {
        unsafe {
            drop(Box::from_raw(value));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn tav_verify_cose_sign1_embedded(
    sign1: *const TavCborValue,
    spki_der: *const u8,
    spki_der_len: usize,
    cose_alg: i32,
) -> *mut TavError {
    into_result(|| {
        let value = unsafe { cbor_value(sign1, "sign1") }?;
        let sign1 =
            cose_sign1(value).map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        let payload = borrowed_bytes(sign1_field(sign1, 2, "payload")?, "payload")?;
        verify_sign1(sign1, payload, spki_der, spki_der_len, cose_alg)
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_verify_cose_sign1_detached(
    sign1: *const TavCborValue,
    payload: *const u8,
    payload_len: usize,
    spki_der: *const u8,
    spki_der_len: usize,
    cose_alg: i32,
) -> *mut TavError {
    into_result(|| {
        let value = unsafe { cbor_value(sign1, "sign1") }?;
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
    use super::*;

    #[test]
    fn c_header_enums_match_rust_enums() {
        let header = include_str!("../../include/tav/cose.h");

        for (name, value) in [
            ("TAV_CBOR_KIND_INT", TavCborKind::Int as i32),
            ("TAV_CBOR_KIND_SIMPLE", TavCborKind::Simple as i32),
            ("TAV_CBOR_KIND_BYTES", TavCborKind::Bytes as i32),
            ("TAV_CBOR_KIND_TEXT", TavCborKind::Text as i32),
            ("TAV_CBOR_KIND_ARRAY", TavCborKind::Array as i32),
            ("TAV_CBOR_KIND_MAP", TavCborKind::Map as i32),
            ("TAV_CBOR_KIND_TAGGED", TavCborKind::Tagged as i32),
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
        ] {
            assert_eq!(
                c_header_enum_value(header, name),
                Some(value),
                "{name} in ffi/include/tav/cose.h must match Rust"
            );
        }
    }

    fn c_header_enum_value(header: &str, name: &str) -> Option<i32> {
        let line = header
            .lines()
            .find(|line| line.trim_start().starts_with(name))?;
        line.split('=')
            .nth(1)?
            .trim()
            .trim_end_matches(',')
            .parse()
            .ok()
    }
}
