// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use cose_openssl::{CborValue, EvpKey};
use std::slice;

// COSE/CWT header labels (matching CCF's C++ constants).
const CWT_CLAIMS: i64 = 15;
const KID: i64 = 4;
const VDS: i64 = 395;
const IAT: i64 = 6;
const ISS: i64 = 1;
const SUB: i64 = 2;
const CCF_LEDGER_SHA256: i64 = 2;

const CCF_V1: &str = "ccf.v1";
const TX_ID: &str = "txid";
const TX_RANGE_BEGIN: &str = "epoch.start.txid";
const TX_RANGE_END: &str = "epoch.end.txid";
const EPOCH_LAST_MERKLE_ROOT: &str = "epoch.end.merkle.root";

unsafe fn slice_from_raw(ptr: *const u8, len: usize) -> &'static [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

unsafe fn str_from_raw(ptr: *const u8, len: usize) -> &'static str {
    let bytes = unsafe { slice_from_raw(ptr, len) };
    std::str::from_utf8(bytes).unwrap_or("")
}

fn build_ledger_phdr(kid: &[u8], iat: i64, issuer: &str, subject: &str, txid: &str) -> CborValue {
    let cwt = CborValue::Map(vec![
        (CborValue::Int(IAT), CborValue::Int(iat)),
        (
            CborValue::Int(ISS),
            CborValue::TextString(issuer.to_string()),
        ),
        (
            CborValue::Int(SUB),
            CborValue::TextString(subject.to_string()),
        ),
    ]);

    let ccf = CborValue::Map(vec![(
        CborValue::TextString(TX_ID.to_string()),
        CborValue::TextString(txid.to_string()),
    )]);

    CborValue::Map(vec![
        (CborValue::Int(KID), CborValue::ByteString(kid.to_vec())),
        (CborValue::Int(VDS), CborValue::Int(CCF_LEDGER_SHA256)),
        (CborValue::Int(CWT_CLAIMS), cwt),
        (CborValue::TextString(CCF_V1.to_string()), ccf),
    ])
}

fn build_endorsement_phdr(
    iat: i64,
    epoch_begin: &str,
    epoch_end: &str,
    previous_merkle_root: &[u8],
) -> CborValue {
    let cwt = CborValue::Map(vec![(CborValue::Int(IAT), CborValue::Int(iat))]);

    let mut ccf_entries = vec![(
        CborValue::TextString(TX_RANGE_BEGIN.to_string()),
        CborValue::TextString(epoch_begin.to_string()),
    )];

    if !epoch_end.is_empty() {
        ccf_entries.push((
            CborValue::TextString(TX_RANGE_END.to_string()),
            CborValue::TextString(epoch_end.to_string()),
        ));
    }

    if !previous_merkle_root.is_empty() {
        ccf_entries.push((
            CborValue::TextString(EPOCH_LAST_MERKLE_ROOT.to_string()),
            CborValue::ByteString(previous_merkle_root.to_vec()),
        ));
    }

    let ccf = CborValue::Map(ccf_entries);

    CborValue::Map(vec![
        (CborValue::Int(CWT_CLAIMS), cwt),
        (CborValue::TextString(CCF_V1.to_string()), ccf),
    ])
}

/// Sign a ledger signature.
///
/// On success, writes the output pointer and length into `out_ptr`/`out_len`
/// and returns 0. On failure returns non-zero. Caller frees with `cose_free`.
///
/// # Safety
/// All pointer+length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_sign_ledger(
    key_der_ptr: *const u8,
    key_der_len: usize,
    kid_ptr: *const u8,
    kid_len: usize,
    iat: i64,
    issuer_ptr: *const u8,
    issuer_len: usize,
    subject_ptr: *const u8,
    subject_len: usize,
    txid_ptr: *const u8,
    txid_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = std::panic::catch_unwind(|| unsafe {
        let key_der = slice_from_raw(key_der_ptr, key_der_len);
        let kid = slice_from_raw(kid_ptr, kid_len);
        let issuer = str_from_raw(issuer_ptr, issuer_len);
        let subject = str_from_raw(subject_ptr, subject_len);
        let txid = str_from_raw(txid_ptr, txid_len);
        let payload = slice_from_raw(payload_ptr, payload_len);

        let key = EvpKey::from_der_private(key_der)?;
        let phdr = build_ledger_phdr(kid, iat, issuer, subject, txid);
        let uhdr = CborValue::Map(vec![]);

        cose_openssl::cose_sign1(&key, phdr, uhdr, payload, true)
    });

    match result {
        Ok(Ok(envelope)) => unsafe {
            let mut buf = envelope.into_boxed_slice();
            *out_ptr = buf.as_mut_ptr();
            *out_len = buf.len();
            std::mem::forget(buf);
            0
        },
        _ => -1,
    }
}

/// Sign an identity endorsement.
///
/// `epoch_end_ptr`/`epoch_end_len` and `prev_root_ptr`/`prev_root_len` may be
/// null/0 if not applicable.
///
/// # Safety
/// All pointer+length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_sign_endorsement(
    key_der_ptr: *const u8,
    key_der_len: usize,
    iat: i64,
    epoch_begin_ptr: *const u8,
    epoch_begin_len: usize,
    epoch_end_ptr: *const u8,
    epoch_end_len: usize,
    prev_root_ptr: *const u8,
    prev_root_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = std::panic::catch_unwind(|| unsafe {
        let key_der = slice_from_raw(key_der_ptr, key_der_len);
        let epoch_begin = str_from_raw(epoch_begin_ptr, epoch_begin_len);
        let epoch_end = str_from_raw(epoch_end_ptr, epoch_end_len);
        let prev_root = slice_from_raw(prev_root_ptr, prev_root_len);
        let payload = slice_from_raw(payload_ptr, payload_len);

        let key = EvpKey::from_der_private(key_der)?;
        let phdr = build_endorsement_phdr(iat, epoch_begin, epoch_end, prev_root);
        let uhdr = CborValue::Map(vec![]);

        cose_openssl::cose_sign1(&key, phdr, uhdr, payload, false)
    });

    match result {
        Ok(Ok(envelope)) => unsafe {
            let mut buf = envelope.into_boxed_slice();
            *out_ptr = buf.as_mut_ptr();
            *out_len = buf.len();
            std::mem::forget(buf);
            0
        },
        _ => -1,
    }
}

/// Free a buffer previously allocated by `cose_sign_*`.
///
/// # Safety
/// `ptr` and `len` must come from a prior successful `cose_sign_*` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            drop(Box::from_raw(slice::from_raw_parts_mut(ptr, len)));
        }
    }
}

/// Verify a COSE_Sign1 from pre-parsed components.
///
/// `alg` is the COSE algorithm integer (e.g. -7 for ES256).
/// `phdr_cbor` is the serialized CBOR protected header.
/// `payload` is the raw payload bytes (not CBOR-wrapped).
/// `sig` is the fixed-size signature.
///
/// Returns 0 on successful verification, non-zero on failure.
///
/// # Safety
/// All pointer+length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_verify1(
    key_pub_der_ptr: *const u8,
    key_pub_der_len: usize,
    alg: i64,
    phdr_cbor_ptr: *const u8,
    phdr_cbor_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> i32 {
    let result = std::panic::catch_unwind(|| unsafe {
        let key_der = slice_from_raw(key_pub_der_ptr, key_pub_der_len);
        let phdr_cbor = slice_from_raw(phdr_cbor_ptr, phdr_cbor_len);
        let payload = slice_from_raw(payload_ptr, payload_len);
        let sig = slice_from_raw(sig_ptr, sig_len);

        let key = EvpKey::from_der_public(key_der)?;

        let verified = cose_openssl::cose_verify1(&key, alg, phdr_cbor, payload, sig)?;
        if verified {
            Ok(0i32)
        } else {
            Err("Signature verification failed".to_string())
        }
    });

    match result {
        Ok(Ok(rc)) => rc,
        _ => -1,
    }
}
