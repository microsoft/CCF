// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use cose_openssl::{CborValue, EvpKey};
use std::slice;

/// Write an error message string into caller-provided output pointers.
///
/// If `err_ptr` and `err_len` are both non-null the message is heap-allocated
/// with `Box<[u8]>` and ownership is transferred to the caller (who must free
/// it with `cose_free`).  When either pointer is null the message is silently
/// dropped.
unsafe fn set_error(msg: &str, err_ptr: *mut *mut u8, err_len: *mut usize) {
    if err_ptr.is_null() || err_len.is_null() {
        return;
    }
    let bytes = msg.as_bytes().to_vec().into_boxed_slice();
    unsafe {
        *err_len = bytes.len();
        *err_ptr = Box::into_raw(bytes) as *mut u8;
    }
}

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

/// Sign an identity endorsement using a pre-created key handle.
///
/// `epoch_end_ptr`/`epoch_end_len` and `prev_root_ptr`/`prev_root_len` may be
/// null/0 if not applicable.
///
/// On failure the error message is written to `err_ptr`/`err_len` (if
/// non-null).  The caller must free it with `cose_free`.
///
/// # Safety
/// `key` must be a valid pointer from `cose_key_from_der_private`.
/// All pointer+length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_sign_endorsement(
    key: *const EvpKey,
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
    err_ptr: *mut *mut u8,
    err_len: *mut usize,
) -> i32 {
    if key.is_null() {
        unsafe { set_error("key is null", err_ptr, err_len) };
        return -1;
    }
    let result = std::panic::catch_unwind(|| unsafe {
        let key = &*key;
        let epoch_begin = str_from_raw(epoch_begin_ptr, epoch_begin_len);
        let epoch_end = str_from_raw(epoch_end_ptr, epoch_end_len);
        let prev_root = slice_from_raw(prev_root_ptr, prev_root_len);
        let payload = slice_from_raw(payload_ptr, payload_len);

        let phdr = build_endorsement_phdr(iat, epoch_begin, epoch_end, prev_root);
        let uhdr = CborValue::Map(vec![]);

        cose_openssl::cose_sign1(key, phdr, uhdr, payload, false)
    });

    match result {
        Ok(Ok(envelope)) => unsafe {
            let mut buf = envelope.into_boxed_slice();
            *out_ptr = buf.as_mut_ptr();
            *out_len = buf.len();
            std::mem::forget(buf);
            0
        },
        Ok(Err(e)) => unsafe {
            set_error(&e, err_ptr, err_len);
            -1
        },
        Err(_) => unsafe {
            set_error("panic during cose_sign_endorsement", err_ptr, err_len);
            -1
        },
    }
}

/// Create an opaque signing key from a DER-encoded private key.
/// Returns a pointer to the key, or null on failure.
/// The caller must free the key with `cose_key_free`.
///
/// On failure the error message is written to `err_ptr`/`err_len` (if
/// non-null).  The caller must free it with `cose_free`.
///
/// # Safety
/// `key_der_ptr` must point to `key_der_len` valid bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_key_from_der_private(
    key_der_ptr: *const u8,
    key_der_len: usize,
    err_ptr: *mut *mut u8,
    err_len: *mut usize,
) -> *mut EvpKey {
    let result = std::panic::catch_unwind(|| unsafe {
        let key_der = slice_from_raw(key_der_ptr, key_der_len);
        EvpKey::from_der_private(key_der)
    });

    match result {
        Ok(Ok(key)) => Box::into_raw(Box::new(key)),
        Ok(Err(e)) => unsafe {
            set_error(&e, err_ptr, err_len);
            std::ptr::null_mut()
        },
        Err(_) => unsafe {
            set_error("panic during cose_key_from_der_private", err_ptr, err_len);
            std::ptr::null_mut()
        },
    }
}

/// Free a key previously created by `cose_key_from_der_private`.
///
/// # Safety
/// `key` must be a pointer returned by `cose_key_from_der_private`,
/// or null (which is a no-op).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_key_free(key: *mut EvpKey) {
    if !key.is_null() {
        unsafe {
            drop(Box::from_raw(key));
        }
    }
}

/// Sign a ledger signature using a pre-created key handle.
///
/// On failure the error message is written to `err_ptr`/`err_len` (if
/// non-null).  The caller must free it with `cose_free`.
///
/// # Safety
/// `key` must be a valid pointer from `cose_key_from_der_private`.
/// All pointer+length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_sign_ledger(
    key: *const EvpKey,
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
    err_ptr: *mut *mut u8,
    err_len: *mut usize,
) -> i32 {
    if key.is_null() {
        unsafe { set_error("key is null", err_ptr, err_len) };
        return -1;
    }
    let result = std::panic::catch_unwind(|| unsafe {
        let key = &*key;
        let kid = slice_from_raw(kid_ptr, kid_len);
        let issuer = str_from_raw(issuer_ptr, issuer_len);
        let subject = str_from_raw(subject_ptr, subject_len);
        let txid = str_from_raw(txid_ptr, txid_len);
        let payload = slice_from_raw(payload_ptr, payload_len);

        let phdr = build_ledger_phdr(kid, iat, issuer, subject, txid);
        let uhdr = CborValue::Map(vec![]);

        cose_openssl::cose_sign1(key, phdr, uhdr, payload, true)
    });

    match result {
        Ok(Ok(envelope)) => unsafe {
            let mut buf = envelope.into_boxed_slice();
            *out_ptr = buf.as_mut_ptr();
            *out_len = buf.len();
            std::mem::forget(buf);
            0
        },
        Ok(Err(e)) => unsafe {
            set_error(&e, err_ptr, err_len);
            -1
        },
        Err(_) => unsafe {
            set_error("panic during cose_sign_ledger", err_ptr, err_len);
            -1
        },
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

/// Create an opaque verification key from a DER-encoded public key.
/// Returns a pointer to the key, or null on failure.
/// The caller must free the key with `cose_key_free`.
///
/// On failure the error message is written to `err_ptr`/`err_len` (if
/// non-null).  The caller must free it with `cose_free`.
///
/// # Safety
/// `key_der_ptr` must point to `key_der_len` valid bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_key_from_der_public(
    key_der_ptr: *const u8,
    key_der_len: usize,
    err_ptr: *mut *mut u8,
    err_len: *mut usize,
) -> *mut EvpKey {
    let result = std::panic::catch_unwind(|| unsafe {
        let key_der = slice_from_raw(key_der_ptr, key_der_len);
        EvpKey::from_der_public(key_der)
    });

    match result {
        Ok(Ok(key)) => Box::into_raw(Box::new(key)),
        Ok(Err(e)) => unsafe {
            set_error(&e, err_ptr, err_len);
            std::ptr::null_mut()
        },
        Err(_) => unsafe {
            set_error("panic during cose_key_from_der_public", err_ptr, err_len);
            std::ptr::null_mut()
        },
    }
}

/// Verify a COSE_Sign1 from pre-parsed components using a pre-created key
/// handle.
///
/// `key` must be a valid pointer from `cose_key_from_der_public` or
/// `cose_key_from_der_private`.
/// `alg` is the COSE algorithm integer (e.g. -7 for ES256).
///
/// Returns 0 on successful verification, non-zero on failure.
///
/// On failure the error message is written to `err_ptr`/`err_len` (if
/// non-null).  The caller must free it with `cose_free`.
///
/// # Safety
/// `key` must be a valid pointer from `cose_key_from_der_public` or
/// `cose_key_from_der_private`.
/// All pointer+length pairs must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_verify1(
    key: *const EvpKey,
    alg: i64,
    phdr_cbor_ptr: *const u8,
    phdr_cbor_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
    err_ptr: *mut *mut u8,
    err_len: *mut usize,
) -> i32 {
    if key.is_null() {
        unsafe { set_error("key is null", err_ptr, err_len) };
        return -1;
    }
    let result = std::panic::catch_unwind(|| unsafe {
        let key = &*key;
        let phdr_cbor = slice_from_raw(phdr_cbor_ptr, phdr_cbor_len);
        let payload = slice_from_raw(payload_ptr, payload_len);
        let sig = slice_from_raw(sig_ptr, sig_len);

        let verified = cose_openssl::cose_verify1(key, alg, phdr_cbor, payload, sig)?;
        if verified {
            Ok(0i32)
        } else {
            Err("Signature verification failed".to_string())
        }
    });

    match result {
        Ok(Ok(rc)) => rc,
        Ok(Err(e)) => unsafe {
            set_error(&e, err_ptr, err_len);
            -1
        },
        Err(_) => unsafe {
            set_error("panic during cose_verify1", err_ptr, err_len);
            -1
        },
    }
}
