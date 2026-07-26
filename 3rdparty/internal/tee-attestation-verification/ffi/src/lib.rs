// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! External C and WebAssembly bindings for TEE attestation verification.
//!
//! Rust consumers should use the domain crates directly. This crate owns the
//! native C ABI (`c_ffi`) and wasm-bindgen API surface (`wasm_ffi`).
//!
//! See `README.md` for consumer-facing docs.

#[cfg(all(not(target_family = "wasm"), sync_crypto))]
use std::ffi::CString;

use attestation::snp::verify::VerificationError;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

/// Shared error codes returned by the public C ABI error accessors.
///
/// The numeric values must match `ffi/include/tav/utils.h`.
///
/// This is also the single source of truth for the wasm API's error codes:
/// on wasm targets this same enum is exported to JS (as `ErrorCode`, via
/// `#[wasm_bindgen(js_name = "ErrorCode")]`, for backwards compatibility with
/// the name used before the C ABI existed). There is no separate wasm-side
/// enum to keep in sync.
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = "ErrorCode"))]
#[cfg_attr(target_family = "wasm", repr(u32))]
#[cfg_attr(not(target_family = "wasm"), repr(C))]
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TavErrorCode {
    // Common codes, returned from any domain.
    Ok = 0,
    InvalidArgument = 1,
    // Returned by `tav_error_code` when passed a null `TavError`.
    ErrorIsNull = 2,
    // Returned when the rust code panics
    Panic = 3,

    // SNP (1xx). Intentionally left unprefixed to preserve the wasm/JS
    // `ErrorCode` member names (each variant maps 1:1 to a JS enum member).
    // Prefixing to `Snp*` is deferred to a future breaking change and can be
    // applied independently on the explicit C header side.
    UnsupportedProcessor = 101,
    InvalidRootCertificate = 102,
    CertificateChainError = 103,
    SignatureVerificationError = 104,
    TcbVerificationError = 105,

    CoseCbor = 201,
    CoseUnexpectedType = 202,
    CoseUnsupportedAlgorithm = 203,
    CoseKeyImport = 204,
    CoseVerification = 205,

    CaciCose = 301,
    CaciCertificate = 302,
    CaciDidX509 = 303,
    CaciSignature = 304,
    CaciMeasurement = 305,
    CaciPolicy = 306,
}

impl From<&VerificationError> for TavErrorCode {
    fn from(error: &VerificationError) -> Self {
        match error {
            VerificationError::UnsupportedProcessor(_) => TavErrorCode::UnsupportedProcessor,
            VerificationError::InvalidRootCertificate(_) => TavErrorCode::InvalidRootCertificate,
            VerificationError::CertificateChainError(_) => TavErrorCode::CertificateChainError,
            VerificationError::SignatureVerificationError(_) => {
                TavErrorCode::SignatureVerificationError
            }
            VerificationError::TcbVerificationError(_) => TavErrorCode::TcbVerificationError,
        }
    }
}

/// Shared error handle returned by public C ABI functions.
#[cfg(all(not(target_family = "wasm"), sync_crypto))]
#[derive(Debug)]
pub struct TavError {
    pub(crate) code: TavErrorCode,
    pub(crate) message: CString,
}

#[cfg(all(not(target_family = "wasm"), sync_crypto))]
impl TavError {
    pub fn new(code: TavErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: c_string(message.into()),
        }
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(TavErrorCode::InvalidArgument, message)
    }

    pub fn into_raw(self) -> *mut Self {
        Box::into_raw(Box::new(self))
    }

    #[cfg(test)]
    pub fn code(&self) -> TavErrorCode {
        self.code
    }

    pub fn message(&self) -> String {
        self.message.to_string_lossy().into_owned()
    }
}

#[cfg(all(not(target_family = "wasm"), sync_crypto))]
fn c_string(message: String) -> CString {
    CString::new(message.replace('\0', "\\0")).expect("NUL bytes were replaced")
}

#[cfg(all(not(target_family = "wasm"), sync_crypto))]
impl std::fmt::Display for TavError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

#[cfg(all(not(target_family = "wasm"), sync_crypto))]
impl std::error::Error for TavError {}

// The native C ABI (`into_result`, below) relies on `std::panic::catch_unwind`
// to guard entry points against panics instead of aborting the host process;
// that guard is a silent no-op under `panic = "abort"`. Fail the build loudly
// instead, so a misconfigured profile (e.g. `panic = "abort"` set for smaller
// binaries) can't silently disable the safety net. wasm32-unknown-unknown is
// exempt: its panic strategy is always `abort` regardless of profile
// settings, and `catch_unwind` isn't used on that target either way.
#[cfg(all(not(target_family = "wasm"), panic = "abort"))]
compile_error!(
    "tee-attestation-verification-ffi requires panic = \"unwind\" for its native C ABI, \
     which relies on std::panic::catch_unwind at FFI entry points (see `into_result`)"
);

/// Runs `f`, converting its `Result` into the C ABI's null-on-success error
/// convention.
///
/// This is the single place that guards entry points against panics: `f` runs
/// under [`std::panic::catch_unwind`], so a panic anywhere in the call graph
/// (e.g. a bug triggered by malformed attacker-controlled input) is caught
/// and reported as a [`TavErrorCode::Panic`] [`TavError`] instead of
/// unwinding into an `extern "C"` frame, which would otherwise abort the
/// host process. Every fallible entry point should route its result through
/// this function rather than converting a `Result` directly.
///
/// This guard is native-only: on `wasm32-unknown-unknown` the panic strategy
/// is always `abort` regardless of profile settings, so `catch_unwind` cannot
/// catch anything there; a panicking wasm export instead traps, which the JS
/// caller observes as a thrown `RuntimeError`.
#[cfg(all(not(target_family = "wasm"), sync_crypto))]
pub fn into_result(f: impl FnOnce() -> Result<(), TavError>) -> *mut TavError {
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|payload| {
            Err(TavError::new(TavErrorCode::Panic, panic_message(&*payload)))
        });
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(error) => error.into_raw(),
    }
}

#[cfg(all(not(target_family = "wasm"), sync_crypto))]
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("operation panicked with a non-string payload");
    format!("internal error: {message}")
}

#[cfg(all(not(target_family = "wasm"), sync_crypto))]
mod c_ffi;
#[cfg(any(target_family = "wasm", test))]
mod wasm_ffi;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_header_error_codes_match_rust_enum() {
        let header = include_str!("../include/tav/utils.h");

        let error_code_map = [
            ("TAV_ERROR_OK", TavErrorCode::Ok as i32),
            (
                "TAV_ERROR_INVALID_ARGUMENT",
                TavErrorCode::InvalidArgument as i32,
            ),
            ("TAV_ERROR_IS_NULL", TavErrorCode::ErrorIsNull as i32),
            ("TAV_ERROR_PANIC", TavErrorCode::Panic as i32),
            (
                "TAV_ERROR_SNP_UNSUPPORTED_PROCESSOR",
                TavErrorCode::UnsupportedProcessor as i32,
            ),
            (
                "TAV_ERROR_SNP_INVALID_ROOT_CERTIFICATE",
                TavErrorCode::InvalidRootCertificate as i32,
            ),
            (
                "TAV_ERROR_SNP_CERTIFICATE_CHAIN_ERROR",
                TavErrorCode::CertificateChainError as i32,
            ),
            (
                "TAV_ERROR_SNP_SIGNATURE_VERIFICATION_ERROR",
                TavErrorCode::SignatureVerificationError as i32,
            ),
            (
                "TAV_ERROR_SNP_TCB_VERIFICATION_ERROR",
                TavErrorCode::TcbVerificationError as i32,
            ),
            ("TAV_ERROR_COSE_CBOR", TavErrorCode::CoseCbor as i32),
            (
                "TAV_ERROR_COSE_UNEXPECTED_TYPE",
                TavErrorCode::CoseUnexpectedType as i32,
            ),
            (
                "TAV_ERROR_COSE_UNSUPPORTED_ALGORITHM",
                TavErrorCode::CoseUnsupportedAlgorithm as i32,
            ),
            (
                "TAV_ERROR_COSE_KEY_IMPORT",
                TavErrorCode::CoseKeyImport as i32,
            ),
            (
                "TAV_ERROR_COSE_VERIFICATION",
                TavErrorCode::CoseVerification as i32,
            ),
            ("TAV_ERROR_CACI_COSE", TavErrorCode::CaciCose as i32),
            (
                "TAV_ERROR_CACI_CERTIFICATE",
                TavErrorCode::CaciCertificate as i32,
            ),
            ("TAV_ERROR_CACI_DID_X509", TavErrorCode::CaciDidX509 as i32),
            (
                "TAV_ERROR_CACI_SIGNATURE",
                TavErrorCode::CaciSignature as i32,
            ),
            (
                "TAV_ERROR_CACI_MEASUREMENT",
                TavErrorCode::CaciMeasurement as i32,
            ),
            ("TAV_ERROR_CACI_POLICY", TavErrorCode::CaciPolicy as i32),
        ];

        for (name, value) in error_code_map {
            assert_eq!(
                c_header_enum_value(header, name),
                Some(value),
                "{name} in include/tav/utils.h must match Rust TavErrorCode"
            );
        }

        // Completeness: every TAV_ERROR_ code declared in the header must be
        // covered by the map above, so adding a header code without updating the
        // Rust enum and this map fails the test in both directions.
        let header_names: std::collections::BTreeSet<&str> = c_header_error_codes(header)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        let mapped_names: std::collections::BTreeSet<&str> =
            error_code_map.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            header_names, mapped_names,
            "include/tav/utils.h TAV_ERROR_ codes must exactly match the checked set"
        );
    }

    fn c_header_enum_value(header: &str, name: &str) -> Option<i32> {
        header.lines().find_map(|line| {
            let (lhs, rhs) = line.split_once('=')?;
            // Token-exact match on the enumerator name so a code whose name is a
            // prefix of another (e.g. TAV_ERROR_COSE_CBOR vs a hypothetical
            // TAV_ERROR_CBOR_EXTRA) cannot bind to the wrong line.
            if lhs.trim() != name {
                return None;
            }
            rhs.trim().trim_end_matches(',').parse().ok()
        })
    }

    fn c_header_error_codes(header: &str) -> Vec<(&str, i32)> {
        header
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if !line.starts_with("TAV_ERROR_") {
                    return None;
                }
                let (name, value) = line.split_once('=')?;
                Some((
                    name.trim(),
                    value.trim().trim_end_matches(',').parse().ok()?,
                ))
            })
            .collect()
    }

    #[test]
    fn verification_errors_map_to_stable_error_codes() {
        let error_code_map = [
            (
                VerificationError::UnsupportedProcessor("unsupported".into()),
                TavErrorCode::UnsupportedProcessor,
            ),
            (
                VerificationError::InvalidRootCertificate("invalid root".into()),
                TavErrorCode::InvalidRootCertificate,
            ),
            (
                VerificationError::CertificateChainError("chain failed".into()),
                TavErrorCode::CertificateChainError,
            ),
            (
                VerificationError::SignatureVerificationError("bad signature".into()),
                TavErrorCode::SignatureVerificationError,
            ),
            (
                VerificationError::TcbVerificationError("bad tcb".into()),
                TavErrorCode::TcbVerificationError,
            ),
        ];

        for (error, code) in error_code_map {
            assert_eq!(TavErrorCode::from(&error), code);
        }
    }

    #[test]
    fn into_result_catches_panics_instead_of_propagating() {
        let error = into_result(|| panic!("boom"));
        assert!(!error.is_null());
        let error = unsafe { Box::from_raw(error) };
        assert_eq!(error.code(), TavErrorCode::Panic);
        assert!(error.message().contains("boom"));
    }

    #[test]
    fn into_result_passes_through_ok() {
        assert!(into_result(|| Ok(())).is_null());
    }
}
