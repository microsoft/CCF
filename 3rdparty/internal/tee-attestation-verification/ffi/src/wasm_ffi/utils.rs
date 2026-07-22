// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::TavErrorCode;
use attestation::snp::verify::VerificationError;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(target_family = "wasm")]
use crypto::{CertificateBackend, Crypto};
#[cfg(target_family = "wasm")]
use js_sys::Array;

/// Split a PEM certificate bundle into individual PEM certificates using the
/// active crypto backend, in the same order they appeared in the input.
#[cfg(target_family = "wasm")]
#[wasm_bindgen]
pub fn split_pem_bundle(pem_bundle: &str) -> Result<Array, String> {
    if pem_bundle.trim().is_empty() {
        return Err("Certificate bundle PEM is empty".into());
    }

    let certificates = Crypto::from_pem_chain(pem_bundle.as_bytes())
        .map_err(|e| format!("Failed to parse certificate bundle PEM: {e}"))?;

    let split = Array::new();
    for certificate in certificates {
        let pem = Crypto::to_pem(&certificate)
            .map_err(|e| format!("Failed to encode certificate PEM: {e}"))?;
        split.push(&JsValue::from_str(&pem));
    }

    Ok(split)
}

/// An error returned by the SNP verify function.
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[derive(Debug)]
pub struct VerifyError {
    code: TavErrorCode,
    message: String,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl VerifyError {
    /// The error category.
    #[cfg_attr(target_family = "wasm", wasm_bindgen(getter))]
    pub fn code(&self) -> TavErrorCode {
        self.code
    }

    /// The human-readable error message.
    #[cfg_attr(target_family = "wasm", wasm_bindgen(getter))]
    pub fn message(&self) -> String {
        self.message.clone()
    }
}

impl VerifyError {
    pub(crate) fn new(code: TavErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
    pub(crate) fn invalid_argument(message: String) -> Self {
        Self::new(TavErrorCode::InvalidArgument, message)
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VerifyError {}

impl From<VerificationError> for VerifyError {
    fn from(e: VerificationError) -> Self {
        let code = TavErrorCode::from(&e);
        Self::new(code, e.to_string())
    }
}
