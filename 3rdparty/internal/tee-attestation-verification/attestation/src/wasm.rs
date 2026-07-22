// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WASM bindings for SEV-SNP attestation verification.
//!
//! Provides JavaScript-facing functions via `wasm-bindgen` for use in
//! browser and Node.js environments.

use wasm_bindgen::prelude::*;
use zerocopy::FromBytes;

use crate::{AttestationReport, SevVerifier};

/// Initialize the WASM module with panic hook and logging.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::default());
}

/// JavaScript-facing verification function.
///
/// Accepts the raw attestation report bytes (1184 bytes) as a `Uint8Array`,
/// fetches the certificate chain from AMD KDS, and verifies the report.
#[wasm_bindgen]
pub async fn verify_attestation_report(attestation_report_bytes: &[u8]) -> Result<(), String> {
    let attestation_report = AttestationReport::read_from_bytes(attestation_report_bytes)
        .map_err(|e| format!("Failed to parse attestation report: {:?}", e))?;

    let mut verifier = SevVerifier::new()
        .await
        .map_err(|e| format!("Failed to initialize verifier: {}", e))?;
    verifier
        .verify_attestation(&attestation_report)
        .await
        .map_err(|e| format!("Verification failed: {:?}", e))
}
