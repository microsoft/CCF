// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::wasm_ffi::cose::CborValue as WasmCborValue;
use js_sys::{Array, Uint8Array};
use std::collections::BTreeMap;
use wasm_bindgen::{prelude::*, JsCast};

use crate::wasm_ffi::snp::SnpAttestationReport;
use attestation::snp::{report::TcbVersionRaw, Cpuid};
use caci::{asynchronous, AciError, SNP_HOST_DATA_LEN};

/// Verify an SEV-SNP attestation report with caller-provided endorsements.
///
/// `amd_endorsements` must contain exactly three byte arrays ordered as
/// `[vcek, ask, ark]`.
///
/// Caller contract: `amd_endorsements` is a live JS array, read once when the
/// returned promise is first polled (see the `wasm_ffi` module docs). Do not mutate the
/// array or its buffers until that promise settles.
#[wasm_bindgen]
#[cfg(async_crypto)]
pub async fn verify_snp_attestation_with_cert_chain_async(
    attestation_report: Vec<u8>,
    amd_endorsements: Array,
) -> Result<SnpAttestationReport, String> {
    if amd_endorsements.length() != 3 {
        return Err(format!(
            "expected AMD endorsements [vcek, ask, ark], got {} certificate(s)",
            amd_endorsements.length()
        ));
    }
    let amd_endorsements = byte_array_values(amd_endorsements, "AMD endorsement")?;
    let endorsement_refs = [
        amd_endorsements[0].as_slice(),
        amd_endorsements[1].as_slice(),
        amd_endorsements[2].as_slice(),
    ];

    let attestation = asynchronous::verify_attestation(&attestation_report, &endorsement_refs)
        .await
        .map_err(wasm_error)?;

    Ok(SnpAttestationReport::from_verified_report(attestation))
}

/// Verify an ACI/UVM endorsement COSE blob with a caller-pinned did:x509 root.
#[wasm_bindgen]
#[cfg(async_crypto)]
pub async fn verify_uvm_endorsement_async(
    uvm_endorsement: Vec<u8>,
    trusted_didx509: &str,
) -> Result<WasmCborValue, String> {
    let inner = asynchronous::verify_uvm_endorsement(&uvm_endorsement, trusted_didx509)
        .await
        .map_err(wasm_error)?;
    Ok(WasmCborValue::from_native(inner))
}

/// Verify Confidential CACI relying-party policy over staged verified artifacts.
///
/// `minimum_tcb_json`, when non-empty, must be a JSON map from CPUID hex
/// strings to TCB hex strings, for example `{ "00a10f11": "04000000000018db" }`.
/// In the future this can be checked against a transparent statement from CACI.
///
/// Caller contract: `attestation` and `uvm` are borrowed wasm handles and
/// `trusted_caci_execution_policies` is a live JS array, all read once when the
/// returned promise is first polled (see the `wasm_ffi` module docs). Do not free those
/// handles or mutate the array until that promise settles.
#[wasm_bindgen]
pub async fn verify_caci_attestation(
    attestation: &SnpAttestationReport,
    minimum_tcb_json: &str,
    trusted_caci_execution_policies: Array,
    uvm: &WasmCborValue,
    uvm_feed: &str,
    minimum_svn: u64,
) -> Result<Vec<u8>, String> {
    let minimum_tcb = parse_minimum_tcb_json(minimum_tcb_json)?;
    let trusted_caci_execution_policies = byte_array_values(
        trusted_caci_execution_policies,
        "trusted CACI execution policy",
    )?
    .iter()
    .map(|policy| parse_host_data_policy(policy))
    .collect::<Result<Vec<_>, _>>()?;
    if trusted_caci_execution_policies.is_empty() {
        return Err("at least one trusted CACI execution policy digest is required".to_string());
    }
    asynchronous::verify_caci_attestation(
        *attestation.report(),
        minimum_tcb,
        trusted_caci_execution_policies,
        uvm.as_native().clone(),
        uvm_feed,
        minimum_svn,
    )
    .await
    .map(|report_data| report_data.to_vec())
    .map_err(wasm_error)
}

fn byte_array_values(values: Array, name: &str) -> Result<Vec<Vec<u8>>, String> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .dyn_into::<Uint8Array>()
                .map(|bytes| bytes.to_vec())
                .map_err(|_| format!("{name} at index {index} must be a Uint8Array"))
        })
        .collect()
}

fn parse_minimum_tcb_json(json: &str) -> Result<Vec<(Cpuid, TcbVersionRaw)>, String> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let map: BTreeMap<String, String> =
        serde_json::from_str(json).map_err(|e| format!("failed to parse minimum TCB JSON: {e}"))?;
    map.into_iter()
        .map(|(cpuid, tcb)| Ok((parse_cpuid_hex(&cpuid)?, parse_tcb_hex(&tcb)?)))
        .collect()
}

fn parse_cpuid_hex(hex: &str) -> Result<Cpuid, String> {
    if hex.len() != 8 {
        return Err(format!("CPUID must be 8 hex characters, got {}", hex.len()));
    }
    let bytes =
        crypto::hex::from_hex(hex).map_err(|e| format!("invalid CPUID hex {hex:?}: {e}"))?;
    let value = u32::from_be_bytes(bytes.try_into().expect("CPUID hex length already checked"));
    Ok(Cpuid::from(value))
}

fn parse_tcb_hex(hex: &str) -> Result<TcbVersionRaw, String> {
    let bytes = crypto::hex::from_hex(hex)?;
    let raw = bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("TCB version must be 8 bytes, got {}", bytes.len()))?;
    Ok(TcbVersionRaw { raw })
}

fn parse_host_data_policy(bytes: &[u8]) -> Result<[u8; SNP_HOST_DATA_LEN], String> {
    bytes.try_into().map_err(|_| {
        format!(
            "trusted CACI execution policy digest must be {SNP_HOST_DATA_LEN} bytes, got {}",
            bytes.len()
        )
    })
}

fn wasm_error(error: AciError) -> String {
    error.to_string()
}
