// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C ABI bindings for staged Confidential ACI attestation verification.
//!
//! This module exports the symbols declared in `ffi/include/tav/caci.h`.

use std::ffi::CStr;
use std::os::raw::c_char;

use super::utils::{
    input_bytes, input_text, owned_out_ptr, tav_error_free, tav_error_message, TavByteBuffer,
    MAX_INPUT_LEN,
};
use crate::c_ffi::cose::{tav_cbor_value_from_bytes, TavCborValue};
use crate::c_ffi::snp::TavSnpAttestationReport;
use crate::{into_result, TavError, TavErrorCode};
use attestation::snp::report::TcbVersionRaw;

use caci::{snp, synchronous, AciError, SNP_HOST_DATA_LEN};

const TCB_VERSION_LEN: usize = std::mem::size_of::<TcbVersionRaw>();
impl From<AciError> for TavError {
    fn from(value: AciError) -> Self {
        let code = match &value {
            AciError::InvalidAmdEndorsements(_) | AciError::InvalidAttestation(_) => {
                TavErrorCode::InvalidArgument
            }
            AciError::AttestationVerification(error) => TavErrorCode::from(error),
            AciError::Certificate(_) => TavErrorCode::CaciCertificate,
            AciError::DidX509(_) => TavErrorCode::CaciDidX509,
            AciError::Cose(_) => TavErrorCode::CaciCose,
            AciError::Signature(_) => TavErrorCode::CaciSignature,
            AciError::Measurement(_) => TavErrorCode::CaciMeasurement,
            AciError::Policy(_) => TavErrorCode::CaciPolicy,
        };
        TavError::new(code, value.to_string())
    }
}

unsafe fn cose_error_to_caci(error: *mut TavError) -> TavError {
    let message = unsafe { CStr::from_ptr(tav_error_message(error)) }
        .to_string_lossy()
        .into_owned();
    unsafe {
        tav_error_free(error);
    }
    TavError::new(
        TavErrorCode::CaciCose,
        format!("failed to materialize verified UVM CBOR: {message}"),
    )
}

unsafe fn attestation_report<'a>(
    report: *const TavSnpAttestationReport,
) -> Result<&'a attestation::snp::report::AttestationReport, TavError> {
    if report.is_null() {
        return Err(TavError::invalid_argument("report is null"));
    }
    Ok(unsafe { (*report).report() })
}

unsafe fn uvm_endorsement_handle<'a>(
    uvm_endorsement: *const TavCborValue,
) -> Result<&'a cose::CborValue, TavError> {
    if uvm_endorsement.is_null() {
        return Err(TavError::invalid_argument("uvm_endorsement is null"));
    }
    // TavCborValue is a repr(transparent) C handle over cose::CborValue.
    Ok(unsafe { &*uvm_endorsement.cast::<cose::CborValue>() })
}

unsafe fn minimum_tcb_entries(
    cpuids: *const u32,
    values: *const u8,
    count: usize,
) -> Result<Vec<(snp::Cpuid, TcbVersionRaw)>, TavError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if cpuids.is_null() {
        return Err(TavError::invalid_argument(
            "minimum_tcb_cpuids pointer is null",
        ));
    }
    if count > MAX_INPUT_LEN / TCB_VERSION_LEN {
        return Err(TavError::invalid_argument(
            "minimum_tcb exceeds maximum input size",
        ));
    }
    let values_len = count
        .checked_mul(TCB_VERSION_LEN)
        .ok_or_else(|| TavError::invalid_argument("minimum_tcb_values length overflow"))?;
    let values = unsafe { input_bytes(values, values_len, "minimum_tcb_values", false) }?;
    let cpuids = unsafe { std::slice::from_raw_parts(cpuids, count) };

    Ok(cpuids
        .iter()
        .zip(values.chunks_exact(TCB_VERSION_LEN))
        .map(|(&cpuid, chunk)| {
            (
                snp::Cpuid::from(cpuid),
                TcbVersionRaw {
                    raw: chunk
                        .try_into()
                        .expect("chunks_exact produced fixed-size chunks"),
                },
            )
        })
        .collect())
}

unsafe fn parse_trusted_policy_digests(
    data: *const u8,
    count: usize,
) -> Result<Vec<[u8; SNP_HOST_DATA_LEN]>, TavError> {
    if count == 0 {
        return Err(TavError::invalid_argument(
            "at least one trusted policy digest is required",
        ));
    }
    if count > MAX_INPUT_LEN / SNP_HOST_DATA_LEN {
        return Err(TavError::invalid_argument(
            "trusted_policy_digests exceeds maximum input size",
        ));
    }
    let len = count * SNP_HOST_DATA_LEN;
    let bytes = unsafe { input_bytes(data, len, "trusted_policy_digests", false) }?;
    Ok(bytes
        .chunks_exact(SNP_HOST_DATA_LEN)
        .map(|chunk| {
            chunk
                .try_into()
                .expect("chunks_exact produced fixed-size chunks")
        })
        .collect())
}

fn write_owned_bytes(
    bytes: impl Into<Vec<u8>>,
    out_bytes: *mut *mut TavByteBuffer,
) -> Result<(), TavError> {
    unsafe { owned_out_ptr(out_bytes, "out_report_data") }?;
    unsafe {
        *out_bytes = Box::into_raw(TavByteBuffer::from_bytes(bytes));
    }
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn tav_verify_caci_uvm_endorsement(
    uvm_endorsement: *const u8,
    uvm_endorsement_len: usize,
    trusted_didx509: *const c_char,
    trusted_didx509_len: usize,
    out_uvm_endorsement: *mut *mut TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { owned_out_ptr(out_uvm_endorsement, "out_uvm_endorsement") }?;
        let uvm_endorsement = unsafe {
            input_bytes(
                uvm_endorsement,
                uvm_endorsement_len,
                "uvm_endorsement",
                false,
            )
        }?;
        let trusted_didx509 = unsafe {
            input_text(
                trusted_didx509,
                trusted_didx509_len,
                "trusted_didx509",
                false,
            )
        }?;
        synchronous::verify_uvm_endorsement(uvm_endorsement, trusted_didx509)
            .map_err(TavError::from)?;
        let cose_error = unsafe {
            tav_cbor_value_from_bytes(
                uvm_endorsement.as_ptr(),
                uvm_endorsement.len(),
                out_uvm_endorsement,
            )
        };
        if !cose_error.is_null() {
            return Err(unsafe { cose_error_to_caci(cose_error) });
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_verify_caci_attestation(
    attestation: *const TavSnpAttestationReport,
    minimum_tcb_cpuids: *const u32,
    minimum_tcb_values: *const u8,
    minimum_tcb_count: usize,
    trusted_policy_digests: *const u8,
    trusted_policy_digest_count: usize,
    uvm_endorsement: *const TavCborValue,
    uvm_feed: *const c_char,
    uvm_feed_len: usize,
    minimum_svn: u64,
    out_report_data: *mut *mut TavByteBuffer,
) -> *mut TavError {
    into_result(|| {
        unsafe { owned_out_ptr(out_report_data, "out_report_data") }?;
        let attestation = unsafe { attestation_report(attestation) }?;
        let minimum_tcb = unsafe {
            minimum_tcb_entries(minimum_tcb_cpuids, minimum_tcb_values, minimum_tcb_count)
        }?;
        let trusted_policy_digests = unsafe {
            parse_trusted_policy_digests(trusted_policy_digests, trusted_policy_digest_count)
        }?;
        let uvm_endorsement = unsafe { uvm_endorsement_handle(uvm_endorsement) }?;
        let uvm_feed = unsafe { input_text(uvm_feed, uvm_feed_len, "uvm_feed", false) }?;
        let report_data = synchronous::verify_caci_attestation(
            *attestation,
            minimum_tcb,
            trusted_policy_digests,
            uvm_endorsement.clone(),
            uvm_feed,
            minimum_svn,
        )
        .map_err(TavError::from)?;
        write_owned_bytes(report_data, out_report_data)
    })
}
