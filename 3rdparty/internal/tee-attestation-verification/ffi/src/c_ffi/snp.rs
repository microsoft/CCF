// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C ABI bindings for caller-provided-certificate SNP attestation verification.
//!
//! This module exports the symbols declared in `ffi/include/tav/snp.h`.
//!
//! [`tav_verify_snp_attestation`] returns a null [`TavError`] pointer on
//! success and an owned [`TavError`] pointer on failure. On success it
//! writes an owned [`TavSnpAttestationReport`] handle to `out_report`.
//! Callers release these handles with [`crate::c_ffi::utils::tav_error_free`] and
//! [`tav_snp_attestation_report_free`].
//!
//! Report accessors assume their pointers are valid handles
//! returned by this library. Passing null, dangling, freed, or otherwise
//! invalid pointers to report accessors is undefined behavior. Error
//! accessors are defensive for null pointers: [`crate::c_ffi::utils::tav_error_code`] returns
//! [`TavErrorCode::ErrorIsNull`] and [`crate::c_ffi::utils::tav_error_message`] returns a static
//! diagnostic string. Freeing a null report or error pointer is a no-op.
//!
//! Byte-slice report accessors return borrowed views by writing a pointer
//! and length to caller-provided out-parameters. The borrowed pointer remains
//! valid only until the owning report handle is freed, and must not be freed
//! by the caller.

use zerocopy::FromBytes;

use super::utils::{input_bytes, owned_out_ptr};
use crate::{into_result, TavError, TavErrorCode};
use attestation::snp::verify::{self, ChainVerification, VerificationError};
use attestation::{certificate_from_pem, AttestationReport};

pub struct TavSnpAttestationReport {
    bytes: Vec<u8>,
}

fn tav_error_from_verification_error(error: VerificationError) -> TavError {
    let code = TavErrorCode::from(&error);
    TavError::new(code, error.to_string())
}

impl TavSnpAttestationReport {
    pub fn report(&self) -> &AttestationReport {
        AttestationReport::ref_from_bytes(&self.bytes).expect(
            "TavSnpAttestationReport is only constructed from verified bytes so parsing should not fail",
        )
    }
}

macro_rules! scalar_accessor {
    ($name:ident, $return_ty:ty, |$report:ident| $value:expr) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name(report: *const TavSnpAttestationReport) -> $return_ty {
            let report = unsafe { &*report };
            let $report = report.report();
            $value
        }
    };
}

macro_rules! bytes_accessor {
    ($name:ident, |$report:ident| $value:expr) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            report: *const TavSnpAttestationReport,
            data: *mut *const u8,
            len: *mut usize,
        ) {
            let report = unsafe { &*report };
            let $report = report.report();
            let bytes = $value;
            unsafe {
                *data = bytes.as_ptr();
                *len = bytes.len();
            }
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn tav_verify_snp_attestation(
    report_bytes: *const u8,
    report_len: usize,
    ark_pem: *const u8,
    ark_pem_len: usize,
    ask_pem: *const u8,
    ask_pem_len: usize,
    vcek_pem: *const u8,
    vcek_pem_len: usize,
    out_report: *mut *mut TavSnpAttestationReport,
) -> *mut TavError {
    into_result(|| {
        unsafe { owned_out_ptr(out_report, "out_report") }?;

        let report_bytes =
            unsafe { input_bytes(report_bytes, report_len, "attestation report", false) }?;
        let report = AttestationReport::ref_from_bytes(report_bytes).map_err(|_| {
            TavError::invalid_argument(format!(
                "Invalid attestation report: expected {} bytes, got {}",
                std::mem::size_of::<AttestationReport>(),
                report_len
            ))
        })?;

        let ark_pem = unsafe { input_bytes(ark_pem, ark_pem_len, "ARK", false) }?;
        let ark = certificate_from_pem(ark_pem).map_err(|error| {
            TavError::invalid_argument(format!("Failed to parse ARK PEM: {error}"))
        })?;

        let ask_pem = unsafe { input_bytes(ask_pem, ask_pem_len, "ASK", false) }?;
        let ask = certificate_from_pem(ask_pem).map_err(|error| {
            TavError::invalid_argument(format!("Failed to parse ASK PEM: {error}"))
        })?;

        let vcek_pem = unsafe { input_bytes(vcek_pem, vcek_pem_len, "VCEK", false) }?;
        let vcek = certificate_from_pem(vcek_pem).map_err(|error| {
            TavError::invalid_argument(format!("Failed to parse VCEK PEM: {error}"))
        })?;

        verify::sync::verify_attestation(
            report,
            &vcek,
            &ChainVerification::WithProvidedArk {
                ask: &ask,
                ark: &ark,
            },
        )
        .map_err(tav_error_from_verification_error)?;

        let report = TavSnpAttestationReport {
            bytes: report_bytes.to_vec(),
        };
        unsafe {
            *out_report = Box::into_raw(Box::new(report));
        }
        Ok(())
    })
}

scalar_accessor!(tav_snp_attestation_report_version, u32, |report| report
    .version
    .get());
scalar_accessor!(tav_snp_attestation_report_guest_svn, u32, |report| report
    .guest_svn
    .get());
scalar_accessor!(tav_snp_attestation_report_policy, u64, |report| report
    .policy
    .get());
scalar_accessor!(tav_snp_attestation_report_policy_abi_minor, u8, |report| {
    report.policy().abi_minor()
});
scalar_accessor!(tav_snp_attestation_report_policy_abi_major, u8, |report| {
    report.policy().abi_major()
});
scalar_accessor!(tav_snp_attestation_report_policy_smt, bool, |report| report
    .policy()
    .smt());
scalar_accessor!(
    tav_snp_attestation_report_policy_migrate_ma,
    bool,
    |report| report.policy().migrate_ma()
);
scalar_accessor!(tav_snp_attestation_report_policy_debug, bool, |report| {
    report.policy().debug()
});
scalar_accessor!(
    tav_snp_attestation_report_policy_single_socket,
    bool,
    |report| report.policy().single_socket()
);
scalar_accessor!(
    tav_snp_attestation_report_policy_cxl_allow,
    bool,
    |report| report.policy().cxl_allow()
);
scalar_accessor!(
    tav_snp_attestation_report_policy_mem_aes_256_xts,
    bool,
    |report| report.policy().mem_aes_256_xts()
);
scalar_accessor!(tav_snp_attestation_report_policy_rapl_dis, bool, |report| {
    report.policy().rapl_dis()
});
scalar_accessor!(
    tav_snp_attestation_report_policy_ciphertext_hiding_dram,
    bool,
    |report| report.policy().ciphertext_hiding_dram()
);
scalar_accessor!(
    tav_snp_attestation_report_policy_page_swap_disable,
    bool,
    |report| report.policy().page_swap_disable()
);
scalar_accessor!(tav_snp_attestation_report_vmpl, u32, |report| report
    .vmpl
    .get());
scalar_accessor!(tav_snp_attestation_report_signature_algo, u32, |report| {
    report.signature_algo.get()
});
scalar_accessor!(tav_snp_attestation_report_platform_info, u64, |report| {
    report.platform_info.get()
});
scalar_accessor!(tav_snp_attestation_report_flags, u32, |report| report
    .flags
    .get());
scalar_accessor!(
    tav_snp_attestation_report_flags_author_key_en,
    bool,
    |report| report.flags().author_key_en()
);
scalar_accessor!(
    tav_snp_attestation_report_flags_mask_chip_key,
    bool,
    |report| report.flags().mask_chip_key()
);
scalar_accessor!(tav_snp_attestation_report_flags_signing_key, u8, |report| {
    report.flags().signing_key().raw()
});
scalar_accessor!(tav_snp_attestation_report_cpuid_fam_id, u8, |report| report
    .cpuid_fam_id);
scalar_accessor!(tav_snp_attestation_report_cpuid_mod_id, u8, |report| report
    .cpuid_mod_id);
scalar_accessor!(tav_snp_attestation_report_cpuid_step, u8, |report| report
    .cpuid_step);
scalar_accessor!(tav_snp_attestation_report_current_build, u8, |report| {
    report.current_build
});
scalar_accessor!(tav_snp_attestation_report_current_minor, u8, |report| {
    report.current_minor
});
scalar_accessor!(tav_snp_attestation_report_current_major, u8, |report| {
    report.current_major
});
scalar_accessor!(tav_snp_attestation_report_committed_build, u8, |report| {
    report.committed_build
});
scalar_accessor!(tav_snp_attestation_report_committed_minor, u8, |report| {
    report.committed_minor
});
scalar_accessor!(tav_snp_attestation_report_committed_major, u8, |report| {
    report.committed_major
});

bytes_accessor!(tav_snp_attestation_report_family_id, |report| &report
    .family_id);
bytes_accessor!(tav_snp_attestation_report_image_id, |report| &report
    .image_id);
bytes_accessor!(tav_snp_attestation_report_platform_version, |report| {
    &report.platform_version.raw
});
bytes_accessor!(tav_snp_attestation_report_report_data, |report| &report
    .report_data);
bytes_accessor!(tav_snp_attestation_report_measurement, |report| &report
    .measurement);
bytes_accessor!(tav_snp_attestation_report_host_data, |report| &report
    .host_data);
bytes_accessor!(tav_snp_attestation_report_id_key_digest, |report| &report
    .id_key_digest);
bytes_accessor!(tav_snp_attestation_report_author_key_digest, |report| {
    &report.author_key_digest
});
bytes_accessor!(tav_snp_attestation_report_report_id, |report| &report
    .report_id);
bytes_accessor!(tav_snp_attestation_report_report_id_ma, |report| &report
    .report_id_ma);
bytes_accessor!(tav_snp_attestation_report_reported_tcb, |report| &report
    .reported_tcb
    .raw);
bytes_accessor!(tav_snp_attestation_report_chip_id, |report| &report.chip_id);
bytes_accessor!(tav_snp_attestation_report_committed_tcb, |report| &report
    .committed_tcb
    .raw);
bytes_accessor!(tav_snp_attestation_report_launch_tcb, |report| &report
    .launch_tcb
    .raw);
bytes_accessor!(tav_snp_attestation_report_signature_r, |report| &report
    .signature
    .r);
bytes_accessor!(tav_snp_attestation_report_signature_s, |report| &report
    .signature
    .s);

#[no_mangle]
pub unsafe extern "C" fn tav_snp_attestation_report_free(report: *mut TavSnpAttestationReport) {
    if !report.is_null() {
        unsafe {
            drop(Box::from_raw(report));
        }
    }
}
