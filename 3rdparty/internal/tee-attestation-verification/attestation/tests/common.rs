// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tee_attestation_verification_lib::snp::verify::ChainVerification;
#[cfg(feature = "kds")]
use tee_attestation_verification_lib::SevVerifier;
use tee_attestation_verification_lib::{certificate_from_pem, AttestationReport};
use zerocopy::FromBytes;

// Attestation reports
pub const MILAN_ATTESTATION: &[u8] = include_bytes!("test_data/milan_attestation_report.bin");
pub const GENOA_ATTESTATION: &[u8] = include_bytes!("test_data/genoa_attestation_report.bin");
pub const TURIN_ATTESTATION: &[u8] = include_bytes!("test_data/turin_attestation_report.bin");

// ARK certificates
pub const MILAN_ARK: &[u8] = include_bytes!("../src/pinned_arks/milan_ark.pem");
pub const GENOA_ARK: &[u8] = include_bytes!("../src/pinned_arks/genoa_ark.pem");
pub const TURIN_ARK: &[u8] = include_bytes!("../src/pinned_arks/turin_ark.pem");

// ASK certificates
pub const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");
pub const GENOA_ASK: &[u8] = include_bytes!("test_data/genoa_ask.pem");
pub const TURIN_ASK: &[u8] = include_bytes!("test_data/turin_ask.pem");

// VCEK certificates
pub const MILAN_VCEK: &[u8] = include_bytes!("test_data/milan_vcek.pem");
pub const GENOA_VCEK: &[u8] = include_bytes!("test_data/genoa_vcek.pem");
pub const TURIN_VCEK: &[u8] = include_bytes!("test_data/turin_vcek.pem");

const SIGNATURE_ALGO_OFFSET: usize = 0x034;
const CPUID_FAM_ID_OFFSET: usize = 0x188;
const CPUID_MOD_ID_OFFSET: usize = 0x189;

fn report_with_signature_algo(signature_algo: u32) -> Vec<u8> {
    let mut report = MILAN_ATTESTATION.to_vec();
    report[SIGNATURE_ALGO_OFFSET..SIGNATURE_ALGO_OFFSET + std::mem::size_of::<u32>()]
        .copy_from_slice(&signature_algo.to_le_bytes());
    report
}

fn report_with_cpuid(cpuid_fam_id: u8, cpuid_mod_id: u8) -> Vec<u8> {
    let mut report = MILAN_ATTESTATION.to_vec();
    report[CPUID_FAM_ID_OFFSET] = cpuid_fam_id;
    report[CPUID_MOD_ID_OFFSET] = cpuid_mod_id;
    report
}

macro_rules! attestation_tests {
    (
        $milan_ark:expr,
        $genoa_ark:expr,
        $turin_ark:expr,
        $milan_ask:expr,
        $genoa_ask:expr,
        $turin_ask:expr,
        $tampered_milan_attestation:expr,
        $unsupported_signature_algo_attestation:expr,
        $unsupported_milan_genoa_model_attestation:expr,
        $unsupported_turin_model_attestation:expr,
        $unsupported_family_attestation:expr
    ) => {
        [
            (
                "genoa_ok_pinned",
                GENOA_ATTESTATION,
                GENOA_VCEK,
                ChainVerification::WithPinnedArk { ask: &$genoa_ask },
                Ok(()),
            ),
            (
                "turin_ok_pinned",
                TURIN_ATTESTATION,
                TURIN_VCEK,
                ChainVerification::WithPinnedArk { ask: &$turin_ask },
                Ok(()),
            ),
            (
                "milan_ok_pinned",
                MILAN_ATTESTATION,
                MILAN_VCEK,
                ChainVerification::WithPinnedArk { ask: &$milan_ask },
                Ok(()),
            ),
            (
                "genoa_ok_provided",
                GENOA_ATTESTATION,
                GENOA_VCEK,
                ChainVerification::WithProvidedArk {
                    ask: &$genoa_ask,
                    ark: &$genoa_ark,
                },
                Ok(()),
            ),
            (
                "turin_ok_provided",
                TURIN_ATTESTATION,
                TURIN_VCEK,
                ChainVerification::WithProvidedArk {
                    ask: &$turin_ask,
                    ark: &$turin_ark,
                },
                Ok(()),
            ),
            (
                "milan_ok_provided",
                MILAN_ATTESTATION,
                MILAN_VCEK,
                ChainVerification::WithProvidedArk {
                    ask: &$milan_ask,
                    ark: &$milan_ark,
                },
                Ok(()),
            ),
            (
                "milan_invalid_root_certificate",
                MILAN_ATTESTATION,
                MILAN_VCEK,
                ChainVerification::WithProvidedArk {
                    ask: &$milan_ask,
                    ark: &$milan_ask,
                },
                Err("Invalid root certificate"),
            ),
            (
                "milan_genoa_ask",
                MILAN_ATTESTATION,
                MILAN_VCEK,
                ChainVerification::WithPinnedArk { ask: &$genoa_ask },
                Err("Certificate chain error"),
            ),
            (
                "milan_valid_provided_root_genoa_ask",
                MILAN_ATTESTATION,
                MILAN_VCEK,
                ChainVerification::WithProvidedArk {
                    ask: &$genoa_ask,
                    ark: &$milan_ark,
                },
                Err("Certificate chain error"),
            ),
            (
                "tampered_attestation",
                &$tampered_milan_attestation,
                MILAN_VCEK,
                ChainVerification::Skip,
                Err("Signature verification error"),
            ),
            (
                "unsupported_signature_algo",
                &$unsupported_signature_algo_attestation,
                MILAN_VCEK,
                ChainVerification::Skip,
                Err("Signature verification error"),
            ),
            (
                "unsupported_milan_genoa_model",
                &$unsupported_milan_genoa_model_attestation,
                MILAN_VCEK,
                ChainVerification::Skip,
                Err("Unsupported processor"),
            ),
            (
                "unsupported_turin_model",
                &$unsupported_turin_model_attestation,
                MILAN_VCEK,
                ChainVerification::Skip,
                Err("Unsupported processor"),
            ),
            (
                "unsupported_family",
                &$unsupported_family_attestation,
                MILAN_VCEK,
                ChainVerification::Skip,
                Err("Unsupported processor"),
            ),
        ]
    };
}

#[cfg(sync_crypto)]
pub fn test_verify_attestation_suite() {
    let tampered_milan_attestation = {
        let mut tampered = MILAN_ATTESTATION.to_vec();
        // Flip some bits in the attestation report to cause signature verification to fail
        tampered[100] ^= 0xFF;
        tampered
    };
    let unsupported_signature_algo_attestation = report_with_signature_algo(0x0002);
    let unsupported_milan_genoa_model_attestation = report_with_cpuid(0x19, 0x20);
    let unsupported_turin_model_attestation = report_with_cpuid(0x1A, 0x12);
    let unsupported_family_attestation = report_with_cpuid(0x1B, 0x00);

    let milan_ark = certificate_from_pem(MILAN_ARK).unwrap();
    let genoa_ark = certificate_from_pem(GENOA_ARK).unwrap();
    let turin_ark = certificate_from_pem(TURIN_ARK).unwrap();
    let milan_ask = certificate_from_pem(MILAN_ASK).unwrap();
    let genoa_ask = certificate_from_pem(GENOA_ASK).unwrap();
    let turin_ask = certificate_from_pem(TURIN_ASK).unwrap();

    for (tag, att, vcek, chain, expected) in attestation_tests!(
        milan_ark,
        genoa_ark,
        turin_ark,
        milan_ask,
        genoa_ask,
        turin_ask,
        tampered_milan_attestation,
        unsupported_signature_algo_attestation,
        unsupported_milan_genoa_model_attestation,
        unsupported_turin_model_attestation,
        unsupported_family_attestation
    ) {
        let report = AttestationReport::read_from_bytes(att).unwrap();
        let vcek = certificate_from_pem(vcek).unwrap();
        let result = tee_attestation_verification_lib::snp::verify::sync::verify_attestation(
            &report, &vcek, &chain,
        );

        if let Err(e_str) = expected {
            let err = result.expect_err(&format!("{}: Expected to fail with {}", tag, e_str));
            assert!(
                err.to_string().contains(e_str),
                "{}: Expected error to contain '{}', got: {:?}",
                tag,
                e_str,
                err
            );
        } else {
            result.expect(&format!("{}: Expected verification to succeed", tag))
        };
    }
}

#[cfg(async_crypto)]
pub async fn test_verify_attestation_suite_async() {
    let tampered_milan_attestation = {
        let mut tampered = MILAN_ATTESTATION.to_vec();
        tampered[100] ^= 0xFF;
        tampered
    };
    let unsupported_signature_algo_attestation = report_with_signature_algo(0x0002);
    let unsupported_milan_genoa_model_attestation = report_with_cpuid(0x19, 0x20);
    let unsupported_turin_model_attestation = report_with_cpuid(0x1A, 0x12);
    let unsupported_family_attestation = report_with_cpuid(0x1B, 0x00);

    let milan_ark = certificate_from_pem(MILAN_ARK).unwrap();
    let genoa_ark = certificate_from_pem(GENOA_ARK).unwrap();
    let turin_ark = certificate_from_pem(TURIN_ARK).unwrap();
    let milan_ask = certificate_from_pem(MILAN_ASK).unwrap();
    let genoa_ask = certificate_from_pem(GENOA_ASK).unwrap();
    let turin_ask = certificate_from_pem(TURIN_ASK).unwrap();

    for (tag, att, vcek, chain, expected) in attestation_tests!(
        milan_ark,
        genoa_ark,
        turin_ark,
        milan_ask,
        genoa_ask,
        turin_ask,
        tampered_milan_attestation,
        unsupported_signature_algo_attestation,
        unsupported_milan_genoa_model_attestation,
        unsupported_turin_model_attestation,
        unsupported_family_attestation
    ) {
        let report = AttestationReport::read_from_bytes(att).unwrap();
        let vcek = certificate_from_pem(vcek).unwrap();
        let result =
            tee_attestation_verification_lib::snp::verify::asynchronous::verify_attestation(
                &report, &vcek, &chain,
            )
            .await;

        if let Err(e_str) = expected {
            let err = result.expect_err(&format!("{}: Expected to fail with {}", tag, e_str));
            assert!(
                err.to_string().contains(e_str),
                "{}: Expected error to contain '{}', got: {:?}",
                tag,
                e_str,
                err
            );
        } else {
            result.expect(&format!("{}: Expected verification to succeed", tag))
        };
    }
}

#[cfg(all(feature = "kds", async_crypto))]
pub async fn verify_attestation_bytes(bytes: &[u8]) -> Result<(), String> {
    let attestation_report = AttestationReport::read_from_bytes(bytes)
        .map_err(|e| format!("Failed to read attestation report: {:?}", e))?;

    let mut verifier = SevVerifier::new()
        .await
        .map_err(|e| format!("Failed to initialize verifier: {:?}", e))?;

    verifier
        .verify_attestation(&attestation_report)
        .await
        .map_err(|e| format!("Verification call failed: {:?}", e))
}

#[cfg(all(feature = "kds", async_crypto))]
pub async fn verify_milan_attestation() -> Result<(), String> {
    verify_attestation_bytes(MILAN_ATTESTATION).await
}

#[cfg(all(feature = "kds", async_crypto))]
pub async fn verify_genoa_attestation() -> Result<(), String> {
    verify_attestation_bytes(GENOA_ATTESTATION).await
}

#[cfg(all(feature = "kds", async_crypto))]
pub async fn verify_turin_attestation() -> Result<(), String> {
    verify_attestation_bytes(TURIN_ATTESTATION).await
}
