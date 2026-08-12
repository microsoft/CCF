// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SEV-SNP attestation verification with caller-provided certificates.
//!
//! The verification APIs identify the processor generation from the report,
//! optionally verify the ARK → ASK → VCEK certificate chain, verify the report
//! signature with the VCEK, and compare report TCB values against VCEK
//! certificate extensions.
//!
//! Successful verification authenticates the signed report, including
//! [`AttestationReport::report_data`](crate::AttestationReport::report_data),
//! but callers should compare `report_data` to their expected nonce, challenge,
//! public-key digest, or other application-specific context.
//!
//! The `sync` and `asynchronous` modules provide separate APIs for synchronous and asynchronous crypto backends.
//!
//! # Example
//!
//! Verify an attestation report before returning the authenticated claims to the caller:
//!
//! ```no_run
//! use tee_attestation_verification_lib::certificate_from_pem;
//! use tee_attestation_verification_lib::snp::report::{AttestationReport, TryFromBytes};
//! use tee_attestation_verification_lib::snp::verify::{asynchronous as tav, ChainVerification};
//!
//! # async fn example<'a>(
//! #     attestation_bytes: &'a [u8],
//! #     vcek_pem: &'a [u8],
//! #     ask_pem: &'a [u8],
//! # ) -> Result<AttestationReport, Box<dyn std::error::Error + 'a>> {
//! let report = AttestationReport::try_read_from_bytes(attestation_bytes)?;
//! let vcek = certificate_from_pem(vcek_pem)?;
//! let ask = certificate_from_pem(ask_pem)?;
//!
//! tav::verify_attestation(
//!     &report,
//!     &vcek,
//!     &ChainVerification::WithPinnedArk { ask: &ask },
//! )
//! .await?;
//!
//! # Ok(report)
//! # }
//! ```

use crate::crypto::{Certificate, CertificateBackend, Crypto};
use crate::{snp, snp::utils::Oid, AttestationReport};

/// Error returned when SEV-SNP attestation verification fails.
#[derive(Debug)]
pub enum VerificationError {
    /// The report's processor family/model is not supported by this crate.
    UnsupportedProcessor(String),
    /// The selected or provided ARK certificate is not a valid trusted root.
    InvalidRootCertificate(String),
    /// The ARK → ASK → VCEK certificate chain could not be verified.
    CertificateChainError(String),
    /// The attestation report signature could not be verified with the VCEK.
    SignatureVerificationError(String),
    /// Report TCB values did not match the corresponding VCEK extensions.
    TcbVerificationError(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedProcessor(e) => write!(f, "Unsupported processor: {}", e),
            Self::InvalidRootCertificate(e) => write!(f, "Invalid root certificate: {}", e),
            Self::CertificateChainError(e) => write!(f, "Certificate chain error: {}", e),
            Self::SignatureVerificationError(e) => write!(f, "Signature verification error: {}", e),
            Self::TcbVerificationError(e) => write!(f, "TCB verification error: {}", e),
        }
    }
}

impl std::error::Error for VerificationError {}

/// Certificate-chain verification mode for caller-provided certificates.
pub enum ChainVerification<'a> {
    /// Skip certificate-chain verification and only verify the report signature
    /// and TCB values using the provided VCEK.
    Skip,
    /// Verify the chain using the ASK provided by the caller and the pinned ARK
    /// for the report's processor generation.
    WithPinnedArk {
        /// AMD SEV Key (ASK) certificate.
        ask: &'a Certificate,
    },
    /// Verify the chain using caller-provided ASK and ARK certificates after
    /// confirming that the provided ARK public key matches the pinned ARK.
    WithProvidedArk {
        /// AMD SEV Key (ASK) certificate.
        ask: &'a Certificate,
        /// AMD Root Key (ARK) certificate.
        ark: &'a Certificate,
    },
}

#[cfg(sync_crypto)]
/// Synchronous SEV-SNP attestation verification.
pub mod sync {
    use crate::crypto::{Certificate, Crypto, CryptoBackend};
    use crate::{snp, AttestationReport};

    use super::{ark_matches_pinned, verify_tcb_values, ChainVerification, VerificationError};

    /// Verifies an SEV-SNP attestation report using caller-provided certificates.
    ///
    /// Verification consists of processor-generation detection, certificate-chain
    /// verification according to `chain_verification`, report signature
    /// verification with `vcek`, and report/VCEK TCB extension matching. Callers
    /// must separately compare `attestation_report.report_data` to the expected
    /// nonce, challenge, public-key digest, or other application-specific context.
    pub fn verify_attestation(
        attestation_report: &AttestationReport,
        vcek: &Certificate,
        chain_verification: &ChainVerification<'_>,
    ) -> Result<(), VerificationError> {
        let generation = snp::model::Generation::from_family_and_model(
            attestation_report.cpuid_fam_id,
            attestation_report.cpuid_mod_id,
        )
        .map_err(|e| VerificationError::UnsupportedProcessor(format!("{:?}", e)))?;

        match chain_verification {
            ChainVerification::WithProvidedArk { ask, ark } => {
                ark_matches_pinned(generation, ark)
                    .map_err(|e| VerificationError::InvalidRootCertificate(format!("{:?}", e)))?;

                Crypto::verify_chain(ark, &[ask], vcek, None)
                    .map_err(|e| VerificationError::CertificateChainError(format!("{:?}", e)))?;
            }
            ChainVerification::WithPinnedArk { ask } => {
                let pinned_ark = crate::pinned_arks::get_ark(generation)
                    .map_err(|e| VerificationError::InvalidRootCertificate(format!("{:?}", e)))?;
                Crypto::verify_chain(&pinned_ark, &[ask], vcek, None)
                    .map_err(|e| VerificationError::CertificateChainError(format!("{:?}", e)))?;
            }
            ChainVerification::Skip => {}
        };

        snp::report::verify_report_signature(vcek, attestation_report)
            .map_err(|e| VerificationError::SignatureVerificationError(format!("{:?}", e)))?;

        verify_tcb_values(vcek, attestation_report)
            .map_err(|e| VerificationError::TcbVerificationError(format!("{:?}", e)))?;

        Ok(())
    }
}

#[cfg(async_crypto)]
/// Asynchronous SEV-SNP attestation verification.
pub mod asynchronous {
    use crate::crypto::{AsyncCryptoBackend, Certificate, Crypto};
    use crate::{snp, AttestationReport};

    use super::{ark_matches_pinned, verify_tcb_values, ChainVerification, VerificationError};

    /// Verifies an SEV-SNP attestation report using caller-provided certificates.
    ///
    /// Verification consists of processor-generation detection, certificate-chain
    /// verification according to `chain_verification`, report signature
    /// verification with `vcek`, and report/VCEK TCB extension matching. Callers
    /// must separately compare `attestation_report.report_data` to the expected
    /// nonce, challenge, public-key digest, or other application-specific context.
    pub async fn verify_attestation(
        attestation_report: &AttestationReport,
        vcek: &Certificate,
        chain_verification: &ChainVerification<'_>,
    ) -> Result<(), VerificationError> {
        let generation = snp::model::Generation::from_family_and_model(
            attestation_report.cpuid_fam_id,
            attestation_report.cpuid_mod_id,
        )
        .map_err(|e| VerificationError::UnsupportedProcessor(format!("{:?}", e)))?;

        match chain_verification {
            ChainVerification::WithProvidedArk { ask, ark } => {
                ark_matches_pinned(generation, ark)
                    .map_err(|e| VerificationError::InvalidRootCertificate(format!("{:?}", e)))?;

                Crypto::verify_chain(ark, &[ask], vcek, None)
                    .await
                    .map_err(|e| VerificationError::CertificateChainError(format!("{:?}", e)))?;
            }
            ChainVerification::WithPinnedArk { ask } => {
                let pinned_ark = crate::pinned_arks::get_ark(generation)
                    .map_err(|e| VerificationError::InvalidRootCertificate(format!("{:?}", e)))?;
                Crypto::verify_chain(&pinned_ark, &[ask], vcek, None)
                    .await
                    .map_err(|e| VerificationError::CertificateChainError(format!("{:?}", e)))?;
            }
            ChainVerification::Skip => {}
        };

        snp::report::verify_report_signature_async(vcek, attestation_report)
            .await
            .map_err(|e| VerificationError::SignatureVerificationError(format!("{:?}", e)))?;

        verify_tcb_values(vcek, attestation_report)
            .map_err(|e| VerificationError::TcbVerificationError(format!("{:?}", e)))?;

        Ok(())
    }
}

pub(crate) fn ark_matches_pinned(
    generation: snp::model::Generation,
    ark: &Certificate,
) -> Result<(), Box<dyn std::error::Error>> {
    let pinned_ark = crate::pinned_arks::get_ark(generation)?;

    let pinned_issuer = Crypto::issuer_name_der(&pinned_ark)?;
    let provided_issuer = Crypto::issuer_name_der(ark)?;
    if pinned_issuer != provided_issuer {
        return Err(format!(
            "Provided ARK issuer does not match pinned ARK for {}",
            generation
        )
        .into());
    }

    let pinned_key = Crypto::get_public_key(&pinned_ark)?;
    let provided_key = Crypto::get_public_key(ark)?;
    if pinned_key != provided_key {
        return Err(format!("Provided ARK does not match pinned ARK for {}", generation).into());
    }
    Ok(())
}

fn extension_value_matches(ext_value: &[u8], expected: &[u8]) -> bool {
    // Try direct match
    if ext_value == expected {
        return true;
    }
    // prefix match
    if ext_value.len() < expected.len()
        && ext_value == &expected[..ext_value.len()]
        && expected[ext_value.len()..].iter().all(|e| *e == 0)
    {
        return true;
    }
    // Try with INTEGER tag (0x02) wrapper
    if ext_value.len() >= 2 && ext_value[0] == 0x02 {
        if let Some(&last) = ext_value.last() {
            if expected.len() == 1 && last == expected[0] {
                return true;
            }
        }
    }
    // Try with OCTET STRING tag (0x04) wrapper
    if ext_value.len() >= 2 && ext_value[0] == 0x04 && ext_value.len() >= 2 {
        return &ext_value[2..] == expected;
    }
    false
}

pub(crate) fn verify_tcb_values(
    vcek: &Certificate,
    attestation_report: &AttestationReport,
) -> Result<(), Box<dyn std::error::Error>> {
    let check_u8_ext = |oid: &str, expected: u8| -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ext_value) = Crypto::get_extension_value_by_oid(vcek, oid)? {
            let expected = [expected];
            if extension_value_matches(&ext_value, &expected) {
                return Ok(());
            }
            return Err(format!(
                "Mismatched value OID {} : {} != {}",
                oid,
                crypto::hex::to_hex(&ext_value),
                crypto::hex::to_hex(&expected)
            )
            .into());
        }
        Err(format!("Extension OID {} not found in VCEK", oid).into())
    };

    let gen = snp::model::Generation::from_family_and_model(
        attestation_report.cpuid_fam_id,
        attestation_report.cpuid_mod_id,
    )?;
    match gen {
        snp::model::Generation::Milan | snp::model::Generation::Genoa => {
            let tcb = attestation_report.reported_tcb.as_milan_genoa();
            let bl_oid = Oid::BootLoader.as_str();
            check_u8_ext(bl_oid, tcb.boot_loader)
                .map_err(|e| format!("Error verifying TCB boot loader: {}", e))?;

            let tee_oid = Oid::Tee.as_str();
            check_u8_ext(tee_oid, tcb.tee)
                .map_err(|e| format!("Error verifying TCB TEE: {}", e))?;

            let snp_oid = Oid::Snp.as_str();
            check_u8_ext(snp_oid, tcb.snp)
                .map_err(|e| format!("Error verifying TCB SNP: {}", e))?;

            let ucode_oid = Oid::Ucode.as_str();
            check_u8_ext(ucode_oid, tcb.microcode)
                .map_err(|e| format!("Error verifying TCB microcode: {}", e))?;
        }
        snp::model::Generation::Turin => {
            let tcb = attestation_report.reported_tcb.as_turin();
            let bl_oid = Oid::BootLoader.as_str();
            check_u8_ext(bl_oid, tcb.boot_loader)
                .map_err(|e| format!("Error verifying TCB boot loader: {}", e))?;

            let tee_oid = Oid::Tee.as_str();
            check_u8_ext(tee_oid, tcb.tee)
                .map_err(|e| format!("Error verifying TCB TEE: {}", e))?;

            let snp_oid = Oid::Snp.as_str();
            check_u8_ext(snp_oid, tcb.snp)
                .map_err(|e| format!("Error verifying TCB SNP: {}", e))?;

            let ucode_oid = Oid::Ucode.as_str();
            check_u8_ext(ucode_oid, tcb.microcode)
                .map_err(|e| format!("Error verifying TCB microcode: {}", e))?;

            let fmc_oid = Oid::Fmc.as_str();
            check_u8_ext(fmc_oid, tcb.fmc)
                .map_err(|e| format!("Error verifying TCB FMC: {}", e))?;
        }
    }

    let hwid_oid = Oid::HwId.as_str();
    if let Some(cert_hwid) = Crypto::get_extension_value_by_oid(vcek, hwid_oid)? {
        if !extension_value_matches(&cert_hwid, attestation_report.chip_id.as_slice()) {
            return Err("Report TCB ID and Certificate ID mismatch".into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use zerocopy::TryFromBytes;

    use crate::crypto::{Certificate, CertificateBackend, Crypto};
    use crate::AttestationReport;

    use super::{extension_value_matches, verify_tcb_values};

    const MILAN_ASK: &[u8] = include_bytes!("../../tests/test_data/milan_ask.pem");
    const MILAN_VCEK: &[u8] = include_bytes!("../../tests/test_data/milan_vcek.pem");
    const MILAN_REPORT: &[u8] =
        include_bytes!("../../tests/test_data/milan_attestation_report.bin");
    const TURIN_REPORT: &[u8] =
        include_bytes!("../../tests/test_data/turin_attestation_report.bin");
    const TURIN_KDS_ASK: &[u8] = include_bytes!("../../tests/test_data/turin_kds_ask.pem");
    const TURIN_KDS_ARK: &[u8] = include_bytes!("../../tests/test_data/turin_kds_ark.pem");

    // KDS-generated Turin VCEKs for the public Turin report fixture's KDS chip ID
    // 59790FB1C39F35C1. The report TCB is fmc=1, bl=1, tee=1, snp=4,
    // ucode=81; each fixture changes exactly one field and leaves the others matched.
    const TURIN_VCEK_MISMATCH_FMC: &[u8] =
        include_bytes!("../../tests/test_data/turin_vcek_mismatch_fmc_02.der");
    const TURIN_VCEK_MISMATCH_BL: &[u8] =
        include_bytes!("../../tests/test_data/turin_vcek_mismatch_bl_02.der");
    const TURIN_VCEK_MISMATCH_TEE: &[u8] =
        include_bytes!("../../tests/test_data/turin_vcek_mismatch_tee_02.der");
    const TURIN_VCEK_MISMATCH_SNP: &[u8] =
        include_bytes!("../../tests/test_data/turin_vcek_mismatch_snp_05.der");
    const TURIN_VCEK_MISMATCH_UCODE: &[u8] =
        include_bytes!("../../tests/test_data/turin_vcek_mismatch_ucode_82.der");

    fn milan_report() -> AttestationReport {
        AttestationReport::try_read_from_bytes(MILAN_REPORT)
            .expect("Milan report fixture should parse")
            .clone()
    }

    fn turin_report() -> AttestationReport {
        AttestationReport::try_read_from_bytes(TURIN_REPORT)
            .expect("Turin report fixture should parse")
            .clone()
    }

    fn cert_from_der(der: &[u8]) -> Certificate {
        Crypto::from_der(der).expect("DER certificate fixture should parse")
    }

    #[test]
    fn turin_kds_chain_fixtures_parse() {
        Crypto::from_pem(TURIN_KDS_ASK).expect("Turin KDS ASK should parse");
        Crypto::from_pem(TURIN_KDS_ARK).expect("Turin KDS ARK should parse");
    }

    #[test]
    fn extension_value_matching_accepts_supported_encodings() {
        assert!(extension_value_matches(&[0x05], &[0x05]));
        assert!(extension_value_matches(&[0x05], &[0x05, 0x00, 0x00]));
        assert!(extension_value_matches(&[0x02, 0x01, 0x05], &[0x05]));
        assert!(extension_value_matches(
            &[0x04, 0x02, 0x05, 0x06],
            &[0x05, 0x06]
        ));
    }

    #[test]
    fn extension_value_matching_rejects_mismatches() {
        assert!(!extension_value_matches(&[0x06], &[0x05]));
        assert!(!extension_value_matches(&[0x05], &[0x05, 0x01]));
        assert!(!extension_value_matches(&[0x02, 0x01, 0x06], &[0x05]));
        assert!(!extension_value_matches(&[0x04, 0x02, 0x06], &[0x05]));
    }

    #[test]
    fn verify_tcb_values_rejects_mismatched_tcb_extension() {
        let vcek = Crypto::from_pem(MILAN_VCEK).expect("Milan VCEK should parse");
        let mut report = milan_report();
        report.reported_tcb.raw[0] ^= 0xFF;

        let err =
            verify_tcb_values(&vcek, &report).expect_err("Mismatched TCB extension should fail");
        assert!(
            err.to_string().contains("Error verifying TCB boot loader"),
            "expected boot loader TCB error, got: {err}"
        );
    }

    #[test]
    fn verify_tcb_values_rejects_missing_tcb_extension() {
        let ask = Crypto::from_pem(MILAN_ASK).expect("Milan ASK should parse");
        let report = milan_report();

        let err = verify_tcb_values(&ask, &report).expect_err("Missing TCB extension should fail");
        assert!(
            err.to_string().contains("Extension OID"),
            "expected missing extension error, got: {err}"
        );
    }

    #[test]
    fn verify_tcb_values_rejects_hwid_mismatch() {
        let vcek = Crypto::from_pem(MILAN_VCEK).expect("Milan VCEK should parse");
        let mut report = milan_report();
        report.chip_id[0] ^= 0xFF;

        let err = verify_tcb_values(&vcek, &report).expect_err("HWID mismatch should fail");
        assert!(
            err.to_string()
                .contains("Report TCB ID and Certificate ID mismatch"),
            "expected HWID mismatch error, got: {err}"
        );
    }

    #[test]
    fn verify_tcb_values_reports_turin_field_mismatches() {
        let report = turin_report();
        let cases: &[(&str, &[u8], &str)] = &[
            (
                "boot loader",
                TURIN_VCEK_MISMATCH_BL,
                "Error verifying TCB boot loader",
            ),
            ("TEE", TURIN_VCEK_MISMATCH_TEE, "Error verifying TCB TEE"),
            ("SNP", TURIN_VCEK_MISMATCH_SNP, "Error verifying TCB SNP"),
            (
                "microcode",
                TURIN_VCEK_MISMATCH_UCODE,
                "Error verifying TCB microcode",
            ),
            ("FMC", TURIN_VCEK_MISMATCH_FMC, "Error verifying TCB FMC"),
        ];

        for (field, der, expected_error) in cases {
            let vcek = cert_from_der(der);
            let err = verify_tcb_values(&vcek, &report)
                .expect_err(&format!("{field} mismatch should fail"));
            assert!(
                err.to_string().contains(expected_error),
                "expected {field} error to contain '{expected_error}', got: {err}"
            );
        }
    }
}
