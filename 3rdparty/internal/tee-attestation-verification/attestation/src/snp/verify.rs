// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SEV-SNP attestation verification with caller-provided certificates.
//!
//! The verification APIs identify the processor generation from the report,
//! optionally verify the ARK → ASK → VCEK certificate chain, verify the report
//! signature with the VCEK, and compare report TCB values against VCEK
//! certificate extensions.
//!
//! Only VCEK-signed reports are supported. Reports whose `SIGNING_KEY` flag
//! selects VLEK, `None`, or a reserved value are rejected, and the VCEK must
//! carry the AMD hardware ID extension.
//!
//! Successful verification authenticates the signed report, including
//! [`AttestationReport::report_data`](crate::AttestationReport::report_data),
//! but callers should compare `report_data` to their expected nonce, challenge,
//! public-key digest, or other application-specific context.
//!
//! # Guarantees and limitations
//!
//! `Ok(())` means the supplied VCEK signed the report and its hardware ID
//! and TCB extensions match the report. [`ChainVerification::WithPinnedArk`]
//! and [`ChainVerification::WithProvidedArk`] also verify the VCEK against
//! the AMD root key compiled into this crate. [`ChainVerification::Skip`]
//! trusts the supplied VCEK as is. Validity periods are checked at the local
//! clock when the chain is verified. Revocation is never checked. Nonce
//! binding, measurement, guest policy, and minimum TCB levels are the
//! caller's responsibility. See the crate README.
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
    /// confirming that the provided ARK has the pinned ARK's issuer and public
    /// key and carries a valid self-signature.
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

    use super::{pinned_ark_matching, verify_tcb_values, ChainVerification, VerificationError};

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
                let pinned_ark = pinned_ark_matching(generation, ark)
                    .map_err(|e| VerificationError::InvalidRootCertificate(format!("{:?}", e)))?;
                Crypto::verify_chain(&pinned_ark, &[], ark, None).map_err(|e| {
                    VerificationError::InvalidRootCertificate(format!(
                        "Provided ARK self-signature is invalid: {:?}",
                        e
                    ))
                })?;

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

        super::check_signing_key(attestation_report)?;
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

    use super::{pinned_ark_matching, verify_tcb_values, ChainVerification, VerificationError};

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
                let pinned_ark = pinned_ark_matching(generation, ark)
                    .map_err(|e| VerificationError::InvalidRootCertificate(format!("{:?}", e)))?;
                Crypto::verify_chain(&pinned_ark, &[], ark, None)
                    .await
                    .map_err(|e| {
                        VerificationError::InvalidRootCertificate(format!(
                            "Provided ARK self-signature is invalid: {:?}",
                            e
                        ))
                    })?;

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

        super::check_signing_key(attestation_report)?;
        snp::report::verify_report_signature_async(vcek, attestation_report)
            .await
            .map_err(|e| VerificationError::SignatureVerificationError(format!("{:?}", e)))?;

        verify_tcb_values(vcek, attestation_report)
            .map_err(|e| VerificationError::TcbVerificationError(format!("{:?}", e)))?;

        Ok(())
    }
}

/// Returns the pinned ARK for `generation` after checking that `ark` has the
/// same issuer name and public key.
///
/// The caller must still verify `ark` against the returned pinned ARK with
/// `Crypto::verify_chain`, so that a provided ARK with a corrupted
/// self-signature is rejected.
pub(crate) fn pinned_ark_matching(
    generation: snp::model::Generation,
    ark: &Certificate,
) -> Result<Certificate, Box<dyn std::error::Error>> {
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
    Ok(pinned_ark)
}

/// Rejects reports that are not signed with a VCEK.
///
/// Only VCEK-signed reports are supported. VLEK, `None`, and reserved
/// signing-key encodings are rejected because their signers cannot be
/// verified with the VCEK chain and hardware ID checks in this module.
pub(crate) fn check_signing_key(report: &AttestationReport) -> Result<(), VerificationError> {
    match report.flags().signing_key() {
        snp::report::SigningKey::Vcek => Ok(()),
        other => Err(VerificationError::SignatureVerificationError(format!(
            "Unsupported signing key {:?}: only VCEK-signed reports are supported",
            other
        ))),
    }
}

/// Matches a TCB component extension value against the report's byte.
///
/// AMD encodes these extensions as a DER INTEGER: `02 01 xx` for values below
/// 0x80 and `02 02 00 xx` for values from 0x80 to 0xFF. A bare single byte is
/// also accepted. Every other length, tag, or non-canonical INTEGER is
/// rejected.
fn tcb_extension_matches(ext_value: &[u8], expected: u8) -> bool {
    match ext_value {
        [value] => *value == expected,
        [0x02, 0x01, value] => *value < 0x80 && *value == expected,
        [0x02, 0x02, 0x00, value] => *value >= 0x80 && *value == expected,
        _ => false,
    }
}

/// Length of the hardware ID carried in the VCEK for each generation.
///
/// Milan and Genoa VCEKs carry the full 64-byte chip ID. Turin VCEKs carry
/// an 8-byte ID that matches the first 8 bytes of the report's `chip_id`; the
/// remaining 56 report bytes must be zero.
fn hwid_len(generation: snp::model::Generation) -> usize {
    match generation {
        snp::model::Generation::Milan | snp::model::Generation::Genoa => 64,
        snp::model::Generation::Turin => 8,
    }
}

/// Matches the VCEK hardware ID extension against the report's `chip_id`.
///
/// The extension value must be exactly `hwid_len(generation)` raw bytes, or
/// that same value wrapped in a DER OCTET STRING with an exact length byte.
/// The raw length is checked first so that an ID starting with 0x04 is not
/// mistaken for a DER wrapper.
fn hwid_extension_matches(
    ext_value: &[u8],
    chip_id: &[u8; 64],
    generation: snp::model::Generation,
) -> bool {
    let len = hwid_len(generation);
    let hwid = if ext_value.len() == len {
        ext_value
    } else if ext_value.len() == len + 2 && ext_value[0] == 0x04 && ext_value[1] as usize == len {
        &ext_value[2..]
    } else {
        return false;
    };
    hwid == &chip_id[..len] && chip_id[len..].iter().all(|b| *b == 0)
}

pub(crate) fn verify_tcb_values(
    vcek: &Certificate,
    attestation_report: &AttestationReport,
) -> Result<(), Box<dyn std::error::Error>> {
    let check_u8_ext = |oid: &str, expected: u8| -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ext_value) = Crypto::get_extension_value_by_oid(vcek, oid)? {
            if tcb_extension_matches(&ext_value, expected) {
                return Ok(());
            }
            return Err(format!(
                "Mismatched value OID {} : {} != {:02x}",
                oid,
                crypto::hex::to_hex(&ext_value),
                expected
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
    let cert_hwid = Crypto::get_extension_value_by_oid(vcek, hwid_oid)?
        .ok_or_else(|| format!("Extension OID {} not found in VCEK", hwid_oid))?;
    if !hwid_extension_matches(&cert_hwid, &attestation_report.chip_id, gen) {
        return Err("Report TCB ID and Certificate ID mismatch".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use zerocopy::TryFromBytes;

    use crate::crypto::{Certificate, CertificateBackend, Crypto};
    use crate::AttestationReport;

    use super::{
        check_signing_key, hwid_extension_matches, tcb_extension_matches, verify_tcb_values,
        VerificationError,
    };
    use crate::snp::model::Generation;

    const MILAN_ASK: &[u8] = include_bytes!("../../tests/test_data/milan_ask.pem");
    const MILAN_VCEK: &[u8] = include_bytes!("../../tests/test_data/milan_vcek.pem");
    const TURIN_VCEK: &[u8] = include_bytes!("../../tests/test_data/turin_vcek.pem");
    const MILAN_REPORT: &[u8] =
        include_bytes!("../../tests/test_data/milan_attestation_report.bin");
    const TURIN_REPORT: &[u8] =
        include_bytes!("../../tests/test_data/turin_attestation_report.bin");
    const TURIN_KDS_ASK: &[u8] = include_bytes!("../../tests/test_data/turin_kds_ask.pem");
    const TURIN_KDS_ARK: &[u8] = include_bytes!("../../tests/test_data/turin_kds_ark.pem");

    // Self-signed certificate carrying the Milan report fixture's TCB extensions
    // (bl=4, tee=0, snp=0x18, ucode=0xDB as DER INTEGERs) but no hardware ID
    // extension. Generated with `openssl req -new -x509 -key <p384 key> -sha384
    // -config <cnf>` where the cnf lists the four 1.3.6.1.4.1.3704.1.3.* OIDs.
    // It is not signed by AMD and is only used for `verify_tcb_values`.
    const SYNTHETIC_VCEK_NO_HWID: &[u8] =
        include_bytes!("../../tests/test_data/synthetic_vcek_no_hwid.pem");

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
    fn tcb_extension_matching_accepts_supported_encodings() {
        assert!(tcb_extension_matches(&[0x05], 0x05));
        assert!(tcb_extension_matches(&[0xDB], 0xDB));
        assert!(tcb_extension_matches(&[0x02, 0x01, 0x05], 0x05));
        assert!(tcb_extension_matches(&[0x02, 0x01, 0x7F], 0x7F));
        assert!(tcb_extension_matches(&[0x02, 0x02, 0x00, 0x80], 0x80));
        assert!(tcb_extension_matches(&[0x02, 0x02, 0x00, 0xDB], 0xDB));
    }

    #[test]
    fn tcb_extension_matching_rejects_mismatches_and_malformed_encodings() {
        // Wrong values.
        assert!(!tcb_extension_matches(&[0x06], 0x05));
        assert!(!tcb_extension_matches(&[0x02, 0x01, 0x06], 0x05));
        assert!(!tcb_extension_matches(&[0x02, 0x02, 0x00, 0xDC], 0xDB));
        // Empty and over-long values.
        assert!(!tcb_extension_matches(&[], 0x00));
        assert!(!tcb_extension_matches(&[0x05, 0x00], 0x05));
        assert!(!tcb_extension_matches(&[0x02, 0x01, 0x05, 0x00], 0x05));
        // Negative INTEGER: 0x80..=0xFF must use the two-byte form.
        assert!(!tcb_extension_matches(&[0x02, 0x01, 0xDB], 0xDB));
        // Non-canonical two-byte INTEGER for a value below 0x80.
        assert!(!tcb_extension_matches(&[0x02, 0x02, 0x00, 0x05], 0x05));
        // Out-of-range INTEGER.
        assert!(!tcb_extension_matches(&[0x02, 0x02, 0x01, 0x05], 0x05));
        // Wrong length byte and wrong tag.
        assert!(!tcb_extension_matches(&[0x02, 0x02, 0x05], 0x05));
        assert!(!tcb_extension_matches(&[0x04, 0x01, 0x05], 0x05));
    }

    #[test]
    fn hwid_extension_matching_accepts_generation_lengths() {
        let mut chip_id = [0u8; 64];
        for (i, b) in chip_id.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        for gen in [Generation::Milan, Generation::Genoa] {
            assert!(hwid_extension_matches(&chip_id, &chip_id, gen));
            let mut wrapped = vec![0x04, 64];
            wrapped.extend_from_slice(&chip_id);
            assert!(hwid_extension_matches(&wrapped, &chip_id, gen));
        }

        let mut turin_chip_id = [0u8; 64];
        turin_chip_id[..8].copy_from_slice(&[0x59, 0x79, 0x0F, 0xB1, 0xC3, 0x9F, 0x35, 0xC1]);
        assert!(hwid_extension_matches(
            &turin_chip_id[..8],
            &turin_chip_id,
            Generation::Turin
        ));
        let mut wrapped = vec![0x04, 8];
        wrapped.extend_from_slice(&turin_chip_id[..8]);
        assert!(hwid_extension_matches(
            &wrapped,
            &turin_chip_id,
            Generation::Turin
        ));

        // A raw ID that starts with 0x04 is compared as raw bytes, not DER.
        let mut chip_id_04 = chip_id;
        chip_id_04[0] = 0x04;
        chip_id_04[1] = 62;
        assert!(hwid_extension_matches(
            &chip_id_04,
            &chip_id_04,
            Generation::Milan
        ));
    }

    #[test]
    fn hwid_extension_matching_rejects_wrong_lengths_and_values() {
        let chip_id = [0x11u8; 64];
        // Wrong length for the generation.
        assert!(!hwid_extension_matches(
            &chip_id[..8],
            &chip_id,
            Generation::Milan
        ));
        assert!(!hwid_extension_matches(
            &chip_id,
            &chip_id,
            Generation::Turin
        ));
        assert!(!hwid_extension_matches(&[], &chip_id, Generation::Milan));
        assert!(!hwid_extension_matches(
            &chip_id[..63],
            &chip_id,
            Generation::Milan
        ));
        // Value mismatch.
        let mut other = chip_id;
        other[63] ^= 0xFF;
        assert!(!hwid_extension_matches(&other, &chip_id, Generation::Milan));
        // DER wrapper with the wrong length byte or trailing bytes.
        let mut wrapped = vec![0x04, 63];
        wrapped.extend_from_slice(&chip_id);
        assert!(!hwid_extension_matches(
            &wrapped,
            &chip_id,
            Generation::Milan
        ));
        let mut trailing = vec![0x04, 64];
        trailing.extend_from_slice(&chip_id);
        trailing.push(0x00);
        assert!(!hwid_extension_matches(
            &trailing,
            &chip_id,
            Generation::Milan
        ));
        // Turin: the 56 report bytes after the 8-byte ID must be zero.
        let mut turin_chip_id = [0u8; 64];
        turin_chip_id[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        turin_chip_id[8] = 1;
        assert!(!hwid_extension_matches(
            &turin_chip_id[..8],
            &turin_chip_id,
            Generation::Turin
        ));
    }

    #[test]
    fn signing_key_check_accepts_only_vcek() {
        let mut report = milan_report();
        check_signing_key(&report).expect("VCEK-signed fixture should be accepted");

        // Flags bits 4:2 hold SIGNING_KEY: 1 = VLEK, 2..=6 reserved, 7 = None.
        for (raw, name) in [
            (1u32, "Vlek"),
            (2, "Reserved(2)"),
            (6, "Reserved(6)"),
            (7, "None"),
        ] {
            report.flags.set(raw << 2);
            assert_ne!(
                report.flags().signing_key(),
                crate::snp::report::SigningKey::Vcek
            );
            match check_signing_key(&report) {
                Err(VerificationError::SignatureVerificationError(msg)) => {
                    assert!(msg.contains(name), "{msg}")
                }
                other => panic!("signing key {raw} should be rejected, got {other:?}"),
            }
        }
    }

    #[test]
    fn verify_tcb_values_accepts_authentic_fixtures() {
        let vcek = Crypto::from_pem(MILAN_VCEK).expect("Milan VCEK should parse");
        verify_tcb_values(&vcek, &milan_report()).expect("Milan fixture should match");

        let vcek = Crypto::from_pem(TURIN_VCEK).expect("Turin VCEK should parse");
        verify_tcb_values(&vcek, &turin_report()).expect("Turin fixture should match");
    }

    #[test]
    fn verify_tcb_values_rejects_missing_hwid_extension() {
        let vcek = Crypto::from_pem(SYNTHETIC_VCEK_NO_HWID).expect("synthetic VCEK should parse");
        let report = milan_report();

        let err = verify_tcb_values(&vcek, &report).expect_err("Missing hwID should fail");
        assert!(
            err.to_string()
                .contains("Extension OID 1.3.6.1.4.1.3704.1.4 not found"),
            "expected missing hwID error, got: {err}"
        );
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
