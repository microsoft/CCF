// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ACI/UVM endorsement verification.
//!
//! This crate verifies an ACI COSE_Sign1 endorsement against a verified
//! SEV-SNP attestation report and a caller-pinned `did:x509` root of trust.
//!
//! Verification is split into two independent stages plus a final binding step:
//!
//! 1. Verify the SEV-SNP attestation report and AMD endorsements.
//! 2. Verify the UVM endorsement COSE, its `x5chain`, and its `did:x509` root.
//! 3. Bind the two verified artifacts by checking that the UVM launch
//!    measurement matches the attestation report measurement.
//!

mod didx509;
mod parse;

use attestation::snp::report::{AttestationReport, TcbVersionForGeneration, TcbVersionRaw};
use attestation::snp::verify::{ChainVerification, VerificationError};
use attestation::Generation;
use crypto::CertificateBackend;
#[cfg(async_crypto)]
use crypto::{AsyncCryptoBackend, AsyncKeyBackend};
#[cfg(sync_crypto)]
use crypto::{CryptoBackend, KeyBackend};

#[cfg(sync_crypto)]
use didx509::verify_didx509_root;
#[cfg(async_crypto)]
use didx509::verify_didx509_root_async;
use parse::{parse_attestation, parse_x5chain_certs, required_bstr, required_int, required_text};

pub use attestation::snp;
pub use cose::CborValue;

const fn attestation_report_field_len<const N: usize>(
    _: fn(&AttestationReport) -> &[u8; N],
) -> usize {
    N
}

const SNP_MEASUREMENT_LEN: usize = attestation_report_field_len(|report| &report.measurement);
/// Length of the SNP `HOST_DATA` field.
pub const SNP_HOST_DATA_LEN: usize = attestation_report_field_len(|report| &report.host_data);
/// Length of the SNP `REPORT_DATA` field.
pub const SNP_REPORT_DATA_LEN: usize = attestation_report_field_len(|report| &report.report_data);
const MAX_GUEST_VMPL: u32 = 3;
const JSON_LAUNCH_MEASUREMENT: &str = "x-ms-sevsnpvm-launchmeasurement";
const JSON_GUEST_SVN: &str = "x-ms-sevsnpvm-guestsvn";
const JSON_GUEST_SVN_INT: &str = "x-ms-sevsnpvm-guestsvn-int";

#[cfg(sync_crypto)]
/// Synchronous staged CACI verification.
///
/// Use this module when the active crypto backend supports synchronous
/// verification:
///
/// ```no_run
/// use tee_attestation_verification_caci::{synchronous as tav, SNP_HOST_DATA_LEN};
///
/// # fn example(
/// #     attestation: &[u8],
/// #     amd_endorsements: &[&[u8]],
/// #     aci_cose: &[u8],
/// #     trusted_didx509: &str,
/// #     trusted_caci_execution_policy: [u8; SNP_HOST_DATA_LEN],
/// #     minimum_uvm_svn: u64,
/// # ) -> Result<(), Box<dyn std::error::Error>> {
/// let report = tav::verify_attestation(
///     attestation,
///     amd_endorsements,
/// )?;
/// let uvm = tav::verify_uvm_endorsement(
///     aci_cose,
///     trusted_didx509,
/// )?;
/// let verified_report_data = tav::verify_caci_attestation(
///     report,
///     vec![],
///     vec![trusted_caci_execution_policy],
///     uvm,
///     "ContainerPlat-AMD-UVM",
///     minimum_uvm_svn,
/// )?;
/// # let _ = verified_report_data;
/// # Ok(())
/// # }
/// ```
pub mod synchronous {
    use super::*;

    /// Verify the SEV-SNP attestation report and its AMD endorsements.
    ///
    /// `amd_endorsements` must contain certificate bytes ordered as `[vcek,
    /// ask, ark]`. Successful verification authenticates the report signature,
    /// validates the AMD certificate chain, vcek -> ask -> ark, and checks report
    ///  TCB values against the VCEK certificate.
    pub fn verify_attestation(
        report: &[u8],
        amd_endorsements: &[&[u8]],
    ) -> Result<AttestationReport, AciError> {
        let report = parse_attestation(report)?;
        if amd_endorsements.len() != attestation::snp::AMD_ENDORSEMENT_COUNT {
            return Err(AciError::InvalidAmdEndorsements(format!(
                "expected [vcek, ask, ark], got {} certificate(s)",
                amd_endorsements.len()
            )));
        }
        let [vcek, ask, ark] = amd_endorsements
            .iter()
            .map(|cert| parse::parse_certificate(cert))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| AciError::InvalidAmdEndorsements("".to_string()))?;
        attestation::snp::verify::sync::verify_attestation(
            &report,
            &vcek,
            &ChainVerification::WithProvidedArk {
                ask: &ask,
                ark: &ark,
            },
        )
        .map_err(AciError::AttestationVerification)?;
        Ok(report)
    }

    /// Verify an ACI/UVM endorsement independently of the attestation report.
    ///
    /// This verifies the COSE_Sign1 signature, the `x5chain`, and that the
    /// chain root matches `trusted_didx509`.
    pub fn verify_uvm_endorsement(
        uvm_endorsement: &[u8],
        trusted_didx509: &str,
    ) -> Result<CborValue, AciError> {
        let parsed = CborValue::from_bytes(uvm_endorsement).map_err(AciError::Cose)?;
        let sign1 = cose::cose_sign1(&parsed).map_err(AciError::Cose)?;
        // sign1 fields
        let protected = required_bstr(sign1.array_at(0).map_err(AciError::Cose)?, "protected")?;
        let _unprotected = sign1.array_at(1).map_err(AciError::Cose)?;
        let payload = required_bstr(sign1.array_at(2).map_err(AciError::Cose)?, "payload")?;
        let signature = required_bstr(sign1.array_at(3).map_err(AciError::Cose)?, "signature")?;

        let protected_header = CborValue::from_bytes(&protected).map_err(AciError::Cose)?;
        let x5chain = parse::parse_x5chain(
            protected_header
                .map_at_int(cose::COSE_HEADER_X5CHAIN)
                .map_err(AciError::Cose)?,
        )?;

        let (root, intermediates, leaf) = parse_x5chain_certs(&x5chain)?;
        let intermediate_refs = intermediates.iter().collect::<Vec<_>>();
        let content_type = protected_header
            .map_at_int(cose::COSE_HEADER_CONTENT_TYPE)
            .or_else(|_| protected_header.map_at_int(cose::COSE_HEADER_PREIMAGE_CONTENT_TYPE))
            .map_err(|_| AciError::Cose("protected content type not found".to_string()))
            .and_then(|value| required_text(value, "protected content type"))?;
        match content_type.as_str() {
            // Legacy UVM endorsements carry claims in protected headers and a JSON payload.
            "application/json"
                if protected_header.map_at_str("iss").is_ok()
                    && protected_header.map_at_str("signingtime").is_ok() =>
            {
                let issuer = required_text(
                    protected_header.map_at_str("iss").map_err(AciError::Cose)?,
                    "iss",
                )?;
                verify_didx509_root(trusted_didx509, &issuer, &x5chain)?;

                let signing_time = protected_header
                    .map_at_str("signingtime")
                    .ok()
                    .map(parse::parse_signing_time)
                    .transpose()?;
                <crypto::Crypto as CryptoBackend>::verify_chain(
                    &root,
                    &intermediate_refs,
                    &leaf,
                    signing_time,
                )
                .map_err(|e| AciError::Certificate(e.to_string()))?;
            }
            "application/octet-stream"
                if protected_header
                    .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
                    .is_ok() =>
            {
                let cwt_claims = protected_header
                    .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
                    .map_err(AciError::Cose)?;
                let issuer = required_text(
                    cwt_claims
                        .map_at_int(cose::CWT_CLAIMS_ISSUER)
                        .map_err(AciError::Cose)?,
                    "CWT iss",
                )?;
                verify_didx509_root(trusted_didx509, &issuer, &x5chain)?;

                let signing_time = cwt_claims
                    .map_at_int(cose::CWT_CLAIMS_IAT)
                    .ok()
                    .map(|iat| {
                        let iat = match iat {
                            CborValue::Tagged { tag: 1, payload } => {
                                required_int(payload, "CWT iat").map_err(|_| ())
                            }
                            CborValue::Int(iat) => Ok(*iat),
                            _ => Err(()),
                        }
                        .and_then(|iat| iat.try_into().map_err(|_| ()))
                        .map(std::time::Duration::from_secs)
                        .map_err(|_| AciError::Cose(format!("CWT iat invalid {iat:?}")))?;
                        Ok(iat)
                    })
                    .transpose()?;
                <crypto::Crypto as CryptoBackend>::verify_chain(
                    &root,
                    &intermediate_refs,
                    &leaf,
                    signing_time,
                )
                .map_err(|e| AciError::Certificate(e.to_string()))?;
            }
            other => {
                return Err(AciError::Measurement(format!(
                    "unsupported ACI payload content type {other}"
                )));
            }
        }

        // Verify signature
        let algorithm = cose::signature_key_algorithm_for_cose_alg(required_int(
            protected_header
                .map_at_int(cose::COSE_HEADER_ALG)
                .map_err(AciError::Cose)?,
            "protected alg",
        )?)
        .map_err(AciError::Cose)?;
        let spki = crypto::Crypto::get_public_key(&leaf)
            .map_err(|e| AciError::Certificate(e.to_string()))?;
        let key =
            <<crypto::Crypto as CryptoBackend>::Key as KeyBackend>::from_spki_der(&spki, algorithm)
                .map_err(|e| AciError::Certificate(e.to_string()))?;
        cose::synchronous::cose_verify1(&key, algorithm, &protected, &payload, &signature)
            .map_err(AciError::Signature)?;

        Ok(parsed)
    }

    /// Verify Confidential CACI relying-party policy over staged verified artifacts.
    ///
    /// [`verify_attestation`] must be used to authenticate the SNP report before
    /// calling this function, and [`verify_uvm_endorsement`] must be used to
    /// authenticate the UVM reference info and its did:x509 root.
    ///
    /// `trusted_caci_execution_policy` is the expected SHA-256 digest of the Confidential
    /// ACI security policy loaded into `SNP_HOST_DATA`. The returned value is the
    /// verified `SNP_REPORT_DATA` from the SNP report.
    pub fn verify_caci_attestation(
        attestation: AttestationReport,
        minimum_tcb: Vec<(snp::Cpuid, TcbVersionRaw)>,
        trusted_caci_execution_policy: Vec<[u8; SNP_HOST_DATA_LEN]>,
        uvm_endorsement: CborValue,
        uvm_feed: &str,
        minimum_svn: u64,
    ) -> Result<[u8; SNP_REPORT_DATA_LEN], AciError> {
        verify_caci_attestation_impl(
            attestation,
            minimum_tcb,
            trusted_caci_execution_policy,
            uvm_endorsement,
            uvm_feed,
            minimum_svn,
        )
    }
}

#[cfg(async_crypto)]
/// Asynchronous staged CACI verification.
///
/// Use this module when the active crypto backend is asynchronous, such as
/// WebCrypto:
///
/// ```no_run
/// use tee_attestation_verification_caci::{asynchronous as tav, SNP_HOST_DATA_LEN};
///
/// # async fn example(
/// #     attestation: &[u8],
/// #     amd_endorsements: &[&[u8]],
/// #     aci_cose: &[u8],
/// #     trusted_didx509: &str,
/// #     trusted_caci_execution_policy: [u8; SNP_HOST_DATA_LEN],
/// #     minimum_uvm_svn: u64,
/// # ) -> Result<(), Box<dyn std::error::Error>> {
/// let report = tav::verify_attestation(
///     attestation,
///     amd_endorsements,
/// ).await?;
/// let uvm = tav::verify_uvm_endorsement(
///     aci_cose,
///     trusted_didx509,
/// ).await?;
/// let verified_report_data = tav::verify_caci_attestation(
///     report,
///     vec![],
///     vec![trusted_caci_execution_policy],
///     uvm,
///     "ContainerPlat-AMD-UVM",
///     minimum_uvm_svn,
/// ).await?;
/// # let _ = verified_report_data;
/// # Ok(())
/// # }
/// ```
pub mod asynchronous {
    use super::*;

    /// Verify the SEV-SNP attestation report and its AMD endorsements.
    ///
    /// `amd_endorsements` must contain certificate bytes ordered as `[vcek,
    /// ask, ark]`. Successful verification authenticates the report signature,
    /// validates the AMD certificate chain, and checks report TCB values against
    /// the VCEK certificate. This is stage 1 of the ACI flow.
    pub async fn verify_attestation(
        report: &[u8],
        amd_endorsements: &[&[u8]],
    ) -> Result<AttestationReport, AciError> {
        let report = parse_attestation(report)?;
        let amd_endorsements: &[&[u8]] = amd_endorsements;
        if amd_endorsements.len() != attestation::snp::AMD_ENDORSEMENT_COUNT {
            return Err(AciError::InvalidAmdEndorsements(format!(
                "expected [vcek, ask, ark], got {} certificate(s)",
                amd_endorsements.len()
            )));
        }
        let [vcek, ask, ark] = amd_endorsements
            .iter()
            .map(|cert| parse::parse_certificate(cert))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| AciError::InvalidAmdEndorsements("".to_string()))?;
        attestation::snp::verify::asynchronous::verify_attestation(
            &report,
            &vcek,
            &ChainVerification::WithProvidedArk {
                ask: &ask,
                ark: &ark,
            },
        )
        .await
        .map_err(AciError::AttestationVerification)?;
        Ok(report)
    }

    /// Verify an ACI/UVM endorsement independently of the attestation report.
    ///
    /// This verifies the COSE_Sign1 signature, the `x5chain`, and that the
    /// chain root matches `trusted_didx509`. This is stage 2 of the ACI flow;
    /// call [`verify_caci_attestation`] afterwards to bind the UVM
    /// endorsement to the verified attestation report and relying-party policy.
    pub async fn verify_uvm_endorsement(
        uvm_endorsement: &[u8],
        trusted_didx509: &str,
    ) -> Result<CborValue, AciError> {
        let parsed = CborValue::from_bytes(uvm_endorsement).map_err(AciError::Cose)?;
        let sign1 = cose::cose_sign1(&parsed).map_err(AciError::Cose)?;
        // Sign1 fields
        let protected = required_bstr(sign1.array_at(0).map_err(AciError::Cose)?, "protected")?;
        let _unprotected = sign1.array_at(1).map_err(AciError::Cose)?;
        let payload = required_bstr(sign1.array_at(2).map_err(AciError::Cose)?, "payload")?;
        let signature = required_bstr(sign1.array_at(3).map_err(AciError::Cose)?, "signature")?;

        let protected_header = CborValue::from_bytes(&protected).map_err(AciError::Cose)?;
        let x5chain = parse::parse_x5chain(
            protected_header
                .map_at_int(cose::COSE_HEADER_X5CHAIN)
                .map_err(AciError::Cose)?,
        )?;
        let (root, intermediates, leaf) = parse_x5chain_certs(&x5chain)?;
        let intermediate_refs = intermediates.iter().collect::<Vec<_>>();
        let content_type = protected_header
            .map_at_int(cose::COSE_HEADER_CONTENT_TYPE)
            .or_else(|_| protected_header.map_at_int(cose::COSE_HEADER_PREIMAGE_CONTENT_TYPE))
            .map_err(|_| AciError::Cose("protected content type not found".to_string()))
            .and_then(|value| required_text(value, "protected content type"))?;
        match content_type.as_str() {
            // Legacy UVM endorsements carry claims in protected headers and a JSON payload.
            "application/json"
                if protected_header.map_at_str("iss").is_ok()
                    && protected_header.map_at_str("signingtime").is_ok() =>
            {
                let issuer = required_text(
                    protected_header.map_at_str("iss").map_err(AciError::Cose)?,
                    "iss",
                )?;
                verify_didx509_root_async(trusted_didx509, &issuer, &x5chain).await?;

                let signing_time = protected_header
                    .map_at_str("signingtime")
                    .ok()
                    .map(parse::parse_signing_time)
                    .transpose()?;
                <crypto::Crypto as AsyncCryptoBackend>::verify_chain(
                    &root,
                    &intermediate_refs,
                    &leaf,
                    signing_time,
                )
                .await
                .map_err(|e| AciError::Certificate(e.to_string()))?;
            }
            "application/octet-stream"
                if protected_header
                    .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
                    .is_ok() =>
            {
                let cwt_claims = protected_header
                    .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
                    .map_err(AciError::Cose)?;
                let issuer = required_text(
                    cwt_claims
                        .map_at_int(cose::CWT_CLAIMS_ISSUER)
                        .map_err(AciError::Cose)?,
                    "CWT iss",
                )?;
                verify_didx509_root_async(trusted_didx509, &issuer, &x5chain).await?;

                let signing_time = cwt_claims
                    .map_at_int(cose::CWT_CLAIMS_IAT)
                    .ok()
                    .map(|iat| {
                        let iat = match iat {
                            CborValue::Tagged { tag: 1, payload } => {
                                required_int(payload, "CWT iat").map_err(|_| ())
                            }
                            CborValue::Int(iat) => Ok(*iat),
                            _ => Err(()),
                        }
                        .and_then(|iat| iat.try_into().map_err(|_| ()))
                        .map(std::time::Duration::from_secs)
                        .map_err(|_| AciError::Cose(format!("CWT iat invalid {iat:?}")))?;
                        Ok(iat)
                    })
                    .transpose()?;
                <crypto::Crypto as AsyncCryptoBackend>::verify_chain(
                    &root,
                    &intermediate_refs,
                    &leaf,
                    signing_time,
                )
                .await
                .map_err(|e| AciError::Certificate(e.to_string()))?;
            }
            other => {
                return Err(AciError::Measurement(format!(
                    "unsupported ACI payload content type {other}"
                )));
            }
        }

        // Verify signature
        let algorithm = cose::signature_key_algorithm_for_cose_alg(required_int(
            protected_header
                .map_at_int(cose::COSE_HEADER_ALG)
                .map_err(AciError::Cose)?,
            "protected alg",
        )?)
        .map_err(AciError::Cose)?;
        let spki = crypto::Crypto::get_public_key(&leaf)
            .map_err(|e| AciError::Certificate(e.to_string()))?;
        let key = <<crypto::Crypto as AsyncCryptoBackend>::Key as AsyncKeyBackend>::from_spki_der(
            &spki, algorithm,
        )
        .await
        .map_err(|e| AciError::Certificate(e.to_string()))?;
        cose::asynchronous::cose_verify1(&key, algorithm, &protected, &payload, &signature)
            .await
            .map_err(AciError::Signature)?;

        Ok(parsed)
    }

    /// Verify Confidential CACI relying-party policy over staged verified artifacts.
    ///
    /// [`verify_attestation`] must be used to authenticate the SNP report before
    /// calling this function, and [`verify_uvm_endorsement`] must be used to
    /// authenticate the UVM reference info and its did:x509 root.
    ///
    /// `trusted_caci_execution_policy` is the expected SHA-256 digest of the Confidential
    /// ACI security policy loaded into `SNP_HOST_DATA`. The returned value is the
    /// verified `SNP_REPORT_DATA` from the SNP report.
    pub async fn verify_caci_attestation(
        attestation: AttestationReport,
        minimum_tcb: Vec<(snp::Cpuid, TcbVersionRaw)>,
        trusted_caci_execution_policy: Vec<[u8; SNP_HOST_DATA_LEN]>,
        uvm_endorsement: CborValue,
        uvm_feed: &str,
        minimum_svn: u64,
    ) -> Result<[u8; SNP_REPORT_DATA_LEN], AciError> {
        verify_caci_attestation_impl(
            attestation,
            minimum_tcb,
            trusted_caci_execution_policy,
            uvm_endorsement,
            uvm_feed,
            minimum_svn,
        )
    }
}

fn verify_caci_attestation_impl(
    attestation: AttestationReport,
    minimum_tcb: Vec<(snp::Cpuid, TcbVersionRaw)>,
    trusted_caci_execution_policy: Vec<[u8; SNP_HOST_DATA_LEN]>,
    uvm_endorsement: CborValue,
    uvm_feed: &str,
    minimum_svn: u64,
) -> Result<[u8; SNP_REPORT_DATA_LEN], AciError> {
    if attestation.policy().debug() {
        return Err(AciError::Policy(
            "SNP guest policy allows debug mode".to_string(),
        ));
    }

    if attestation.vmpl.get() > MAX_GUEST_VMPL {
        return Err(AciError::Policy(
            "SNP report VMPL is outside the guest range".to_string(),
        ));
    }

    if !minimum_tcb.is_empty() {
        let generation = attestation
            .cpu_generation()
            .map_err(|e| AciError::Policy(format!("Unsupported SNP CPU generation: {e}")))?;

        for (cpuid, minimum_tcb) in &minimum_tcb {
            let minimum_generation = Generation::from_cpuid(cpuid).map_err(|e| {
                AciError::Policy(format!("Unsupported minimum TCB CPUID {cpuid:?}: {e}"))
            })?;
            if minimum_generation != generation {
                continue;
            }
            let minimum_tcb = TcbVersionForGeneration::new(*minimum_tcb, generation);
            let reported_tcb = TcbVersionForGeneration::new(attestation.reported_tcb, generation);
            if !(minimum_tcb <= reported_tcb) {
                return Err(AciError::Policy(format!(
                    "SNP reported TCB {:?} for generation {} is below trusted minimum {:?}",
                    attestation.reported_tcb, generation, minimum_tcb.tcb
                )));
            }
        }
    }

    let sign1 = cose::cose_sign1(&uvm_endorsement).map_err(AciError::Cose)?;
    let payload = parse::cose_payload(sign1)?;
    let protected = required_bstr(sign1.array_at(0).map_err(AciError::Cose)?, "protected")?;
    let protected_header = CborValue::from_bytes(&protected).map_err(AciError::Cose)?;

    let content_type = protected_header
        .map_at_int(cose::COSE_HEADER_CONTENT_TYPE)
        .or_else(|_| protected_header.map_at_int(cose::COSE_HEADER_PREIMAGE_CONTENT_TYPE))
        .map_err(|_| AciError::Cose("protected content type not found".to_string()))
        .and_then(|value| required_text(value, "protected content type"))?;
    match content_type.as_str() {
        // Legacy UVM endorsements carry claims in protected headers and a JSON payload.
        "application/json" if protected_header.map_at_str("feed").is_ok() => {
            // feed matches
            let feed = protected_header
                .map_at_str("feed")
                .map_err(|err| AciError::Cose(format!("failed to get feed: {err}")))
                .and_then(|value| required_text(value, "feed"))?;
            if feed != uvm_feed {
                return Err(AciError::Policy(format!(
                    "UVM feed {:?} does not match trusted feed {}",
                    feed, uvm_feed
                )));
            }

            let reference_info = serde_json::from_slice::<serde_json::Value>(&payload)
                .map_err(|e| AciError::Measurement(e.to_string()))?;
            reference_info.as_object().ok_or_else(|| {
                AciError::Measurement("ReferenceInfo payload must be a JSON object".into())
            })?;

            // svn matches
            let svn = parse::json::required_str(&reference_info, JSON_GUEST_SVN)?;
            if svn.is_empty() || !svn.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(AciError::Policy(format!(
                    "UVM SVN {svn:?} is not a non-negative integer"
                )));
            }
            let svn_int = parse::json::required_u64(&reference_info, JSON_GUEST_SVN_INT)?;
            if svn_int < minimum_svn {
                return Err(AciError::Policy(format!(
                    "UVM SVN {svn_int} is below trusted minimum {minimum_svn}"
                )));
            }

            // measurement matches attestation
            let reference_info_measurement = parse::json::required_hex::<SNP_MEASUREMENT_LEN>(
                &reference_info,
                JSON_LAUNCH_MEASUREMENT,
            )?;
            if reference_info_measurement != attestation.measurement {
                return Err(AciError::Measurement(
                    "ACI payload measurement does not match attestation measurement".to_string(),
                ));
            }
        }
        "application/octet-stream"
            if protected_header
                .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
                .is_ok() =>
        {
            let cwt_claims = protected_header
                .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
                .map_err(AciError::Cose)?;
            let feed = required_text(
                cwt_claims
                    .map_at_int(cose::CWT_CLAIMS_SUBJECT)
                    .map_err(AciError::Cose)?,
                "CWT sub",
            )?;
            if feed != uvm_feed {
                return Err(AciError::Policy(format!(
                    "UVM feed {:?} does not match trusted feed {}",
                    feed, uvm_feed
                )));
            }

            let svn: u64 = required_int(
                cwt_claims.map_at_str("svn").map_err(AciError::Cose)?,
                "CWT svn",
            )?
            .try_into()
            .map_err(|_| AciError::Policy("UVM SVN is not a non-negative integer".to_string()))?;
            if svn < minimum_svn {
                return Err(AciError::Policy(format!(
                    "UVM SVN {svn} is below trusted minimum {minimum_svn}"
                )));
            }

            let reference_info_measurement: [u8; SNP_MEASUREMENT_LEN] =
                payload.try_into().map_err(|payload: Vec<u8>| {
                    AciError::Measurement(format!(
                        "ACI payload measurement must be {SNP_MEASUREMENT_LEN} bytes, got {}",
                        payload.len()
                    ))
                })?;
            if reference_info_measurement != attestation.measurement {
                return Err(AciError::Measurement(
                    "ACI payload measurement does not match attestation measurement".to_string(),
                ));
            }
        }
        other => {
            return Err(AciError::Measurement(format!(
                "unsupported ACI payload content type {other}"
            )));
        }
    }

    if !trusted_caci_execution_policy.contains(&attestation.host_data) {
        return Err(AciError::Policy(
            "SNP HOST_DATA does not match trusted policy".to_string(),
        ));
    }

    Ok(attestation.report_data)
}

/// Error returned when CACI verification fails.
#[derive(Debug)]
pub enum AciError {
    /// The caller did not provide exactly `[vcek, ask, ark]`.
    InvalidAmdEndorsements(String),
    /// The attestation report could not be parsed.
    InvalidAttestation(String),
    /// SEV-SNP attestation verification failed.
    AttestationVerification(VerificationError),
    /// Certificate parsing or verification failed.
    Certificate(String),
    /// DID x509 parsing or root pinning failed.
    DidX509(String),
    /// COSE envelope/header parsing failed.
    Cose(String),
    /// COSE signature verification failed.
    Signature(String),
    /// ACI payload measurement did not match the attestation measurement.
    Measurement(String),
    /// Relying-party policy did not match the verified claims.
    Policy(String),
}

impl std::fmt::Display for AciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAmdEndorsements(e) => write!(f, "Invalid AMD endorsements: {e}"),
            Self::InvalidAttestation(e) => write!(f, "Invalid attestation: {e}"),
            Self::AttestationVerification(e) => write!(f, "Attestation verification failed: {e}"),
            Self::Certificate(e) => write!(f, "Certificate error: {e}"),
            Self::DidX509(e) => write!(f, "DID x509 policy error: {e}"),
            Self::Cose(e) => write!(f, "COSE error: {e}"),
            Self::Signature(e) => write!(f, "COSE signature verification failed: {e}"),
            Self::Measurement(e) => write!(f, "Measurement verification failed: {e}"),
            Self::Policy(e) => write!(f, "Relying-party policy verification failed: {e}"),
        }
    }
}

impl std::error::Error for AciError {}

#[cfg(test)]
mod tests;
