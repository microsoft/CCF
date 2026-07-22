// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

use crate::parse;
use crypto::base64::base64_standard_decode;

const HOST_AMD_CERT_BASE64: &str = include_str!("../tests/fixtures/host-amd-cert.base64");
const REFERENCE_INFO_BASE64: &str = include_str!("../tests/fixtures/reference-info.base64");
const REPORT_HEX: &str = include_str!("../tests/fixtures/report.hex");
const HOST_AMD_CERT_SCITT_CWT_BASE64: &str =
    include_str!("../tests/fixtures/host-amd-cert-scitt-cwt.base64");
const REFERENCE_INFO_SCITT_CWT_BASE64: &str =
    include_str!("../tests/fixtures/reference-info-scitt-cwt.base64");
const REPORT_SCITT_CWT_HEX: &str = include_str!("../tests/fixtures/report-scitt-cwt.hex");
const TRUSTED_ACI_DIDX509: &str =
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2";
const ACI_FEED: &str = "ContainerPlat-AMD-UVM";
const ACI_SVN: u64 = 104;
const MILAN_CPUID: u32 = 0x00A00F11;
const GENOA_CPUID: u32 = 0x00A10F11;

#[derive(Clone, Copy)]
struct CaciFixture {
    name: &'static str,
    report_hex: &'static str,
    host_amd_cert_base64: &'static str,
    reference_info_base64: &'static str,
    cpuid: u32,
}

const LEGACY_FIXTURE: CaciFixture = CaciFixture {
    name: "legacy",
    report_hex: REPORT_HEX,
    host_amd_cert_base64: HOST_AMD_CERT_BASE64,
    reference_info_base64: REFERENCE_INFO_BASE64,
    cpuid: MILAN_CPUID,
};

const TRANSPARENT_FIXTURE: CaciFixture = CaciFixture {
    name: "transparent",
    report_hex: REPORT_SCITT_CWT_HEX,
    host_amd_cert_base64: HOST_AMD_CERT_SCITT_CWT_BASE64,
    reference_info_base64: REFERENCE_INFO_SCITT_CWT_BASE64,
    cpuid: GENOA_CPUID,
};

fn fixture_cases() -> [CaciFixture; 2] {
    [LEGACY_FIXTURE, TRANSPARENT_FIXTURE]
}

#[cfg(sync_crypto)]
mod synchronous {
    use super::*;

    #[cfg(target_family = "wasm")]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn verifies_caci_attestation_end_to_end() {
        for fixture in fixture_cases() {
            let attestation = attestation_fixture(fixture);
            let endorsements = amd_endorsement_fixture(fixture);
            let endorsement_refs = endorsement_refs(&endorsements);
            let reference_info = reference_info_fixture(fixture);

            let report =
                crate::synchronous::verify_attestation(&attestation, &endorsement_refs).unwrap();
            let uvm =
                crate::synchronous::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509)
                    .unwrap();

            let report_data = crate::synchronous::verify_caci_attestation(
                report,
                Vec::new(),
                vec![report.host_data],
                uvm,
                ACI_FEED,
                ACI_SVN,
            )
            .unwrap();

            assert_eq!(report_data, report.report_data, "{}", fixture.name);
        }
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn step1_attestation_verification_works_and_rejects_invalid_inputs() {
        for fixture in fixture_cases() {
            let attestation = attestation_fixture(fixture);
            let endorsements = amd_endorsement_fixture(fixture);
            let endorsement_refs = endorsement_refs(&endorsements);

            let report =
                crate::synchronous::verify_attestation(&attestation, &endorsement_refs).unwrap();
            assert_verified_attestation_matches_fixture(report, fixture);

            match crate::synchronous::verify_attestation(&attestation, &endorsement_refs[..2]) {
                Err(AciError::InvalidAmdEndorsements(actual)) => {
                    assert_eq!(actual, "expected [vcek, ask, ark], got 2 certificate(s)")
                }
                other => panic!(
                    "expected InvalidAmdEndorsements for {}, got {other:?}",
                    fixture.name
                ),
            }

            let truncated = &attestation[..64];
            match crate::synchronous::verify_attestation(truncated, &endorsement_refs) {
                Err(AciError::InvalidAttestation(actual)) => assert_contains(&actual, "SizeError"),
                other => panic!(
                    "expected InvalidAttestation for {}, got {other:?}",
                    fixture.name
                ),
            }

            let mut tampered = attestation.clone();
            tampered[100] ^= 0xff;
            match crate::synchronous::verify_attestation(&tampered, &endorsement_refs) {
                Err(AciError::AttestationVerification(
                    attestation::snp::verify::VerificationError::SignatureVerificationError(actual),
                )) => assert_contains(
                    &actual.to_ascii_lowercase(),
                    "signature verification failed",
                ),
                other => panic!(
                    "expected attestation signature verification error for {}, got {other:?}",
                    fixture.name
                ),
            }
        }
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn step2_uvm_endorsement_verification_works_and_rejects_invalid_inputs() {
        for fixture in fixture_cases() {
            let reference_info = reference_info_fixture(fixture);
            let expected_report = parse_attestation(&attestation_fixture(fixture)).unwrap();

            let uvm =
                crate::synchronous::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509)
                    .unwrap();
            assert_verified_uvm_matches_fixture(&uvm, expected_report, fixture);

            match crate::synchronous::verify_uvm_endorsement(&reference_info, "not-a-did") {
                Err(AciError::DidX509(actual)) => {
                    assert_eq!(actual, "expected did:x509:0:sha256:<fingerprint>")
                }
                other => panic!("expected DidX509 error for {}, got {other:?}", fixture.name),
            }

            match crate::synchronous::verify_uvm_endorsement(
                &reference_info,
                "did:x509:0:sha256:wrong",
            ) {
                Err(AciError::DidX509(actual)) => assert_eq!(
                    actual,
                    "issuer DID prefix did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s does not match trusted DID prefix did:x509:0:sha256:wrong"
                ),
                other => panic!("expected DidX509 error for {}, got {other:?}", fixture.name),
            }

            let mut tampered_signature = reference_info;
            *tampered_signature.last_mut().unwrap() ^= 1;
            match crate::synchronous::verify_uvm_endorsement(
                &tampered_signature,
                TRUSTED_ACI_DIDX509,
            ) {
                Err(AciError::Signature(actual)) => assert_contains(
                    &actual.to_ascii_lowercase(),
                    "signature verification failed",
                ),
                other => panic!(
                    "expected Signature error for {}, got {other:?}",
                    fixture.name
                ),
            }
        }

        match crate::synchronous::verify_uvm_endorsement(b"not cose", TRUSTED_ACI_DIDX509) {
            Err(AciError::Cose(actual)) => assert_eq!(actual, "Failed to parse CBOR bytes"),
            other => panic!("expected Cose error, got {other:?}"),
        }
    }

    #[cfg_attr(not(target_family = "wasm"), test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    fn step3_policy_binding_works_and_rejects_invalid_inputs() {
        let mut verified = Vec::new();
        for fixture in fixture_cases() {
            let attestation = attestation_fixture(fixture);
            let endorsements = amd_endorsement_fixture(fixture);
            let endorsement_refs = endorsement_refs(&endorsements);
            let report =
                crate::synchronous::verify_attestation(&attestation, &endorsement_refs).unwrap();
            let uvm = crate::synchronous::verify_uvm_endorsement(
                &reference_info_fixture(fixture),
                TRUSTED_ACI_DIDX509,
            )
            .unwrap();

            let report_data = crate::synchronous::verify_caci_attestation(
                report,
                Vec::new(),
                vec![report.host_data],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN,
            )
            .unwrap();
            assert_eq!(report_data, report.report_data, "{}", fixture.name);

            match crate::synchronous::verify_caci_attestation(
                report,
                Vec::new(),
                vec![report.host_data],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN + 1,
            ) {
                Err(AciError::Policy(actual)) => {
                    assert_eq!(actual, "UVM SVN 104 is below trusted minimum 105")
                }
                other => panic!("expected Policy error for {}, got {other:?}", fixture.name),
            }

            let mut policy = report.host_data;
            policy[0] ^= 1;
            match crate::synchronous::verify_caci_attestation(
                report,
                Vec::new(),
                vec![policy],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN,
            ) {
                Err(AciError::Policy(actual)) => {
                    assert_eq!(actual, "SNP HOST_DATA does not match trusted policy")
                }
                other => panic!("expected Policy error for {}, got {other:?}", fixture.name),
            }

            let wrong_feed = replace_cose_feed(uvm.clone(), "not-confidential-aci");
            match crate::synchronous::verify_caci_attestation(
                report,
                Vec::new(),
                vec![report.host_data],
                wrong_feed,
                ACI_FEED,
                ACI_SVN,
            ) {
                Err(AciError::Policy(actual)) => assert_eq!(
                    actual,
                    "UVM feed \"not-confidential-aci\" does not match trusted feed ContainerPlat-AMD-UVM"
                ),
                other => panic!("expected Policy error for {}, got {other:?}", fixture.name),
            }

            let matching_cpuid = snp::Cpuid::from(fixture.cpuid);
            let mut minimum_tcb = report.reported_tcb;
            minimum_tcb.raw[0] = minimum_tcb.raw[0].saturating_add(1);
            match crate::synchronous::verify_caci_attestation(
                report,
                vec![(matching_cpuid, minimum_tcb)],
                vec![report.host_data],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN,
            ) {
                Err(AciError::Policy(actual)) => assert_contains(&actual, "SNP reported TCB"),
                other => panic!("expected Policy error for {}, got {other:?}", fixture.name),
            }

            let mut wrong_measurement = report;
            wrong_measurement.measurement[0] ^= 1;
            match crate::synchronous::verify_caci_attestation(
                wrong_measurement,
                Vec::new(),
                vec![wrong_measurement.host_data],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN,
            ) {
                Err(AciError::Measurement(actual)) => assert_eq!(
                    actual,
                    "ACI payload measurement does not match attestation measurement"
                ),
                other => panic!(
                    "expected Measurement error for {}, got {other:?}",
                    fixture.name
                ),
            }

            let debug_report = report_with_debug_enabled(fixture);
            match crate::synchronous::verify_caci_attestation(
                debug_report,
                Vec::new(),
                vec![debug_report.host_data],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN,
            ) {
                Err(AciError::Policy(actual)) => {
                    assert_eq!(actual, "SNP guest policy allows debug mode")
                }
                other => panic!("expected Policy error for {}, got {other:?}", fixture.name),
            }

            let host_report = report_with_vmpl(fixture, 4);
            match crate::synchronous::verify_caci_attestation(
                host_report,
                Vec::new(),
                vec![host_report.host_data],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN,
            ) {
                Err(AciError::Policy(actual)) => {
                    assert_eq!(actual, "SNP report VMPL is outside the guest range")
                }
                other => panic!("expected Policy error for {}, got {other:?}", fixture.name),
            }

            verified.push((fixture, report, uvm));
        }

        let (fixture, _report, uvm) = verified
            .into_iter()
            .find(|(fixture, _, _)| fixture.name == LEGACY_FIXTURE.name)
            .unwrap();
        let attestation = attestation_fixture(fixture);
        let endorsements = amd_endorsement_fixture(fixture);
        let legacy_endorsement_refs = endorsement_refs(&endorsements);
        let report =
            crate::synchronous::verify_attestation(&attestation, &legacy_endorsement_refs).unwrap();

        let missing_svn_int =
            replace_cose_payload(uvm.clone(), reference_payload_without_guestsvn_int(report));
        match crate::synchronous::verify_caci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            missing_svn_int,
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Measurement(actual)) => {
                assert_eq!(actual, "x-ms-sevsnpvm-guestsvn-int must be a JSON integer")
            }
            other => panic!("expected Measurement error, got {other:?}"),
        }

        let uppercase_measurement =
            replace_cose_payload(uvm, reference_payload_with_uppercase_measurement(report));
        match crate::synchronous::verify_caci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            uppercase_measurement,
            ACI_FEED,
            ACI_SVN,
        ) {
            Err(AciError::Measurement(actual)) => assert_eq!(
                actual,
                "x-ms-sevsnpvm-launchmeasurement must be hex encoded"
            ),
            other => panic!("expected Measurement error, got {other:?}"),
        }
    }
}

#[cfg(async_crypto)]
mod asynchronous {
    use super::*;

    #[cfg(target_family = "wasm")]
    use wasm_bindgen_test::wasm_bindgen_test;

    async fn verify_caci_attestation(
        attestation: AttestationReport,
        minimum_tcb: Vec<(snp::Cpuid, TcbVersionRaw)>,
        trusted_caci_execution_policy: Vec<[u8; SNP_HOST_DATA_LEN]>,
        uvm_endorsement: CborValue,
        uvm_feed: &str,
        minimum_svn: u64,
    ) -> Result<[u8; SNP_REPORT_DATA_LEN], AciError> {
        crate::asynchronous::verify_caci_attestation(
            attestation,
            minimum_tcb,
            trusted_caci_execution_policy,
            uvm_endorsement,
            uvm_feed,
            minimum_svn,
        )
        .await
    }

    #[cfg_attr(not(target_family = "wasm"), tokio::test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    async fn verifies_caci_attestation_end_to_end() {
        for fixture in fixture_cases() {
            let attestation = attestation_fixture(fixture);
            let endorsements = amd_endorsement_fixture(fixture);
            let endorsement_refs = endorsement_refs(&endorsements);
            let reference_info = reference_info_fixture(fixture);

            let report = crate::asynchronous::verify_attestation(&attestation, &endorsement_refs)
                .await
                .unwrap();
            let uvm =
                crate::asynchronous::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509)
                    .await
                    .unwrap();

            let report_data = verify_caci_attestation(
                report,
                Vec::new(),
                vec![report.host_data],
                uvm,
                ACI_FEED,
                ACI_SVN,
            )
            .await
            .unwrap();

            assert_eq!(report_data, report.report_data, "{}", fixture.name);
        }
    }

    #[cfg_attr(not(target_family = "wasm"), tokio::test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    async fn step1_attestation_verification_works_and_rejects_invalid_inputs() {
        for fixture in fixture_cases() {
            let attestation = attestation_fixture(fixture);
            let endorsements = amd_endorsement_fixture(fixture);
            let endorsement_refs = endorsement_refs(&endorsements);

            let report = crate::asynchronous::verify_attestation(&attestation, &endorsement_refs)
                .await
                .unwrap();
            assert_verified_attestation_matches_fixture(report, fixture);

            match crate::asynchronous::verify_attestation(&attestation, &endorsement_refs[..2])
                .await
            {
                Err(AciError::InvalidAmdEndorsements(actual)) => {
                    assert_eq!(actual, "expected [vcek, ask, ark], got 2 certificate(s)")
                }
                other => panic!(
                    "expected InvalidAmdEndorsements for {}, got {other:?}",
                    fixture.name
                ),
            }

            let truncated = &attestation[..64];
            match crate::asynchronous::verify_attestation(truncated, &endorsement_refs).await {
                Err(AciError::InvalidAttestation(actual)) => assert_contains(&actual, "SizeError"),
                other => panic!(
                    "expected InvalidAttestation for {}, got {other:?}",
                    fixture.name
                ),
            }

            let mut tampered = attestation.clone();
            tampered[100] ^= 0xff;
            match crate::asynchronous::verify_attestation(&tampered, &endorsement_refs).await {
                Err(AciError::AttestationVerification(
                    attestation::snp::verify::VerificationError::SignatureVerificationError(actual),
                )) => assert_contains(
                    &actual.to_ascii_lowercase(),
                    "signature verification failed",
                ),
                other => panic!(
                    "expected attestation signature verification error for {}, got {other:?}",
                    fixture.name
                ),
            }
        }
    }

    #[cfg_attr(not(target_family = "wasm"), tokio::test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    async fn step2_uvm_endorsement_verification_works_and_rejects_invalid_inputs() {
        for fixture in fixture_cases() {
            let reference_info = reference_info_fixture(fixture);
            let expected_report = parse_attestation(&attestation_fixture(fixture)).unwrap();

            let uvm =
                crate::asynchronous::verify_uvm_endorsement(&reference_info, TRUSTED_ACI_DIDX509)
                    .await
                    .unwrap();
            assert_verified_uvm_matches_fixture(&uvm, expected_report, fixture);

            match crate::asynchronous::verify_uvm_endorsement(&reference_info, "not-a-did").await {
                Err(AciError::DidX509(actual)) => {
                    assert_eq!(actual, "expected did:x509:0:sha256:<fingerprint>")
                }
                other => panic!("expected DidX509 error for {}, got {other:?}", fixture.name),
            }

            match crate::asynchronous::verify_uvm_endorsement(
                &reference_info,
                "did:x509:0:sha256:wrong",
            )
            .await
            {
                Err(AciError::DidX509(actual)) => assert_eq!(
                    actual,
                    "issuer DID prefix did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s does not match trusted DID prefix did:x509:0:sha256:wrong"
                ),
                other => panic!("expected DidX509 error for {}, got {other:?}", fixture.name),
            }

            let mut tampered_signature = reference_info;
            *tampered_signature.last_mut().unwrap() ^= 1;
            match crate::asynchronous::verify_uvm_endorsement(
                &tampered_signature,
                TRUSTED_ACI_DIDX509,
            )
            .await
            {
                Err(AciError::Signature(actual)) => assert_contains(
                    &actual.to_ascii_lowercase(),
                    "signature verification failed",
                ),
                other => panic!(
                    "expected Signature error for {}, got {other:?}",
                    fixture.name
                ),
            }
        }

        match crate::asynchronous::verify_uvm_endorsement(b"not cose", TRUSTED_ACI_DIDX509).await {
            Err(AciError::Cose(actual)) => assert_eq!(actual, "Failed to parse CBOR bytes"),
            other => panic!("expected Cose error, got {other:?}"),
        }
    }

    #[cfg_attr(not(target_family = "wasm"), tokio::test)]
    #[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
    async fn step3_policy_binding_works_and_rejects_invalid_inputs() {
        let mut verified = Vec::new();
        for fixture in fixture_cases() {
            let attestation = attestation_fixture(fixture);
            let endorsements = amd_endorsement_fixture(fixture);
            let endorsement_refs = endorsement_refs(&endorsements);
            let report = crate::asynchronous::verify_attestation(&attestation, &endorsement_refs)
                .await
                .unwrap();
            let uvm = crate::asynchronous::verify_uvm_endorsement(
                &reference_info_fixture(fixture),
                TRUSTED_ACI_DIDX509,
            )
            .await
            .unwrap();

            let report_data = verify_caci_attestation(
                report,
                Vec::new(),
                vec![report.host_data],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN,
            )
            .await
            .unwrap();
            assert_eq!(report_data, report.report_data, "{}", fixture.name);

            match verify_caci_attestation(
                report,
                Vec::new(),
                vec![report.host_data],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN + 1,
            )
            .await
            {
                Err(AciError::Policy(actual)) => {
                    assert_eq!(actual, "UVM SVN 104 is below trusted minimum 105")
                }
                other => panic!("expected Policy error for {}, got {other:?}", fixture.name),
            }

            let mut policy = report.host_data;
            policy[0] ^= 1;
            match verify_caci_attestation(
                report,
                Vec::new(),
                vec![policy],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN,
            )
            .await
            {
                Err(AciError::Policy(actual)) => {
                    assert_eq!(actual, "SNP HOST_DATA does not match trusted policy")
                }
                other => panic!("expected Policy error for {}, got {other:?}", fixture.name),
            }

            let wrong_feed = replace_cose_feed(uvm.clone(), "not-confidential-aci");
            match verify_caci_attestation(
                report,
                Vec::new(),
                vec![report.host_data],
                wrong_feed,
                ACI_FEED,
                ACI_SVN,
            )
            .await
            {
                Err(AciError::Policy(actual)) => assert_eq!(
                    actual,
                    "UVM feed \"not-confidential-aci\" does not match trusted feed ContainerPlat-AMD-UVM"
                ),
                other => panic!("expected Policy error for {}, got {other:?}", fixture.name),
            }

            let matching_cpuid = snp::Cpuid::from(fixture.cpuid);
            let mut minimum_tcb = report.reported_tcb;
            minimum_tcb.raw[0] = minimum_tcb.raw[0].saturating_add(1);
            match verify_caci_attestation(
                report,
                vec![(matching_cpuid, minimum_tcb)],
                vec![report.host_data],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN,
            )
            .await
            {
                Err(AciError::Policy(actual)) => assert_contains(&actual, "SNP reported TCB"),
                other => panic!("expected Policy error for {}, got {other:?}", fixture.name),
            }

            let mut wrong_measurement = report;
            wrong_measurement.measurement[0] ^= 1;
            match verify_caci_attestation(
                wrong_measurement,
                Vec::new(),
                vec![wrong_measurement.host_data],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN,
            )
            .await
            {
                Err(AciError::Measurement(actual)) => assert_eq!(
                    actual,
                    "ACI payload measurement does not match attestation measurement"
                ),
                other => panic!(
                    "expected Measurement error for {}, got {other:?}",
                    fixture.name
                ),
            }

            let debug_report = report_with_debug_enabled(fixture);
            match verify_caci_attestation(
                debug_report,
                Vec::new(),
                vec![debug_report.host_data],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN,
            )
            .await
            {
                Err(AciError::Policy(actual)) => {
                    assert_eq!(actual, "SNP guest policy allows debug mode")
                }
                other => panic!("expected Policy error for {}, got {other:?}", fixture.name),
            }

            let host_report = report_with_vmpl(fixture, 4);
            match verify_caci_attestation(
                host_report,
                Vec::new(),
                vec![host_report.host_data],
                uvm.clone(),
                ACI_FEED,
                ACI_SVN,
            )
            .await
            {
                Err(AciError::Policy(actual)) => {
                    assert_eq!(actual, "SNP report VMPL is outside the guest range")
                }
                other => panic!("expected Policy error for {}, got {other:?}", fixture.name),
            }

            verified.push((fixture, report, uvm));
        }

        let (fixture, _report, uvm) = verified
            .into_iter()
            .find(|(fixture, _, _)| fixture.name == LEGACY_FIXTURE.name)
            .unwrap();
        let attestation = attestation_fixture(fixture);
        let endorsements = amd_endorsement_fixture(fixture);
        let legacy_endorsement_refs = endorsement_refs(&endorsements);
        let report =
            crate::asynchronous::verify_attestation(&attestation, &legacy_endorsement_refs)
                .await
                .unwrap();

        let missing_svn_int =
            replace_cose_payload(uvm.clone(), reference_payload_without_guestsvn_int(report));
        match verify_caci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            missing_svn_int,
            ACI_FEED,
            ACI_SVN,
        )
        .await
        {
            Err(AciError::Measurement(actual)) => {
                assert_eq!(actual, "x-ms-sevsnpvm-guestsvn-int must be a JSON integer")
            }
            other => panic!("expected Measurement error, got {other:?}"),
        }

        let uppercase_measurement =
            replace_cose_payload(uvm, reference_payload_with_uppercase_measurement(report));
        match verify_caci_attestation(
            report,
            Vec::new(),
            vec![report.host_data],
            uppercase_measurement,
            ACI_FEED,
            ACI_SVN,
        )
        .await
        {
            Err(AciError::Measurement(actual)) => assert_eq!(
                actual,
                "x-ms-sevsnpvm-launchmeasurement must be hex encoded"
            ),
            other => panic!("expected Measurement error, got {other:?}"),
        }
    }
}

fn attestation_fixture(fixture: CaciFixture) -> Vec<u8> {
    crypto::hex::from_hex(fixture.report_hex.trim()).unwrap()
}

fn reference_info_fixture(fixture: CaciFixture) -> Vec<u8> {
    decode_base64_fixture(fixture.reference_info_base64)
}

fn amd_endorsement_fixture(fixture: CaciFixture) -> [Vec<u8>; 3] {
    endorsements_from_host_amd_cert_fixture(fixture.host_amd_cert_base64).unwrap()
}

fn endorsement_refs(endorsements: &[Vec<u8>; 3]) -> [&[u8]; 3] {
    [
        endorsements[0].as_slice(),
        endorsements[1].as_slice(),
        endorsements[2].as_slice(),
    ]
}

fn endorsements_from_host_amd_cert_fixture(
    host_amd_cert_base64: &str,
) -> Result<[Vec<u8>; 3], AciError> {
    let host_amd_cert_base64 = host_amd_cert_base64
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect::<String>();
    let host_amd_cert =
        base64_standard_decode(&host_amd_cert_base64).map_err(AciError::InvalidAmdEndorsements)?;
    let host_amd_cert: serde_json::Value = serde_json::from_slice(&host_amd_cert)
        .map_err(|e| AciError::InvalidAmdEndorsements(e.to_string()))?;
    let vcek = required_json_string(&host_amd_cert, "vcekCert")?;
    let certificate_chain = required_json_string(&host_amd_cert, "certificateChain")?;
    let chain = split_pem_chain(certificate_chain)?;
    if chain.len() != 2 {
        return Err(AciError::InvalidAmdEndorsements(format!(
            "expected certificateChain to contain ASK and ARK, got {} certificate(s)",
            chain.len()
        )));
    }

    Ok([vcek.as_bytes().to_vec(), chain[0].clone(), chain[1].clone()])
}

fn required_json_string<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, AciError> {
    value
        .get(key)
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            AciError::InvalidAmdEndorsements(format!(
                "host AMD cert JSON missing string field {key}"
            ))
        })
}

fn split_pem_chain(pem_chain: &str) -> Result<Vec<Vec<u8>>, AciError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let mut certs = Vec::new();
    let mut remaining = pem_chain;
    while let Some(begin) = remaining.find(BEGIN) {
        let after_begin = &remaining[begin..];
        let end = after_begin.find(END).ok_or_else(|| {
            AciError::InvalidAmdEndorsements("certificateChain has unterminated PEM".to_string())
        })?;
        let end = end + END.len();
        let mut cert = after_begin[..end].to_string();
        cert.push('\n');
        certs.push(cert.into_bytes());
        remaining = &after_begin[end..];
    }

    if certs.is_empty() {
        return Err(AciError::InvalidAmdEndorsements(
            "certificateChain contains no PEM certificates".to_string(),
        ));
    }

    Ok(certs)
}

fn decode_base64_fixture(encoded: &str) -> Vec<u8> {
    let encoded = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect::<String>();
    base64_standard_decode(&encoded).unwrap()
}

fn assert_verified_attestation_matches_fixture(report: AttestationReport, fixture: CaciFixture) {
    let expected = parse_attestation(&attestation_fixture(fixture)).unwrap();
    assert_eq!(report.measurement, expected.measurement);
    assert_eq!(report.host_data, expected.host_data);
    assert_eq!(report.report_data, expected.report_data);
}

fn assert_verified_uvm_matches_fixture(
    endorsement: &CborValue,
    expected_report: AttestationReport,
    fixture: CaciFixture,
) {
    let protected_header = endorsement_protected_header(endorsement);
    let x5chain = parse::parse_x5chain(
        protected_header
            .map_at_int(cose::COSE_HEADER_X5CHAIN)
            .unwrap(),
    )
    .unwrap();
    assert!(x5chain.len() >= 2);

    if fixture.name == LEGACY_FIXTURE.name {
        let payload = endorsement_payload(endorsement);
        let issuer =
            parse::required_text(protected_header.map_at_str("iss").unwrap(), "iss").unwrap();
        let feed = protected_header
            .map_at_str("feed")
            .ok()
            .map(|value| parse::required_text(value, "feed"))
            .transpose()
            .unwrap();

        assert_eq!(issuer, TRUSTED_ACI_DIDX509);
        assert_eq!(feed.as_deref(), Some(ACI_FEED));
        assert_eq!(
            parse::json::required_str(&payload, "x-ms-sevsnpvm-guestsvn").unwrap(),
            ACI_SVN.to_string()
        );
        assert_eq!(
            parse::json::required_hex::<SNP_MEASUREMENT_LEN>(
                &payload,
                "x-ms-sevsnpvm-launchmeasurement"
            )
            .unwrap(),
            expected_report.measurement
        );
    } else {
        let sign1 = cose::cose_sign1(endorsement).unwrap();
        let payload = parse::cose_payload(sign1).unwrap();
        let cwt_claims = protected_header
            .map_at_int(cose::COSE_HEADER_CWT_CLAIMS)
            .unwrap();
        let issuer = parse::required_text(
            cwt_claims.map_at_int(cose::CWT_CLAIMS_ISSUER).unwrap(),
            "CWT iss",
        )
        .unwrap();
        let feed = parse::required_text(
            cwt_claims.map_at_int(cose::CWT_CLAIMS_SUBJECT).unwrap(),
            "CWT sub",
        )
        .unwrap();
        let svn = parse::required_int(cwt_claims.map_at_str("svn").unwrap(), "CWT svn").unwrap();

        assert_eq!(issuer, TRUSTED_ACI_DIDX509);
        assert_eq!(feed, ACI_FEED);
        assert_eq!(svn, ACI_SVN as i64);
        assert_eq!(payload, expected_report.measurement);
    }
}

fn report_with_debug_enabled(fixture: CaciFixture) -> AttestationReport {
    report_from_reference_fixture(fixture, |bytes| {
        let mut policy = u64::from_le_bytes(bytes[0x008..0x010].try_into().unwrap());
        policy |= 1 << 19;
        bytes[0x008..0x010].copy_from_slice(&policy.to_le_bytes());
    })
}

fn report_with_vmpl(fixture: CaciFixture, vmpl: u32) -> AttestationReport {
    report_from_reference_fixture(fixture, |bytes| {
        bytes[0x030..0x034].copy_from_slice(&vmpl.to_le_bytes());
    })
}

fn report_from_reference_fixture(
    fixture: CaciFixture,
    mutate: impl FnOnce(&mut [u8]),
) -> AttestationReport {
    let mut report = attestation_fixture(fixture);
    mutate(&mut report);
    parse_attestation(&report).unwrap()
}

fn reference_payload_without_guestsvn_int(report: AttestationReport) -> Vec<u8> {
    format!(
        r#"{{
            "x-ms-sevsnpvm-launchmeasurement": "{}",
            "x-ms-sevsnpvm-guestsvn": "{}"
        }}"#,
        measurement_hex_lower(report),
        ACI_SVN,
    )
    .into_bytes()
}

fn reference_payload_with_uppercase_measurement(report: AttestationReport) -> Vec<u8> {
    format!(
        r#"{{
            "x-ms-sevsnpvm-launchmeasurement": "{}",
            "x-ms-sevsnpvm-guestsvn": "{}",
            "x-ms-sevsnpvm-guestsvn-int": {}
        }}"#,
        measurement_hex_upper(report),
        ACI_SVN,
        ACI_SVN,
    )
    .into_bytes()
}

fn measurement_hex_lower(report: AttestationReport) -> String {
    crypto::hex::to_hex(&report.measurement)
}

fn measurement_hex_upper(report: AttestationReport) -> String {
    crypto::hex::to_hex(&report.measurement).to_uppercase()
}

fn endorsement_protected_header(endorsement: &CborValue) -> CborValue {
    let sign1 = cose::cose_sign1(endorsement).unwrap();
    let protected = parse::required_bstr(sign1.array_at(0).unwrap(), "protected").unwrap();
    CborValue::from_bytes(&protected).unwrap()
}

fn endorsement_payload(endorsement: &CborValue) -> serde_json::Value {
    let sign1 = cose::cose_sign1(endorsement).unwrap();
    let payload = parse::cose_payload(sign1).unwrap();
    let protected_header = endorsement_protected_header(endorsement);
    let content_type = parse::required_text(
        protected_header
            .map_at_int(cose::COSE_HEADER_CONTENT_TYPE)
            .unwrap(),
        "protected content type",
    )
    .unwrap();
    assert_eq!(content_type, "application/json");
    serde_json::from_slice(&payload).unwrap()
}

fn replace_cose_payload(mut endorsement: CborValue, payload: Vec<u8>) -> CborValue {
    sign1_items_mut(&mut endorsement)[2] = CborValue::ByteString(payload);
    endorsement
}

fn replace_cose_feed(mut endorsement: CborValue, feed: &str) -> CborValue {
    let protected = match &sign1_items_mut(&mut endorsement)[0] {
        CborValue::ByteString(protected) => protected.clone(),
        other => panic!("expected protected header byte string, got {other:?}"),
    };
    let mut protected_header = CborValue::from_bytes(&protected).unwrap();
    let protected_entries = match &mut protected_header {
        CborValue::Map(entries) => entries,
        other => panic!("expected protected header map, got {other:?}"),
    };
    if let Some((_, feed_claim)) = protected_entries
        .iter_mut()
        .find(|(key, _)| key == &CborValue::TextString("feed".to_string()))
    {
        *feed_claim = CborValue::TextString(feed.to_string());
    } else {
        let cwt_claims = protected_entries
            .iter_mut()
            .find(|(key, _)| key == &CborValue::Int(cose::COSE_HEADER_CWT_CLAIMS))
            .map(|(_, value)| value)
            .expect("feed claim should be present");
        let cwt_entries = match cwt_claims {
            CborValue::Map(entries) => entries,
            other => panic!("expected CWT claims map, got {other:?}"),
        };
        let subject_claim = cwt_entries
            .iter_mut()
            .find(|(key, _)| key == &CborValue::Int(cose::CWT_CLAIMS_SUBJECT))
            .map(|(_, value)| value)
            .expect("CWT sub claim should be present");
        *subject_claim = CborValue::TextString(feed.to_string());
    }
    sign1_items_mut(&mut endorsement)[0] =
        CborValue::ByteString(protected_header.to_bytes().unwrap());

    endorsement
}

fn sign1_items_mut(endorsement: &mut CborValue) -> &mut Vec<CborValue> {
    match endorsement {
        CborValue::Tagged { payload, .. } => match payload.as_mut() {
            CborValue::Array(items) => items,
            other => panic!("expected tagged COSE_Sign1 array, got {other:?}"),
        },
        CborValue::Array(items) => items,
        other => panic!("expected COSE_Sign1 document, got {other:?}"),
    }
}

fn assert_contains(actual: &str, expected: &str) {
    assert!(
        actual.contains(expected),
        "expected error to contain {expected:?}, got {actual:?}"
    );
}
