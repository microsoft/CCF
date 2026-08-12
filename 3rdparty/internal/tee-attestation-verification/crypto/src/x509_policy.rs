// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(dead_code)]

use std::time::Duration;

use super::CertificateBackend;

/// Iterates over a path with padded sliding windows.
///
/// For a window size of 3 over `[A, B, C]`, the windows are
/// `[None, None, A]`, `[None, A, B]`, `[A, B, C]`, `[B, C, None]`, and
/// `[C, None, None]`.
///
/// Maximum window size is 127, as the padding is encoded in a signed integer.
pub(crate) fn padded_windows<'cert, Certificate: 'cert, Path, const WINDOW_SIZE: usize>(
    path: Path,
) -> impl Iterator<Item = [Option<&'cert Certificate>; WINDOW_SIZE]>
where
    Path: Clone + Iterator<Item = &'cert Certificate>,
{
    const {
        assert!(WINDOW_SIZE > 0, "window size must be non-zero");
        assert!(WINDOW_SIZE <= 127, "window size must be at most 127");
    }

    let path_len = isize::try_from(path.clone().count()).expect("path length must fit isize");
    let window_size = isize::try_from(WINDOW_SIZE).expect("window size must fit isize");
    let roots = 1 - window_size..path_len;
    roots.map(move |window_index| {
        std::array::from_fn(|offset| {
            let path_index = window_index + offset as isize;
            usize::try_from(path_index)
                .ok()
                .and_then(|path_index| path.clone().nth(path_index))
        })
    })
}

/// Evaluates the implemented RFC 5280 path policy subset for an ordered path.
///
/// This assumes the path has already passed signature verification and is
/// ordered from the trusted root toward the target certificate.
pub(crate) fn rfc5280_policy<'cert, Backend, Path>(
    path: Path,
    unix_time: Duration,
) -> super::Result<()>
where
    Backend: CertificateBackend,
    Backend::Certificate: 'cert,
    Path: Clone + Iterator<Item = &'cert Backend::Certificate>,
{
    let path_len = path.clone().count();
    if path_len == 0 {
        return Err("Certificate path must not be empty".into());
    }

    // Issuer validation
    for window in padded_windows::<_, _, 2>(path.clone()) {
        match window {
            [None, Some(cert)] => {
                if !Backend::is_self_issued(cert)? {
                    return Err(format!(
                        "First certificate {} is not self-issued",
                        Backend::subject_name(cert)
                    )
                    .into());
                }
            }
            [Some(issuer), Some(subject)] => {
                if !Backend::issuer_name_matches_subject(subject, issuer)? {
                    return Err(format!(
                        "Issuer name {} does not match issuing certificate subject name {}",
                        Backend::issuer_name(subject),
                        Backend::subject_name(issuer)
                    )
                    .into());
                }
            }
            [Some(_), None] => {}
            [None, None] => return Err("Certificate path must not be empty".into()),
        }
    }

    for window in padded_windows::<_, _, 1>(path.clone()) {
        let cert = window[0].unwrap();
        let cert_subject = Backend::subject_name(cert);
        if !Backend::is_valid_at(cert, unix_time)? {
            return Err(format!(
                "Certificate {} is not valid at the given time",
                cert_subject
            )
            .into());
        }
        assert_skipped_extension_not_present::<Backend>(cert, oid::CERTIFICATE_POLICIES, false)?;
        assert_skipped_extension_not_present::<Backend>(cert, oid::POLICY_MAPPINGS, true)?;
        assert_skipped_extension_not_present::<Backend>(cert, oid::NAME_CONSTRAINTS, true)?;
        assert_skipped_extension_not_present::<Backend>(cert, oid::POLICY_CONSTRAINTS, true)?;
        assert_skipped_extension_not_present::<Backend>(cert, oid::INHIBIT_ANY_POLICY, true)?;
        assert_no_unhandled_critical_extensions::<Backend>(cert)?;
    }

    // assert basic_constraints and key usage for all certs with a child - ie a non-leaf cert
    for window in padded_windows::<_, _, 2>(path.clone()) {
        match window {
            [Some(cert), Some(_)] => {
                if Backend::version(cert)? != 2 {
                    return Err(format!(
                        "Issuer certificate {} must be a v3 certificate",
                        Backend::subject_name(cert)
                    )
                    .into());
                }

                let basic_constraints = Backend::basic_constraints(cert)?.ok_or_else(|| {
                    format!(
                        "Issuer certificate {} is missing basicConstraints",
                        Backend::subject_name(cert)
                    )
                })?;
                if !basic_constraints.critical {
                    return Err(format!(
                        "Issuer certificate {} basicConstraints extension must be critical",
                        Backend::subject_name(cert)
                    )
                    .into());
                }
                if !basic_constraints.ca {
                    return Err(format!(
                        "Issuer certificate {} basicConstraints cA must be asserted",
                        Backend::subject_name(cert)
                    )
                    .into());
                }

                if let Some(key_usage) = Backend::key_usage(cert)? {
                    if !key_usage.key_cert_sign {
                        return Err(format!(
                            "Issuer certificate {} keyUsage must allow certificate signing",
                            Backend::subject_name(cert)
                        )
                        .into());
                    }
                }
            }
            [None, Some(_)] | [Some(_), None] => {}
            [None, None] => return Err("Certificate path must not be empty".into()),
        }
    }

    let mut max_path_length = path_len;
    for window in padded_windows::<_, _, 2>(path) {
        match window {
            [Some(cert), Some(_)] => {
                if !Backend::is_self_issued(cert)? {
                    if max_path_length == 0 {
                        return Err(format!(
                            "Issuer certificate {} exceeds pathLenConstraint",
                            Backend::subject_name(cert)
                        )
                        .into());
                    }

                    max_path_length -= 1;
                }

                if let Some(path_len_constraint) =
                    Backend::basic_constraints(cert)?.and_then(|bc| {
                        if bc.ca {
                            bc.path_len_constraint
                        } else {
                            None
                        }
                    })
                {
                    max_path_length = max_path_length.min(path_len_constraint);
                }
            }
            [None, Some(_)] | [Some(_), None] => {}
            [None, None] => return Err("Certificate path must not be empty".into()),
        }
    }

    Ok(())
}

/// Rejects an extension that this partial policy does not implement.
fn assert_skipped_extension_not_present<Backend: CertificateBackend>(
    cert: &Backend::Certificate,
    oid: &str,
    reject_non_critical: bool,
) -> super::Result<()> {
    let criticality = Backend::extension_criticality(cert, oid)?;
    if criticality == Some(true) || (reject_non_critical && criticality.is_some()) {
        return Err(format!(
            "Certificate {} contains unsupported extension {}",
            Backend::subject_name(cert),
            oid
        )
        .into());
    }

    Ok(())
}

/// Rejects critical extensions outside the subset handled by this module.
fn assert_no_unhandled_critical_extensions<Backend: CertificateBackend>(
    cert: &Backend::Certificate,
) -> super::Result<()> {
    for critical_oid in Backend::critical_extension_oids(cert) {
        if !oid::HANDLED_CRITICAL_EXTENSIONS.contains(&critical_oid.as_str()) {
            return Err(format!(
                "Certificate {} contains unhandled critical extension {}",
                Backend::subject_name(cert),
                critical_oid
            )
            .into());
        }
    }

    Ok(())
}

mod oid {
    /// RFC 5280 section 4.2.1.9: id-ce-basicConstraints OBJECT IDENTIFIER ::= { id-ce 19 }.
    pub const BASIC_CONSTRAINTS: &str = "2.5.29.19";
    /// RFC 5280 section 4.2.1.3: id-ce-keyUsage OBJECT IDENTIFIER ::= { id-ce 15 }.
    pub const KEY_USAGE: &str = "2.5.29.15";
    /// RFC 5280 section 4.2.1.4: id-ce-certificatePolicies OBJECT IDENTIFIER ::= { id-ce 32 }.
    pub const CERTIFICATE_POLICIES: &str = "2.5.29.32";
    /// RFC 5280 section 4.2.1.5: id-ce-policyMappings OBJECT IDENTIFIER ::= { id-ce 33 }.
    pub const POLICY_MAPPINGS: &str = "2.5.29.33";
    /// RFC 5280 section 4.2.1.10: id-ce-nameConstraints OBJECT IDENTIFIER ::= { id-ce 30 }.
    pub const NAME_CONSTRAINTS: &str = "2.5.29.30";
    /// RFC 5280 section 4.2.1.11: id-ce-policyConstraints OBJECT IDENTIFIER ::= { id-ce 36 }.
    pub const POLICY_CONSTRAINTS: &str = "2.5.29.36";
    /// RFC 5280 section 4.2.1.14: id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::= { id-ce 54 }.
    pub const INHIBIT_ANY_POLICY: &str = "2.5.29.54";

    pub const HANDLED_CRITICAL_EXTENSIONS: &[&str] = &[BASIC_CONSTRAINTS, KEY_USAGE];
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::{padded_windows, rfc5280_policy};
    use crate::{BasicConstraints, CertificateBackend, KeyUsage, Result};

    fn policy(path: &[&TestCertificate], unix_time: Duration) -> Result<()> {
        rfc5280_policy::<TestBackend, _>(path.iter().copied(), unix_time)
    }

    #[test]
    fn padded_windows_evaluates_padded_windows() {
        let certificates = ["A", "B", "C"];
        let path = certificates.iter().collect::<Vec<_>>();

        let windows = padded_windows::<_, _, 3>(path.iter().copied())
            .map(|window| window.map(|entry| entry.copied()))
            .collect::<Vec<_>>();

        assert_eq!(
            windows,
            vec![
                [None, None, Some("A")],
                [None, Some("A"), Some("B")],
                [Some("A"), Some("B"), Some("C")],
                [Some("B"), Some("C"), None],
                [Some("C"), None, None],
            ]
        );
    }

    #[test]
    fn padded_windows_can_drive_accumulation() {
        let certificates = [1, 2, 3];
        let path = certificates.iter().collect::<Vec<_>>();

        let mut sum = 0;
        for [cert] in padded_windows::<_, _, 1>(path.iter().copied()) {
            sum += *cert.expect("window should contain one certificate");
        }

        assert_eq!(sum, 6);
    }

    #[test]
    fn padded_windows_can_drive_fallible_loops() {
        let certificates = [1, 2, 3];
        let path = certificates.iter().collect::<Vec<_>>();
        let mut count = 0;

        let error = (|| {
            for [cert] in padded_windows::<_, _, 1>(path.iter().copied()) {
                if *cert.expect("window should contain one certificate") == 2 {
                    return Err("stop");
                }
                count += 1;
            }
            Ok(())
        })()
        .expect_err("policy should stop at failing certificate");

        assert_eq!(error, "stop");
        assert_eq!(count, 1);
    }

    #[test]
    fn padded_windows_supports_pairwise_checks() {
        let certificates = ["A", "B"];
        let path = certificates.iter().collect::<Vec<_>>();

        for window in padded_windows::<_, _, 2>(path.iter().copied()) {
            match window.map(|entry| entry.copied()) {
                [None, Some("A")] | [Some("A"), Some("B")] | [Some("B"), None] => {}
                unexpected => panic!("unexpected window: {:?}", unexpected),
            }
        }
    }

    #[test]
    fn rfc5280_policy_accepts_valid_path() {
        let root = TestCertificate::ca("Root", "Root");
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        policy(&path, Duration::from_secs(10)).unwrap();
    }

    #[test]
    fn rfc5280_policy_rejects_non_self_issued_first_certificate() {
        let root = TestCertificate::ca("Root", "Other");
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        policy(&path, Duration::from_secs(10)).expect_err("first certificate must be self-issued");
    }

    #[test]
    fn rfc5280_policy_rejects_issuer_subject_mismatch() {
        let root = TestCertificate::ca("Root", "Root");
        let leaf = TestCertificate::leaf("Leaf", "Other");
        let path = [&root, &leaf];

        policy(&path, Duration::from_secs(10))
            .expect_err("issuer subject must match subject issuer");
    }

    #[test]
    fn rfc5280_policy_rejects_invalid_cert_time() {
        let root = TestCertificate::ca("Root", "Root");
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        policy(&path, Duration::from_secs(200))
            .expect_err("certificate must be valid at evaluation time");
    }

    #[test]
    fn rfc5280_policy_rejects_critical_certificate_policies() {
        let mut root = TestCertificate::ca("Root", "Root");
        root.extensions.insert("2.5.29.32".to_string(), true);
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        policy(&path, Duration::from_secs(10))
            .expect_err("unsupported critical certificatePolicies must fail");
    }

    #[test]
    fn rfc5280_policy_allows_non_critical_certificate_policies() {
        let mut root = TestCertificate::ca("Root", "Root");
        root.extensions.insert("2.5.29.32".to_string(), false);
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        policy(&path, Duration::from_secs(10)).unwrap();
    }

    #[test]
    fn rfc5280_policy_rejects_unhandled_critical_extension() {
        let mut root = TestCertificate::ca("Root", "Root");
        root.extensions.insert("1.2.3.4.5".to_string(), true);
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        policy(&path, Duration::from_secs(10)).expect_err("unknown critical extension must fail");
    }

    #[test]
    fn rfc5280_policy_rejects_non_ca_issuer() {
        let mut root = TestCertificate::ca("Root", "Root");
        root.basic_constraints = Some(BasicConstraints {
            critical: true,
            ca: false,
            path_len_constraint: None,
        });
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        policy(&path, Duration::from_secs(10)).expect_err("issuer must assert basicConstraints cA");
    }

    #[test]
    fn rfc5280_policy_rejects_issuer_without_key_cert_sign_usage() {
        let mut root = TestCertificate::ca("Root", "Root");
        root.key_usage = Some(KeyUsage {
            key_cert_sign: false,
        });
        let leaf = TestCertificate::leaf("Leaf", "Root");
        let path = [&root, &leaf];

        policy(&path, Duration::from_secs(10))
            .expect_err("issuer keyUsage must allow certificate signing");
    }

    #[test]
    fn rfc5280_policy_rejects_path_len_constraint_exceeded() {
        let mut root = TestCertificate::ca("Root", "Root");
        root.basic_constraints = Some(BasicConstraints {
            critical: true,
            ca: true,
            path_len_constraint: Some(0),
        });
        let intermediate = TestCertificate::ca("Intermediate", "Root");
        let leaf = TestCertificate::leaf("Leaf", "Intermediate");
        let path = [&root, &intermediate, &leaf];

        policy(&path, Duration::from_secs(10))
            .expect_err("root pathLenConstraint should reject intermediate CA");
    }

    #[derive(Clone, Debug)]
    struct TestCertificate {
        subject: String,
        issuer: String,
        valid_from: Duration,
        valid_until: Duration,
        v3: bool,
        basic_constraints: Option<BasicConstraints>,
        key_usage: Option<KeyUsage>,
        extensions: HashMap<String, bool>,
    }

    impl TestCertificate {
        fn ca(subject: &str, issuer: &str) -> Self {
            let mut extensions = HashMap::new();
            extensions.insert("2.5.29.19".to_string(), true);
            extensions.insert("2.5.29.15".to_string(), true);

            Self {
                subject: subject.to_string(),
                issuer: issuer.to_string(),
                valid_from: Duration::from_secs(0),
                valid_until: Duration::from_secs(100),
                v3: true,
                basic_constraints: Some(BasicConstraints {
                    critical: true,
                    ca: true,
                    path_len_constraint: None,
                }),
                key_usage: Some(KeyUsage {
                    key_cert_sign: true,
                }),
                extensions,
            }
        }

        fn leaf(subject: &str, issuer: &str) -> Self {
            Self {
                subject: subject.to_string(),
                issuer: issuer.to_string(),
                valid_from: Duration::from_secs(0),
                valid_until: Duration::from_secs(100),
                v3: true,
                basic_constraints: None,
                key_usage: None,
                extensions: HashMap::new(),
            }
        }
    }

    struct TestBackend;

    impl CertificateBackend for TestBackend {
        type Certificate = TestCertificate;

        fn from_pem(_pem: &[u8]) -> Result<Self::Certificate> {
            unimplemented!("test backend does not parse certificates")
        }

        fn from_pem_chain(_pem: &[u8]) -> Result<Vec<Self::Certificate>> {
            unimplemented!("test backend does not parse certificate chains")
        }

        fn from_der(_der: &[u8]) -> Result<Self::Certificate> {
            unimplemented!("test backend does not parse certificates")
        }

        fn to_der(_cert: &Self::Certificate) -> Result<Vec<u8>> {
            unimplemented!("test backend does not encode certificates")
        }

        fn to_pem(_cert: &Self::Certificate) -> Result<String> {
            unimplemented!("test backend does not encode certificates")
        }

        fn get_public_key(_cert: &Self::Certificate) -> Result<Vec<u8>> {
            unimplemented!("test backend does not expose public keys")
        }

        fn get_extension_value_by_oid(
            _cert: &Self::Certificate,
            _oid: &str,
        ) -> Result<Option<Vec<u8>>> {
            unimplemented!("test backend does not expose raw extensions")
        }

        fn subject_name(cert: &Self::Certificate) -> String {
            cert.subject.clone()
        }

        fn issuer_name(cert: &Self::Certificate) -> String {
            cert.issuer.clone()
        }

        fn subject_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
            Ok(cert.subject.as_bytes().to_vec())
        }

        fn issuer_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
            Ok(cert.issuer.as_bytes().to_vec())
        }

        fn is_valid_at(cert: &Self::Certificate, unix_time: Duration) -> Result<bool> {
            Ok(cert.valid_from <= unix_time && unix_time <= cert.valid_until)
        }

        fn version(cert: &Self::Certificate) -> Result<u8> {
            Ok(if cert.v3 { 2 } else { 0 })
        }

        fn basic_constraints(cert: &Self::Certificate) -> Result<Option<BasicConstraints>> {
            Ok(cert.basic_constraints)
        }

        fn key_usage(cert: &Self::Certificate) -> Result<Option<KeyUsage>> {
            Ok(cert.key_usage)
        }

        fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>> {
            Ok(cert.extensions.get(oid).copied())
        }

        fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String> {
            cert.extensions
                .iter()
                .filter_map(|(oid, critical)| critical.then(|| oid.clone()))
                .collect()
        }
    }
}
