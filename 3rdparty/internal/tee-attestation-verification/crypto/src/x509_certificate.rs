// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(all(async_crypto, not(sync_crypto)))]
use std::{future::Future, pin::Pin};

use pkcs1::{RsaPssParams, TrailerField};
use x509_cert::der::{
    asn1::AnyRef, oid::ObjectIdentifier, pem::LineEnding, referenced::OwnedToRef, Decode,
    DecodePem, Encode, EncodePem,
};
use x509_cert::ext::pkix::{BasicConstraints as X509BasicConstraints, KeyUsage as X509KeyUsage};
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::{
    BasicConstraints, KeyUsage, Result, RsaPkcs1v15SignatureKeyAlgorithm,
    RsaPssSignatureKeyAlgorithm, SignatureKeyAlgorithm,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    inner: x509_cert::Certificate,
}

/// Synchronous checking of a certificate path
#[cfg(sync_crypto)]
pub fn verify_certificate_path(
    mut verify_signature: impl FnMut(&Certificate, &Certificate) -> Result<()>,
    root_trust_anchor: &Certificate,
    untrusted_chain: &[&Certificate],
    leaf: &Certificate,
) -> Result<()> {
    // Verify that the chain is properly ordered and that signatures are valid.
    let full_chain = untrusted_chain
        .iter()
        .copied()
        .chain(std::iter::once(leaf))
        .collect::<Vec<_>>();

    // The trusted certificate must issue the first certificate in the path.
    verify_signature(root_trust_anchor, full_chain[0])
        .map_err(|e| format!("Certificate signature verification failed: {e}"))?;
    for edge in full_chain.windows(2) {
        let issuer = edge[0];
        let subject = edge[1];
        verify_signature(issuer, subject)
            .map_err(|e| format!("Certificate signature verification failed: {e}"))?;
    }

    Ok(())
}

/// Asynchronous checking of the certificate path
// If sync_crypto enabled, this is automatically dispatched to verify_certificate_path
// So disable if sync_crypto is enabled to avoid unused warnings
#[cfg(all(async_crypto, not(sync_crypto)))]
pub async fn verify_certificate_path_async<F>(
    mut verify_signature: F,
    root_trust_anchor: &Certificate,
    untrusted_chain: &[&Certificate],
    leaf: &Certificate,
) -> Result<()>
where
    F: for<'a> FnMut(
        &'a Certificate,
        &'a Certificate,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>>,
{
    // Verify that the chain is properly ordered and that signatures are valid.
    let full_chain = untrusted_chain
        .iter()
        .copied()
        .chain(std::iter::once(leaf))
        .collect::<Vec<_>>();

    // The trusted certificate must issue the first certificate in the path.
    verify_signature(root_trust_anchor, full_chain[0])
        .await
        .map_err(|e| format!("Certificate signature verification failed: {e}"))?;
    for edge in full_chain.windows(2) {
        let issuer = edge[0];
        let subject = edge[1];
        verify_signature(issuer, subject)
            .await
            .map_err(|e| format!("Certificate signature verification failed: {e}"))?;
    }

    Ok(())
}

impl Certificate {
    // Certificate accessors.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: x509_cert::Certificate::from_pem(pem)?,
        })
    }

    pub fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self>> {
        x509_cert::Certificate::load_pem_chain(pem)?
            .into_iter()
            .map(|inner| Ok(Self { inner }))
            .collect()
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: x509_cert::Certificate::from_der(der)?,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.inner.to_der()?)
    }

    pub fn to_pem(&self) -> Result<String> {
        Ok(self.inner.to_pem(LineEnding::LF)?)
    }

    pub fn public_key_spki_der(&self) -> Result<Vec<u8>> {
        Ok(self
            .inner
            .tbs_certificate
            .subject_public_key_info
            .to_der()?)
    }

    pub fn get_extension_value_by_oid(&self, oid: &str) -> Result<Option<Vec<u8>>> {
        let oid = ObjectIdentifier::new(oid)?;

        let extensions = match self.inner.tbs_certificate.extensions.as_ref() {
            Some(extensions) => extensions,
            None => return Ok(None),
        };

        Ok(extensions
            .iter()
            .find(|extension| extension.extn_id == oid)
            .map(|extension| extension.extn_value.as_bytes().to_vec()))
    }

    pub fn tbs_certificate_der(&self) -> Result<Vec<u8>> {
        Ok(self.inner.tbs_certificate.to_der()?)
    }

    pub fn signature_bytes(&self) -> &[u8] {
        self.inner.signature.raw_bytes()
    }

    pub fn signature_algorithm(&self) -> Result<SignatureKeyAlgorithm> {
        parse_signature_algorithm(&self.inner.signature_algorithm)
    }
    pub fn subject_name(&self) -> String {
        self.inner.tbs_certificate.subject.to_string()
    }

    pub fn issuer_name(&self) -> String {
        self.inner.tbs_certificate.issuer.to_string()
    }

    pub fn subject_name_der(&self) -> Result<Vec<u8>> {
        Ok(self.inner.tbs_certificate.subject.to_der()?)
    }

    pub fn issuer_name_der(&self) -> Result<Vec<u8>> {
        Ok(self.inner.tbs_certificate.issuer.to_der()?)
    }

    pub fn is_valid_at(&self, unix_time: std::time::Duration) -> Result<bool> {
        let validity = self.inner.tbs_certificate.validity;
        Ok(validity.not_before.to_unix_duration() <= unix_time
            && unix_time <= validity.not_after.to_unix_duration())
    }

    pub fn version(&self) -> u8 {
        self.inner.tbs_certificate.version as u8
    }

    pub fn basic_constraints(&self) -> Result<Option<BasicConstraints>> {
        Ok(self
            .inner
            .tbs_certificate
            .get::<X509BasicConstraints>()?
            .map(|(critical, basic_constraints)| BasicConstraints {
                critical,
                ca: basic_constraints.ca,
                path_len_constraint: basic_constraints.path_len_constraint.map(usize::from),
            }))
    }

    pub fn key_usage(&self) -> Result<Option<KeyUsage>> {
        Ok(self
            .inner
            .tbs_certificate
            .get::<X509KeyUsage>()?
            .map(|(_, key_usage)| KeyUsage {
                key_cert_sign: key_usage.key_cert_sign(),
            }))
    }

    pub fn extension_criticality(&self, oid: &str) -> Result<Option<bool>> {
        let oid = ObjectIdentifier::new(oid)?;

        Ok(self
            .inner
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .find(|extension| extension.extn_id == oid)
            .map(|extension| extension.critical))
    }

    pub fn critical_extension_oids(&self) -> Vec<String> {
        self.inner
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter_map(|extension| extension.critical.then(|| extension.extn_id.to_string()))
            .collect()
    }
}

fn parse_signature_algorithm(
    algorithm: &AlgorithmIdentifierOwned,
) -> Result<SignatureKeyAlgorithm> {
    let algorithm_ref = algorithm.owned_to_ref();

    if algorithm_ref.oid == oid::RSA_PSS {
        let parameters = algorithm_ref
            .parameters
            .ok_or("RSA-PSS signature algorithm parameters are required")?;

        return parse_rsa_pss_signature_algorithm(parameters);
    }

    if algorithm_ref.oid == oid::SHA256_WITH_RSA_ENCRYPTION {
        return Ok(SignatureKeyAlgorithm::RsaPkcs1v15(
            RsaPkcs1v15SignatureKeyAlgorithm::Rs256,
        ));
    }
    if algorithm_ref.oid == oid::SHA384_WITH_RSA_ENCRYPTION {
        return Ok(SignatureKeyAlgorithm::RsaPkcs1v15(
            RsaPkcs1v15SignatureKeyAlgorithm::Rs384,
        ));
    }
    if algorithm_ref.oid == oid::SHA512_WITH_RSA_ENCRYPTION {
        return Ok(SignatureKeyAlgorithm::RsaPkcs1v15(
            RsaPkcs1v15SignatureKeyAlgorithm::Rs512,
        ));
    }

    Err(format!("Unsupported signature algorithm OID: {}", algorithm_ref.oid).into())
}

fn parse_rsa_pss_signature_algorithm(parameters: AnyRef<'_>) -> Result<SignatureKeyAlgorithm> {
    let parameters = parameters.decode_as::<RsaPssParams<'_>>()?;
    let algorithm = rsa_pss_algorithm_from_hash_oid(parameters.hash.oid)?;

    if !parameters
        .hash
        .parameters
        .map(|parameters| parameters.is_null())
        .unwrap_or(true)
    {
        return Err("Unsupported RSA-PSS hash algorithm parameters".into());
    }

    let Some(mask_gen_hash) = parameters.mask_gen.parameters else {
        return Err("RSA-PSS MGF1 parameters are required".into());
    };

    if parameters.mask_gen.oid != oid::MGF1
        || mask_gen_hash.oid != rsa_pss_hash_oid(algorithm)
        || !mask_gen_hash
            .parameters
            .map(|parameters| parameters.is_null())
            .unwrap_or(true)
    {
        return Err("Unsupported RSA-PSS mask generation parameters".into());
    }

    if usize::from(parameters.salt_len) != algorithm.salt_len() {
        return Err(format!(
            "Unsupported RSA-PSS salt length: expected {}, got {}",
            algorithm.salt_len(),
            parameters.salt_len
        )
        .into());
    }

    if parameters.trailer_field != TrailerField::BC {
        return Err("Unsupported RSA-PSS trailer field".into());
    }

    Ok(SignatureKeyAlgorithm::RsaPss(algorithm))
}

fn rsa_pss_algorithm_from_hash_oid(oid: ObjectIdentifier) -> Result<RsaPssSignatureKeyAlgorithm> {
    match oid {
        oid::SHA256 => Ok(RsaPssSignatureKeyAlgorithm::Ps256),
        oid::SHA384 => Ok(RsaPssSignatureKeyAlgorithm::Ps384),
        oid::SHA512 => Ok(RsaPssSignatureKeyAlgorithm::Ps512),
        _ => Err("Unsupported RSA-PSS hash algorithm parameters".into()),
    }
}

fn rsa_pss_hash_oid(algorithm: RsaPssSignatureKeyAlgorithm) -> ObjectIdentifier {
    match algorithm {
        RsaPssSignatureKeyAlgorithm::Ps256 => oid::SHA256,
        RsaPssSignatureKeyAlgorithm::Ps384 => oid::SHA384,
        RsaPssSignatureKeyAlgorithm::Ps512 => oid::SHA512,
    }
}

mod oid {
    use x509_cert::der::oid::ObjectIdentifier;

    // RFC 4055: https://www.rfc-editor.org/rfc/rfc4055.html
    // RFC 5754: https://www.rfc-editor.org/rfc/rfc5754.html
    // RFC 8017: https://www.rfc-editor.org/rfc/rfc8017.html
    /// id-RSASSA-PSS from RFC 4055 section 3.1 and RFC 8017 appendix A.2.3.
    pub const RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
    /// id-mgf1 from RFC 8017 appendix A.2.1.
    pub const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
    /// id-sha256 from RFC 5754 section 2.2.
    pub const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    /// id-sha384 from RFC 5754 section 2.3.
    pub const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
    /// id-sha512 from RFC 5754 section 2.4.
    pub const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
    /// sha256WithRSAEncryption from RFC 5754 section 3.2.
    pub const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    /// sha384WithRSAEncryption from RFC 5754 section 3.2.
    pub const SHA384_WITH_RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    /// sha512WithRSAEncryption from RFC 5754 section 3.2.
    pub const SHA512_WITH_RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
}

#[cfg(test)]
mod test {
    use x509_cert::der::{asn1::AnyRef, Decode, Encode};

    use super::Certificate;
    use crate::{
        RsaPkcs1v15SignatureKeyAlgorithm, RsaPssSignatureKeyAlgorithm, SignatureKeyAlgorithm,
    };

    const MILAN_ARK: &[u8] = include_bytes!("test_data/milan_ark.pem");
    const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");
    const MILAN_VCEK: &[u8] = include_bytes!("test_data/milan_vcek.pem");

    fn cert(pem: &[u8]) -> Certificate {
        Certificate::from_pem(pem).unwrap()
    }

    #[test]
    fn from_der_round_trips_from_pem_certificate() {
        let cert = cert(MILAN_VCEK);
        let der = cert.to_der().expect("DER encoding should succeed");
        let reparsed = Certificate::from_der(&der).expect("DER should parse");

        assert_eq!(reparsed.to_der().expect("Reparsed DER should encode"), der);
    }

    #[test]
    fn get_public_key_returns_subject_public_key_info_der() {
        let cert = cert(MILAN_ARK);

        assert_eq!(
            cert.public_key_spki_der()
                .expect("SPKI extraction should succeed"),
            cert.inner
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .expect("SPKI DER should encode")
        );
    }

    #[test]
    fn extension_lookup_returns_expected_bootloader_value() {
        let vcek = cert(MILAN_VCEK);

        let bootloader = vcek
            .get_extension_value_by_oid("1.3.6.1.4.1.3704.1.3.1")
            .expect("BootLoader OID lookup should succeed")
            .expect("BootLoader OID should be present in Milan VCEK");

        assert_eq!(bootloader, vec![0x02, 0x01, 0x04]);
    }

    #[test]
    fn extension_lookup_returns_expected_hwid_value() {
        let vcek = cert(MILAN_VCEK);

        let hwid = vcek
            .get_extension_value_by_oid("1.3.6.1.4.1.3704.1.4")
            .expect("HWID OID lookup should succeed")
            .expect("HWID OID should be present in Milan VCEK");

        assert_eq!(
            hwid,
            [
                79, 251, 92, 180, 253, 89, 79, 63, 238, 101, 40, 252, 63, 177, 3, 112, 187, 56,
                171, 232, 157, 205, 91, 162, 207, 10, 182, 161, 29, 242, 202, 40, 42, 221, 81, 107,
                239, 69, 168, 144, 168, 201, 249, 115, 43, 220, 166, 143, 159, 63, 22, 196, 46,
                132, 96, 48, 168, 0, 41, 93, 190, 177, 155, 165,
            ]
        );
    }

    #[test]
    fn extension_lookup_returns_none_for_missing_oid() {
        let vcek = cert(MILAN_VCEK);

        let missing = vcek
            .get_extension_value_by_oid("1.2.3.4.5.6.7.8.9")
            .expect("Missing OID lookup should not fail");

        assert!(missing.is_none());
    }

    #[test]
    fn extension_lookup_rejects_malformed_oid() {
        let vcek = cert(MILAN_VCEK);

        vcek.get_extension_value_by_oid("not-an-oid")
            .expect_err("Malformed OID should fail");
    }

    #[test]
    fn pem_chain_parsing_preserves_input_order() {
        let mut pem_chain = Vec::new();
        pem_chain.extend_from_slice(MILAN_ASK);
        pem_chain.push(b'\n');
        pem_chain.extend_from_slice(MILAN_ARK);

        let chain = Certificate::from_pem_chain(&pem_chain).expect("PEM chain should parse");

        assert_eq!(chain.len(), 2);
        assert_eq!(
            chain[0].to_der().expect("ASK DER should encode"),
            cert(MILAN_ASK)
                .to_der()
                .expect("ASK fixture DER should encode")
        );
        assert_eq!(
            chain[1].to_der().expect("ARK DER should encode"),
            cert(MILAN_ARK)
                .to_der()
                .expect("ARK fixture DER should encode")
        );
    }

    #[test]
    fn pem_encoding_round_trips_through_from_pem() {
        let cert = cert(MILAN_VCEK);
        let pem = cert.to_pem().expect("PEM encoding should succeed");
        let reparsed = Certificate::from_pem(pem.as_bytes()).expect("PEM should parse");

        assert_eq!(
            reparsed.to_der().expect("Reparsed DER should encode"),
            cert.to_der().expect("Original DER should encode")
        );
    }

    #[test]
    fn signature_algorithm_reports_rsa_pss() {
        let cert = cert(MILAN_VCEK);

        assert_eq!(
            cert.signature_algorithm()
                .expect("Signature algorithm should parse"),
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384)
        );
    }

    #[test]
    fn signature_algorithm_accepts_rsa_pkcs1v15_sha2_oids() {
        for (oid, algorithm) in [
            (
                super::oid::SHA256_WITH_RSA_ENCRYPTION,
                RsaPkcs1v15SignatureKeyAlgorithm::Rs256,
            ),
            (
                super::oid::SHA384_WITH_RSA_ENCRYPTION,
                RsaPkcs1v15SignatureKeyAlgorithm::Rs384,
            ),
            (
                super::oid::SHA512_WITH_RSA_ENCRYPTION,
                RsaPkcs1v15SignatureKeyAlgorithm::Rs512,
            ),
        ] {
            let algorithm_identifier = x509_cert::spki::AlgorithmIdentifierOwned {
                oid,
                parameters: None,
            };

            assert_eq!(
                super::parse_signature_algorithm(&algorithm_identifier)
                    .expect("RSA PKCS#1 v1.5 SHA-2 OID should parse"),
                SignatureKeyAlgorithm::RsaPkcs1v15(algorithm)
            );
        }
    }

    #[test]
    fn rsa_pss_signature_algorithm_requires_parameters() {
        let algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: super::oid::RSA_PSS,
            parameters: None,
        };

        super::parse_signature_algorithm(&algorithm)
            .expect_err("RSA-PSS parameters default to SHA-1 and should be rejected");
    }

    #[test]
    fn rsa_pss_signature_algorithm_accepts_supported_hashes() {
        for algorithm in [
            RsaPssSignatureKeyAlgorithm::Ps256,
            RsaPssSignatureKeyAlgorithm::Ps384,
            RsaPssSignatureKeyAlgorithm::Ps512,
        ] {
            let der = rsa_pss_params_der(algorithm, algorithm, algorithm.salt_len());
            let parameters = AnyRef::from_der(&der).expect("RSA-PSS params DER should parse");

            assert_eq!(
                super::parse_rsa_pss_signature_algorithm(parameters)
                    .expect("RSA-PSS params should be supported"),
                SignatureKeyAlgorithm::RsaPss(algorithm)
            );
        }
    }

    #[test]
    fn rsa_pss_signature_algorithm_requires_matching_mgf1_hash() {
        let der = rsa_pss_params_der(
            RsaPssSignatureKeyAlgorithm::Ps384,
            RsaPssSignatureKeyAlgorithm::Ps256,
            RsaPssSignatureKeyAlgorithm::Ps384.salt_len(),
        );
        let parameters = AnyRef::from_der(&der).expect("RSA-PSS params DER should parse");

        super::parse_rsa_pss_signature_algorithm(parameters)
            .expect_err("Mismatched MGF1 hash should be rejected");
    }

    #[test]
    fn rsa_pss_signature_algorithm_requires_matching_salt_length() {
        let der = rsa_pss_params_der(
            RsaPssSignatureKeyAlgorithm::Ps512,
            RsaPssSignatureKeyAlgorithm::Ps512,
            RsaPssSignatureKeyAlgorithm::Ps384.salt_len(),
        );
        let parameters = AnyRef::from_der(&der).expect("RSA-PSS params DER should parse");

        super::parse_rsa_pss_signature_algorithm(parameters)
            .expect_err("Mismatched salt length should be rejected");
    }

    fn rsa_pss_params_der(
        hash: RsaPssSignatureKeyAlgorithm,
        mgf1_hash: RsaPssSignatureKeyAlgorithm,
        salt_len: usize,
    ) -> Vec<u8> {
        der_sequence(
            &[
                der_explicit(0, &hash_algorithm_identifier(hash)),
                der_explicit(1, &mgf1_algorithm_identifier(mgf1_hash)),
                der_explicit(2, &[0x02, 0x01, salt_len as u8]),
                der_explicit(3, &[0x02, 0x01, 0x01]),
            ]
            .concat(),
        )
    }

    fn mgf1_algorithm_identifier(hash: RsaPssSignatureKeyAlgorithm) -> Vec<u8> {
        let mut bytes = vec![
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
        ];
        bytes.extend_from_slice(&hash_algorithm_identifier(hash));
        der_sequence(&bytes)
    }

    fn hash_algorithm_identifier(hash: RsaPssSignatureKeyAlgorithm) -> Vec<u8> {
        let oid_final_byte = match hash {
            RsaPssSignatureKeyAlgorithm::Ps256 => 0x01,
            RsaPssSignatureKeyAlgorithm::Ps384 => 0x02,
            RsaPssSignatureKeyAlgorithm::Ps512 => 0x03,
        };
        der_sequence(&[
            0x06,
            0x09,
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            oid_final_byte,
            0x05,
            0x00,
        ])
    }

    fn der_explicit(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0xa0 + tag, content.len() as u8];
        bytes.extend_from_slice(content);
        bytes
    }

    fn der_sequence(content: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x30, content.len() as u8];
        bytes.extend_from_slice(content);
        bytes
    }
}
