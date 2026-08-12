// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native OpenSSL-backed cryptographic backend.
//!
//! This backend uses OpenSSL for X.509 certificate parsing and encoding,
//! certificate-chain verification, and SEV-SNP attestation report signature
//! verification. It is the native backend selected when `crypto_openssl` is
//! enabled for a non-`wasm32` target.

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::asn1::{Asn1Object, Asn1ObjectRef, Asn1Time};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier as OpenSslVerifier};
use openssl::stack::Stack;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::verify::X509VerifyParam;
use openssl_sys::{
    ASN1_STRING_get0_data, ASN1_STRING_length, X509_EXTENSION_get_critical,
    X509_EXTENSION_get_data, X509_EXTENSION_get_object, X509_get_ext, X509_get_ext_by_OBJ,
    X509_get_ext_count, X509_get_extension_flags, X509_get_key_usage, X509v3_KU_KEY_CERT_SIGN,
    EXFLAG_CA,
};
use std::cmp::Ordering;

use super::{
    compatible_key_and_signature, CertificateBackend, CryptoBackend, DigestAlgorithm,
    EcSignatureKeyAlgorithm, KeyBackend, Result, RsaPkcs1v15SignatureKeyAlgorithm,
    RsaPssSignatureKeyAlgorithm, SignatureBackend, SignatureKeyAlgorithm,
};

pub struct Crypto;

type Certificate = openssl::x509::X509;

pub struct Key {
    key: PKey<Public>,
    verification: OpenSslKeyVerification,
}

pub enum Signature {
    Ecdsa {
        algorithm: EcSignatureKeyAlgorithm,
        der: Vec<u8>,
    },
    RsaPss {
        algorithm: RsaPssSignatureKeyAlgorithm,
        raw: Vec<u8>,
    },
    RsaPkcs1v15 {
        algorithm: RsaPkcs1v15SignatureKeyAlgorithm,
        raw: Vec<u8>,
    },
}

enum OpenSslKeyVerification {
    Ecdsa {
        algorithm: EcSignatureKeyAlgorithm,
    },
    RsaPss {
        algorithm: RsaPssSignatureKeyAlgorithm,
    },
    RsaPkcs1v15 {
        algorithm: RsaPkcs1v15SignatureKeyAlgorithm,
    },
}

impl KeyBackend for Key {
    fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        let key = PKey::public_key_from_der(spki_der)?;
        let verification = OpenSslKeyVerification::from_key_algorithm(&key, algorithm)?;

        Ok(Key { key, verification })
    }
}

impl SignatureBackend for Signature {
    fn from_bytes(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(algorithm) => {
                let der = EcdsaSig::from_der(signature)
                    .map_err(|e| format!("Failed to parse DER ECDSA signature: {:?}", e))?
                    .to_der()?;
                Ok(Self::Ecdsa { algorithm, der })
            }
            SignatureKeyAlgorithm::RsaPss(algorithm) => Ok(Self::RsaPss {
                algorithm,
                raw: signature.to_vec(),
            }),
            SignatureKeyAlgorithm::RsaPkcs1v15(algorithm) => Ok(Self::RsaPkcs1v15 {
                algorithm,
                raw: signature.to_vec(),
            }),
        }
    }

    fn from_ec_components(r: &[u8], s: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Self> {
        let r = ec_component_from_bytes("r", r, algorithm)?;
        let s = ec_component_from_bytes("s", s, algorithm)?;
        let der = EcdsaSig::from_private_components(r, s)?.to_der()?;

        Ok(Self::Ecdsa { algorithm, der })
    }
}

impl CertificateBackend for Crypto {
    type Certificate = Certificate;

    fn from_pem(pem: &[u8]) -> Result<Self::Certificate> {
        openssl::x509::X509::from_pem(pem).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self::Certificate>> {
        openssl::x509::X509::stack_from_pem(pem)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn from_der(der: &[u8]) -> Result<Self::Certificate> {
        openssl::x509::X509::from_der(der).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn to_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.to_der()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    fn to_pem(cert: &Self::Certificate) -> Result<String> {
        let pem = cert
            .to_pem()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        String::from_utf8(pem).map_err(|e| format!("Failed to decode PEM as UTF-8: {:?}", e).into())
    }

    fn get_public_key(cert: &Self::Certificate) -> Result<Vec<u8>> {
        let pub_key = cert.public_key()?;
        Ok(pub_key.public_key_to_der()?)
    }

    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        let oid = Asn1Object::from_str(oid)
            .map_err(|e| format!("Invalid extension OID {}: {:?}", oid, e))?;

        unsafe {
            let index = X509_get_ext_by_OBJ(cert.as_ptr(), oid.as_ptr(), -1);
            if index == -1 {
                return Ok(None);
            }

            let extension = X509_get_ext(cert.as_ptr(), index);
            if extension.is_null() {
                return Err("OpenSSL returned null extension pointer".into());
            }

            let data = X509_EXTENSION_get_data(extension);
            if data.is_null() {
                return Err("OpenSSL returned null extension data".into());
            }

            let len = ASN1_STRING_length(data.cast());
            if len < 0 {
                return Err("OpenSSL returned negative extension length".into());
            }

            let data_ptr = ASN1_STRING_get0_data(data.cast());
            if data_ptr.is_null() {
                return Err("OpenSSL returned null extension bytes".into());
            }

            let bytes = std::slice::from_raw_parts(data_ptr, len as usize).to_vec();
            Ok(Some(bytes))
        }
    }

    fn subject_name(cert: &Self::Certificate) -> String {
        format!("{:?}", cert.subject_name())
    }

    fn issuer_name(cert: &Self::Certificate) -> String {
        format!("{:?}", cert.issuer_name())
    }

    fn subject_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        Ok(cert.subject_name().to_der()?)
    }

    fn issuer_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        Ok(cert.issuer_name().to_der()?)
    }

    fn is_valid_at(cert: &Self::Certificate, unix_time: std::time::Duration) -> Result<bool> {
        let unix_time = unix_time
            .as_secs()
            .try_into()
            .map_err(|_| "Unix time does not fit OpenSSL time_t")?;
        let unix_time = Asn1Time::from_unix(unix_time)?;

        Ok(cert.not_before().compare(&unix_time)? != Ordering::Greater
            && cert.not_after().compare(&unix_time)? != Ordering::Less)
    }

    fn version(cert: &Self::Certificate) -> Result<u8> {
        cert.version()
            .try_into()
            .map_err(|_| "OpenSSL returned a negative certificate version".into())
    }

    fn basic_constraints(cert: &Self::Certificate) -> Result<Option<super::BasicConstraints>> {
        let critical = match Self::extension_criticality(cert, oid::BASIC_CONSTRAINTS)? {
            Some(critical) => critical,
            None => return Ok(None),
        };
        let path_len_constraint = cert
            .pathlen()
            .map(usize::try_from)
            .transpose()
            .map_err(|_| "pathLenConstraint does not fit usize")?;
        let flags = unsafe { X509_get_extension_flags(cert.as_ptr()) };

        Ok(Some(super::BasicConstraints {
            critical,
            ca: flags & EXFLAG_CA != 0,
            path_len_constraint,
        }))
    }

    fn key_usage(cert: &Self::Certificate) -> Result<Option<super::KeyUsage>> {
        if Self::extension_criticality(cert, oid::KEY_USAGE)?.is_none() {
            return Ok(None);
        }
        let key_usage = unsafe { X509_get_key_usage(cert.as_ptr()) };

        Ok(Some(super::KeyUsage {
            key_cert_sign: key_usage & X509v3_KU_KEY_CERT_SIGN != 0,
        }))
    }

    fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>> {
        let oid = Asn1Object::from_str(oid)
            .map_err(|e| format!("Invalid extension OID {}: {:?}", oid, e))?;

        unsafe {
            let index = X509_get_ext_by_OBJ(cert.as_ptr(), oid.as_ptr(), -1);
            if index == -1 {
                return Ok(None);
            }

            let extension = X509_get_ext(cert.as_ptr(), index);
            if extension.is_null() {
                return Err("OpenSSL returned null extension pointer".into());
            }

            Ok(Some(X509_EXTENSION_get_critical(extension) != 0))
        }
    }

    fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String> {
        let count = unsafe { X509_get_ext_count(cert.as_ptr()) };
        if count <= 0 {
            return Vec::new();
        }

        (0..count)
            .filter_map(|index| {
                let extension = unsafe { X509_get_ext(cert.as_ptr(), index) };
                if extension.is_null() {
                    return None;
                }

                let critical = unsafe { X509_EXTENSION_get_critical(extension) != 0 };
                if !critical {
                    return None;
                }

                let object = unsafe { X509_EXTENSION_get_object(extension) };
                if object.is_null() {
                    return None;
                }

                Some(unsafe { Asn1ObjectRef::from_ptr(object) }.to_string())
            })
            .collect()
    }
}

mod oid {
    /// RFC 5280 section 4.2.1.9: id-ce-basicConstraints OBJECT IDENTIFIER ::= { id-ce 19 }.
    pub const BASIC_CONSTRAINTS: &str = "2.5.29.19";
    /// RFC 5280 section 4.2.1.3: id-ce-keyUsage OBJECT IDENTIFIER ::= { id-ce 15 }.
    pub const KEY_USAGE: &str = "2.5.29.15";
}

impl CryptoBackend for Crypto {
    type Key = Key;
    type Signature = Signature;

    fn digest(algorithm: DigestAlgorithm, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(hash(message_digest(algorithm), bytes)?.to_vec())
    }

    fn verify_signature(
        key: &Self::Key,
        signature: &Self::Signature,
        signed_bytes: &[u8],
    ) -> Result<()> {
        let signature_algorithm = signature.algorithm();
        key.verification
            .ensure_signature_algorithm(signature_algorithm)?;
        let signature = signature.as_openssl_bytes();
        let mut verifier = key.verification.verifier(&key.key, signature_algorithm)?;

        match verifier.verify_oneshot(signature, signed_bytes) {
            Ok(true) => Ok(()),
            Ok(false) => Err(key.verification.failure_message().into()),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn verify_chain(
        trusted_cert: &Certificate,
        untrusted_chain: &[&Certificate],
        leaf: &Certificate,
        unix_time: Option<std::time::Duration>,
    ) -> Result<()> {
        let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
        store_builder.add_cert(trusted_cert.to_owned())?;
        store_builder.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
        if let Some(unix_time) = unix_time {
            let mut params = X509VerifyParam::new()?;
            let unix_time = unix_time
                .as_secs()
                .try_into()
                .map_err(|_| "Unix time does not fit OpenSSL time_t")?;
            params.set_time(unix_time);
            store_builder.set_param(&params)?;
        }
        let store = store_builder.build();
        let mut ctx = openssl::x509::X509StoreContext::new()?;
        let mut chain = Stack::<Certificate>::new()?;
        for cert in untrusted_chain {
            chain.push((*cert).to_owned())?;
        }
        match ctx.init(&store, leaf, &chain, |c| c.verify_cert()) {
            Ok(true) => Ok(()),
            Ok(false) => Err("Certificate verification failed".into()),
            Err(e) => Err(Box::new(e)),
        }
    }
}

impl Key {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        self.verification.algorithm()
    }
}

impl OpenSslKeyVerification {
    fn from_key_algorithm(key: &PKey<Public>, algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(algorithm) => {
                let key = key
                    .ec_key()
                    .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                let curve_name = key
                    .group()
                    .curve_name()
                    .ok_or("ECDSA public key must use a named curve")?;
                let expected_curve_name = ec_curve_nid(algorithm);
                if curve_name != expected_curve_name {
                    return Err(format!(
                        "ECDSA public key curve does not match algorithm {}",
                        algorithm.name()
                    )
                    .into());
                }

                Ok(Self::Ecdsa { algorithm })
            }
            SignatureKeyAlgorithm::RsaPss(algorithm) => {
                key.rsa()
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;
                Ok(Self::RsaPss { algorithm })
            }
            SignatureKeyAlgorithm::RsaPkcs1v15(algorithm) => {
                key.rsa()
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;
                Ok(Self::RsaPkcs1v15 { algorithm })
            }
        }
    }

    fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::Ecdsa { algorithm } => SignatureKeyAlgorithm::Ec(*algorithm),
            Self::RsaPss { algorithm } => SignatureKeyAlgorithm::RsaPss(*algorithm),
            Self::RsaPkcs1v15 { algorithm } => SignatureKeyAlgorithm::RsaPkcs1v15(*algorithm),
        }
    }

    fn ensure_signature_algorithm(&self, actual: SignatureKeyAlgorithm) -> Result<()> {
        let expected = self.algorithm();
        if !compatible_key_and_signature(expected, actual) {
            return Err(format!(
                "Signature algorithm {actual:?} does not match key algorithm {expected:?}"
            )
            .into());
        }

        Ok(())
    }

    fn verifier<'key>(
        &self,
        key: &'key PKey<Public>,
        signature_algorithm: SignatureKeyAlgorithm,
    ) -> Result<OpenSslVerifier<'key>> {
        let digest = message_digest(signature_algorithm.digest());
        let mut verifier = OpenSslVerifier::new(digest, key)?;

        if matches!(signature_algorithm, SignatureKeyAlgorithm::RsaPss(_)) {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            verifier.set_rsa_mgf1_md(digest)?;
        } else if matches!(signature_algorithm, SignatureKeyAlgorithm::RsaPkcs1v15(_)) {
            verifier.set_rsa_padding(Padding::PKCS1)?;
        }

        Ok(verifier)
    }

    fn failure_message(&self) -> &'static str {
        match self {
            Self::Ecdsa { algorithm: _ } => "ECDSA signature verification failed",
            Self::RsaPss { algorithm: _ } => "RSA-PSS signature verification failed",
            Self::RsaPkcs1v15 { algorithm: _ } => "RSA PKCS#1 v1.5 signature verification failed",
        }
    }
}

impl Signature {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::Ecdsa { algorithm, .. } => SignatureKeyAlgorithm::Ec(*algorithm),
            Self::RsaPss { algorithm, .. } => SignatureKeyAlgorithm::RsaPss(*algorithm),
            Self::RsaPkcs1v15 { algorithm, .. } => SignatureKeyAlgorithm::RsaPkcs1v15(*algorithm),
        }
    }

    fn as_openssl_bytes(&self) -> &[u8] {
        match self {
            Self::Ecdsa { der, .. } => der,
            Self::RsaPss { raw, .. } => raw,
            Self::RsaPkcs1v15 { raw, .. } => raw,
        }
    }
}

fn ec_component_from_bytes(
    name: &str,
    component: &[u8],
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<BigNum> {
    let max_len = algorithm.scalar_byte_len();
    if component.is_empty() || component.len() > max_len {
        return Err(format!(
            "Invalid ECDSA {} {name} component length: expected 1..={}, got {}",
            algorithm.name(),
            max_len,
            component.len()
        )
        .into());
    }

    Ok(BigNum::from_slice(component)?)
}

fn message_digest(digest: DigestAlgorithm) -> MessageDigest {
    match digest {
        DigestAlgorithm::Sha256 => MessageDigest::sha256(),
        DigestAlgorithm::Sha384 => MessageDigest::sha384(),
        DigestAlgorithm::Sha512 => MessageDigest::sha512(),
    }
}

fn ec_curve_nid(algorithm: EcSignatureKeyAlgorithm) -> Nid {
    match algorithm {
        EcSignatureKeyAlgorithm::P256 => Nid::X9_62_PRIME256V1,
        EcSignatureKeyAlgorithm::P384 => Nid::SECP384R1,
        EcSignatureKeyAlgorithm::P521 => Nid::SECP521R1,
    }
}
