// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Portable pure-Rust cryptographic backend.
//!
//! This backend is selected when `crypto_pure_rust` is enabled and no
//! target-preferred backend is enabled. It uses pure-Rust crates for X.509
//! certificate parsing, certificate-chain signature checks, and SEV-SNP
//! attestation report signature verification.

use p256::ecdsa::{Signature as EcdsaP256Signature, VerifyingKey as EcdsaP256VerifyingKey};
use p384::ecdsa::{Signature as EcdsaP384Signature, VerifyingKey as EcdsaP384VerifyingKey};
use p521::ecdsa::{Signature as EcdsaP521Signature, VerifyingKey as EcdsaP521VerifyingKey};
use rsa::{
    pkcs1v15::{Signature as Pkcs1v15Signature, VerifyingKey as Pkcs1v15VerifyingKey},
    pkcs8::DecodePublicKey,
    pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey},
    RsaPublicKey,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::time::Duration;
#[cfg(not(target_family = "wasm"))]
use std::time::{SystemTime, UNIX_EPOCH};

use super::x509_certificate::{self, Certificate};
use super::x509_policy;
use super::{
    compatible_key_and_signature, CertificateBackend, CryptoBackend, DigestAlgorithm,
    EcSignatureKeyAlgorithm, KeyBackend, Result, RsaPkcs1v15SignatureKeyAlgorithm,
    RsaPssSignatureKeyAlgorithm, SignatureBackend, SignatureKeyAlgorithm,
};

pub struct Crypto;

pub enum Key {
    EcdsaP256(EcdsaP256VerifyingKey),
    EcdsaP384(EcdsaP384VerifyingKey),
    EcdsaP521(EcdsaP521VerifyingKey),
    RsaPss {
        algorithm: RsaPssSignatureKeyAlgorithm,
        key: RsaPublicKey,
    },
    RsaPkcs1v15 {
        algorithm: RsaPkcs1v15SignatureKeyAlgorithm,
        key: RsaPublicKey,
    },
}

pub enum Signature {
    EcdsaP256(EcdsaP256Signature),
    EcdsaP384(EcdsaP384Signature),
    EcdsaP521(EcdsaP521Signature),
    RsaPss {
        algorithm: RsaPssSignatureKeyAlgorithm,
        signature: PssSignature,
    },
    RsaPkcs1v15 {
        algorithm: RsaPkcs1v15SignatureKeyAlgorithm,
        signature: Pkcs1v15Signature,
    },
}

impl SignatureBackend for Signature {
    fn from_bytes(signature: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256) => Ok(Signature::EcdsaP256(
                EcdsaP256Signature::from_der(signature)
                    .map_err(|e| format!("Failed to parse DER ECDSA P-256 signature: {:?}", e))?,
            )),
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384) => Ok(Signature::EcdsaP384(
                EcdsaP384Signature::from_der(signature)
                    .map_err(|e| format!("Failed to parse DER ECDSA P-384 signature: {:?}", e))?,
            )),
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521) => Ok(Signature::EcdsaP521(
                EcdsaP521Signature::from_der(signature)
                    .map_err(|e| format!("Failed to parse DER ECDSA P-521 signature: {:?}", e))?,
            )),
            SignatureKeyAlgorithm::RsaPss(algorithm) => Ok(Signature::RsaPss {
                algorithm,
                signature: PssSignature::try_from(signature)
                    .map_err(|e| format!("Failed to parse RSA-PSS signature: {:?}", e))?,
            }),
            SignatureKeyAlgorithm::RsaPkcs1v15(algorithm) => Ok(Signature::RsaPkcs1v15 {
                algorithm,
                signature: Pkcs1v15Signature::try_from(signature)
                    .map_err(|e| format!("Failed to parse RSA PKCS#1 v1.5 signature: {:?}", e))?,
            }),
        }
    }

    fn from_ec_components(r: &[u8], s: &[u8], algorithm: EcSignatureKeyAlgorithm) -> Result<Self> {
        let expected_len = algorithm.scalar_byte_len();
        if r.len() != expected_len || s.len() != expected_len {
            return Err(format!(
                "Invalid ECDSA {} component length: expected {}, got r={} s={}",
                algorithm.name(),
                expected_len,
                r.len(),
                s.len()
            )
            .into());
        }

        let mut fixed = Vec::with_capacity(algorithm.fixed_signature_byte_len());
        fixed.extend_from_slice(r);
        fixed.extend_from_slice(s);
        match algorithm {
            EcSignatureKeyAlgorithm::P256 => Ok(Signature::EcdsaP256(
                EcdsaP256Signature::from_slice(&fixed).map_err(|e| {
                    format!("Failed to parse fixed-width ECDSA P-256 signature: {:?}", e)
                })?,
            )),
            EcSignatureKeyAlgorithm::P384 => Ok(Signature::EcdsaP384(
                EcdsaP384Signature::from_slice(&fixed).map_err(|e| {
                    format!("Failed to parse fixed-width ECDSA P-384 signature: {:?}", e)
                })?,
            )),
            EcSignatureKeyAlgorithm::P521 => Ok(Signature::EcdsaP521(
                EcdsaP521Signature::from_slice(&fixed).map_err(|e| {
                    format!("Failed to parse fixed-width ECDSA P-521 signature: {:?}", e)
                })?,
            )),
        }
    }
}

impl KeyBackend for Key {
    fn from_spki_der(spki_der: &[u8], algorithm: SignatureKeyAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256) => {
                let key = EcdsaP256VerifyingKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                Ok(Key::EcdsaP256(key))
            }
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384) => {
                let key = EcdsaP384VerifyingKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                Ok(Key::EcdsaP384(key))
            }
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521) => {
                use p521::elliptic_curve::sec1::ToEncodedPoint;

                let public_key = p521::PublicKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                let key =
                    EcdsaP521VerifyingKey::from_encoded_point(&public_key.to_encoded_point(false))
                        .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;
                Ok(Key::EcdsaP521(key))
            }
            SignatureKeyAlgorithm::RsaPss(algorithm) => {
                let rsa_pub = RsaPublicKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;
                Ok(Key::RsaPss {
                    algorithm,
                    key: rsa_pub,
                })
            }
            SignatureKeyAlgorithm::RsaPkcs1v15(algorithm) => {
                let rsa_pub = RsaPublicKey::from_public_key_der(spki_der)
                    .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;
                Ok(Key::RsaPkcs1v15 {
                    algorithm,
                    key: rsa_pub,
                })
            }
        }
    }
}

impl CertificateBackend for Crypto {
    type Certificate = Certificate;

    fn from_pem(pem: &[u8]) -> Result<Self::Certificate> {
        Certificate::from_pem(pem)
    }

    fn from_pem_chain(pem: &[u8]) -> Result<Vec<Self::Certificate>> {
        Certificate::from_pem_chain(pem)
    }

    fn from_der(der: &[u8]) -> Result<Self::Certificate> {
        Certificate::from_der(der)
    }

    fn to_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.to_der()
    }

    fn to_pem(cert: &Self::Certificate) -> Result<String> {
        cert.to_pem()
    }

    fn get_public_key(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.public_key_spki_der()
    }

    fn get_extension_value_by_oid(cert: &Self::Certificate, oid: &str) -> Result<Option<Vec<u8>>> {
        cert.get_extension_value_by_oid(oid)
    }

    fn subject_name(cert: &Self::Certificate) -> String {
        cert.subject_name()
    }

    fn issuer_name(cert: &Self::Certificate) -> String {
        cert.issuer_name()
    }

    fn subject_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.subject_name_der()
    }

    fn issuer_name_der(cert: &Self::Certificate) -> Result<Vec<u8>> {
        cert.issuer_name_der()
    }

    fn is_valid_at(cert: &Self::Certificate, unix_time: std::time::Duration) -> Result<bool> {
        cert.is_valid_at(unix_time)
    }

    fn version(cert: &Self::Certificate) -> Result<u8> {
        Ok(cert.version())
    }

    fn basic_constraints(cert: &Self::Certificate) -> Result<Option<super::BasicConstraints>> {
        cert.basic_constraints()
    }

    fn key_usage(cert: &Self::Certificate) -> Result<Option<super::KeyUsage>> {
        cert.key_usage()
    }

    fn extension_criticality(cert: &Self::Certificate, oid: &str) -> Result<Option<bool>> {
        cert.extension_criticality(oid)
    }

    fn critical_extension_oids(cert: &Self::Certificate) -> Vec<String> {
        cert.critical_extension_oids()
    }
}

impl CryptoBackend for Crypto {
    type Key = Key;
    type Signature = Signature;

    fn digest(algorithm: DigestAlgorithm, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(match algorithm {
            DigestAlgorithm::Sha256 => Sha256::digest(bytes).to_vec(),
            DigestAlgorithm::Sha384 => Sha384::digest(bytes).to_vec(),
            DigestAlgorithm::Sha512 => Sha512::digest(bytes).to_vec(),
        })
    }

    fn verify_signature(
        key: &Self::Key,
        signature: &Self::Signature,
        signed_bytes: &[u8],
    ) -> Result<()> {
        if !compatible_key_and_signature(key.algorithm(), signature.algorithm()) {
            return Err(format!(
                "Signature algorithm {:?} does not match key algorithm {:?}",
                signature.algorithm(),
                key.algorithm()
            )
            .into());
        }

        match (key, signature) {
            (Key::EcdsaP256(key), Signature::EcdsaP256(signature)) => {
                verify_ecdsa_signature(key, signed_bytes, signature, EcSignatureKeyAlgorithm::P256)
            }
            (Key::EcdsaP384(key), Signature::EcdsaP384(signature)) => {
                verify_ecdsa_signature(key, signed_bytes, signature, EcSignatureKeyAlgorithm::P384)
            }
            (Key::EcdsaP521(key), Signature::EcdsaP521(signature)) => {
                verify_ecdsa_signature(key, signed_bytes, signature, EcSignatureKeyAlgorithm::P521)
            }
            (
                Key::RsaPss { key, .. } | Key::RsaPkcs1v15 { key, .. },
                Signature::RsaPss {
                    algorithm,
                    signature,
                },
            ) => match algorithm {
                RsaPssSignatureKeyAlgorithm::Ps256 => verify_rsa_pss_signature(
                    &PssVerifyingKey::<Sha256>::new(key.clone()),
                    signed_bytes,
                    signature,
                ),
                RsaPssSignatureKeyAlgorithm::Ps384 => verify_rsa_pss_signature(
                    &PssVerifyingKey::<Sha384>::new(key.clone()),
                    signed_bytes,
                    signature,
                ),
                RsaPssSignatureKeyAlgorithm::Ps512 => verify_rsa_pss_signature(
                    &PssVerifyingKey::<Sha512>::new(key.clone()),
                    signed_bytes,
                    signature,
                ),
            },
            (
                Key::RsaPss { key, .. } | Key::RsaPkcs1v15 { key, .. },
                Signature::RsaPkcs1v15 {
                    algorithm,
                    signature,
                },
            ) => match algorithm {
                RsaPkcs1v15SignatureKeyAlgorithm::Rs256 => verify_rsa_pkcs1v15_signature(
                    &Pkcs1v15VerifyingKey::<Sha256>::new(key.clone()),
                    signed_bytes,
                    signature,
                ),
                RsaPkcs1v15SignatureKeyAlgorithm::Rs384 => verify_rsa_pkcs1v15_signature(
                    &Pkcs1v15VerifyingKey::<Sha384>::new(key.clone()),
                    signed_bytes,
                    signature,
                ),
                RsaPkcs1v15SignatureKeyAlgorithm::Rs512 => verify_rsa_pkcs1v15_signature(
                    &Pkcs1v15VerifyingKey::<Sha512>::new(key.clone()),
                    signed_bytes,
                    signature,
                ),
            },
            _ => unreachable!("incompatible key and signature algorithms were rejected"),
        }
    }

    fn verify_chain(
        trusted_cert: &Certificate,
        untrusted_chain: &[&Certificate],
        leaf: &Certificate,
        unix_time: Option<Duration>,
    ) -> Result<()> {
        x509_certificate::verify_certificate_path(
            verify_certificate_signature,
            trusted_cert,
            untrusted_chain,
            leaf,
        )?;

        let policy_path = std::iter::once(trusted_cert)
            .chain(untrusted_chain.iter().copied())
            .chain(std::iter::once(leaf));
        x509_policy::rfc5280_policy::<Crypto, _>(policy_path, unix_time.unwrap_or(unix_time_now()?))
    }
}

#[cfg(not(target_family = "wasm"))]
fn unix_time_now() -> Result<Duration> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?)
}

#[cfg(target_family = "wasm")]
fn unix_time_now() -> Result<Duration> {
    let millis = js_sys::Date::now();
    if !millis.is_finite() || millis < 0.0 || millis > u64::MAX as f64 {
        return Err("Failed to read current Unix time from JavaScript Date".into());
    }

    Ok(Duration::from_millis(millis as u64))
}

fn verify_certificate_signature(issuer: &Certificate, subject: &Certificate) -> Result<()> {
    let tbs_bytes = subject.tbs_certificate_der()?;
    let issuer_spki = issuer.public_key_spki_der()?;
    let algorithm = subject.signature_algorithm()?;
    let key = <Key as KeyBackend>::from_spki_der(&issuer_spki, algorithm)?;
    let signature =
        <Signature as SignatureBackend>::from_bytes(subject.signature_bytes(), algorithm)?;

    <Crypto as CryptoBackend>::verify_signature(&key, &signature, &tbs_bytes)
}

impl Key {
    pub fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Key::EcdsaP256(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256),
            Key::EcdsaP384(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384),
            Key::EcdsaP521(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521),
            Key::RsaPss { algorithm, .. } => SignatureKeyAlgorithm::RsaPss(*algorithm),
            Key::RsaPkcs1v15 { algorithm, .. } => SignatureKeyAlgorithm::RsaPkcs1v15(*algorithm),
        }
    }
}

fn verify_ecdsa_signature<K, S>(
    key: &K,
    signed_bytes: &[u8],
    signature: &S,
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<()>
where
    K: ecdsa::signature::Verifier<S>,
{
    ecdsa::signature::Verifier::verify(key, signed_bytes, &signature).map_err(|e| {
        format!(
            "ECDSA {} signature verification failed: {:?}",
            algorithm.name(),
            e
        )
    })?;
    Ok(())
}

fn verify_rsa_pss_signature<D>(
    key: &PssVerifyingKey<D>,
    signed_bytes: &[u8],
    signature: &PssSignature,
) -> Result<()>
where
    D: sha2::Digest,
    PssVerifyingKey<D>: rsa::signature::Verifier<PssSignature>,
{
    use rsa::signature::Verifier;
    key.verify(signed_bytes, signature)
        .map_err(|e| format!("RSA-PSS signature verification failed: {:?}", e))?;
    Ok(())
}

fn verify_rsa_pkcs1v15_signature<D>(
    key: &Pkcs1v15VerifyingKey<D>,
    signed_bytes: &[u8],
    signature: &Pkcs1v15Signature,
) -> Result<()>
where
    D: sha2::Digest,
    Pkcs1v15VerifyingKey<D>: rsa::signature::Verifier<Pkcs1v15Signature>,
{
    use rsa::signature::Verifier;
    key.verify(signed_bytes, signature)
        .map_err(|e| format!("RSA PKCS#1 v1.5 signature verification failed: {:?}", e))?;
    Ok(())
}

impl Signature {
    fn algorithm(&self) -> SignatureKeyAlgorithm {
        match self {
            Self::EcdsaP256(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256),
            Self::EcdsaP384(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384),
            Self::EcdsaP521(_) => SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521),
            Self::RsaPss { algorithm, .. } => SignatureKeyAlgorithm::RsaPss(*algorithm),
            Self::RsaPkcs1v15 { algorithm, .. } => SignatureKeyAlgorithm::RsaPkcs1v15(*algorithm),
        }
    }
}
