// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::cbor::{serialize_array, CborSlice, CborValue};
#[cfg(async_crypto)]
use crypto::AsyncCryptoBackend;
#[cfg(sync_crypto)]
use crypto::CryptoBackend;
use crypto::{
    compatible_key_and_signature, EcSignatureKeyAlgorithm, RsaPssSignatureKeyAlgorithm,
    SignatureBackend, SignatureKeyAlgorithm,
};

// COSE_Sign1 Sig_structure context string.
// RFC 9052, Section 4.4: https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4
const SIG_STRUCTURE1_CONTEXT: &str = "Signature1";

// RFC 9052, Section 4.2: tagged COSE_Sign1 is CBOR tag 18.
pub const COSE_SIGN1_TAG: u64 = 18;
pub const COSE_SIGN1_PROTECTED: usize = 0;
pub const COSE_SIGN1_UNPROTECTED: usize = 1;
pub const COSE_SIGN1_PAYLOAD: usize = 2;
pub const COSE_SIGN1_SIGNATURE: usize = 3;

// IANA COSE Header Parameters registry
// https://www.iana.org/assignments/cose/cose.xhtml
pub const COSE_HEADER_ALG: i64 = 1;
pub const COSE_HEADER_CWT_CLAIMS: i64 = 15;
pub const COSE_HEADER_X5CHAIN: i64 = 33;
pub const COSE_HEADER_CONTENT_TYPE: i64 = 3;
pub const COSE_HEADER_PREIMAGE_CONTENT_TYPE: i64 = 259;

// IANA CWT Claims registry
// https://www.iana.org/assignments/cwt/cwt.xhtml
pub const CWT_CLAIMS_ISSUER: i64 = 1;
pub const CWT_CLAIMS_SUBJECT: i64 = 2;
pub const CWT_CLAIMS_IAT: i64 = 6;

/// Return the COSE_Sign1 array from a tagged or untagged COSE_Sign1 document.
pub fn cose_sign1(document: &CborValue) -> Result<&CborValue, String> {
    // RFC 9052, Section 4.2: COSE_Sign1 may be encoded as CBOR tag 18
    // wrapping the underlying COSE_Sign1 array or a raw array
    match document {
        CborValue::Tagged { tag, payload } if *tag == COSE_SIGN1_TAG && payload.len()? == 4 => {
            Ok(payload.as_ref())
        }
        CborValue::Array(_) if document.len()? == 4 => Ok(document),
        _ => Err("expected tagged COSE_Sign1 envelope".to_string()),
    }
}

/// Return the backend signature algorithm for a COSE algorithm identifier.
///
/// Supported identifiers are:
///
/// | COSE alg | Algorithm |
/// |---:|---|
/// | `-7` | ES256: ECDSA P-256 / SHA-256 |
/// | `-35` | ES384: ECDSA P-384 / SHA-384 |
/// | `-36` | ES512: ECDSA P-521 / SHA-512 |
/// | `-37` | PS256: RSA-PSS / SHA-256 |
/// | `-38` | PS384: RSA-PSS / SHA-384 |
/// | `-39` | PS512: RSA-PSS / SHA-512 |
///
/// ECDSA algorithm identifiers are from RFC 9053. RSA-PSS algorithm
/// identifiers are from RFC 8230. All are registered in the IANA COSE
/// Algorithms registry:
/// - RFC 9053: https://www.rfc-editor.org/rfc/rfc9053.html
/// - RFC 8230, Section 2: https://www.rfc-editor.org/rfc/rfc8230.html#section-2
/// - IANA: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
///
/// RSA keys are compatible across the RSA-PSS hash variants; the COSE
/// signature algorithm controls the digest and salt length used for
/// verification.
pub fn signature_key_algorithm_for_cose_alg(alg: i64) -> Result<SignatureKeyAlgorithm, String> {
    match alg {
        // ES256. RFC 9053, Section 2.1; IANA COSE Algorithms value -7.
        -7 => Ok(SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256)),
        // ES384. RFC 9053, Section 2.1; IANA COSE Algorithms value -35.
        -35 => Ok(SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384)),
        // ES512. RFC 9053, Section 2.1; IANA COSE Algorithms value -36.
        -36 => Ok(SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521)),
        // PS256. RFC 8230, Section 2; IANA COSE Algorithms value -37.
        -37 => Ok(SignatureKeyAlgorithm::RsaPss(
            RsaPssSignatureKeyAlgorithm::Ps256,
        )),
        // PS384. RFC 8230, Section 2; IANA COSE Algorithms value -38.
        -38 => Ok(SignatureKeyAlgorithm::RsaPss(
            RsaPssSignatureKeyAlgorithm::Ps384,
        )),
        // PS512. RFC 8230, Section 2; IANA COSE Algorithms value -39.
        -39 => Ok(SignatureKeyAlgorithm::RsaPss(
            RsaPssSignatureKeyAlgorithm::Ps512,
        )),
        _ => Err(format!("{alg} is not a supported COSE signature algorithm")),
    }
}

/// Return the COSE algorithm identifier for a backend signature algorithm.
pub fn cose_alg_for_signature_key_algorithm(
    algorithm: SignatureKeyAlgorithm,
) -> Result<i64, String> {
    match algorithm {
        SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256) => Ok(-7),
        SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384) => Ok(-35),
        SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P521) => Ok(-36),
        SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps256) => Ok(-37),
        SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384) => Ok(-38),
        SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps512) => Ok(-39),
        _ => Err(format!(
            "Unsupported signature key algorithm {:?} for COSE",
            algorithm
        )),
    }
}

/// To-be-signed (TBS).
/// https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4.
fn sig_structure(phdr: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    serialize_array(&[
        CborSlice::TextStr(SIG_STRUCTURE1_CONTEXT),
        CborSlice::ByteStr(phdr),
        CborSlice::ByteStr(&[]),
        CborSlice::ByteStr(payload),
    ])
}

/// Verify a COSE_Sign1 signature with the active synchronous crypto backend.
///
/// `phdr` must be the serialized protected-header byte string from the
/// COSE_Sign1 envelope. `payload` is the payload bytes covered by the signature,
/// either from the embedded payload field or supplied by the caller for detached
/// payload use cases. `sig` is the COSE signature byte string.
///
/// The function rebuilds the COSE Sig_structure:
///
/// ```text
/// ["Signature1", phdr, b"", payload]
/// ```
///
/// and verifies `sig` with `key` and `algorithm`. If the protected header
/// contains an `alg`, it must match `algorithm`; if it omits `alg`, the caller's
/// algorithm context is used. Unsupported algorithms, key/algorithm mismatches,
/// malformed signatures, and failed signature verification are returned as
/// errors.
#[cfg(sync_crypto)]
pub fn cose_verify1(
    key: &<crypto::Crypto as CryptoBackend>::Key,
    algorithm: SignatureKeyAlgorithm,
    phdr: &[u8],
    payload: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    validate_protected_header_algorithm(phdr, algorithm)?;
    if !compatible_key_and_signature(key.algorithm(), algorithm) {
        return Err("Algorithm mismatch between supplied alg and key".into());
    }
    let signature = signature_from_cose_bytes(sig, algorithm)?;
    let tbs = sig_structure(phdr, payload)?;

    <crypto::Crypto as CryptoBackend>::verify_signature(key, &signature, &tbs)
        .map_err(|e| e.to_string())
}

/// Verify a COSE_Sign1 signature with the active asynchronous crypto backend.
///
/// This is the async equivalent of [`cose_verify1`]. Use it with backends such
/// as WebCrypto, where signature verification is asynchronous.
#[cfg(async_crypto)]
pub async fn cose_verify1_async(
    key: &<crypto::Crypto as AsyncCryptoBackend>::Key,
    algorithm: SignatureKeyAlgorithm,
    phdr: &[u8],
    payload: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    validate_protected_header_algorithm(phdr, algorithm)?;
    if !compatible_key_and_signature(key.algorithm(), algorithm) {
        return Err("Algorithm mismatch between supplied alg and key".into());
    }
    let signature = signature_from_cose_bytes(sig, algorithm)?;
    let tbs = sig_structure(phdr, payload)?;

    <crypto::Crypto as AsyncCryptoBackend>::verify_signature(key, &signature, &tbs)
        .await
        .map_err(|e| e.to_string())
}

fn validate_protected_header_algorithm(
    phdr: &[u8],
    algorithm: SignatureKeyAlgorithm,
) -> Result<(), String> {
    let expected_alg = cose_alg_for_signature_key_algorithm(algorithm)?;
    if let Some(protected_alg) = protected_header_alg(phdr)? {
        if protected_alg != expected_alg {
            return Err(format!(
                "protected alg {protected_alg} does not match supplied alg {expected_alg}"
            ));
        }
    }
    Ok(())
}

fn protected_header_alg(phdr: &[u8]) -> Result<Option<i64>, String> {
    if phdr.is_empty() {
        return Ok(None);
    }

    let protected = CborValue::from_bytes(phdr)?;
    for (key, value) in protected.iter_map()? {
        if key == &CborValue::Int(COSE_HEADER_ALG) {
            return match value {
                CborValue::Int(alg) => Ok(Some(*alg)),
                _ => Err("protected alg must be an integer".to_string()),
            };
        }
    }
    Ok(None)
}

fn signature_from_cose_bytes(
    sig: &[u8],
    algorithm: SignatureKeyAlgorithm,
) -> Result<crypto::Signature, String> {
    match algorithm {
        SignatureKeyAlgorithm::Ec(algorithm) => {
            let field_size = algorithm.scalar_byte_len();
            if sig.len() != field_size * 2 {
                return Err(format!(
                    "Expected {} byte ECDSA signature, got {}",
                    field_size * 2,
                    sig.len()
                ));
            }

            <crypto::Signature as SignatureBackend>::from_ec_components(
                &sig[..field_size],
                &sig[field_size..],
                algorithm,
            )
            .map_err(|e| e.to_string())
        }
        SignatureKeyAlgorithm::RsaPss(_) => {
            <crypto::Signature as SignatureBackend>::from_bytes(sig, algorithm)
                .map_err(|e| e.to_string())
        }
        _ => Err(format!("Unsupported signature type {:?}", algorithm).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::KeyBackend;

    const PAYLOAD: &[u8] = b"verification-only COSE vector";

    const P256_SPKI: &[u8] = &[
        48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3,
        66, 0, 4, 201, 171, 117, 35, 159, 13, 22, 69, 184, 252, 18, 119, 177, 246, 18, 133, 248,
        151, 60, 164, 201, 112, 233, 4, 224, 54, 241, 53, 11, 85, 3, 249, 180, 113, 248, 87, 244,
        106, 253, 83, 32, 139, 158, 31, 51, 72, 167, 32, 114, 51, 92, 109, 60, 158, 23, 216, 2, 11,
        126, 11, 242, 186, 211, 205,
    ];
    const P256_PHDR: &[u8] = &[161, 1, 38];
    const P256_SIG: &[u8] = &[
        90, 37, 149, 163, 211, 129, 174, 167, 177, 116, 232, 19, 137, 13, 86, 18, 47, 248, 221,
        245, 81, 132, 222, 25, 6, 230, 131, 70, 41, 27, 154, 74, 57, 92, 210, 184, 112, 104, 224,
        64, 234, 0, 184, 153, 253, 249, 148, 125, 58, 93, 103, 128, 147, 144, 252, 13, 252, 91,
        233, 88, 189, 169, 103, 151,
    ];

    const RSA_PSS_SPKI: &[u8] = &[
        48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0,
        48, 130, 1, 10, 2, 130, 1, 1, 0, 175, 27, 158, 101, 168, 58, 209, 97, 4, 179, 2, 172, 30,
        85, 207, 239, 147, 239, 117, 160, 15, 74, 0, 187, 226, 206, 146, 151, 66, 169, 236, 97,
        160, 250, 245, 177, 238, 210, 124, 161, 38, 23, 163, 31, 155, 96, 28, 183, 13, 174, 70,
        185, 134, 2, 253, 106, 66, 185, 3, 127, 53, 97, 56, 27, 90, 15, 118, 188, 167, 23, 128,
        134, 188, 224, 207, 205, 17, 17, 148, 146, 178, 88, 11, 114, 126, 183, 104, 193, 215, 7,
        71, 182, 91, 118, 174, 220, 146, 94, 123, 11, 197, 3, 25, 104, 111, 55, 9, 48, 142, 67, 34,
        246, 127, 220, 194, 47, 15, 0, 44, 137, 39, 185, 22, 216, 112, 44, 226, 164, 58, 130, 119,
        175, 191, 210, 224, 159, 62, 74, 21, 115, 184, 24, 248, 123, 151, 112, 221, 0, 85, 57, 82,
        158, 56, 239, 0, 34, 184, 233, 153, 40, 250, 194, 114, 76, 210, 193, 124, 70, 108, 48, 128,
        99, 231, 12, 9, 1, 203, 39, 69, 223, 206, 118, 24, 252, 141, 173, 86, 140, 127, 73, 192,
        115, 93, 141, 222, 251, 189, 58, 179, 37, 214, 126, 250, 129, 16, 5, 182, 118, 69, 77, 148,
        154, 201, 225, 227, 26, 171, 172, 110, 196, 16, 104, 254, 18, 188, 68, 39, 126, 212, 133,
        39, 151, 236, 217, 183, 36, 127, 133, 46, 223, 36, 67, 243, 223, 28, 140, 48, 12, 181, 139,
        149, 2, 123, 87, 198, 151, 2, 3, 1, 0, 1,
    ];
    const RSA_PSS_PHDR: &[u8] = &[161, 1, 56, 36];
    const RSA_PSS_SIG: &[u8] = &[
        120, 140, 34, 185, 178, 240, 162, 3, 67, 154, 48, 48, 123, 75, 49, 28, 172, 121, 157, 121,
        60, 52, 179, 5, 70, 143, 108, 198, 170, 32, 22, 182, 48, 38, 77, 207, 86, 34, 184, 15, 147,
        104, 157, 234, 38, 10, 253, 236, 187, 4, 158, 154, 98, 122, 90, 122, 50, 93, 214, 143, 55,
        171, 26, 109, 250, 150, 130, 37, 200, 235, 161, 196, 153, 220, 39, 167, 110, 69, 208, 139,
        191, 201, 229, 116, 38, 129, 229, 249, 132, 55, 156, 249, 118, 192, 247, 241, 134, 93, 156,
        125, 174, 116, 96, 194, 187, 10, 75, 133, 45, 44, 213, 187, 55, 193, 165, 89, 121, 116,
        186, 8, 14, 72, 23, 154, 69, 64, 206, 169, 225, 8, 203, 26, 173, 213, 162, 182, 87, 172,
        106, 136, 40, 220, 241, 190, 135, 79, 31, 105, 31, 18, 38, 50, 14, 246, 35, 185, 161, 35,
        43, 113, 207, 153, 106, 40, 75, 193, 177, 122, 82, 93, 246, 137, 248, 247, 218, 154, 221,
        119, 84, 142, 153, 154, 3, 184, 188, 10, 87, 228, 228, 52, 16, 107, 94, 251, 223, 179, 253,
        250, 204, 125, 230, 218, 34, 86, 183, 110, 161, 159, 89, 214, 251, 1, 159, 231, 231, 95,
        230, 13, 22, 185, 239, 209, 151, 109, 19, 149, 212, 207, 169, 80, 167, 108, 239, 161, 216,
        168, 172, 208, 150, 38, 14, 34, 76, 203, 219, 160, 78, 11, 108, 193, 8, 109, 89, 223, 228,
        73,
    ];

    #[test]
    fn cose_sign1_accepts_tagged_and_untagged_sign1_arrays() {
        let sign1 = CborValue::Array(vec![
            CborValue::ByteString(vec![]),
            CborValue::Map(vec![]),
            CborValue::ByteString(vec![]),
            CborValue::ByteString(vec![]),
        ]);
        let tagged = CborValue::Tagged {
            tag: 18,
            payload: Box::new(sign1.clone()),
        };

        assert_eq!(cose_sign1(&sign1).unwrap(), &sign1);
        assert_eq!(cose_sign1(&tagged).unwrap(), &sign1);
    }

    #[test]
    fn cose_sign1_rejects_non_sign1_documents() {
        assert_eq!(
            cose_sign1(&CborValue::Int(1)).unwrap_err(),
            "expected tagged COSE_Sign1 envelope"
        );
        assert_eq!(
            cose_sign1(&CborValue::Tagged {
                tag: 17,
                payload: Box::new(CborValue::Array(vec![])),
            })
            .unwrap_err(),
            "expected tagged COSE_Sign1 envelope"
        );
    }

    #[test]
    fn cose_sign1_requires_four_fields() {
        let valid = CborValue::Array(vec![
            CborValue::ByteString(vec![]),
            CborValue::Map(vec![]),
            CborValue::ByteString(vec![]),
            CborValue::ByteString(vec![]),
        ]);
        let invalid = CborValue::Array(vec![CborValue::ByteString(vec![])]);

        cose_sign1(&valid).unwrap();
        assert_eq!(
            cose_sign1(&invalid).unwrap_err(),
            "expected tagged COSE_Sign1 envelope"
        );
    }

    fn key(
        spki: &[u8],
        algorithm: SignatureKeyAlgorithm,
    ) -> <crypto::Crypto as CryptoBackend>::Key {
        <<crypto::Crypto as CryptoBackend>::Key as KeyBackend>::from_spki_der(spki, algorithm)
            .unwrap()
    }

    #[test]
    #[cfg(sync_crypto)]
    fn cose_verify1_ec_p256_vector() {
        let algorithm = SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256);
        let key = key(P256_SPKI, algorithm);

        cose_verify1(&key, algorithm, P256_PHDR, PAYLOAD, P256_SIG).unwrap();
    }

    #[test]
    #[cfg(sync_crypto)]
    fn cose_verify1_rsa_ps256_vector() {
        let algorithm = SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps256);
        let key = key(RSA_PSS_SPKI, algorithm);

        cose_verify1(&key, algorithm, RSA_PSS_PHDR, PAYLOAD, RSA_PSS_SIG).unwrap();
    }

    #[test]
    #[cfg(sync_crypto)]
    fn cose_verify1_rsa_key_imported_with_different_pss_algorithm() {
        let key_algorithm = SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384);
        let key = key(RSA_PSS_SPKI, key_algorithm);
        let signature_algorithm = SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps256);

        cose_verify1(
            &key,
            signature_algorithm,
            RSA_PSS_PHDR,
            PAYLOAD,
            RSA_PSS_SIG,
        )
        .unwrap();
    }

    #[test]
    #[cfg(sync_crypto)]
    fn cose_verify1_wrong_message_returns_error() {
        let algorithm = SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256);
        let key = key(P256_SPKI, algorithm);

        let err = cose_verify1(&key, algorithm, P256_PHDR, b"wrong", P256_SIG).unwrap_err();
        assert!(
            err.contains("signature verification failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(sync_crypto)]
    fn cose_verify1_wrong_alg() {
        let algorithm = SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256);
        let key = key(P256_SPKI, algorithm);

        assert_eq!(
            cose_verify1(&key, algorithm, RSA_PSS_PHDR, b"", b"").unwrap_err(),
            "protected alg -37 does not match supplied alg -7"
        );
    }

    #[test]
    #[cfg(sync_crypto)]
    fn cose_verify1_rejects_invalid_protected_header_cbor() {
        let algorithm = SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256);
        let key = key(P256_SPKI, algorithm);

        assert_eq!(
            cose_verify1(&key, algorithm, &[0xff], b"", b"").unwrap_err(),
            "Failed to parse CBOR bytes"
        );
    }

    #[test]
    #[cfg(sync_crypto)]
    fn cose_verify1_rejects_non_map_protected_header() {
        let algorithm = SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256);
        let key = key(P256_SPKI, algorithm);

        assert_eq!(
            cose_verify1(&key, algorithm, &[0x80], b"", b"").unwrap_err(),
            "Expected Map, got \"Array\""
        );
    }

    #[test]
    #[cfg(sync_crypto)]
    fn cose_verify1_allows_missing_protected_alg() {
        let algorithm = SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256);
        let key = key(P256_SPKI, algorithm);

        let err = cose_verify1(&key, algorithm, &[0xa0], PAYLOAD, P256_SIG).unwrap_err();
        assert!(
            err.contains("signature verification failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(sync_crypto)]
    fn cose_verify1_allows_empty_protected_header() {
        let algorithm = SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256);
        let key = key(P256_SPKI, algorithm);

        let err = cose_verify1(&key, algorithm, &[], PAYLOAD, P256_SIG).unwrap_err();
        assert!(
            err.contains("signature verification failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[cfg(sync_crypto)]
    fn cose_verify1_rejects_non_integer_protected_alg() {
        let algorithm = SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256);
        let key = key(P256_SPKI, algorithm);

        assert_eq!(
            cose_verify1(&key, algorithm, &[0xa1, 0x01, 0x40], b"", b"").unwrap_err(),
            "protected alg must be an integer"
        );
    }

    #[test]
    #[cfg(sync_crypto)]
    fn cose_verify1_ec_sig_wrong_length() {
        let algorithm = SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256);
        let key = key(P256_SPKI, algorithm);

        assert_eq!(
            cose_verify1(&key, algorithm, P256_PHDR, b"", &[0u8; 3]).unwrap_err(),
            "Expected 64 byte ECDSA signature, got 3"
        );
    }
}
