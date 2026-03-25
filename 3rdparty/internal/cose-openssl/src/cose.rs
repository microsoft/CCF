use crate::cbor::{CborSlice, CborValue, serialize_array};
use crate::ossl_wrappers::{
    EvpKey, KeyType, WhichEC, WhichRSA, ecdsa_der_to_fixed, ecdsa_fixed_to_der,
    rsa_pss_md_for_cose_alg,
};

#[cfg(feature = "pqc")]
use crate::ossl_wrappers::WhichMLDSA;

const COSE_SIGN1_TAG: u64 = 18;
const COSE_HEADER_ALG: i64 = 1;
const SIG_STRUCTURE1_CONTEXT: &str = "Signature1";
const CBOR_SIMPLE_VALUE_NULL: u8 = 22;

/// Return the COSE algorithm identifier for a given key.
/// https://www.iana.org/assignments/cose/cose.xhtml
fn cose_alg(key: &EvpKey) -> Result<i64, String> {
    match &key.typ {
        KeyType::EC(WhichEC::P256) => Ok(-7),
        KeyType::EC(WhichEC::P384) => Ok(-35),
        KeyType::EC(WhichEC::P521) => Ok(-36),
        KeyType::RSA(WhichRSA::PS256) => Ok(-37),
        KeyType::RSA(WhichRSA::PS384) => Ok(-38),
        KeyType::RSA(WhichRSA::PS512) => Ok(-39),
        #[cfg(feature = "pqc")]
        KeyType::MLDSA(which) => match which {
            WhichMLDSA::P44 => Ok(-48),
            WhichMLDSA::P65 => Ok(-49),
            WhichMLDSA::P87 => Ok(-50),
        },
    }
}

/// Insert alg(1) into a CborValue map, return error if already exists.
fn insert_alg_value(
    key: &EvpKey,
    phdr: CborValue,
) -> Result<CborValue, String> {
    let mut entries = match phdr {
        CborValue::Map(entries) => entries,
        _ => {
            return Err("Protected header is not a CBOR map".to_string());
        }
    };

    let alg_key = CborValue::Int(COSE_HEADER_ALG);
    if entries.iter().any(|(k, _)| k == &alg_key) {
        return Err("Algorithm already set in protected header".to_string());
    }

    let alg_val = CborValue::Int(cose_alg(key)?);
    entries.insert(0, (alg_key, alg_val));

    Ok(CborValue::Map(entries))
}

/// To-be-signed (TBS).
/// https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4.
///
/// Uses `serialize_array` with borrowed slices to avoid copying
/// `phdr` and `payload` into intermediate `Vec<u8>`s. These can
/// be large (payload especially), so we serialize directly from
/// the caller's buffers.
fn sig_structure(phdr: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    serialize_array(&[
        CborSlice::TextStr(SIG_STRUCTURE1_CONTEXT),
        CborSlice::ByteStr(phdr),
        CborSlice::ByteStr(&[]),
        CborSlice::ByteStr(payload),
    ])
}

/// Produce a COSE_Sign1 envelope.
pub fn cose_sign1(
    key: &EvpKey,
    phdr: CborValue,
    uhdr: CborValue,
    payload: &[u8],
    detached: bool,
) -> Result<Vec<u8>, String> {
    let phdr_with_alg = insert_alg_value(key, phdr)?;
    let phdr_bytes = phdr_with_alg.to_bytes()?;
    let tbs = sig_structure(&phdr_bytes, payload)?;
    let sig = crate::sign::sign(key, &tbs)?;

    let sig = match &key.typ {
        KeyType::EC(_) => ecdsa_der_to_fixed(&sig, key.ec_field_size()?)?,
        KeyType::RSA(_) => sig,
        #[cfg(feature = "pqc")]
        KeyType::MLDSA(_) => sig,
    };

    let payload_item = if detached {
        CborValue::Simple(CBOR_SIMPLE_VALUE_NULL)
    } else {
        CborValue::ByteString(payload.to_vec())
    };

    let envelope = CborValue::Tagged {
        tag: COSE_SIGN1_TAG,
        payload: Box::new(CborValue::Array(vec![
            CborValue::ByteString(phdr_bytes),
            uhdr,
            payload_item,
            CborValue::ByteString(sig),
        ])),
    };

    envelope.to_bytes()
}

/// Verify a COSE_Sign1 from pre-parsed components. The caller supplies
/// the serialized protected header, payload, fixed-size signature (all
/// as byte slices), and the COSE algorithm integer (e.g. -7 for ES256).
pub fn cose_verify1(
    key: &EvpKey,
    alg: i64,
    phdr: &[u8],
    payload: &[u8],
    sig: &[u8],
) -> Result<bool, String> {
    match &key.typ {
        KeyType::RSA(_) => {
            // For RSA, accept any PS* algorithm regardless of key size.
            rsa_pss_md_for_cose_alg(alg)?;
        }
        _ => {
            let expected_alg = cose_alg(key)?;
            if alg != expected_alg {
                return Err(
                    "Algorithm mismatch between supplied alg and key".into()
                );
            }
        }
    }

    let sig = match &key.typ {
        KeyType::EC(_) => ecdsa_fixed_to_der(sig, key.ec_field_size()?)?,
        KeyType::RSA(_) => sig.to_vec(),
        #[cfg(feature = "pqc")]
        KeyType::MLDSA(_) => sig.to_vec(),
    };

    let tbs = sig_structure(phdr, payload)?;

    match &key.typ {
        KeyType::RSA(_) => {
            let md = rsa_pss_md_for_cose_alg(alg)?;
            crate::verify::verify_with_md(key, &sig, &tbs, md)
        }
        _ => crate::verify::verify(key, &sig, &tbs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd-length hex string");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const TEST_PHDR: &str = "A319018B020FA3061A698B72820173736572766963652E6578616D706C652E636F6D02706C65646765722E7369676E6174757265666363662E7631A1647478696465322E313334";

    /// Helper: sign then verify via the new APIs.
    fn sign_and_verify(key_type: KeyType) {
        let key = EvpKey::new(key_type).unwrap();
        let phdr_bytes = hex_decode(TEST_PHDR);
        let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
        let uhdr = CborValue::Map(vec![]);
        let payload = b"Good boy...";

        let envelope = cose_sign1(&key, phdr, uhdr, payload, false).unwrap();

        // Parse envelope to extract raw components for cose_verify1.
        let parsed = CborValue::from_bytes(&envelope).unwrap();
        let inner = match parsed {
            CborValue::Tagged { payload, .. } => *payload,
            _ => panic!("not tagged"),
        };
        let items = match inner {
            CborValue::Array(v) => v,
            _ => panic!("not array"),
        };
        let phdr_raw = match &items[0] {
            CborValue::ByteString(b) => b.clone(),
            _ => panic!("phdr not bstr"),
        };
        let sig_raw = match &items[3] {
            CborValue::ByteString(b) => b.clone(),
            _ => panic!("sig not bstr"),
        };

        let alg = cose_alg(&key).unwrap();
        assert!(cose_verify1(&key, alg, &phdr_raw, payload, &sig_raw).unwrap());
    }

    #[test]
    fn test_insert_alg() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let phdr_bytes = hex_decode(TEST_PHDR);
        let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
        let phdr_with_alg = insert_alg_value(&key, phdr).unwrap();

        let alg = phdr_with_alg.map_at_int(COSE_HEADER_ALG).unwrap();
        assert_eq!(alg, &CborValue::Int(cose_alg(&key).unwrap()));

        assert_eq!(
            insert_alg_value(&key, phdr_with_alg).unwrap_err(),
            "Algorithm already set in protected header"
        );
    }

    #[test]
    fn cose_ec_p256() {
        sign_and_verify(KeyType::EC(WhichEC::P256));
    }

    #[test]
    fn cose_ec_p384() {
        sign_and_verify(KeyType::EC(WhichEC::P384));
    }

    #[test]
    fn cose_ec_p521() {
        sign_and_verify(KeyType::EC(WhichEC::P521));
    }

    #[test]
    fn cose_detached_payload() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let phdr_bytes = hex_decode(TEST_PHDR);
        let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
        let uhdr = CborValue::Map(vec![]);
        let payload = b"Good boy...";

        let envelope = cose_sign1(&key, phdr, uhdr, payload, true).unwrap();

        let parsed = CborValue::from_bytes(&envelope).unwrap();
        let inner = match parsed {
            CborValue::Tagged { payload, .. } => *payload,
            _ => panic!("not tagged"),
        };
        let items = match inner {
            CborValue::Array(v) => v,
            _ => panic!("not array"),
        };
        let phdr_raw = match &items[0] {
            CborValue::ByteString(b) => b.clone(),
            _ => panic!("phdr not bstr"),
        };
        let sig_raw = match &items[3] {
            CborValue::ByteString(b) => b.clone(),
            _ => panic!("sig not bstr"),
        };

        assert_eq!(items[2], CborValue::Simple(CBOR_SIMPLE_VALUE_NULL));

        let alg = cose_alg(&key).unwrap();
        assert!(cose_verify1(&key, alg, &phdr_raw, payload, &sig_raw).unwrap());
    }

    #[test]
    fn cose_verify1_wrong_alg() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        assert_eq!(
            cose_verify1(&key, -35, b"", b"", b"").unwrap_err(),
            "Algorithm mismatch between supplied alg and key"
        );
    }

    #[test]
    fn cose_with_der_imported_key() {
        let original_key = EvpKey::new(KeyType::EC(WhichEC::P384)).unwrap();

        let priv_der = original_key.to_der_private().unwrap();
        let signing_key = EvpKey::from_der_private(&priv_der).unwrap();

        let pub_der = original_key.to_der_public().unwrap();
        let verification_key = EvpKey::from_der_public(&pub_der).unwrap();

        let phdr_bytes = hex_decode(TEST_PHDR);
        let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
        let uhdr = CborValue::Map(vec![]);
        let payload = b"test with DER-imported key";

        let envelope =
            cose_sign1(&signing_key, phdr, uhdr, payload, false).unwrap();

        let parsed = CborValue::from_bytes(&envelope).unwrap();
        let inner = match parsed {
            CborValue::Tagged { payload, .. } => *payload,
            _ => panic!("not tagged"),
        };
        let items = match inner {
            CborValue::Array(v) => v,
            _ => panic!("not array"),
        };
        let phdr_raw = match &items[0] {
            CborValue::ByteString(b) => b.clone(),
            _ => panic!("phdr not bstr"),
        };
        let sig_raw = match &items[3] {
            CborValue::ByteString(b) => b.clone(),
            _ => panic!("sig not bstr"),
        };

        let alg = cose_alg(&verification_key).unwrap();
        assert!(
            cose_verify1(&verification_key, alg, &phdr_raw, payload, &sig_raw)
                .unwrap()
        );
    }

    #[test]
    fn cose_rsa_ps256() {
        sign_and_verify(KeyType::RSA(WhichRSA::PS256));
    }

    #[test]
    fn cose_rsa_ps384() {
        sign_and_verify(KeyType::RSA(WhichRSA::PS384));
    }

    #[test]
    fn cose_rsa_ps512() {
        sign_and_verify(KeyType::RSA(WhichRSA::PS512));
    }

    #[test]
    fn cose_rsa_with_der_imported_key() {
        let original_key = EvpKey::new(KeyType::RSA(WhichRSA::PS256)).unwrap();

        let priv_der = original_key.to_der_private().unwrap();
        let signing_key = EvpKey::from_der_private(&priv_der).unwrap();

        let pub_der = original_key.to_der_public().unwrap();
        let verification_key = EvpKey::from_der_public(&pub_der).unwrap();

        let phdr_bytes = hex_decode(TEST_PHDR);
        let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
        let uhdr = CborValue::Map(vec![]);
        let payload = b"RSA with DER-imported key";

        let envelope =
            cose_sign1(&signing_key, phdr, uhdr, payload, false).unwrap();

        let parsed = CborValue::from_bytes(&envelope).unwrap();
        let inner = match parsed {
            CborValue::Tagged { payload, .. } => *payload,
            _ => panic!("not tagged"),
        };
        let items = match inner {
            CborValue::Array(v) => v,
            _ => panic!("not array"),
        };
        let phdr_raw = match &items[0] {
            CborValue::ByteString(b) => b.clone(),
            _ => panic!("phdr not bstr"),
        };
        let sig_raw = match &items[3] {
            CborValue::ByteString(b) => b.clone(),
            _ => panic!("sig not bstr"),
        };

        let alg = cose_alg(&verification_key).unwrap();
        assert!(
            cose_verify1(&verification_key, alg, &phdr_raw, payload, &sig_raw)
                .unwrap()
        );
    }

    #[test]
    fn cose_rsa_detached_payload() {
        let key = EvpKey::new(KeyType::RSA(WhichRSA::PS384)).unwrap();
        let phdr_bytes = hex_decode(TEST_PHDR);
        let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
        let uhdr = CborValue::Map(vec![]);
        let payload = b"RSA detached";

        let envelope = cose_sign1(&key, phdr, uhdr, payload, true).unwrap();

        let parsed = CborValue::from_bytes(&envelope).unwrap();
        let inner = match parsed {
            CborValue::Tagged { payload, .. } => *payload,
            _ => panic!("not tagged"),
        };
        let items = match inner {
            CborValue::Array(v) => v,
            _ => panic!("not array"),
        };
        let phdr_raw = match &items[0] {
            CborValue::ByteString(b) => b.clone(),
            _ => panic!("phdr not bstr"),
        };
        let sig_raw = match &items[3] {
            CborValue::ByteString(b) => b.clone(),
            _ => panic!("sig not bstr"),
        };

        let alg = cose_alg(&key).unwrap();
        assert!(cose_verify1(&key, alg, &phdr_raw, payload, &sig_raw).unwrap());
    }

    /// Sign with a PS256 key (2048-bit RSA) but use SHA-384 (PS384
    /// algorithm). Verify must succeed because the header's algorithm
    /// drives the digest, not the key's WhichRSA variant.
    #[test]
    fn cose_rsa_ps256_key_with_sha384() {
        use crate::ossl_wrappers::rsa_pss_md_for_cose_alg;

        let key = EvpKey::new(KeyType::RSA(WhichRSA::PS256)).unwrap();
        let payload = b"PS256 key, SHA-384 digest";

        // Build phdr with alg = -38 (PS384) already set.
        let phdr_bytes = hex_decode(TEST_PHDR);
        let mut phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
        if let CborValue::Map(ref mut entries) = phdr {
            entries.insert(
                0,
                (CborValue::Int(COSE_HEADER_ALG), CborValue::Int(-38)),
            );
        }
        let phdr_ser = phdr.to_bytes().unwrap();

        // Build TBS and sign with SHA-384.
        let tbs = sig_structure(&phdr_ser, payload).unwrap();
        let md = rsa_pss_md_for_cose_alg(-38).unwrap();
        let sig = crate::sign::sign_with_md(&key, &tbs, md).unwrap();

        // Verify with PS384 alg.
        assert!(cose_verify1(&key, -38, &phdr_ser, payload, &sig).unwrap());
    }

    /// Verify that a &[u8] payload is stored directly in the envelope
    /// bstr without double-encoding as bstr(bstr(...)).
    #[test]
    fn cose_sign1_no_double_encoding() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let phdr_bytes = hex_decode(TEST_PHDR);
        let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
        let uhdr = CborValue::Map(vec![]);
        let payload = b"test payload";

        let envelope = cose_sign1(&key, phdr, uhdr, payload, false).unwrap();

        let parsed = CborValue::from_bytes(&envelope).unwrap();
        let inner = match parsed {
            CborValue::Tagged { payload, .. } => *payload,
            _ => panic!("not tagged"),
        };
        let items = match inner {
            CborValue::Array(v) => v,
            _ => panic!("not array"),
        };
        let payload_in_envelope = match &items[2] {
            CborValue::ByteString(b) => b.clone(),
            _ => panic!("payload not bstr"),
        };
        // The envelope payload must equal the raw data, not a
        // CBOR-encoded bstr wrapping it.
        assert_eq!(
            payload_in_envelope,
            payload.to_vec(),
            "payload double-encoded as bstr(bstr(...))"
        );
    }

    // ---------------------------------------------------------------
    // Negative tests: error propagation through cose_sign1/cose_verify1
    // ---------------------------------------------------------------

    #[test]
    fn cose_sign1_rejects_non_map_phdr() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        assert_eq!(
            cose_sign1(
                &key,
                CborValue::Int(0),
                CborValue::Map(vec![]),
                b"msg",
                false
            )
            .unwrap_err(),
            "Protected header is not a CBOR map"
        );
    }

    #[test]
    fn cose_sign1_rejects_duplicate_alg() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let phdr = CborValue::Map(vec![(
            CborValue::Int(COSE_HEADER_ALG),
            CborValue::Int(-7),
        )]);
        assert_eq!(
            cose_sign1(&key, phdr, CborValue::Map(vec![]), b"msg", false)
                .unwrap_err(),
            "Algorithm already set in protected header"
        );
    }

    #[test]
    fn cose_sign1_propagates_ossl_sign_error() {
        // Null key triggers EVP_DigestSignInit failure.
        let null_key = EvpKey {
            key: std::ptr::null_mut(),
            typ: KeyType::EC(WhichEC::P256),
        };
        let err = cose_sign1(
            &null_key,
            CborValue::Map(vec![]),
            CborValue::Map(vec![]),
            b"msg",
            false,
        )
        .unwrap_err();
        assert!(
            err.starts_with("EVP_DigestSignInit returned 0: error:"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cose_verify1_wrong_rsa_alg() {
        let key = EvpKey::new(KeyType::RSA(WhichRSA::PS256)).unwrap();
        assert_eq!(
            cose_verify1(&key, -7, b"", b"", b"").unwrap_err(),
            "-7 is not a COSE RSA-PSS algorithm"
        );
    }

    #[test]
    fn cose_verify1_ec_sig_wrong_length() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let pub_der = key.to_der_public().unwrap();
        let pub_key = EvpKey::from_der_public(&pub_der).unwrap();
        // P-256 expects 64 byte fixed sig, pass 3 bytes.
        assert_eq!(
            cose_verify1(&pub_key, -7, b"", b"", &[0u8; 3]).unwrap_err(),
            "Expected 64 byte ECDSA signature, got 3"
        );
    }

    #[test]
    fn cose_verify1_propagates_ossl_verify_error() {
        // Null key triggers EVP_DigestVerifyInit failure.
        let null_key = EvpKey {
            key: std::ptr::null_mut(),
            typ: KeyType::RSA(WhichRSA::PS256),
        };
        let err =
            cose_verify1(&null_key, -37, b"", b"", &[0u8; 256]).unwrap_err();
        assert!(
            err.starts_with("EVP_DigestVerifyInit returned 0: error:"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "pqc")]
    mod pqc_tests {
        use super::*;
        #[test]
        fn cose_mldsa44() {
            sign_and_verify(KeyType::MLDSA(WhichMLDSA::P44));
        }
        #[test]
        fn cose_mldsa65() {
            sign_and_verify(KeyType::MLDSA(WhichMLDSA::P65));
        }
        #[test]
        fn cose_mldsa87() {
            sign_and_verify(KeyType::MLDSA(WhichMLDSA::P87));
        }

        #[test]
        fn cose_mldsa_with_der_imported_key() {
            let original_key =
                EvpKey::new(KeyType::MLDSA(WhichMLDSA::P65)).unwrap();

            let priv_der = original_key.to_der_private().unwrap();
            let signing_key = EvpKey::from_der_private(&priv_der).unwrap();

            let pub_der = original_key.to_der_public().unwrap();
            let verification_key = EvpKey::from_der_public(&pub_der).unwrap();

            let phdr_bytes = hex_decode(TEST_PHDR);
            let phdr = CborValue::from_bytes(&phdr_bytes).unwrap();
            let uhdr = CborValue::Map(vec![]);
            let payload = b"ML-DSA with DER-imported key";

            let envelope =
                cose_sign1(&signing_key, phdr, uhdr, payload, false).unwrap();

            let parsed = CborValue::from_bytes(&envelope).unwrap();
            let inner = match parsed {
                CborValue::Tagged { payload, .. } => *payload,
                _ => panic!("not tagged"),
            };
            let items = match inner {
                CborValue::Array(v) => v,
                _ => panic!("not array"),
            };
            let phdr_raw = match &items[0] {
                CborValue::ByteString(b) => b.clone(),
                _ => panic!("phdr not bstr"),
            };
            let sig_raw = match &items[3] {
                CborValue::ByteString(b) => b.clone(),
                _ => panic!("sig not bstr"),
            };

            let alg = cose_alg(&verification_key).unwrap();
            assert!(
                cose_verify1(
                    &verification_key,
                    alg,
                    &phdr_raw,
                    payload,
                    &sig_raw
                )
                .unwrap()
            );
        }
    }
}
