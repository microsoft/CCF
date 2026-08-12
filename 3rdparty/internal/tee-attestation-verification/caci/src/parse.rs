// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::AciError;
use attestation::snp::report::{AttestationReport, TryFromBytes};
use cose::CborValue;
use crypto::CertificateBackend;

// https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64
pub(crate) fn parse_attestation(attestation: &[u8]) -> Result<AttestationReport, AciError> {
    AttestationReport::try_read_from_bytes(attestation)
        .map_err(|e| AciError::InvalidAttestation(format!("{e:?}")))
}

pub(crate) fn cose_payload(sign1: &CborValue) -> Result<Vec<u8>, AciError> {
    required_bstr(sign1.array_at(2).map_err(AciError::Cose)?, "payload")
}

pub(crate) fn parse_x5chain_certs(
    x5chain: &[Vec<u8>],
) -> Result<
    (
        crypto::Certificate,
        Vec<crypto::Certificate>,
        crypto::Certificate,
    ),
    AciError,
> {
    if x5chain.is_empty() {
        return Err(AciError::Certificate(
            "x5chain must contain at least one certificate".to_string(),
        ));
    }

    let leaf =
        crypto::Crypto::from_der(&x5chain[0]).map_err(|e| AciError::Certificate(e.to_string()))?;
    let root = crypto::Crypto::from_der(x5chain.last().unwrap())
        .map_err(|e| AciError::Certificate(e.to_string()))?;
    let intermediate_certs = if x5chain.len() > 1 {
        &x5chain[1..x5chain.len() - 1]
    } else {
        &[]
    };
    let intermediates = intermediate_certs
        .iter()
        .map(|cert| {
            crypto::Crypto::from_der(cert).map_err(|e| AciError::Certificate(e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok((root, intermediates, leaf))
}

pub(crate) mod json {
    use super::*;

    pub(crate) fn required_str<'a>(
        object: &'a serde_json::Value,
        key: &str,
    ) -> Result<&'a str, AciError> {
        object
            .as_object()
            .and_then(|object| object.get(key))
            .and_then(|value| value.as_str())
            .ok_or_else(|| AciError::Measurement(format!("{key} must be a JSON string")))
    }

    pub(crate) fn required_u64(object: &serde_json::Value, key: &str) -> Result<u64, AciError> {
        object
            .as_object()
            .and_then(|object| object.get(key))
            .and_then(|value| value.as_u64())
            .ok_or_else(|| AciError::Measurement(format!("{key} must be a JSON integer")))
    }

    pub(crate) fn required_hex<const N: usize>(
        object: &serde_json::Value,
        key: &str,
    ) -> Result<[u8; N], AciError> {
        let hex = required_str(object, key)?;
        if hex.is_empty()
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AciError::Measurement(format!("{key} must be hex encoded")));
        }
        let bytes = crypto::hex::from_hex(hex).map_err(AciError::Measurement)?;
        bytes
            .try_into()
            .map_err(|_| AciError::Measurement(format!("{key} must be a {N}-byte hex string")))
    }
}

pub(crate) fn parse_certificate(cert: &[u8]) -> Result<crypto::Certificate, AciError> {
    crypto::Crypto::from_pem(cert)
        .or_else(|_| crypto::Crypto::from_der(cert))
        .map_err(|e| AciError::Certificate(e.to_string()))
}

pub(crate) fn parse_signing_time(value: &CborValue) -> Result<std::time::Duration, AciError> {
    match value {
        CborValue::Tagged { tag: 1, payload } => {
            let signing_time = required_int(payload, "signingtime")?
                .try_into()
                .map_err(|_| AciError::Cose("signingtime must be non-negative".to_string()))?;
            Ok(std::time::Duration::from_secs(signing_time))
        }
        _ => Err(AciError::Cose(
            "signingtime must be a CBOR tag 1 epoch timestamp".to_string(),
        )),
    }
}

pub(crate) fn parse_x5chain(value: &CborValue) -> Result<Vec<Vec<u8>>, AciError> {
    match value {
        CborValue::ByteString(cert) => Ok(vec![cert.clone()]),
        CborValue::Array(certs) => {
            if certs.len() < 2 {
                return Err(AciError::Cose(
                    "x5chain array must contain at least two certificates".to_string(),
                ));
            }
            certs
                .iter()
                .map(|value| required_bstr(value, "x5chain certificate"))
                .collect()
        }
        _ => Err(AciError::Cose(
            "x5chain must be a byte string or array of byte strings".to_string(),
        )),
    }
}

pub fn required_bstr(value: &CborValue, name: &str) -> Result<Vec<u8>, AciError> {
    match value {
        CborValue::ByteString(bytes) => Ok(bytes.clone()),
        _ => Err(AciError::Cose(format!("{name} must be a byte string"))),
    }
}

pub fn required_text(value: &CborValue, name: &str) -> Result<String, AciError> {
    match value {
        CborValue::TextString(text) => Ok(text.clone()),
        _ => Err(AciError::Cose(format!("{name} must be a text string"))),
    }
}

pub fn required_int(value: &CborValue, name: &str) -> Result<i64, AciError> {
    match value {
        CborValue::Int(i) => Ok(*i),
        _ => Err(AciError::Cose(format!("{name} must be an integer"))),
    }
}
