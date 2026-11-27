// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(async_crypto)]
use crypto::AsyncCryptoBackend;
#[cfg(sync_crypto)]
use crypto::CryptoBackend;

use crate::AciError;
use crypto::base64::base64_encode_no_padding;
use crypto::CertificateBackend;

#[cfg(sync_crypto)]
pub(crate) fn verify_didx509(
    trusted_didx509: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
) -> Result<(), AciError> {
    let (trusted, root) = verify_issuer_and_eku(trusted_didx509, issuer, x5chain)?;
    verify_didx509_fingerprint(&trusted, &sha256_base64(root)?)
}

#[cfg(async_crypto)]
pub(crate) async fn verify_didx509_async(
    trusted_didx509: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
) -> Result<(), AciError> {
    let (trusted, root) = verify_issuer_and_eku(trusted_didx509, issuer, x5chain)?;
    verify_didx509_fingerprint(&trusted, &sha256_base64_async(root).await?)
}

/// Checks everything except the root fingerprint, whose digest is sync or
/// async depending on the backend. Returns the root certificate to digest.
fn verify_issuer_and_eku<'a>(
    trusted_didx509: &'a str,
    issuer: &str,
    x5chain: &'a [Vec<u8>],
) -> Result<(ParsedDidX509<'a>, &'a [u8]), AciError> {
    let trusted = parse_didx509(trusted_didx509)?;
    if issuer != trusted_didx509 {
        return Err(AciError::DidX509(format!(
            "issuer DID {issuer} does not match trusted DID {trusted_didx509}"
        )));
    }

    let (Some(leaf), Some(root)) = (x5chain.first(), x5chain.last()) else {
        return Err(AciError::Certificate("x5chain is empty".to_string()));
    };
    let leaf = crypto::Crypto::from_der(leaf).map_err(|e| AciError::Certificate(e.to_string()))?;
    let has_eku = crypto::Crypto::extended_key_usage(&leaf)
        .map_err(|e| AciError::Certificate(e.to_string()))?
        .is_some_and(|usages| usages.iter().any(|usage| usage == trusted.eku));
    if !has_eku {
        return Err(AciError::DidX509(format!(
            "x5chain leaf certificate does not have the extended key usage required by trusted DID {trusted_didx509}"
        )));
    }

    Ok((trusted, root))
}

fn verify_didx509_fingerprint(
    trusted: &ParsedDidX509<'_>,
    actual_fingerprint: &str,
) -> Result<(), AciError> {
    if actual_fingerprint != trusted.fingerprint {
        return Err(AciError::DidX509(format!(
            "x5chain root certificate fingerprint does not match trusted DID {}",
            trusted.raw
        )));
    }

    Ok(())
}

pub(crate) struct ParsedDidX509<'a> {
    pub(crate) fingerprint: &'a str,
    pub(crate) eku: &'a str,
    pub(crate) raw: &'a str,
}

/// Only `did:x509:0:sha256:<fingerprint>::eku:<oid>` is supported.
pub(crate) fn parse_didx509(did: &str) -> Result<ParsedDidX509<'_>, AciError> {
    let syntax_error =
        || AciError::DidX509("expected did:x509:0:sha256:<fingerprint>::eku:<oid>".to_string());
    let (prefix, predicate) = did.split_once("::").ok_or_else(syntax_error)?;
    let eku = predicate
        .strip_prefix("eku:")
        .filter(|oid| is_numeric_oid(oid))
        .ok_or_else(syntax_error)?;
    let mut tokens = prefix.split(':');
    let scheme = tokens.next();
    let method = tokens.next();
    let version = tokens.next();
    let hash = tokens.next();
    let fingerprint = tokens.next();
    if tokens.next().is_some()
        || scheme != Some("did")
        || method != Some("x509")
        || version != Some("0")
        || hash != Some("sha256")
    {
        return Err(syntax_error());
    }

    let fingerprint =
        fingerprint.ok_or_else(|| AciError::DidX509("missing fingerprint".to_string()))?;
    if fingerprint.is_empty() {
        return Err(AciError::DidX509("empty fingerprint".to_string()));
    }

    Ok(ParsedDidX509 {
        fingerprint,
        eku,
        raw: did,
    })
}

/// Validates an RFC 4512 section 1.4 `numericoid`:
/// `numericoid = number 1*( "." number )`, `number = DIGIT / ( %x31-39 1*DIGIT )`.
fn is_numeric_oid(oid: &str) -> bool {
    let valid_arc = |arc: &str| {
        matches!(arc.as_bytes(), [b'0'..=b'9'] | [b'1'..=b'9', ..])
            && arc.bytes().all(|b| b.is_ascii_digit())
    };
    let mut arcs = oid.split('.');
    arcs.next().is_some_and(valid_arc) && arcs.next().is_some_and(valid_arc) && arcs.all(valid_arc)
}

#[cfg(sync_crypto)]
pub(crate) fn sha256_base64(bytes: &[u8]) -> Result<String, AciError> {
    let digest = <crypto::Crypto as CryptoBackend>::digest(crypto::DigestAlgorithm::Sha256, bytes)
        .map_err(|e| {
            AciError::DidX509(format!(
                "failed to compute DID x509 SHA-256 fingerprint: {e}"
            ))
        })?;
    Ok(base64_encode_no_padding(&digest))
}

#[cfg(async_crypto)]
async fn sha256_base64_async(bytes: &[u8]) -> Result<String, AciError> {
    let digest =
        <crypto::Crypto as AsyncCryptoBackend>::digest(crypto::DigestAlgorithm::Sha256, bytes)
            .await
            .map_err(|e| {
                AciError::DidX509(format!(
                    "failed to compute DID x509 SHA-256 fingerprint: {e}"
                ))
            })?;
    Ok(base64_encode_no_padding(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_didx509_supports_only_a_single_eku_predicate() {
        let parsed = parse_didx509("did:x509:0:sha256:abc::eku:1.3.6.1").unwrap();
        assert_eq!((parsed.fingerprint, parsed.eku), ("abc", "1.3.6.1"));

        for did in [
            "did:x509:0:sha256:abc",
            "did:x509:0:sha256:abc::eku:",
            "did:x509:0:sha256:abc::eku:1",
            "did:x509:0:sha256:abc::eku:1...5",
            "did:x509:0:sha256:abc::eku:1.3.",
            "did:x509:0:sha256:abc::eku:1.03",
            "did:x509:0:sha256:abc::eku:1.a",
            "did:x509:0:sha256:abc::eku:1.3::eku:1.4",
            "did:x509:0:sha256:abc::subject:CN:x",
            "did:x509:0:sha256:::eku:1.3",
            "did:x509:0:sha384:abc::eku:1.3",
            "did:x509:1:sha256:abc::eku:1.3",
        ] {
            assert!(parse_didx509(did).is_err(), "{did}");
        }
    }
}
