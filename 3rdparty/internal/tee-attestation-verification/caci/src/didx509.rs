// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(async_crypto)]
use crypto::AsyncCryptoBackend;
#[cfg(sync_crypto)]
use crypto::CryptoBackend;

use crate::AciError;
use crypto::base64::base64_encode_no_padding;

#[cfg(sync_crypto)]
pub(crate) fn verify_didx509_root(
    trusted_didx509: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
) -> Result<(), AciError> {
    let trusted = parse_didx509_prefix(trusted_didx509)?;
    let issuer = parse_didx509_prefix(issuer)?;
    if issuer.prefix != trusted.prefix {
        return Err(AciError::DidX509(format!(
            "issuer DID prefix {} does not match trusted DID prefix {}",
            issuer.prefix, trusted.prefix
        )));
    }

    let root = x5chain
        .last()
        .ok_or_else(|| AciError::Certificate("x5chain is empty".to_string()))?;
    let actual_fingerprint = sha256_base64(root)?;
    verify_didx509_fingerprint(&trusted, &actual_fingerprint)
}

#[cfg(async_crypto)]
pub(crate) async fn verify_didx509_root_async(
    trusted_didx509: &str,
    issuer: &str,
    x5chain: &[Vec<u8>],
) -> Result<(), AciError> {
    let trusted = parse_didx509_prefix(trusted_didx509)?;
    let issuer = parse_didx509_prefix(issuer)?;
    if issuer.prefix != trusted.prefix {
        return Err(AciError::DidX509(format!(
            "issuer DID prefix {} does not match trusted DID prefix {}",
            issuer.prefix, trusted.prefix
        )));
    }

    let root = x5chain
        .last()
        .ok_or_else(|| AciError::Certificate("x5chain is empty".to_string()))?;
    let actual_fingerprint = sha256_base64_async(root).await?;
    verify_didx509_fingerprint(&trusted, &actual_fingerprint)
}

fn verify_didx509_fingerprint(
    trusted: &ParsedDidX509Prefix<'_>,
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

pub(crate) struct ParsedDidX509Prefix<'a> {
    pub(crate) prefix: &'a str,
    pub(crate) fingerprint: &'a str,
    pub(crate) raw: &'a str,
}

pub(crate) fn parse_didx509_prefix(did: &str) -> Result<ParsedDidX509Prefix<'_>, AciError> {
    let prefix = did.split_once("::").map_or(did, |(prefix, _)| prefix);
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
        return Err(AciError::DidX509(
            "expected did:x509:0:sha256:<fingerprint>".to_string(),
        ));
    }

    let fingerprint =
        fingerprint.ok_or_else(|| AciError::DidX509("missing fingerprint".to_string()))?;
    if fingerprint.is_empty() {
        return Err(AciError::DidX509("empty fingerprint".to_string()));
    }

    Ok(ParsedDidX509Prefix {
        prefix,
        fingerprint,
        raw: did,
    })
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
