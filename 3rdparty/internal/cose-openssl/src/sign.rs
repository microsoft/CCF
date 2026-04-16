use crate::ossl_wrappers::{EvpKey, EvpMdContext, SignOp, ossl_err_string};

use openssl_sys as ossl;
use std::ptr;

pub fn sign(key: &EvpKey, msg: &[u8]) -> Result<Vec<u8>, String> {
    let ctx = EvpMdContext::<SignOp>::new(key)?;
    sign_with_ctx(&ctx, msg)
}

// Only used in tests to sign with an explicit digest that differs from the key's default.
#[cfg(test)]
pub fn sign_with_md(
    key: &EvpKey,
    msg: &[u8],
    md: *const ossl::EVP_MD,
) -> Result<Vec<u8>, String> {
    let ctx = EvpMdContext::<SignOp>::new_with_md(key, md)?;
    sign_with_ctx(&ctx, msg)
}

fn sign_with_ctx(
    ctx: &EvpMdContext<SignOp>,
    msg: &[u8],
) -> Result<Vec<u8>, String> {
    unsafe {
        let mut sig_size: usize = 0;
        let res = ossl::EVP_DigestSign(
            ctx.ctx,
            ptr::null_mut(),
            &mut sig_size,
            msg.as_ptr(),
            msg.len(),
        );
        if res != 1 {
            return Err(format!(
                "EVP_DigestSign (get size) returned {}: {}",
                res,
                ossl_err_string()
            ));
        }

        let mut sig = vec![0u8; sig_size];
        let res = ossl::EVP_DigestSign(
            ctx.ctx,
            sig.as_mut_ptr(),
            &mut sig_size,
            msg.as_ptr(),
            msg.len(),
        );
        if res != 1 {
            return Err(format!(
                "EVP_DigestSign returned {}: {}",
                res,
                ossl_err_string()
            ));
        }

        // Not always fixed size, e.g. for EC keys. More on this here:
        // https://docs.openssl.org/3.0/man3/EVP_DigestSignInit/#description.
        sig.truncate(sig_size);

        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ossl_wrappers::{EvpKey, KeyType, WhichEC, WhichRSA};

    #[test]
    fn sign_ec_succeeds() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let sig = sign(&key, b"hello");
        assert!(sig.is_ok());
        assert!(!sig.unwrap().is_empty());
    }

    #[test]
    fn sign_rsa_succeeds() {
        let key = EvpKey::new(KeyType::RSA(WhichRSA::PS256)).unwrap();
        let sig = sign(&key, b"hello");
        assert!(sig.is_ok());
        assert!(!sig.unwrap().is_empty());
    }

    #[test]
    fn sign_with_public_only_ec_key_fails_with_ossl_detail() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let pub_der = key.to_der_public().unwrap();
        let pub_key = EvpKey::from_der_public(&pub_der).unwrap();
        let err = sign(&pub_key, b"hello").unwrap_err();
        assert!(
            err.starts_with("EVP_DigestSign returned 0: error:"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sign_with_public_only_rsa_key_fails_with_ossl_detail() {
        let key = EvpKey::new(KeyType::RSA(WhichRSA::PS256)).unwrap();
        let pub_der = key.to_der_public().unwrap();
        let pub_key = EvpKey::from_der_public(&pub_der).unwrap();
        let err = sign(&pub_key, b"hello").unwrap_err();
        assert!(
            err.starts_with("EVP_DigestSign returned 0: error:"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sign_context_init_error_propagates() {
        let null_key = EvpKey {
            key: std::ptr::null_mut(),
            typ: KeyType::EC(WhichEC::P256),
        };
        let err = sign(&null_key, b"hello").unwrap_err();
        assert!(
            err.starts_with("EVP_DigestSignInit returned 0: error:"),
            "unexpected error: {err}"
        );
    }
}
