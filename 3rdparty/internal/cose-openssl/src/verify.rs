use crate::ossl_wrappers::{EvpKey, EvpMdContext, VerifyOp, ossl_err_string};

use openssl_sys as ossl;

pub fn verify(key: &EvpKey, sig: &[u8], msg: &[u8]) -> Result<bool, String> {
    let ctx = EvpMdContext::<VerifyOp>::new(key)?;
    verify_with_ctx(&ctx, sig, msg)
}

pub fn verify_with_md(
    key: &EvpKey,
    sig: &[u8],
    msg: &[u8],
    md: *const ossl::EVP_MD,
) -> Result<bool, String> {
    let ctx = EvpMdContext::<VerifyOp>::new_with_md(key, md)?;
    verify_with_ctx(&ctx, sig, msg)
}

fn verify_with_ctx(
    ctx: &EvpMdContext<VerifyOp>,
    sig: &[u8],
    msg: &[u8],
) -> Result<bool, String> {
    unsafe {
        let res = ossl::EVP_DigestVerify(
            ctx.ctx,
            sig.as_ptr(),
            sig.len(),
            msg.as_ptr(),
            msg.len(),
        );

        match res {
            1 => Ok(true),
            0 => Ok(false),
            err => Err(format!(
                "EVP_DigestVerify returned {}: {}",
                err,
                ossl_err_string()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ossl_wrappers::{EvpKey, KeyType, WhichEC, WhichRSA};
    use crate::sign;

    #[test]
    fn verify_ec_valid_signature() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let msg = b"test message";
        let sig = sign::sign(&key, msg).unwrap();
        let pub_der = key.to_der_public().unwrap();
        let pub_key = EvpKey::from_der_public(&pub_der).unwrap();
        assert_eq!(verify(&pub_key, &sig, msg).unwrap(), true);
    }

    #[test]
    fn verify_ec_wrong_message_returns_false() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let sig = sign::sign(&key, b"correct").unwrap();
        let pub_der = key.to_der_public().unwrap();
        let pub_key = EvpKey::from_der_public(&pub_der).unwrap();
        assert_eq!(verify(&pub_key, &sig, b"wrong").unwrap(), false);
    }

    #[test]
    fn verify_rsa_valid_signature() {
        let key = EvpKey::new(KeyType::RSA(WhichRSA::PS256)).unwrap();
        let msg = b"test message";
        let sig = sign::sign(&key, msg).unwrap();
        let pub_der = key.to_der_public().unwrap();
        let pub_key = EvpKey::from_der_public(&pub_der).unwrap();
        assert_eq!(verify(&pub_key, &sig, msg).unwrap(), true);
    }

    #[test]
    fn verify_rsa_wrong_message_returns_false() {
        let key = EvpKey::new(KeyType::RSA(WhichRSA::PS256)).unwrap();
        let sig = sign::sign(&key, b"correct").unwrap();
        let pub_der = key.to_der_public().unwrap();
        let pub_key = EvpKey::from_der_public(&pub_der).unwrap();
        assert_eq!(verify(&pub_key, &sig, b"wrong").unwrap(), false);
    }

    #[test]
    fn verify_ec_garbage_signature_returns_false_or_err() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let pub_der = key.to_der_public().unwrap();
        let pub_key = EvpKey::from_der_public(&pub_der).unwrap();
        match verify(&pub_key, &[0xde, 0xad], b"msg") {
            Ok(valid) => assert!(!valid, "Garbage signature must not verify"),
            Err(err) => assert!(
                err.starts_with("EVP_DigestVerify returned"),
                "unexpected error: {err}"
            ),
        }
    }

    #[test]
    fn verify_rsa_garbage_signature_returns_false_or_err() {
        let key = EvpKey::new(KeyType::RSA(WhichRSA::PS256)).unwrap();
        let pub_der = key.to_der_public().unwrap();
        let pub_key = EvpKey::from_der_public(&pub_der).unwrap();
        match verify(&pub_key, &[0xde, 0xad], b"msg") {
            Ok(valid) => assert!(!valid, "Garbage signature must not verify"),
            Err(err) => assert!(
                err.starts_with("EVP_DigestVerify returned"),
                "unexpected error: {err}"
            ),
        }
    }

    #[test]
    fn verify_context_init_error_propagates() {
        let null_key = EvpKey {
            key: std::ptr::null_mut(),
            typ: KeyType::EC(WhichEC::P256),
        };
        let err = verify(&null_key, &[0xde], b"hello").unwrap_err();
        assert!(
            err.starts_with("EVP_DigestVerifyInit returned 0: error:"),
            "unexpected error: {err}"
        );
    }
}
