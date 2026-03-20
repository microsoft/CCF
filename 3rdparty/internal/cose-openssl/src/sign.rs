use crate::ossl_wrappers::{EvpKey, EvpMdContext, SignOp};

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
            return Err(format!("Failed to get signature size, err: {}", res));
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
            return Err(format!("Failed to sign, err: {}", res));
        }

        // Not always fixed size, e.g. for EC keys. More on this here:
        // https://docs.openssl.org/3.0/man3/EVP_DigestSignInit/#description.
        sig.truncate(sig_size);

        Ok(sig)
    }
}
