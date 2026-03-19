use crate::ossl_wrappers::{EvpKey, EvpMdContext, VerifyOp};

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
            err => Err(format!("Failed to verify signature, err: {}", err)),
        }
    }
}
