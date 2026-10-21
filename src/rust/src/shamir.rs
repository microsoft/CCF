// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use ccf_shamir::{Error, LIMBS, Share};
use std::slice;

unsafe extern "C" {
    fn OPENSSL_cleanse(ptr: *mut std::ffi::c_void, len: usize);
}

fn status(error: Error) -> i32 {
    match error {
        Error::InvalidThreshold => 1,
        Error::InvalidCoefficient => 2,
        Error::DuplicateShare => 3,
        Error::InvalidWorkspace => 4,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ccf_shamir_reduce(x: u64) -> u64 {
    ccf_shamir::reduce(x)
}

/// # Safety
///
/// Null pointers and invalid lengths are rejected without dereferencing buffers.
/// Otherwise pointers must be aligned and valid for their indicated lengths
/// (in elements). Output must not overlap coefficients.
/// No buffer may be concurrently accessed for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ccf_shamir_evaluate(
    coefficients: *const u64,
    coefficient_count: usize,
    values: *mut u32,
    share_count: usize,
) -> i32 {
    if coefficients.is_null()
        || values.is_null()
        || coefficient_count == 0
        || coefficient_count > isize::MAX as usize / size_of::<u64>()
        || share_count == 0
        || share_count >= ccf_shamir::PRIME as usize
        || share_count > isize::MAX as usize / size_of::<u32>()
    {
        return 1;
    }
    // SAFETY: The caller supplies disjoint, aligned, live buffers as documented.
    let coefficients = unsafe { slice::from_raw_parts(coefficients, coefficient_count) };
    let values = unsafe { slice::from_raw_parts_mut(values, share_count) };
    for (i, value) in values.iter_mut().enumerate() {
        match ccf_shamir::evaluate(coefficients, (i + 1) as u32) {
            Ok(y) => *value = y,
            Err(error) => return status(error),
        }
    }
    0
}

/// # Safety
///
/// Null pointers and invalid lengths are rejected without dereferencing buffers.
/// Otherwise pointers must be aligned and valid for their indicated lengths.
/// Shares, weights, and the LIMBS-element secret output must not overlap.
/// Shares must not be mutated concurrently; outputs require exclusive access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ccf_shamir_recover(
    shares: *const Share,
    threshold: usize,
    weights: *mut u64,
    secret: *mut u32,
) -> i32 {
    if shares.is_null()
        || weights.is_null()
        || secret.is_null()
        || threshold == 0
        || threshold > isize::MAX as usize / size_of::<Share>()
    {
        return 1;
    }
    // SAFETY: The caller supplies disjoint, aligned, live buffers as documented.
    let shares = unsafe { slice::from_raw_parts(shares, threshold) };
    let weights = unsafe { slice::from_raw_parts_mut(weights, threshold) };
    let secret = unsafe { slice::from_raw_parts_mut(secret, LIMBS) };
    match ccf_shamir::recover(shares, weights) {
        Ok(mut value) => {
            secret.copy_from_slice(&value);
            // SAFETY: This temporary is exclusively owned and live for all LIMBS.
            unsafe {
                OPENSSL_cleanse(value.as_mut_ptr().cast(), size_of_val(&value));
            }
            0
        }
        Err(error) => status(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_layout_matches_the_header() {
        assert_eq!(size_of::<Share>(), 44);
        assert_eq!(align_of::<Share>(), align_of::<u32>());
        assert_eq!(std::mem::offset_of!(Share, y), 4);
    }

    #[test]
    fn c_abi_evaluation_and_recovery() {
        let coefficients = [123, 456, 789];
        let mut values = [0; 3];
        // SAFETY: All arrays are disjoint and have the indicated lengths.
        assert_eq!(
            unsafe {
                ccf_shamir_evaluate(
                    coefficients.as_ptr(),
                    coefficients.len(),
                    values.as_mut_ptr(),
                    values.len(),
                )
            },
            0
        );
        assert_eq!(values, [1368, 4191, 8592]);
        let shares = std::array::from_fn::<_, 3, _>(|i| Share {
            x: i as u32 + 1,
            y: [values[i]; LIMBS],
        });
        let mut weights = [0; 3];
        let mut secret = [0; LIMBS];
        // SAFETY: All arrays are disjoint and have the indicated lengths.
        assert_eq!(
            unsafe {
                ccf_shamir_recover(
                    shares.as_ptr(),
                    shares.len(),
                    weights.as_mut_ptr(),
                    secret.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(secret, [123; LIMBS]);
    }

    #[test]
    fn c_abi_errors_preserve_the_secret() {
        let shares = [Share {
            x: 1,
            y: [42; LIMBS],
        }; 2];
        let mut weights = [0; 2];
        let mut secret = [17; LIMBS];
        // SAFETY: All arrays are disjoint and have the indicated lengths.
        assert_eq!(
            unsafe {
                ccf_shamir_recover(
                    shares.as_ptr(),
                    shares.len(),
                    weights.as_mut_ptr(),
                    secret.as_mut_ptr(),
                )
            },
            3
        );
        assert_eq!(secret, [17; LIMBS]);
        // SAFETY: Null pointers and zero lengths are rejected before dereference.
        assert_eq!(
            unsafe {
                ccf_shamir_recover(
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            1
        );
        // SAFETY: Null pointers and zero lengths are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_evaluate(std::ptr::null(), 0, std::ptr::null_mut(), 0) },
            1
        );
    }
}
