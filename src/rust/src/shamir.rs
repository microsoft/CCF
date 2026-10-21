// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use ccf_shamir::{Error, LIMBS, Share};
use std::slice;

unsafe extern "C" {
    fn OPENSSL_cleanse(ptr: *mut std::ffi::c_void, len: usize);
}

/// Status codes returned across the C ABI, mirroring `ccf_shamir_status`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Ok = 0,
    InvalidArguments = 1,
    InvalidCoefficient = 2,
    DuplicateShare = 3,
    InvalidWorkspace = 4,
}

impl From<Error> for Status {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidThreshold => Status::InvalidArguments,
            Error::InvalidCoefficient => Status::InvalidCoefficient,
            Error::DuplicateShare => Status::DuplicateShare,
            Error::InvalidWorkspace => Status::InvalidWorkspace,
        }
    }
}

type ByteRange = (usize, usize);

/// Validate a buffer argument without dereferencing it.
///
/// Accepts only nonnull, aligned, nonempty buffers whose byte extent fits in
/// `isize::MAX` and does not wrap around the address space, as `slice` requires.
fn buffer<T>(ptr: *const T, len: usize) -> Option<ByteRange> {
    if ptr.is_null() || !ptr.is_aligned() || len == 0 {
        return None;
    }
    let bytes = len.checked_mul(size_of::<T>())?;
    if bytes > isize::MAX as usize {
        return None;
    }
    let start = ptr.addr();
    Some((start, start.checked_add(bytes)?))
}

fn disjoint(a: ByteRange, b: ByteRange) -> bool {
    a.1 <= b.0 || b.1 <= a.0
}

#[unsafe(no_mangle)]
pub extern "C" fn ccf_shamir_reduce(x: u64) -> u64 {
    ccf_shamir::reduce(x)
}

/// # Safety
///
/// Null, misaligned, empty, oversized, or overlapping buffers are rejected
/// without dereferencing anything. Otherwise pointers must be valid for their
/// indicated lengths (in elements), and no buffer may be accessed concurrently
/// for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ccf_shamir_evaluate(
    coefficients: *const u64,
    coefficient_count: usize,
    values: *mut u32,
    share_count: usize,
) -> Status {
    let (Some(c), Some(v)) = (
        buffer(coefficients, coefficient_count),
        buffer(values.cast_const(), share_count),
    ) else {
        return Status::InvalidArguments;
    };
    if !disjoint(c, v) || share_count >= ccf_shamir::PRIME as usize {
        return Status::InvalidArguments;
    }
    // SAFETY: The buffers are nonnull, aligned, disjoint, and sized as checked
    // above; the caller guarantees they are live and not accessed concurrently.
    let coefficients = unsafe { slice::from_raw_parts(coefficients, coefficient_count) };
    let values = unsafe { slice::from_raw_parts_mut(values, share_count) };
    for (i, value) in values.iter_mut().enumerate() {
        match ccf_shamir::evaluate(coefficients, (i + 1) as u32) {
            Ok(y) => *value = y,
            Err(error) => return error.into(),
        }
    }
    Status::Ok
}

/// # Safety
///
/// Null, misaligned, empty, oversized, or overlapping buffers are rejected
/// without dereferencing anything. Otherwise pointers must be valid for their
/// indicated lengths: `threshold` shares and weights, and `LIMBS` secret limbs.
/// Shares must not be mutated concurrently; outputs require exclusive access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ccf_shamir_recover(
    shares: *const Share,
    threshold: usize,
    weights: *mut u64,
    secret: *mut u32,
) -> Status {
    let (Some(s), Some(w), Some(out)) = (
        buffer(shares, threshold),
        buffer(weights.cast_const(), threshold),
        buffer(secret.cast_const(), LIMBS),
    ) else {
        return Status::InvalidArguments;
    };
    if !disjoint(s, w) || !disjoint(s, out) || !disjoint(w, out) {
        return Status::InvalidArguments;
    }
    // SAFETY: The buffers are nonnull, aligned, disjoint, and sized as checked
    // above; the caller guarantees they are live and not accessed concurrently.
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
            Status::Ok
        }
        Err(error) => error.into(),
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
        assert_eq!(size_of::<Status>(), size_of::<std::ffi::c_int>());
        assert_eq!(Status::Ok as i32, 0);
        assert_eq!(Status::InvalidArguments as i32, 1);
        assert_eq!(Status::InvalidCoefficient as i32, 2);
        assert_eq!(Status::DuplicateShare as i32, 3);
        assert_eq!(Status::InvalidWorkspace as i32, 4);
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
            Status::Ok
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
            Status::Ok
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
            Status::DuplicateShare
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
            Status::InvalidArguments
        );
        // SAFETY: Null pointers and zero lengths are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_evaluate(std::ptr::null(), 0, std::ptr::null_mut(), 0) },
            Status::InvalidArguments
        );
    }

    #[test]
    fn c_abi_rejects_misaligned_overlapping_and_wrapping_buffers() {
        let coefficients = [1u64; 4];
        let mut values = [0u32; 4];
        let misaligned = coefficients
            .as_ptr()
            .cast::<u8>()
            .wrapping_add(1)
            .cast::<u64>();
        // SAFETY: Misaligned buffers are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_evaluate(misaligned, 2, values.as_mut_ptr(), 1) },
            Status::InvalidArguments
        );
        let mut buffer = [0u64; 4];
        let overlapping = buffer.as_mut_ptr().cast::<u32>();
        // SAFETY: Overlapping buffers are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_evaluate(buffer.as_ptr(), 2, overlapping, 2) },
            Status::InvalidArguments
        );
        let wrapping: *const u64 = std::ptr::without_provenance(usize::MAX - 7);
        // SAFETY: Extents that wrap the address space are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_evaluate(wrapping, 2, values.as_mut_ptr(), 1) },
            Status::InvalidArguments
        );
        let mut shares = [Share {
            x: 1,
            y: [1; LIMBS],
        }];
        let mut weights = [0u64; 1];
        let aliased = shares.as_mut_ptr().cast::<u32>();
        // SAFETY: Overlapping buffers are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_recover(shares.as_ptr(), 1, weights.as_mut_ptr(), aliased) },
            Status::InvalidArguments
        );
        let mut secret = [0u32; LIMBS];
        let misaligned = shares.as_ptr().cast::<u8>().wrapping_add(2).cast::<Share>();
        // SAFETY: Misaligned buffers are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_recover(misaligned, 1, weights.as_mut_ptr(), secret.as_mut_ptr()) },
            Status::InvalidArguments
        );
        // SAFETY: All arrays are disjoint, aligned and have the indicated lengths.
        assert_eq!(
            unsafe {
                ccf_shamir_recover(
                    shares.as_ptr(),
                    1,
                    weights.as_mut_ptr(),
                    secret.as_mut_ptr(),
                )
            },
            Status::Ok
        );
        assert_eq!(secret, [1; LIMBS]);
    }
}
