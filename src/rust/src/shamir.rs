// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use ccf_shamir::{Error, LIMBS, Share};
use std::slice;

/// Status codes returned across the C ABI, mirroring `ccf_shamir_status`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Ok = 0,
    InvalidArguments = 1,
    InvalidCoefficient = 2,
    DuplicateShare = 3,
    InvalidWorkspace = 4,
    OutOfMemory = 5,
}

impl From<Error> for Status {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidThreshold | Error::InvalidLimb | Error::InvalidShareCount => {
                Status::InvalidArguments
            }
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
pub unsafe extern "C" fn ccf_shamir_share_limb(
    coefficients: *const u64,
    coefficient_count: usize,
    limb: usize,
    shares: *mut Share,
    share_count: usize,
) -> Status {
    let (Some(c), Some(s)) = (
        buffer(coefficients, coefficient_count),
        buffer(shares.cast_const(), share_count),
    ) else {
        return Status::InvalidArguments;
    };
    if !disjoint(c, s) {
        return Status::InvalidArguments;
    }
    // SAFETY: The buffers are nonnull, aligned, disjoint, and sized as checked
    // above; the caller guarantees they are live and not accessed concurrently.
    let coefficients = unsafe { slice::from_raw_parts(coefficients, coefficient_count) };
    let shares = unsafe { slice::from_raw_parts_mut(shares, share_count) };
    match ccf_shamir::share_limb(coefficients, limb, shares) {
        Ok(()) => Status::Ok,
        Err(error) => error.into(),
    }
}

/// # Safety
///
/// Null, misaligned, empty, oversized, or overlapping buffers are rejected
/// without dereferencing anything. Otherwise `shares` must be valid for
/// `threshold` elements and not mutated concurrently, and `secret` must be
/// valid for exclusive access. The secret is written in place by the core;
/// this layer holds no copy of it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ccf_shamir_recover(
    shares: *const Share,
    threshold: usize,
    secret: *mut [u32; LIMBS],
) -> Status {
    let (Some(s), Some(out)) = (buffer(shares, threshold), buffer(secret.cast_const(), 1)) else {
        return Status::InvalidArguments;
    };
    if !disjoint(s, out) {
        return Status::InvalidArguments;
    }
    let mut weights = Vec::new();
    if weights.try_reserve_exact(threshold).is_err() {
        return Status::OutOfMemory;
    }
    weights.resize(threshold, 0u64);
    // SAFETY: The buffers are nonnull, aligned, disjoint, and sized as checked
    // above; the caller guarantees they are live and not accessed concurrently.
    let shares = unsafe { slice::from_raw_parts(shares, threshold) };
    let secret = unsafe { &mut *secret };
    match ccf_shamir::recover(shares, &mut weights, secret) {
        Ok(()) => Status::Ok,
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
        assert_eq!(Status::OutOfMemory as i32, 5);
    }

    #[test]
    fn c_abi_sharing_and_recovery() {
        let coefficients = [123, 456, 789];
        let mut shares: [Share; 3] = std::array::from_fn(|_| Share {
            x: 0,
            y: [0; LIMBS],
        });
        for limb in 0..LIMBS {
            // SAFETY: All arrays are disjoint and have the indicated lengths.
            assert_eq!(
                unsafe {
                    ccf_shamir_share_limb(
                        coefficients.as_ptr(),
                        coefficients.len(),
                        limb,
                        shares.as_mut_ptr(),
                        shares.len(),
                    )
                },
                Status::Ok
            );
        }
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.x, i as u32 + 1);
            assert_eq!(share.y, [[1368, 4191, 8592][i]; LIMBS]);
        }
        let mut secret = [0; LIMBS];
        // SAFETY: All arrays are disjoint and have the indicated lengths.
        assert_eq!(
            unsafe { ccf_shamir_recover(shares.as_ptr(), shares.len(), &raw mut secret) },
            Status::Ok
        );
        assert_eq!(secret, [123; LIMBS]);
    }

    #[test]
    fn c_abi_errors_preserve_the_outputs() {
        let shares: [Share; 2] = std::array::from_fn(|_| Share {
            x: 1,
            y: [42; LIMBS],
        });
        let mut secret = [17; LIMBS];
        // SAFETY: All arrays are disjoint and have the indicated lengths.
        assert_eq!(
            unsafe { ccf_shamir_recover(shares.as_ptr(), shares.len(), &raw mut secret) },
            Status::DuplicateShare
        );
        assert_eq!(secret, [17; LIMBS]);
        // SAFETY: Null pointers and zero lengths are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_recover(std::ptr::null(), 0, std::ptr::null_mut()) },
            Status::InvalidArguments
        );
        // SAFETY: Null pointers and zero lengths are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_share_limb(std::ptr::null(), 0, 0, std::ptr::null_mut(), 0) },
            Status::InvalidArguments
        );
        let coefficients = [1u64; 2];
        let mut outputs: [Share; 2] = std::array::from_fn(|_| Share {
            x: 0,
            y: [0; LIMBS],
        });
        // SAFETY: All arrays are disjoint and have the indicated lengths.
        assert_eq!(
            unsafe {
                ccf_shamir_share_limb(
                    coefficients.as_ptr(),
                    coefficients.len(),
                    LIMBS,
                    outputs.as_mut_ptr(),
                    outputs.len(),
                )
            },
            Status::InvalidArguments
        );
        assert!(
            outputs
                .iter()
                .all(|share| share.x == 0 && share.y == [0; LIMBS])
        );
    }

    #[test]
    fn c_abi_rejects_misaligned_overlapping_and_wrapping_buffers() {
        let coefficients = [1u64; 4];
        let mut outputs: [Share; 1] = std::array::from_fn(|_| Share {
            x: 0,
            y: [0; LIMBS],
        });
        let misaligned = coefficients
            .as_ptr()
            .cast::<u8>()
            .wrapping_add(1)
            .cast::<u64>();
        // SAFETY: Misaligned buffers are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_share_limb(misaligned, 1, 0, outputs.as_mut_ptr(), 1) },
            Status::InvalidArguments
        );
        let mut buffer = [0u64; 12];
        let overlapping = buffer.as_mut_ptr().cast::<Share>();
        // SAFETY: Overlapping buffers are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_share_limb(buffer.as_ptr(), 1, 0, overlapping, 1) },
            Status::InvalidArguments
        );
        let wrapping: *const u64 = std::ptr::without_provenance(usize::MAX - 7);
        // SAFETY: Extents that wrap the address space are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_share_limb(wrapping, 2, 0, outputs.as_mut_ptr(), 1) },
            Status::InvalidArguments
        );
        let mut shares = [Share {
            x: 1,
            y: [1; LIMBS],
        }];
        let aliased = shares.as_mut_ptr().cast::<[u32; LIMBS]>();
        // SAFETY: Overlapping buffers are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_recover(shares.as_ptr(), 1, aliased) },
            Status::InvalidArguments
        );
        let mut secret = [0u32; LIMBS];
        let misaligned = shares.as_ptr().cast::<u8>().wrapping_add(2).cast::<Share>();
        // SAFETY: Misaligned buffers are rejected before dereference.
        assert_eq!(
            unsafe { ccf_shamir_recover(misaligned, 1, &raw mut secret) },
            Status::InvalidArguments
        );
        // SAFETY: All arrays are disjoint, aligned and have the indicated lengths.
        assert_eq!(
            unsafe { ccf_shamir_recover(shares.as_ptr(), 1, &raw mut secret) },
            Status::Ok
        );
        assert_eq!(secret, [1; LIMBS]);
    }
}
