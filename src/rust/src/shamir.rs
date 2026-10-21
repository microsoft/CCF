// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use ccf_shamir::{Error, Share};
use std::slice;

/// The number of 32-bit limbs in a secret and in each share.
pub const LIMBS: usize = 10;
const _: () = assert!(LIMBS == ccf_shamir::LIMBS);

/// Status codes returned by every fallible entry point of the C ABI.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// Success.
    Ok = 0,
    /// Null, misaligned, empty, oversized or overlapping buffers, or lengths
    /// outside the supported range.
    InvalidArguments = 1,
    /// A polynomial coefficient is not canonical, i.e. not below the prime.
    InvalidCoefficient = 2,
    /// Two input shares have the same x coordinate modulo the prime.
    DuplicateShare = 3,
    /// Internal workspace mismatch. Cannot occur through this interface, which
    /// sizes its own workspace, but kept so every core error has a name.
    InvalidWorkspace = 4,
    /// The workspace for the recovery could not be allocated.
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

/// Reduce any 64-bit value to its canonical representative below the prime.
#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn ccf_shamir_reduce(x: u64) -> u64 {
    ccf_shamir::reduce(x)
}

/// Evaluate the polynomial at x = i + 1 for the share at index i, record that
/// coordinate in the share, and store the value in the given limb. Other limbs
/// are unchanged. Lengths are in elements. Requires limb < CCF_SHAMIR_LIMBS and
/// 0 < coefficient_count <= share_count < 2^31 - 1.
///
/// # Safety
///
/// Null, misaligned, empty, oversized, or overlapping buffers are rejected
/// without dereferencing anything. Otherwise the buffers must be live for
/// their indicated lengths, and no buffer may be accessed concurrently for the
/// duration of this call.
#[must_use]
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

/// Recover the secret from the first threshold shares. The secret is written
/// in place by the verified core, without an intermediate copy, and is
/// unchanged on error.
///
/// # Safety
///
/// Null, misaligned, empty, oversized, or overlapping buffers are rejected
/// without dereferencing anything. Otherwise `shares` must be live for
/// `threshold` elements and not mutated concurrently, and `secret` must be
/// live for exclusive access.
#[must_use]
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
