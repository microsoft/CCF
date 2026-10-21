// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#![forbid(unsafe_code)]

pub const PRIME: u64 = 2147483647;
pub const LIMBS: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Share {
    pub x: u32,
    pub y: [u32; LIMBS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidThreshold,
    InvalidCoefficient,
    DuplicateShare,
    InvalidWorkspace,
}

/// Reduce any u64 without data-dependent branches or division.
pub fn reduce(mut x: u64) -> u64 {
    let d = x >> 31;
    x -= d * PRIME;
    let d = x >> 31;
    x -= d * PRIME;
    let d = (x + 1) >> 31;
    x - d * PRIME
}

fn mul(x: u64, y: u64) -> u64 {
    reduce(x * y)
}

fn add(x: u64, y: u64) -> u64 {
    reduce(x + y)
}

fn sub(x: u64, y: u64) -> u64 {
    reduce(PRIME + x - y)
}

fn inverse(mut x: u64) -> u64 {
    let mut n = PRIME - 2;
    let mut y = 1;
    while n > 0 {
        if n & 1 != 0 {
            y = mul(y, x);
        }
        x = mul(x, x);
        n >>= 1;
    }
    y
}

/// Evaluate a polynomial with constant coefficient first.
///
/// Coefficients must be canonical field elements. The index is reduced just
/// like an input recovery coordinate. Branches depend only on public lengths
/// and the validity of coefficients, not on valid coefficient values.
pub fn evaluate(coefficients: &[u64], x: u32) -> Result<u32, Error> {
    if coefficients.is_empty() {
        return Err(Error::InvalidThreshold);
    }
    let x = reduce(u64::from(x));
    let mut y = 0;
    let mut i = coefficients.len();
    while i > 0 {
        i -= 1;
        if coefficients[i] >= PRIME {
            return Err(Error::InvalidCoefficient);
        }
        y = add(coefficients[i], mul(x, y));
    }
    Ok(y as u32)
}

/// Precompute interpolation weights at zero. Coordinates are public.
///
/// The caller supplies exactly one workspace entry per selected share. Equal
/// coordinates modulo PRIME are rejected, as in the C++ implementation.
pub fn lagrange(shares: &[Share], weights: &mut [u64]) -> Result<(), Error> {
    if shares.is_empty() {
        return Err(Error::InvalidThreshold);
    }
    if weights.len() != shares.len() {
        return Err(Error::InvalidWorkspace);
    }
    let mut i = 0;
    while i < shares.len() {
        let mut numerator = 1;
        let mut denominator = 1;
        let mut j = 0;
        while j < shares.len() {
            if i != j {
                let xj = reduce(u64::from(shares[j].x));
                let xi = reduce(u64::from(shares[i].x));
                numerator = mul(numerator, xj);
                denominator = mul(denominator, sub(xj, xi));
            }
            j += 1;
        }
        if denominator == 0 {
            return Err(Error::DuplicateShare);
        }
        weights[i] = mul(numerator, inverse(denominator));
        i += 1;
    }
    Ok(())
}

/// Recover all limbs using the selected shares, reducing noncanonical inputs.
///
/// Working storage is caller-owned and linear in the threshold. No allocation,
/// entropy source, raw pointer, or foreign call is part of the safe core.
pub fn recover(shares: &[Share], weights: &mut [u64]) -> Result<[u32; LIMBS], Error> {
    lagrange(shares, weights)?;
    let mut secret = [0; LIMBS];
    let mut limb = 0;
    while limb < LIMBS {
        let mut y = 0;
        let mut i = 0;
        while i < shares.len() {
            y = add(y, mul(weights[i], reduce(u64::from(shares[i].y[limb]))));
            i += 1;
        }
        secret[limb] = y as u32;
        limb += 1;
    }
    Ok(secret)
}
