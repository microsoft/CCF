// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use ccf_shamir::{Error, LIMBS, PRIME, Share, evaluate, lagrange, recover, reduce};

fn polynomial(coefficients: &[u64], x: u32) -> u32 {
    let mut power = 1;
    let mut value = 0;
    for coefficient in coefficients {
        value = (value + coefficient * power) % PRIME;
        power = power * (u64::from(x) % PRIME) % PRIME;
    }
    value as u32
}

#[test]
fn reduction_matches_remainder_including_u64_boundaries() {
    for x in [0, 1, PRIME - 1, PRIME, PRIME + 1, u64::MAX] {
        assert_eq!(reduce(x), x % PRIME);
    }
    let mut x = 0_u64;
    for _ in 0..100_000 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        assert_eq!(reduce(x), x % PRIME);
    }
    for i in 0..(1 << 16) {
        for x in [
            (PRIME * i).wrapping_sub(1),
            PRIME * i,
            PRIME * i + PRIME / 2,
        ] {
            assert_eq!(reduce(x), x % PRIME);
        }
    }
}

#[test]
fn evaluation_matches_legacy_power_sum() {
    for coefficients in [
        vec![0],
        vec![PRIME - 1],
        vec![123, 456, 789],
        vec![PRIME - 1; 400],
    ] {
        for x in [0, 1, 2, 42, PRIME as u32, u32::MAX] {
            assert_eq!(evaluate(&coefficients, x), Ok(polynomial(&coefficients, x)));
        }
    }
    assert_eq!(evaluate(&[123, 456, 789], 1), Ok(1368));
    assert_eq!(evaluate(&[123, 456, 789], 2), Ok(4191));
    assert_eq!(evaluate(&[123, 456, 789], 3), Ok(8592));
}

#[test]
fn every_three_share_subset_recovers_each_limb() {
    let mut shares = [Share {
        x: 0,
        y: [0; LIMBS],
    }; 8];
    for (i, share) in shares.iter_mut().enumerate() {
        share.x = i as u32 + 1;
        for limb in 0..LIMBS {
            share.y[limb] = polynomial(&[123 + limb as u64, 456, PRIME - 789], share.x);
        }
    }
    for i in 0..8 {
        for j in i + 1..8 {
            for k in j + 1..8 {
                let recovered = recover(&[shares[i], shares[j], shares[k]], &mut [0; 3]).unwrap();
                for (limb, value) in recovered.iter().enumerate() {
                    assert_eq!(*value, 123 + limb as u32);
                }
            }
        }
    }
}

#[test]
fn recovery_reduces_noncanonical_values_and_coordinates() {
    let shares = [
        Share {
            x: PRIME as u32 + 1,
            y: [PRIME as u32 + 16; LIMBS],
        },
        Share {
            x: PRIME as u32 + 2,
            y: [PRIME as u32 + 23; LIMBS],
        },
    ];
    assert_eq!(recover(&shares, &mut [0; 2]), Ok([9; LIMBS]));
    let at_zero = Share {
        x: PRIME as u32,
        y: [u32::MAX; LIMBS],
    };
    assert_eq!(recover(&[at_zero], &mut [0; 1]), Ok([1; LIMBS]));
}

#[test]
fn invalid_inputs_are_explicit_errors() {
    assert_eq!(evaluate(&[], 1), Err(Error::InvalidThreshold));
    assert_eq!(evaluate(&[PRIME], 1), Err(Error::InvalidCoefficient));
    assert_eq!(recover(&[], &mut []), Err(Error::InvalidThreshold));
    let share = Share {
        x: 1,
        y: [42; LIMBS],
    };
    assert_eq!(lagrange(&[share], &mut []), Err(Error::InvalidWorkspace));
    let duplicate = Share {
        x: PRIME as u32 + 1,
        ..share
    };
    assert_eq!(
        recover(&[share, duplicate], &mut [0; 2]),
        Err(Error::DuplicateShare)
    );
}
