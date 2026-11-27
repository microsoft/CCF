// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Decoders for the X.509 extension values returned by
//! `CertificateBackend::get_extension_value_by_oid`.

use super::Result;

const SEQUENCE: u8 = 0x30;
const OBJECT_IDENTIFIER: u8 = 0x06;

/// RFC 5280 section 4.2.1.12: id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }.
pub(crate) const EXTENDED_KEY_USAGE_OID: &str = "2.5.29.37";

/// Decodes `ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId` into dotted-decimal OIDs.
pub(crate) fn extended_key_usage(value: &[u8]) -> Result<Vec<String>> {
    let (mut key_purposes, trailing) = read_tlv(value, SEQUENCE)?;
    if !trailing.is_empty() {
        return Err("Trailing data after extended key usage".into());
    }

    let mut oids = Vec::new();
    while !key_purposes.is_empty() {
        let (oid, rest) = read_tlv(key_purposes, OBJECT_IDENTIFIER)?;
        oids.push(oid_to_dotted_decimal(oid)?);
        key_purposes = rest;
    }
    Ok(oids)
}

/// Reads one DER value with the expected tag, returning its contents and the
/// input that follows it.
fn read_tlv(input: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    let [actual_tag, first_length, rest @ ..] = input else {
        return Err("Truncated DER value".into());
    };
    if *actual_tag != tag {
        return Err("Unexpected DER tag".into());
    }

    let (length, rest) = if *first_length < 0x80 {
        (usize::from(*first_length), rest)
    } else {
        // Long form: the low seven bits count the big-endian length octets.
        let count = usize::from(first_length & 0x7f);
        if count == 0 || count > 4 || count > rest.len() {
            return Err("Unsupported DER length".into());
        }
        let (length_octets, rest) = rest.split_at(count);
        let length = length_octets
            .iter()
            .fold(0, |length, &octet| length << 8 | usize::from(octet));
        if length < 0x80 || length_octets[0] == 0 {
            return Err("Non-minimal DER length".into());
        }
        (length, rest)
    };
    if length > rest.len() {
        return Err("Truncated DER value".into());
    }
    Ok(rest.split_at(length))
}

/// Decodes the contents of a DER OBJECT IDENTIFIER (X.690 section 8.19).
fn oid_to_dotted_decimal(contents: &[u8]) -> Result<String> {
    let mut arcs = Vec::new();
    let mut subidentifier = 0u128;
    let mut complete = true;
    for &octet in contents {
        if complete && octet == 0x80 {
            return Err("Non-minimal OID subidentifier".into());
        }
        if subidentifier > u128::MAX >> 7 {
            return Err("OID subidentifier is too large".into());
        }
        subidentifier = subidentifier << 7 | u128::from(octet & 0x7f);
        complete = octet & 0x80 == 0;
        if complete {
            if arcs.is_empty() {
                // The first subidentifier packs the first two arcs as 40 * first + second.
                let first = (subidentifier / 40).min(2);
                arcs.push(first);
                subidentifier -= first * 40;
            }
            arcs.push(subidentifier);
            subidentifier = 0;
        }
    }
    if !complete || arcs.is_empty() {
        return Err("Truncated OID".into());
    }

    let arcs = arcs.iter().map(u128::to_string).collect::<Vec<_>>();
    Ok(arcs.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn oid_contents_decode_to_dotted_decimal() {
        for (contents, expected) in [
            (&[0x00][..], "0.0"),
            (&[0x4f], "1.39"),
            (&[0x50], "2.0"),
            // X.690 section 8.19.5 example.
            (&[0x81, 0x34, 0x03], "2.100.3"),
            (
                &[
                    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x4c, 0x3b, 0x01, 0x02,
                ],
                "1.3.6.1.4.1.311.76.59.1.2",
            ),
        ] {
            assert_eq!(oid_to_dotted_decimal(contents).unwrap(), expected);
        }

        let too_large = [&[0x2a, 0x84][..], &[0x80; 18], &[0x00]].concat();
        for contents in [&[][..], &[0x2a, 0x81], &[0x2a, 0x80, 0x01], &too_large] {
            assert!(oid_to_dotted_decimal(contents).is_err(), "{contents:x?}");
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn extended_key_usage_decodes_each_key_purpose() {
        let value = [0x30, 7, 0x06, 2, 0x2a, 0x03, 0x06, 1, 0x2b];
        assert_eq!(extended_key_usage(&value).unwrap(), ["1.2.3", "1.3"]);

        // A long-form length, as needed for 128 bytes or more.
        let long = [&[0x30, 0x81, 129][..], &[0x06, 1, 0x2b].repeat(43)].concat();
        assert_eq!(extended_key_usage(&long).unwrap(), vec!["1.3"; 43]);

        let malformed: [&[u8]; 8] = [
            &[],
            // Not a SEQUENCE.
            &[0x31, 3, 0x06, 1, 0x2a],
            // Element is not an OBJECT IDENTIFIER.
            &[0x30, 3, 0x04, 1, 0x2a],
            // Trailing data.
            &[0x30, 3, 0x06, 1, 0x2a, 0x00],
            // SEQUENCE longer than the input.
            &[0x30, 4, 0x06, 1, 0x2a],
            // OID longer than the SEQUENCE.
            &[0x30, 3, 0x06, 2, 0x2a],
            // Indefinite length.
            &[0x30, 0x80, 0x06, 1, 0x2a, 0x00, 0x00],
            // Long-form length where the short form fits.
            &[0x30, 0x81, 3, 0x06, 1, 0x2a],
        ];
        for value in malformed {
            assert!(extended_key_usage(value).is_err(), "{value:x?}");
        }
    }

    /// Decodes with OpenSSL, also reporting whether the input is DER: whether
    /// OpenSSL encodes what it decoded back to the same bytes.
    #[cfg(crypto_backend = "crypto_openssl")]
    fn openssl_extended_key_usage(value: &[u8]) -> Option<(Vec<String>, bool)> {
        use foreign_types_shared::{ForeignType, ForeignTypeRef};
        use openssl::{asn1::Asn1Object, stack::Stack};
        use std::ffi::{c_int, c_long, c_uchar, c_void};

        extern "C" {
            fn d2i_EXTENDED_KEY_USAGE(
                out: *mut *mut c_void,
                input: *mut *const c_uchar,
                len: c_long,
            ) -> *mut c_void;
            fn i2d_EXTENDED_KEY_USAGE(usage: *const c_void, out: *mut *mut c_uchar) -> c_int;
        }

        let mut input = value.as_ptr();
        // SAFETY: input points to value.len() readable bytes, which OpenSSL does not retain.
        let usage = unsafe {
            d2i_EXTENDED_KEY_USAGE(std::ptr::null_mut(), &mut input, value.len() as c_long)
        };
        if usage.is_null() {
            // SAFETY: clearing the thread's error queue has no preconditions.
            unsafe { openssl_sys::ERR_clear_error() };
            return None;
        }
        // SAFETY: a non-null EXTENDED_KEY_USAGE is an owned stack of ASN1_OBJECT.
        let usage = unsafe { Stack::<Asn1Object>::from_ptr(usage.cast()) };
        // SAFETY: OpenSSL leaves input within value, or one past its end.
        if unsafe { input.offset_from(value.as_ptr()) } as usize != value.len() {
            return None;
        }

        // SAFETY: a null output asks only for the encoded length.
        let len = unsafe { i2d_EXTENDED_KEY_USAGE(usage.as_ptr().cast(), std::ptr::null_mut()) };
        let mut encoded = vec![0u8; len.try_into().unwrap()];
        // SAFETY: encoded is writable for the length OpenSSL just reported.
        unsafe { i2d_EXTENDED_KEY_USAGE(usage.as_ptr().cast(), &mut encoded.as_mut_ptr()) };

        let oids = usage.iter().map(|oid| {
            let mut text = [0u8; 4096];
            // SAFETY: oid is a live ASN1_OBJECT and text is writable for the length passed.
            // The final argument selects the dotted-decimal form.
            let len = unsafe {
                openssl_sys::OBJ_obj2txt(
                    text.as_mut_ptr().cast(),
                    text.len() as c_int,
                    oid.as_ptr(),
                    1,
                )
            };
            String::from_utf8(text[..len.try_into().unwrap()].to_vec()).unwrap()
        });
        Some((oids.collect(), encoded == value))
    }

    /// Builds an input that is usually close to a valid extended key usage.
    #[cfg(crypto_backend = "crypto_openssl")]
    fn random_extended_key_usage(random: &mut impl rand::Rng) -> Vec<u8> {
        use rand::RngExt;

        fn tlv(random: &mut impl rand::Rng, tag: u8, contents: &[u8]) -> Vec<u8> {
            let tag = if random.random_range(0..32) == 0 {
                random.random()
            } else {
                tag
            };
            let length = (contents.len() as u32).to_be_bytes();
            let length = &length[length.iter().position(|&b| b != 0).unwrap_or(3)..];
            let padding = match random.random_range(0..16) {
                0 => random.random_range(0..3),
                _ => 0,
            };
            let mut encoded = vec![tag];
            if random.random_range(0..16) == 0 {
                // Indefinite length, ended by an end-of-contents marker.
                encoded.push(0x80);
                encoded.extend_from_slice(contents);
                encoded.extend_from_slice(&[0, 0]);
                return encoded;
            }
            if padding > 0 || contents.len() >= 0x80 {
                encoded.push(0x80 | (padding + length.len()) as u8);
                encoded.extend(std::iter::repeat_n(0, padding));
            }
            encoded.extend_from_slice(length);
            encoded.extend_from_slice(contents);
            encoded
        }

        let mut key_purposes = Vec::new();
        let max_key_purposes = 1 << random.random_range(0..5);
        for _ in 0..random.random_range(0..=max_key_purposes) {
            let mut oid = Vec::new();
            for _ in 0..random.random_range(0..8) {
                // 19 base-128 digits is the most that fits 128 bits.
                let max_digits = 4 << random.random_range(0..4);
                for digit in (0..random.random_range(1..=max_digits)).rev() {
                    let continuation = if digit > 0 { 0x80 } else { 0 };
                    // A leading zero digit is padding, which DER forbids.
                    let low = [
                        0x7f,
                        random.random_range(1..0x80),
                        random.random_range(0..0x80),
                    ];
                    oid.push(continuation | low[random.random_range(0..3)]);
                }
            }
            key_purposes.extend(tlv(random, OBJECT_IDENTIFIER, &oid));
        }
        let mut value = tlv(random, SEQUENCE, &key_purposes);

        match random.random_range(0..8) {
            0 if !value.is_empty() => {
                let at = random.random_range(0..value.len());
                value[at] = random.random();
            }
            1 if !value.is_empty() => value.truncate(random.random_range(0..value.len())),
            2 => value.push(random.random()),
            _ => {}
        }
        value
    }

    /// OpenSSL decodes more than DER. On DER, the two decoders must agree,
    /// except that OpenSSL has no limit on the size of an arc. Anything else
    /// that OpenSSL decodes must be rejected here.
    #[test]
    #[cfg(crypto_backend = "crypto_openssl")]
    fn extended_key_usage_matches_openssl_on_random_data() {
        use rand::{rngs::StdRng, rngs::SysRng, SeedableRng, TryRng};

        let seed = SysRng
            .try_next_u64()
            .expect("system RNG should provide a test seed");
        eprintln!("extended key usage random seed: {seed:#018x}");
        let mut random = StdRng::seed_from_u64(seed);

        let exceeds_128_bits = |oid: &String| {
            let mut arcs = oid.split('.').map(str::parse::<u128>);
            // The second arc is encoded as 80 more than its value when the first is 2.
            arcs.nth(1)
                .unwrap()
                .map_or(true, |arc| arc > u128::MAX - 80)
                || arcs.any(|arc| arc.is_err())
        };
        let mut agreed = 0;
        for _ in 0..20_000 {
            let value = random_extended_key_usage(&mut random);
            let context = format!("seed {seed:#018x}, input {value:02x?}");
            match (
                extended_key_usage(&value),
                openssl_extended_key_usage(&value),
            ) {
                (Ok(oids), Some((expected, is_der))) => {
                    assert_eq!(oids, expected, "{context}");
                    assert!(is_der, "accepted an input that is not DER: {context}");
                    agreed += 1;
                }
                (Ok(_), None) => panic!("accepted an input that OpenSSL rejects: {context}"),
                (Err(error), Some((expected, true))) => assert!(
                    expected.iter().any(exceeds_128_bits),
                    "rejected DER that OpenSSL accepts: {error}: {context}"
                ),
                (Err(_), _) => {}
            }
        }
        // The generator must keep producing inputs that exercise the comparison.
        assert!(agreed > 1000, "only {agreed} inputs were accepted");
    }
}
