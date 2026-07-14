// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Encode bytes using URL-safe base64 without padding.
pub fn base64_encode_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let indexes = base64_indexes(chunk);
        encoded.push(ALPHABET[indexes[0] as usize] as char);
        encoded.push(ALPHABET[indexes[1] as usize] as char);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[indexes[2] as usize] as char);
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[indexes[3] as usize] as char);
        }
    }
    encoded
}

/// Decode standard base64 with padding.
pub fn base64_standard_decode(encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.len() % 4 != 0 {
        return Err("base64 input length must be a multiple of 4".to_string());
    }

    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(encoded.len() / 4 * 3);
    for (chunk_index, chunk) in bytes.chunks_exact(4).enumerate() {
        let first = base64_standard_value(chunk[0])
            .ok_or_else(|| format!("invalid base64 byte at offset {}", chunk_index * 4))?;
        let second = base64_standard_value(chunk[1])
            .ok_or_else(|| format!("invalid base64 byte at offset {}", chunk_index * 4 + 1))?;
        let third =
            if chunk[2] == b'=' {
                None
            } else {
                Some(base64_standard_value(chunk[2]).ok_or_else(|| {
                    format!("invalid base64 byte at offset {}", chunk_index * 4 + 2)
                })?)
            };
        let fourth =
            if chunk[3] == b'=' {
                None
            } else {
                Some(base64_standard_value(chunk[3]).ok_or_else(|| {
                    format!("invalid base64 byte at offset {}", chunk_index * 4 + 3)
                })?)
            };

        if third.is_none() && fourth.is_some() {
            return Err("invalid base64 padding".to_string());
        }
        if chunk_index + 1 != encoded.len() / 4 && (third.is_none() || fourth.is_none()) {
            return Err("base64 padding is only allowed in the final chunk".to_string());
        }

        let indexes = [first, second, third.unwrap_or(0), fourth.unwrap_or(0)];
        let block = bytes_from_base64_indexes(indexes);
        decoded.push(block[0]);
        if third.is_some() {
            decoded.push(block[1]);
            if fourth.is_some() {
                decoded.push(block[2]);
            }
        }
    }
    Ok(decoded)
}

fn base64_standard_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn base64_indexes(chunk: &[u8]) -> [u8; 4] {
    let mut block = [0u8; 3];
    block[..chunk.len()].copy_from_slice(chunk);
    let packed = u32::from_be_bytes([0, block[0], block[1], block[2]]);
    [
        ((packed >> 18) & 0x3f) as u8,
        ((packed >> 12) & 0x3f) as u8,
        ((packed >> 6) & 0x3f) as u8,
        (packed & 0x3f) as u8,
    ]
}

fn bytes_from_base64_indexes(indexes: [u8; 4]) -> [u8; 3] {
    let packed = (u32::from(indexes[0]) << 18)
        | (u32::from(indexes[1]) << 12)
        | (u32::from(indexes[2]) << 6)
        | u32::from(indexes[3]);
    let bytes = packed.to_be_bytes();
    [bytes[1], bytes[2], bytes[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_no_padding_matches_known_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
            ("\u{ffef}", "77-v"),
        ] {
            assert_eq!(base64_encode_no_padding(plain.as_bytes()), encoded);
        }
    }

    #[test]
    fn base64_standard_decode_matches_known_vectors() {
        for (encoded, plain) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
        ] {
            assert_eq!(base64_standard_decode(encoded).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn base64_standard_decode_rejects_malformed_inputs() {
        assert_eq!(
            base64_standard_decode("Zg=").unwrap_err(),
            "base64 input length must be a multiple of 4"
        );
        assert_eq!(
            base64_standard_decode("Zg=A").unwrap_err(),
            "invalid base64 padding"
        );
        assert_eq!(
            base64_standard_decode("Zg==AAAA").unwrap_err(),
            "base64 padding is only allowed in the final chunk"
        );
        assert_eq!(
            base64_standard_decode("Zm$=").unwrap_err(),
            "invalid base64 byte at offset 2"
        );
    }
}
