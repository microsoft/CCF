// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn nibble_to_hex(nibble: u8) -> char {
    const ASCII_0: u8 = b'0';
    const ASCII_A: u8 = b'a';
    match nibble {
        0..=9 => (nibble + ASCII_0) as char,
        10..=15 => (nibble - 10 + ASCII_A) as char,
        _ => panic!("Invalid hex digit: {nibble}"),
    }
}

/// Encodes bytes as lowercase hexadecimal text.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(nibble_to_hex(byte >> 4));
        encoded.push(nibble_to_hex(byte & 0x0f));
    }
    encoded
}

/// Decodes hexadecimal text into bytes.
///
/// Returns an error if the input contains non-ASCII characters, has odd
/// length, or contains characters that are not valid hexadecimal digits.
pub fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.is_ascii() {
        return Err("Hex string must contain only ASCII characters".to_string());
    }
    if hex.len() % 2 != 0 {
        return Err("Hex string must have an even length".to_string());
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex digit {}", byte as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_hex_matches_known_vectors() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(to_hex(&[0x00]), "00");
        assert_eq!(to_hex(&[0xff]), "ff");
        assert_eq!(to_hex(&[0xab]), "ab");
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn from_hex_matches_known_vectors() {
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
        assert_eq!(from_hex("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(from_hex("00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(from_hex("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn from_hex_rejects_malformed_input() {
        assert_eq!(
            from_hex("café").unwrap_err(),
            "Hex string must contain only ASCII characters"
        );
        assert_eq!(
            from_hex("abc").unwrap_err(),
            "Hex string must have an even length"
        );
        assert_eq!(from_hex("zz").unwrap_err(), "invalid hex digit z");
    }

    #[test]
    fn hex_round_trips() {
        let data = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(from_hex(&to_hex(&data)).unwrap(), data);
    }

    #[test]
    #[should_panic(expected = "Invalid hex digit")]
    fn nibble_to_hex_panics_on_invalid() {
        nibble_to_hex(16);
    }
}
