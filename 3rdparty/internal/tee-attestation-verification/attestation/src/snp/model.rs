// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CPUID parsing for AMD SEV-SNP processors.

/// Little-endian 4-byte CPUID representation.
///
/// Bit layout (32 bits total, little-endian):
/// ```text
/// Bits  0-3:   stepping
/// Bits  4-7:   base_model
/// Bits  8-11:  base_family
/// Bits 12-15:  reserved
/// Bits 16-19:  extended_model
/// Bits 20-27:  extended_family
/// Bits 28-31:  reserved2
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct Cpuid(pub [u8; 4]);

impl Cpuid {
    /// Create a new CPUID from raw bytes (little-endian).
    pub fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Stepping (bits 0-3).
    pub fn stepping(&self) -> u8 {
        self.0[0] & 0x0F
    }

    /// Base model (bits 4-7).
    pub fn base_model(&self) -> u8 {
        (self.0[0] >> 4) & 0x0F
    }

    /// Base family (bits 8-11).
    pub fn base_family(&self) -> u8 {
        self.0[1] & 0x0F
    }

    /// Extended model (bits 16-19).
    pub fn extended_model(&self) -> u8 {
        self.0[2] & 0x0F
    }

    /// Extended family (bits 20-27).
    pub fn extended_family(&self) -> u8 {
        ((self.0[2] >> 4) & 0x0F) | ((self.0[3] & 0x0F) << 4)
    }

    /// Compute full family ID: base_family + extended_family.
    pub fn family(&self) -> u8 {
        self.base_family().wrapping_add(self.extended_family())
    }

    /// Compute full model ID: (extended_model << 4) | base_model.
    pub fn model(&self) -> u8 {
        (self.extended_model() << 4) | self.base_model()
    }

    /// Return hex string of the raw bytes (big-endian display order).
    pub fn hex_str(&self) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            self.0[3], self.0[2], self.0[1], self.0[0]
        )
    }
}

impl From<[u8; 4]> for Cpuid {
    fn from(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}

impl From<u32> for Cpuid {
    fn from(val: u32) -> Self {
        Self(val.to_le_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generation {
    Milan,
    Genoa,
    Turin,
}

impl Generation {
    /// Identify generation from family and model IDs.
    pub fn from_family_and_model(
        family: u8,
        model: u8,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        match family {
            0x19 => match model {
                0x0..=0x0F => Ok(Generation::Milan),
                0x10..=0x1F | 0xA0..=0xAF => Ok(Generation::Genoa),
                _ => Err(format!("Unsupported CPU model: {:#04X}", model).into()),
            },
            0x1A => match model {
                0x0..=0x11 => Ok(Generation::Turin),
                _ => Err(format!("Unsupported CPU model: {:#04X}", model).into()),
            },
            _ => Err(format!("Unsupported CPU family: {:#04X}", family).into()),
        }
    }

    /// Identify generation from a Cpuid struct.
    pub fn from_cpuid(cpuid: &Cpuid) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_family_and_model(cpuid.family(), cpuid.model())
    }
}

impl std::fmt::Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Generation::Milan => "Milan",
            Generation::Genoa => "Genoa",
            Generation::Turin => "Turin",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpuid_parsing() {
        let milan = Cpuid::from(0x00A00F11);
        assert_eq!(milan.extended_family(), 0x0A);
        assert_eq!(milan.extended_model(), 0x0);
        assert_eq!(milan.base_family(), 0xF);
        assert_eq!(milan.base_model(), 0x1);
        assert_eq!(milan.stepping(), 0x1);
        assert_eq!(milan.family(), 0x19);
        assert_eq!(milan.model(), 0x01);
        let genoa = Cpuid::from(0x00A10F11);
        assert_eq!(genoa.extended_family(), 0x0A);
        assert_eq!(genoa.extended_model(), 0x1);
        assert_eq!(genoa.base_family(), 0x0F);
        assert_eq!(genoa.base_model(), 0x01);
        assert_eq!(genoa.stepping(), 0x1);
        assert_eq!(genoa.family(), 0x19);
        assert_eq!(genoa.model(), 0x11);
        let turin = Cpuid::from(0x00B10F11);
        assert_eq!(turin.extended_family(), 0x0B);
        assert_eq!(turin.extended_model(), 0x1);
        assert_eq!(turin.base_family(), 0x0F);
        assert_eq!(turin.base_model(), 0x01);
        assert_eq!(turin.stepping(), 0x1);
        assert_eq!(turin.family(), 0x1A);
        assert_eq!(turin.model(), 0x11);
    }

    #[test]
    fn test_hex_str() {
        let cpuid = Cpuid::new([0x11, 0x0F, 0x80, 0x00]);
        assert_eq!(cpuid.hex_str(), "00800f11");
    }

    #[test]
    fn test_generation() {
        let milan = Cpuid::from(0x00A00F11);
        assert_eq!(Generation::from_cpuid(&milan).unwrap(), Generation::Milan);
        assert_eq!(
            Generation::from_family_and_model(milan.family(), milan.model()).unwrap(),
            Generation::Milan
        );

        for (cpuid, model) in &[
            (Cpuid::from(0x00A00F11), Generation::Milan),
            (Cpuid::from(0x00A10F11), Generation::Genoa),
            (Cpuid::from(0x00B10F11), Generation::Turin),
        ] {
            assert_eq!(Generation::from_cpuid(cpuid).unwrap(), *model);
            assert_eq!(
                Generation::from_family_and_model(cpuid.family(), cpuid.model()).unwrap(),
                *model
            );
        }
    }

    #[test]
    fn unsupported_generation_inputs_return_errors() {
        let unsupported_milan_genoa_model = Generation::from_family_and_model(0x19, 0x20)
            .expect_err("Unsupported Milan/Genoa model should fail");
        assert_eq!(
            unsupported_milan_genoa_model.to_string(),
            "Unsupported CPU model: 0x20"
        );

        let unsupported_turin_model = Generation::from_family_and_model(0x1A, 0x12)
            .expect_err("Unsupported Turin model should fail");
        assert_eq!(
            unsupported_turin_model.to_string(),
            "Unsupported CPU model: 0x12"
        );

        let unsupported_family = Generation::from_family_and_model(0x1B, 0x00)
            .expect_err("Unsupported family should fail");
        assert_eq!(
            unsupported_family.to_string(),
            "Unsupported CPU family: 0x1B"
        );
    }
}
