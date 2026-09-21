// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Digest algorithm used by hashing and signature operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    pub const fn byte_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// Elliptic-curve signature key algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcSignatureKeyAlgorithm {
    P256,
    P384,
    P521,
}

impl EcSignatureKeyAlgorithm {
    pub const fn digest(self) -> DigestAlgorithm {
        match self {
            Self::P256 => DigestAlgorithm::Sha256,
            Self::P384 => DigestAlgorithm::Sha384,
            Self::P521 => DigestAlgorithm::Sha512,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }

    pub const fn scalar_byte_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    pub const fn fixed_signature_byte_len(self) -> usize {
        self.scalar_byte_len() * 2
    }
}

/// RSA-PSS signature key algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaPssSignatureKeyAlgorithm {
    Ps256,
    Ps384,
    Ps512,
}

impl RsaPssSignatureKeyAlgorithm {
    pub const fn digest(self) -> DigestAlgorithm {
        match self {
            Self::Ps256 => DigestAlgorithm::Sha256,
            Self::Ps384 => DigestAlgorithm::Sha384,
            Self::Ps512 => DigestAlgorithm::Sha512,
        }
    }

    pub const fn salt_len(self) -> usize {
        self.digest().byte_len()
    }
}

/// RSA PKCS#1 v1.5 signature key algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaPkcs1v15SignatureKeyAlgorithm {
    Rs256,
    Rs384,
    Rs512,
}

impl RsaPkcs1v15SignatureKeyAlgorithm {
    pub const fn digest(self) -> DigestAlgorithm {
        match self {
            Self::Rs256 => DigestAlgorithm::Sha256,
            Self::Rs384 => DigestAlgorithm::Sha384,
            Self::Rs512 => DigestAlgorithm::Sha512,
        }
    }
}

/// A key algorithm bound to the signature operation it is used to verify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureKeyAlgorithm {
    Ec(EcSignatureKeyAlgorithm),
    RsaPss(RsaPssSignatureKeyAlgorithm),
    RsaPkcs1v15(RsaPkcs1v15SignatureKeyAlgorithm),
}

impl SignatureKeyAlgorithm {
    pub const fn digest(self) -> DigestAlgorithm {
        match self {
            Self::Ec(algorithm) => algorithm.digest(),
            Self::RsaPss(algorithm) => algorithm.digest(),
            Self::RsaPkcs1v15(algorithm) => algorithm.digest(),
        }
    }
}

/// Return whether key material imported for `key_algorithm` can verify a
/// signature using `signature_algorithm`.
///
/// ECDSA keys are curve-specific, so the curve must match exactly. RSA keys are
/// not intrinsically bound to a specific RSA hash/padding choice, so any RSA
/// key algorithm is compatible with any RSA signature algorithm.
pub const fn compatible_key_and_signature(
    key_algorithm: SignatureKeyAlgorithm,
    signature_algorithm: SignatureKeyAlgorithm,
) -> bool {
    match (key_algorithm, signature_algorithm) {
        (SignatureKeyAlgorithm::Ec(key), SignatureKeyAlgorithm::Ec(signature)) => {
            key as u8 == signature as u8
        }
        (SignatureKeyAlgorithm::RsaPss(_), SignatureKeyAlgorithm::RsaPss(_)) => true,
        (SignatureKeyAlgorithm::RsaPss(_), SignatureKeyAlgorithm::RsaPkcs1v15(_)) => true,
        (SignatureKeyAlgorithm::RsaPkcs1v15(_), SignatureKeyAlgorithm::RsaPss(_)) => true,
        (SignatureKeyAlgorithm::RsaPkcs1v15(_), SignatureKeyAlgorithm::RsaPkcs1v15(_)) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_compatibility_requires_matching_curve() {
        assert!(compatible_key_and_signature(
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256),
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256),
        ));
        assert!(!compatible_key_and_signature(
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256),
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P384),
        ));
    }

    #[test]
    fn rsa_pss_compatibility_allows_different_parameters() {
        assert!(compatible_key_and_signature(
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps256),
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps384),
        ));
    }

    #[test]
    fn rsa_compatibility_allows_different_signature_schemes() {
        assert!(compatible_key_and_signature(
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps256),
            SignatureKeyAlgorithm::RsaPkcs1v15(RsaPkcs1v15SignatureKeyAlgorithm::Rs384),
        ));
        assert!(compatible_key_and_signature(
            SignatureKeyAlgorithm::RsaPkcs1v15(RsaPkcs1v15SignatureKeyAlgorithm::Rs384),
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps256),
        ));
    }

    #[test]
    fn mixed_key_types_are_not_compatible() {
        assert!(!compatible_key_and_signature(
            SignatureKeyAlgorithm::Ec(EcSignatureKeyAlgorithm::P256),
            SignatureKeyAlgorithm::RsaPss(RsaPssSignatureKeyAlgorithm::Ps256),
        ));
    }
}
