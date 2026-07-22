// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Portable TEE attestation verification library.
//!
//! This crate verifies AMD SEV-SNP attestation reports and certificate
//! collateral. It supports native and WASM environments through selectable
//! crypto backends.
//!
//! # Feature flags
//!
//! At least one target-compatible crypto backend feature must be enabled.
//!
//! ## Crypto backends
//!
//! - `crypto_openssl`: native OpenSSL-backed verification.
//! - `crypto_webcrypto`: WASM WebCrypto-backed verification.
//! - `crypto_pure_rust`: portable pure-Rust verification, selected when no target-preferred backend is enabled.
//!
//! ## Additional features
//!
//! - `kds`: enables certificate fetching from AMD KDS.
//!
//! # Usage
//!
//! [`AttestationReport`] provides the parsing and inspection APIs for SEV-SNP attestation reports.
//!
//! [`snp::verify`] is used to verify reports using provided collateral.
//!
//! ```no_run
//! use tee_attestation_verification_lib::certificate_from_pem;
//! use tee_attestation_verification_lib::snp::report::{AttestationReport, TryFromBytes};
//! use tee_attestation_verification_lib::snp::verify::{asynchronous as tav, ChainVerification};
//!
//! # async fn example<'a>(
//! #     attestation_bytes: &'a [u8],
//! #     vcek_pem: &'a [u8],
//! #     ask_pem: &'a [u8],
//! # ) -> Result<(), Box<dyn std::error::Error + 'a>> {
//! let attestation_report = AttestationReport::try_read_from_bytes(attestation_bytes)?;
//! let vcek = certificate_from_pem(vcek_pem)?;
//! let ask = certificate_from_pem(ask_pem)?;
//!
//! tav::verify_attestation(
//!     &attestation_report,
//!     &vcek,
//!     &ChainVerification::WithPinnedArk { ask: &ask },
//! )
//! .await?;
//! # Ok(())
//! # }
//! ```
//!

pub(crate) use crypto;
pub mod pinned_arks;
pub mod snp;

use crypto::{CertificateBackend, Crypto};

pub use crypto::Certificate;
pub use snp::report::AttestationReport;
pub use snp::{Cpuid, Generation};

/// Parses a PEM-encoded X.509 certificate using the enabled crypto backend.
///
/// The returned [`Certificate`] can be passed to the SEV-SNP verification APIs
/// in [`snp::verify`].
pub fn certificate_from_pem(pem: &[u8]) -> Result<Certificate, Box<dyn std::error::Error>> {
    Crypto::from_pem(pem)
}

/// Parses a DER-encoded X.509 certificate using the enabled crypto backend.
///
/// The returned [`Certificate`] can be passed to the SEV-SNP verification APIs
/// in [`snp::verify`].
pub fn certificate_from_der(der: &[u8]) -> Result<Certificate, Box<dyn std::error::Error>> {
    Crypto::from_der(der)
}

#[cfg(feature = "kds")]
mod certificate_chain;
#[cfg(feature = "kds")]
mod kds;
#[cfg(feature = "kds")]
pub mod sev_verification;
#[cfg(feature = "kds")]
pub use certificate_chain::AmdCertificates;
#[cfg(feature = "kds")]
pub use sev_verification::SevVerifier;

#[cfg(all(target_arch = "wasm32", feature = "kds"))]
pub mod wasm;

#[cfg(test)]
mod tests {
    use crate::crypto::CertificateBackend;

    const MILAN_VCEK: &[u8] = include_bytes!("../tests/test_data/milan_vcek.pem");

    #[test]
    fn certificate_from_der_parses_der_encoded_certificate() {
        let cert = crate::certificate_from_pem(MILAN_VCEK).expect("PEM certificate should parse");
        let der = crate::crypto::Crypto::to_der(&cert).expect("DER encoding should succeed");
        let reparsed = crate::certificate_from_der(&der).expect("DER certificate should parse");

        assert_eq!(
            crate::crypto::Crypto::to_der(&reparsed).expect("Reparsed DER should encode"),
            der
        );
    }
}
