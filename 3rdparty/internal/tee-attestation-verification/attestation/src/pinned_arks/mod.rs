// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pinned AMD Root Key (ARK) certificates for SEV-SNP verification.
//!
//! These certificates are embedded at compile time and used for offline verification
//! without requiring network access to AMD's KDS.

use crate::crypto::{Certificate, CertificateBackend, Crypto};
use crate::snp::model::Generation;

const MILAN_ARK_PEM: &[u8] = include_bytes!("milan_ark.pem");
const GENOA_ARK_PEM: &[u8] = include_bytes!("genoa_ark.pem");
const TURIN_ARK_PEM: &[u8] = include_bytes!("turin_ark.pem");

/// Get the pinned ARK certificate for a given processor generation.
pub fn get_ark(generation: Generation) -> Result<Certificate, Box<dyn std::error::Error>> {
    let pem_bytes = match generation {
        Generation::Milan => MILAN_ARK_PEM,
        Generation::Genoa => GENOA_ARK_PEM,
        Generation::Turin => TURIN_ARK_PEM,
        #[allow(unreachable_patterns)]
        _ => {
            return Err(format!(
                "No pinned ARK available for processor generation: {}",
                generation
            )
            .into())
        }
    };
    Crypto::from_pem(pem_bytes)
        .map_err(|e| format!("Failed to parse {} ARK certificate: {}", generation, e).into())
}
