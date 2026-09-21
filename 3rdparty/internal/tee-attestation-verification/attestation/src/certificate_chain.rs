// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(not(feature = "kds"))]
compile_error!("certificate_chain module requires the 'kds' feature");

#[cfg(async_crypto)]
use crate::crypto::AsyncCryptoBackend;
#[cfg(sync_crypto)]
use crate::crypto::CryptoBackend;
use crate::crypto::{Certificate, Crypto as ActiveCrypto};
use crate::kds::KdsFetcher;
#[cfg(sync_crypto)]
use crate::pinned_arks;
use crate::{snp, AttestationReport};
use log::info;
use std::collections::HashMap;
use std::mem::discriminant;

pub struct Chain {
    /// AMD Root Key (ARK) certificate
    pub ark: Certificate,
    /// AMD SEV Key (ASK) certificate
    pub ask: Certificate,
}

/// AMD certificate manager for SEV-SNP verification.
pub struct AmdCertificates {
    pub chains_cache: Vec<(snp::model::Generation, Chain)>,
    /// Versioned Chip Endorsement Key (VCEK) certificates by processor model
    vcek_cache: HashMap<String, Certificate>,
    /// Certificate fetcher
    fetcher: KdsFetcher,
}

impl AmdCertificates {
    /// Creates a new KDS-backed certificate manager.
    ///
    /// Certificate chains and VCEKs are fetched lazily when verification needs
    /// them.
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_cache(false).await
    }

    /// Creates a new KDS-backed certificate manager with optional KDS fetcher caching.
    ///
    /// Certificate chains and VCEKs are still cached by this manager after they
    /// are fetched; `use_cache` controls whether the underlying KDS fetcher uses
    /// its own cache.
    pub async fn with_cache(use_cache: bool) -> Result<Self, Box<dyn std::error::Error>> {
        // Create fetcher
        let fetcher = if use_cache {
            KdsFetcher::with_cache()
        } else {
            KdsFetcher::new()
        };

        Ok(Self {
            chains_cache: Vec::new(),
            vcek_cache: HashMap::new(),
            fetcher,
        })
    }

    /// Create a new AmdCertificates for offline verification using pinned ARKs.
    ///
    /// This constructor verifies the certificate chain upon instantiation:
    /// - Selects the ARK from pinned certificates based on the processor model in the report
    /// - Verifies that the ASK is signed by the ARK
    /// - Verifies that the VCEK is signed by the ASK
    ///
    /// # Arguments
    /// * `attestation_report` - The attestation report (used to determine processor model)
    /// * `ask` - The AMD SEV Key certificate (ASK)
    /// * `vcek` - The Versioned Chip Endorsement Key certificate (VCEK)
    ///
    /// # Returns
    /// A verified `AmdCertificates` instance, or an error if chain verification fails.
    #[cfg(sync_crypto)]
    pub fn from_certs(
        attestation_report: &AttestationReport,
        ask: Certificate,
        vcek: Certificate,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Determine processor generation from attestation report
        let processor_model = snp::model::Generation::from_family_and_model(
            attestation_report.cpuid_fam_id,
            attestation_report.cpuid_mod_id,
        )?;

        // Get pinned ARK for this processor generation
        let ark = pinned_arks::get_ark(processor_model)?;

        <ActiveCrypto as CryptoBackend>::verify_chain(&ark, &[&ask], &vcek, None)
            .map_err(|e| format!("Failed to verify certificate chain: {}", e))?;

        info!(
            "Certificate chain verified successfully for {} (using pinned ARK)",
            processor_model
        );

        // Build cache key from processor model and chip_id
        let cache_key = format!(
            "{}_{:02x?}",
            processor_model,
            &attestation_report.chip_id[..8]
        );

        let chain = Chain { ark, ask };
        let mut vcek_cache = HashMap::new();
        vcek_cache.insert(cache_key, vcek);

        Ok(Self {
            chains_cache: vec![(processor_model, chain)],
            vcek_cache,
            fetcher: KdsFetcher::new(),
        })
    }

    /// Get the VCEK certificate that was provided during construction (for offline verification).
    ///
    /// This method is intended for use with instances created via `from_certs`.
    #[cfg(sync_crypto)]
    pub fn get_vcek_sync(
        &self,
        processor_model: snp::model::Generation,
        attestation_report: &AttestationReport,
    ) -> Result<&Certificate, Box<dyn std::error::Error>> {
        let cache_key = format!(
            "{}_{:02x?}",
            processor_model,
            &attestation_report.chip_id[..8]
        );

        self.vcek_cache
            .get(&cache_key)
            .ok_or_else(|| format!("VCEK not found for cache key: {}", cache_key).into())
    }

    async fn get_chain(
        &mut self,
        processor_model: snp::model::Generation,
    ) -> Result<&Chain, Box<dyn std::error::Error>> {
        let existing_indx = self
            .chains_cache
            .iter()
            .position(|(gen, _)| discriminant(gen) == discriminant(&processor_model));

        if let Some(indx) = existing_indx {
            return Ok(&self.chains_cache[indx].1);
        }

        let (ark, ask) = self
            .fetcher
            .fetch_amd_chain(processor_model)
            .await
            .map_err(|e| format!("Error fetching chain: {}", e))?;

        <ActiveCrypto as AsyncCryptoBackend>::verify_chain(&ark, &[], &ask, None)
            .await
            .map_err(|e| format!("Failed to verify ASK signature: {}", e))?;

        let chain = Chain { ark, ask };

        self.chains_cache.push((processor_model, chain));
        Ok(&self.chains_cache.last().unwrap().1)
    }

    /// Get or fetch the VCEK certificate for a given processor model and attestation report
    pub async fn get_vcek(
        &mut self,
        processor_model: snp::model::Generation,
        attestation_report: &AttestationReport,
    ) -> Result<&Certificate, Box<dyn std::error::Error>> {
        // Build cache key from processor model and chip_id
        let cache_key = format!(
            "{}_{:02x?}",
            processor_model,
            &attestation_report.chip_id[..8]
        );

        // Check if we already have this VCEK
        if !self.vcek_cache.contains_key(&cache_key) {
            // Fetch the VCEK
            let vcek = self
                .fetcher
                .fetch_amd_vcek(processor_model, attestation_report)
                .await?;

            // Verify that VCEK is signed by ASK
            let chain = self.get_chain(processor_model).await?;
            <ActiveCrypto as AsyncCryptoBackend>::verify_chain(
                &chain.ark,
                &[&chain.ask],
                &vcek,
                None,
            )
            .await
            .map_err(|e| format!("Failed to verify certificate chain: {}", e))?;

            info!(
                "VCEK certificate verified successfully for {}",
                processor_model
            );

            // Store in cache
            self.vcek_cache.insert(cache_key.clone(), vcek);
        }

        // Return reference to cached VCEK
        Ok(self.vcek_cache.get(&cache_key).unwrap())
    }

    /// Check if a VCEK is already cached for the given processor model
    pub fn has_vcek(&self, processor_model: &str, attestation_report: &AttestationReport) -> bool {
        let cache_key = format!(
            "{}_{:02x?}",
            processor_model,
            &attestation_report.chip_id[..8]
        );
        self.vcek_cache.contains_key(&cache_key)
    }
}

/// Trait for fetching AMD certificates from a certificate source
pub(crate) trait CertificateFetcher {
    /// Fetch AMD certificate chain (ARK and ASK)
    async fn fetch_amd_chain(
        &mut self,
        model: snp::model::Generation,
    ) -> Result<(Certificate, Certificate), Box<dyn std::error::Error>>;

    /// Fetch VCEK certificate for a given processor model and attestation report
    async fn fetch_amd_vcek(
        &mut self,
        model: snp::model::Generation,
        attestation_report: &AttestationReport,
    ) -> Result<Certificate, Box<dyn std::error::Error>>;
}
