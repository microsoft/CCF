// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AMD SEV-SNP attestation report structures.
//!
//! [`crate::snp::report::AttestationReport`] mirrors the AMD SEV-SNP ABI report
//! layout and can be parsed directly from the raw 1184-byte report buffer using
//! `zerocopy`'s [`zerocopy::TryFromBytes`] trait.
//!
//! # Example
//!
//! Verify an attestation report before returning the authenticated claims to the caller:
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
//! # ) -> Result<AttestationReport, Box<dyn std::error::Error + 'a>> {
//! let report = AttestationReport::try_read_from_bytes(attestation_bytes)?;
//! let vcek = certificate_from_pem(vcek_pem)?;
//! let ask = certificate_from_pem(ask_pem)?;
//!
//! tav::verify_attestation(
//!     &report,
//!     &vcek,
//!     &ChainVerification::WithPinnedArk { ask: &ask },
//! )
//! .await?;
//!
//! # Ok(report)
//! # }
//! ```

pub use zerocopy::TryFromBytes;
use zerocopy::{
    byteorder::little_endian as le, try_transmute, FromBytes, Immutable, IntoBytes, KnownLayout,
    Unaligned,
};

use crate::snp::Generation;

// ---------------------------------------------------------------------------
// Decoded bitfield types
// ---------------------------------------------------------------------------

/// Decoded guest policy from the 64-bit policy field.
///
/// See AMD SEV-SNP ABI Specification, Table 9: GUEST_POLICY Structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct GuestPolicy(u64);

impl GuestPolicy {
    const ABI_MINOR_MASK: u64 = 0xFF;
    const ABI_MAJOR_MASK: u64 = 0xFF << 8;
    const SMT_BIT: u64 = 1 << 16;
    const MIGRATE_MA_BIT: u64 = 1 << 18;
    const DEBUG_BIT: u64 = 1 << 19;
    const SINGLE_SOCKET_BIT: u64 = 1 << 20;
    const CXL_ALLOW_BIT: u64 = 1 << 21;
    const MEM_AES_256_XTS_BIT: u64 = 1 << 22;
    const RAPL_DIS_BIT: u64 = 1 << 23;
    const CIPHERTEXT_HIDING_DRAM_BIT: u64 = 1 << 24;
    const PAGE_SWAP_DISABLE_BIT: u64 = 1 << 25;

    /// Wraps the raw 64-bit guest policy field.
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw 64-bit guest policy field.
    pub fn raw(&self) -> u64 {
        self.0
    }

    /// Returns the minimum ABI minor version required by the guest.
    pub fn abi_minor(&self) -> u8 {
        (self.0 & Self::ABI_MINOR_MASK) as u8
    }

    /// Returns the minimum ABI major version required by the guest.
    pub fn abi_major(&self) -> u8 {
        ((self.0 & Self::ABI_MAJOR_MASK) >> 8) as u8
    }

    /// Returns whether simultaneous multithreading is allowed.
    pub fn smt(&self) -> bool {
        self.0 & Self::SMT_BIT != 0
    }

    /// Returns whether association with a migration agent is allowed.
    pub fn migrate_ma(&self) -> bool {
        self.0 & Self::MIGRATE_MA_BIT != 0
    }

    /// Returns whether debug mode is allowed.
    pub fn debug(&self) -> bool {
        self.0 & Self::DEBUG_BIT != 0
    }

    /// Returns whether the guest must run on a single socket.
    pub fn single_socket(&self) -> bool {
        self.0 & Self::SINGLE_SOCKET_BIT != 0
    }

    /// Returns whether CXL devices are allowed.
    pub fn cxl_allow(&self) -> bool {
        self.0 & Self::CXL_ALLOW_BIT != 0
    }

    /// Returns whether 256-bit AES-XTS memory encryption is required.
    pub fn mem_aes_256_xts(&self) -> bool {
        self.0 & Self::MEM_AES_256_XTS_BIT != 0
    }

    /// Returns whether RAPL is disabled.
    pub fn rapl_dis(&self) -> bool {
        self.0 & Self::RAPL_DIS_BIT != 0
    }

    /// Returns whether ciphertext hiding for DRAM is enabled.
    pub fn ciphertext_hiding_dram(&self) -> bool {
        self.0 & Self::CIPHERTEXT_HIDING_DRAM_BIT != 0
    }

    /// Returns whether page swapping is disabled.
    pub fn page_swap_disable(&self) -> bool {
        self.0 & Self::PAGE_SWAP_DISABLE_BIT != 0
    }
}

/// The key type used to sign the attestation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKey {
    /// Versioned Chip Endorsement Key.
    Vcek,
    /// Versioned Loaded Endorsement Key.
    Vlek,
    /// No signing key is indicated.
    None,
    /// Reserved signing-key encoding from the report.
    Reserved(u8),
}

impl SigningKey {
    /// Decodes the raw signing-key field from report flags.
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Vcek,
            1 => Self::Vlek,
            7 => Self::None,
            value => Self::Reserved(value),
        }
    }

    /// Returns the raw signing-key encoding.
    pub fn raw(&self) -> u8 {
        match self {
            Self::Vcek => 0,
            Self::Vlek => 1,
            Self::None => 7,
            Self::Reserved(value) => *value,
        }
    }
}

/// Decoded flags field from the attestation report.
///
/// See AMD SEV-SNP ABI Specification, Table 23: ATTESTATION_REPORT Structure,
/// flags field description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ReportFlags(u32);

impl ReportFlags {
    const AUTHOR_KEY_EN_BIT: u32 = 1;
    const MASK_CHIP_KEY_BIT: u32 = 1 << 1;
    const SIGNING_KEY_MASK: u32 = 0b111 << 2;

    /// Wraps the raw 32-bit report flags field.
    pub fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw 32-bit report flags field.
    pub fn raw(&self) -> u32 {
        self.0
    }

    /// Returns whether the report includes an author key digest.
    pub fn author_key_en(&self) -> bool {
        self.0 & Self::AUTHOR_KEY_EN_BIT != 0
    }

    /// Returns whether the chip ID is masked in the report.
    pub fn mask_chip_key(&self) -> bool {
        self.0 & Self::MASK_CHIP_KEY_BIT != 0
    }

    /// Returns the decoded signing key used for the report.
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_raw(((self.0 & Self::SIGNING_KEY_MASK) >> 2) as u8)
    }
}

// ---------------------------------------------------------------------------
// TCB version types
// ---------------------------------------------------------------------------

/// TCB version layout used by Milan and Genoa processors.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes)]
#[repr(C)]
pub struct TcbVersionMilanGenoa {
    /// Boot loader security version number.
    pub boot_loader: u8,
    /// TEE security version number.
    pub tee: u8,
    reserved: [u8; 4],
    /// SNP firmware security version number.
    pub snp: u8,
    /// Microcode security version number.
    pub microcode: u8,
}

impl PartialEq for TcbVersionMilanGenoa {
    fn eq(&self, other: &Self) -> bool {
        self.boot_loader == other.boot_loader
            && self.tee == other.tee
            && self.snp == other.snp
            && self.microcode == other.microcode
    }
}

impl Eq for TcbVersionMilanGenoa {}

impl PartialOrd for TcbVersionMilanGenoa {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        partial_cmp_tcb_fields(&[
            self.boot_loader.cmp(&other.boot_loader),
            self.tee.cmp(&other.tee),
            self.snp.cmp(&other.snp),
            self.microcode.cmp(&other.microcode),
        ])
    }
}

/// TCB version layout used by Turin processors.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes)]
#[repr(C)]
pub struct TcbVersionTurin {
    /// Firmware microcontroller security version number.
    pub fmc: u8,
    /// Boot loader security version number.
    pub boot_loader: u8,
    /// TEE security version number.
    pub tee: u8,
    /// SNP firmware security version number.
    pub snp: u8,
    reserved: [u8; 3],
    /// Microcode security version number.
    pub microcode: u8,
}

impl PartialEq for TcbVersionTurin {
    fn eq(&self, other: &Self) -> bool {
        self.fmc == other.fmc
            && self.boot_loader == other.boot_loader
            && self.tee == other.tee
            && self.snp == other.snp
            && self.microcode == other.microcode
    }
}

impl Eq for TcbVersionTurin {}

impl PartialOrd for TcbVersionTurin {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        partial_cmp_tcb_fields(&[
            self.fmc.cmp(&other.fmc),
            self.boot_loader.cmp(&other.boot_loader),
            self.tee.cmp(&other.tee),
            self.snp.cmp(&other.snp),
            self.microcode.cmp(&other.microcode),
        ])
    }
}

fn partial_cmp_tcb_fields(field_orderings: &[std::cmp::Ordering]) -> Option<std::cmp::Ordering> {
    let has_less = field_orderings.contains(&std::cmp::Ordering::Less);
    let has_greater = field_orderings.contains(&std::cmp::Ordering::Greater);
    match (has_less, has_greater) {
        (false, false) => Some(std::cmp::Ordering::Equal),
        (true, false) => Some(std::cmp::Ordering::Less),
        (false, true) => Some(std::cmp::Ordering::Greater),
        (true, true) => None,
    }
}

/// Raw 8-byte TCB version field from an attestation report.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Default, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct TcbVersionRaw {
    /// Raw TCB bytes in report layout order.
    pub raw: [u8; 8],
}

/// A TCB version interpreted for a specific CPU generation.
#[derive(Clone, Copy, Debug)]
pub struct TcbVersionForGeneration {
    pub generation: Generation,
    pub tcb: TcbVersionRaw,
}

impl TcbVersionForGeneration {
    pub const fn new(tcb: TcbVersionRaw, generation: Generation) -> Self {
        Self { generation, tcb }
    }
}

impl PartialEq for TcbVersionForGeneration {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
            && match self.generation {
                Generation::Milan | Generation::Genoa => {
                    self.tcb.as_milan_genoa() == other.tcb.as_milan_genoa()
                }
                Generation::Turin => self.tcb.as_turin() == other.tcb.as_turin(),
            }
    }
}

impl Eq for TcbVersionForGeneration {}

impl PartialOrd for TcbVersionForGeneration {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.generation != other.generation {
            return None;
        }

        match self.generation {
            Generation::Milan | Generation::Genoa => self
                .tcb
                .as_milan_genoa()
                .partial_cmp(&other.tcb.as_milan_genoa()),
            Generation::Turin => self.tcb.as_turin().partial_cmp(&other.tcb.as_turin()),
        }
    }
}

impl TcbVersionRaw {
    /// Interprets the raw bytes using the Milan/Genoa TCB layout.
    pub fn as_milan_genoa(&self) -> TcbVersionMilanGenoa {
        try_transmute!(*self).unwrap()
    }

    /// Interprets the raw bytes using the Turin TCB layout.
    pub fn as_turin(&self) -> TcbVersionTurin {
        try_transmute!(*self).unwrap()
    }
}

/// ECDSA signature field from an SEV-SNP attestation report.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct Signature {
    /// Signature `r` component in the report's little-endian padded encoding.
    pub r: [u8; 72],
    /// Signature `s` component in the report's little-endian padded encoding.
    pub s: [u8; 72],
    reserved: [u8; 512 - 144],
}

const ECDSA_P384_SCALAR_SIZE: usize = 48;
const SNP_ECDSA_P384_SCALAR_SIZE: usize = 72;

impl Signature {
    fn to_ecdsa_components(
        self,
    ) -> crypto::Result<([u8; ECDSA_P384_SCALAR_SIZE], [u8; ECDSA_P384_SCALAR_SIZE])> {
        let r = snp_ecdsa_p384_scalar_to_fixed("r", &self.r)?;
        let s = snp_ecdsa_p384_scalar_to_fixed("s", &self.s)?;

        Ok((r, s))
    }
}

fn snp_ecdsa_p384_scalar_to_fixed(
    name: &str,
    scalar: &[u8; SNP_ECDSA_P384_SCALAR_SIZE],
) -> crypto::Result<[u8; ECDSA_P384_SCALAR_SIZE]> {
    if scalar[ECDSA_P384_SCALAR_SIZE..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(format!(
            "Invalid {name} scalar padding: upper 24 bytes must be zero for P-384 signatures"
        )
        .into());
    }

    let mut fixed: [u8; ECDSA_P384_SCALAR_SIZE] = scalar[..ECDSA_P384_SCALAR_SIZE]
        .try_into()
        .map_err(|_| format!("Invalid {name} scalar length"))?;
    fixed.reverse();
    Ok(fixed)
}

/// SEV-SNP attestation report (0x4A0 = 1184 bytes).
///
/// See AMD SEV-SNP ABI Specification, Table 23: ATTESTATION_REPORT Structure.
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct AttestationReport {
    /// Version number of this attestation report. Set to 0x03 for this specification.
    pub version: le::U32, // 0x000

    /// The guest SVN (Security Version Number).
    pub guest_svn: le::U32, // 0x004

    /// The guest policy. See Table 10 for a description of the guest policy structure.
    pub policy: le::U64, // 0x008

    /// The family ID provided at launch.
    pub family_id: [u8; 16], // 0x010

    /// The image ID provided at launch.
    pub image_id: [u8; 16], // 0x020

    /// The VMPL (Virtual Machine Privilege Level) for this report.
    ///
    /// For a guest-requested attestation report (MSG_REPORT_REQ), this field contains
    /// the value 0-3. A host-requested attestation report (SNP_HV_REPORT_REQ) will
    /// have a value of 0xFFFFFFFF.
    pub vmpl: le::U32, // 0x030

    /// The signature algorithm used to sign this report. See Chapter 10 for encodings.
    pub signature_algo: le::U32, // 0x034

    /// Current TCB (Trusted Computing Base) version.
    pub platform_version: TcbVersionRaw, // 0x038

    /// Information about the platform. See Table 24.
    pub platform_info: le::U64, // 0x040

    /// Flags field containing:
    /// - Bits 31:5: Reserved (must be zero)
    /// - Bits 4:2 (SIGNING_KEY): Encodes the key used to sign this report
    ///   (0=VCEK, 1=VLEK, 2-6=Reserved, 7=None)
    /// - Bit 1 (MASK_CHIP_KEY): The value of MaskChipKey
    /// - Bit 0 (AUTHOR_KEY_EN): Indicates that the digest of the author key is present
    ///   in AUTHOR_KEY_DIGEST. Set to the value of GCTX.AuthorKeyEn.
    pub flags: le::U32, // 0x048

    /// Reserved. Must be zero.
    pub reserved0: le::U32, // 0x04C

    /// Guest-provided data if REQUEST_SOURCE is guest, otherwise zero-filled by firmware.
    ///
    /// Verification authenticates this value as part of the signed report, but
    /// callers are responsible for comparing it to their expected nonce,
    /// challenge, public-key digest, or other application-specific context.
    pub report_data: [u8; 64], // 0x050

    /// The measurement calculated at launch.
    pub measurement: [u8; 48], // 0x090

    /// Data provided by the hypervisor at launch.
    pub host_data: [u8; 32], // 0x0C0

    /// SHA-384 digest of the ID public key that signed the ID block provided in SNP_LAUNCH_FINISH.
    pub id_key_digest: [u8; 48], // 0x0E0

    /// SHA-384 digest of the Author public key that certified the ID key, if provided
    /// in SNP_LAUNCH_FINISH. Zeroes if AUTHOR_KEY_EN is 0.
    pub author_key_digest: [u8; 48], // 0x110

    /// Report ID of this guest.
    pub report_id: [u8; 32], // 0x140

    /// Report ID of this guest's migration agent.
    pub report_id_ma: [u8; 32], // 0x160

    /// Reported TCB version used to derive the VCEK that signed this report.
    pub reported_tcb: TcbVersionRaw, // 0x180

    /// CPUID Family ID (combined Extended Family ID and Family ID).
    pub cpuid_fam_id: u8, // 0x188

    /// CPUID Model (combined Extended Model and Model fields).
    pub cpuid_mod_id: u8, // 0x189

    /// CPUID Stepping.
    pub cpuid_step: u8, // 0x18A

    /// Reserved.
    pub reserved1: [u8; 21], // 0x18B

    /// If MaskChipId is set to 0, identifier unique to the chip as output by GET_ID.
    /// Otherwise, set to 0h.
    pub chip_id: [u8; 64], // 0x1A0

    /// Committed TCB version.
    pub committed_tcb: TcbVersionRaw, // 0x1E0

    /// The build number of CurrentVersion.
    pub current_build: u8, // 0x1E8

    /// The minor number of CurrentVersion.
    pub current_minor: u8, // 0x1E9

    /// The major number of CurrentVersion.
    pub current_major: u8, // 0x1EA

    /// Reserved.
    pub reserved2: u8, // 0x1EB

    /// The build number of CommittedVersion.
    pub committed_build: u8, // 0x1EC

    /// The minor version of CommittedVersion.
    pub committed_minor: u8, // 0x1ED

    /// The major version of CommittedVersion.
    pub committed_major: u8, // 0x1EE

    /// Reserved.
    pub reserved3: u8, // 0x1EF

    /// The CurrentTcb at the time the guest was launched or imported.
    pub launch_tcb: TcbVersionRaw, // 0x1F0

    /// Reserved.
    pub reserved4: [u8; 168], // 0x1F8

    /// Signature of bytes 0x00 to 0x29F inclusive of this report.
    /// The format of the signature is described in Chapter 10.
    pub signature: Signature, // 0x2A0
}

impl AttestationReport {
    /// Returns the signed portion of the report (everything before the signature).
    pub fn signed_bytes(&self) -> &[u8] {
        let bytes = self.as_bytes();
        &bytes[..0x2A0]
    }

    /// Returns the decoded guest policy bitfield.
    pub fn policy(&self) -> GuestPolicy {
        GuestPolicy::from_raw(self.policy.get())
    }

    /// Returns the decoded report flags bitfield.
    pub fn flags(&self) -> ReportFlags {
        ReportFlags::from_raw(self.flags.get())
    }

    /// Returns the CPU generation indicated by this report's CPUID family and model fields.
    pub fn cpu_generation(&self) -> Result<Generation, Box<dyn std::error::Error>> {
        Generation::from_family_and_model(self.cpuid_fam_id, self.cpuid_mod_id)
    }
}

#[cfg(sync_crypto)]
pub(crate) fn verify_report_signature(
    cert: &crate::Certificate,
    report: &AttestationReport,
) -> crypto::Result<()> {
    match report.signature_algo.get() {
        0x0001 => {
            let (r, s) = report.signature.to_ecdsa_components()?;
            let algorithm = crypto::EcSignatureKeyAlgorithm::P384;
            let signature = <crypto::Signature as crypto::SignatureBackend>::from_ec_components(
                &r, &s, algorithm,
            )?;
            let spki_der = <crypto::Crypto as crypto::CertificateBackend>::get_public_key(cert)?;
            let key = <crypto::Key as crypto::KeyBackend>::from_spki_der(
                &spki_der,
                crypto::SignatureKeyAlgorithm::Ec(algorithm),
            )?;

            <crypto::Crypto as crypto::CryptoBackend>::verify_signature(
                &key,
                &signature,
                report.signed_bytes(),
            )
        }
        _ => Err(format!(
            "Unsupported signature algorithm: 0x{:04X}",
            report.signature_algo.get()
        )
        .into()),
    }
}

#[cfg(async_crypto)]
pub(crate) async fn verify_report_signature_async(
    cert: &crate::Certificate,
    report: &AttestationReport,
) -> crypto::Result<()> {
    match report.signature_algo.get() {
        0x0001 => {
            let (r, s) = report.signature.to_ecdsa_components()?;
            let algorithm = crypto::EcSignatureKeyAlgorithm::P384;
            let signature = <crypto::Signature as crypto::SignatureBackend>::from_ec_components(
                &r, &s, algorithm,
            )?;
            let spki_der = <crypto::Crypto as crypto::CertificateBackend>::get_public_key(cert)?;
            let key = <crypto::Key as crypto::AsyncKeyBackend>::from_spki_der(
                &spki_der,
                crypto::SignatureKeyAlgorithm::Ec(algorithm),
            )
            .await?;

            <crypto::Crypto as crypto::AsyncCryptoBackend>::verify_signature(
                &key,
                &signature,
                report.signed_bytes(),
            )
            .await
        }
        _ => Err(format!(
            "Unsupported signature algorithm: 0x{:04X}",
            report.signature_algo.get()
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CertificateBackend, Crypto};
    use std::mem::size_of;

    const MILAN_VCEK: &[u8] = include_bytes!("../../tests/test_data/milan_vcek.pem");
    const GENOA_VCEK: &[u8] = include_bytes!("../../tests/test_data/genoa_vcek.pem");
    const MILAN_REPORT: &[u8] =
        include_bytes!("../../tests/test_data/milan_attestation_report.bin");

    fn cert(pem: &[u8]) -> crate::Certificate {
        Crypto::from_pem(pem).unwrap()
    }

    fn report() -> AttestationReport {
        AttestationReport::try_read_from_bytes(MILAN_REPORT)
            .expect("Failed to parse attestation report")
            .clone()
    }

    #[test]
    fn attestation_report_size() {
        assert_eq!(size_of::<AttestationReport>(), 0x4A0);
    }

    #[cfg(sync_crypto)]
    mod sync_verifier_tests {
        use super::*;

        #[test]
        fn attestation_report_signature_verifies() {
            verify_report_signature(&cert(MILAN_VCEK), &report()).unwrap();
        }

        #[test]
        fn corrupted_report_fails_to_verify() {
            let vcek = cert(MILAN_VCEK);
            let mut report = report();

            let report_bytes = report.as_mut_bytes();
            report_bytes[100] ^= 0xFF;

            verify_report_signature(&vcek, &report)
                .expect_err("Corrupted report should not verify");
        }

        #[test]
        fn corrupt_signature_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report = report();

            report.signature.r[0] ^= 0xFF;

            verify_report_signature(&vcek, &report)
                .expect_err("Corrupt signature should not verify");
        }

        #[test]
        fn zeroed_signature_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report = report();

            report.signature.r.fill(0);
            report.signature.s.fill(0);

            verify_report_signature(&vcek, &report)
                .expect_err("Zeroed signature should not verify");
        }

        #[cfg(all(feature = "crypto_pure_rust", not(feature = "crypto_openssl")))]
        #[test]
        fn nonzero_r_scalar_padding_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report = report();

            report.signature.r[48] = 1;

            let err = verify_report_signature(&vcek, &report)
                .expect_err("Nonzero r scalar padding should not verify");
            assert!(
                err.to_string().contains("Invalid r scalar padding"),
                "expected r scalar padding error, got: {err}"
            );
        }

        #[cfg(all(feature = "crypto_pure_rust", not(feature = "crypto_openssl")))]
        #[test]
        fn nonzero_s_scalar_padding_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report = report();

            report.signature.s[48] = 1;

            let err = verify_report_signature(&vcek, &report)
                .expect_err("Nonzero s scalar padding should not verify");
            assert!(
                err.to_string().contains("Invalid s scalar padding"),
                "expected s scalar padding error, got: {err}"
            );
        }

        #[test]
        fn wrong_cert_rejects_signature() {
            verify_report_signature(&cert(GENOA_VCEK), &report())
                .expect_err("Wrong cert should not verify report");
        }
    }

    #[cfg(all(async_crypto, not(sync_crypto)))]
    mod async_verifier_tests {
        use super::*;

        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::wasm_bindgen_test;

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn attestation_report_signature_verifies() {
            verify_report_signature_async(&cert(MILAN_VCEK), &report())
                .await
                .unwrap();
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn corrupted_report_fails_to_verify() {
            let vcek = cert(MILAN_VCEK);
            let mut report = report();

            let report_bytes = report.as_mut_bytes();
            report_bytes[100] ^= 0xFF;

            verify_report_signature_async(&vcek, &report)
                .await
                .expect_err("Corrupted report should not verify");
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn corrupt_signature_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report = report();

            report.signature.r[0] ^= 0xFF;

            verify_report_signature_async(&vcek, &report)
                .await
                .expect_err("Corrupt signature should not verify");
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn zeroed_signature_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report = report();

            report.signature.r.fill(0);
            report.signature.s.fill(0);

            verify_report_signature_async(&vcek, &report)
                .await
                .expect_err("Zeroed signature should not verify");
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn non_zero_scalar_padding_fails() {
            let vcek = cert(MILAN_VCEK);
            let mut report = report();

            report.signature.r[60] = 1;

            let error = verify_report_signature_async(&vcek, &report)
                .await
                .expect_err("Non-zero scalar padding should not verify");

            assert!(
                error.to_string().contains("Invalid r scalar padding"),
                "Expected scalar padding error, got: {error:?}"
            );
        }

        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
        async fn wrong_cert_rejects_signature() {
            verify_report_signature_async(&cert(GENOA_VCEK), &report())
                .await
                .expect_err("Wrong cert should not verify report");
        }
    }

    #[test]
    fn signature_size() {
        assert_eq!(size_of::<Signature>(), 512);
    }

    #[test]
    fn guest_policy_accessors() {
        let raw = 0x12_u64
            | (0x34_u64 << 8)
            | (1_u64 << 16)
            | (1_u64 << 18)
            | (1_u64 << 19)
            | (1_u64 << 20)
            | (1_u64 << 21)
            | (1_u64 << 22)
            | (1_u64 << 23)
            | (1_u64 << 24)
            | (1_u64 << 25);
        let policy = GuestPolicy::from_raw(raw);

        assert_eq!(policy.raw(), raw);
        assert_eq!(policy.abi_minor(), 0x12);
        assert_eq!(policy.abi_major(), 0x34);
        assert!(policy.smt());
        assert!(policy.migrate_ma());
        assert!(policy.debug());
        assert!(policy.single_socket());
        assert!(policy.cxl_allow());
        assert!(policy.mem_aes_256_xts());
        assert!(policy.rapl_dis());
        assert!(policy.ciphertext_hiding_dram());
        assert!(policy.page_swap_disable());
    }

    #[test]
    fn guest_policy_all_clear() {
        let policy = GuestPolicy::from_raw(0);
        assert_eq!(policy.abi_minor(), 0);
        assert_eq!(policy.abi_major(), 0);
        assert!(!policy.smt());
        assert!(!policy.migrate_ma());
        assert!(!policy.debug());
        assert!(!policy.single_socket());
        assert!(!policy.cxl_allow());
        assert!(!policy.mem_aes_256_xts());
        assert!(!policy.rapl_dis());
        assert!(!policy.ciphertext_hiding_dram());
        assert!(!policy.page_swap_disable());
    }

    #[test]
    fn guest_policy_each_bit_individually() {
        let bit_accessors: &[(u64, fn(&GuestPolicy) -> bool)] = &[
            (1 << 16, GuestPolicy::smt),
            (1 << 18, GuestPolicy::migrate_ma),
            (1 << 19, GuestPolicy::debug),
            (1 << 20, GuestPolicy::single_socket),
            (1 << 21, GuestPolicy::cxl_allow),
            (1 << 22, GuestPolicy::mem_aes_256_xts),
            (1 << 23, GuestPolicy::rapl_dis),
            (1 << 24, GuestPolicy::ciphertext_hiding_dram),
            (1 << 25, GuestPolicy::page_swap_disable),
        ];

        for (i, (bit, accessor)) in bit_accessors.iter().enumerate() {
            let policy = GuestPolicy::from_raw(*bit);
            assert!(
                accessor(&policy),
                "accessor at index {i} should be true when its bit is set"
            );
            for (j, (_, other_accessor)) in bit_accessors.iter().enumerate() {
                if i != j {
                    assert!(
                        !other_accessor(&policy),
                        "accessor at index {j} should be false when only bit {i} is set"
                    );
                }
            }
        }
    }

    #[test]
    fn report_flags_accessors() {
        let flags = ReportFlags::from_raw((1_u32 << 0) | (1_u32 << 1) | (1_u32 << 2));

        assert_eq!(flags.raw(), 0b111);
        assert!(flags.author_key_en());
        assert!(flags.mask_chip_key());
        assert_eq!(flags.signing_key(), SigningKey::Vlek);

        let reserved = ReportFlags::from_raw(5_u32 << 2);
        assert_eq!(reserved.signing_key(), SigningKey::Reserved(5));

        let none = ReportFlags::from_raw(7_u32 << 2);
        assert_eq!(none.signing_key(), SigningKey::None);
    }

    #[test]
    fn signing_key_round_trip() {
        for raw in 0..=7u8 {
            let key = SigningKey::from_raw(raw);
            assert_eq!(key.raw(), raw);
        }
    }

    fn milan_genoa_tcb(boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> TcbVersionMilanGenoa {
        TcbVersionMilanGenoa {
            boot_loader,
            tee,
            reserved: [0; 4],
            snp,
            microcode,
        }
    }

    fn turin_tcb(fmc: u8, boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> TcbVersionTurin {
        TcbVersionTurin {
            fmc,
            boot_loader,
            tee,
            snp,
            reserved: [0; 3],
            microcode,
        }
    }

    #[test]
    fn milan_genoa_tcb_versions_compare_component_wise() {
        let baseline = milan_genoa_tcb(1, 2, 3, 4);
        let higher = milan_genoa_tcb(2, 2, 4, 4);
        let lower = milan_genoa_tcb(1, 1, 3, 3);
        let mixed = milan_genoa_tcb(2, 1, 3, 4);
        let mut same_fields_different_reserved = baseline;
        same_fields_different_reserved.reserved = [9; 4];

        assert_eq!(baseline, same_fields_different_reserved);
        assert!(higher > baseline);
        assert!(lower < baseline);
        assert!(mixed.partial_cmp(&baseline).is_none());
        assert!(!(mixed >= baseline));
        assert!(!(mixed <= baseline));
    }

    #[test]
    fn turin_tcb_versions_compare_component_wise() {
        let baseline = turin_tcb(1, 2, 3, 4, 5);
        let higher = turin_tcb(1, 3, 3, 5, 5);
        let lower = turin_tcb(0, 2, 2, 4, 5);
        let mixed = turin_tcb(2, 2, 2, 4, 5);
        let mut same_fields_different_reserved = baseline;
        same_fields_different_reserved.reserved = [9; 3];

        assert_eq!(baseline, same_fields_different_reserved);
        assert!(higher > baseline);
        assert!(lower < baseline);
        assert!(mixed.partial_cmp(&baseline).is_none());
        assert!(!(mixed >= baseline));
        assert!(!(mixed <= baseline));
    }

    fn raw_milan_genoa_tcb(boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> TcbVersionRaw {
        TcbVersionRaw {
            raw: [boot_loader, tee, 0, 0, 0, 0, snp, microcode],
        }
    }

    fn raw_turin_tcb(fmc: u8, boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> TcbVersionRaw {
        TcbVersionRaw {
            raw: [fmc, boot_loader, tee, snp, 0, 0, 0, microcode],
        }
    }

    #[test]
    fn raw_tcb_versions_compare_for_generation() {
        let genoa_baseline =
            TcbVersionForGeneration::new(raw_milan_genoa_tcb(1, 2, 3, 4), Generation::Genoa);
        let genoa_higher =
            TcbVersionForGeneration::new(raw_milan_genoa_tcb(1, 3, 3, 5), Generation::Genoa);
        let genoa_mixed =
            TcbVersionForGeneration::new(raw_milan_genoa_tcb(2, 1, 3, 4), Generation::Genoa);
        let turin_higher =
            TcbVersionForGeneration::new(raw_turin_tcb(1, 3, 3, 5, 5), Generation::Turin);

        assert!(genoa_baseline < genoa_higher);
        assert!(genoa_mixed.partial_cmp(&genoa_baseline).is_none());
        assert!(genoa_baseline.partial_cmp(&turin_higher).is_none());
    }

    #[test]
    fn attestation_report_policy_and_flags_accessors() {
        let mut bytes = [0_u8; size_of::<AttestationReport>()];
        let policy_raw = 0x5A_u64 | (0xA5_u64 << 8) | (1_u64 << 16) | (1_u64 << 25);
        let flags_raw = (1_u32 << 0) | (7_u32 << 2);

        bytes[0x008..0x010].copy_from_slice(&policy_raw.to_le_bytes());
        bytes[0x048..0x04C].copy_from_slice(&flags_raw.to_le_bytes());

        let report = AttestationReport::ref_from_bytes(&bytes).unwrap();

        assert_eq!(report.policy().raw(), policy_raw);
        assert_eq!(report.policy().abi_minor(), 0x5A);
        assert_eq!(report.policy().abi_major(), 0xA5);
        assert!(report.policy().smt());
        assert!(report.policy().page_swap_disable());

        assert_eq!(report.flags().raw(), flags_raw);
        assert!(report.flags().author_key_en());
        assert!(!report.flags().mask_chip_key());
        assert_eq!(report.flags().signing_key(), SigningKey::None);
    }

    #[test]
    fn attestation_report_returns_cpu_generation() {
        let mut bytes = [0_u8; size_of::<AttestationReport>()];

        bytes[0x188] = 0x19;
        bytes[0x189] = 0x11;
        let report = AttestationReport::ref_from_bytes(&bytes).unwrap();
        assert_eq!(report.cpu_generation().unwrap(), Generation::Genoa);

        bytes[0x188] = 0x1A;
        bytes[0x189] = 0x11;
        let report = AttestationReport::ref_from_bytes(&bytes).unwrap();
        assert_eq!(report.cpu_generation().unwrap(), Generation::Turin);

        bytes[0x188] = 0x1B;
        bytes[0x189] = 0x00;
        let report = AttestationReport::ref_from_bytes(&bytes).unwrap();
        assert!(report.cpu_generation().is_err());
    }

    #[test]
    fn field_offsets() {
        use std::mem::offset_of;

        assert_eq!(offset_of!(AttestationReport, version), 0x000);
        assert_eq!(offset_of!(AttestationReport, guest_svn), 0x004);
        assert_eq!(offset_of!(AttestationReport, policy), 0x008);
        assert_eq!(offset_of!(AttestationReport, family_id), 0x010);
        assert_eq!(offset_of!(AttestationReport, image_id), 0x020);
        assert_eq!(offset_of!(AttestationReport, vmpl), 0x030);
        assert_eq!(offset_of!(AttestationReport, signature_algo), 0x034);
        assert_eq!(offset_of!(AttestationReport, platform_version), 0x038);
        assert_eq!(offset_of!(AttestationReport, platform_info), 0x040);
        assert_eq!(offset_of!(AttestationReport, flags), 0x048);
        assert_eq!(offset_of!(AttestationReport, reserved0), 0x04C);
        assert_eq!(offset_of!(AttestationReport, report_data), 0x050);
        assert_eq!(offset_of!(AttestationReport, measurement), 0x090);
        assert_eq!(offset_of!(AttestationReport, host_data), 0x0C0);
        assert_eq!(offset_of!(AttestationReport, id_key_digest), 0x0E0);
        assert_eq!(offset_of!(AttestationReport, author_key_digest), 0x110);
        assert_eq!(offset_of!(AttestationReport, report_id), 0x140);
        assert_eq!(offset_of!(AttestationReport, report_id_ma), 0x160);
        assert_eq!(offset_of!(AttestationReport, reported_tcb), 0x180);
        assert_eq!(offset_of!(AttestationReport, cpuid_fam_id), 0x188);
        assert_eq!(offset_of!(AttestationReport, cpuid_mod_id), 0x189);
        assert_eq!(offset_of!(AttestationReport, cpuid_step), 0x18A);
        assert_eq!(offset_of!(AttestationReport, reserved1), 0x18B);
        assert_eq!(offset_of!(AttestationReport, chip_id), 0x1A0);
        assert_eq!(offset_of!(AttestationReport, committed_tcb), 0x1E0);
        assert_eq!(offset_of!(AttestationReport, current_build), 0x1E8);
        assert_eq!(offset_of!(AttestationReport, current_minor), 0x1E9);
        assert_eq!(offset_of!(AttestationReport, current_major), 0x1EA);
        assert_eq!(offset_of!(AttestationReport, reserved2), 0x1EB);
        assert_eq!(offset_of!(AttestationReport, committed_build), 0x1EC);
        assert_eq!(offset_of!(AttestationReport, committed_minor), 0x1ED);
        assert_eq!(offset_of!(AttestationReport, committed_major), 0x1EE);
        assert_eq!(offset_of!(AttestationReport, reserved3), 0x1EF);
        assert_eq!(offset_of!(AttestationReport, launch_tcb), 0x1F0);
        assert_eq!(offset_of!(AttestationReport, reserved4), 0x1F8);
        assert_eq!(offset_of!(AttestationReport, signature), 0x2A0);
    }
}
