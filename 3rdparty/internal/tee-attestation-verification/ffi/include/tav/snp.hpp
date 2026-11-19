// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Header-only RAII layer over the public SEV-SNP attestation C ABI in <tav/snp.h>.
//
// Handle ownership:
// - Report is independently owned and releases its handle on destruction.
//   Report cannot be copied, so one handle is never freed twice. Moving
//   transfers the handle and empties the source.
// - Accessing an empty Report throws tav::Exception with ErrorCode::IS_NULL.
//
// Payload ownership:
// - Scalar accessors are copied out. Byte-slice accessors return a
//   std::span<const uint8_t> borrowed from the owning Report; the span must
//   not outlive the Report it was obtained from.
//
// Failures throw tav::Exception (see <tav/errors.hpp>).

#pragma once

#include <tav/snp.h>
#include <tav/errors.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace tav::snp
{
/// An owned SEV-SNP attestation report, either cryptographically verified or
/// explicitly unverified.
class Report
{
public:
    Report(const Report&) = delete;
    Report& operator=(const Report&) = delete;

    Report(Report&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}

    Report& operator=(Report&& other) noexcept
    {
        if (this != &other)
        {
            tav_snp_attestation_report_free(handle_);
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    ~Report()
    {
        tav_snp_attestation_report_free(handle_);
    }

    [[nodiscard]] bool empty() const noexcept
    {
        return handle_ == nullptr;
    }

    /// Borrows the handle for C ABI calls; ownership stays with the Report.
    /// Do not free the pointer or use it after the owning Report releases it.
    /// Throws ErrorCode::IS_NULL if empty. CACI verification requires a handle
    /// from verify(), not from_unverified_bytes().
    [[nodiscard]] const TavSnpAttestationReport* get() const
    {
        return handle();
    }

    /// Verify an SNP attestation report using caller-provided ARK, ASK, and
    /// VCEK certificates in PEM format. Input spans need only remain valid
    /// for the duration of the call; none are retained.
    [[nodiscard]] static Report verify(
      std::span<const uint8_t> report_bytes,
      std::span<const uint8_t> ark_pem,
      std::span<const uint8_t> ask_pem,
      std::span<const uint8_t> vcek_pem)
    {
        TavSnpAttestationReport* out = nullptr;
        check(tav_verify_snp_attestation(
          report_bytes.data(),
          report_bytes.size(),
          ark_pem.data(),
          ark_pem.size(),
          ask_pem.data(),
          ask_pem.size(),
          vcek_pem.data(),
          vcek_pem.size(),
          &out));
        return Report(out);
    }

    /// Decode a report's fixed-size layout without cryptographic
    /// verification. This does not validate field values, reserved bytes,
    /// signatures, certificates, or TCBs. Do not make trust decisions from
    /// the result.
    [[nodiscard]] static Report from_unverified_bytes(
      std::span<const uint8_t> report_bytes)
    {
        TavSnpAttestationReport* out = nullptr;
        check(tav_snp_attestation_report_from_unverified_bytes(
          report_bytes.data(), report_bytes.size(), &out));
        return Report(out);
    }

    [[nodiscard]] uint32_t version() const
    {
        return tav_snp_attestation_report_version(handle());
    }

    [[nodiscard]] uint32_t guest_svn() const
    {
        return tav_snp_attestation_report_guest_svn(handle());
    }

    [[nodiscard]] uint64_t policy() const
    {
        return tav_snp_attestation_report_policy(handle());
    }

    [[nodiscard]] uint8_t policy_abi_minor() const
    {
        return tav_snp_attestation_report_policy_abi_minor(handle());
    }

    [[nodiscard]] uint8_t policy_abi_major() const
    {
        return tav_snp_attestation_report_policy_abi_major(handle());
    }

    [[nodiscard]] bool policy_smt() const
    {
        return tav_snp_attestation_report_policy_smt(handle());
    }

    [[nodiscard]] bool policy_migrate_ma() const
    {
        return tav_snp_attestation_report_policy_migrate_ma(handle());
    }

    [[nodiscard]] bool policy_debug() const
    {
        return tav_snp_attestation_report_policy_debug(handle());
    }

    [[nodiscard]] bool policy_single_socket() const
    {
        return tav_snp_attestation_report_policy_single_socket(handle());
    }

    [[nodiscard]] bool policy_cxl_allow() const
    {
        return tav_snp_attestation_report_policy_cxl_allow(handle());
    }

    [[nodiscard]] bool policy_mem_aes_256_xts() const
    {
        return tav_snp_attestation_report_policy_mem_aes_256_xts(handle());
    }

    [[nodiscard]] bool policy_rapl_dis() const
    {
        return tav_snp_attestation_report_policy_rapl_dis(handle());
    }

    [[nodiscard]] bool policy_ciphertext_hiding_dram() const
    {
        return tav_snp_attestation_report_policy_ciphertext_hiding_dram(handle());
    }

    [[nodiscard]] bool policy_page_swap_disable() const
    {
        return tav_snp_attestation_report_policy_page_swap_disable(handle());
    }

    [[nodiscard]] uint32_t vmpl() const
    {
        return tav_snp_attestation_report_vmpl(handle());
    }

    [[nodiscard]] uint32_t signature_algo() const
    {
        return tav_snp_attestation_report_signature_algo(handle());
    }

    [[nodiscard]] uint64_t platform_info() const
    {
        return tav_snp_attestation_report_platform_info(handle());
    }

    [[nodiscard]] uint32_t flags() const
    {
        return tav_snp_attestation_report_flags(handle());
    }

    [[nodiscard]] bool flags_author_key_en() const
    {
        return tav_snp_attestation_report_flags_author_key_en(handle());
    }

    [[nodiscard]] bool flags_mask_chip_key() const
    {
        return tav_snp_attestation_report_flags_mask_chip_key(handle());
    }

    [[nodiscard]] uint8_t flags_signing_key() const
    {
        return tav_snp_attestation_report_flags_signing_key(handle());
    }

    [[nodiscard]] uint8_t cpuid_fam_id() const
    {
        return tav_snp_attestation_report_cpuid_fam_id(handle());
    }

    [[nodiscard]] uint8_t cpuid_mod_id() const
    {
        return tav_snp_attestation_report_cpuid_mod_id(handle());
    }

    [[nodiscard]] uint8_t cpuid_step() const
    {
        return tav_snp_attestation_report_cpuid_step(handle());
    }

    [[nodiscard]] uint8_t current_build() const
    {
        return tav_snp_attestation_report_current_build(handle());
    }

    [[nodiscard]] uint8_t current_minor() const
    {
        return tav_snp_attestation_report_current_minor(handle());
    }

    [[nodiscard]] uint8_t current_major() const
    {
        return tav_snp_attestation_report_current_major(handle());
    }

    [[nodiscard]] uint8_t committed_build() const
    {
        return tav_snp_attestation_report_committed_build(handle());
    }

    [[nodiscard]] uint8_t committed_minor() const
    {
        return tav_snp_attestation_report_committed_minor(handle());
    }

    [[nodiscard]] uint8_t committed_major() const
    {
        return tav_snp_attestation_report_committed_major(handle());
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> report_data() const
    {
        return bytes(tav_snp_attestation_report_report_data);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> family_id() const
    {
        return bytes(tav_snp_attestation_report_family_id);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> image_id() const
    {
        return bytes(tav_snp_attestation_report_image_id);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> platform_version() const
    {
        return bytes(tav_snp_attestation_report_platform_version);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> measurement() const
    {
        return bytes(tav_snp_attestation_report_measurement);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> host_data() const
    {
        return bytes(tav_snp_attestation_report_host_data);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> id_key_digest() const
    {
        return bytes(tav_snp_attestation_report_id_key_digest);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> author_key_digest() const
    {
        return bytes(tav_snp_attestation_report_author_key_digest);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> report_id() const
    {
        return bytes(tav_snp_attestation_report_report_id);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> report_id_ma() const
    {
        return bytes(tav_snp_attestation_report_report_id_ma);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> reported_tcb() const
    {
        return bytes(tav_snp_attestation_report_reported_tcb);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> chip_id() const
    {
        return bytes(tav_snp_attestation_report_chip_id);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> committed_tcb() const
    {
        return bytes(tav_snp_attestation_report_committed_tcb);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> launch_tcb() const
    {
        return bytes(tav_snp_attestation_report_launch_tcb);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> signature_r() const
    {
        return bytes(tav_snp_attestation_report_signature_r);
    }

    /// Borrowed from this Report; must not outlive it.
    [[nodiscard]] std::span<const uint8_t> signature_s() const
    {
        return bytes(tav_snp_attestation_report_signature_s);
    }

private:
    explicit Report(TavSnpAttestationReport* handle) : handle_(handle) {}

    [[nodiscard]] const TavSnpAttestationReport* handle() const
    {
        if (empty())
        {
            throw Exception(ErrorCode::IS_NULL, "Cannot access an empty SNP report");
        }
        return handle_;
    }

    using BytesAccessor = void (*)(const TavSnpAttestationReport*, const uint8_t**, size_t*);

    [[nodiscard]] std::span<const uint8_t> bytes(BytesAccessor accessor) const
    {
        const uint8_t* data = nullptr;
        size_t len = 0;
        accessor(handle(), &data, &len);
        return {data, len};
    }

    TavSnpAttestationReport* handle_ = nullptr;
};
}
