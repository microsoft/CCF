// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/pal/attestation.h"

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/ds/json.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/sev_snp_cpuid.h"
#include "ds/internal_logger.h"
#include "pal/tav_ffi.h"

#include <cstdint>
#include <openssl/objects.h>

namespace ccf::pal
{
  namespace snp
  {
    class AttestationReport::Impl
    {
    public:
      TavAttestationReportPtr report;

      explicit Impl(TavAttestationReportPtr&& report_) :
        report(std::move(report_))
      {}
    };

    class AttestationReportFactory
    {
    public:
      static AttestationReport make(TavAttestationReportPtr&& report)
      {
        return AttestationReport(
          std::make_unique<AttestationReport::Impl>(std::move(report)));
      }
    };

    AttestationReport::AttestationReport(std::unique_ptr<Impl> impl_) :
      impl(std::move(impl_))
    {}
    AttestationReport::AttestationReport(AttestationReport&&) noexcept =
      default;
    AttestationReport& AttestationReport::operator=(
      AttestationReport&&) noexcept = default;
    AttestationReport::~AttestationReport() = default;

    namespace
    {
      using BytesAccessor =
        void (*)(const TavSnpAttestationReport*, const uint8_t**, size_t*);

      std::vector<uint8_t> get_bytes(
        const TavSnpAttestationReport* report,
        BytesAccessor accessor,
        size_t expected_size,
        std::string_view field)
      {
        const uint8_t* data = nullptr;
        size_t size = 0;
        accessor(report, &data, &size);
        if (size != expected_size || data == nullptr)
        {
          throw std::logic_error(fmt::format(
            "SEV-SNP: TAV returned {} bytes for {} (data {}), expected {}",
            size,
            field,
            data == nullptr ? "is null" : "is not null",
            expected_size));
        }
        return {data, data + size};
      }

      [[noreturn]] void throw_tav_error(
        std::string_view operation, const TavError* error)
      {
        const auto error_code = tav_error_code(error);
        const auto* error_message = tav_error_message(error);
        throw std::logic_error(fmt::format(
          "SEV-SNP: TAV {} failed ({}): {}",
          operation,
          static_cast<uint32_t>(error_code),
          error_message == nullptr ? "Unknown TAV error" : error_message));
      }
    }

#define SNP_SCALAR_ACCESSOR(method, tav_accessor, type) \
  type AttestationReport::method() const \
  { \
    return tav_accessor(impl->report.get()); \
  }

    SNP_SCALAR_ACCESSOR(version, tav_snp_attestation_report_version, uint32_t)
    SNP_SCALAR_ACCESSOR(
      guest_svn, tav_snp_attestation_report_guest_svn, uint32_t)
    SNP_SCALAR_ACCESSOR(policy, tav_snp_attestation_report_policy, uint64_t)
    SNP_SCALAR_ACCESSOR(
      policy_abi_minor, tav_snp_attestation_report_policy_abi_minor, uint8_t)
    SNP_SCALAR_ACCESSOR(
      policy_abi_major, tav_snp_attestation_report_policy_abi_major, uint8_t)
    SNP_SCALAR_ACCESSOR(policy_smt, tav_snp_attestation_report_policy_smt, bool)
    SNP_SCALAR_ACCESSOR(
      policy_migrate_ma, tav_snp_attestation_report_policy_migrate_ma, bool)
    SNP_SCALAR_ACCESSOR(
      policy_debug, tav_snp_attestation_report_policy_debug, bool)
    SNP_SCALAR_ACCESSOR(
      policy_single_socket,
      tav_snp_attestation_report_policy_single_socket,
      bool)
    SNP_SCALAR_ACCESSOR(vmpl, tav_snp_attestation_report_vmpl, uint32_t)
    SNP_SCALAR_ACCESSOR(
      signature_algo, tav_snp_attestation_report_signature_algo, uint32_t)
    SNP_SCALAR_ACCESSOR(
      platform_info, tav_snp_attestation_report_platform_info, uint64_t)
    SNP_SCALAR_ACCESSOR(flags, tav_snp_attestation_report_flags, uint32_t)
    SNP_SCALAR_ACCESSOR(
      flags_author_key_en, tav_snp_attestation_report_flags_author_key_en, bool)
    SNP_SCALAR_ACCESSOR(
      flags_mask_chip_key, tav_snp_attestation_report_flags_mask_chip_key, bool)
    SNP_SCALAR_ACCESSOR(
      flags_signing_key, tav_snp_attestation_report_flags_signing_key, uint8_t)
    SNP_SCALAR_ACCESSOR(
      cpuid_fam_id, tav_snp_attestation_report_cpuid_fam_id, uint8_t)
    SNP_SCALAR_ACCESSOR(
      cpuid_mod_id, tav_snp_attestation_report_cpuid_mod_id, uint8_t)
    SNP_SCALAR_ACCESSOR(
      cpuid_step, tav_snp_attestation_report_cpuid_step, uint8_t)
    SNP_SCALAR_ACCESSOR(
      current_build, tav_snp_attestation_report_current_build, uint8_t)
    SNP_SCALAR_ACCESSOR(
      current_minor, tav_snp_attestation_report_current_minor, uint8_t)
    SNP_SCALAR_ACCESSOR(
      current_major, tav_snp_attestation_report_current_major, uint8_t)
    SNP_SCALAR_ACCESSOR(
      committed_build, tav_snp_attestation_report_committed_build, uint8_t)
    SNP_SCALAR_ACCESSOR(
      committed_minor, tav_snp_attestation_report_committed_minor, uint8_t)
    SNP_SCALAR_ACCESSOR(
      committed_major, tav_snp_attestation_report_committed_major, uint8_t)

#undef SNP_SCALAR_ACCESSOR

#define SNP_BYTES_ACCESSOR(method, tav_accessor, size) \
  std::vector<uint8_t> AttestationReport::method() const \
  { \
    return get_bytes(impl->report.get(), tav_accessor, size, #method); \
  }

    SNP_BYTES_ACCESSOR(family_id, tav_snp_attestation_report_family_id, 16)
    SNP_BYTES_ACCESSOR(image_id, tav_snp_attestation_report_image_id, 16)
    SNP_BYTES_ACCESSOR(
      report_data,
      tav_snp_attestation_report_report_data,
      snp_attestation_report_data_size)
    SNP_BYTES_ACCESSOR(
      measurement,
      tav_snp_attestation_report_measurement,
      snp_attestation_measurement_size)
    SNP_BYTES_ACCESSOR(host_data, tav_snp_attestation_report_host_data, 32)
    SNP_BYTES_ACCESSOR(
      id_key_digest, tav_snp_attestation_report_id_key_digest, 48)
    SNP_BYTES_ACCESSOR(
      author_key_digest, tav_snp_attestation_report_author_key_digest, 48)
    SNP_BYTES_ACCESSOR(report_id, tav_snp_attestation_report_report_id, 32)
    SNP_BYTES_ACCESSOR(
      report_id_ma, tav_snp_attestation_report_report_id_ma, 32)
    SNP_BYTES_ACCESSOR(chip_id, tav_snp_attestation_report_chip_id, 64)
    SNP_BYTES_ACCESSOR(signature_r, tav_snp_attestation_report_signature_r, 72)
    SNP_BYTES_ACCESSOR(signature_s, tav_snp_attestation_report_signature_s, 72)

#undef SNP_BYTES_ACCESSOR

    TcbVersionRaw AttestationReport::platform_version() const
    {
      return TcbVersionRaw(get_bytes(
        impl->report.get(),
        tav_snp_attestation_report_platform_version,
        snp_tcb_version_size,
        "platform_version"));
    }

    TcbVersionRaw AttestationReport::reported_tcb() const
    {
      return TcbVersionRaw(get_bytes(
        impl->report.get(),
        tav_snp_attestation_report_reported_tcb,
        snp_tcb_version_size,
        "reported_tcb"));
    }

    TcbVersionRaw AttestationReport::committed_tcb() const
    {
      return TcbVersionRaw(get_bytes(
        impl->report.get(),
        tav_snp_attestation_report_committed_tcb,
        snp_tcb_version_size,
        "committed_tcb"));
    }

    TcbVersionRaw AttestationReport::launch_tcb() const
    {
      return TcbVersionRaw(get_bytes(
        impl->report.get(),
        tav_snp_attestation_report_launch_tcb,
        snp_tcb_version_size,
        "launch_tcb"));
    }

    std::vector<uint8_t> AttestationReport::chip_id_for_vcek() const
    {
      auto id = chip_id();
      const auto product = get_sev_snp_product(cpuid_fam_id(), cpuid_mod_id());
      if (product == ProductName::Milan || product == ProductName::Genoa)
      {
        return id;
      }
      if (product == ProductName::Turin)
      {
        id.resize(8);
        return id;
      }
      throw std::logic_error(
        fmt::format("Unsupported SEV-SNP product: {}", product));
    }

    AttestationReport parse_attestation_report_unverified(
      std::span<const uint8_t> report)
    {
      TavSnpAttestationReport* raw_report = nullptr;
      TavErrorPtr error(tav_snp_attestation_report_from_unverified_bytes(
        report.data(), report.size(), &raw_report));
      TavAttestationReportPtr parsed_report(raw_report);
      if (error != nullptr)
      {
        throw_tav_error("unverified report parsing", error.get());
      }
      if (parsed_report == nullptr)
      {
        throw std::logic_error(
          "SEV-SNP: TAV parsing succeeded without returning a report");
      }
      return AttestationReportFactory::make(std::move(parsed_report));
    }
  }

  using Unique_ASN1_OBJECT = ccf::crypto::OpenSSL::
    Unique_SSL_OBJECT<ASN1_OBJECT, ASN1_OBJECT_new, ASN1_OBJECT_free>;
  using Unique_ASN1_INTEGER = ccf::crypto::OpenSSL::
    Unique_SSL_OBJECT<ASN1_INTEGER, ASN1_INTEGER_new, ASN1_INTEGER_free>;

  void verify_virtual_attestation_report(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data)
  {
    auto j = ccf::parse_json_safe(quote_info.quote);

    const auto s_measurement = j["measurement"].get<std::string>();
    measurement.data =
      std::vector<uint8_t>(s_measurement.begin(), s_measurement.end());
    report_data = VirtualAttestationReportData(
      j["report_data"].get<std::vector<uint8_t>>());
  }

  std::optional<long> get_integer_from_cert_extensions(
    const ccf::crypto::OpenSSL::Unique_X509& x509, const std::string& oid)
  {
    Unique_ASN1_OBJECT target(OBJ_txt2obj(oid.c_str(), 1), ASN1_OBJECT_free);

    size_t ext_loc = X509_get_ext_by_OBJ(x509, target, -1);
    if (ext_loc < 0)
    {
      LOG_FAIL_FMT("TCB version OID {} not present in VCEK certificate", oid);
      return std::nullopt;
    }

    X509_EXTENSION* ext = X509_get_ext(x509, ext_loc);
    if (ext == nullptr)
    {
      throw std::logic_error(fmt::format(
        "Expected TCB version OID {} present but could not fetch extension "
        "at index {} in VCEK certificate",
        oid,
        ext_loc));
    }

    ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
    if (data == nullptr)
    {
      throw std::logic_error((fmt::format(
        "Expected TCB version OID {} present but no data in VCEK certificate",
        oid)));
    }
    int len = ASN1_STRING_length(data);
    const unsigned char* p = ASN1_STRING_get0_data(data);

    Unique_ASN1_INTEGER ai(
      d2i_ASN1_INTEGER(nullptr, &p, len), ASN1_INTEGER_free);
    return ASN1_INTEGER_get(ai);
  }

#define TCB_OID_PREFIX "1.3.6.1.4.1.3704.1.3."
// Macro to factor repeated pattern (OID lookup -> assign -> early return)
#define RETRIEVE_TCB_FIELD(TCB, FIELD, OID_SUFFIX) \
  do \
  { \
    auto val_##FIELD = \
      get_integer_from_cert_extensions(x509, TCB_OID_PREFIX OID_SUFFIX); \
    if (!val_##FIELD.has_value()) \
    { \
      return std::nullopt; \
    } \
    if (val_##FIELD.value() < 0 || val_##FIELD.value() > UINT8_MAX) \
    { \
      throw std::logic_error(fmt::format( \
        "Invalid {} value in TCB version: {}", #FIELD, val_##FIELD.value())); \
    } \
    (TCB)->FIELD = static_cast<uint8_t>(val_##FIELD.value()); \
  } while (0)

  std::optional<snp::TcbVersionRaw> get_milan_genoa_tcb_from_cert(
    const crypto::Pem& vcek_leaf_cert)
  {
    // From "Versioned Chip Endorsement Key (VCEK) Certificate and KDS Interface
    // Specification"
    // https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf
    //
    // Table 10 VCEK Certificate Extensions for Family 19h
    // 1.3.6.1.4.1.3704.1.3.1 blSPL
    // 1.3.6.1.4.1.3704.1.3.2 teeSPL
    // 1.3.6.1.4.1.3704.1.3.4 spl_4
    // 1.3.6.1.4.1.3704.1.3.5 spl_5
    // 1.3.6.1.4.1.3704.1.3.6 spl_6
    // 1.3.6.1.4.1.3704.1.3.7 spl_7
    // 1.3.6.1.4.1.3704.1.3.3 snpSPL
    // 1.3.6.1.4.1.3704.1.3.8 ucodeSPL

    snp::TcbVersionRaw raw;
    auto* tcb = raw.as_milan_genoa();

    ccf::crypto::OpenSSL::Unique_BIO mem_bio(vcek_leaf_cert);
    ccf::crypto::OpenSSL::Unique_X509 x509(mem_bio, true);

    RETRIEVE_TCB_FIELD(tcb, boot_loader, "1"); // blSPL
    RETRIEVE_TCB_FIELD(tcb, tee, "2"); // teeSPL
    RETRIEVE_TCB_FIELD(tcb, snp, "3"); // snpSPL
    RETRIEVE_TCB_FIELD(tcb, microcode, "8"); // ucodeSPL
    return raw;
  }

  std::optional<snp::TcbVersionRaw> get_turin_tcb_from_cert(
    const crypto::Pem& vcek_leaf_cert)
  {
    // From "Versioned Chip Endorsement Key (VCEK) Certificate and KDS Interface
    // Specification"
    // https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf
    //
    // Table 11 VCEK Certificate Extensions for Family 1Ah (Turin)
    // 1.3.6.1.4.1.3704.1.3.9 fmcSPL
    // 1.3.6.1.4.1.3704.1.3.1 blSPL
    // 1.3.6.1.4.1.3704.1.3.2 teeSPL
    // 1.3.6.1.4.1.3704.1.3.3 snpSPL
    // 1.3.6.1.4.1.3704.1.3.5 spl_5
    // 1.3.6.1.4.1.3704.1.3.6 spl_6
    // 1.3.6.1.4.1.3704.1.3.7 spl_7
    // 1.3.6.1.4.1.3704.1.3.8 ucodeSPL

    ccf::crypto::OpenSSL::Unique_BIO mem_bio(vcek_leaf_cert);
    ccf::crypto::OpenSSL::Unique_X509 x509(mem_bio, true);

    snp::TcbVersionRaw raw;
    auto* tcb = raw.as_turin();

    // Table 11 mapping
    RETRIEVE_TCB_FIELD(tcb, fmc, "9"); // fmcSPL
    RETRIEVE_TCB_FIELD(tcb, boot_loader, "1"); // blSPL
    RETRIEVE_TCB_FIELD(tcb, tee, "2"); // teeSPL
    RETRIEVE_TCB_FIELD(tcb, snp, "3"); // snpSPL
    RETRIEVE_TCB_FIELD(tcb, microcode, "8"); // ucodeSPL

    return raw;
  }
#undef RETRIEVE_TCB_FIELD

  std::optional<snp::TcbVersionRaw> get_endorsed_tcb_from_cert(
    snp::ProductName product, const crypto::Pem& vcek_leaf_cert)
  {
    switch (product)
    {
      case snp::ProductName::Milan:
      case snp::ProductName::Genoa:
        return get_milan_genoa_tcb_from_cert(vcek_leaf_cert);
      case snp::ProductName::Turin:
        return get_turin_tcb_from_cert(vcek_leaf_cert);
      default:
        throw std::logic_error("Unknown SEV-SNP product");
    }
  }

  std::optional<std::vector<uint8_t>> get_endorsed_chip_id_from_cert(
    const crypto::Pem& vcek_leaf_cert)
  {
    ccf::crypto::OpenSSL::Unique_BIO mem_bio(vcek_leaf_cert);
    ccf::crypto::OpenSSL::Unique_X509 x509(mem_bio, true);

    const std::string chip_id_oid = "1.3.6.1.4.1.3704.1.4";

    Unique_ASN1_OBJECT chip_id_obj(
      OBJ_txt2obj(chip_id_oid.c_str(), 1), ASN1_OBJECT_free);

    int ext_index = X509_get_ext_by_OBJ(x509, chip_id_obj, -1);
    if (ext_index < 0)
    {
      LOG_FAIL_FMT(
        "Chip ID OID {} not present in VCEK certificate", chip_id_oid);
      return std::nullopt;
    }

    X509_EXTENSION* ext = X509_get_ext(x509, ext_index);
    if (ext == nullptr)
    {
      throw std::logic_error(fmt::format(
        "Failed to fetch extension at index {} for OID {}",
        ext_index,
        chip_id_oid));
    }

    ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
    if (data == nullptr)
    {
      throw std::logic_error(fmt::format("No data for OID {}", chip_id_oid));
    }
    const unsigned char* p = ASN1_STRING_get0_data(data);
    int len = ASN1_STRING_length(data);
    return std::vector(p, p + len);
  }

  // Verifying SNP attestation report is available on all platforms.
  snp::AttestationReport verify_snp_attestation_report_and_get(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data)
  {
    if (quote_info.format != QuoteFormat::amd_sev_snp_v1)
    {
      throw std::logic_error(fmt::format(
        "Unexpected attestation report to verify for SEV-SNP: {}",
        quote_info.format));
    }

    // ---- Verify certificate chain ----

    auto certificates = ccf::crypto::split_x509_cert_bundle(std::string_view(
      reinterpret_cast<const char*>(quote_info.endorsements.data()),
      quote_info.endorsements.size()));
    if (certificates.size() != 3)
    {
      throw std::logic_error(fmt::format(
        "Expected 3 endorsement certificates but got {}", certificates.size()));
    }

    // ark_cert --signs--> ask_cert
    // ask_cert --signs--> vcek_cert
    auto vcek_cert = certificates[0];
    auto ask_cert = certificates[1];
    auto ark_cert = certificates[2];

    TavSnpAttestationReport* verified_report_raw = nullptr;
    TavErrorPtr verification_error(tav_verify_snp_attestation(
      quote_info.quote.data(),
      quote_info.quote.size(),
      ark_cert.data(),
      ark_cert.size(),
      ask_cert.data(),
      ask_cert.size(),
      vcek_cert.data(),
      vcek_cert.size(),
      &verified_report_raw));
    TavAttestationReportPtr verified_report(verified_report_raw);
    if (verification_error != nullptr)
    {
      const auto error_code = tav_error_code(verification_error.get());
      const auto* error_message = tav_error_message(verification_error.get());
      throw std::logic_error(fmt::format(
        "SEV-SNP: TAV verification failed ({}): {}",
        static_cast<uint32_t>(error_code),
        error_message == nullptr ? "Unknown TAV error" : error_message));
    }

    if (verified_report == nullptr)
    {
      throw std::logic_error(
        "SEV-SNP: TAV verification succeeded without returning a report");
    }

    auto attestation =
      snp::AttestationReportFactory::make(std::move(verified_report));

    if (attestation.version() < snp::minimum_attestation_version)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Attestation version is {} not >= expected minimum {}",
        attestation.version(),
        snp::minimum_attestation_version));
    }

    const auto product_family = snp::get_sev_snp_product(
      attestation.cpuid_fam_id(), attestation.cpuid_mod_id());

    // ---- Verify attestation report contents ----

    if (
      attestation.flags_signing_key() !=
      snp::attestation_flags_signing_key_vcek)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Attestation report must be signed by VCEK: {}",
        attestation.flags_signing_key()));
    }

    // mask_chip_key if set means the operator set the vcek to 0s
    if (attestation.flags_mask_chip_key())
    {
      throw std::logic_error(
        fmt::format("SEV-SNP: Mask chip key must not be set"));
    }

    // All attestation reports generated by guests must have VMPL <= 3
    // while host generated reports have VMPL > 3.
    // We should reject host generated reports.
    if (attestation.vmpl() > 3)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: This report seems to be host generated (VMPL {} > 3)",
        attestation.vmpl()));
    }

    // Debug mode would allow decryption of guest pages
    if (attestation.policy_debug())
    {
      throw std::logic_error(
        "SEV-SNP: SNP attestation report guest policy debugging must not be "
        "enabled");
    }

    // Migration of CCF nodes and other services could allow duplicates, and
    // hence must be disallowed
    if (attestation.policy_migrate_ma())
    {
      throw std::logic_error(
        "SEV-SNP: SNP attestation report guest policy migration must not be "
        "enabled");
    }

    auto endorsed_tcb = get_endorsed_tcb_from_cert(product_family, vcek_cert);
    if (endorsed_tcb.has_value())
    {
      auto endorsed_tcb_policy = endorsed_tcb->to_policy(product_family);
      auto reported_tcb = attestation.reported_tcb().to_policy(product_family);

      if (!snp::TcbVersionPolicy::is_valid(endorsed_tcb_policy, reported_tcb))
      {
        throw std::logic_error(fmt::format(
          "SEV-SNP: Reported TCB {} does not meet or exceed the endorsed TCB "
          "{}",
          nlohmann::json(reported_tcb).dump(),
          nlohmann::json(endorsed_tcb).dump()));
      }
    }

    auto endorsed_chip_id = get_endorsed_chip_id_from_cert(vcek_cert);
    auto reported_chip_id = attestation.chip_id_for_vcek();
    if (
      endorsed_chip_id.has_value() &&
      (endorsed_chip_id->size() != reported_chip_id.size() ||
       memcmp(
         endorsed_chip_id->data(),
         reported_chip_id.data(),
         reported_chip_id.size()) != 0))
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Chip ID in attestation does not match endorsed chip ID: {} "
        "!= {}",
        ccf::ds::to_hex(endorsed_chip_id.value()),
        ccf::ds::to_hex(reported_chip_id)));
    }

    if (quote_info.endorsed_tcb.has_value())
    {
      const auto& quote_endorsed_tcb = quote_info.endorsed_tcb.value();
      auto raw_endorsed_tcb = snp::TcbVersionRaw::from_hex(quote_endorsed_tcb);

      const auto reported_tcb = attestation.reported_tcb();
      if (raw_endorsed_tcb != reported_tcb)
      {
        auto endorsed_tcb_hex = raw_endorsed_tcb.to_hex();
        auto report_tcb_hex = reported_tcb.to_hex();
        throw std::logic_error(fmt::format(
          "SEV-SNP: endorsed TCB {} does not match reported TCB {}",
          endorsed_tcb_hex,
          report_tcb_hex));
      }
    }

    // ---- Set return values ----

    report_data = SnpAttestationReportData(attestation.report_data());
    measurement = SnpAttestationMeasurement(attestation.measurement());
    return attestation;
  }

  void verify_snp_attestation_report(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data)
  {
    verify_snp_attestation_report_and_get(quote_info, measurement, report_data);
  }

  void verify_quote(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data)
  {
    if (quote_info.format == QuoteFormat::insecure_virtual)
    {
      verify_virtual_attestation_report(quote_info, measurement, report_data);
    }
    else if (quote_info.format == QuoteFormat::amd_sev_snp_v1)
    {
      verify_snp_attestation_report(quote_info, measurement, report_data);
    }
    else
    {
      throw std::logic_error(
        "CCF 7.0.0 only supports SNP and Virtual attestation formats");
    }
  }
}