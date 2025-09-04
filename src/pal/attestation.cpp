// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/pal/attestation.h"

#include "ccf/crypto/ecdsa.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/verifier.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/sev_snp_cpuid.h"

#include <cstdint>

namespace ccf::pal
{
  using Unique_ASN1_OBJECT = ccf::crypto::OpenSSL::
    Unique_SSL_OBJECT<ASN1_OBJECT, ASN1_OBJECT_new, ASN1_OBJECT_free>;
  using Unique_ASN1_INTEGER = ccf::crypto::OpenSSL::
    Unique_SSL_OBJECT<ASN1_INTEGER, ASN1_INTEGER_new, ASN1_INTEGER_free>;

  void verify_virtual_attestation_report(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data)
  {
    auto j = nlohmann::json::parse(quote_info.quote);

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

// Macro to factor repeated pattern (OID lookup -> assign -> early return)
#define RETRIEVE_TCB_FIELD(TCB, FIELD, OID) \
  do \
  { \
    auto val_##FIELD = get_integer_from_cert_extensions(x509, OID); \
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

    const std::string tcb_oid_prefix = "1.3.6.1.4.1.3704.1.3.";
    RETRIEVE_TCB_FIELD(tcb, boot_loader, tcb_oid_prefix + "1"); // blSPL
    RETRIEVE_TCB_FIELD(tcb, tee, tcb_oid_prefix + "2"); // teeSPL
    RETRIEVE_TCB_FIELD(tcb, snp, tcb_oid_prefix + "3"); // snpSPL
    RETRIEVE_TCB_FIELD(tcb, microcode, tcb_oid_prefix + "8"); // ucodeSPL
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

    const std::string tcb_oid_prefix = "1.3.6.1.4.1.3704.1.3.";

    // Table 11 mapping
    RETRIEVE_TCB_FIELD(tcb, fmc, tcb_oid_prefix + "9"); // fmcSPL
    RETRIEVE_TCB_FIELD(tcb, boot_loader, tcb_oid_prefix + "1"); // blSPL
    RETRIEVE_TCB_FIELD(tcb, tee, tcb_oid_prefix + "2"); // teeSPL
    RETRIEVE_TCB_FIELD(tcb, snp, tcb_oid_prefix + "3"); // snpSPL
    RETRIEVE_TCB_FIELD(tcb, microcode, tcb_oid_prefix + "8"); // ucodeSPL

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
  void verify_snp_attestation_report(
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

    if (quote_info.quote.size() != sizeof(snp::Attestation))
    {
      throw std::logic_error(fmt::format(
        "Input SEV-SNP attestation report is not of expected size {}: {}",
        sizeof(snp::Attestation),
        quote_info.quote.size()));
    }

    auto quote =
      *reinterpret_cast<const snp::Attestation*>(quote_info.quote.data());
    auto product_family =
      snp::get_sev_snp_product(quote.cpuid_fam_id, quote.cpuid_mod_id);

    if (quote.version < snp::minimum_attestation_version)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Attestation version is {} not >= expected minimum {}",
        quote.version,
        snp::minimum_attestation_version));
    }

    if (quote.flags.signing_key != snp::attestation_flags_signing_key_vcek)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Attestation report must be signed by VCEK: {}",
        static_cast<uint8_t>(quote.flags.signing_key)));
    }

    if (quote.flags.mask_chip_key != 0)
    {
      throw std::logic_error(
        fmt::format("SEV-SNP: Mask chip key must not be set"));
    }

    // Introduced in
    // https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/programmer-references/56860.pdf
    // The guest sets the VMPL field to a value from 0 thru 3 which indicates a
    // request from the guest. For a Guest requested attestation report this
    // field will contain the value (0-3). A Host requested attestation report
    // will have a value of 0xffffffff. CCF current always sets VMPL to 0, and
    // rejects non-guest values.
    if (quote.vmpl > 3)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: VMPL for guest attestations must be in 0-3 range, not {}",
        quote.vmpl));
    }

    report_data = SnpAttestationReportData(quote.report_data);
    measurement = SnpAttestationMeasurement(quote.measurement);

    auto certificates = ccf::crypto::split_x509_cert_bundle(std::string_view(
      reinterpret_cast<const char*>(quote_info.endorsements.data()),
      quote_info.endorsements.size()));
    if (certificates.size() != 3)
    {
      throw std::logic_error(fmt::format(
        "Expected 3 endorsement certificates but got {}", certificates.size()));
    }

    // chip_cert (VCEK) <-signs- sev_version (ASK)
    // ASK <-signs- root_certificate (ARK)
    auto chip_certificate = certificates[0];
    auto sev_version_certificate = certificates[1];
    auto root_certificate = certificates[2];

    auto root_cert_verifier = ccf::crypto::make_verifier(root_certificate);

    std::string expected_root_public_key;
    if (quote.version < 3)
    {
      // before version 3 there are no cpuid fields so we must assume that it is
      // milan
      expected_root_public_key = snp::amd_milan_root_signing_public_key;
    }
    else
    {
      auto key = snp::amd_root_signing_keys.find(product_family);
      if (key == snp::amd_root_signing_keys.end())
      {
        throw std::logic_error(fmt::format(
          "SEV-SNP: Unsupported CPUID family {} model {}",
          quote.cpuid_fam_id,
          quote.cpuid_mod_id));
      }
      expected_root_public_key = key->second;
    }
    if (root_cert_verifier->public_key_pem().str() != expected_root_public_key)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: The root of trust public key for this attestation was not "
        "the expected one for v{} {} {}:  {} != {}",
        quote.version,
        quote.cpuid_fam_id,
        quote.cpuid_mod_id,
        root_cert_verifier->public_key_pem().str(),
        expected_root_public_key));
    }

    if (!root_cert_verifier->verify_certificate({&root_certificate}))
    {
      throw std::logic_error(
        "SEV-SNP: The root of trust certificate for this attestation was not "
        "self signed as expected");
    }

    auto chip_cert_verifier = ccf::crypto::make_verifier(chip_certificate);
    if (!chip_cert_verifier->verify_certificate(
          {&root_certificate}, {&sev_version_certificate}))
    {
      throw std::logic_error(
        "SEV-SNP: Could no verify attestation endorsement chain");
    }

    // According to Table 134 (2025-06-12) only ecdsa_p384_sha384 is supported
    if (quote.signature_algo != snp::SignatureAlgorithm::ecdsa_p384_sha384)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Unsupported signature algorithm: {} (supported: {})",
        quote.signature_algo,
        snp::SignatureAlgorithm::ecdsa_p384_sha384));
    }

    // Make ASN1 DER signature
    auto quote_signature = ccf::crypto::ecdsa_sig_from_r_s(
      quote.signature.r,
      sizeof(quote.signature.r),
      quote.signature.s,
      sizeof(quote.signature.s),
      false /* little endian */
    );

    std::span quote_without_signature{
      quote_info.quote.data(),
      quote_info.quote.size() - sizeof(quote.signature)};
    if (!chip_cert_verifier->verify(quote_without_signature, quote_signature))
    {
      throw std::logic_error(
        "SEV-SNP: Chip certificate (VCEK) did not sign this attestation");
    }

    // We should check this (although not security critical) but the guest
    // policy ABI is currently set to 0.31, although we are targeting 1.54
    // if (quote.policy.abi_major < snp::attestation_policy_abi_major)
    // {
    //   throw std::logic_error(fmt::format(
    //     "SEV-SNP: Attestation guest policy ABI major {} must be greater than
    //     " "or equal to {}", quote.policy.abi_major,
    //     snp::attestation_policy_abi_major));
    // }

    if (quote.policy.debug != 0)
    {
      throw std::logic_error(
        "SEV-SNP: SNP attestation report guest policy debugging must not be "
        "enabled");
    }

    if (quote.policy.migrate_ma != 0)
    {
      throw std::logic_error("SEV-SNP: Migration agents must not be enabled");
    }

    auto endorsed_tcb =
      get_endorsed_tcb_from_cert(product_family, chip_certificate);
    if (endorsed_tcb.has_value())
    {
      auto endorsed_tcb_policy = endorsed_tcb->to_policy(product_family);
      auto reported_tcb = quote.reported_tcb.to_policy(product_family);

      if (!snp::TcbVersionPolicy::is_valid(endorsed_tcb_policy, reported_tcb))
      {
        throw std::logic_error(fmt::format(
          "SEV-SNP: Reported TCB {} does not meet or exceed the endorsed TCB "
          "{}",
          nlohmann::json(reported_tcb).dump(),
          nlohmann::json(endorsed_tcb).dump()));
      }
    }

    auto endorsed_chip_id = get_endorsed_chip_id_from_cert(chip_certificate);
    if (
      endorsed_chip_id.has_value() &&
      (endorsed_chip_id->size() != sizeof(quote.chip_id) ||
       memcmp(endorsed_chip_id->data(), quote.chip_id, sizeof(quote.chip_id)) !=
         0))
    {
      auto printable_reported_chip_id = std::span<uint8_t>(
        quote.chip_id, quote.chip_id + sizeof(quote.chip_id));
      throw std::logic_error(fmt::format(
        "SEV-SNP: Chip ID in attestation does not match endorsed chip ID: {} "
        "!= {}",
        ccf::ds::to_hex(endorsed_chip_id.value()),
        ccf::ds::to_hex(printable_reported_chip_id)));
    }

    if (quote_info.endorsed_tcb.has_value())
    {
      const auto& quote_endorsed_tcb = quote_info.endorsed_tcb.value();
      auto raw_endorsed_tcb = snp::TcbVersionRaw::from_hex(quote_endorsed_tcb);

      if (raw_endorsed_tcb != quote.reported_tcb)
      {
        auto endorsed_tcb_hex = raw_endorsed_tcb.to_hex();
        auto report_tcb_hex = quote.reported_tcb.to_hex();
        throw std::logic_error(fmt::format(
          "SEV-SNP: endorsed TCB {} does not match reported TCB {}",
          endorsed_tcb_hex,
          report_tcb_hex));
      }
    }
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