// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ecdsa.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/logger.h"
#include "ccf/ds/quote_info.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/snp_ioctl.h"

#include <cstdint>
#include <fcntl.h>
#include <functional>
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <optional>
#include <stdexcept>
#include <sys/ioctl.h>

namespace ccf::pal
{
  // Caller-supplied callback used to retrieve endorsements as specified by
  // the config argument. When called back, the quote_info argument will have
  // already been populated with the raw quote.
  using RetrieveEndorsementCallback = std::function<void(
    const QuoteInfo& quote_info,
    const snp::EndorsementEndpointsConfiguration& config)>;

  static void verify_virtual_attestation_report(
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

  static std::optional<snp::TcbVersionRaw> get_endorsed_tcb_from_cert(
    const crypto::Pem& vcek_leaf_cert)
  {
    using Unique_ASN1_OBJECT = ccf::crypto::OpenSSL::
      Unique_SSL_OBJECT<ASN1_OBJECT, ASN1_OBJECT_new, ASN1_OBJECT_free>;
    using Unique_ASN1_INTEGER = ccf::crypto::OpenSSL::
      Unique_SSL_OBJECT<ASN1_INTEGER, ASN1_INTEGER_new, ASN1_INTEGER_free>;

    ccf::crypto::OpenSSL::Unique_BIO mem_bio(vcek_leaf_cert);
    ccf::crypto::OpenSSL::Unique_X509 x509(mem_bio, true);

    const std::string oid_base = "1.3.6.1.4.1.3704.1.3.";
    std::vector<uint8_t> raw(sizeof(snp::TcbVersionRaw), 0);
    for (size_t byte_idx = 0; byte_idx < raw.size(); ++byte_idx)
    {
      auto oid = fmt::format("{}{}", oid_base, byte_idx + 1);
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
      long v = ASN1_INTEGER_get(ai);
      if (v < 0 || v > UINT8_MAX)
      {
        throw std::logic_error(
          fmt::format("OID {} integer out of byte range: {}", oid, v));
      }
      raw[byte_idx] = static_cast<uint8_t>(v & UINT8_MAX);
    }

    return snp::TcbVersionRaw(raw);
  }

  static std::optional<std::vector<uint8_t>> get_endorsed_chip_id_from_cert(
    const crypto::Pem& vcek_leaf_cert)
  {
    using Unique_ASN1_OBJECT = ccf::crypto::OpenSSL::
      Unique_SSL_OBJECT<ASN1_OBJECT, ASN1_OBJECT_new, ASN1_OBJECT_free>;

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
  static void verify_snp_attestation_report(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data)
  {
    // valid quote metadata for snp
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

    // -------------------- Verify the certificate chain --------------------

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

    if (!root_cert_verifier->verify_certificate({&root_certificate}))
    {
      throw std::logic_error(
        "SEV-SNP: The root of trust public key for this attestation was not "
        "self signed as expected");
    }

    // Updated to pass ASK as a chain rather than trusted cert!!
    auto chip_cert_verifier = ccf::crypto::make_verifier(chip_certificate);
    if (!chip_cert_verifier->verify_certificate(
          {&root_certificate}, {&sev_version_certificate}))
    {
      throw std::logic_error(
        "SEV-SNP: The chain of signatures from the root of trust to this "
        "attestation is broken");
    }

    auto attestation =
      *reinterpret_cast<const snp::Attestation*>(quote_info.quote.data());

    if (attestation.version < snp::minimum_attestation_version)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Attestation version is {} not >= expected minimum {}",
        attestation.version,
        snp::minimum_attestation_version));
    }

    // Signature verification

    // According to Table 134 (2025-06-12) only ecdsa_p384_sha384 is supported
    if (
      attestation.signature_algo != snp::SignatureAlgorithm::ecdsa_p384_sha384)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Unsupported signature algorithm: {} (supported: {})",
        attestation.signature_algo,
        snp::SignatureAlgorithm::ecdsa_p384_sha384));
    }

    // Make ASN1 DER signature
    auto quote_signature = ccf::crypto::ecdsa_sig_from_r_s(
      attestation.signature.r,
      sizeof(attestation.signature.r),
      attestation.signature.s,
      sizeof(attestation.signature.s),
      false /* little endian */
    );

    std::span quote_without_signature{
      quote_info.quote.data(),
      quote_info.quote.size() - sizeof(attestation.signature)};
    if (!chip_cert_verifier->verify(quote_without_signature, quote_signature))
    {
      throw std::logic_error(
        "SEV-SNP: Chip certificate (VCEK) did not sign this attestation");
    }

    // Ensure that the root certificate matches the expected one for the cpu
    auto key = snp::amd_root_signing_keys.find(snp::get_sev_snp_product(
      attestation.cpuid_fam_id, attestation.cpuid_mod_id));
    if (key == snp::amd_root_signing_keys.end())
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Unsupported CPUID family {} model {}",
        attestation.cpuid_fam_id,
        attestation.cpuid_mod_id));
    }
    std::string expected_root_public_key = key->second;
    if (root_cert_verifier->public_key_pem().str() != expected_root_public_key)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: The root of trust public key for this attestation was not "
        "the expected one for v{} {} {}:  {} != {}",
        attestation.version,
        attestation.cpuid_fam_id,
        attestation.cpuid_mod_id,
        root_cert_verifier->public_key_pem().str(),
        expected_root_public_key));
    }

    // Ensure that the tcb version in the attestation matches the endorsements
    // get the relevant oids from the endorsements and then compare to the tcb
    // version

    // Attestation metadata verification
    if (
      attestation.flags.signing_key != snp::attestation_flags_signing_key_vcek)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Attestation report must be signed by VCEK: {}",
        static_cast<uint8_t>(attestation.flags.signing_key)));
    }
    if (attestation.flags.mask_chip_key != 0)
    {
      throw std::logic_error(
        fmt::format("SEV-SNP: Mask chip key must not be set"));
    }
    if (attestation.policy.debug != 0)
    {
      throw std::logic_error(
        "SEV-SNP: SNP attestation report guest policy debugging must not be "
        "enabled");
    }
    if (attestation.policy.migrate_ma != 0)
    {
      throw std::logic_error("SEV-SNP: Migration agents must not be enabled");
    }
    // Introduced in
    // https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/programmer-references/56860.pdf
    // The guest sets the VMPL field to a value from 0 thru 3 which indicates a
    // request from the guest. For a Guest requested attestation report this
    // field will contain the value (0-3). A Host requested attestation report
    // will have a value of 0xffffffff. CCF current always sets VMPL to 0, and
    // rejects non-guest values.
    if (attestation.vmpl > 3)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: VMPL for guest attestations must be in 0-3 range, not {}",
        attestation.vmpl));
    }

    auto product_family = snp::get_sev_snp_product(
      attestation.cpuid_fam_id, attestation.cpuid_mod_id);
    auto endorsed_tcb = get_endorsed_tcb_from_cert(chip_certificate);
    if (endorsed_tcb.has_value())
    {
      auto endorsed_tcb_policy = endorsed_tcb->to_policy(product_family);
      auto reported_tcb = attestation.reported_tcb.to_policy(product_family);
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
      (endorsed_chip_id->size() != sizeof(attestation.chip_id) ||
       memcmp(endorsed_chip_id->data(), attestation.chip_id, sizeof(attestation.chip_id)) !=
         0))
    {
      throw std::logic_error(
        "SEV-SNP: Chip ID in attestation does not match endorsed chip ID");
    }

    report_data = SnpAttestationReportData(attestation.report_data);
    measurement = SnpAttestationMeasurement(attestation.measurement);
  }

  static void verify_quote(
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
        "SGX attestation reports are no longer supported from 6.0.0 onwards");
    }
  }

  class AttestationCollateralFetchingTimeout : public std::exception
  {
  private:
    std::string msg;

  public:
    AttestationCollateralFetchingTimeout(const std::string& msg_) : msg(msg_) {}

    virtual const char* what() const throw()
    {
      return msg.c_str();
    }
  };
}