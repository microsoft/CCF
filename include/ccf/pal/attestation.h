// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ecdsa.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/logger.h"
#include "ccf/ds/quote_info.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/snp_ioctl.h"

#include <fcntl.h>
#include <functional>
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

  // Verifying SNP attestation report is available on all platforms.
  static void verify_snp_attestation_report(
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
    auto chip_certificate = certificates[0];
    auto sev_version_certificate = certificates[1];
    auto root_certificate = certificates[2];

    auto root_cert_verifier = ccf::crypto::make_verifier(root_certificate);

    auto expected_root_public_key = snp::amd_root_signing_keys.find(
      std::make_pair(quote.cpuid_fam_id, quote.cpuid_mod_id));
    if (expected_root_public_key == snp::amd_root_signing_keys.end())
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Unsupported CPUID family {} model {}",
        quote.cpuid_fam_id,
        quote.cpuid_mod_id));
    }
    if (
      root_cert_verifier->public_key_pem().str() !=
      expected_root_public_key->second)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: The root of trust public key for this attestation was not "
        "the expected one for {} {}:  {} != {}",
        quote.cpuid_fam_id,
        quote.cpuid_mod_id,
        root_cert_verifier->public_key_pem().str(),
        expected_root_public_key->second));
    }

    if (!root_cert_verifier->verify_certificate({&root_certificate}))
    {
      throw std::logic_error(
        "SEV-SNP: The root of trust public key for this attestation was not "
        "self signed as expected");
    }

    auto chip_cert_verifier = ccf::crypto::make_verifier(chip_certificate);
    if (!chip_cert_verifier->verify_certificate(
          {&root_certificate, &sev_version_certificate}))
    {
      throw std::logic_error(
        "SEV-SNP: The chain of signatures from the root of trust to this "
        "attestation is broken");
    }

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

    // Only has value when endorsements are retrieved from environment
    if (quote_info.endorsed_tcb.has_value())
    {
      const auto& endorsed_tcb = quote_info.endorsed_tcb.value();
      auto raw_tcb = ds::from_hex(quote_info.endorsed_tcb.value());

      if (raw_tcb.size() != sizeof(snp::TcbVersion))
      {
        throw std::logic_error(fmt::format(
          "SEV-SNP: TCB of size {}, expected {}",
          raw_tcb.size(),
          sizeof(snp::TcbVersion)));
      }

      snp::TcbVersion tcb = *reinterpret_cast<snp::TcbVersion*>(raw_tcb.data());
      if (tcb != quote.reported_tcb)
      {
        auto* reported_tcb = reinterpret_cast<uint8_t*>(&quote.reported_tcb);
        throw std::logic_error(fmt::format(
          "SEV-SNP: endorsed TCB {} does not match reported TCB {}",
          endorsed_tcb,
          ds::to_hex(
            {reported_tcb, reported_tcb + sizeof(quote.reported_tcb)})));
      }
    }
  }

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)

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
#endif

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