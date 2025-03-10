// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ecdsa.h"
#include "ccf/crypto/hash_provider.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/logger.h"
#include "ccf/ds/quote_info.h"
#include "ccf/node/startup_config.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/snp_ioctl.h"
#include "ds/files.h"

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

  static std::string virtual_attestation_path(const std::string& suffix)
  {
    return fmt::format("ccf_virtual_attestation.{}.{}", ::getpid(), suffix);
  };

  static void emit_virtual_measurement(const std::string& package_path)
  {
    auto hasher = ccf::crypto::make_incremental_sha256();
    std::ifstream f(package_path, std::ios::binary | std::ios::ate);
    if (!f)
    {
      throw std::runtime_error(fmt::format(
        "Cannot emit virtual measurement: Cannot open file {}", package_path));
    }

    const size_t size = f.tellg();
    f.seekg(0, std::ios::beg);

    static constexpr size_t buf_size = 4096;
    char buf[buf_size];

    size_t handled = 0;
    while (handled < size)
    {
      const auto this_read = std::min(size - handled, buf_size);
      f.read(buf, this_read);

      hasher->update_hash({(const uint8_t*)buf, this_read});

      handled += this_read;
    }

    const auto package_hash = hasher->finalise();

    auto j = nlohmann::json::object();

    j["measurement"] = "Insecure hard-coded virtual measurement v1";
    j["host_data"] = package_hash.hex_str();

    files::dump(j.dump(2), virtual_attestation_path("measurement"));
  }

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

  // Verifying SNP attestation report is available on all platforms as unlike
  // SGX, this does not require external dependencies (Open Enclave for SGX).
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

    if (
      root_cert_verifier->public_key_pem().str() !=
      snp::amd_milan_root_signing_public_key)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: The root of trust public key for this attestation was not "
        "the expected one {}",
        root_cert_verifier->public_key_pem().str()));
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

  static void populate_attestation(
    QuoteInfo& node_quote_info,
    const PlatformAttestationReportData& report_data)
  {
#if defined(PLATFORM_VIRTUAL)
    node_quote_info.format = QuoteFormat::insecure_virtual;

    auto quote = files::slurp_json(virtual_attestation_path("measurement"));
    quote["report_data"] = ccf::crypto::b64_from_raw(report_data.data);

    auto dumped_quote = quote.dump();
    node_quote_info.quote =
      std::vector<uint8_t>(dumped_quote.begin(), dumped_quote.end());

    // Also write the virtual quote to a file, so it could be
    // inspected/retrieved elsewhere
    files::dump(dumped_quote, virtual_attestation_path("attestation"));

#elif defined(PLATFORM_SNP)
    node_quote_info.format = QuoteFormat::amd_sev_snp_v1;
    auto attestation = ccf::pal::snp::get_attestation(report_data);

    node_quote_info.quote = attestation->get_raw();

#else
    throw std::logic_error("Unable to construct attestation");
#endif
  }

  static void populate_snp_attestation_endorsements(
    QuoteInfo& node_quote_info,
    const ccf::CCFConfig::Attestation& attestation_config)
  {
    if (attestation_config.environment.snp_endorsements.has_value())
    {
      const auto raw_data = ccf::crypto::raw_from_b64(
        attestation_config.environment.snp_endorsements.value());

      const auto j = nlohmann::json::parse(raw_data);
      const auto aci_endorsements =
        j.get<ccf::pal::snp::ACIReportEndorsements>();

      // Check that tcbm in endorsement matches reported TCB in our retrieved
      // attestation
      auto* quote =
        reinterpret_cast<const snp::Attestation*>(node_quote_info.quote.data());
      const auto reported_tcb = quote->reported_tcb;
      const uint8_t* raw = reinterpret_cast<const uint8_t*>(&reported_tcb);
      const auto tcb_as_hex = ccf::ds::to_hex(raw, raw + sizeof(reported_tcb));

      if (tcb_as_hex == aci_endorsements.tcbm)
      {
        auto& endorsements_pem = node_quote_info.endorsements;
        endorsements_pem.insert(
          endorsements_pem.end(),
          aci_endorsements.vcek_cert.begin(),
          aci_endorsements.vcek_cert.end());
        endorsements_pem.insert(
          endorsements_pem.end(),
          aci_endorsements.certificate_chain.begin(),
          aci_endorsements.certificate_chain.end());

        // TODO: Should we check that this is a valid PEM chain now?

        return;
      }
      else
      {
        LOG_INFO_FMT(
          "SNP endorsements loaded from disk ({}) contained tcbm {}, which "
          "does not match reported TCB of current attestation {}. Falling back "
          "to fetching fresh endorsements from server.",
          attestation_config.snp_endorsements_file.value(),
          aci_endorsements.tcbm,
          tcb_as_hex);
      }
    }

    if (attestation_config.snp_endorsements_servers.empty())
    {
      throw std::runtime_error(
        "One or more SNP endorsements servers must be specified to fetch "
        "the collateral for the attestation");
    }

    // TODO: Fetch from servers, inline
    throw std::runtime_error(
      "Fetching from SNP endorsement servers is currently unimplemented");
  }

  static void populate_attestation_endorsements(
    QuoteInfo& node_quote_info,
    const ccf::CCFConfig::Attestation& attestation_config)
  {
    switch (node_quote_info.format)
    {
      case (QuoteFormat::amd_sev_snp_v1):
      {
        populate_snp_attestation_endorsements(
          node_quote_info, attestation_config);
        break;
      }
      default:
      {
        // There are no endorsements for virtual attestations
        break;
      }
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