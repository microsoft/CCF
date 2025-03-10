// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/hash_provider.h"
#include "ccf/ds/hex.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/report_data.h"
#include "ds/files.h"

#include <unistd.h>

namespace ccf::pal
{
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
}
