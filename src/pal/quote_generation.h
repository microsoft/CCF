// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/files.h"

#include <nlohmann/json.hpp>
#include <string>

namespace ccf::pal
{
  static std::string virtual_attestation_path(const std::string& suffix)
  {
    return fmt::format("ccf_virtual_attestation.{}.{}", ::getpid(), suffix);
  };

  static void emit_virtual_measurement(const std::string& package_path)
  {
    auto package = files::slurp(package_path);

    auto package_hash = ccf::crypto::Sha256Hash(package);

    auto j = nlohmann::json::object();
    j["measurement"] = "TODO: Call uname";
    j["host_data"] = package_hash.hex_str();

    files::dump(j.dump(2), virtual_attestation_path("measurement"));
  }

#if defined(PLATFORM_VIRTUAL)

  static void generate_quote(
    PlatformAttestationReportData& report_data,
    RetrieveEndorsementCallback endorsement_cb,
    const snp::EndorsementsServers& endorsements_servers = {})
  {
    auto quote = files::slurp_json(virtual_attestation_path("measurement"));
    quote["report_data"] = ccf::crypto::b64_from_raw(report_data.data);

    files::dump(quote.dump(2), virtual_attestation_path("attestation"));

    auto dumped_quote = quote.dump();
    std::vector<uint8_t> quote_vec(dumped_quote.begin(), dumped_quote.end());

    endorsement_cb(
      {.format = QuoteFormat::insecure_virtual,
       .quote = quote_vec,
       .endorsements = {},
       .uvm_endorsements = {},
       .endorsed_tcb = {}},
      {});
  }

#elif defined(PLATFORM_SNP)

  static void generate_quote(
    PlatformAttestationReportData& report_data,
    RetrieveEndorsementCallback endorsement_cb,
    const snp::EndorsementsServers& endorsements_servers = {})
  {
    QuoteInfo node_quote_info = {};
    node_quote_info.format = QuoteFormat::amd_sev_snp_v1;
    auto attestation = snp::get_attestation(report_data);

    node_quote_info.quote = attestation->get_raw();

    if (endorsement_cb != nullptr)
    {
      endorsement_cb(
        node_quote_info,
        snp::make_endorsement_endpoint_configuration(
          attestation->get(), endorsements_servers));
    }
  }
#endif
}
