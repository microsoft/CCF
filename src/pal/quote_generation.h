// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/hash_provider.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/snp_ioctl.h"
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

    if (attestation->get().version < pal::snp::minimum_attestation_version)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: attestation version {} is less than the minimum supported "
        "version {}",
        attestation->get().version,
        pal::snp::minimum_attestation_version));
    }

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
