// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <list>
#include <map>
#include <string>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf::pal::snp
{
  constexpr auto product_name = "Milan";

  struct ACIReportEndorsements
  {
    std::string cache_control;
    std::string vcek_cert;
    std::string certificate_chain;
    std::string tcbm;
  };
  DECLARE_JSON_TYPE(ACIReportEndorsements);
  DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(ACIReportEndorsements, cache_control, "cacheControl", vcek_cert, "vcekCert", certificate_chain, "certificateChain", tcbm, "tcbm");

  struct EndorsementEndpointsConfiguration
  {
    struct EndpointInfo
    {
      std::string host;
      std::string port;
      std::string uri;
      std::map<std::string, std::string> params;
      bool response_is_der = false;
    };
    using Server = std::list<EndpointInfo>;

    // First server in list is always used first and other servers are provided
    // as fallback.
    std::list<Server> servers;
  };

  enum EndorsementsEndpointType
  {
    Azure = 0,
    AMD = 1
  };
  DECLARE_JSON_ENUM(
    EndorsementsEndpointType,
    {{EndorsementsEndpointType::Azure, "Azure"},
     {EndorsementsEndpointType::AMD, "AMD"}});

  struct EndorsementsServer
  {
    EndorsementsEndpointType type = Azure;
    std::optional<std::string> url = std::nullopt;

    bool operator==(const EndorsementsServer&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(EndorsementsServer);
  DECLARE_JSON_REQUIRED_FIELDS(EndorsementsServer);
  DECLARE_JSON_OPTIONAL_FIELDS(EndorsementsServer, type, url);
  using EndorsementsServers = std::vector<EndorsementsServer>;

  constexpr auto default_azure_endorsements_endpoint_host =
    "global.acccache.azure.net";

  static EndorsementEndpointsConfiguration::Server
  make_azure_endorsements_server(
    const std::string& endpoint,
    const std::string& chip_id_hex,
    const std::string& reported_tcb)
  {
    std::map<std::string, std::string> params;
    params["api-version"] = "2020-10-15-preview";
    return {
      {endpoint,
       "443",
       fmt::format("/SevSnpVM/certificates/{}/{}", chip_id_hex, reported_tcb),
       params}};
  }

  // AMD endorsements endpoints. See
  // https://www.amd.com/system/files/TechDocs/57230.pdf
  constexpr auto default_amd_endorsements_endpoint_host = "kdsintf.amd.com";

  static EndorsementEndpointsConfiguration::Server make_amd_endorsements_server(
    const std::string& endpoint,
    const std::string& chip_id_hex,
    const std::string& boot_loader,
    const std::string& tee,
    const std::string& snp,
    const std::string& microcode)
  {
    std::map<std::string, std::string> params;
    params["blSPL"] = boot_loader;
    params["teeSPL"] = tee;
    params["snpSPL"] = snp;
    params["ucodeSPL"] = microcode;

    EndorsementEndpointsConfiguration::Server server;
    server.push_back(
      {endpoint,
       "443",
       fmt::format("/vcek/v1/{}/{}", product_name, chip_id_hex),
       params,
       true});
    server.push_back(
      {endpoint,
       "443",
       fmt::format("/vcek/v1/{}/cert_chain", product_name),
       {}});

    return server;
  }
}