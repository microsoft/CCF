// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/pal/sev_snp_cpuid.h"

#include <list>
#include <map>
#include <string>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf::pal::snp
{
  struct ACIReportEndorsements
  {
    std::string cache_control;
    std::string vcek_cert;
    std::string certificate_chain;
    std::string tcbm;
  };
  DECLARE_JSON_TYPE(ACIReportEndorsements);
  DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
    ACIReportEndorsements,
    cache_control,
    "cacheControl",
    vcek_cert,
    "vcekCert",
    certificate_chain,
    "certificateChain",
    tcbm,
    "tcbm");

  struct EndorsementEndpointsConfiguration
  {
    struct EndpointInfo
    {
      std::string host;
      std::string port;
      std::string uri;
      std::map<std::string, std::string> params;
      bool response_is_der = false;
      bool response_is_thim_json = false;
      std::map<std::string, std::string> headers = {};
      bool tls = true;

      bool operator==(const EndpointInfo&) const = default;
    };
    using Server = std::list<EndpointInfo>;

    // First server in list is always used first and other servers are provided
    // as fallback.
    std::list<Server> servers;
  };

  enum EndorsementsEndpointType
  {
    Azure = 0,
    AMD = 1,
    THIM = 2,
  };
  DECLARE_JSON_ENUM(
    EndorsementsEndpointType,
    {{EndorsementsEndpointType::Azure, "Azure"},
     {EndorsementsEndpointType::AMD, "AMD"},
     {EndorsementsEndpointType::THIM, "THIM"}});

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

  struct HostPort
  {
    std::string host;
    std::string port;
  };

  static HostPort default_azure_endorsements_endpoint = {
    "global.acccache.azure.net", "443"};

  static EndorsementEndpointsConfiguration::Server
  make_azure_endorsements_server(
    const HostPort& endpoint,
    const std::string& chip_id_hex,
    const std::string& reported_tcb)
  {
    std::map<std::string, std::string> params;
    params["api-version"] = "2020-10-15-preview";
    return {
      {endpoint.host,
       endpoint.port,
       fmt::format("/SevSnpVM/certificates/{}/{}", chip_id_hex, reported_tcb),
       params}};
  }

  // AMD endorsements endpoints. See
  // https://www.amd.com/system/files/TechDocs/57230.pdf
  static HostPort default_amd_endorsements_endpoint = {
    "kdsintf.amd.com", "443"};

  static EndorsementEndpointsConfiguration::Server make_amd_endorsements_server(
    const HostPort& endpoint,
    const std::string& chip_id_hex,
    const std::string& boot_loader,
    const std::string& tee,
    const std::string& snp,
    const std::string& microcode,
    const ProductName& product_name)
  {
    std::map<std::string, std::string> params;
    params["blSPL"] = boot_loader;
    params["teeSPL"] = tee;
    params["snpSPL"] = snp;
    params["ucodeSPL"] = microcode;

    EndorsementEndpointsConfiguration::EndpointInfo leaf{
      endpoint.host,
      endpoint.port,
      fmt::format("/vcek/v1/{}/{}", to_string(product_name), chip_id_hex),
      params,
      true // DER
    };
    EndorsementEndpointsConfiguration::EndpointInfo chain{
      endpoint.host,
      endpoint.port,
      fmt::format("/vcek/v1/{}/cert_chain", to_string(product_name)),
      {}};

    EndorsementEndpointsConfiguration::Server server;
    server.push_back(leaf);
    server.push_back(chain);

    return server;
  }

  static HostPort default_thim_endorsements_endpoint = {
    "169.254.169.254", "80"};

  static EndorsementEndpointsConfiguration::Server
  make_thim_endorsements_server(
    const HostPort& endpoint,
    const std::string& chip_id_hex,
    const std::string& reported_tcb)
  {
    std::map<std::string, std::string> params;
    params["tcbVersion"] = reported_tcb;
    params["platformId"] = chip_id_hex;
    return {{
      endpoint.host,
      endpoint.port,
      "/metadata/THIM/amd/certification",
      params,
      false, // Not DER
      true, // But THIM JSON
      {{"Metadata", "true"}},
      false // No TLS
    }};
  }
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<ccf::pal::snp::EndorsementEndpointsConfiguration::EndpointInfo>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(
    const ccf::pal::snp::EndorsementEndpointsConfiguration::EndpointInfo& e,
    FormatContext& ctx) const
  {
    return format_to(
      ctx.out(), "http{}://{}:{}", e.tls ? "s" : "", e.host, e.port);
  }
};
FMT_END_NAMESPACE