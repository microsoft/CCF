// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <list>
#include <map>
#include <string>

namespace ccf::pal::snp
{
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
    std::list<EndpointInfo> endpoints;
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

  constexpr auto default_azure_endorsements_endpoint_host =
    "global.acccache.azure.net";

  // AMD endorsements endpoints. See
  // https://www.amd.com/system/files/TechDocs/57230.pdf
  constexpr auto default_amd_endorsements_endpoint_host = "kdsintf.amd.com";
}