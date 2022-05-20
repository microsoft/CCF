// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <optional>
#include <string>
#include <vector>

namespace ccf
{
  struct ACMEClientConfig
  {
    std::string ca_cert;
    std::string directory_url;
    std::string service_dns_name;
    std::string node_dns_name;
    std::vector<std::string> contact;
    bool terms_of_service_agreed = true;
    std::string challenge_type;
    std::optional<std::string> not_before = std::nullopt;
    std::optional<std::string> not_after = std::nullopt;

    bool operator==(const ACMEClientConfig& other) const = default;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ACMEClientConfig);
  DECLARE_JSON_REQUIRED_FIELDS(
    ACMEClientConfig,
    ca_cert,
    directory_url,
    service_dns_name,
    node_dns_name,
    contact,
    terms_of_service_agreed,
    challenge_type);
  DECLARE_JSON_OPTIONAL_FIELDS(ACMEClientConfig, not_before, not_after);
}