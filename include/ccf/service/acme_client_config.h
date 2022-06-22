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
    // Root certificate(s) of the CA to connect to in PEM format (for TLS
    // connections to the CA, e.g. Let's Encrypt's ISRG Root X1)
    std::vector<std::string> ca_certs;

    // URL of the ACME server's directory
    std::string directory_url;

    // DNS name of the service we represent
    std::string service_dns_name;

    // Contact addresses (see RFC8555 7.3, e.g. mailto:john@example.com)
    std::vector<std::string> contact;

    // Indication that the user/operator is aware of the latest terms and
    // conditions for the CA
    bool terms_of_service_agreed = false;

    // Type of the ACME challenge (currently only http-01 supported)
    std::string challenge_type = "http-01";

    // Validity range (Note: not supported by Let's Encrypt)
    std::optional<std::string> not_before;
    std::optional<std::string> not_after;

    // Name of the interface that the challenge server listens on
    std::string challenge_server_interface;

    bool operator==(const ACMEClientConfig& other) const = default;
  };

  DECLARE_JSON_TYPE(ACMEClientConfig);
  DECLARE_JSON_REQUIRED_FIELDS(
    ACMEClientConfig,
    ca_certs,
    directory_url,
    service_dns_name,
    contact,
    terms_of_service_agreed,
    challenge_type,
    challenge_server_interface);
  DECLARE_JSON_OPTIONAL_FIELDS(ACMEClientConfig, not_before, not_after);
}
