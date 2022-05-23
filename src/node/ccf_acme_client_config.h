// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "node/acme_client.h"

#include <optional>
#include <string>
#include <vector>

namespace ccf
{
  using ACMEClientConfig = ACME::ClientConfig;
}

namespace ACME
{
  DECLARE_JSON_TYPE(ClientConfig);
  DECLARE_JSON_REQUIRED_FIELDS(
    ClientConfig,
    ca_certs,
    directory_url,
    service_dns_name,
    contact,
    terms_of_service_agreed,
    challenge_type,
    challenge_server_interface);
}
