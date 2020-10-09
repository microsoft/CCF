// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"

#include <string>
#include <utility>

namespace ccf
{
  namespace endpoints
  {
    using URI = std::string;
    using HttpVerb = std::string;

    using EndpointKey = std::pair<URI, HttpVerb>;

    enum class ForwardingRequired
    {
      Sometimes,
      Always,
      Never
    };

    DECLARE_JSON_ENUM(
      ForwardingRequired,
      {{ForwardingRequired::Sometimes, "sometimes"},
       {ForwardingRequired::Always, "always"},
       {ForwardingRequired::Never, "never"}});

    struct EndpointMetadata
    {
      virtual ~EndpointMetadata() = default;

      URI method;
      HttpVerb verb;

      ForwardingRequired forwarding_required = ForwardingRequired::Always;
      bool execute_locally = false;
      bool require_client_signature = false;
      bool require_client_identity = true;
    };

    DECLARE_JSON_TYPE(EndpointMetadata);
    DECLARE_JSON_REQUIRED_FIELDS(
      EndpointMetadata,
      method,
      verb,
      forwarding_required,
      execute_locally,
      require_client_signature,
      require_client_identity);

    using EndpointMetadataPtr = std::shared_ptr<EndpointMetadata>;
  }
}