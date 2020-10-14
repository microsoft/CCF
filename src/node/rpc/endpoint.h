// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "kv/map.h"

#include <string>
#include <utility>

namespace ccf
{
  namespace endpoints
  {
    using URI = std::string;

    struct EndpointKey
    {
      URI uri_path;
      RESTVerb verb = HTTP_POST;

      MSGPACK_DEFINE(uri_path, verb);
    };

    DECLARE_JSON_TYPE(EndpointKey);
    DECLARE_JSON_REQUIRED_FIELDS(EndpointKey, uri_path, verb);

    enum class ForwardingRequired
    {
      Sometimes,
      Always,
      Never
    };
  }
}

MSGPACK_ADD_ENUM(ccf::endpoints::ForwardingRequired);

namespace ccf
{
  namespace endpoints
  {
    DECLARE_JSON_ENUM(
      ForwardingRequired,
      {{ForwardingRequired::Sometimes, "sometimes"},
       {ForwardingRequired::Always, "always"},
       {ForwardingRequired::Never, "never"}});

    struct EndpointProperties
    {
      ForwardingRequired forwarding_required = ForwardingRequired::Always;
      bool execute_locally = false;
      bool require_client_signature = false;
      bool require_client_identity = true;

      MSGPACK_DEFINE(
        forwarding_required,
        execute_locally,
        require_client_signature,
        require_client_identity);
    };

    DECLARE_JSON_TYPE(EndpointProperties);
    DECLARE_JSON_REQUIRED_FIELDS(
      EndpointProperties,
      forwarding_required,
      execute_locally,
      require_client_signature,
      require_client_identity);

    struct EndpointDefinition
    {
      virtual ~EndpointDefinition() = default;

      EndpointKey dispatch;
      EndpointProperties properties;
    };

    using EndpointDefinitionPtr = std::shared_ptr<EndpointDefinition>;

    using EndpointsMap = kv::Map<EndpointKey, EndpointProperties>;
  }
}