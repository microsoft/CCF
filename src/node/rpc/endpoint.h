// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "http/authentication/authentication_types.h"
#include "kv/serialise_entry_blit.h"
#include "node/service_map.h"

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
    };

    DECLARE_JSON_TYPE(EndpointKey);
    DECLARE_JSON_REQUIRED_FIELDS(EndpointKey, uri_path, verb);

    enum class ForwardingRequired
    {
      Sometimes,
      Always,
      Never
    };

    enum class ExecuteOutsideConsensus
    {
      Never,
      Locally,
      Primary
    };

    enum class Mode
    {
      ReadWrite,
      ReadOnly,
      Historical
    };
  }
}

MSGPACK_ADD_ENUM(ccf::endpoints::ForwardingRequired);
MSGPACK_ADD_ENUM(ccf::endpoints::ExecuteOutsideConsensus);
MSGPACK_ADD_ENUM(ccf::endpoints::Mode);

namespace kv::serialisers
{
  template <>
  struct BlitSerialiser<ccf::endpoints::EndpointKey>
  {
    static SerialisedEntry to_serialised(
      const ccf::endpoints::EndpointKey& endpoint_key)
    {
      size_t size_ = sizeof(size_t) + endpoint_key.uri_path.size() +
        sizeof(endpoint_key.verb);
      SerialisedEntry data(size_);
      auto data_ = data.data();

      serialized::write(data_, size_, endpoint_key.uri_path);
      serialized::write(data_, size_, endpoint_key.verb);
      return data;
    }

    static ccf::endpoints::EndpointKey from_serialised(
      const SerialisedEntry& data)
    {
      auto data_ = data.data();
      auto size_ = data.size();

      auto uri_path = serialized::read<ccf::endpoints::URI>(data_, size_);
      auto verb = serialized::read<ccf::RESTVerb>(data_, size_);
      return {uri_path, verb};
    }
  };
}

namespace ccf
{
  namespace endpoints
  {
    DECLARE_JSON_ENUM(
      ForwardingRequired,
      {{ForwardingRequired::Sometimes, "sometimes"},
       {ForwardingRequired::Always, "always"},
       {ForwardingRequired::Never, "never"}});

    DECLARE_JSON_ENUM(
      ExecuteOutsideConsensus,
      {{ExecuteOutsideConsensus::Never, "never"},
       {ExecuteOutsideConsensus::Locally, "locally"},
       {ExecuteOutsideConsensus::Primary, "primary"}});

    DECLARE_JSON_ENUM(
      Mode,
      {{Mode::ReadWrite, "readwrite"},
       {Mode::ReadOnly, "readonly"},
       {Mode::Historical, "historical"}});

    using AuthnPolicies = std::vector<std::shared_ptr<AuthnPolicy>>;

    struct EndpointProperties
    {
      Mode mode = Mode::ReadWrite;
      ForwardingRequired forwarding_required = ForwardingRequired::Always;
      ExecuteOutsideConsensus execute_outside_consensus =
        ExecuteOutsideConsensus::Never;
      std::vector<std::string> authn_policies = {};

      nlohmann::json openapi;
      bool openapi_hidden = false;
    };

    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(EndpointProperties);
    DECLARE_JSON_REQUIRED_FIELDS(
      EndpointProperties, forwarding_required, authn_policies);
    DECLARE_JSON_OPTIONAL_FIELDS(
      EndpointProperties, openapi, openapi_hidden, mode);

    struct EndpointDefinition
    {
      virtual ~EndpointDefinition() = default;

      EndpointKey dispatch;
      EndpointProperties properties;

      /** List of authentication policies which will be checked before executing
       * this endpoint.
       *
       * When multiple policies are specified, any single successful check is
       * sufficient to grant access, even if others fail. If all policies fail,
       * the last will set an error status on the response, and the endpoint
       * will not be invoked. If no policies are specified then the default
       * behaviour is that the endpoint accepts all requests, without any
       * authentication checks.
       *
       * If an auth policy passes, it may construct an object describing the
       * Identity of the caller to be used by the endpoint. This can be
       * retrieved inside the endpoint with ctx.get_caller<IdentType>(),
       * @see ccf::UserCertAuthnIdentity
       * @see ccf::JwtAuthnIdentity
       * @see ccf::UserSignatureAuthnIdentity
       *
       * @see ccf::empty_auth_policy
       * @see ccf::user_cert_auth_policy
       * @see ccf::user_signature_auth_policy
       */
      AuthnPolicies authn_policies;
    };

    using EndpointDefinitionPtr = std::shared_ptr<const EndpointDefinition>;

    using EndpointsMap = ccf::ServiceMap<EndpointKey, EndpointProperties>;
  }
}