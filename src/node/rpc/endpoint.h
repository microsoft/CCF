// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "http/authentication/authentication_types.h"
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

    using AuthnPolicies = std::vector<std::shared_ptr<AuthnPolicy>>;

    struct EndpointProperties
    {
      ForwardingRequired forwarding_required = ForwardingRequired::Always;
      bool execute_locally = false;
      bool require_client_signature = false;
      bool require_client_identity = true;
      bool require_jwt_authentication = false;

      nlohmann::json openapi;
      bool openapi_hidden = false;

      MSGPACK_DEFINE(
        forwarding_required,
        execute_locally,
        require_client_signature,
        require_client_identity,
        require_jwt_authentication,
        openapi,
        openapi_hidden);
    };

    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(EndpointProperties);
    DECLARE_JSON_REQUIRED_FIELDS(
      EndpointProperties,
      forwarding_required,
      execute_locally,
      require_client_signature,
      require_client_identity);
    DECLARE_JSON_OPTIONAL_FIELDS(
      EndpointProperties, require_jwt_authentication, openapi, openapi_hidden);

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

    using EndpointsMap = kv::Map<EndpointKey, EndpointProperties>;
  }
}