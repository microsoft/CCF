// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoints/authentication/authentication_types.h"

namespace ccf
{
  // To make authentication _optional_, no-auth can be listed as one of several
  // specified policies
  struct EmptyAuthnIdentity : public AuthnIdentity
  {};

  class EmptyAuthnPolicy : public AuthnPolicy
  {
  public:
    static constexpr auto SECURITY_SCHEME_NAME = "no_auth";

    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx&,
      const std::shared_ptr<ccf::RpcContext>&,
      std::string&) override;

    void set_unauthenticated_error(
      std::shared_ptr<ccf::RpcContext>, std::string&&) override;

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      return unauthenticated_schema;
    }
  };
}
