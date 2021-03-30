// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpc_context.h"
#include "ccf/tx.h"

#include <memory>

namespace ccf
{
  struct AuthnIdentity
  {
    virtual ~AuthnIdentity() = default;
  };

  using OpenAPISecuritySchema = std::pair<std::string, nlohmann::json>;
  static const OpenAPISecuritySchema unauthenticated_schema =
    std::make_pair("", nlohmann::json());

  class AuthnPolicy
  {
  public:
    virtual ~AuthnPolicy() = default;

    virtual std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) = 0;

    virtual void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>& ctx, std::string&& error_reason)
    {
      ctx->set_error(
        HTTP_STATUS_UNAUTHORIZED,
        ccf::errors::InvalidAuthenticationInfo,
        std::move(error_reason));
    }

    virtual std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const = 0;
  };

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
      const std::shared_ptr<enclave::RpcContext>&,
      std::string&) override
    {
      return std::make_unique<EmptyAuthnIdentity>();
    }

    void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>&, std::string&&) override
    {
      throw std::logic_error("Should not happen");
    }

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      return unauthenticated_schema;
    }
  };

  using AuthnPolicies = std::vector<std::shared_ptr<AuthnPolicy>>;
}