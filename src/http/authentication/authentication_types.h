// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpc_context.h"
#include "kv/tx.h"

#include <memory>

namespace ccf
{
  struct AuthnIdentity
  {
    virtual ~AuthnIdentity() = default;
  };

  class AuthnPolicy
  {
  public:
    using OpenAPISecuritySchema = std::pair<std::string, nlohmann::json>;
    static OpenAPISecuritySchema unauthenticated_schema()
    {
      return std::make_pair("", nlohmann::json());
    }

    virtual ~AuthnPolicy() = default;

    virtual std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) = 0;

    virtual void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>& ctx,
      std::string&& error_reason) = 0;

    virtual OpenAPISecuritySchema get_openapi_security_schema() const = 0;
  };

  // To make authentication _optional_, we list no-auth as one of several
  // specified policies
  // TODO: Is this worth doing? Or should we just keep "require_client_identity
  // = false", and use that for all the special casing?
  struct EmptyAuthnIdentity : public AuthnIdentity
  {};

  class EmptyAuthnPolicy : public AuthnPolicy
  {
  public:
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

    OpenAPISecuritySchema get_openapi_security_schema() const override
    {
      return unauthenticated_schema();
    }
  };
}