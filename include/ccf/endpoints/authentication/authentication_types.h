// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"

#include <memory>
#include <nlohmann/json.hpp>
#include <string>

namespace ccf
{
  class RpcContext;
}

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
      ccf::kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) = 0;

    virtual void set_unauthenticated_error(
      std::shared_ptr<ccf::RpcContext> ctx, std::string&& error_reason)
    {}

    [[nodiscard]] virtual std::optional<OpenAPISecuritySchema>
    get_openapi_security_schema() const = 0;

    virtual std::string get_security_scheme_name() = 0;
  };

  using AuthnPolicies = std::vector<std::shared_ptr<AuthnPolicy>>;
}