// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoints/authentication/authentication_types.h"
#include "ccf/entity_id.h"

namespace ccf
{
  namespace
  {
    std::optional<OpenAPISecuritySchema> get_cert_based_security_schema()
    {
      // There is currently no OpenAPI-compliant way to describe cert-based TLS
      // auth, so this policy is not documented. This should change in
      // OpenAPI3.1: https://github.com/OAI/OpenAPI-Specification/pull/1764
      return std::nullopt;
    }
  }

  struct UserCertAuthnIdentity : public AuthnIdentity
  {
    /** CCF user ID */
    UserId user_id;
  };

  class UserCertAuthnPolicy : public AuthnPolicy
  {
  public:
    static constexpr auto SECURITY_SCHEME_NAME = "user_cert";

    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override;

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      return get_cert_based_security_schema();
    }
  };

  struct MemberCertAuthnIdentity : public AuthnIdentity
  {
    /** CCF member ID */
    MemberId member_id;
  };

  class MemberCertAuthnPolicy : public AuthnPolicy
  {
  public:
    static constexpr auto SECURITY_SCHEME_NAME = "member_cert";

    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override;

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      return get_cert_based_security_schema();
    }
  };

  struct NodeCertAuthnIdentity : public AuthnIdentity
  {
    ccf::NodeId node_id;
  };

  class NodeCertAuthnPolicy : public AuthnPolicy
  {
  public:
    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override;

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      return get_cert_based_security_schema();
    }
  };
}
