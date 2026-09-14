// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoints/authentication/authentication_types.h"
#include "ccf/entity_id.h"

namespace ccf
{
  inline std::optional<OpenAPISecuritySchema> get_cert_based_security_schema()
  {
    // There is currently no OpenAPI-compliant way to describe cert-based TLS
    // auth, so this policy is not documented. This should change in
    // OpenAPI3.1: https://github.com/OAI/OpenAPI-Specification/pull/1764
    return std::nullopt;
  }

  struct UserCertAuthnIdentity : public AuthnIdentity
  {
    /** CCF user ID */
    UserId user_id;
  };

  struct ValidityPeriodsCache;

  class UserCertAuthnPolicy : public AuthnPolicy
  {
  protected:
    std::unique_ptr<ValidityPeriodsCache> validity_periods;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "user_cert";

    UserCertAuthnPolicy();
    ~UserCertAuthnPolicy() override;

    std::unique_ptr<AuthnIdentity> authenticate(
      ccf::kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override;

    [[nodiscard]] std::optional<OpenAPISecuritySchema>
    get_openapi_security_schema() const override
    {
      return get_cert_based_security_schema();
    }

    std::string get_security_scheme_name() override
    {
      return SECURITY_SCHEME_NAME;
    };
  };

  struct MemberCertAuthnIdentity : public AuthnIdentity
  {
    /** CCF member ID */
    MemberId member_id;
  };

  class MemberCertAuthnPolicy : public AuthnPolicy
  {
  protected:
    std::unique_ptr<ValidityPeriodsCache> validity_periods;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "member_cert";

    MemberCertAuthnPolicy();
    ~MemberCertAuthnPolicy() override;

    std::unique_ptr<AuthnIdentity> authenticate(
      ccf::kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override;

    [[nodiscard]] std::optional<OpenAPISecuritySchema>
    get_openapi_security_schema() const override
    {
      return get_cert_based_security_schema();
    }

    std::string get_security_scheme_name() override
    {
      return SECURITY_SCHEME_NAME;
    };
  };

  struct NodeCertAuthnIdentity : public AuthnIdentity
  {
    ccf::NodeId node_id;
  };

  class NodeCertAuthnPolicy : public AuthnPolicy
  {
  public:
    static constexpr auto SECURITY_SCHEME_NAME = "node_cert";

    std::unique_ptr<AuthnIdentity> authenticate(
      ccf::kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override;

    [[nodiscard]] std::optional<OpenAPISecuritySchema>
    get_openapi_security_schema() const override
    {
      return get_cert_based_security_schema();
    }

    std::string get_security_scheme_name() override
    {
      return SECURITY_SCHEME_NAME;
    };
  };

  struct AnyCertAuthnIdentity : public AuthnIdentity
  {
    // Certificate as a vector of DER-encoded bytes
    std::vector<uint8_t> cert;
  };

  class AnyCertAuthnPolicy : public AuthnPolicy
  {
  protected:
    std::unique_ptr<ValidityPeriodsCache> validity_periods;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "any_cert";

    AnyCertAuthnPolicy();
    ~AnyCertAuthnPolicy() override;

    std::unique_ptr<AuthnIdentity> authenticate(
      ccf::kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override;

    [[nodiscard]] std::optional<OpenAPISecuritySchema>
    get_openapi_security_schema() const override
    {
      return get_cert_based_security_schema();
    }

    std::string get_security_scheme_name() override
    {
      return SECURITY_SCHEME_NAME;
    };
  };
}
