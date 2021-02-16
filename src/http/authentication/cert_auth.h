// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "authentication_types.h"
#include "node/certs.h"
#include "node/members.h"
#include "node/nodes.h"
#include "node/users.h"
#include "tls/pem.h"

namespace ccf
{
  struct UserCertAuthnIdentity : public AuthnIdentity
  {
    /** CCF user ID, as defined in @c public:ccf.gov.users.info table */
    UserId user_id;
    /** User certificate, as established by TLS */
    tls::Pem user_cert;
    /** Additional user data, as defined in @c public:ccf.gov.users.info */
    nlohmann::json user_data;
  };

  class UserCertAuthnPolicy : public AuthnPolicy
  {
  public:
    static constexpr auto SECURITY_SCHEME_NAME = "user_cert";

    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) override
    {
      const auto caller_cert = ctx->session->caller_cert;

      auto users_by_cert = tx.ro<CertDERs>(Tables::USER_CERT_DERS);
      const auto user_id = users_by_cert->get(caller_cert);

      if (user_id.has_value())
      {
        Users users_table(Tables::USERS);
        auto users = tx.ro(users_table);
        const auto user = users->get(user_id.value());
        if (!user.has_value())
        {
          throw std::logic_error("Users and user certs tables do not match");
        }

        auto identity = std::make_unique<UserCertAuthnIdentity>();
        identity->user_id = user_id.value();
        identity->user_cert = user->cert;
        identity->user_data = user->user_data;
        return identity;
      }
      else
      {
        error_reason = "Could not find matching user certificate";
      }

      return nullptr;
    }

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      // There is currently no OpenAPI-compliant way to describe cert-based TLS
      // auth, so this policy is not documented. This should change in
      // OpenAPI3.1: https://github.com/OAI/OpenAPI-Specification/pull/1764
      return std::nullopt;
    }
  };

  struct MemberCertAuthnIdentity : public AuthnIdentity
  {
    MemberId member_id;
    tls::Pem member_cert;
    nlohmann::json member_data;
  };

  class MemberCertAuthnPolicy : public AuthnPolicy
  {
  public:
    static constexpr auto SECURITY_SCHEME_NAME = "member_cert";

    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) override
    {
      const auto caller_cert = ctx->session->caller_cert;

      auto members_by_cert = tx.ro<CertDERs>(Tables::MEMBER_CERT_DERS);
      const auto member_id = members_by_cert->get(caller_cert);

      if (member_id.has_value())
      {
        Members members_table(Tables::MEMBERS);
        auto members = tx.ro(members_table);
        const auto member = members->get(member_id.value());
        if (!member.has_value())
        {
          throw std::logic_error(
            "Members and member certs tables do not match");
        }

        auto identity = std::make_unique<MemberCertAuthnIdentity>();
        identity->member_id = member_id.value();
        identity->member_cert = member->cert;
        identity->member_data = member->member_data;
        return identity;
      }
      else
      {
        error_reason = "Could not find matching member certificate";
      }

      return nullptr;
    }

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      // There is currently no OpenAPI-compliant way to describe cert-based TLS
      // auth, so this policy is not documented. This should change in
      // OpenAPI3.1: https://github.com/OAI/OpenAPI-Specification/pull/1764
      return std::nullopt;
    }
  };

  struct NodeCertAuthnIdentity : public AuthnIdentity
  {
    ccf::NodeId node_id;
    ccf::NodeInfo node_info;
  };

  class NodeCertAuthnPolicy : public AuthnPolicy
  {
  public:
    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) override
    {
      const auto caller_cert_pem =
        tls::cert_der_to_pem(ctx->session->caller_cert);

      std::unique_ptr<NodeCertAuthnIdentity> identity = nullptr;

      auto nodes = tx.ro<ccf::Nodes>(Tables::NODES);
      nodes->foreach(
        [&caller_cert_pem, &identity](const auto& id, const auto& info) {
          if (info.cert == caller_cert_pem)
          {
            identity = std::make_unique<NodeCertAuthnIdentity>();
            identity->node_id = id;
            identity->node_info = info;
            return false;
          }

          return true;
        });

      if (identity == nullptr)
      {
        error_reason = "Caller cert does not match any known node cert";
      }

      return identity;
    }

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      // There is currently no OpenAPI-compliant way to describe cert-based TLS
      // auth, so this policy is not documented. This should change in
      // OpenAPI3.1: https://github.com/OAI/OpenAPI-Specification/pull/1764
      return std::nullopt;
    }
  };
}
