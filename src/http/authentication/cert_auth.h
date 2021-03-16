// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "authentication_types.h"
#include "crypto/pem.h"
#include "node/certs.h"
#include "node/members.h"
#include "node/nodes.h"
#include "node/users.h"

namespace ccf
{
  struct UserCertAuthnIdentity : public AuthnIdentity
  {
    /** CCF user ID */
    UserId user_id;
    /** User certificate, as established by TLS */
    crypto::Pem user_cert;
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
      const auto& caller_cert = ctx->session->caller_cert;
      auto caller_id = crypto::Sha256Hash(caller_cert).hex_str();

      auto user_certs = tx.ro<UserCerts>(Tables::USER_CERTS);
      const auto user_cert = user_certs->get(caller_id);
      if (user_cert.has_value())
      {
        auto identity = std::make_unique<UserCertAuthnIdentity>();
        identity->user_id = caller_id;
        identity->user_cert = user_cert.value();
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
    crypto::Pem member_cert;
    // nlohmann::json member_data; // TODO: Delete
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
      const auto& caller_cert = ctx->session->caller_cert;
      auto caller_id = crypto::Sha256Hash(caller_cert).hex_str();

      auto member_certs = tx.ro<MemberCerts>(Tables::MEMBER_CERTS);
      const auto member_cert = member_certs->get(caller_id);
      if (member_cert.has_value())
      {
        auto identity = std::make_unique<MemberCertAuthnIdentity>();
        identity->member_id = caller_id;
        identity->member_cert = member_cert.value();
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
        crypto::cert_der_to_pem(ctx->session->caller_cert);

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
