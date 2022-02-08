// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "authentication_types.h"
#include "crypto/pem.h"
#include "crypto/verifier.h"
#include "service/blit.h"
#include "service/table_names.h"
#include "service/tables/members.h"
#include "service/tables/nodes.h"
#include "service/tables/users.h"

namespace ccf
{
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
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) override
    {
      const auto& caller_cert = ctx->session->caller_cert;
      auto caller_id = crypto::Sha256Hash(caller_cert).hex_str();

      auto user_certs = tx.ro<UserCerts>(Tables::USER_CERTS);
      if (user_certs->has(caller_id))
      {
        auto identity = std::make_unique<UserCertAuthnIdentity>();
        identity->user_id = caller_id;
        return identity;
      }

      error_reason = "Could not find matching user certificate";
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
    /** CCF member ID */
    MemberId member_id;
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
      if (member_certs->has(caller_id))
      {
        auto identity = std::make_unique<MemberCertAuthnIdentity>();
        identity->member_id = caller_id;
        return identity;
      }

      error_reason = "Could not find matching member certificate";
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
      auto node_caller_id =
        compute_node_id_from_cert_der(ctx->session->caller_cert);

      auto nodes = tx.ro<ccf::Nodes>(Tables::NODES);
      auto node = nodes->get(node_caller_id);
      if (node.has_value())
      {
        auto identity = std::make_unique<NodeCertAuthnIdentity>();
        identity->node_id = node_caller_id;
        identity->node_info = node.value();
        return identity;
      }

      std::vector<ccf::NodeId> known_nids;
      nodes->foreach([&known_nids](const NodeId& nid, const NodeInfo& ni) {
        known_nids.push_back(nid);
        return true;
      });
      LOG_DEBUG_FMT(
        "Could not find matching node certificate for node {}; we have "
        "certificates for the following node ids: {}",
        node_caller_id,
        fmt::join(known_nids, ", "));

      error_reason = "Could not find matching node certificate";
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
}
