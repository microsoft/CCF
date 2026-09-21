// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoints/authentication/cert_auth.h"
#include "ccf/node_context.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/nodes.h"

namespace ccf
{
  class SelfCertAuthnPolicy : public AnyCertAuthnPolicy
  {
  private:
    const AbstractNodeContext& node_context;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "self_cert";

    explicit SelfCertAuthnPolicy(const AbstractNodeContext& node_context_) :
      node_context(node_context_)
    {}

    std::unique_ptr<AuthnIdentity> authenticate(
      ccf::kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override
    {
      auto identity = AnyCertAuthnPolicy::authenticate(tx, ctx, error_reason);
      if (identity == nullptr)
      {
        return nullptr;
      }

      const auto caller_node_id =
        compute_node_id_from_cert_der(ctx->get_session_context()->caller_cert);
      // The node ID may not be set yet when this policy is constructed.
      if (caller_node_id != node_context.get_node_id())
      {
        error_reason = "Only the node itself can call this endpoint.";
        return nullptr;
      }

      return identity;
    }

    std::string get_security_scheme_name() override
    {
      return SECURITY_SCHEME_NAME;
    }
  };
}
