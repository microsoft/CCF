// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/cert_auth.h"

#include "ccf/rpc_context.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/users.h"
#include "ds/x509_time_fmt.h"
#include "enclave/enclave_time.h"

namespace ccf
{
  static inline bool is_cert_valid_now(
    const std::vector<uint8_t>& der_cert, std::string& error_reason)
  {
    auto verifier = crypto::make_unique_verifier(der_cert);

    const auto [valid_from_timestring, valid_to_timestring] =
      verifier->validity_period();

    using namespace std::chrono;

    const auto valid_from_unix_time =
      duration_cast<seconds>(
        ds::time_point_from_string(valid_from_timestring).time_since_epoch())
        .count();
    const auto valid_to_unix_time =
      duration_cast<seconds>(
        ds::time_point_from_string(valid_to_timestring).time_since_epoch())
        .count();

    const auto time_now =
      duration_cast<seconds>(ccf::get_enclave_time()).count();

    if (time_now < valid_from_unix_time)
    {
      error_reason = fmt::format(
        "Current time {} is before certificate's Not Before validity period {}",
        time_now,
        valid_from_unix_time);
      return false;
    }
    else if (time_now > valid_to_unix_time)
    {
      error_reason = fmt::format(
        "Current time {} is after certificate's Not After validity period {}",
        time_now,
        valid_from_unix_time);
      return false;
    }

    return true;
  }

  std::unique_ptr<AuthnIdentity> UserCertAuthnPolicy::authenticate(
    kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    const auto& caller_cert = ctx->get_session_context()->caller_cert;
    if (caller_cert.empty())
    {
      error_reason = "No caller user certificate";
      return nullptr;
    }

    if (!is_cert_valid_now(caller_cert, error_reason))
    {
      return nullptr;
    }

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

  std::unique_ptr<AuthnIdentity> MemberCertAuthnPolicy::authenticate(
    kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    const auto& caller_cert = ctx->get_session_context()->caller_cert;
    if (caller_cert.empty())
    {
      error_reason = "No caller member certificate";
      return nullptr;
    }

    if (!is_cert_valid_now(caller_cert, error_reason))
    {
      return nullptr;
    }

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

  std::unique_ptr<AuthnIdentity> NodeCertAuthnPolicy::authenticate(
    kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    const auto& caller_cert = ctx->get_session_context()->caller_cert;
    if (caller_cert.empty())
    {
      error_reason = "No caller node certificate";
      return nullptr;
    }

    auto node_caller_id = compute_node_id_from_cert_der(caller_cert);

    auto nodes = tx.ro<ccf::Nodes>(Tables::NODES);
    auto node = nodes->get(node_caller_id);
    if (node.has_value())
    {
      auto identity = std::make_unique<NodeCertAuthnIdentity>();
      identity->node_id = node_caller_id;
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
}
