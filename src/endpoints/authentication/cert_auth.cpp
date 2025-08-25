// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/cert_auth.h"

#include "ccf/ds/x509_time_fmt.h"
#include "ccf/pal/locking.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/users.h"
#include "ds/lru.h"

namespace ccf
{
  struct ValidityPeriodsCache
  {
    static constexpr size_t DEFAULT_MAX_PERIODS = 500;

    struct ValidityPeriod
    {
      long long valid_from_unix_time;
      long long valid_to_unix_time;
    };

    using DER = std::vector<uint8_t>;

    ccf::pal::Mutex periods_lock;
    LRU<DER, ValidityPeriod> periods;

    ValidityPeriodsCache(size_t max_periods = DEFAULT_MAX_PERIODS) :
      periods(max_periods)
    {}

    ValidityPeriod get_validity_period(const DER& der)
    {
      std::lock_guard<ccf::pal::Mutex> guard(periods_lock);

      auto it = periods.find(der);
      if (it == periods.end())
      {
        auto verifier = ccf::crypto::make_unique_verifier(der);

        const auto [valid_from_timestring, valid_to_timestring] =
          verifier->validity_period();

        using namespace std::chrono;

        const auto valid_from_unix_time =
          duration_cast<seconds>(
            ccf::ds::time_point_from_string(valid_from_timestring)
              .time_since_epoch())
            .count();
        const auto valid_to_unix_time =
          duration_cast<seconds>(
            ccf::ds::time_point_from_string(valid_to_timestring)
              .time_since_epoch())
            .count();

        it = periods.insert(
          der, ValidityPeriod{valid_from_unix_time, valid_to_unix_time});
      }

      return it->second;
    }

    bool is_cert_valid_now(
      const std::vector<uint8_t>& der_cert, std::string& error_reason)
    {
      const auto [valid_from_unix_time, valid_to_unix_time] =
        get_validity_period(der_cert);

      using namespace std::chrono;
      const auto time_now =
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count();

      if (time_now < valid_from_unix_time)
      {
        error_reason = fmt::format(
          "Current time {} is before certificate's Not Before validity period "
          "{}",
          time_now,
          valid_from_unix_time);
        return false;
      }

      if (time_now > valid_to_unix_time)
      {
        error_reason = fmt::format(
          "Current time {} is after certificate's Not After validity period {}",
          time_now,
          valid_to_unix_time);
        return false;
      }

      return true;
    }
  };

  UserCertAuthnPolicy::UserCertAuthnPolicy() :
    validity_periods(std::make_unique<ValidityPeriodsCache>())
  {}

  UserCertAuthnPolicy::~UserCertAuthnPolicy() = default;

  std::unique_ptr<AuthnIdentity> UserCertAuthnPolicy::authenticate(
    ccf::kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    const auto& caller_cert = ctx->get_session_context()->caller_cert;
    if (caller_cert.empty())
    {
      error_reason = "No caller user certificate";
      return nullptr;
    }

    if (!validity_periods->is_cert_valid_now(caller_cert, error_reason))
    {
      // Error is set by the call when necessary
      return nullptr;
    }

    auto caller_id = ccf::crypto::Sha256Hash(caller_cert).hex_str();

    auto* user_certs = tx.ro<UserCerts>(Tables::USER_CERTS);
    if (user_certs->has(caller_id))
    {
      auto identity = std::make_unique<UserCertAuthnIdentity>();
      identity->user_id = caller_id;
      return identity;
    }

    error_reason = "Could not find matching user certificate";
    return nullptr;
  }

  MemberCertAuthnPolicy::MemberCertAuthnPolicy() :
    validity_periods(std::make_unique<ValidityPeriodsCache>())
  {}

  MemberCertAuthnPolicy::~MemberCertAuthnPolicy() = default;

  std::unique_ptr<AuthnIdentity> MemberCertAuthnPolicy::authenticate(
    ccf::kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    const auto& caller_cert = ctx->get_session_context()->caller_cert;
    if (caller_cert.empty())
    {
      error_reason = "No caller member certificate";
      return nullptr;
    }

    auto caller_id = ccf::crypto::Sha256Hash(caller_cert).hex_str();

    auto* member_certs = tx.ro<MemberCerts>(Tables::MEMBER_CERTS);
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
    ccf::kv::ReadOnlyTx& tx,
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

    auto* nodes = tx.ro<ccf::Nodes>(Tables::NODES);
    auto node = nodes->get(node_caller_id);
    if (node.has_value())
    {
      auto identity = std::make_unique<NodeCertAuthnIdentity>();
      identity->node_id = node_caller_id;
      return identity;
    }

    std::vector<ccf::NodeId> known_nids;
    nodes->foreach([&known_nids](const NodeId& nid, const NodeInfo& ni) {
      (void)ni;
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

  AnyCertAuthnPolicy::AnyCertAuthnPolicy() :
    validity_periods(std::make_unique<ValidityPeriodsCache>())
  {}

  AnyCertAuthnPolicy::~AnyCertAuthnPolicy() = default;

  std::unique_ptr<AuthnIdentity> AnyCertAuthnPolicy::authenticate(
    ccf::kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    (void)tx;
    const auto& caller_cert = ctx->get_session_context()->caller_cert;
    if (caller_cert.empty())
    {
      error_reason = "No caller certificate";
      return nullptr;
    }

    if (!validity_periods->is_cert_valid_now(caller_cert, error_reason))
    {
      // Error is set by the call when necessary
      return nullptr;
    }

    auto identity = std::make_unique<AnyCertAuthnIdentity>();
    identity->cert = caller_cert;
    return identity;
  }
}
