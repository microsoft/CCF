// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/quote_info.h"
#include "ccf/node_startup_state.h"
#include "ccf/service/acme_client_config.h"
#include "ccf/service/node_info_network.h"
#include "ccf/service/tables/code_id.h"
#include "common/configuration.h"
#include "http/http_builder.h"
#include "http/http_parser.h"
#include "node/rpc/gov_effects_interface.h"
#include "node/rpc/node_operation_interface.h"
#include "node/session_metrics.h"

namespace ccf
{
  class AbstractNodeState
  {
  public:
    virtual ~AbstractNodeState() {}

    virtual void transition_service_to_open(
      kv::Tx& tx, AbstractGovernanceEffects::ServiceIdentities identities) = 0;
    virtual bool rekey_ledger(kv::Tx& tx) = 0;
    virtual void trigger_recovery_shares_refresh(kv::Tx& tx) = 0;
    virtual void trigger_ledger_chunk(kv::Tx& tx) = 0;
    virtual void trigger_snapshot(kv::Tx& tx) = 0;
    virtual void trigger_host_process_launch(
      const std::vector<std::string>& args) = 0;
    virtual void trigger_acme_refresh(
      kv::Tx& tx,
      const std::optional<std::vector<std::string>>& interfaces =
        std::nullopt) = 0;
    virtual void install_custom_acme_challenge_handler(
      const NodeInfoNetwork::RpcInterfaceID& interface_id,
      std::shared_ptr<ACMEChallengeHandler> h) = 0;
    virtual bool is_in_initialised_state() const = 0;
    virtual bool is_part_of_public_network() const = 0;
    virtual bool is_primary() const = 0;
    virtual bool can_replicate() = 0;
    virtual bool is_reading_public_ledger() const = 0;
    virtual bool is_reading_private_ledger() const = 0;
    virtual bool is_part_of_network() const = 0;
    virtual kv::Version get_last_recovered_signed_idx() = 0;
    virtual void initiate_private_recovery(kv::Tx& tx) = 0;
    virtual ExtendedState state() = 0;
    virtual QuoteVerificationResult verify_quote(
      kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der,
      pal::PlatformAttestationMeasurement& measurement) = 0;
    virtual kv::Version get_startup_snapshot_seqno() = 0;
    virtual SessionMetrics get_session_metrics() = 0;
    virtual size_t get_jwt_attempts() = 0;
    virtual crypto::Pem get_self_signed_certificate() = 0;
    virtual const StartupConfig& get_node_config() const = 0;
    virtual crypto::Pem get_network_cert() = 0;

    virtual void make_http_request(
      const http::URL& url,
      http::Request&& req,
      std::function<
        bool(http_status status, http::HeaderMap&&, std::vector<uint8_t>&&)>
        callback,
      const std::vector<std::string>& ca_certs = {},
      ccf::ApplicationProtocol app_protocol = ccf::ApplicationProtocol::HTTP1,
      bool use_node_client_certificate = false) = 0;
  };
}