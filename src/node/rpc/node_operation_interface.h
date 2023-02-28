// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/quote_info.h"
#include "ccf/node/quote.h"
#include "ccf/node_startup_state.h"
#include "ccf/node_subsystem_interface.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/tx.h"
#include "node/session_metrics.h"

namespace ccf
{
  using ExtendedState = std::tuple<
    NodeStartupState,
    std::optional<kv::Version> /* recovery_target_seqno */,
    std::optional<kv::Version> /* last_recovered_seqno */>;

  class AbstractNodeOperation : public ccf::AbstractNodeSubSystem
  {
  public:
    virtual ~AbstractNodeOperation() = default;

    static char const* get_subsystem_name()
    {
      return "NodeOperation";
    }

    virtual ExtendedState state() = 0;

    virtual bool is_in_initialised_state() const = 0;
    virtual bool is_part_of_public_network() const = 0;
    virtual bool is_part_of_network() const = 0;
    virtual bool is_reading_public_ledger() const = 0;
    virtual bool is_reading_private_ledger() const = 0;

    virtual bool can_replicate() = 0;

    virtual kv::Version get_last_recovered_signed_idx() = 0;
    virtual kv::Version get_startup_snapshot_seqno() = 0;

    virtual SessionMetrics get_session_metrics() = 0;
    virtual size_t get_jwt_attempts() = 0;

    virtual QuoteVerificationResult verify_quote(
      kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der,
      pal::PlatformAttestationMeasurement& measurement) = 0;

    virtual void initiate_private_recovery(kv::Tx& tx) = 0;

    virtual crypto::Pem get_self_signed_node_certificate() = 0;
  };
}