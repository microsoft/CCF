// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/entities.h"
#include "node_call_types.h"

namespace ccf
{
  enum class QuoteVerificationResult
  {
    Verified = 0,
    Failed,
    FailedCodeIdNotFound,
    FailedInvalidQuotedPublicKey,
  };

  using ExtendedState = std::tuple<
    State,
    std::optional<kv::Version> /* recovery_target_seqno */,
    std::optional<kv::Version> /* last_recovered_seqno */>;

  class AbstractNodeState
  {
  public:
    virtual ~AbstractNodeState() {}
    virtual void transition_service_to_open(kv::Tx& tx) = 0;
    virtual bool rekey_ledger(kv::Tx& tx) = 0;
    virtual void trigger_recovery_shares_refresh(kv::Tx& tx) = 0;
    virtual bool is_part_of_public_network() const = 0;
    virtual bool is_primary() const = 0;
    virtual bool is_reading_public_ledger() const = 0;
    virtual bool is_reading_private_ledger() const = 0;
    virtual bool is_verifying_snapshot() const = 0;
    virtual bool is_part_of_network() const = 0;
    virtual NodeId get_node_id() const = 0;
    virtual kv::Version get_last_recovered_signed_idx() = 0;
    virtual void initiate_private_recovery(kv::Tx& tx) = 0;
    virtual ExtendedState state() = 0;
    virtual void open_user_frontend() = 0;
    virtual QuoteVerificationResult verify_quote(
      kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der) = 0;
  };
}