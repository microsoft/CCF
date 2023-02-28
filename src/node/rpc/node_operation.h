// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/rpc/node_interface.h"
#include "node/rpc/node_operation_interface.h"

namespace ccf
{
  class NodeOperation : public AbstractNodeOperation
  {
  protected:
    AbstractNodeState& impl;

  public:
    NodeOperation(AbstractNodeState& impl_) : impl(impl_) {}

    ExtendedState state() override
    {
      return impl.state();
    }

    bool is_in_initialised_state() const override
    {
      return impl.is_in_initialised_state();
    }

    bool is_part_of_public_network() const override
    {
      return impl.is_part_of_public_network();
    }

    bool is_part_of_network() const override
    {
      return impl.is_part_of_network();
    }

    bool is_reading_public_ledger() const override
    {
      return impl.is_reading_public_ledger();
    }

    bool is_reading_private_ledger() const override
    {
      return impl.is_reading_private_ledger();
    }

    bool can_replicate() override
    {
      return impl.can_replicate();
    }

    kv::Version get_last_recovered_signed_idx() override
    {
      return impl.get_last_recovered_signed_idx();
    }

    kv::Version get_startup_snapshot_seqno() override
    {
      return impl.get_startup_snapshot_seqno();
    }

    SessionMetrics get_session_metrics() override
    {
      return impl.get_session_metrics();
    }

    size_t get_jwt_attempts() override
    {
      return impl.get_jwt_attempts();
    }

    QuoteVerificationResult verify_quote(
      kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der,
      PlatformAttestationMeasurement& measurement) override
    {
      return impl.verify_quote(
        tx, quote_info, expected_node_public_key_der, measurement);
    }

    void initiate_private_recovery(kv::Tx& tx) override
    {
      impl.initiate_private_recovery(tx);
    }

    crypto::Pem get_self_signed_node_certificate() override
    {
      return impl.get_self_signed_certificate();
    }
  };
}