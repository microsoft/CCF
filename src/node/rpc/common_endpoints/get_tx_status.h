// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "node/rpc/tx_status.h"

namespace ccf
{
  static ccf::TxStatus get_tx_status_v1(
    kv::Consensus* consensus, const TxID& tx_id)
  {
    if (consensus != nullptr)
    {
      const auto tx_view = consensus->get_view(tx_id.version);
      const auto committed_seqno = consensus->get_committed_seqno();
      const auto committed_view = consensus->get_view(committed_seqno);

      return ccf::evaluate_tx_status(
        tx_id.term, tx_id.version, tx_view, committed_view, committed_seqno);
    }

    return ccf::TxStatus::Unknown;
  }
}