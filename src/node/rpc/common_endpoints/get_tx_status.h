// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "node/rpc/tx_status.h"

namespace ccf
{
  // TODO: Should really be passing enough state here so we can reliably support this for a long time...
  static ccf::TxStatus get_tx_status_v1(
    kv::Consensus* consensus,
    kv::Consensus::View view,
    kv::Consensus::SeqNo seqno)
  {
    if (consensus != nullptr)
    {
      const auto tx_view = consensus->get_view(seqno);
      const auto committed_seqno = consensus->get_committed_seqno();
      const auto committed_view = consensus->get_view(committed_seqno);

      return ccf::evaluate_tx_status(
        view, seqno, tx_view, committed_view, committed_seqno);
    }

    return ccf::TxStatus::Unknown;
  }
}