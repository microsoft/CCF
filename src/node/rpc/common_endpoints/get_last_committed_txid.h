// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "node/rpc/tx_status.h"

#include <optional>

namespace ccf
{
  // TODO: TxID says (term, version), but this is the public API we want to
  // expose!
  static std::optional<kv::TxID> get_last_committed_txid_v1(
    kv::Consensus* consensus)
  {
    if (consensus != nullptr)
    {
      return consensus->get_committed_txid();
    }

    return std::nullopt;
  }
}