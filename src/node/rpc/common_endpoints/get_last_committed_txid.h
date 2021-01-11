// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "node/rpc/tx_status.h"

#include <optional>

namespace ccf
{
  static std::optional<std::pair<kv::Consensus::View, kv::Consensus::SeqNo>>
  get_last_committed_txid_v1(kv::Consensus* consensus)
  {
    if (consensus != nullptr)
    {
      return consensus->get_committed_txid();
    }

    return std::nullopt;
  }
}