// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"

namespace ccf::kv
{
  struct BaseTx::PrivateImpl
  {
    AbstractStore* store = nullptr;

    // NB: This exists only to maintain the old API, where this Tx stores
    // MapHandles and returns raw pointers to them. It could be removed entirely
    // with a near-identical API if we return `shared_ptr`s, and assuming that
    // we don't actually care about returning exactly the same Handle instance
    // if `rw` is called multiple times
    using PossibleHandles = std::list<std::unique_ptr<AbstractHandle>>;
    std::map<std::string, PossibleHandles> all_handles;

    // Note: read_txid version is set to NoVersion for the first transaction in
    // the service, before anything has been applied to the KV.
    std::optional<TxID> read_txid = std::nullopt;
    ccf::View commit_view = ccf::VIEW_UNKNOWN;

    std::map<std::string, std::shared_ptr<AbstractMap>> created_maps;
  };
}