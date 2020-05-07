// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/pbft/libbyz/parameters.h"
#include "node/entities.h"

#include <array>
#include <msgpack/msgpack.hpp>
#include <vector>

namespace pbft
{
  struct ViewChange
  {
    int64_t view;
    int node_id;
    std::vector<uint8_t> contents;

    MSGPACK_DEFINE(view, node_id, contents);
  };

  DECLARE_JSON_TYPE(ViewChange);
  DECLARE_JSON_REQUIRED_FIELDS(ViewChange, view, node_id, contents);

  // size_t is used as the key of the table. This key will always be 0 since we
  // don't want to store the view changes in the kv over time, we just want to
  // get them into the ledger
  using ViewChangesMap = ccf::Store::Map<size_t, ViewChange>;
}