// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/pbft/libbyz/parameters.h"
#include "kv/map.h"

#include <array>
#include <msgpack/msgpack.hpp>
#include <vector>

namespace pbft
{
  struct NewView
  {
    int64_t view;
    int node_id;
    std::vector<uint8_t> contents;

    MSGPACK_DEFINE(view, node_id, contents);
  };

  DECLARE_JSON_TYPE(NewView);
  DECLARE_JSON_REQUIRED_FIELDS(NewView, view, node_id, contents);

  // size_t is used as the key of the table. This key will always be 0 since we
  // don't want to store the new views in the kv over time, we just want to
  // get them into the ledger
  using NewViewsMap = kv::Map<size_t, NewView>;
}