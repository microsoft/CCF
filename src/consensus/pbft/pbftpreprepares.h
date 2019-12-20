// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/entities.h"
#include "node/rpc/jsonrpc.h"

#include <msgpack-c/msgpack.hpp>
#include <vector>

namespace pbft
{
  struct PrePrepare
  {
    int64_t seqno;
    int message_size;
    int16_t num_big_requests;
    std::vector<uint8_t> contents;

    MSGPACK_DEFINE(seqno, message_size, num_big_requests, contents);
  };

  DECLARE_JSON_TYPE(PrePrepare);
  DECLARE_JSON_REQUIRED_FIELDS(
    PrePrepare, seqno, message_size, num_big_requests, contents);

  // size_t is used as the key of the table. This key will always be 0 since we
  // don't want to store the pre prepare in the kv over time, we just want to
  // get them into the ledger
  using PrePrepares = ccf::Store::Map<size_t, PrePrepare>;
}