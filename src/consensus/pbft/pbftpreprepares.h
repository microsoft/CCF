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
  struct PrePrepare
  {
    int64_t seqno;
    int16_t num_big_requests;
    PbftSignature digest_sig;
    std::vector<uint8_t> contents;

    MSGPACK_DEFINE(seqno, num_big_requests, digest_sig, contents);
  };

  DECLARE_JSON_TYPE(PrePrepare);
  DECLARE_JSON_REQUIRED_FIELDS(
    PrePrepare, seqno, num_big_requests, digest_sig, contents);

  // size_t is used as the key of the table. This key will always be 0 since we
  // don't want to store the pre prepare in the kv over time, we just want to
  // get them into the ledger
  using PrePreparesMap = ccf::Store::Map<size_t, PrePrepare>;
}