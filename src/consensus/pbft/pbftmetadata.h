// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/entities.h"
#include "node/rpc/jsonrpc.h"

#include <msgpack-c/msgpack.hpp>
#include <vector>

namespace pbft
{
  struct Request
  {
    uint64_t actor;
    uint64_t caller_id;
    std::vector<uint8_t> caller_cert;
    std::vector<uint8_t> raw;

    MSGPACK_DEFINE(actor, caller_id, caller_cert, raw);
  };

  using PbftRequests = ccf::Store::Map<size_t, Request>;

  DECLARE_JSON_TYPE(Request);
  DECLARE_JSON_REQUIRED_FIELDS(Request, actor, caller_id, caller_cert, raw);
}