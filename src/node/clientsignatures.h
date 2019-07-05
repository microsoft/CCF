// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "../ds/hash.h"
#include "entities.h"
#include "rpc/jsonrpc.h"

#include <msgpack-c/msgpack.hpp>
#include <vector>

namespace ccf
{
  struct SignedReq
  {
    // the encoded json-rpc signed by the clients private key
    std::vector<uint8_t> sig = {};
    // the encoded json-rpc sent by the client
    std::vector<uint8_t> req = {};

    MSGPACK_DEFINE(sig, req);
  };
  // this maps client-id to latest SignedReq
  using ClientSignatures = Store::Map<CallerId, SignedReq>;

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(SignedReq)
  DECLARE_JSON_REQUIRED_FIELDS(SignedReq, sig);
  DECLARE_JSON_OPTIONAL_FIELDS(SignedReq, req);
}