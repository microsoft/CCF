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

  inline void to_json(nlohmann::json& j, const Request& r)
  {
    j["actor"] = r.actor;
    j["caller_id"] = r.caller_id;
    j["caller_cert"] = r.caller_cert;
    j["raw"] = r.raw;
  }

  inline void from_json(const nlohmann::json& j, Request& r)
  {
    r.actor = j["actor"];
    r.caller_id = j["caller_id"];
    assign_j(r.caller_cert, j["caller_cert"]);
    assign_j(r.raw, j["raw"]);
  }
}