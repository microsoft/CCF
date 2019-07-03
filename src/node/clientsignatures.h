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
    std::vector<uint8_t> sig;
    // the encoded json-rpc sent by the client
    std::vector<uint8_t> req;

    MSGPACK_DEFINE(sig, req);
  };
  // this maps client-id to latest SignedReq
  using ClientSignatures = Store::Map<CallerId, SignedReq>;

  inline void to_json(nlohmann::json& j, const SignedReq& sr)
  {
    if (!sr.sig.empty())
    {
      j["sig"] = sr.sig;
    }
    if (!sr.req.empty())
    {
      j["req"] = nlohmann::json::from_msgpack(sr.req);
    }
  }

  inline void from_json(const nlohmann::json& j, SignedReq& sr)
  {
    auto sig_it = j.find("req");
    if (sig_it != j.end())
    {
      assign_j(sr.sig, j["sig"]);
    }
    auto req_it = j.find("req");
    if (req_it != j.end())
    {
      assign_j(sr.req, nlohmann::json::to_msgpack(req_it.value()));
    }
  }
}