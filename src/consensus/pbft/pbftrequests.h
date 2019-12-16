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

    std::vector<uint8_t> serialise()
    {
      bool include_caller = false;
      size_t size =
        sizeof(actor) + sizeof(caller_id) + sizeof(bool) + raw.size();
      if (!caller_cert.empty())
      {
        size += sizeof(size_t) + caller_cert.size();
        include_caller = true;
      }

      std::vector<uint8_t> serialized_req(size);
      auto data_ = serialized_req.data();
      auto size_ = serialized_req.size();
      serialized::write(data_, size_, actor);
      serialized::write(data_, size_, caller_id);
      serialized::write(data_, size_, include_caller);
      if (include_caller)
      {
        serialized::write(data_, size_, caller_cert.size());
        serialized::write(data_, size_, caller_cert.data(), caller_cert.size());
      }
      serialized::write(data_, size_, raw.data(), raw.size());

      return serialized_req;
    }

    void deserialise(const std::vector<uint8_t>& serialized_req)
    {
      auto data_ = serialized_req.data();
      auto size_ = serialized_req.size();

      actor = serialized::read<uint64_t>(data_, size_);
      caller_id = serialized::read<uint64_t>(data_, size_);
      auto includes_caller = serialized::read<bool>(data_, size_);
      if (includes_caller)
      {
        auto caller_size = serialized::read<size_t>(data_, size_);
        caller_cert = serialized::read(data_, size_, caller_size);
      }
      raw = serialized::read(data_, size_, size_);
    }
  };

  // size_t is used as the key of the table. This key will always be 0 since we
  // don't want to store the requests in the kv over time, we just want to get
  // them into the ledger
  using PbftRequests = ccf::Store::Map<size_t, Request>;

  DECLARE_JSON_TYPE(Request);
  DECLARE_JSON_REQUIRED_FIELDS(Request, actor, caller_id, caller_cert, raw);
}