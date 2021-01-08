// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "kv/map.h"
#include "node/entities.h"

#include <msgpack/msgpack.hpp>
#include <vector>

namespace aft
{
  struct Request
  {
    kv::TxHistory::RequestID rid;
    std::vector<uint8_t> caller_cert;
    std::vector<uint8_t> raw;
    uint8_t frame_format = enclave::FrameFormat::http;

    MSGPACK_DEFINE(rid, caller_cert, raw, frame_format);

    std::vector<uint8_t> serialise()
    {
      bool include_caller = false;
      size_t size = sizeof(rid) + sizeof(include_caller) + sizeof(size_t) +
        raw.size() + sizeof(enclave::FrameFormat);
      if (!caller_cert.empty())
      {
        size += sizeof(size_t) + caller_cert.size();
        include_caller = true;
      }

      std::vector<uint8_t> serialized_req(size);
      auto data_ = serialized_req.data();
      auto size_ = serialized_req.size();
      serialized::write(data_, size_, rid);
      serialized::write(data_, size_, include_caller);
      if (include_caller)
      {
        serialized::write(data_, size_, caller_cert.size());
        serialized::write(data_, size_, caller_cert.data(), caller_cert.size());
      }
      serialized::write(data_, size_, raw.size());
      serialized::write(data_, size_, raw.data(), raw.size());

      serialized::write(data_, size_, frame_format);
      return serialized_req;
    }

    void deserialise(const uint8_t* data_, size_t size_)
    {
      rid = serialized::read<kv::TxHistory::RequestID>(data_, size_);
      auto includes_caller = serialized::read<bool>(data_, size_);
      if (includes_caller)
      {
        auto caller_size = serialized::read<size_t>(data_, size_);
        caller_cert = serialized::read(data_, size_, caller_size);
      }
      auto raw_size = serialized::read<size_t>(data_, size_);
      raw = serialized::read(data_, size_, raw_size);

      frame_format = serialized::read<enclave::FrameFormat>(data_, size_);
    }
  };

  DECLARE_JSON_TYPE(Request);
  DECLARE_JSON_REQUIRED_FIELDS(Request, rid, caller_cert, raw, frame_format);

  // size_t is used as the key of the table. This key will always be 0 since we
  // don't want to store the requests in the kv over time, we just want to get
  // them into the ledger
  using RequestsMap = kv::Map<size_t, Request>;
}
