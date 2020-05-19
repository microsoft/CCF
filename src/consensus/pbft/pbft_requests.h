// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/entities.h"

#include <msgpack/msgpack.hpp>
#include <vector>

namespace pbft
{
  struct Request
  {
    uint64_t caller_id;
    std::vector<uint8_t> caller_cert;
    std::vector<uint8_t> raw;
    std::vector<uint8_t> pbft_raw;
    uint8_t frame_format = enclave::FrameFormat::http;

    MSGPACK_DEFINE(caller_id, caller_cert, raw, pbft_raw, frame_format);

    std::vector<uint8_t> serialise()
    {
      bool include_caller = false;
      size_t size = sizeof(caller_id) + sizeof(bool) + sizeof(size_t) +
        raw.size() + sizeof(size_t) + sizeof(enclave::FrameFormat) +
        pbft_raw.size();
      if (!caller_cert.empty())
      {
        size += sizeof(size_t) + caller_cert.size();
        include_caller = true;
      }

      std::vector<uint8_t> serialized_req(size);
      auto data_ = serialized_req.data();
      auto size_ = serialized_req.size();
      serialized::write(data_, size_, caller_id);
      serialized::write(data_, size_, include_caller);
      if (include_caller)
      {
        serialized::write(data_, size_, caller_cert.size());
        serialized::write(data_, size_, caller_cert.data(), caller_cert.size());
      }
      serialized::write(data_, size_, raw.size());
      serialized::write(data_, size_, raw.data(), raw.size());
      serialized::write(data_, size_, pbft_raw.size());
      serialized::write(data_, size_, pbft_raw.data(), pbft_raw.size());

      serialized::write(data_, size_, frame_format);
      return serialized_req;
    }

    void deserialise(const uint8_t* data_, size_t size_)
    {
      caller_id = serialized::read<uint64_t>(data_, size_);
      auto includes_caller = serialized::read<bool>(data_, size_);
      if (includes_caller)
      {
        auto caller_size = serialized::read<size_t>(data_, size_);
        caller_cert = serialized::read(data_, size_, caller_size);
      }
      auto raw_size = serialized::read<size_t>(data_, size_);
      raw = serialized::read(data_, size_, raw_size);
      auto pbft_raw_size = serialized::read<size_t>(data_, size_);
      pbft_raw = serialized::read(data_, size_, pbft_raw_size);

      frame_format = serialized::read<enclave::FrameFormat>(data_, size_);
    }
  };

  DECLARE_JSON_TYPE(Request);
  DECLARE_JSON_REQUIRED_FIELDS(
    Request, caller_id, caller_cert, raw, pbft_raw, frame_format);

  // size_t is used as the key of the table. This key will always be 0 since we
  // don't want to store the requests in the kv over time, we just want to get
  // them into the ledger
  using RequestsMap = ccf::Store::Map<size_t, Request>;
}