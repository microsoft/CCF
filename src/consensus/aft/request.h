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

    size_t serialised_size() const
    {
      size_t size = sizeof(rid) + sizeof(bool) + sizeof(size_t) + raw.size() +
        sizeof(enclave::FrameFormat);

      if (!caller_cert.empty())
      {
        size += sizeof(size_t) + caller_cert.size();
      }
      return size;
    }

    void serialise(uint8_t* data, size_t size) const
    {
      bool include_caller = false;
      if (!caller_cert.empty())
      {
        include_caller = true;
      }

      serialized::write(data, size, rid);
      serialized::write(data, size, include_caller);
      if (include_caller)
      {
        serialized::write(data, size, caller_cert.size());
        serialized::write(data, size, caller_cert.data(), caller_cert.size());
      }
      serialized::write(data, size, raw.size());
      serialized::write(data, size, raw.data(), raw.size());

      serialized::write(data, size, frame_format);
    }

    std::vector<uint8_t> serialise() const
    {
      std::vector<uint8_t> serialised_req(serialised_size());
      serialise(serialised_req.data(), serialised_req.size());
      return serialised_req;
    }

    void apply(const uint8_t* data_, size_t size_)
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
  using RequestsMap = kv::RawCopySerialisedMap<size_t, Request>;
}

namespace kv::serialisers
{
  template <>
  struct BlitSerialiser<aft::Request>
  {
    static SerialisedEntry to_serialised(const aft::Request& request)
    {
      SerialisedEntry s(request.serialised_size());
      request.serialise(s.data(), s.size());
      return s;
    }

    static aft::Request from_serialised(const SerialisedEntry& data)
    {
      aft::Request r;
      r.apply(data.data(), data.size());
      return r;
    }
  };
}
