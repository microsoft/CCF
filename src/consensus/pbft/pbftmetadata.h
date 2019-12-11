// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/entities.h"
#include "node/rpc/jsonrpc.h"

#include <msgpack-c/msgpack.hpp>
#include <vector>

namespace pbft
{
  enum class DataType
  {
    REQUEST = 0,
    PRE_PREPARE = 1
  };
}

MSGPACK_ADD_ENUM(pbft::DataType);

namespace pbft
{
  struct PbftMeta
  {
    std::vector<uint8_t> metadata;
    DataType data_type;

    MSGPACK_DEFINE(metadata, data_type);
  };
  using PbftMetaData = ccf::Store::Map<size_t, PbftMeta>;

  inline void to_json(nlohmann::json& j, const PbftMeta& md)
  {
    j["metadata"] = md.metadata;
    j["data_type"] = md.data_type;
  }

  inline void from_json(const nlohmann::json& j, PbftMeta& md)
  {
    assign_j(md.metadata, j["metadata"]);
    md.data_type = j["data_type"];
  }
}