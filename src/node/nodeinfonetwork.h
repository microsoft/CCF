// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ds/json.h"

#include <msgpack.hpp>
#include <string>

namespace ccf
{
  struct NodeInfoNetwork
  {
    std::string host;
    std::string pubhost;
    std::string nodeport;
    std::string rpcport;

    MSGPACK_DEFINE(host, pubhost, nodeport, rpcport);
  };
  DECLARE_JSON_TYPE(NodeInfoNetwork);
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeInfoNetwork, host, pubhost, nodeport, rpcport);
}