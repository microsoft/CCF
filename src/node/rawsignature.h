// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "rpc/jsonrpc.h"

#include <vector>

namespace ccf
{
  struct RawSignature
  {
    std::vector<uint8_t> sig;
  };
  DECLARE_REQUIRED_JSON_FIELDS(RawSignature, sig)
}