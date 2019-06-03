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
  ADD_JSON_TRANSLATORS(RawSignature, sig)
}