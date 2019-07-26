// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"

#include <vector>

namespace ccf
{
  struct RawSignature
  {
    std::vector<uint8_t> sig;

    bool operator==(const RawSignature& o) const
    {
      return sig == o.sig;
    }

    MSGPACK_DEFINE(sig);
  };
  DECLARE_JSON_TYPE(RawSignature);
  DECLARE_JSON_REQUIRED_FIELDS(RawSignature, sig);
}