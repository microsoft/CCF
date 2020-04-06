// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entities.h"

#include <msgpack/msgpack.hpp>

namespace ccf
{
  struct Config
  {
    // Number of required shares to decrypt ledger secrets (recovery)
    size_t recovery_threshold;

    MSGPACK_DEFINE(recovery_threshold)
  };
  DECLARE_JSON_TYPE(Config)
  DECLARE_JSON_REQUIRED_FIELDS(Config, recovery_threshold)

  // The key for this table is always 0 as there is always only one active
  // configuration.
  using Configuration = Store::Map<size_t, Config>;
}