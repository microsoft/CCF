// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"

#include <msgpack.hpp>
#include <nlohmann/json.hpp>
#include <set>

namespace ccf
{
  struct AllowedUserCodeIds
  {
    std::set<CodeDigest> code_ids;

    MSGPACK_DEFINE(code_ids);
  };
  DECLARE_JSON_TYPE(AllowedUserCodeIds);
  DECLARE_JSON_REQUIRED_FIELDS(AllowedUserCodeIds, code_ids);

  // Key is always 0
  using UserCodeIds = Store::Map<size_t, AllowedUserCodeIds>;
}