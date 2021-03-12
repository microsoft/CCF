// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entities.h"
#include "service_map.h"

#include <msgpack/msgpack.hpp>

namespace ccf
{
  // SGX MRENCLAVE is SHA256 digest
  static constexpr size_t CODE_DIGEST_BYTES = 256 / 8;
  using CodeDigest = std::array<uint8_t, CODE_DIGEST_BYTES>;

  enum class CodeStatus
  {
    ALLOWED_TO_JOIN = 0
  };
  DECLARE_JSON_ENUM(
    CodeStatus, {{CodeStatus::ALLOWED_TO_JOIN, "ALLOWED_TO_JOIN"}});
}

MSGPACK_ADD_ENUM(ccf::CodeStatus);

namespace ccf
{
  using CodeIDs = ServiceMap<CodeDigest, CodeStatus>;
}
