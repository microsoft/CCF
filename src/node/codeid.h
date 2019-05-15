// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"

#include <msgpack.hpp>

namespace ccf
{
  enum class CodeStatus
  {
    ACCEPTED = 0,
    RETIRED = 1,
    // not to be used
    UNKNOWN
  };
}

MSGPACK_ADD_ENUM(ccf::CodeStatus);

namespace ccf
{
  struct CodeInfo
  {
    CodeStatus status;
    CodeDigest digest;

    MSGPACK_DEFINE(status, digest);
  };
  DECLARE_REQUIRED_JSON_FIELDS(CodeInfo, status, digest)

  using CodeIDs = Store::Map<CodeVersion, CodeInfo>;
}