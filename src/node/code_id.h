// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash_provider.h"
#include "ds/hex.h"
#include "ds/json.h"
#include "entities.h"
#include "service_map.h"

namespace ccf
{
  struct CodeDigest
  {
    std::array<uint8_t, crypto::Sha256Hash::SIZE> data;

    CodeDigest() = default;
    CodeDigest(const CodeDigest& other) : data(other.data) {}
  };

  inline void to_json(nlohmann::json& j, const CodeDigest& code_digest)
  {
    j = ds::to_hex(code_digest.data);
  }

  inline void from_json(const nlohmann::json& j, CodeDigest& code_digest)
  {
    if (j.is_string())
    {
      auto value = j.get<std::string>();
      ds::from_hex(value, code_digest.data);
    }
    else
    {
      throw JsonParseError(
        fmt::format("Code Digest should be hex-encoded string: {}", j.dump()));
    }
  }

  enum class CodeStatus
  {
    ALLOWED_TO_JOIN = 0
  };
  DECLARE_JSON_ENUM(
    CodeStatus, {{CodeStatus::ALLOWED_TO_JOIN, "AllowedToJoin"}});

  using CodeIDs = ServiceMap<CodeDigest, CodeStatus>;
}
