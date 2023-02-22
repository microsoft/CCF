// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/json.h"

namespace ccf
{
  // Generic wrapper for code digests on all TEE platforms
  struct CodeDigest
  {
    // TODO: Enforce size invariants for SGX and SNP
    // TODO: Should this be a vector instead??
    // pal::AttestationMeasurement data;
    std::vector<uint8_t> data;
    // std::array<uint8_t, 64> data;

    CodeDigest() = default;
    CodeDigest(const CodeDigest&) = default;

    // TODO: Needed?
    template <size_t N>
    CodeDigest(const std::array<uint8_t, N>& raw) : data(raw.begin(), raw.end())
    {}

    CodeDigest& operator=(const CodeDigest&) = default;

    std::string hex_str() const
    {
      return ds::to_hex(data);
    }
  };
  DECLARE_JSON_TYPE(CodeDigest);
  DECLARE_JSON_REQUIRED_FIELDS(CodeDigest, data);

  // inline void to_json(nlohmann::json& j, const CodeDigest& code_digest)
  // {
  //   j = code_digest.hex_str();
  // }

  // inline void from_json(const nlohmann::json& j, CodeDigest& code_digest)
  // {
  //   if (j.is_string())
  //   {
  //     auto value = j.get<std::string>();
  //     code_digest.data.resize(value.size() / 2);
  //     ds::from_hex(value, code_digest.data);
  //   }
  //   else
  //   {
  //     throw JsonParseError(
  //       fmt::format("Code Digest should be hex-encoded string: {}",
  //       j.dump()));
  //   }
  // }

  // inline std::string schema_name(const CodeDigest*)
  // {
  //   return "CodeDigest";
  // }

  // inline void fill_json_schema(nlohmann::json& schema, const CodeDigest*)
  // {
  //   schema["type"] = "string";

  //   // According to the spec, "format is an open value, so you can use any
  //   // formats, even not those defined by the OpenAPI Specification"
  //   // https://swagger.io/docs/specification/data-models/data-types/#format
  //   schema["format"] = "hex";
  //   // NB: We are not specific about the length of the pattern here, because
  //   it
  //   // varies by target platform
  //   schema["pattern"] = "^[a-f0-9]+$";
  // }

  enum class CodeStatus
  {
    ALLOWED_TO_JOIN = 0
  };
  DECLARE_JSON_ENUM(
    CodeStatus, {{CodeStatus::ALLOWED_TO_JOIN, "AllowedToJoin"}});
}

namespace kv::serialisers
{
  template <>
  struct BlitSerialiser<ccf::CodeDigest>
  {
    static SerialisedEntry to_serialised(const ccf::CodeDigest& code_digest)
    {
      auto hex_str = ds::to_hex(code_digest.data);
      return SerialisedEntry(hex_str.begin(), hex_str.end());
    }

    static ccf::CodeDigest from_serialised(const SerialisedEntry& data)
    {
      ccf::CodeDigest ret;
      ds::from_hex(std::string(data.data(), data.end()), ret.data);
      return ret;
    }
  };
}
