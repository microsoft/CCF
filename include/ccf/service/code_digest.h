// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/json.h"

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#  include "ccf/pal/attestation_sev_snp.h"
#else
#  include "ccf/pal/attestation_sgx.h"
#endif

namespace ccf
{
  struct CodeDigest
  {
    pal::attestation_measurement data = {};

    CodeDigest() = default;
    CodeDigest(const CodeDigest&) = default;

    CodeDigest& operator=(const CodeDigest&) = default;

    std::string hex_str() const
    {
      return ds::to_hex(data);
    }
  };

  inline void to_json(nlohmann::json& j, const CodeDigest& code_digest)
  {
    j = code_digest.hex_str();
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

  inline std::string schema_name(const CodeDigest*)
  {
    return "CodeDigest";
  }

  inline void fill_json_schema(nlohmann::json& schema, const CodeDigest*)
  {
    schema["type"] = "string";

    // According to the spec, "format is an open value, so you can use any
    // formats, even not those defined by the OpenAPI Specification"
    // https://swagger.io/docs/specification/data-models/data-types/#format
    schema["format"] = "hex";
    // NB: We are not specific about the length of the pattern here, because it
    // varies by target platform
    schema["pattern"] = "^[a-f0-9]+$";
  }

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
