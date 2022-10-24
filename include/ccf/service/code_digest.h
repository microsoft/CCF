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
    std::array<uint8_t, pal::attestation_measurement_size> data = {};

    CodeDigest() = default;
    CodeDigest(const CodeDigest&) = default;

    CodeDigest& operator=(const CodeDigest&) = default;
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
