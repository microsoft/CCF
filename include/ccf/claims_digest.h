// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"

namespace ccf
{
  class ClaimsDigest
  {
  public:
    using Digest = ccf::crypto::Sha256Hash;

  private:
    bool is_set = false;
    Digest digest;

  public:
    ClaimsDigest() = default;

    inline void set(Digest&& digest_)
    {
      is_set = true;
      digest = std::move(digest_);
    }

    inline void set(Digest::Representation&& r)
    {
      is_set = true;
      digest.set(std::move(r));
    }

    [[nodiscard]] inline bool empty() const
    {
      return !is_set;
    }

    [[nodiscard]] const Digest& value() const
    {
      return digest;
    }

    bool operator==(const ClaimsDigest& other) const
    {
      return (is_set == other.is_set) && (digest == other.digest);
    }
  };

  inline void to_json(nlohmann::json& j, const ClaimsDigest& hash)
  {
    j = hash.value();
  }

  inline void from_json(const nlohmann::json& j, ClaimsDigest& hash)
  {
    hash.set(j.get<ClaimsDigest::Digest>());
  }

  inline std::string schema_name(const ClaimsDigest*)
  {
    return ds::json::schema_name<ClaimsDigest::Digest>();
  }

  inline void fill_json_schema(nlohmann::json& schema, const ClaimsDigest*)
  {
    ds::json::fill_schema<ClaimsDigest::Digest>(schema);
  }

  static ClaimsDigest empty_claims()
  {
    ClaimsDigest cd;
    cd.set(ClaimsDigest::Digest::Representation());
    return cd;
  }
}