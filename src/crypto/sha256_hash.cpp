// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/sha256_hash.h"

#include "ccf/ds/hex.h"
#include "ccf/ds/logger.h"

namespace crypto
{
  extern void default_sha256(const std::span<const uint8_t>& data, uint8_t* h);

  Sha256Hash::Sha256Hash(const uint8_t* data, size_t size)
  {
    default_sha256(std::span<const uint8_t>(data, size), h.data());
  }

  Sha256Hash::Sha256Hash(const std::vector<uint8_t>& vec)
  {
    default_sha256(vec, h.data());
  }

  Sha256Hash::Sha256Hash(const std::string& str)
  {
    std::span<const uint8_t> cb(
      reinterpret_cast<const uint8_t*>(str.data()), str.size());
    default_sha256(cb, h.data());
  }

  Sha256Hash::Sha256Hash(const Sha256Hash& left, const Sha256Hash& right)
  {
    std::vector<uint8_t> data(left.h.size() + right.h.size());
    std::copy(left.h.begin(), left.h.end(), data.begin());
    std::copy(right.h.begin(), right.h.end(), data.begin() + left.h.size());
    default_sha256(data, h.data());
  }

  Sha256Hash::Sha256Hash(
    const Sha256Hash& first, const Sha256Hash& second, const Sha256Hash& third)
  {
    std::vector<uint8_t> data(
      first.h.size() + second.h.size() + third.h.size());
    std::copy(first.h.begin(), first.h.end(), data.begin());
    std::copy(second.h.begin(), second.h.end(), data.begin() + first.h.size());
    std::copy(
      third.h.begin(),
      third.h.end(),
      data.begin() + first.h.size() + second.h.size());
    default_sha256(data, h.data());
  }

  std::ostream& operator<<(std::ostream& os, const crypto::Sha256Hash& h)
  {
    for (unsigned i = 0; i < crypto::Sha256Hash::SIZE; i++)
    {
      os << std::hex << static_cast<int>(h.h[i]);
    }

    return os;
  }

  std::string Sha256Hash::hex_str() const
  {
    return ds::to_hex(h);
  }

  Sha256Hash Sha256Hash::from_hex_string(const std::string& str)
  {
    Sha256Hash digest;
    ds::from_hex(str, digest.h);
    return digest;
  }

  Sha256Hash Sha256Hash::from_span(const std::span<const uint8_t, SIZE>& sp)
  {
    Sha256Hash digest;
    std::copy(sp.begin(), sp.end(), digest.h.begin());
    return digest;
  }

  Sha256Hash Sha256Hash::from_representation(const Representation& r)
  {
    Sha256Hash digest;
    digest.h = r;
    return digest;
  }

  void to_json(nlohmann::json& j, const Sha256Hash& hash)
  {
    j = hash.hex_str();
  }

  void from_json(const nlohmann::json& j, Sha256Hash& hash)
  {
    auto value = j.get<std::string>();
    try
    {
      ds::from_hex(value, hash.h);
    }
    catch (const std::logic_error& e)
    {
      throw JsonParseError(fmt::format(
        "Input string \"{}\" is not valid hex-encoded SHA-256: {}",
        value,
        e.what()));
    }
  }

  std::string schema_name(const Sha256Hash*)
  {
    return "Sha256Digest";
  }

  void fill_json_schema(nlohmann::json& schema, const Sha256Hash*)
  {
    schema["type"] = "string";

    // According to the spec, "format is an open value, so you can use any
    // formats, even not those defined by the OpenAPI Specification"
    // https://swagger.io/docs/specification/data-models/data-types/#format
    schema["format"] = "hex";
    schema["pattern"] = fmt::format("^[a-f0-9]{{{}}}$", Sha256Hash::SIZE);
  }

  bool operator==(const Sha256Hash& lhs, const Sha256Hash& rhs)
  {
    for (unsigned i = 0; i < crypto::Sha256Hash::SIZE; i++)
    {
      if (lhs.h[i] != rhs.h[i])
      {
        return false;
      }
    }
    return true;
  }

  bool operator!=(const Sha256Hash& lhs, const Sha256Hash& rhs)
  {
    return !(lhs == rhs);
  }
}
