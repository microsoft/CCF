// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/buffer.h"
#include "ds/hex.h"
#include "ds/json.h"

#include <cstdint>
#include <iostream>
#include <vector>

namespace crypto
{
  enum class MDType
  {
    NONE = 0,
    SHA1,
    SHA256,
    SHA384,
    SHA512
  };

  DECLARE_JSON_ENUM(
    MDType,
    {{MDType::NONE, "NONE"},
     {MDType::SHA1, "SHA1"},
     {MDType::SHA256, "SHA256"},
     {MDType::SHA384, "SHA384"},
     {MDType::SHA512, "SHA512"}});
}

namespace crypto
{
  extern void default_sha256(const CBuffer& data, uint8_t* h);

  using HashBytes = std::vector<uint8_t>;

  class HashProvider
  {
  public:
    /** Generic Hash function
     * @param data The data to hash
     * @param size The size of @p data
     * @param type The type of hash to compute
     */
    virtual HashBytes Hash(
      const uint8_t* data, size_t size, MDType type) const = 0;

    virtual ~HashProvider() = default;
  };

  class Sha256Hash
  {
  public:
    static constexpr size_t SIZE = 256 / 8;
    Sha256Hash() : h{0} {}
    Sha256Hash(const CBuffer& data) : h{0}
    {
      default_sha256(data, h.data());
    }
    Sha256Hash(const std::string& s)
    {
      ds::from_hex(s, h);
    }
    Sha256Hash(const Sha256Hash& left, const Sha256Hash& right)
    {
      std::vector<uint8_t> data(left.h.size() + right.h.size());
      std::copy(left.h.begin(), left.h.end(), data.begin());
      std::copy(right.h.begin(), right.h.end(), data.begin() + left.h.size());
      default_sha256(data, h.data());
    }

    std::array<uint8_t, SIZE> h;

    friend std::ostream& operator<<(
      std::ostream& os, const crypto::Sha256Hash& h)
    {
      for (unsigned i = 0; i < crypto::Sha256Hash::SIZE; i++)
      {
        os << std::hex << static_cast<int>(h.h[i]);
      }

      return os;
    }

    std::string hex_str() const
    {
      return ds::to_hex(h);
    };
  };

  inline void to_json(nlohmann::json& j, const Sha256Hash& hash)
  {
    j = hash.hex_str();
  }

  inline void from_json(const nlohmann::json& j, Sha256Hash& hash)
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

  inline bool operator==(const Sha256Hash& lhs, const Sha256Hash& rhs)
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

  inline bool operator!=(const Sha256Hash& lhs, const Sha256Hash& rhs)
  {
    return !(lhs == rhs);
  }

  // Incremental Hash Objects
  class ISha256Hash
  {
  public:
    ISha256Hash() {}
    virtual ~ISha256Hash() {}

    virtual void update_hash(CBuffer data) = 0;
    virtual Sha256Hash finalise() = 0;

    template <typename T>
    void update(const T& t)
    {
      update_hash({reinterpret_cast<const uint8_t*>(&t), sizeof(T)});
    }

    template <>
    void update<std::vector<uint8_t>>(const std::vector<uint8_t>& d)
    {
      update_hash({d.data(), d.size()});
    }
  };
}
