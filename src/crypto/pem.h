// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/buffer.h"
#include "ds/json.h"

#include <cstring>
#include <exception>
#include <memory>
#include <string_view>
#include <vector>

namespace crypto
{
  // Convenience class ensuring null termination of PEM-encoded certificates as
  // required by mbedTLS
  class Pem
  {
    std::string s;

  public:
    Pem() = default;

    Pem(const std::string& s_) : s(s_) {}

    Pem(size_t size) : s(size, '0') {}

    Pem(const uint8_t* data, size_t size)
    {
      if (size == 0)
        throw std::logic_error("Got PEM of size 0.");

      // If it's already null-terminated, don't suffix again
      const auto null_terminated = *(data + size - 1) == 0;
      if (null_terminated)
        size -= 1;

      s.assign(reinterpret_cast<const char*>(data), size);
    }

    Pem(const CBuffer& b) : Pem(b.p, b.n) {}

    Pem(const std::vector<uint8_t>& v) : Pem(v.data(), v.size()) {}

    bool operator==(const Pem& rhs) const
    {
      return s == rhs.s;
    }

    bool operator!=(const Pem& rhs) const
    {
      return !(*this == rhs);
    }

    bool operator<(const Pem& rhs) const
    {
      return s < rhs.s;
    }

    const std::string& str() const
    {
      return s;
    }

    uint8_t* data()
    {
      return reinterpret_cast<uint8_t*>(s.data());
    }

    const uint8_t* data() const
    {
      return reinterpret_cast<const uint8_t*>(s.data());
    }

    size_t size() const
    {
      // +1 for null termination
      return s.size() + 1;
    }

    bool empty() const
    {
      return s.empty();
    }

    std::vector<uint8_t> raw() const
    {
      return {data(), data() + size()};
    }

    // Not null-terminated
    std::vector<uint8_t> contents() const
    {
      return {data(), data() + s.size()};
    }
  };

  inline void to_json(nlohmann::json& j, const Pem& p)
  {
    j = p.str();
  }

  inline void from_json(const nlohmann::json& j, Pem& p)
  {
    if (j.is_string())
    {
      p = Pem(j.get<std::string>());
    }
    else if (j.is_array())
    {
      p = Pem(j.get<std::vector<uint8_t>>());
    }
    else
    {
      throw std::runtime_error(
        fmt::format("Unable to parse pem from this JSON: {}", j.dump()));
    }
  }

  inline std::string schema_name(const Pem&)
  {
    return "Pem";
  }

  inline void fill_json_schema(nlohmann::json& schema, const Pem&)
  {
    schema["type"] = "string";
  }
}

namespace std
{
  template <>
  struct hash<crypto::Pem>
  {
    size_t operator()(const crypto::Pem& pem) const
    {
      return std::hash<std::string>()(pem.str());
    }
  };
}