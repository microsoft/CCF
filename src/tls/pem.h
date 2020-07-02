// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/buffer.h"
#include "ds/json.h"
#include "tls.h"

#include <cstring>
#include <exception>
#include <memory>
#include <msgpack/msgpack.hpp>
#include <vector>

namespace tls
{
  // Convenience class ensuring null termination of PEM-encoded certificates as
  // required by mbedTLS
  class Pem
  {
    std::string s;

  public:
    Pem() = default;

    Pem(const std::string& s_) : s(s_) {}

    Pem(const CBuffer& b)
    {
      if (b.n == 0)
        throw std::logic_error("Got PEM of size 0.");

      s.assign(reinterpret_cast<const char*>(b.p), b.n);
    }

    Pem(const std::vector<uint8_t>& v) : Pem(CBuffer{v}) {}

    bool operator==(const Pem& rhs) const
    {
      return s == rhs.s;
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

    std::vector<uint8_t> raw() const
    {
      return {data(), data() + size()};
    }

    MSGPACK_DEFINE(s);
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
}