// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace ccf::crypto
{
  // Convenience class ensuring null termination of PEM-encoded certificates
  class Pem
  {
  private:
    std::string s;
    void check_pem_format();

  public:
    Pem() = default;
    Pem(std::string pem_string);
    Pem(const uint8_t* data, size_t size);

    explicit Pem(std::span<const uint8_t> s) : Pem(s.data(), s.size()) {}
    explicit Pem(const std::vector<uint8_t>& v) : Pem(v.data(), v.size()) {}

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

    [[nodiscard]] const std::string& str() const
    {
      return s;
    }

    uint8_t* data()
    {
      return reinterpret_cast<uint8_t*>(s.data());
    }

    [[nodiscard]] const uint8_t* data() const
    {
      return reinterpret_cast<const uint8_t*>(s.data());
    }

    [[nodiscard]] size_t size() const
    {
      return s.size();
    }

    [[nodiscard]] bool empty() const
    {
      return s.empty();
    }

    [[nodiscard]] std::vector<uint8_t> raw() const
    {
      return {data(), data() + size()};
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

  inline std::string schema_name([[maybe_unused]] const Pem* pem)
  {
    return "Pem";
  }

  std::vector<ccf::crypto::Pem> split_x509_cert_bundle(
    const std::string_view& pem);

  inline void fill_json_schema(
    nlohmann::json& schema, [[maybe_unused]] const Pem* pem)
  {
    schema["type"] = "string";
  }
}

namespace std
{
  template <>
  struct hash<ccf::crypto::Pem>
  {
    size_t operator()(const ccf::crypto::Pem& pem) const
    {
      return std::hash<std::string>()(pem.str());
    }
  };
}
