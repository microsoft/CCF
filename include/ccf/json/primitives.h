// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/base64.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace ccf
{
  /** Represents a field within a JSON object. */
  template <typename T>
  struct JsonField
  {
    using Target = T;
    char const* name;
  };

  class JsonParseError : public std::invalid_argument
  {
  public:
    std::vector<std::string> pointer_elements;

    using std::invalid_argument::invalid_argument;

    JsonParseError(const JsonParseError& other) noexcept = default;

    [[nodiscard]] std::string pointer() const
    {
      return fmt::format(
        "#/{}",
        fmt::join(pointer_elements.crbegin(), pointer_elements.crend(), "/"));
    }

    [[nodiscard]] std::string describe() const
    {
      return fmt::format("At {}: {}", pointer(), what());
    }
  };

  inline constexpr size_t MAX_JSON_NESTING_DEPTH = 64;

  class JsonTooDeep : public ccf::JsonParseError
  {
  public:
    explicit JsonTooDeep(size_t max_depth) :
      ccf::JsonParseError(fmt::format(
        "JSON object/array nesting exceeds maximum depth of {}", max_depth))
    {}
  };

  inline nlohmann::json::parser_callback_t make_depth_limit_callback(
    size_t max_depth)
  {
    return [max_depth](
             int depth, nlohmann::json::parse_event_t event, nlohmann::json&) {
      using E = nlohmann::json::parse_event_t;
      if (
        (event == E::object_start || event == E::array_start) &&
        static_cast<size_t>(depth) >= max_depth)
      {
        throw JsonTooDeep{max_depth};
      }
      return true;
    };
  }

  // Use for inputs whose nesting depth has not been validated upstream.
  template <typename Bytes>
  nlohmann::json parse_json_safe(
    Bytes&& bytes, size_t max_depth = MAX_JSON_NESTING_DEPTH)
  {
    return nlohmann::json::parse(
      std::forward<Bytes>(bytes), make_depth_limit_callback(max_depth));
  }

  template <typename Iter>
  nlohmann::json parse_json_safe(
    Iter first, Iter last, size_t max_depth = MAX_JSON_NESTING_DEPTH)
  {
    return nlohmann::json::parse(
      first, last, make_depth_limit_callback(max_depth));
  }
}

// NOLINTBEGIN(cert-dcl58-cpp)
namespace std
{
  template <typename T>
  inline void to_json(nlohmann::json& j, const std::optional<T>& t)
  {
    if (t.has_value())
    {
      j = t.value();
    }
  }

  template <typename T>
  inline void from_json(const nlohmann::json& j, std::optional<T>& t)
  {
    if (!j.is_null())
    {
      t = j.get<T>();
    }
  }

  template <typename T>
  inline void to_json(nlohmann::json& j, const std::vector<T>& t)
  {
    if constexpr (std::is_same_v<T, uint8_t>)
    {
      j = ccf::crypto::b64_from_raw(t);
    }
    else
    {
      j = nlohmann::json::array();
      for (const auto& e : t)
      {
        j.push_back(e);
      }
    }
  }

  template <typename T>
  inline void from_json(const nlohmann::json& j, std::vector<T>& t)
  {
    if constexpr (std::is_same_v<T, uint8_t>)
    {
      if (j.is_string())
      {
        try
        {
          t = ccf::crypto::raw_from_b64(j.get<std::string>());
          return;
        }
        catch (const std::exception&)
        {
          throw ccf::JsonParseError(fmt::format(
            "Vector of bytes object \"{}\" is not valid base64", j.dump()));
        }
      }
    }

    // Continue accepting the legacy array representation of byte vectors.
    if (!j.is_array())
    {
      throw ccf::JsonParseError(
        fmt::format("Vector object \"{}\" is not an array", j.dump()));
    }

    for (size_t i = 0; i < j.size(); ++i)
    {
      try
      {
        t.push_back(j.at(i).template get<T>());
      }
      catch (ccf::JsonParseError& jpe)
      {
        jpe.pointer_elements.push_back(std::to_string(i));
        throw;
      }
    }
  }
}

// NOLINTEND(cert-dcl58-cpp)
