// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/nonstd.h"

#include <charconv>
#include <cmath>
#include <nlohmann/json.hpp>
#include <string>

namespace ccf::ds
{
  // Inspired by CLI11's AsNumberWithUnit
  class UnitStringConverter
  {
  public:
    template <class F, typename T>
    static size_t convert(
      const std::string_view& input,
      std::map<std::string_view, T>& mapping,
      F&& f) // NOLINT(cppcoreguidelines-missing-std-forward)
    {
      if (input.empty())
      {
        throw std::logic_error("Cannot convert empty unit string");
      }

      const auto* unit_begin = input.end();
      while (unit_begin > input.begin() && std::isalpha(*(unit_begin - 1)))
      {
        unit_begin--;
      }

      auto unit = std::string(unit_begin, input.end());
      ccf::nonstd::to_lower(unit);
      auto value = std::string(input.begin(), unit_begin);

      size_t ret = 0;
      auto res =
        std::from_chars(value.data(), value.data() + value.size(), ret);
      if (res.ec != std::errc())
      {
        throw std::logic_error(fmt::format(
          "Could not convert value from size string \"{}\": {}",
          value,
          res.ec));
      }

      if (unit.empty())
      {
        return ret;
      }

      auto factor = mapping.find(unit);
      if (factor == mapping.end())
      {
        // Return list of allowed units
        std::string allowed_units_str;
        for (auto it = mapping.begin(); it != mapping.end(); ++it)
        {
          allowed_units_str += it->first;
          if (std::next(it) != mapping.end())
          {
            allowed_units_str += ", ";
          }
        }
        throw std::logic_error(fmt::format(
          "Unit {} is invalid. Allowed: {}", unit, allowed_units_str));
      }

      return f(ret, factor->second);
    }
  };

  static size_t convert_size_string(const std::string_view& input)
  {
    std::map<std::string_view, size_t> size_suffix_to_power = {
      {"b", 0}, {"kb", 1}, {"mb", 2}, {"gb", 3}, {"tb", 4}, {"pb", 5}};

    return UnitStringConverter::convert(
      input, size_suffix_to_power, [](size_t value, size_t power) {
        return value * std::pow(1024, power);
      });
  }

  static size_t convert_time_string(const std::string_view& input)
  {
    std::map<std::string_view, std::pair<size_t, size_t>> size_suffix_to_power =
      {{"", {1, 0}},
       {"us", {1, 0}},
       {"ms", {1, 3}},
       {"s", {1, 6}},
       {"min", {60, 6}},
       {"h", {36, 8}}};

    return UnitStringConverter::convert(
      input,
      size_suffix_to_power,
      [](size_t value, const std::pair<size_t, size_t>& factors) {
        return value * factors.first * std::pow(10, factors.second);
      });
  }

  struct UnitString
  {
    std::string str;

    UnitString() = default;
    UnitString(const std::string_view& str_) : str(str_) {}

    bool operator==(const UnitString&) const = default;
  };

  inline void to_json(nlohmann::json& j, const UnitString& s)
  {
    j = s.str;
  }

  struct SizeString : UnitString
  {
    size_t value;

    SizeString() = default;
    SizeString(const std::string_view& str_) :
      UnitString(str_),
      value(convert_size_string(str_))
    {}

    SizeString(const char* str_) :
      UnitString(str_),
      value(convert_size_string(str_))
    {}

    operator size_t() const
    {
      return value;
    }

    [[nodiscard]] size_t count_bytes() const
    {
      return value;
    }
  };

  inline void from_json(const nlohmann::json& j, SizeString& s)
  {
    s = j.get<std::string_view>();
  }

  inline std::string schema_name(
    [[maybe_unused]] const SizeString* size_string_type)
  {
    return "TimeString";
  }

  inline void fill_json_schema(
    nlohmann::json& schema, [[maybe_unused]] const SizeString* size_string_type)
  {
    schema["type"] = "string";
    schema["pattern"] = "^[0-9]+(B|KB|MB|GB|TB|PB)?$";
  }

  struct TimeString : UnitString
  {
    std::chrono::microseconds value;

    TimeString() = default;
    TimeString(const std::string_view& str_) :
      UnitString(str_),
      value(convert_time_string(str_))
    {}

    operator std::chrono::microseconds() const
    {
      return value;
    }

    operator std::chrono::milliseconds() const
    {
      return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::microseconds(*this));
    }

    operator std::chrono::seconds() const
    {
      return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::microseconds(*this));
    }

    [[nodiscard]] size_t count_ms() const
    {
      return std::chrono::milliseconds(*this).count();
    }

    [[nodiscard]] size_t count_s() const
    {
      return std::chrono::seconds(*this).count();
    }
  };

  inline void from_json(const nlohmann::json& j, TimeString& s)
  {
    s = j.get<std::string_view>();
  }

  inline std::string schema_name(
    [[maybe_unused]] const TimeString* time_string_type)
  {
    return "TimeString";
  }

  inline void fill_json_schema(
    nlohmann::json& schema, [[maybe_unused]] const TimeString* time_string_type)
  {
    schema["type"] = "string";
    schema["pattern"] = "^[0-9]+(us|ms|s|min|h)?$";
  }
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<ccf::ds::SizeString>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::ds::SizeString& v, FormatContext& ctx) const
  {
    std::stringstream ss;
    ss << v.str;
    return format_to(ctx.out(), "{}", ss.str());
  }
};
FMT_END_NAMESPACE