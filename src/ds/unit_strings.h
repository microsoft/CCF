// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/nonstd.h"

#include <charconv>
#include <cmath>
#include <nlohmann/json.hpp>
#include <string>

namespace ds
{
  // Inspired by CLI11's AsNumberWithUnit
  class UnitStringConverter
  {
  public:
    template <class F, typename T>
    static size_t convert(
      const std::string& input, std::map<std::string, T>& mapping, F&& f)
    {
      if (input.empty())
      {
        throw std::logic_error("Cannot convert empty unit string");
      }

      auto unit_begin = input.end();
      while (unit_begin > input.begin() && std::isalpha(*(unit_begin - 1)))
      {
        unit_begin--;
      }

      auto unit = std::string(unit_begin, input.end());
      nonstd::to_lower(unit);
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

  static size_t convert_size_string(const std::string& input)
  {
    std::map<std::string, size_t> size_suffix_to_power = {
      {"b", 0}, {"kb", 1}, {"mb", 2}, {"gb", 3}, {"tb", 4}, {"pb", 5}};

    return UnitStringConverter::convert(
      input, size_suffix_to_power, [](size_t value, size_t power) {
        return value * std::pow(1024, power);
      });
  }

  static size_t convert_time_string(const std::string& input)
  {
    std::map<std::string, std::pair<size_t, size_t>> size_suffix_to_power = {
      {"", {1, 0}},
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
    UnitString(const std::string& str_) : str(str_) {}

    bool operator==(const UnitString&) const = default;
  };

  inline void from_json(const nlohmann::json& j, UnitString& s)
  {
    s = j.get<std::string>();
  }

  inline void to_json(nlohmann::json& j, const UnitString& s)
  {
    j = s.str;
  }

  struct SizeString : UnitString
  {
    SizeString() = default;
    SizeString(const std::string& str_) : UnitString(str_) {}

    inline operator size_t() const
    {
      return convert_size_string(str);
    }
  };

  struct TimeString : UnitString
  {
    TimeString() = default;
    TimeString(const std::string& str_) : UnitString(str_) {}

    inline operator std::chrono::microseconds() const
    {
      return std::chrono::microseconds(convert_time_string(str));
    }

    inline operator std::chrono::milliseconds() const
    {
      return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::microseconds(*this));
    }

    inline operator std::chrono::seconds() const
    {
      return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::microseconds(*this));
    }

    size_t count_ms() const
    {
      return std::chrono::milliseconds(*this).count();
    }

    size_t count_s() const
    {
      return std::chrono::seconds(*this).count();
    }
  };
}