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
    template <class F>
    static size_t convert(
      const std::string& input, std::map<std::string, size_t>& mapping, F&& f)
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

  struct SizeString
  {
    size_t value;

    SizeString() = default;
    SizeString(size_t val) : value(val) {}

    void operator=(size_t val)
    {
      value = val;
    }

    bool operator==(const SizeString&) const = default;

    inline operator size_t() const
    {
      return value;
    }
  };

  inline void from_json(const nlohmann::json& j, SizeString& str)
  {
    str = convert_size_string(j.get<std::string>());
  }

  inline void to_json(nlohmann::json& j, const SizeString& str)
  {
    j = str.value;
  }
}