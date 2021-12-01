// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <chrono>
#include <nlohmann/json.hpp>

struct SizeString
{
  size_t value;

  SizeString() = default;
  SizeString(size_t val) : value(val) {}

  bool operator==(const SizeString&) const = default;

  inline operator size_t() const
  {
    return value;
  }
};

// Note: from_json() is defined differently whether for host or in enclave
inline void from_json(const nlohmann::json& j, SizeString& str);
inline void to_json(nlohmann::json& j, const SizeString& str)
{
  j = str.value;
}

struct TimeString
{
  size_t value_us;

  TimeString() = default;
  TimeString(size_t value_us_) : value_us(value_us_) {}

  bool operator==(const TimeString&) const = default;

  inline operator size_t() const
  {
    return value_us;
  }

  inline operator std::chrono::microseconds() const
  {
    return std::chrono::microseconds(value_us);
  }
};

// Note: from_json() is defined differently whether for host or in enclave
inline void from_json(const nlohmann::json& j, TimeString& str);
inline void to_json(nlohmann::json& j, const TimeString& str)
{
  j = str.value_us;
}

// using SizeString = UnitString<cli::SizeStringConverter>;
// using TimeString = UnitString<cli::TimeStringConverter>;