// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#ifndef INSIDE_ENCLAVE
#  include "ds/cli_helper.h"
#endif

#include "ds/logger.h"

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

inline void to_json(nlohmann::json& j, const SizeString& str)
{
  j = str.value;
}

// Note: Read differently whether on host or enclave
inline void from_json(const nlohmann::json& j, SizeString& str)
{
#ifdef INSIDE_ENCLAVE
  str = j.get<size_t>();
#else
  str = cli::convert_size_string(
    j.get<std::string>()); // Read from config file on host
#endif
}

struct TimeString
{
  std::chrono::microseconds value;

  TimeString() = default;
  TimeString(size_t value_us_) : value(value_us_) {}

  bool operator==(const TimeString&) const = default;

  inline operator std::chrono::microseconds() const
  {
    LOG_FAIL_FMT("us(): {}", value.count());
    return value;
  }

  inline operator std::chrono::milliseconds() const
  {
    return std::chrono::duration_cast<std::chrono::milliseconds>(value);
  }

  inline operator std::chrono::seconds() const
  {
    return std::chrono::duration_cast<std::chrono::seconds>(value);
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

// Note: from_json() is defined differently whether for host or in enclave
inline void from_json(const nlohmann::json& j, TimeString& str)
{
#ifdef INSIDE_ENCLAVE
  str = j.get<size_t>();
#else
  str = cli::convert_time_string(
    j.get<std::string>()); // Read from config file on host
#endif
}

inline void to_json(nlohmann::json& j, const TimeString& str)
{
  j = str.value.count();
}