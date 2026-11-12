// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/json/glaze.h"

#include <glaze/json/read.hpp>
#include <glaze/json/write.hpp>
#include <string>
#include <string_view>

namespace ccf::json
{
  struct Options : glz::opts
  {
    bool validate_trailing_whitespace = true;
    bool escape_control_characters = true;
  };

  inline constexpr auto options = [] {
    Options value{};
    value.null_terminated = false;
    value.error_on_unknown_keys = false;
    value.error_on_missing_keys = true;
    value.skip_null_members = false;
    return value;
  }();

  template <typename T>
  void write(const T& value, std::string& output)
  {
    const auto error = glz::write<options>(value, output);
    if (error)
    {
      throw std::logic_error(glz::format_error(error, ""));
    }
  }

  template <typename T>
  std::string write(const T& value)
  {
    std::string output;
    write(value, output);
    return output;
  }

  template <typename T>
  void read(T& value, std::string_view input)
  {
    const auto error = glz::read<options>(value, input);
    if (error)
    {
      throw ccf::JsonParseError(glz::format_error(error, ""));
    }
  }

  template <typename T>
  T read(std::string_view input)
  {
    T value{};
    read(value, input);
    return value;
  }
}
