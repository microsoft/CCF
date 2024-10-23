// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <span>
#include <variant>
#include <vector>

namespace ccf::cose::edit
{
  namespace op
  {
    struct Append
    {};

    struct SetAtKey
    {
      ssize_t key;
    };

    using Type = std::variant<Append, SetAtKey>;
  }

  std::vector<uint8_t> insert_in_uhdr(
    const std::span<const uint8_t>& buf_,
    ssize_t key,
    op::Type op,
    const std::vector<uint8_t> value);
}