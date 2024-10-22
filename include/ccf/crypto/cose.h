// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace ccf::cose::edit
{
  std::vector<uint8_t> insert_at_key_in_uhdr(
    const std::span<const uint8_t>& buf_,
    size_t key,
    size_t subkey,
    const std::vector<uint8_t> value);
}