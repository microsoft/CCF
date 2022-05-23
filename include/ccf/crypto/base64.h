// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <string>
#include <vector>

namespace crypto
{
  std::vector<uint8_t> raw_from_b64(const std::string_view& b64_string);

  std::vector<uint8_t> raw_from_b64url(const std::string_view& b64url_string);

  std::string b64_from_raw(const uint8_t* data, size_t size);

  std::string b64_from_raw(const std::vector<uint8_t>& data);
}
