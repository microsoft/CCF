// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ccf::crypto
{
  // Returns a hex-encoded SHA-256 hash of the DER-encoded public key,
  // suitable for use as a key identifier (kid).
  std::string kid_from_key(const std::vector<uint8_t>& public_key_der);
}
