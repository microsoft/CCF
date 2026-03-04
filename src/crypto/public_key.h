// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ccf::crypto
{
  // Compute the key identifier (kid) for a public key given its DER encoding,
  // as used in COSE receipts. The kid is the hex-encoded SHA-256 hash of the
  // DER-encoded public key.
  std::string kid_from_key(const std::vector<uint8_t>& public_key_der);
}
