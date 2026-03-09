// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/public_key.h"

#include "ccf/crypto/sha256_hash.h"

namespace ccf::crypto
{
  std::string kid_from_key(const std::vector<uint8_t>& public_key_der)
  {
    return Sha256Hash(public_key_der).hex_str();
  }
}
