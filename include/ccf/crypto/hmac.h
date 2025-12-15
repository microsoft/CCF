// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/hash_bytes.h"
#include "ccf/crypto/md_type.h"

namespace ccf::crypto
{
  /** Compute the HMAC of @p key and @p data
   */
  HashBytes hmac(
    MDType type,
    const std::span<const uint8_t>& key,
    const std::span<const uint8_t>& data);
}
