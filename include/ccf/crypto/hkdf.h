// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/md_type.h"

#include <span>
#include <vector>

namespace ccf::crypto
{
  /** Perform HKDF key derivation */
  std::vector<uint8_t> hkdf(
    MDType md_type,
    size_t length,
    const std::span<const uint8_t>& ikm,
    const std::span<const uint8_t>& salt = {},
    const std::span<const uint8_t>& info = {});
}