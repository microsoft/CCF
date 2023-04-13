// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"

#include <chrono>

namespace crypto
{
  class COSESigner
  {
  public:
    virtual std::vector<uint8_t> sign(
      const std::span<const uint8_t>& payload) const = 0;
    virtual ~COSESigner() = default;
  };

  using COSESignerUniquePtr = std::unique_ptr<COSESigner>;

  COSESignerUniquePtr make_cose_signer(const Pem& priv_key_pem);
}
