// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/public_key.h"

#include <chrono>

namespace crypto
{
  class COSEVerifier
  {
  public:
    virtual bool verify(
      const std::span<const uint8_t>& buf,
      std::span<uint8_t>& authned_content) const = 0;
    virtual ~COSEVerifier() = default;
  };

  using COSEVerifierUniquePtr = std::unique_ptr<COSEVerifier>;

  COSEVerifierUniquePtr make_cose_verifier(const std::vector<uint8_t>& cert);
  COSEVerifierUniquePtr make_cose_verifier(const PublicKeyPtr& pubk_ptr);
}
