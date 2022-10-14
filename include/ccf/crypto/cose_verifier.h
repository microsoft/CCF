// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/public_key.h"

#include <chrono>
#include <t_cose/q_useful_buf.h>

namespace crypto
{
  class COSEVerifier
  {
  public:
    virtual bool verify(
      const q_useful_buf_c& buf, q_useful_buf_c& authned_content) const = 0;
    virtual ~COSEVerifier() = default;
  };

  using COSEVerifierUniquePtr = std::unique_ptr<COSEVerifier>;

  COSEVerifierUniquePtr make_cose_verifier(const std::vector<uint8_t>& cert);
}
