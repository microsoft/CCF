// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/verifier.h"
#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/verifier.h"

#include <chrono>
#include <openssl/x509.h>

namespace crypto
{
  class COSEVerifier_OpenSSL : public Verifier_OpenSSL, public COSEVerifier
  {
  public:
    COSEVerifier_OpenSSL(const std::vector<uint8_t>& c);
    virtual ~COSEVerifier_OpenSSL();

    virtual bool verify(const q_useful_buf_c& buf) const override;
  };
}
