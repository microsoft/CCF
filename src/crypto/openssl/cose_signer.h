// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_signer.h"
#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/key_pair.h"

namespace crypto
{
  class COSESigner_OpenSSL : public COSESigner
  {
  private:
    std::shared_ptr<KeyPair_OpenSSL> kp;

  public:
    COSESigner_OpenSSL(const Pem& priv_key_pem);
    virtual ~COSESigner_OpenSSL() override;
    virtual std::vector<uint8_t> sign(
      const std::span<const uint8_t>& payload) const override;
  };
}
