// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/verifier.h"
#include "crypto/openssl/ec_public_key.h"

#include <chrono>
#include <openssl/x509.h>

namespace ccf::crypto
{
  class COSEVerifier_OpenSSL : public COSEVerifier
  {
  protected:
    std::shared_ptr<ECPublicKey_OpenSSL> public_key;

  public:
    virtual ~COSEVerifier_OpenSSL() override;
    virtual bool verify(
      const std::span<const uint8_t>& buf,
      std::span<uint8_t>& authned_content) const override;
    virtual bool verify_detached(
      std::span<const uint8_t> buf,
      std::span<const uint8_t> payload) const override;
  };

  class COSECertVerifier_OpenSSL : public COSEVerifier_OpenSSL
  {
  public:
    COSECertVerifier_OpenSSL(const std::vector<uint8_t>& certificate);
  };

  class COSEKeyVerifier_OpenSSL : public COSEVerifier_OpenSSL
  {
  public:
    COSEKeyVerifier_OpenSSL(const Pem& public_key);
  };
}
