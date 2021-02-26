// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/verifier.h"

#include <openssl/x509.h>

namespace crypto
{
  class Verifier_OpenSSL : public Verifier
  {
  protected:
    mutable X509* cert;

    MDType get_md_type(int mdt) const;

  public:
    Verifier_OpenSSL(const std::vector<uint8_t>& c);
    Verifier_OpenSSL(Verifier_OpenSSL&& v) = default;
    Verifier_OpenSSL(const Verifier_OpenSSL&) = delete;
    virtual ~Verifier_OpenSSL();

    virtual std::vector<uint8_t> cert_der() override;
    virtual Pem cert_pem() override;
  };
}
