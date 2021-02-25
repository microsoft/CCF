// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/verifier.h"

#include "mbedtls_wrappers.h"

namespace crypto
{
  class Verifier_mbedTLS : public Verifier
  {
  protected:
    mutable mbedtls::X509Crt cert;

    MDType get_md_type(mbedtls_md_type_t mdt) const;

  public:
    Verifier_mbedTLS(const std::vector<uint8_t>& c);
    Verifier_mbedTLS(const Verifier_mbedTLS&) = delete;
    virtual ~Verifier_mbedTLS() = default;

    virtual std::vector<uint8_t> cert_der() override;
    virtual Pem cert_pem() override;
  };
}
