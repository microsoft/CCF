// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/verifier.h"

#include <chrono>
#include <openssl/x509.h>

namespace ccf::crypto
{
  class Verifier_OpenSSL : public Verifier
  {
  protected:
    mutable OpenSSL::Unique_X509 cert;

    static MDType get_md_type(int mdt);

  public:
    Verifier_OpenSSL(const std::vector<uint8_t>& c);
    Verifier_OpenSSL(Verifier_OpenSSL&& v) = default;
    Verifier_OpenSSL(const Verifier_OpenSSL&) = delete;
    virtual ~Verifier_OpenSSL();

    virtual std::vector<uint8_t> cert_der() override;
    virtual Pem cert_pem() override;

    virtual bool verify_certificate(
      const std::vector<const Pem*>& trusted_certs,
      const std::vector<const Pem*>& chain = {},
      bool ignore_time = false) override;

    virtual bool is_self_signed() const override;

    virtual std::string serial_number() const override;

    virtual std::pair<std::string, std::string> validity_period()
      const override;

    virtual size_t remaining_seconds(
      const std::chrono::system_clock::time_point& now) const override;

    virtual double remaining_percentage(
      const std::chrono::system_clock::time_point& now) const override;

    virtual std::string subject() const override;
  };
}
