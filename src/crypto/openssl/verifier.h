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
    ~Verifier_OpenSSL() override;

    std::vector<uint8_t> cert_der() override;
    Pem cert_pem() override;

    bool verify_certificate(
      const std::vector<const Pem*>& trusted_certs,
      const std::vector<const Pem*>& chain = {},
      bool ignore_time = false) override;

    bool is_self_signed() const override;

    std::string serial_number() const override;

    std::pair<std::string, std::string> validity_period()
      const override;

    size_t remaining_seconds(
      const std::chrono::system_clock::time_point& now) const override;

    double remaining_percentage(
      const std::chrono::system_clock::time_point& now) const override;

    std::string subject() const override;
  };
}
