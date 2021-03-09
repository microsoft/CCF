// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../key_pair.h"

#include "openssl_wrappers.h"
#include "public_key.h"

#include <stdexcept>
#include <string>

namespace crypto
{
  class KeyPair_OpenSSL : public PublicKey_OpenSSL, public KeyPair
  {
  public:
    KeyPair_OpenSSL(CurveID curve_id);
    KeyPair_OpenSSL(const KeyPair_OpenSSL&) = delete;
    KeyPair_OpenSSL(const Pem& pem, CBuffer pw = nullb);
    virtual ~KeyPair_OpenSSL() = default;

    virtual Pem private_key_pem() const override;
    virtual Pem public_key_pem() const override;
    virtual std::vector<uint8_t> public_key_der() const override;

    using PublicKey_OpenSSL::verify;

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature) override;

    virtual std::vector<uint8_t> sign(
      CBuffer d, MDType md_type = {}) const override;

    int sign(
      CBuffer d, size_t* sig_size, uint8_t* sig, MDType md_type = {}) const;

    std::vector<uint8_t> sign_hash(
      const uint8_t* hash, size_t hash_size) const override;

    virtual int sign_hash(
      const uint8_t* hash,
      size_t hash_size,
      size_t* sig_size,
      uint8_t* sig) const override;

    virtual Pem create_csr(const std::string& name) const override;

    virtual Pem sign_csr(
      const Pem& issuer_cert,
      const Pem& signing_request,
      const std::vector<SubjectAltName> subject_alt_names,
      bool ca = false) const override;
  };
}
