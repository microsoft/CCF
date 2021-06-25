// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../key_pair.h"
#include "../san.h"
#include "mbedtls_wrappers.h"
#include "public_key.h"

namespace crypto
{
  class KeyPair_mbedTLS : public PublicKey_mbedTLS, public KeyPair
  {
  public:
    KeyPair_mbedTLS(CurveID cid);
    KeyPair_mbedTLS(const Pem& pem, CBuffer pw = nullb);
    KeyPair_mbedTLS(mbedtls::PKContext&& k);
    KeyPair_mbedTLS(const KeyPair_mbedTLS&) = delete;
    virtual ~KeyPair_mbedTLS() = default;

    virtual Pem private_key_pem() const override;
    virtual Pem public_key_pem() const override;
    virtual std::vector<uint8_t> public_key_der() const override;

    using PublicKey_mbedTLS::verify;

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature) override;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size) override;

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
