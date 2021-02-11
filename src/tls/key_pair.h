// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "asn1_san.h"
#include "curve.h"
#include "entropy.h"
#include "error_string.h"
#include "hash.h"
#include "key_pair_base.h"
#include "key_pair_mbedtls.h"
#include "key_pair_openssl.h"
#include "pem.h"
#include "san.h"

#include <cstring>
#include <iomanip>
#include <limits>
#include <memory>

namespace tls
{
  using PublicKey = PublicKey_OpenSSL;
  using PublicKeyPtr = std::shared_ptr<PublicKeyBase>;

  /**
   * Construct PublicKey from a raw public key in PEM format
   *
   * @param public_pem Sequence of bytes containing the key in PEM format
   */
  inline PublicKeyPtr make_public_key(const Pem& public_pem)
  {
    return std::make_shared<PublicKey>(public_pem);
  }

  /**
   * Construct PublicKey from a raw public key in DER format
   *
   * @param public_der Sequence of bytes containing the key in DER format
   */
  inline PublicKeyPtr make_public_key(const std::vector<uint8_t> public_der)
  {
    return std::make_shared<PublicKey>(public_der);
  }

  using KeyPair = KeyPair_OpenSSL;
  using KeyPairPtr = std::shared_ptr<KeyPairBase>;

  /**
   * Create a new public / private ECDSA key pair on specified curve and
   * implementation
   */
  inline KeyPairPtr make_key_pair(
    CurveID curve_id = service_identity_curve_choice)
  {
    return std::make_shared<KeyPair>(curve_id);
  }

  /**
   * Create a public / private ECDSA key pair from existing private key data
   */
  inline KeyPairPtr make_key_pair(const Pem& pkey, CBuffer pw = nullb)
  {
    return std::make_shared<KeyPair>(pkey, pw);
  }

  static inline tls::Pem public_key_pem_from_cert(const tls::Pem& cert)
  {
    auto c = mbedtls::make_unique<mbedtls::X509Crt>();
    int rc = mbedtls_x509_crt_parse(c.get(), cert.data(), cert.size());
    if (rc != 0)
    {
      throw std::runtime_error(fmt::format(
        "Failed to parse certificate, mbedtls_x509_crt_parse: {}", rc));
    }
    uint8_t data[2048];
    rc = mbedtls_pk_write_pubkey_pem(&c->pk, data, max_pem_key_size);
    if (rc != 0)
    {
      throw std::runtime_error(fmt::format(
        "Failed to serialise public key, mbedtls_pk_write_pubkey_pem: {}", rc));
    }

    size_t len = strlen((char const*)data);
    return tls::Pem(data, len);
  }

  inline void check_is_cert(CBuffer der)
  {
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int rc = mbedtls_x509_crt_parse(&cert, der.p, der.n);
    mbedtls_x509_crt_free(&cert);
    if (rc != 0)
    {
      throw std::invalid_argument(fmt::format(
        "Failed to parse certificate, mbedtls_x509_crt_parse: {}",
        tls::error_string(rc)));
    }
  }
}
