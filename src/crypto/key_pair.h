// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "curve.h"
#include "key_pair_base.h"
#include "key_pair_mbedtls.h"
#include "key_pair_openssl.h"
#include "pem.h"
#include "san.h"

#include <cstring>
#include <iomanip>
#include <limits>
#include <memory>

namespace crypto
{
#ifdef CRYPTO_PROVIDER_IS_MBEDTLS
  using PublicKey = PublicKey_mbedTLS;
#else
  using PublicKey = PublicKey_OpenSSL;
#endif
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

#ifdef CRYPTO_PROVIDER_IS_MBEDTLS
  using KeyPair = KeyPair_mbedTLS;
#else
  using KeyPair = KeyPair_OpenSSL;
#endif
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
}
