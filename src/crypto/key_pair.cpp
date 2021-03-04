// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "key_pair.h"

#include "mbedtls/key_pair.h"
#include "mbedtls/public_key.h"
#include "openssl/key_pair.h"
#include "openssl/public_key.h"

#include <cstring>
#include <iomanip>
#include <limits>
#include <memory>
#include <string>

namespace crypto
{
#ifdef CRYPTO_PROVIDER_IS_MBEDTLS
  using PublicKeyImpl = PublicKey_mbedTLS;
  using KeyPairImpl = KeyPair_mbedTLS;
#else
  using PublicKeyImpl = PublicKey_OpenSSL;
  using KeyPairImpl = KeyPair_OpenSSL;
#endif

  PublicKeyPtr make_public_key(const Pem& pem)
  {
    return std::make_shared<PublicKeyImpl>(pem);
  }

  PublicKeyPtr make_public_key(const std::vector<uint8_t>& der)
  {
    return std::make_shared<PublicKeyImpl>(der);
  }

  KeyPairPtr make_key_pair(CurveID curve_id)
  {
    return std::make_shared<KeyPairImpl>(curve_id);
  }

  KeyPairPtr make_key_pair(const Pem& pem, CBuffer pw)
  {
    return std::make_shared<KeyPairImpl>(pem, pw);
  }
}
