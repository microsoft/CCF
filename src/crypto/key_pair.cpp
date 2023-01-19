// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/key_pair.h"

#include "openssl/key_pair.h"
#include "openssl/public_key.h"

#include <cstring>
#include <iomanip>
#include <limits>
#include <memory>
#include <string>

namespace crypto
{
  using PublicKeyImpl = PublicKey_OpenSSL;
  using KeyPairImpl = KeyPair_OpenSSL;

  PublicKeyPtr make_public_key(const Pem& pem)
  {
    return std::make_shared<PublicKeyImpl>(pem);
  }

  PublicKeyPtr make_public_key(const std::vector<uint8_t>& der)
  {
    return std::make_shared<PublicKeyImpl>(der);
  }

  PublicKeyPtr make_public_key(const JsonWebKeyECPublic& jwk)
  {
    return std::make_shared<PublicKeyImpl>(jwk);
  }

  KeyPairPtr make_key_pair(CurveID curve_id)
  {
    return std::make_shared<KeyPairImpl>(curve_id);
  }

  KeyPairPtr make_key_pair(const Pem& pem)
  {
    return std::make_shared<KeyPairImpl>(pem);
  }
}
