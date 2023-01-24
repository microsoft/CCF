// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/eddsa_key_pair.h"

#include "openssl/eddsa_key_pair.h"
#include "openssl/public_key.h"

#include <cstring>
#include <iomanip>
#include <limits>
#include <memory>
#include <string>

namespace crypto
{
  using PublicKeyImpl = EdDSAPublicKey_OpenSSL;
  using KeyPairImpl = EdDSAKeyPair_OpenSSL;

  EdDSAPublicKeyPtr make_eddsa_public_key(const Pem& pem)
  {
    return std::make_shared<PublicKeyImpl>(pem);
  }

  EdDSAPublicKeyPtr make_eddsa_public_key(const JsonWebKeyEdDSAPublic& jwk)
  {
    return std::make_shared<PublicKeyImpl>(jwk);
  }

  EdDSAKeyPairPtr make_eddsa_key_pair(CurveID curve_id)
  {
    return std::make_shared<KeyPairImpl>(curve_id);
  }

  EdDSAKeyPairPtr make_eddsa_key_pair(const Pem& pem)
  {
    return std::make_shared<KeyPairImpl>(pem);
  }

  EdDSAKeyPairPtr make_eddsa_key_pair(const JsonWebKeyEdDSAPrivate& jwk)
  {
    return std::make_shared<KeyPairImpl>(jwk);
  }
}
