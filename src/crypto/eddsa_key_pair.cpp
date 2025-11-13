// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/eddsa_key_pair.h"

#include "openssl/ec_public_key.h"
#include "openssl/eddsa_key_pair.h"

#include <cstring>
#include <iomanip>
#include <limits>
#include <memory>
#include <string>

namespace ccf::crypto
{
  EdDSAPublicKeyPtr make_eddsa_public_key(const Pem& pem)
  {
    return std::make_shared<EdDSAPublicKey_OpenSSL>(pem);
  }

  EdDSAPublicKeyPtr make_eddsa_public_key(const JsonWebKeyEdDSAPublic& jwk)
  {
    return std::make_shared<EdDSAPublicKey_OpenSSL>(jwk);
  }

  EdDSAKeyPairPtr make_eddsa_key_pair(CurveID curve_id)
  {
    return std::make_shared<EdDSAKeyPair_OpenSSL>(curve_id);
  }

  EdDSAKeyPairPtr make_eddsa_key_pair(const Pem& pem)
  {
    return std::make_shared<EdDSAKeyPair_OpenSSL>(pem);
  }

  EdDSAKeyPairPtr make_eddsa_key_pair(const JsonWebKeyEdDSAPrivate& jwk)
  {
    return std::make_shared<EdDSAKeyPair_OpenSSL>(jwk);
  }
}
