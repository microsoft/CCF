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

  EdDSAKeyPairPtr make_eddsa_key_pair(CurveID curve_id)
  {
    return std::make_shared<KeyPairImpl>(curve_id);
  }

  EdDSAPublicKeyPtr make_eddsa_public_key(const Pem& pem)
  {
    return std::make_shared<PublicKeyImpl>(pem);
  }

  std::vector<uint8_t> eddsa_sign(
    const std::vector<uint8_t>& data, const Pem& private_key)
  {
    return KeyPairImpl::sign(data, private_key);
  }

}
