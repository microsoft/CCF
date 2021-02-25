// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "rsa_key_pair.h"

#include "mbedtls/rsa_key_pair.h"
#include "openssl/rsa_key_pair.h"

namespace crypto
{
#ifdef CRYPTO_PROVIDER_IS_MBEDTLS
  using RSAPublicKeyImpl = RSAPublicKey_mbedTLS;
  using RSAKeyPairImpl = RSAKeyPair_mbedTLS;
#else
  using RSAPublicKeyImpl = RSAPublicKey_OpenSSL;
  using RSAKeyPairImpl = RSAKeyPair_OpenSSL;
#endif

  RSAPublicKeyPtr make_rsa_public_key(const Pem& public_pem)
  {
    return make_rsa_public_key(public_pem.data(), public_pem.size());
  }

  RSAPublicKeyPtr make_rsa_public_key(const std::vector<uint8_t>& der)
  {
    return std::make_shared<RSAPublicKeyImpl>(der);
  }

  static constexpr auto PEM_BEGIN = "-----BEGIN";
  static constexpr auto PEM_BEGIN_LEN =
    std::char_traits<char>::length(PEM_BEGIN);

  RSAPublicKeyPtr make_rsa_public_key(const uint8_t* data, size_t size)
  {
    if (size < 10 || strncmp(PEM_BEGIN, (char*)data, PEM_BEGIN_LEN) != 0)
    {
      std::vector<uint8_t> der = {data, data + size};
      return std::make_shared<RSAPublicKeyImpl>(der);
    }
    else
    {
      Pem pem(data, size);
      return std::make_shared<RSAPublicKeyImpl>(pem);
    }
  }

  /**
   * Create a new public / private RSA key pair with specified size and exponent
   */
  RSAKeyPairPtr make_rsa_key_pair(
    size_t public_key_size, size_t public_exponent)
  {
    return std::make_shared<RSAKeyPairImpl>(public_key_size, public_exponent);
  }

  /**
   * Create a public / private RSA key pair from existing private key data
   */
  RSAKeyPairPtr make_rsa_key_pair(const Pem& pem, CBuffer pw)
  {
    return std::make_shared<RSAKeyPairImpl>(pem, pw);
  }
}
