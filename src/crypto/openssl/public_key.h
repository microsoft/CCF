// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/openssl/openssl_wrappers.h"

#include <openssl/evp.h>
#include <stdexcept>
#include <string>

namespace ccf::crypto
{
  class PublicKey_OpenSSL
  {
  protected:
    // The key is always owned by the PublicKey_OpenSSL instance
    // even when passed to the constructor, and is disposed of
    // by the PublicKey_OpenSSL destructor.
    EVP_PKEY* key = nullptr;

  public:
    PublicKey_OpenSSL() = default;
    PublicKey_OpenSSL(EVP_PKEY* key) : key(key) {}
    PublicKey_OpenSSL(const Pem& pem)
    {
      OpenSSL::Unique_BIO mem(pem);
      key = PEM_read_bio_PUBKEY(mem, nullptr, nullptr, nullptr);
      if (key == nullptr)
      {
        throw std::runtime_error("could not parse PEM");
      }
    }

    void check_is_cose_compatible(int cose_alg)
    {
      if (!key)
      {
        throw std::logic_error("Public key is not initialized");
      }

      const int key_type = EVP_PKEY_get_base_id(key);

      if (key_type == EVP_PKEY_EC)
      {
        // Get the curve name
        size_t gname_len = 0;
        OpenSSL::CHECK1(EVP_PKEY_get_group_name(key, nullptr, 0, &gname_len));
        std::string gname(gname_len + 1, '\0');
        OpenSSL::CHECK1(
          EVP_PKEY_get_group_name(key, gname.data(), gname.size(), &gname_len));
        gname.resize(gname_len);

        // Map curve to COSE algorithm
        if (gname == SN_X9_62_prime256v1 && cose_alg != -7) // P-256
        {
          throw std::domain_error(
            fmt::format("Incompatible cose algorithm {} for P-256", cose_alg));
        }
        if (gname == SN_secp384r1 && cose_alg != -35) // P-384
        {
          throw std::domain_error(
            fmt::format("Incompatible cose algorithm {} for P-384", cose_alg));
        }
        if (gname == SN_secp521r1 && cose_alg != -36) // P-521
        {
          throw std::domain_error(
            fmt::format("Incompatible cose algorithm {} for P-521", cose_alg));
        }
      }
      else if (key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_RSA_PSS)
      {
        // It is RECOMMENDED although not required to match hash function and key
        // sizes, so any of PS256(-37), PS384(-38), and PS512(-39) is acceptable.
        //
        // https://www.iana.org/assignments/cose/cose.xhtml
        if (cose_alg != -37 && cose_alg != -38 && cose_alg != -39)
        {
          throw std::domain_error(
            fmt::format("Incompatible cose algorithm {} for RSA", cose_alg));
        }
      }
    }

    operator EVP_PKEY*() const
    {
      return key;
    }

    virtual ~PublicKey_OpenSSL()
    {
      if (key != nullptr)
      {
        EVP_PKEY_free(key);
      }
    }
  };
}