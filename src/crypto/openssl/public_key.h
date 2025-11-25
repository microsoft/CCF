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

    std::optional<int> cose_alg_id()
    {
      if (!key)
      {
        return std::nullopt;
      }

      int key_type = EVP_PKEY_get_base_id(key);

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
        if (gname == SN_X9_62_prime256v1) // P-256
        {
          return -7; // ES256
        }
        if (gname == SN_secp384r1) // P-384
        {
          return -35; // ES384
        }
        if (gname == SN_secp521r1) // P-521
        {
          return -36; // ES512
        }
      }
      else if (key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_RSA_PSS)
      {
        int bits = EVP_PKEY_bits(key);

        // Map key size to COSE PS algorithm
        // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
        if (bits == 2048)
        {
          return -37; // PS256
        }

        // RSASSA-PSS using SHA-384 and MGF1 with SHA-384
        if (bits == 3072)
        {
          return -38; // PS384
        }

        // RSASSA-PSS using SHA-512 and MGF1 with SHA-512
        if (bits == 4096)
        {
          return -39; // PS512
        }
      }

      return std::nullopt;
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