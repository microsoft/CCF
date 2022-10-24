// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/eddsa_key_pair.h"
#include "crypto/openssl/hash.h"
#include "openssl_wrappers.h"

namespace crypto
{
  using namespace OpenSSL;

  EdDSAPublicKey_OpenSSL::EdDSAPublicKey_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem);
    key = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    if (!key)
    {
      throw std::runtime_error("could not parse PEM");
    }
  }

  EdDSAPublicKey_OpenSSL::~EdDSAPublicKey_OpenSSL()
  {
    if (key)
    {
      EVP_PKEY_free(key);
    }
  }

  Pem EdDSAPublicKey_OpenSSL::public_key_pem() const
  {
    Unique_BIO buf;

    OpenSSL::CHECK1(PEM_write_bio_PUBKEY(buf, key));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }

  bool EdDSAPublicKey_OpenSSL::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* signature,
    size_t signature_size)
  {
    // MYTODO: remove unnecessary print, error handling
    Unique_EVP_MD_CTX ctx;
    EVP_PKEY_CTX* pkctx = nullptr;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_ED25519)
    {
      printf("wrong base id\n");
    }

    if (1 != EVP_DigestVerifyInit(ctx, &pkctx, NULL, NULL, key))
    {
      printf("EVP_DigestVerifyInit failed\n");
    }
    char buffer[512];
    int ret =
      EVP_DigestVerify(ctx, signature, signature_size, contents, contents_size);
    if (ret != 1)
    {
      printf(
        "EVP_DigestVerify: %s\n", ERR_error_string(ERR_get_error(), buffer));
    }
    return ret == 1;
  }

  int EdDSAPublicKey_OpenSSL::get_openssl_group_id(CurveID gid)
  {
    switch (gid)
    {
      case CurveID::CURVE25519:
        return EVP_PKEY_ED25519;
      default:
        throw std::logic_error(
          fmt::format("unsupported OpenSSL CurveID {}", gid));
    }
    return NID_undef;
  }
}