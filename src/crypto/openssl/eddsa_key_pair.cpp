// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/eddsa_key_pair.h"

namespace crypto
{

  EdDSAKeyPair_OpenSSL::EdDSAKeyPair_OpenSSL(CurveID curve_id)
  {
    // MYTODO: mechanizm to get value of EVP_PKEY_ED25519
    // int curve_nid = get_openssl_group_id(curve_id);
    key = EVP_PKEY_new();
    EVP_PKEY_CTX* pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    // MYTODO: Error handling (also for similar codes)
    EVP_PKEY_keygen_init(pkctx);
    EVP_PKEY_keygen(pkctx, &key);
    EVP_PKEY_CTX_free(pkctx); // MYTODO: necessary here?
  }

  Pem EdDSAKeyPair_OpenSSL::private_key_pem() const
  {
    OpenSSL::Unique_BIO buf;

    OpenSSL::CHECK1(
      PEM_write_bio_PrivateKey(buf, key, NULL, NULL, 0, NULL, NULL));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }

  Pem EdDSAKeyPair_OpenSSL::public_key_pem() const
  {
    return EdDSAPublicKey_OpenSSL::public_key_pem();
  }

  std::vector<uint8_t> EdDSAKeyPair_OpenSSL::sign(
    std::span<const uint8_t> d, MDType md_type) const
  {
    EVP_PKEY_CTX* pkctx = nullptr;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new(); // MYTODO: free it?

    // type parameter must be NULL for ED25519 since it is PureEdDSA.
    EVP_DigestSignInit(ctx, &pkctx, NULL, NULL, key);

    size_t siglen = 64; // 64 for Ed25519 signautre
    std::vector<uint8_t> sigret(siglen);

    EVP_DigestSign(ctx, &sigret[0], &siglen, &d[0], d.size());

    // MYTODO: is it the best way?
    sigret.resize(siglen);

    return sigret;
  }

  bool EdDSAKeyPair_OpenSSL::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* signature,
    size_t signature_size)
  {
    return EdDSAPublicKey_OpenSSL::verify(
      contents, contents_size, signature, signature_size);
  }

}
