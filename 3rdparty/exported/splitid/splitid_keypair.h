// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "splitid_ec.h"
#include "splitid_util.h"

#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <stdexcept>

namespace SplitIdentity
{
  class KeyPair
  {
  public:
    KeyPair() : private_key(NULL) {}

    KeyPair(EC::CurveID curve = EC::CurveID::SECP384R1) : private_key(NULL)
    {
      int curve_nid = get_openssl_group_id(curve);
      private_key = EVP_PKEY_new();
      Wrapped_EVP_PKEY_CTX pkctx;
      CHECK1(EVP_PKEY_paramgen_init(pkctx));
      CHECK1(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, curve_nid));
      CHECK1(EVP_PKEY_CTX_set_ec_param_enc(pkctx, OPENSSL_EC_NAMED_CURVE));
      CHECK1(EVP_PKEY_keygen_init(pkctx));
      CHECK1(EVP_PKEY_keygen(pkctx, &private_key));

      Wrapped_BIO buf;
      CHECK1(PEM_write_bio_PUBKEY(buf, private_key));
      BUF_MEM* bptr;
      BIO_get_mem_ptr(buf, &bptr);
      public_key_pem = {
        (uint8_t*)bptr->data, (uint8_t*)bptr->data + bptr->length};
    }

    KeyPair(EVP_PKEY* key)
    {
      private_key = key;
      CHECK1(EVP_PKEY_up_ref(private_key));

      Wrapped_BIO buf;
      CHECK1(PEM_write_bio_PUBKEY(buf, private_key));
      BUF_MEM* bptr;
      BIO_get_mem_ptr(buf, &bptr);
      public_key_pem = {
        (uint8_t*)bptr->data, (uint8_t*)bptr->data + bptr->length};
    }

    KeyPair(KeyPair& other) = delete;

    KeyPair(KeyPair&& other)
    {
      private_key = other.private_key;
      other.private_key = NULL;
      public_key_pem = other.public_key_pem;
      other.public_key_pem.clear();
    }

    virtual ~KeyPair()
    {
      if (private_key)
      {
        EVP_PKEY_free(private_key);
      }
    }

    EVP_PKEY* private_key;
    std::vector<uint8_t> public_key_pem;

    std::vector<uint8_t> derive_shared_secret(
      const std::vector<uint8_t>& peer_public_key) const
    {
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, NULL);
      EVP_PKEY_derive_init(ctx);

      EVP_PKEY* onid_public;
      Wrapped_BIO bio(peer_public_key.data(), peer_public_key.size());
      CHECKNULL(onid_public = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL));

      EVP_PKEY_derive_set_peer(ctx, onid_public);
      size_t shared_len = 0;
      EVP_PKEY_derive(ctx, NULL, &shared_len);

      std::vector<uint8_t> shared_secret(shared_len, 0);
      EVP_PKEY_derive(ctx, shared_secret.data(), &shared_len);
      EVP_PKEY_free(onid_public);
      EVP_PKEY_CTX_free(ctx);

      return shared_secret;
    }
  };
}