// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "aes_gcm.h"

#include "ds/logger.h"

extern "C"
{
#include <evercrypt/EverCrypt_AEAD.h>
}

#include <alloca.h>
#include <cstring>

typedef struct aes_gcm_ctx
{
  EverCrypt_AEAD_state_s* st;
} aes_gcm_ctx;

aes_gcm_ctx_t aes_gcm_new(char key[])
{
  aes_gcm_ctx* ctx = new aes_gcm_ctx;

  EverCrypt_AEAD_create_in(Spec_AEAD_AES128_GCM, &ctx->st, (uint8_t*)key);
  return ctx;
}

int aes_gcm_delete(aes_gcm_ctx_t ctx)
{
  EverCrypt_AEAD_free(ctx->st);
  delete ctx;
  return (1);
}

int aes_gcm(aes_gcm_ctx_t ctx, char* input, long len, char tag[], char nonce[8])
{
  uint64_t iv[2];
  iv[0] = ((uint64_t*)nonce)[0];
  iv[1] = 0;

  uint8_t* cipher = (uint8_t*)alloca(len + 16);

  uint32_t adlen = 0;
  uint8_t ad[16] = {0};

  // TODO: we do not care about the cypher text, so maybe not produce it?
  auto rc = EverCrypt_AEAD_encrypt(
    ctx->st,
    (uint8_t*)iv,
    ad,
    adlen,
    (uint8_t*)input,
    (uint32_t)len,
    cipher,
    (uint8_t*)tag);

  if (rc != EverCrypt_Error_Success)
  {
    LOG_FAIL << "aes_gcm failed: " << rc << std::endl;
    return 0;
  }

  return (1);
}
