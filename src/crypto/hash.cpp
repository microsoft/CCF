// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include <stdexcept>
#include "hash.h"

#include <mbedtls/sha256.h>

extern "C" {
#include <evercrypt/EverCrypt_Hash.h>
}

using namespace std;

void crypto::Sha256Hash::mbedtls_sha256(initializer_list<CBuffer> il, uint8_t *h)
{
  mbedtls_sha256_context ctx;
  mbedtls_sha256_starts_ret(&ctx, 0);

  for (auto data : il)
    mbedtls_sha256_update_ret(&ctx, data.p, data.rawSize());

  mbedtls_sha256_finish_ret(&ctx, h);
  mbedtls_sha256_free(&ctx);
}

void crypto::Sha256Hash::evercrypt_sha256(initializer_list<CBuffer> il, uint8_t *h)
{
  EverCrypt_Hash_state_s *state = EverCrypt_Hash_create(Spec_Hash_Definitions_SHA2_256);
  EverCrypt_Hash_init(state);

  for (auto data : il)
  {
    EverCrypt_Hash_update_multi(state, const_cast<uint8_t*>(data.p), data.rawSize());
    EverCrypt_Hash_update_last(state, const_cast<uint8_t*>(data.p), data.rawSize());
  }

  EverCrypt_Hash_finish(state, h);
  EverCrypt_Hash_free(state);
}

void crypto::Sha256Hash::hacl_sha256(initializer_list<CBuffer> il, uint8_t *h)
{
  uint32_t ctx[137U] = { 0U };
  Hacl_Hash_Core_SHA2_init_256(ctx);

  for (auto data : il)
  {
    uint64_t input_len = data.rawSize();
    uint32_t blocks_n = input_len / (uint32_t)64U;
    uint32_t blocks_len = blocks_n * (uint32_t)64U;
    uint8_t *blocks = const_cast<uint8_t*>(data.p);
    uint32_t rest_len = input_len - blocks_len;
    uint8_t *rest = blocks + blocks_len;
    Hacl_Hash_SHA2_update_multi_256(ctx, blocks, blocks_n);
    Hacl_Hash_SHA2_update_last_256(ctx, blocks_len, rest, rest_len);
  }

  Hacl_Hash_Core_SHA2_finish_256(ctx, h);
}

crypto::Sha256Hash::Sha256Hash() : h{0}
{
}

crypto::Sha256Hash::Sha256Hash(initializer_list<CBuffer> il) : h{0}
{
  evercrypt_sha256(il, h);
}
