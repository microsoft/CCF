// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "hash.h"

#include <mbedtls/sha256.h>
#include <stdexcept>

extern "C"
{
#include <evercrypt/EverCrypt_Hash.h>
}

using namespace std;

void crypto::Sha256Hash::mbedtls_sha256(const CBuffer& data, uint8_t* h)
{
  mbedtls_sha256_context ctx;
  mbedtls_sha256_starts_ret(&ctx, 0);

  mbedtls_sha256_update_ret(&ctx, data.p, data.rawSize());

  mbedtls_sha256_finish_ret(&ctx, h);
  mbedtls_sha256_free(&ctx);
}

void crypto::Sha256Hash::evercrypt_sha256(const CBuffer& data, uint8_t* h)
{
  EverCrypt_Hash_state_s* state =
    EverCrypt_Hash_create(Spec_Hash_Definitions_SHA2_256);
  EverCrypt_Hash_init(state);

  constexpr auto block_size = 64u; // No way to ask evercrypt for this

  const auto data_begin = const_cast<uint8_t*>(data.p);
  const auto size = data.rawSize();
  const auto full_blocks = size / block_size;

  const auto full_blocks_size = full_blocks * block_size;
  const auto full_blocks_end = data_begin + full_blocks_size;

  // update_multi takes complete blocks
  EverCrypt_Hash_update_multi(state, data_begin, full_blocks_size);

  // update_last takes start of last chunk (NOT a full block!), and _total size_
  EverCrypt_Hash_update_last(state, full_blocks_end, size);

  EverCrypt_Hash_finish(state, h);
  EverCrypt_Hash_free(state);
}

crypto::Sha256Hash::Sha256Hash() : h{0} {}

crypto::Sha256Hash::Sha256Hash(const CBuffer& data) : h{0}
{
  evercrypt_sha256(data, h.data());
}