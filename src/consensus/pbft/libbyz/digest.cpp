// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "digest.h"

#include "ds/logger.h"
#include "pbft_assert.h"
#include "statistics.h"

#include <string.h>

Digest::Digest(char* s, unsigned n)
{
#ifndef NODIGESTS
  INCR_OP(num_digests);

  // creates a digest for string "s" with length "n"
  EverCrypt_Hash_hash(
    Spec_Hash_Definitions_SHA2_256, (uint8_t*)d, (uint8_t*)s, (uint32_t)n);

#else
  for (int i = 0; i < 4; i++)
    d[i] = 3;
#endif // NODIGESTS
}

Digest::Context::Context() :
  s{(uint32_t)0x6a09e667U,
    (uint32_t)0xbb67ae85U,
    (uint32_t)0x3c6ef372U,
    (uint32_t)0xa54ff53aU,
    (uint32_t)0x510e527fU,
    (uint32_t)0x9b05688cU,
    (uint32_t)0x1f83d9abU,
    (uint32_t)0x5be0cd19U}
{
  scrut.tag = EverCrypt_Hash_SHA2_256_s;
  scrut.case_SHA2_256_s = s;
}

unsigned Digest::block_length()
{
  // Spec_Hash_Definitions_SHA2_256
  return (uint32_t)64U;
}

void Digest::update(Digest::Context& ctx, char* s, unsigned n)
{
  PBFT_ASSERT(n % block_length() == 0, "n must be a mutiple of block_length()");
  EverCrypt_Hash_update_multi(&ctx.scrut, (uint8_t*)s, n);
}

void Digest::update_last(Digest::Context& ctx, const char* s, unsigned n)
{
  EverCrypt_Hash_update_last(&ctx.scrut, (uint8_t*)s, n);
}

void Digest::finalize(Digest::Context& ctx)
{
  EverCrypt_Hash_finish(&ctx.scrut, (uint8_t*)d);
}

void Digest::print()
{
  LOG_INFO << "digest=[" << d[0] << "," << d[1] << "," << d[2] << "," << d[3]
           << "]" << std::endl;
}
