// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "hash.h"

#include "../tls/mbedtls_wrappers.h"

#include <mbedtls/sha256.h>
#include <stdexcept>

using namespace std;

namespace crypto
{
  void Sha256Hash::mbedtls_sha256(const CBuffer& data, uint8_t* h)
  {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);

    mbedtls_sha256_update_ret(&ctx, data.p, data.rawSize());

    mbedtls_sha256_finish_ret(&ctx, h);
    mbedtls_sha256_free(&ctx);
  }

  class MBSha256HashImpl
  {
  public:
    MBSha256HashImpl()
    {
      ctx = std::move(mbedtls::make_unique<mbedtls::SHA256Ctx>());
      mbedtls_sha256_starts_ret(ctx.get(), 0);
    }

    void finalize(std::array<uint8_t, Sha256Hash::SIZE>& h)
    {
      mbedtls_sha256_finish_ret(ctx.get(), h.data());
    }

    void update(const CBuffer& data)
    {
      mbedtls_sha256_update_ret(ctx.get(), data.p, data.rawSize());
    }

  private:
    mbedtls::SHA256Ctx ctx;
  };

  Sha256Hash::Sha256Hash() : h{0} {}
  Sha256Hash::Sha256Hash(const CBuffer& data) : h{0}
  {
    mbedtls_sha256(data, h.data());
  }

  CSha256Hash::CSha256Hash() : p(std::make_unique<MBSha256HashImpl>()) {}
  CSha256Hash::~CSha256Hash() {}

  void CSha256Hash::update_hash(CBuffer data)
  {
    if (p == nullptr)
    {
      throw std::logic_error("Attempting to use hash after it was finalized");
    }
    p->update(data);
  }

  Sha256Hash CSha256Hash::finalize()
  {
    if (p == nullptr)
    {
      throw std::logic_error("Attempting to use hash after it was finalized");
    }

    Sha256Hash h;
    p->finalize(h.h);
    p = nullptr;
    return h;
  }
}