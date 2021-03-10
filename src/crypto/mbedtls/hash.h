// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash_provider.h"
#include "ds/buffer.h"

#include <mbedtls/md.h>
#include <mbedtls/pk.h>

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <msgpack/msgpack.hpp>

namespace crypto
{
  namespace mbedtls
  {
    inline mbedtls_md_type_t get_md_type(MDType type)
    {
      switch (type)
      {
        case MDType::NONE:
          return MBEDTLS_MD_NONE;
        case MDType::SHA1:
          return MBEDTLS_MD_SHA1;
        case MDType::SHA256:
          return MBEDTLS_MD_SHA256;
        case MDType::SHA384:
          return MBEDTLS_MD_SHA384;
        case MDType::SHA512:
          return MBEDTLS_MD_SHA512;
        default:
          throw std::runtime_error("Unsupported hash algorithm");
      }
      return MBEDTLS_MD_NONE;
    }
  }

  class MBedHashProvider : public HashProvider
  {
  public:
    virtual HashBytes Hash(const uint8_t* data, size_t size, MDType type) const
    {
      HashBytes r;
      const auto mbedtls_md_type = mbedtls::get_md_type(type);
      const auto info = mbedtls_md_info_from_type(mbedtls_md_type);
      const auto hash_size = mbedtls_md_get_size(info);

      r.resize(hash_size);

      if (mbedtls_md(info, data, size, r.data()) != 0)
        r.clear();

      return r;
    }
  };

  class ISha256MbedTLS : public ISha256Hash
  {
  public:
    ISha256MbedTLS();
    ~ISha256MbedTLS();
    virtual void update_hash(CBuffer data);
    virtual Sha256Hash finalise();

  protected:
    void* ctx;
  };

  void mbedtls_sha256(const CBuffer& data, uint8_t* h);
}
