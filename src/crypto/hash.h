// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/buffer.h"
#include "ds/json.h"

#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <msgpack/msgpack.hpp>
#include <ostream>

namespace crypto
{
  enum class MDType
  {
    NONE = 0,
    SHA1,
    SHA256,
    SHA384,
    SHA512
  };

  using HashBytes = std::vector<uint8_t>;

  class HashProviderBase
  {
  public:
    virtual HashBytes Hash(const uint8_t*, size_t, MDType) const = 0;
  };

  class MBedHashProvider : public HashProviderBase
  {
  public:
    static inline mbedtls_md_type_t get_md_type(MDType type)
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

    virtual HashBytes Hash(const uint8_t* data, size_t size, MDType type) const
    {
      HashBytes r;
      const auto mbedtls_md_type = get_md_type(type);
      const auto info = mbedtls_md_info_from_type(mbedtls_md_type);
      const auto hash_size = mbedtls_md_get_size(info);

      r.resize(hash_size);

      if (mbedtls_md(info, data, size, r.data()) != 0)
        r.clear();

      return r;
    }
  };

  class OpenSSLHashProvider : public HashProviderBase
  {
  public:
    static inline const EVP_MD* get_md_type(MDType type)
    {
      switch (type)
      {
        case MDType::NONE:
          return nullptr;
        case MDType::SHA1:
          return EVP_sha1();
        case MDType::SHA256:
          return EVP_sha256();
        case MDType::SHA384:
          return EVP_sha384();
        case MDType::SHA512:
          return EVP_sha512();
        default:
          throw std::runtime_error("Unsupported hash algorithm");
      }
      return nullptr;
    }

    virtual HashBytes Hash(const uint8_t* data, size_t size, MDType type) const
    {
      HashBytes r;
      unsigned int len = 0;
      auto o_md_type = get_md_type(type);

      r.resize(EVP_MD_size(o_md_type));

      if (EVP_Digest(data, size, r.data(), &len, o_md_type, NULL) != 1)
        throw std::runtime_error("OpenSSL hash update error");

      return r;
    }
  };

  typedef MBedHashProvider HashProvider;

  class Sha256Hash
  {
  public:
    static constexpr size_t SIZE = 256 / 8;
    Sha256Hash() : h{0} {}
    Sha256Hash(const CBuffer& data) : h{0}
    {
      // const auto info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
      // assert(mbedtls_md_get_size(info) == SIZE);
      // mbedtls_md(info, data.p, data.rawSize(), h.data());

      ::SHA256(data.p, data.rawSize(), h.data());

      // Check if this is slower?
      // HashProvider hp;
      // auto hash = hp.Hash(data.data(), data.size(), MDType::SHA256);
      // std::copy(h.data());
    }

    std::array<uint8_t, SIZE> h;

    static void mbedtls_sha256(const CBuffer& data, uint8_t* h);
    static void openssl_sha256(const CBuffer& data, uint8_t* h);

    friend std::ostream& operator<<(
      std::ostream& os, const crypto::Sha256Hash& h)
    {
      for (unsigned i = 0; i < crypto::Sha256Hash::SIZE; i++)
      {
        os << std::hex << static_cast<int>(h.h[i]);
      }

      return os;
    }

    std::string hex_str() const
    {
      return fmt::format("{:02x}", fmt::join(h, ""));
    };

    MSGPACK_DEFINE(h);
  };

  DECLARE_JSON_TYPE(Sha256Hash);
  DECLARE_JSON_REQUIRED_FIELDS(Sha256Hash, h);

  inline bool operator==(const Sha256Hash& lhs, const Sha256Hash& rhs)
  {
    for (unsigned i = 0; i < crypto::Sha256Hash::SIZE; i++)
    {
      if (lhs.h[i] != rhs.h[i])
      {
        return false;
      }
    }
    return true;
  }

  inline bool operator!=(const Sha256Hash& lhs, const Sha256Hash& rhs)
  {
    return !(lhs == rhs);
  }

  // Incremental Hash Objects
  class ISha256HashBase
  {
  public:
    ISha256HashBase() {}
    virtual ~ISha256HashBase() {}

    virtual void update_hash(CBuffer data) = 0;
    virtual Sha256Hash finalise() = 0;

    template <typename T>
    void update(const T& t)
    {
      update_hash({reinterpret_cast<const uint8_t*>(&t), sizeof(T)});
    }

    template <>
    void update<std::vector<uint8_t>>(const std::vector<uint8_t>& d)
    {
      update_hash({d.data(), d.size()});
    }
  };

  class ISha256MbedTLS : public ISha256HashBase
  {
  public:
    ISha256MbedTLS();
    ~ISha256MbedTLS();
    virtual void update_hash(CBuffer data);
    virtual Sha256Hash finalise();

  protected:
    void* ctx;
  };

  class ISha256OpenSSL : public ISha256HashBase
  {
  public:
    ISha256OpenSSL();
    ~ISha256OpenSSL();
    virtual void update_hash(CBuffer data);
    virtual Sha256Hash finalise();

  protected:
    void* ctx;
  };

  typedef ISha256OpenSSL ISha256Hash;
}

namespace fmt
{
  template <>
  struct formatter<crypto::Sha256Hash>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const crypto::Sha256Hash& p, FormatContext& ctx)
    {
      return format_to(ctx.out(), "<sha256 {:02x}>", fmt::join(p.h, ""));
    }
  };
}