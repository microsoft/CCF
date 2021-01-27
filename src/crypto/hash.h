// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/buffer.h"
#include "ds/json.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <msgpack/msgpack.hpp>
#include <ostream>

namespace crypto
{
  class Sha256Hash
  {
  public:
    static constexpr size_t SIZE = 256 / 8;
    Sha256Hash();
    Sha256Hash(const CBuffer& data);

    std::array<uint8_t, SIZE> h;

    static void mbedtls_sha256(const CBuffer& data, uint8_t* h);

#ifdef HAVE_OPENSSL
    static void openssl_sha256(const CBuffer& data, uint8_t* h);
#endif

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

#ifdef HAVE_OPENSSL
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
#else
  typedef ISha256MbedTLS ISha256Hash;
#endif
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