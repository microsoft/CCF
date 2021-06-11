// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "splitid_util.h"

#include <cassert>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <stdexcept>

namespace SplitIdentity
{
  namespace EC
  {
    class Point;
  };

  class BigNum
  {
  public:
    BigNum()
    {
      CHECKNULL(b = BN_new());
    }

    BigNum(const BigNum& other)
    {
      CHECKNULL(b = BN_dup(other.b));
    }

    BigNum(BigNum&& other)
    {
      b = other.b;
      other.b = NULL;
    }

    BigNum(const std::string& value)
    {
      CHECKNULL(b = BN_new());
      BN_dec2bn(&b, value.c_str());
    }

    BigNum(unsigned long i)
    {
      CHECKNULL(b = BN_new());
      CHECK1(BN_set_word(b, i));
    }

    BigNum(const BIGNUM* other)
    {
      CHECKNULL(b = BN_dup(other));
    }

    BigNum(const uint8_t*& buf, size_t& sz)
    {
      size_t bsz = deserialise_size_t(buf, sz);
      CHECKNULL(b = BN_bin2bn(buf, bsz, NULL));
      buf += bsz;
      sz -= bsz;
    }

    BigNum(const std::vector<uint8_t>& buf)
    {
      CHECKNULL(b = BN_bin2bn(buf.data(), buf.size(), NULL));
    }

    ~BigNum()
    {
      BN_free(b);
    }

    void operator=(const BigNum& other)
    {
      BN_free(b);
      CHECKNULL(b = BN_dup(other.b));
    }

    bool operator==(const BigNum& other) const
    {
      return BN_cmp(b, other.b) == 0;
    }

    bool operator!=(const BigNum& other) const
    {
      return BN_cmp(b, other.b) != 0;
    }

    bool operator<(const BigNum& other) const
    {
      return BN_cmp(b, other.b) < 0;
    }

    static BigNum random(const BigNum& order)
    {
      BigNum r;
      CHECK1(BN_rand_range(r.b, order.b));
      return r;
    }

    static const BigNum& zero()
    {
      static BigNum z((unsigned long)0);
      return z;
    }

    static BigNum make_zero()
    {
      BigNum r;
      BN_zero(r.b);
      return r;
    }

    static BigNum from_hex(const std::string& value)
    {
      BigNum r;
      BN_hex2bn(&r.b, value.c_str());
      return r;
    }

    BigNum mul(const BigNum& other)
    {
      BigNum r;
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      CHECK1(BN_mul(r.b, this->b, other.b, ctx));
      BN_CTX_free(ctx);
      return r;
    }

    BigNum add(const BigNum& other)
    {
      BigNum r;
      CHECK1(BN_add(r.b, this->b, other.b));
      return r;
    }

    BigNum sub(const BigNum& other)
    {
      BigNum r;
      CHECK1(BN_sub(r.b, this->b, other.b));
      return r;
    }

    static BigNum mod(const BigNum& a, const BigNum& m)
    {
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BigNum r;
      CHECK1(BN_mod(r.b, a.b, m.b, ctx));
      BN_CTX_free(ctx);
      return r;
    }

    BigNum mod(const BigNum& m)
    {
      return mod(*this, b);
    }

    static BigNum mod_exp(const BigNum& a, const BigNum& b, const BigNum& m)
    {
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BigNum r;
      CHECK1(BN_mod_exp(r.b, a.b, b.b, m.b, ctx));
      BN_CTX_free(ctx);
      return r;
    }

    BigNum mod_exp(const BigNum& b, const BigNum& m)
    {
      return mod_exp(*this, b, m);
    }

    static BigNum mod_mul(const BigNum& a, const BigNum& b, const BigNum& m)
    {
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BigNum r;
      CHECK1(BN_mod_mul(r.b, a.b, b.b, m.b, ctx));
      BN_CTX_free(ctx);
      return r;
    }

    BigNum mod_mul(const BigNum& b, const BigNum& m) const
    {
      return mod_mul(*this, b, m);
    }

    static BigNum mod_add(const BigNum& a, const BigNum& b, const BigNum& m)
    {
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BigNum r;
      CHECK1(BN_mod_add(r.b, a.b, b.b, m.b, ctx));
      BN_CTX_free(ctx);
      return r;
    }

    BigNum mod_add(const BigNum& b, const BigNum& m) const
    {
      return mod_add(*this, b, m);
    }

    static BigNum mod_sub(const BigNum& a, const BigNum& b, const BigNum& m)
    {
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BigNum r;
      CHECK1(BN_mod_sub(r.b, a.b, b.b, m.b, ctx));
      BN_CTX_free(ctx);
      return r;
    }

    BigNum mod_sub(const BigNum& b, const BigNum& m) const
    {
      return mod_sub(*this, b, m);
    }

    static BigNum mod_inv(const BigNum& a, const BigNum& m)
    {
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BigNum r;
      if (!BN_mod_inverse(r.b, a.b, m.b, ctx))
      {
        throw std::runtime_error("OpenSSL error: BN_mod_inverse failed");
      }
      BN_CTX_free(ctx);
      return r;
    }

    BigNum mod_inv(const BigNum& m)
    {
      return mod_inv(*this, m);
    }

    static BigNum lagrange_coefficient(
      const std::vector<size_t>& indices,
      size_t i,
      const BigNum& input,
      const BigNum& group_order)
    {
      BigNum r(1);
      BigNum i_bn(indices[i]);
      for (size_t j = 0; j < indices.size(); j++)
      {
        if (i != j)
        {
          BigNum j_bn(indices[j]);
          auto numerator = BigNum::mod_sub(input, j_bn, group_order);
          auto bottom = BigNum::mod_sub(i_bn, j_bn, group_order);
          auto denominator = BigNum::mod_inv(bottom, group_order);
          auto nd = BigNum::mod_mul(numerator, denominator, group_order);
          r = BigNum::mod_mul(r, nd, group_order);
        }
      }
      return r;
    }

    static BigNum lagrange_interpolate(
      const std::vector<BigNum>& values,
      const std::vector<size_t>& indices,
      const BigNum& j,
      const BigNum& group_order)
    {
      assert(values.size() == indices.size());
      BigNum r = BigNum::zero();
      for (size_t i = 0; i < values.size(); i++)
      {
        auto coeff_i = lagrange_coefficient(indices, i, j, group_order);
        auto t = BigNum::mod_mul(coeff_i, values[i], group_order);
        r = BigNum::mod_add(r, t, group_order);
      }
      return r;
    }

    size_t byte_size() const
    {
      return BN_num_bytes(b);
    }

    std::vector<uint8_t> serialise() const
    {
      size_t bsz = byte_size();
      std::vector<uint8_t> r = serialise_size_t(bsz);
      r.resize(r.size() + bsz);
      BN_bn2bin(b, r.data() + r.size() - bsz);
      return r;
    }

    std::string to_string() const
    {
      char* cs = BN_bn2dec(b);
      CHECKNULL(cs);
      std::string r = cs;
      OPENSSL_free(cs);
      return r;
    }

    BIGNUM* raw() const
    {
      return b;
    };

  protected:
    BIGNUM* b;

    friend class EC::Point;
  };

#if defined(NLOHMANN_JSON_VERSION_MAJOR) && NLOHMANN_JSON_VERSION_MAJOR >= 3
  inline void to_json(nlohmann::json& j, const BigNum& b)
  {
    j = b.to_string();
  }

  inline void from_json(const nlohmann::json& j, BigNum& b)
  {
    if (j.is_string())
    {
      b = BigNum(j.get<std::string>());
    }
    else
    {
      throw std::runtime_error(
        std::string("BigNum is not a string-encoded number: " + j.dump()));
    }
  }
#endif
}
