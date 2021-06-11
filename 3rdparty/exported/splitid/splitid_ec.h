// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "splitid_bignum.h"
#include "splitid_logging.h"
#include "splitid_util.h"

#include <map>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <stdexcept>

namespace SplitIdentity
{
  namespace EC
  {
    enum class CurveID
    {
      SECP384R1
    };

    static inline EC_GROUP* get_openssl_group(CurveID curve)
    {
      switch (curve)
      {
        case CurveID::SECP384R1:
          return EC_GROUP_new_by_curve_name(NID_secp384r1);
          break;
        // case CurveID::SECP256R1:
        //   return EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        //   break;
        default:
          throw std::logic_error("unsupported curve");
      }
    }

    static inline int get_openssl_group_id(CurveID gid)
    {
      switch (gid)
      {
        case CurveID::SECP384R1:
          return NID_secp384r1;
        // case CurveID::SECP256R1:
        //   return NID_X9_62_prime256v1;
        default:
          throw std::logic_error("unsupported curve");
      }
      return NID_undef;
    }

    static EC_GROUP* group = get_openssl_group(CurveID::SECP384R1);

    static BigNum group_order(CurveID curve = CurveID::SECP384R1)
    {
      EC_GROUP* group = get_openssl_group(curve);
      BN_CTX* ctx = BN_CTX_new();
      CHECKNULL(ctx);
      BIGNUM* group_order = BN_new();
      CHECKNULL(group_order);
      CHECK1(EC_GROUP_get_order(group, group_order, ctx));
      BigNum r(group_order);
      BN_free(group_order);
      BN_CTX_free(ctx);
      EC_GROUP_free(group);
      return r;
    }

    class CompressedPoint : public std::vector<uint8_t>
    {
    public:
      CompressedPoint() = default;
      ~CompressedPoint() = default;
      CompressedPoint(size_t sz) : std::vector<uint8_t>(sz) {}
      CompressedPoint(const uint8_t* from, const uint8_t* to) :
        std::vector<uint8_t>(from, to)
      {}
      CompressedPoint(const std::vector<uint8_t>& v) : std::vector<uint8_t>(v)
      {}

      // #if defined(NLOHMANN_JSON_VERSION_MAJOR) && NLOHMANN_JSON_VERSION_MAJOR
      // >= 3
      //       inline void to_json(nlohmann::json& j, const CompressedPoint& t)
      //       {
      //         j = base64_encode(t.data(), t.size());
      //       }

      //       inline void from_json(const nlohmann::json& j, CompressedPoint&
      //       t)
      //       {
      //         t = base64_decode(j.get<std::string>());
      //       }
      // #endif
    };

    class Point
    {
    public:
      Point(CurveID curve = CurveID::SECP384R1)
      {
        group = get_openssl_group(curve);
        CHECKNULL(p = EC_POINT_new(group));
        CHECKNULL(bn_ctx = BN_CTX_new());
      }

      Point(const EC_GROUP* group)
      {
        group = EC_GROUP_dup(group);
        CHECKNULL(p = EC_POINT_new(group));
        CHECKNULL(bn_ctx = BN_CTX_new());
      }

      Point(
        const std::string& value,
        bool y_bit /* y=0/1 */,
        CurveID curve = CurveID::SECP384R1)
      {
        group = get_openssl_group(curve);
        CHECKNULL(p = EC_POINT_new(group));
        CHECKNULL(bn_ctx = BN_CTX_new());
        BIGNUM* b = BN_new();
        CHECKNULL(b);
        BN_hex2bn(&b, value.c_str());
        CHECK1(EC_POINT_set_compressed_coordinates(group, p, b, y_bit, bn_ctx));
        BN_free(b);
      }

      Point(const std::vector<uint8_t>& buf, CurveID curve = CurveID::SECP384R1)
      {
        group = get_openssl_group(curve);
        CHECKNULL(p = EC_POINT_new(group));
        CHECKNULL(bn_ctx = BN_CTX_new());
        EC_POINT_oct2point(group, p, buf.data(), buf.size(), bn_ctx);
      }

      Point(const Point& other)
      {
        CHECKNULL(group = EC_GROUP_dup(other.group));
        CHECKNULL(p = EC_POINT_dup(other.p, group));
        CHECKNULL(bn_ctx = BN_CTX_new());
      }

      Point(Point&& other)
      {
        group = other.group;
        p = other.p;
        bn_ctx = other.bn_ctx;
        other.group = NULL;
        other.p = NULL;
        other.bn_ctx = NULL;
      }

      Point(
        const BigNum& x, const BigNum& y, CurveID curve = CurveID::SECP384R1)
      {
        group = get_openssl_group(curve);
        CHECKNULL(p = EC_POINT_new(group));
        CHECKNULL(bn_ctx = BN_CTX_new());
        CHECK1(EC_POINT_set_affine_coordinates(group, p, x.b, y.b, bn_ctx));
      }

      Point(const EC_POINT* p, CurveID curve = CurveID::SECP384R1)
      {
        group = get_openssl_group(curve);
        CHECKNULL(this->p = EC_POINT_dup(p, group));
        CHECKNULL(bn_ctx = BN_CTX_new());
      }

      virtual ~Point()
      {
        BN_CTX_free(bn_ctx);
        EC_GROUP_free(group);
        EC_POINT_free(p);
      }

      Point& operator=(const Point& other)
      {
        BN_CTX_free(bn_ctx);
        EC_GROUP_free(group);
        EC_POINT_free(p);
        CHECKNULL(group = EC_GROUP_dup(other.group));
        CHECKNULL(p = EC_POINT_dup(other.p, group));
        CHECKNULL(bn_ctx = BN_CTX_new());
        return *this;
      }

      bool operator==(const Point& other) const
      {
        return EC_POINT_cmp(group, p, other.p, bn_ctx);
      }

      Point mul(const BigNum& b) const
      {
        Point r;
        CHECK1(EC_POINT_mul(group, r.p, NULL, this->p, b.b, bn_ctx));
        return r;
      }

      Point add(const Point& p) const
      {
        Point r;
        CHECK1(EC_POINT_add(group, r.p, this->p, p.p, bn_ctx));
        return r;
      }

      CompressedPoint compress() const
      {
        int sz = EC_POINT_point2oct(
          group, p, POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
        CompressedPoint r(sz);
        if (
          EC_POINT_point2oct(
            group, p, POINT_CONVERSION_COMPRESSED, r.data(), sz, bn_ctx) == 0)
          throw std::runtime_error("could not compress point into buffer");
        return r;
      }

      std::string to_compressed_hex() const
      {
        char* buf =
          EC_POINT_point2hex(group, p, POINT_CONVERSION_COMPRESSED, bn_ctx);
        std::string r = buf;
        OPENSSL_free(buf);
        return r;
      }

      EC_KEY* to_public_key(CurveID curve = CurveID::SECP384R1) const
      {
        EC_KEY* r;
        CHECKNULL(r = EC_KEY_new());
        EC_GROUP* g = get_openssl_group(curve);
        CHECK1(EC_KEY_set_group(r, g));
        CHECK1(EC_KEY_set_public_key(r, p));
        EC_GROUP_free(g);
        return r;
      }

      std::string to_public_pem(CurveID curve = CurveID::SECP384R1) const
      {
        EC_KEY* key = to_public_key();
        BIO* bio = BIO_new(BIO_s_mem());

        CHECK1(PEM_write_bio_EC_PUBKEY(bio, key));
        BUF_MEM* bptr;
        BIO_get_mem_ptr(bio, &bptr);
        std::string r(bptr->data, bptr->length);

        BIO_free(bio);
        EC_KEY_free(key);
        return r;
      }

      BigNum x() const
      {
        auto r = BigNum::make_zero();
        CHECK1(EC_POINT_get_affine_coordinates(group, p, r.b, NULL, bn_ctx));
        return r;
      }

      BigNum y() const
      {
        auto r = BigNum::make_zero();
        CHECK1(EC_POINT_get_affine_coordinates(group, p, NULL, r.b, bn_ctx));
        return r;
      }

      std::string to_string() const
      {
        return fmt::format("{}/{}", x().to_string(), y().to_string());
      }

    protected:
      BN_CTX* bn_ctx;
      EC_POINT* p;
      EC_GROUP* group;
    };

    static EC::Point eval_in_exp(
      const std::vector<CompressedPoint>& commitment,
      size_t j,
      BigNum group_order)
    {
      size_t degree = commitment.size();
      assert(degree > 0);

      // LOG_TRACE_FMT("c[0]={}", to_hex(commitment[0]));
      EC::Point result(commitment[0]);
      // LOG_TRACE_FMT("c={}", result.to_compressed_hex());
      // LOG_TRACE_FMT("result={}", result.to_compressed_hex());
      for (size_t i = 1; i < degree; i++)
      {
        auto t = BigNum::mod_exp(BigNum(j), BigNum(i), group_order);
        // LOG_TRACE_FMT("t={}", t.to_string());
        // LOG_TRACE_FMT("c[i]={}", to_hex(commitment[i]));
        EC::Point c(commitment[i]);
        // LOG_TRACE_FMT("c={}", c.to_compressed_hex());
        result = result.add(c.mul(t));
        // LOG_TRACE_FMT("result={}", result.to_compressed_hex());
      }
      return result;
    }

    class CurveParameters
    {
    public:
      CurveParameters(
        const BigNum& prime,
        const BigNum& b,
        const BigNum& G_x,
        const BigNum& G_y,
        CurveID curve) :
        prime(prime),
        b(b),
        G_x(G_x),
        G_y(G_y)
      {
        if (curve == CurveID::SECP384R1)
        {
          std::vector<std::string> basis_points_strings = {
            // clang-format off
          "03dba858f075dbbb963b791f4188bca1619697bcf5e042499a8eb9b726e381bbe9649a4dbef5ac0f97188a0da88052711e",
          "033953e90a2a1508e2b5328fa49a3fc08cee8a6e9982805c6609eb87963a188050b0cf9c66184f6289e7ede96bcd690c07",
          "025917d93be7e10f27624d54fc4a1ff3d2bc39a63880720d8e04d7dc847cd47569b873604b076ec95e2f2a9cecb227c4aa",
          "03568b906382ef59651f8467c20c6363cfe8020255f3594f37c857f5e630b06ee5b380d24708f19b5f7111e5975fc77c45",
          "02de35c607f96e2aa67448d8adfbf65d2cf5ca141304bece5af5cb1858f0f7aa0c2d8332edbae2408100c1ded076ee7c75",
          "0393b22ab6ba93ead24d09a5ea9f7009c5465a3cd399913b92d44ddd21d53a20ae5673955e907c3590f53478c32b0e738c",
          "03a68f392cbdc24fcc170fb66e20bbaea19e4ae2945fa0443b6845a815b417df674eef61775693776ec92b848ec98a859c",
          "026303eb4c2b07422a2e8f553ec5095dde4da22eb735e2535feb52d4d5a25bd482dbfc08e96ef5980e7d4dc3cad30b385f",
          "0369ba45307acaec23595d1ed1eea86408bcb71d5e3589499474fa4d00ed28d0e11403c7fc042c5a4abba511bba9abb5a1",
          "03985ba2bee0c0c8b4003cd53574356999c7ee02edf90aff9143494474dec9232810b017beacd60aa88215a1e3146e609e",
          "03add81d8a9664ea7bc4702cf85449cd392328d7c315725f4f275b334f7417d1ec5d27b2d62e73777deeaee4a88e1200cb",
          "036a54335a7ff3a6f84609a00d38bbd076272fbadf8233d75a953a4e1f8e5ad097d559e05b378bce135864949a57e1fd00",
          "024fca965946d12265d8b6d097d2d2441bfd807ac7d3726150535811acc0d80720169e1c40ead8d6b3bac22d415532c0bf",
            // clang-format on
          };

          for (auto s : basis_points_strings)
          {
            basis.push_back(
              std::make_shared<EC::Point>(s.substr(2), s.substr(0, 2) != "02"));
          }

          G = EC::Point(G_x, G_y);
        }
        else
        {
          throw std::runtime_error("curve not supported");
        }

        order = EC::group_order(curve);
      }

      CurveParameters() {}

      BigNum prime, b, G_x, G_y, order;
      EC::Point G;
      std::vector<std::shared_ptr<EC::Point>> basis;
    };

    // clang-format off
  static std::map<CurveID, CurveParameters> curve_parameters = {
    { CurveID::SECP384R1, CurveParameters(
      // prime and base point for curve P-384 taken from FIPS 186-4 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
      BigNum("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319"),
      BigNum::from_hex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
      BigNum::from_hex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
      BigNum::from_hex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
      CurveID::SECP384R1)}
    };
  // clang-format on  

  static Point commit_multi(
      size_t start,
      const std::vector<BigNum>& msgs,
      CurveID curve = CurveID::SECP384R1)
    {
      const auto& basis = curve_parameters[curve].basis;
      assert(
        0 <= start and start + msgs.size() < basis.size() and msgs.size() > 0);
      EC::Point r = basis[start]->mul(msgs[0]);
      for (size_t i = 1; i < msgs.size(); i++)
      {
        r = r.add(basis[start + i]->mul(msgs[i]));
      }
      return r;
    }
  }

  static EC::CompressedPoint compressed_commit_multi(
    size_t start,
    const std::vector<BigNum>& msgs,
    EC::CurveID curve = EC::CurveID::SECP384R1)
  {
    return EC::commit_multi(start, msgs, curve).compress();
  }
}
