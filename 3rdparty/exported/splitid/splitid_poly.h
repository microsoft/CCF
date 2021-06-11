// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "splitid_bignum.h"
#include "splitid_ec.h"
#include "splitid_util.h"
#include "splitid_zkp.h"

namespace SplitIdentity
{
  class Polynomial
  {
  public:
    Polynomial(size_t degree, EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      group_order = EC::group_order(curve);

      for (size_t i = 0; i < degree + 1; i++)
      {
        coefficients.push_back(BigNum::random(group_order));
      }
    }

    Polynomial(
      const std::vector<BigNum>& coefficients,
      EC::CurveID curve = EC::CurveID::SECP384R1) :
      coefficients(coefficients)
    {
      if (coefficients.empty())
      {
        throw std::logic_error("no coefficients for polynomial");
      }
      group_order = EC::group_order(curve);
    }

    Polynomial(
      const std::vector<std::string>& coefficient_strings,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      group_order = EC::group_order(curve);

      for (size_t i = 0; i < coefficient_strings.size(); i++)
      {
        coefficients.push_back(BigNum(coefficient_strings[i]));
      }
    }

    Polynomial(
      const uint8_t*& buf,
      size_t& sz,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      size_t n = deserialise_size_t(buf, sz);
      for (size_t i = 0; i < n; i++)
      {
        coefficients.push_back(BigNum(buf, sz));
      }
    }

    virtual ~Polynomial(){};

    static BigNum eval(
      const std::vector<BigNum>& coefficients,
      const BigNum& input,
      const BigNum& m)
    {
      BigNum r = BigNum::make_zero();
      for (size_t i = 0; i < coefficients.size(); i++)
      {
        auto t1 = BigNum::mod_exp(input, BigNum(i), m);
        auto t2 = BigNum::mod_mul(coefficients[i], t1, m);
        r = BigNum::mod_add(r, t2, m);
      }
      return r;
    }

    BigNum eval(const BigNum& input, const BigNum& m)
    {
      return eval(coefficients, input, m);
    }

    static std::shared_ptr<Polynomial> sample_rss(
      size_t degree,
      size_t num_zero_coefficients = 0,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      std::vector<BigNum> coefficients;
      auto go = EC::group_order(curve);

      for (size_t i = 0; i < degree + 1; i++)
      {
        coefficients.push_back(BigNum::random(go));
      }

      for (size_t i = 0; i < num_zero_coefficients; i++)
      {
        coefficients.push_back(BigNum::make_zero());
      }

      return std::make_shared<Polynomial>(std::move(coefficients));
    }

    static std::shared_ptr<Polynomial> sample_zss(
      size_t t,
      const BigNum* coeff0 = nullptr,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      assert(t > 0);
      auto r = std::make_shared<Polynomial>(t - 1, curve);
      BigNum c0 = BigNum::make_zero();
      if (coeff0)
        c0 = *coeff0;
      r->coefficients.insert(r->coefficients.begin(), c0);
      return r;
    }

    std::string to_string() const
    {
      return fmt::format("[{}]", fmt::join(coefficients, ", "));
    }

    std::vector<uint8_t> serialise() const
    {
      std::vector<uint8_t> r = serialise_size_t(coefficients.size());
      for (auto& c : coefficients)
      {
        auto b = c.serialise();
        r.insert(r.end(), b.begin(), b.end());
      }

      return r;
    }

    size_t size() const
    {
      return coefficients.size();
    }

    std::vector<BigNum> coefficients;

  protected:
    BigNum group_order;
  };

  class BivariatePolynomial
  {
  public:
    BivariatePolynomial(EC::CurveID curve = EC::CurveID::SECP384R1) :
      curve(curve)
    {}

    BivariatePolynomial(
      const uint8_t*& buf,
      size_t& sz,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      size_t n = deserialise_size_t(buf, sz);
      for (size_t i = 0; i < n; i++)
      {
        std::vector<BigNum> t;
        size_t m = deserialise_size_t(buf, sz);
        for (size_t j = 0; j < m; j++)
        {
          t.push_back(BigNum(buf, sz));
        }
        coefficients.push_back(t);
      }
    }

    virtual ~BivariatePolynomial() {}

    static std::shared_ptr<BivariatePolynomial> sample_rss(
      size_t degree_x,
      size_t degree_y,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      auto r = std::make_shared<BivariatePolynomial>(curve);
      auto go = EC::group_order(curve);

      for (size_t i = 0; i < degree_y + 1; i++)
      {
        std::vector<BigNum> t;
        for (size_t j = 0; j < degree_x + 1; j++)
        {
          t.push_back(BigNum::random(go));
        }
        r->coefficients.push_back(t);
      }

      return r;
    }

    static std::shared_ptr<BivariatePolynomial> sample_zss(
      size_t degree_x,
      size_t degree_y,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      auto r = std::make_shared<BivariatePolynomial>(curve);

      r->coefficients.push_back({});
      for (size_t i = 0; i < degree_x + 1; i++)
      {
        r->coefficients.back().push_back(BigNum::make_zero());
      }

      for (size_t i = 0; i < degree_y; i++)
      {
        r->coefficients.push_back({});
        for (size_t j = 0; j < degree_x + 1; j++)
        {
          auto group_order = EC::group_order(curve);
          r->coefficients.back().push_back(BigNum::random(group_order));
        }
      }

      return r;
    }

    Polynomial y_coefficients(const BigNum& x, const BigNum& m)
    {
      std::vector<BigNum> r;

      for (size_t i = 0; i < coefficients.size(); i++)
      {
        r.push_back(Polynomial::eval(coefficients[i], x, m));
      }

      return Polynomial(r);
    }

    std::string to_string() const
    {
      return fmt::format("[{}]", fmt::join(coefficients, ", "));
    }

    std::vector<uint8_t> serialise() const
    {
      std::vector<uint8_t> r = serialise_size_t(coefficients.size());
      for (auto& cc : coefficients)
      {
        std::vector<uint8_t> rcc = serialise_size_t(cc.size());
        for (auto& c : cc)
        {
          auto b = c.serialise();
          rcc.insert(rcc.end(), b.begin(), b.end());
        }
        r.insert(r.end(), rcc.begin(), rcc.end());
      }
      return r;
    }

    std::vector<std::vector<BigNum>> coefficients;

  protected:
    EC::CurveID curve;
  };

  class SharePolynomials
  {
  public:
    Polynomial q;
    Polynomial q_witness;

    SharePolynomials(const Polynomial& q, const Polynomial& q_witness) :
      q(q),
      q_witness(q_witness)
    {}

    SharePolynomials(const uint8_t*& buf, size_t& sz) :
      q(buf, sz),
      q_witness(buf, sz)
    {}

    std::vector<uint8_t> serialise() const
    {
      std::vector<uint8_t> r = q.serialise();
      std::vector<uint8_t> rw = q_witness.serialise();
      r.insert(r.end(), rw.begin(), rw.end());
      return r;
    }

    std::string to_string() const
    {
      return fmt::format("{}, {}", q, q_witness);
    }
  };
}
