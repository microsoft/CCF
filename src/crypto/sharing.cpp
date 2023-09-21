// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "sharing.h"

#include "ccf/crypto/entropy.h"

#include <stdexcept>

namespace crypto
{
  /* PRIME FIELD

     For simplicity, we use a finite field F[prime] where all operations
     are defined in plain uint64_t arithmetic, and we reduce after every
     operation. This is not meant to be efficient. Compared to e.g. GF(2^n), the
     main drawback is that we need to hash the "raw secret" to obtain a
     uniformly-distributed secret.
  */

  using element = uint64_t;
  constexpr element prime = (1ul << 31) - 1ul; // a notorious Mersenne prime

  static element reduce(uint64_t x)
  {
    return (x % prime);
  }

  static element mul(element x, element y)
  {
    return ((x * y) % prime);
  }

  static element add(element x, element y)
  {
    return ((x + y) % prime);
  }

  static element sub(element x, element y)
  {
    return ((prime + x - y)) % prime;
  }

  // naive algorithm, used only to compute coefficients, not for use on secrets!
  static element exp(element x, size_t n)
  {
    element y = 1;
    while (n > 0)
    {
      if (n & 1)
        y = mul(y, x);
      x = mul(x, x);
      n >>= 1;
    }
    return y;
  }

  static element inv(element x)
  {
    if (x == 0)
    {
      throw std::invalid_argument("division by zero");
    }
    return exp(x, prime - 2);
  }

  // This function is specific to prime=2^31-1.
  // We assume the lower 31 bits are uniformly distributed,
  // and retry if they are all set to get uniformity in F[prime].

  static element sample(const crypto::EntropyPtr& entropy)
  {
    uint64_t res = prime;
    while (res == prime)
    {
      res = entropy->random64() & prime;
    }
    return res;
  }

  /* POLYNOMIAL SHARING AND INTERPOLATION */

  static void sample_polynomial(
    element p[], size_t degree, const crypto::EntropyPtr& entropy)
  {
    for (size_t i = 0; i <= degree; i++)
    {
      p[i] = sample(entropy);
    }
  }

  static element eval(element p[], size_t degree, element x)
  {
    element y = 0, x_i = 1;
    for (size_t i = 0; i <= degree; i++)
    {
      // x_i == x^i
      y = add(y, mul(p[i], x_i));
      x_i = mul(x, x_i);
    }
    return y;
  }

  void sample_secret_and_shares(
    Share& raw_secret, const std::span<Share>& shares, size_t threshold)
  {
    if (shares.size() < 1)
    {
      throw std::invalid_argument("insufficient number of shares");
    }

    if (threshold < 1 || threshold > shares.size())
    {
      throw std::invalid_argument("invalid threshold");
    }

    size_t degree = threshold - 1;

    raw_secret.x = 0;
    for (size_t s = 0; s < shares.size(); s++)
    {
      shares[s].x = s + 1;
    }

    auto entropy = crypto::create_entropy();

    for (size_t limb = 0; limb < LIMBS; limb++)
    {
      element p[degree + 1]; /*SECRET*/
      sample_polynomial(p, degree, entropy);
      raw_secret.y[limb] = p[0];
      for (size_t s = 0; s < shares.size(); s++)
      {
        shares[s].y[limb] = eval(p, degree, shares[s].x);
      }
    }
  }

  void recover_unauthenticated_secret(
    Share& raw_secret, const std::span<Share const>& shares, size_t threshold)
  {
    if (shares.size() < threshold)
    {
      throw std::invalid_argument("insufficient input shares");
    }
    // We systematically reduce the input shares instead of checking they are
    // well-formed.

    size_t degree = threshold - 1;

    // Precomputes Lagrange coefficients for interpolating p(0). No secrets
    // involved.
    element lagrange[degree + 1];
    for (size_t i = 0; i <= degree; i++)
    {
      element numerator = 1, denominator = 1;
      for (size_t j = 0; j <= degree; j++)
      {
        if (i != j)
        {
          numerator = mul(numerator, reduce(shares[j].x));
          denominator =
            mul(denominator, sub(reduce(shares[j].x), reduce(shares[i].x)));
        }
      }
      if (denominator == 0)
      {
        throw std::invalid_argument("duplicate input share");
      }
      lagrange[i] = mul(numerator, inv(denominator));
    }

    // Interpolate every limb of the secret. Constant-time on y values.
    raw_secret.x = 0;
    for (size_t limb = 0; limb < LIMBS; limb++)
    {
      element y = 0;
      for (size_t i = 0; i <= degree; i++)
      {
        y = add(y, mul(lagrange[i], reduce(shares[i].y[limb])));
      }
      raw_secret.y[limb] = y;
    }
  }
}
