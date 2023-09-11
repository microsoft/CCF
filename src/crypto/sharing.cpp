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

  typedef uint64_t element;

  const uint64_t prime = (1ul << 31) - 1ul; // a notorious Mersenne prime

  element reduce(uint64_t x)
  {
    return (x % prime);
  }
  element mul(element x, element y)
  {
    return ((x * y) % prime);
  }
  element add(element x, element y)
  {
    return ((x + y) % prime);
  }
  element sub(element x, element y)
  {
    return ((prime + x - y)) % prime;
  }

  // naive algorithm, used only to compute coefficients, not for use on secrets!
  element exp(element x, size_t n)
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

  element inv(element x)
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

  element sample()
  {
    uint64_t res = prime;
    while (res == prime)
    {
      res = crypto::create_entropy()->random64() & prime;
    }
    return res;
  }

  /* POLYNOMIAL SHARING AND INTERPOLATION */

  void sample_polynomial(element p[], size_t degree)
  {
    for (size_t i = 0; i <= degree; i++)
      p[i] = sample();
  }

  element eval(element p[], size_t degree, element x)
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
    Share& raw_secret, Share output[], size_t degree, size_t share_number)
  {
    raw_secret.x = 0;
    for (size_t s = 0; s < share_number; s++)
      output[s].x = s + 1;

    for (size_t limb = 0; limb < LIMBS; limb++)
    {
      element p[degree + 1]; /*SECRET*/
      sample_polynomial(p, degree);
      raw_secret.y[limb] = p[0];
      for (size_t s = 0; s < share_number; s++)
      {
        output[s].y[limb] = eval(p, degree, output[s].x);
      }
    }
  }

  int recover_secret(Share& raw_secret, const Share input[], size_t degree)
  {
    // We systematically reduce the input shares instead of checking they are
    // well-formed.

    // Precomputes Lagrange coefficients for interpolating p(0). No secrets
    // involved.
    element lagrange[degree + 1];
    for (size_t i = 0; i <= degree; i++)
    {
      element numerator = 1, denominator = 1;
      for (size_t j = 0; j <= degree; j++)
        if (i != j)
        {
          numerator = mul(numerator, reduce(input[j].x));
          denominator =
            mul(denominator, sub(reduce(input[j].x), reduce(input[i].x)));
        }
      if (denominator == 0)
        // Error: duplicate input share
        return (-1);
      lagrange[i] = mul(numerator, inv(denominator));
    }

    // Interpolate every limb of the secret. Constant-time on y values.
    raw_secret.x = 0;
    for (size_t limb = 0; limb < LIMBS; limb++)
    {
      element y = 0;
      for (size_t i = 0; i <= degree; i++)
        y = add(y, mul(lagrange[i], reduce(input[i].y[limb])));
      raw_secret.y[limb] = y;
    }
    return 0;
  }

}
