// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "sharing.h"

#include "ccf/crypto/entropy.h"
#include "sharing_ffi.h"

#include <algorithm>
#include <stdexcept>

namespace ccf::crypto::sharing
{
  static_assert(
    sizeof(ccf_shamir_share::y) == sizeof(Share::y),
    "C ABI share layout must match Share");
  static_assert(
    sizeof(ccf_shamir_share) == Share::serialised_size,
    "C ABI share layout must match Share");

  namespace
  {
    constexpr element prime = (1ULL << 31) - 1;

    template <typename T>
    struct CleansedVector : public std::vector<T>
    {
      explicit CleansedVector(size_t size) : std::vector<T>(size) {}

      ~CleansedVector()
      {
        OPENSSL_cleanse(this->data(), this->size() * sizeof(T));
      }
    };

    void check_status(int32_t status)
    {
      switch (status)
      {
        case 0:
        {
          return;
        }
        case 1:
        {
          throw std::invalid_argument("invalid threshold");
        }
        case 2:
        {
          throw std::invalid_argument("invalid polynomial coefficient");
        }
        case 3:
        {
          throw std::invalid_argument("duplicate input share");
        }
        case 4:
        {
          throw std::logic_error("invalid Shamir workspace");
        }
        default:
        {
          throw std::logic_error("unknown Shamir error");
        }
      }
    }

    element sample(const ccf::crypto::EntropyPtr& entropy)
    {
      element value = prime;
      while (value == prime)
      {
        value = entropy->random64() & prime;
      }
      return value;
    }
  }

  element ct_reduce(element x)
  {
    return ccf_shamir_reduce(x);
  }

  void sample_secret_and_shares(
    Share& raw_secret, const std::span<Share>& shares, size_t threshold)
  {
    if (shares.empty())
    {
      throw std::invalid_argument("insufficient number of shares");
    }
    if (threshold < 1 || threshold > shares.size())
    {
      throw std::invalid_argument("invalid threshold");
    }
    if (shares.size() >= prime)
    {
      throw std::invalid_argument("too many shares for the field");
    }

    CleansedVector<element> polynomial(threshold);
    CleansedVector<uint32_t> values(shares.size());
    const auto entropy = ccf::crypto::get_entropy();
    raw_secret.x = 0;
    for (size_t s = 0; s < shares.size(); ++s)
    {
      shares[s].x = s + 1;
    }
    for (size_t limb = 0; limb < LIMBS; ++limb)
    {
      for (auto& coefficient : polynomial)
      {
        coefficient = sample(entropy);
      }
      check_status(ccf_shamir_evaluate(
        polynomial.data(), threshold, values.data(), shares.size()));
      raw_secret.y[limb] = polynomial[0];
      for (size_t s = 0; s < shares.size(); ++s)
      {
        shares[s].y[limb] = values[s];
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
    if (threshold == 0)
    {
      throw std::invalid_argument("invalid threshold");
    }
    // Share has a cleansing destructor. Copy members rather than reinterpreting
    // its storage as a distinct C ABI type.
    CleansedVector<ccf_shamir_share> inputs(threshold);
    std::vector<element> weights(threshold);
    for (size_t i = 0; i < threshold; ++i)
    {
      inputs[i].x = shares[i].x;
      std::copy_n(shares[i].y, LIMBS, inputs[i].y);
    }
    check_status(ccf_shamir_recover(
      inputs.data(), threshold, weights.data(), raw_secret.y));
    raw_secret.x = 0;
  }
}
