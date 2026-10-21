// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/crypto/entropy.h"
#include "sharing.h"
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

    void check_status(ccf_shamir_status status)
    {
      switch (status)
      {
        case CCF_SHAMIR_OK:
        {
          return;
        }
        case CCF_SHAMIR_INVALID_ARGUMENTS:
        {
          throw std::invalid_argument("invalid threshold");
        }
        case CCF_SHAMIR_INVALID_COEFFICIENT:
        {
          throw std::invalid_argument("invalid polynomial coefficient");
        }
        case CCF_SHAMIR_DUPLICATE_SHARE:
        {
          throw std::invalid_argument("duplicate input share");
        }
        case CCF_SHAMIR_INVALID_WORKSPACE:
        {
          throw std::logic_error("invalid Shamir workspace");
        }
        case CCF_SHAMIR_OUT_OF_MEMORY:
        {
          throw std::bad_alloc();
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
    CleansedVector<ccf_shamir_share> outputs(shares.size());
    const auto entropy = ccf::crypto::get_entropy();
    for (size_t limb = 0; limb < LIMBS; ++limb)
    {
      for (auto& coefficient : polynomial)
      {
        coefficient = sample(entropy);
      }
      check_status(ccf_shamir_share_limb(
        polynomial.data(), threshold, limb, outputs.data(), outputs.size()));
      raw_secret.y[limb] = polynomial[0];
    }
    raw_secret.x = 0;
    // The shares' coordinates are assigned by the verified core.
    for (size_t s = 0; s < shares.size(); ++s)
    {
      shares[s].x = outputs[s].x;
      std::copy_n(outputs[s].y, LIMBS, shares[s].y);
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
    for (size_t i = 0; i < threshold; ++i)
    {
      inputs[i].x = shares[i].x;
      std::copy_n(shares[i].y, LIMBS, inputs[i].y);
    }
    check_status(ccf_shamir_recover(inputs.data(), threshold, &raw_secret.y));
    raw_secret.x = 0;
  }
}
