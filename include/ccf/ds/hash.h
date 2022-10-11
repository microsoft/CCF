// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/siphash.h"

#include <array>
#include <cstdint>
#include <small_vector/SmallVector.h>
#include <string_view>
#include <vector>

namespace ds::hashutils
{
  template <typename T>
  inline void hash_combine(size_t& n, const T& v, std::hash<T>& h)
  {
    n ^= h(v) + (n << 6) + (n >> 2);
  }

  template <typename T>
  inline size_t hash_container(const T& v)
  {
    size_t n = 0x444e414c544f4353;
    std::hash<typename T::value_type> h{};

    for (const auto& e : v)
    {
      hash_combine(n, e, h);
    }

    return n;
  }
}

namespace std
{
  template <>
  struct hash<std::vector<uint8_t>>
  {
    size_t operator()(const std::vector<uint8_t>& v) const
    {
      // For cryptographically secure hashing, use SipHash directly with a
      // secret key. For std::hash, we use this fixed key
      static constexpr siphash::SipKey k{
        0x7720796f726c694b, 0x2165726568207361};
      return siphash::siphash<2, 4>(v, k);
    }
  };

  template <typename T>
  struct hash<std::vector<T>>
  {
    size_t operator()(const std::vector<T>& v) const
    {
      return ds::hashutils::hash_container(v);
    }
  };

  template <typename T, size_t N>
  struct hash<std::array<T, N>>
  {
    size_t operator()(const std::array<T, N>& v) const
    {
      return ds::hashutils::hash_container(v);
    }
  };

  template <typename A, typename B>
  struct hash<std::pair<A, B>>
  {
    size_t operator()(const std::pair<A, B>& v) const
    {
      size_t n = 0x444e414c544f4353;

      std::hash<A> h_a{};
      ds::hashutils::hash_combine(n, v.first, h_a);

      std::hash<B> h_b{};
      ds::hashutils::hash_combine(n, v.second, h_b);

      return n;
    }
  };

}

namespace ds
{
  /// Simple, fast constexpr hash function (NOT cryptographically sound)
  namespace
  {
    template <typename T>
    struct fnv_parameters
    {};

    template <>
    struct fnv_parameters<uint32_t>
    {
      static constexpr uint32_t offset_basis = 0x811c9dc5;
      static constexpr uint32_t prime = 16777619;
    };

    template <>
    struct fnv_parameters<uint64_t>
    {
      static constexpr uint64_t offset_basis = 0xcbf29ce484222325;
      static constexpr uint64_t prime = 1099511628211;
    };
  }

  template <typename T>
  static constexpr T fnv_1a(const std::string_view& sv)
  {
    using params = fnv_parameters<T>;

    T hash = params::offset_basis;

    for (const auto& c : sv)
    {
      hash ^= c;
      hash *= params::prime;
    }

    return hash;
  }
}
