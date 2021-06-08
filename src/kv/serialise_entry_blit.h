// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/nonstd.h"
#include "serialised_entry.h"

namespace kv::serialisers
{
  template <typename T>
  struct BlitSerialiser
  {
    static SerialisedEntry to_serialised(const T& t)
    {
      if constexpr (std::is_same_v<T, std::vector<uint8_t>>)
      {
        return SerialisedEntry(t.begin(), t.end());
      }
      else if constexpr (nonstd::is_std_array<T>::value)
      {
        return SerialisedEntry(t.begin(), t.end());
      }
      else if constexpr (std::is_same_v<
                           T,
                           std::pair<std::string, std::vector<uint8_t>>>)
      {
        const auto& [str, vec] = t;
        uint64_t str_size = str.size();
        auto size = sizeof(str_size) + str_size + vec.size() * sizeof(vec[0]);
        SerialisedEntry s(size);
        auto offset = 0;
        std::memcpy(s.data() + offset, (uint8_t*)&str_size, sizeof(str_size));
        offset += sizeof(str_size);
        std::memcpy(s.data() + offset, str.data(), str_size);
        offset += str_size;
        std::memcpy(s.data() + offset, vec.data(), vec.size());
        return s;
      }
      else if constexpr (std::is_integral_v<T>)
      {
        SerialisedEntry s(sizeof(t));
        std::memcpy(s.data(), (uint8_t*)&t, sizeof(t));
        return s;
      }
      else if constexpr (std::is_same_v<T, std::string>)
      {
        return SerialisedEntry(t.begin(), t.end());
      }
      else
      {
        static_assert(
          nonstd::dependent_false<T>::value, "Can't serialise this type");
      }
    }

    static T from_serialised(const SerialisedEntry& rep)
    {
      if constexpr (std::is_same_v<T, std::vector<uint8_t>>)
      {
        return T(rep.begin(), rep.end());
      }
      else if constexpr (nonstd::is_std_array<T>::value)
      {
        T t;
        if (rep.size() != t.size())
        {
          throw std::logic_error(fmt::format(
            "Wrong serialised size {} for deserialisation of array of size {}",
            rep.size(),
            t.size()));
        }
        std::copy_n(rep.begin(), t.size(), t.begin());
        return t;
      }
      else if constexpr (std::is_same_v<
                           T,
                           std::pair<std::string, std::vector<uint8_t>>>)
      {
        uint64_t str_size;
        if (rep.size() < sizeof(str_size))
        {
          throw std::logic_error(fmt::format(
            "Wrong serialised size {} for deserialisation of pair",
            rep.size()));
        }
        std::memcpy((uint8_t*)&str_size, rep.data(), sizeof(str_size));
        if (str_size > rep.size() - sizeof(str_size))
        {
          throw std::logic_error(fmt::format(
            "Wrong serialised size {} for deserialisation of pair",
            rep.size()));
        }
        auto str_begin = rep.begin() + sizeof(str_size);
        auto str_end = str_begin + str_size;
        std::string str{str_begin, str_end};
        std::vector<uint8_t> vec{str_end, rep.end()};
        return {str, vec};
      }
      else if constexpr (std::is_integral_v<T>)
      {
        if (rep.size() != sizeof(T))
        {
          throw std::logic_error(fmt::format(
            "Wrong serialised size {} for deserialisation of integral of size "
            "{}",
            rep.size(),
            sizeof(T)));
        }
        return *(T*)rep.data();
      }
      else if constexpr (std::is_same_v<T, std::string>)
      {
        return T(rep.begin(), rep.end());
      }
      else
      {
        static_assert(
          nonstd::dependent_false<T>::value, "Can't deserialise this type");
      }
    }
  };
}