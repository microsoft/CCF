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
        auto size = sizeof(size_t) + str.size() + sizeof(size_t) + vec.size();
        SerialisedEntry s(size);
        auto data = s.data();
        serialized::write(data, size, str);
        serialized::write(data, size, vec.size());
        serialized::write(data, size, vec.data(), vec.size());
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
        auto data = rep.data();
        auto size = rep.size();
        auto str = serialized::read<std::string>(data, size);
        auto vec_size = serialized::read<size_t>(data, size);
        auto vec = serialized::read(data, size, vec_size);
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