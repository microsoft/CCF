// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
#include "ccf/kv/serialisers/serialised_entry.h"

namespace ccf::kv::serialisers
{
  // Converts values to their raw, in-memory representation. To add support for
  // custom types, add a specialization of BlitSerialiser for them.
  template <typename T>
  struct BlitSerialiser
  {
    static SerialisedEntry to_serialised(const T& t)
    {
      if constexpr (std::is_same_v<T, std::vector<uint8_t>>)
      {
        return SerialisedEntry(t.begin(), t.end());
      }
      else if constexpr (ccf::nonstd::is_std_array<T>::value)
      {
        return SerialisedEntry(t.begin(), t.end());
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
          ccf::nonstd::dependent_false<T>::value, "Can't serialise this type");
      }
    }

    static T from_serialised(const SerialisedEntry& rep)
    {
      if constexpr (std::is_same_v<T, std::vector<uint8_t>>)
      {
        return T(rep.begin(), rep.end());
      }
      else if constexpr (ccf::nonstd::is_std_array<T>::value)
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
          ccf::nonstd::dependent_false<T>::value,
          "Can't deserialise this type");
      }
    }
  };
}