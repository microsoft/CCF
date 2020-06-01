// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "serialised_entry.h"

namespace kv::serialisers
{
  template <typename T>
  struct dependent_false : public std::false_type
  {};

  template <typename T>
  struct BlitSerialiser
  {
    static SerialisedEntry to_serialised(const T& t)
    {
      if constexpr (std::is_same_v<T, std::vector<uint8_t>>)
      {
        return t;
      }
      else if constexpr (std::is_integral_v<T>)
      {
        SerialisedEntry s(sizeof(t));
        std::memcpy(s.data(), (uint8_t*)&t, sizeof(t));
        return s;
      }
      else
      {
        static_assert(dependent_false<T>::value, "Can't serialise this type");
      }
    }

    static T from_serialised(const SerialisedEntry& rep)
    {
      if constexpr (std::is_same_v<T, std::vector<uint8_t>>)
      {
        return rep;
      }
      else if constexpr (std::is_integral_v<T>)
      {
        if (rep.size() != sizeof(T))
        {
          throw std::logic_error("Wrong size for deserialising");
        }
        return *(T*)rep.data();
      }
      else
      {
        static_assert(dependent_false<T>::value, "Can't deserialise this type");
      }
    }
  };
}