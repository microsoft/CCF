#pragma once

#include "serialized.h"
#include "ccf_assert.h"

/*
  template <class T>
  struct default_size
  {
    uint32_t operator()(T type) const
    {
      return sizeof(type) + sizeof(uint64_t);
    }
  };
  */


namespace champ
{
  template <class T>
  size_t get_size(const T& data)
  {
    return sizeof(uint64_t) * 2;
    }

/*
  template <>
  size_t get_size<uint64_t>(const uint64_t& data)
  {
    return sizeof(uint64_t) * 2;
  }
*/
}