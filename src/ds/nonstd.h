// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <string>

namespace ccf::nonstd
{
  // Iterators for map-keys and map-values
  template <typename TMapIterator>
  class KeyIterator : public TMapIterator
  {
  public:
    KeyIterator() : TMapIterator() {}
    KeyIterator(TMapIterator it) : TMapIterator(it) {}

    using Key =
      typename std::iterator_traits<TMapIterator>::value_type::first_type;
    using value_type = Key;

    Key* operator->()
    {
      return TMapIterator::operator->()->first;
    }

    // NOLINTNEXTLINE(readability-const-return-type)
    Key operator*()
    {
      return TMapIterator::operator*().first;
    }
  };

  template <typename TMapIterator>
  class ValueIterator : public TMapIterator
  {
  public:
    ValueIterator() : TMapIterator() {}
    ValueIterator(TMapIterator it) : TMapIterator(it) {}

    using Value =
      typename std::iterator_traits<TMapIterator>::value_type::second_type;
    using value_type = Value;

    Value* operator->()
    {
      return TMapIterator::operator->()->second;
    }

    Value operator*()
    {
      return TMapIterator::operator*().second;
    }
  };
}
