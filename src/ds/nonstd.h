// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <string>

namespace ccf::nonstd
{
  // Iterator for map keys
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

}
