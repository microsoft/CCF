// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/siphash.h"

#include <small_vector/SmallVector.h>

namespace ccf
{
  using ByteVector = llvm_vecsmall::SmallVector<uint8_t, 8>;
}

namespace std
{
  template <typename T, unsigned N>
  struct hash<llvm_vecsmall::SmallVector<T, N>>
  {
    size_t operator()(const llvm_vecsmall::SmallVector<T, N>& v) const
    {
      static constexpr siphash::SipKey k{
        0x7720796f726c694b, 0x2165726568207361};
      return siphash::siphash<2, 4>(v.data(), v.size(), k);
    }
  };
}
