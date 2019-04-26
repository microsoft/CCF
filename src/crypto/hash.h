// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "../ds/buffer.h"

#include <ostream>

namespace crypto
{
  class Sha256Hash
  {
  public:
    static constexpr size_t SIZE = 256 / 8;
    Sha256Hash();
    Sha256Hash(std::initializer_list<CBuffer> il);

    uint8_t h[SIZE];

    static void mbedtls_sha256(std::initializer_list<CBuffer> il, uint8_t* h);
    static void evercrypt_sha256(std::initializer_list<CBuffer> il, uint8_t* h);
    static void hacl_sha256(std::initializer_list<CBuffer> il, uint8_t* h);

    friend std::ostream& operator<<(
      std::ostream& os, const crypto::Sha256Hash& h)
    {
      for (unsigned i = 0; i < crypto::Sha256Hash::SIZE; i++)
        os << std::hex << static_cast<int>(h.h[i]);

      return os;
    }
  };

  inline bool operator==(const Sha256Hash& lhs, const Sha256Hash& rhs)
  {
    for (unsigned i = 0; i < crypto::Sha256Hash::SIZE; i++)
      if (lhs.h[i] != rhs.h[i])
        return false;
    return true;
  }

  inline bool operator!=(const Sha256Hash& lhs, const Sha256Hash& rhs)
  {
    return !(lhs == rhs);
  }
}
