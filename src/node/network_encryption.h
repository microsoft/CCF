// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls/25519.h"
#include "tls/entropy.h"

namespace ccf
{
  struct NetworkEncryptionKey
  {
    std::vector<uint8_t> private_raw;

    bool operator==(const NetworkEncryptionKey& other) const
    {
      return private_raw == other.private_raw;
    }

    NetworkEncryptionKey() = default;

    NetworkEncryptionKey(std::vector<uint8_t>&& private_key_raw) :
      private_raw(std::move(private_key_raw))
    {}
  };
}