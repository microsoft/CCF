// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/cryptobox.h"
#include "tls/25519.h"
#include "tls/entropy.h"

namespace ccf
{
  struct NetworkEncryptionKey
  {
  private:
    static constexpr auto KEY_SIZE = crypto::BoxKey::KEY_SIZE;

  public:
    std::vector<uint8_t> private_raw;

    bool operator==(const NetworkEncryptionKey& other) const
    {
      return private_raw == other.private_raw;
    }

    NetworkEncryptionKey(bool random = false)
    {
      if (random)
      {
        private_raw = tls::create_entropy()->random(crypto::BoxKey::KEY_SIZE);
      }
    }

    std::vector<uint8_t> get_public_pem()
    {
      return tls::PublicX25519::write(
               crypto::BoxKey::public_from_private(private_raw))
        .raw();
    }
  };
}