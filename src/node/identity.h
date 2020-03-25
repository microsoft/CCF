// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls/key_pair.h"

#include <string>
#include <vector>

namespace ccf
{
  struct NetworkIdentity
  {
    std::vector<uint8_t> cert;
    std::vector<uint8_t> priv_key;

    bool operator==(const NetworkIdentity& other) const
    {
      return cert == other.cert && priv_key == other.priv_key;
    }

    NetworkIdentity() {}

    NetworkIdentity(const std::string& name)
    {
      auto identity_key_pair = tls::make_key_pair();
      cert = identity_key_pair->self_sign(name);
      auto privk_pem = identity_key_pair->private_key_pem();
      priv_key = std::vector<uint8_t>(
        privk_pem.data(), privk_pem.data() + privk_pem.size());
    }
  };
}