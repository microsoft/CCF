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
    tls::Pem cert;
    tls::Pem priv_key;

    bool operator==(const NetworkIdentity& other) const
    {
      return cert == other.cert && priv_key == other.priv_key;
    }

    NetworkIdentity() = default;

    NetworkIdentity(const std::string& name)
    {
      auto identity_key_pair = tls::make_key_pair();
      cert = identity_key_pair->self_sign(name);
      priv_key = identity_key_pair->private_key_pem();
    }
  };
}