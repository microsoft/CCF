// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/curve.h"
#include "crypto/openssl/key_pair.h"

#include <string>
#include <vector>

namespace ccf
{
  struct Identity
  {
    enum class IdentityType
    {
      NORMAL,
      BYZANTINE
    };

    IdentityType type = IdentityType::NORMAL;
    crypto::Pem cert;
  };

  struct NetworkIdentity : public Identity
  {
    crypto::Pem priv_key;

    bool operator==(const NetworkIdentity& other) const
    {
      return cert == other.cert && priv_key == other.priv_key;
    }

    NetworkIdentity() = default;

    NetworkIdentity(const std::string& name, crypto::CurveID curve_id)
    {
      auto identity_key_pair =
        std::make_shared<crypto::KeyPair_OpenSSL>(curve_id);
      cert = identity_key_pair->self_sign(name);
      priv_key = identity_key_pair->private_key_pem();
    }
  };
}