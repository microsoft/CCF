// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/curve.h"
#include "crypto/openssl/key_pair.h"

#include <openssl/crypto.h>
#include <string>
#include <vector>

namespace ccf
{
  enum class IdentityType
  {
    REPLICATED,
    SPLIT
  };

  struct NetworkIdentity
  {
    crypto::Pem priv_key;
    crypto::Pem cert;
    std::optional<IdentityType> type;

    bool operator==(const NetworkIdentity& other) const
    {
      return cert == other.cert && priv_key == other.priv_key &&
        type == other.type;
    }

    NetworkIdentity() : type(IdentityType::REPLICATED) {}
    NetworkIdentity(IdentityType type) : type(type) {}

    virtual ~NetworkIdentity() {}
  };

  class ReplicatedNetworkIdentity : public NetworkIdentity
  {
  public:
    ReplicatedNetworkIdentity() : NetworkIdentity(IdentityType::REPLICATED) {}

    ReplicatedNetworkIdentity(
      const std::string& name, crypto::CurveID curve_id) :
      NetworkIdentity(IdentityType::REPLICATED)
    {
      auto identity_key_pair =
        std::make_shared<crypto::KeyPair_OpenSSL>(curve_id);
      cert = identity_key_pair->self_sign(name);
      priv_key = identity_key_pair->private_key_pem();
    }

    ReplicatedNetworkIdentity(const NetworkIdentity& other) :
      NetworkIdentity(IdentityType::REPLICATED)
    {
      if (type != other.type)
      {
        throw std::runtime_error("invalid identity type conversion");
      }
      priv_key = other.priv_key;
      cert = other.cert;
    }

    ~ReplicatedNetworkIdentity() override
    {
      OPENSSL_cleanse(priv_key.data(), priv_key.size());
    }
  };

  class SplitNetworkIdentity : public NetworkIdentity
  {
  public:
    SplitNetworkIdentity() : NetworkIdentity(IdentityType::SPLIT) {}

    SplitNetworkIdentity(const NetworkIdentity& other) :
      NetworkIdentity(IdentityType::SPLIT)
    {
      if (type != other.type)
      {
        throw std::runtime_error("invalid identity type conversion");
      }
      priv_key = {};
      cert = other.cert;
    }
  };
}