// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/key_pair.h"
#include "ccf/ds/logger.h"
#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/public_key.h"

#include <iostream>
#include <map>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include <stdexcept>

namespace tls
{
  class KeyExchangeContext
  {
  private:
    crypto::KeyPairPtr own_key;
    crypto::PublicKeyPtr peer_key;
    crypto::CurveID curve;

  public:
    KeyExchangeContext() : curve(crypto::CurveID::SECP384R1)
    {
      own_key = make_key_pair(curve);
    }

    KeyExchangeContext(
      std::shared_ptr<crypto::KeyPair> own_kp,
      std::shared_ptr<crypto::PublicKey> peer_pubk) :
      curve(own_kp->get_curve_id())
    {
      own_key = own_kp;
      peer_key = peer_pubk;
    }

    ~KeyExchangeContext() {}

    std::vector<uint8_t> get_own_key_share() const
    {
      if (!own_key)
      {
        throw std::runtime_error("missing node key");
      }

      // For backwards compatibility we need to keep the format we used with
      // mbedTLS, which is the raw EC point with an extra size byte in the
      // front.
      auto tmp = own_key->public_key_raw();
      tmp.insert(tmp.begin(), tmp.size());
      return tmp;
    }

    std::vector<uint8_t> get_peer_key_share() const
    {
      if (!peer_key)
      {
        throw std::runtime_error("missing peer key");
      }

      auto tmp = peer_key->public_key_raw();
      tmp.insert(tmp.begin(), tmp.size());
      return tmp;
    }

    void reset()
    {
      peer_key.reset();
      own_key = make_key_pair(crypto::CurveID::SECP384R1);
    }

    void load_peer_key_share(std::span<const uint8_t> ks)
    {
      if (ks.size() == 0)
      {
        throw std::runtime_error("missing peer key share");
      }

      std::vector<uint8_t> tmp(ks.begin(), ks.end());
      tmp.erase(tmp.begin());

      int nid = crypto::PublicKey_OpenSSL::get_openssl_group_id(curve);
      auto pk = crypto::key_from_raw_ec_point(tmp, nid);

      if (!pk)
      {
        throw std::runtime_error("could not parse peer key share");
      }

      peer_key = std::make_shared<crypto::PublicKey_OpenSSL>(pk);
    }

    std::vector<uint8_t> compute_shared_secret()
    {
      if (!own_key)
      {
        throw std::logic_error("missing own key");
      }

      if (!peer_key)
      {
        throw std::logic_error("missing peer key");
      }

      auto r = own_key->derive_shared_secret(*peer_key);
      // own_key.reset(); // TODO: Wants to only do this once...
      // peer_key.reset();
      return r;
    }
  };
}
