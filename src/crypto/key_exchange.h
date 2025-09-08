// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/public_key.h"
#include "ds/internal_logger.h.h"

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
    ccf::crypto::KeyPairPtr own_key;
    ccf::crypto::PublicKeyPtr peer_key;
    ccf::crypto::CurveID curve;
    std::vector<uint8_t> shared_secret;

    void compute_shared_secret()
    {
      if (!own_key)
      {
        own_key = make_key_pair(curve);
      }

      if (!peer_key)
      {
        throw std::logic_error(
          "Cannot compute shared secret - missing peer key");
      }

      shared_secret = own_key->derive_shared_secret(*peer_key);
    }

  public:
    KeyExchangeContext() : curve(ccf::crypto::CurveID::SECP384R1) {}

    ~KeyExchangeContext() {}

    std::vector<uint8_t> get_own_key_share()
    {
      if (!own_key)
      {
        own_key = make_key_pair(curve);
        shared_secret.clear();
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
        throw std::runtime_error("Cannot get peer key - missing peer key");
      }

      auto tmp = peer_key->public_key_raw();
      tmp.insert(tmp.begin(), tmp.size());
      return tmp;
    }

    void reset()
    {
      own_key.reset();
      peer_key.reset();
      OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
      shared_secret.clear();
    }

    void load_peer_key_share(std::span<const uint8_t> ks)
    {
      if (ks.size() == 0)
      {
        throw std::runtime_error("Provided peer key share is empty");
      }

      std::vector<uint8_t> tmp(ks.begin(), ks.end());
      tmp.erase(tmp.begin());

      int nid = ccf::crypto::PublicKey_OpenSSL::get_openssl_group_id(curve);
      auto pk = ccf::crypto::key_from_raw_ec_point(tmp, nid);

      if (!pk)
      {
        throw std::runtime_error("Failed to parse peer key share");
      }

      peer_key = std::make_shared<ccf::crypto::PublicKey_OpenSSL>(pk);
      shared_secret.clear();
    }

    const std::vector<uint8_t>& get_shared_secret()
    {
      if (shared_secret.empty())
      {
        compute_shared_secret();
      }

      return shared_secret;
    }
  };
}
