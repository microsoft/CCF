// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/entropy.h"
#include "crypto/key_pair.h"
// #include "crypto/mbedtls/error_string.h"
// #include "crypto/mbedtls/key_pair.h"
#include "ds/logger.h"

#include <iostream>
#include <map>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <openenclave/3rdparty/openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>
#include <stdexcept>

namespace tls
{
  class KeyExchangeContext
  {
  private:
    crypto::KeyPairPtr own_key;
    crypto::PublicKeyPtr peer_key;
    
  public:
    KeyExchangeContext()
    {
      own_key = make_key_pair(crypto::CurveID::SECP384R1);      
    }

    KeyExchangeContext(
      std::shared_ptr<crypto::KeyPair> own_kp,
      std::shared_ptr<crypto::PublicKey> peer_pubk)
    {
      own_key = own_kp;
      peer_key = peer_pubk;
    }

    void free_ctx()
    {
      // Should only be called when shared secret has been computed.
      own_key.reset();
      peer_key.reset();
    }

    ~KeyExchangeContext()
    {
    }

    std::vector<uint8_t> get_own_key_share() const
    {
      if (!own_key)
      {
        throw std::runtime_error("missing node key");
      }
      
      return own_key->public_key_der();
    }

    std::vector<uint8_t> get_peer_key_share() const
    {
      if (!peer_key)
      {
        throw std::runtime_error("missing peer key");
      }

      return peer_key->public_key_der();
    }

    void reset()
    {      
      peer_key.reset();
      own_key = make_key_pair(crypto::CurveID::SECP384R1);      
    }

    void load_peer_key_share(const std::vector<uint8_t>& ks)
    {
      if (ks.size() == 0)
      {
        throw std::runtime_error("Missing peer key share");
      }

      peer_key = crypto::make_public_key(ks);      
    }

    void load_peer_key_share(CBuffer ks)
    {      
      load_peer_key_share({ks.p, ks.p + ks.n});
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
      own_key.reset();
      peer_key.reset();
      return r;
    }
  };
}
