// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/entropy.h"
#include "crypto/key_pair.h"
#include "crypto/mbedtls/key_pair.h"
#include "ds/logger.h"
#include "tls/error_string.h"

#include <iostream>
#include <map>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <stdexcept>

namespace tls
{
  class KeyExchangeContext
  {
  private:
    crypto::mbedtls::ECDHContext ctx = nullptr;
    std::vector<uint8_t> key_share;
    std::vector<uint8_t> peer_key_share;

    void create_fresh_key_share()
    {
      auto tmp_ctx =
        crypto::mbedtls::make_unique<crypto::mbedtls::ECDHContext>();
      size_t len = 0;

      int rc = mbedtls_ecp_group_load(&tmp_ctx->grp, domain_parameter);

      if (rc != 0)
      {
        throw std::logic_error(error_string(rc));
      }

      crypto::EntropyPtr entropy = crypto::create_entropy();

      key_share.resize(len_public);

      rc = mbedtls_ecdh_make_public(
        tmp_ctx.get(),
        &len,
        key_share.data(),
        key_share.size(),
        entropy->get_rng(),
        entropy->get_data());

      if (rc != 0)
      {
        throw std::logic_error(error_string(rc));
      }

      key_share.resize(len);

      ctx = std::move(tmp_ctx);
    }

  public:
    static constexpr mbedtls_ecp_group_id domain_parameter =
      MBEDTLS_ECP_DP_SECP384R1;

    static constexpr size_t len_public = 1024 + 1;
    static constexpr size_t len_shared_secret = 1024;

    KeyExchangeContext() : key_share(len_public)
    {
      create_fresh_key_share();
    }

    KeyExchangeContext(
      std::shared_ptr<crypto::KeyPair_mbedTLS> own_kp,
      std::shared_ptr<crypto::PublicKey_mbedTLS> peer_pubk)
    {
      auto tmp_ctx =
        crypto::mbedtls::make_unique<crypto::mbedtls::ECDHContext>();

      int rc = mbedtls_ecdh_get_params(
        tmp_ctx.get(),
        mbedtls_pk_ec(*own_kp->get_raw_context()),
        MBEDTLS_ECDH_OURS);
      if (rc != 0)
      {
        throw std::logic_error(error_string(rc));
      }

      rc = mbedtls_ecdh_get_params(
        tmp_ctx.get(),
        mbedtls_pk_ec(*peer_pubk->get_raw_context()),
        MBEDTLS_ECDH_THEIRS);
      if (rc != 0)
      {
        throw std::logic_error(error_string(rc));
      }
      ctx = std::move(tmp_ctx);
    }

    void free_ctx()
    {
      // Should only be called when shared secret has been computed.
      ctx.reset();
    }

    ~KeyExchangeContext()
    {
      free_ctx();
    }

    const std::vector<uint8_t>& get_own_key_share()
    {
      if (!ctx)
      {
        throw std::runtime_error("Missing key exchange context");
      }

      if (key_share.empty())
      {
        throw std::runtime_error("Missing node key share");
      }

      // Note that this function returns a vector of bytes
      // where the first byte represents the
      // size of the public key
      return key_share;
    }

    const std::vector<uint8_t>& get_peer_key_share()
    {
      return peer_key_share;
    }

    void reset()
    {
      key_share.clear();
      peer_key_share.clear();
      ctx.reset();
      create_fresh_key_share();
    }

    void load_peer_key_share(const std::vector<uint8_t>& ks)
    {
      load_peer_key_share({ks.data(), ks.size()});
    }

    void load_peer_key_share(CBuffer ks)
    {
      if (!ctx)
      {
        throw std::runtime_error(
          "Missing key exchange context when loading peer key share");
      }

      if (ks.n == 0)
      {
        throw std::runtime_error("Missing peer key share");
      }

      int rc = mbedtls_ecdh_read_public(ctx.get(), ks.p, ks.n);
      if (rc != 0)
      {
        throw std::logic_error(error_string(rc));
      }

      peer_key_share = {ks.p, ks.p + ks.n};
    }

    std::vector<uint8_t> compute_shared_secret()
    {
      crypto::EntropyPtr entropy = crypto::create_entropy();

      // Should only be called once, when peer public has been loaded.
      std::vector<uint8_t> shared_secret(len_shared_secret);
      size_t len;
      int rc = mbedtls_ecdh_calc_secret(
        ctx.get(),
        &len,
        shared_secret.data(),
        shared_secret.size(),
        entropy->get_rng(),
        entropy->get_data());
      if (rc != 0)
      {
        throw std::logic_error(error_string(rc));
      }

      shared_secret.resize(len);

      return shared_secret;
    }
  };
}
