// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "tls/entropy.h"
#include "tls/keypair.h"

#include <everest/x25519.h>
#include <iostream>
#include <map>
#include <mbedtls/ecdh.h>

namespace tls
{
  class KeyExchangeContext
  {
  private:
    tls::EntropyPtr entropy;
    mbedtls_ecdh_context ctx;
    std::vector<uint8_t> own_public;

  public:
    // Curve parameters for key exchange
    static constexpr mbedtls_ecp_group_id domain_parameter =
      MBEDTLS_ECP_DP_CURVE25519;

    // Size of DH public, as per mbedtls_x25519_make_public
    static constexpr size_t len_public = MBEDTLS_X25519_KEY_SIZE_BYTES + 1;
    // Size of shared secret, as per mbedtls_x25519_calc_secret
    static constexpr size_t len_shared_secret = MBEDTLS_X25519_KEY_SIZE_BYTES;

    KeyExchangeContext() : own_public(len_public), entropy(create_entropy())
    {
      mbedtls_ecdh_init(&ctx);
      size_t len;

      if (mbedtls_ecdh_setup(&ctx, domain_parameter) != 0)
      {
        throw std::logic_error("Failed to setup context");
      }

      if (
        mbedtls_ecdh_make_public(
          &ctx,
          &len,
          own_public.data(),
          len_public,
          entropy->get_rng(),
          entropy->get_data()) != 0)
      {
        throw std::logic_error("Failed to generate key exchange pair");
      }
    }

    void free_ctx()
    {
      // Should only be called when shared secret has been computed.
      mbedtls_ecdh_free(&ctx);
    }

    ~KeyExchangeContext()
    {
      free_ctx();
    }

    std::vector<uint8_t> get_own_public()
    {
      // Note that this function returns a vector of bytes size
      // MBEDTLS_X25519_KEY_SIZE_BYTES + 1 with the first byte represents the
      // size of the public key
      return own_public;
    }

    void load_peer_public(const uint8_t* bytes, size_t size)
    {
      if (mbedtls_ecdh_read_public(&ctx, bytes, size) != 0)
      {
        throw std::logic_error("Failed to read peer public");
      }
    }

    std::vector<uint8_t> compute_shared_secret()
    {
      // Should only be called once, when peer public has been loaded.
      std::vector<uint8_t> shared_secret(len_shared_secret);
      size_t len;
      if (
        mbedtls_ecdh_calc_secret(
          &ctx,
          &len,
          shared_secret.data(),
          len_shared_secret,
          entropy->get_rng(),
          entropy->get_data()) != 0)
      {
        throw std::logic_error("Failed to compute shared secret");
      }

      return shared_secret;
    }
  };
}
