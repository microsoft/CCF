// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "key_pair.h"

namespace tls
{
  class ECKeyPair : public KeyPair
  {
  public:
    /**
     * Create a new public / private ECDSA key pair
     */
    ECKeyPair(mbedtls_ecp_group_id ec)
    {
      EntropyPtr entropy = create_entropy();
      mbedtls_pk_init(ctx.get());

      int rc = mbedtls_pk_setup(
        ctx.get(), mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
      if (rc != 0)
      {
        throw std::logic_error(
          "Could not set up ECDSA context: " + error_string(rc));
      }

      rc = mbedtls_ecp_gen_key(
        ec, mbedtls_pk_ec(*ctx), entropy->get_rng(), entropy->get_data());
      if (rc != 0)
      {
        throw std::logic_error(
          "Could not generate ECDSA keypair: " + error_string(rc));
      }

      const auto actual_ec = get_ec_from_context(*ctx);
      if (actual_ec != ec)
      {
        throw std::logic_error(
          "Created key and received unexpected type: " +
          std::to_string(actual_ec) + " != " + error_string(ec));
      }
    }

    ECKeyPair(std::unique_ptr<mbedtls_pk_context>&& k) : KeyPair(std::move(k))
    {}

    ECKeyPair(const ECKeyPair&) = delete;
  };

  class ECKeyPair_k1Bitcoin : public ECKeyPair
  {
  protected:
    BCk1ContextPtr bc_ctx =
      make_bc_context(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    secp256k1_pubkey bc_pub;

    static constexpr size_t privk_size = 32;
    uint8_t c4_priv[privk_size] = {0};

  public:
    template <typename... Ts>
    ECKeyPair_k1Bitcoin(Ts... ts) : ECKeyPair(std::forward<Ts>(ts)...)
    {
      const auto ec = get_ec_from_context(*ctx);
      if (ec != MBEDTLS_ECP_DP_SECP256K1)
      {
        throw std::logic_error(
          "Bitcoin implementation cannot extend curve on " +
          std::to_string(ec));
      }

      int rc = 0;

      rc = mbedtls_mpi_write_binary(
        &(mbedtls_pk_ec(*ctx)->d), c4_priv, privk_size);
      if (rc != 0)
      {
        throw std::logic_error(
          "Could not extract raw private key: " + error_string(rc));
      }

      if (secp256k1_ec_seckey_verify(bc_ctx->p, c4_priv) != 1)
      {
        throw std::logic_error("secp256k1 private key is not valid");
      }

      parse_secp256k_bc(*ctx, bc_ctx->p, &bc_pub);
    }

    // Since this inherits from PublicKey (via Keypair), rather than
    // PublicKey_k1Bitcoin, we re-override verify_hash here
    bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* signature,
      size_t signature_size) override
    {
      bool ok = verify_secp256k_bc(
        bc_ctx->p, signature, signature_size, hash, hash_size, &bc_pub);

      return ok;
    }

    int sign_hash(
      const uint8_t* hash,
      size_t hash_size,
      size_t* sig_size,
      uint8_t* sig) const override
    {
      if (hash_size != 32)
        return -1;

      secp256k1_ecdsa_signature k1_sig;
      if (
        secp256k1_ecdsa_sign(
          bc_ctx->p, &k1_sig, hash, c4_priv, nullptr, nullptr) != 1)
        return -2;

      if (
        secp256k1_ecdsa_signature_serialize_der(
          bc_ctx->p, sig, sig_size, &k1_sig) != 1)
        return -3;

      return 0;
    }

    RecoverableSignature sign_recoverable_hashed(CBuffer hashed)
    {
      int rc;

      if (hashed.n != 32)
      {
        throw std::logic_error(
          fmt::format("Expected {} bytes in hash, got {}", 32, hashed.n));
      }

      secp256k1_ecdsa_recoverable_signature sig;
      rc = secp256k1_ecdsa_sign_recoverable(
        bc_ctx->p, &sig, hashed.p, c4_priv, nullptr, nullptr);
      if (rc != 1)
      {
        throw std::logic_error("secp256k1_ecdsa_sign_recoverable failed");
      }

      RecoverableSignature ret;
      rc = secp256k1_ecdsa_recoverable_signature_serialize_compact(
        bc_ctx->p, ret.raw.data(), &ret.recovery_id, &sig);
      if (rc != 1)
      {
        throw std::logic_error(
          "secp256k1_ecdsa_recoverable_signature_serialize_compact failed");
      }

      return ret;
    }
  };

  using KeyPairPtr = std::shared_ptr<KeyPair>;

  /**
   * Create a new public / private key pair on specified curve and
   * implementation
   */
  inline KeyPairPtr make_ec_key_pair(
    CurveImpl curve = CurveImpl::service_identity_curve_choice)
  {
    const auto ec = get_ec_for_curve_impl(curve);
    if (curve == CurveImpl::secp256k1_bitcoin)
    {
      return KeyPairPtr(new ECKeyPair_k1Bitcoin(ec));
    }
    else
    {
      return KeyPairPtr(new ECKeyPair(ec));
    }
  }

  inline std::unique_ptr<mbedtls_pk_context> parse_private_key(
    const Pem& pkey, CBuffer pw = nullb)
  {
    std::unique_ptr<mbedtls_pk_context> key =
      std::make_unique<mbedtls_pk_context>();
    mbedtls_pk_init(key.get());

    // keylen is +1 to include terminating null byte
    int rc =
      mbedtls_pk_parse_key(key.get(), pkey.data(), pkey.size(), pw.p, pw.n);
    if (rc != 0)
    {
      throw std::logic_error("Could not parse key: " + error_string(rc));
    }

    return key;
  }

  /**
   * Create a public / private from existing private key data
   */
  inline KeyPairPtr make_ec_key_pair(
    const Pem& pkey,
    CBuffer pw = nullb,
    bool use_bitcoin_impl = prefer_bitcoin_secp256k1)
  {
    auto key = parse_private_key(pkey, pw);

    const auto curve = get_ec_from_context(*key);

    if (curve == MBEDTLS_ECP_DP_SECP256K1 && use_bitcoin_impl)
    {
      return std::make_shared<ECKeyPair_k1Bitcoin>(std::move(key));
    }
    else
    {
      return std::make_shared<ECKeyPair>(std::move(key));
    }
  }
}