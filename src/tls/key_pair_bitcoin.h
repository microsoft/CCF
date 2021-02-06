// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "key_pair_mbedtls.h"

#include <secp256k1/include/secp256k1.h>
#include <secp256k1/include/secp256k1_recovery.h>

namespace tls
{
  static constexpr size_t ecp_num_size = 100;

  inline void parse_secp256k_bc(
    const mbedtls_pk_context& ctx,
    secp256k1_context* bc_ctx,
    secp256k1_pubkey* bc_pub)
  {
    auto k = mbedtls_pk_ec(ctx);
    size_t pub_len;
    uint8_t pub_buf[ecp_num_size];

    int rc = mbedtls_ecp_point_write_binary(
      &k->grp,
      &k->Q,
      MBEDTLS_ECP_PF_COMPRESSED,
      &pub_len,
      pub_buf,
      ecp_num_size);
    if (rc != 0)
    {
      throw std::logic_error(
        "mbedtls_ecp_point_write_binary failed: " + error_string(rc));
    }

    rc = secp256k1_ec_pubkey_parse(bc_ctx, bc_pub, pub_buf, pub_len);
    if (rc != 1)
    {
      throw std::logic_error("secp256k1_ec_pubkey_parse failed");
    }
  }

  struct RecoverableSignature
  {
    // Signature consists of 32 byte R, 32 byte S, and recovery id. Some formats
    // concatenate all 3 into 65 bytes. We stick with libsecp256k1 and separate
    // 64 bytes of (R, S) from recovery_id.
    static constexpr size_t RS_Size = 64;
    std::array<uint8_t, RS_Size> raw;
    int recovery_id;
  };

  class PublicKey_k1Bitcoin : public PublicKey_mbedTLS
  {
  protected:
    BCk1ContextPtr bc_ctx = make_bc_context(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey bc_pub;

  public:
    template <typename... Ts>
    PublicKey_k1Bitcoin(Ts... ts) : PublicKey_mbedTLS(std::forward<Ts>(ts)...)
    {
      parse_secp256k_bc(*ctx, bc_ctx->p, &bc_pub);
    }

    bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType) override
    {
      return verify_secp256k_bc(
        bc_ctx->p, sig, sig_size, hash, hash_size, &bc_pub);
    }

    static PublicKey_k1Bitcoin recover_key(
      const RecoverableSignature& rs, CBuffer hashed)
    {
      int rc;

      size_t buf_len = 65;
      std::array<uint8_t, 65> buf;

      if (hashed.n != 32)
      {
        throw std::logic_error(
          fmt::format("Expected {} bytes in hash, got {}", 32, hashed.n));
      }

      // Recover with libsecp256k1
      {
        auto ctx = make_bc_context(SECP256K1_CONTEXT_VERIFY);

        secp256k1_ecdsa_recoverable_signature sig;
        rc = secp256k1_ecdsa_recoverable_signature_parse_compact(
          ctx->p, &sig, rs.raw.data(), rs.recovery_id);
        if (rc != 1)
        {
          throw std::logic_error(
            "secp256k1_ecdsa_recoverable_signature_parse_compact failed");
        }

        secp256k1_pubkey pubk;
        rc = secp256k1_ecdsa_recover(ctx->p, &pubk, &sig, hashed.p);
        if (rc != 1)
        {
          throw std::logic_error("secp256k1_ecdsa_recover failed");
        }

        rc = secp256k1_ec_pubkey_serialize(
          ctx->p, buf.data(), &buf_len, &pubk, SECP256K1_EC_UNCOMPRESSED);
        if (rc != 1)
        {
          throw std::logic_error("secp256k1_ec_pubkey_serialize failed");
        }
      }

      // Read recovered key into mbedtls context
      {
        auto pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
        if (pk_info == nullptr)
        {
          throw std::logic_error("mbedtls_pk_info_t not found");
        }

        auto ctx = mbedtls::make_unique<mbedtls::PKContext>();

        rc = mbedtls_pk_setup(ctx.get(), pk_info);
        if (rc != 0)
        {
          throw std::logic_error(
            "mbedtls_pk_setup failed with: " + error_string(rc));
        }

        auto kp = mbedtls_pk_ec(*ctx);

        rc = mbedtls_ecp_group_load(&kp->grp, MBEDTLS_ECP_DP_SECP256K1);
        if (rc != 0)
        {
          throw std::logic_error(
            "mbedtls_ecp_group_load failed with: " + error_string(rc));
        }

        rc = mbedtls_ecp_point_read_binary(
          &kp->grp, &kp->Q, buf.data(), buf.size());
        if (rc != 0)
        {
          throw std::logic_error(
            "mbedtls_ecp_point_read_binary failed with: " + error_string(rc));
        }

        rc = mbedtls_ecp_check_pubkey(&kp->grp, &kp->Q);
        if (rc != 0)
        {
          throw std::logic_error(
            "mbedtls_ecp_check_pubkey failed with: " + error_string(rc));
        }

        return PublicKey_k1Bitcoin(std::move(ctx));
      }
    }
  };

  class KeyPair_k1Bitcoin : public KeyPair_mbedTLS
  {
  protected:
    BCk1ContextPtr bc_ctx =
      make_bc_context(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    secp256k1_pubkey bc_pub;

    static constexpr size_t privk_size = 32;
    uint8_t c4_priv[privk_size] = {0};

  public:
    template <typename... Ts>
    KeyPair_k1Bitcoin(Ts... ts) : KeyPair_mbedTLS(std::forward<Ts>(ts)...)
    {
      if (get_curve_id() != CurveID::SECP256K1)
      {
        throw std::logic_error(
          "Bitcoin implementation supports only secp256k1");
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
      size_t signature_size,
      MDType) override
    {
      return verify_secp256k_bc(
        bc_ctx->p, signature, signature_size, hash, hash_size, &bc_pub);
    }

    virtual int sign_hash(
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

    virtual std::vector<uint8_t> sign_hash(
      const uint8_t* hash, size_t hash_size) const override
    {
      uint8_t sig[MBEDTLS_ECDSA_MAX_LEN];
      size_t written = sizeof(sig);

      if (sign_hash(hash, hash_size, &written, sig) != 0)
      {
        return {};
      }

      return {sig, sig + written};
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
}
