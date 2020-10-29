// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "asn1_san.h"
#include "csr.h"
#include "curve.h"
#include "entropy.h"
#include "error_string.h"
#include "hash.h"
#include "pem.h"
#include "san.h"

#include <cstring>
#include <iomanip>
#include <limits>
#include <mbedtls/bignum.h>
#include <mbedtls/pem.h>
#include <memory>

namespace tls
{
  static constexpr size_t ecp_num_size = 100;
  static constexpr size_t max_pem_key_size = 2048;

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

  class PublicKey
  {
  protected:
    std::unique_ptr<mbedtls_pk_context> ctx =
      std::make_unique<mbedtls_pk_context>();

    PublicKey() {}

  public:
    /**
     * Construct from a pre-initialised pk context
     */
    PublicKey(std::unique_ptr<mbedtls_pk_context>&& c) : ctx(std::move(c)) {}

    virtual ~PublicKey()
    {
      if (ctx)
      {
        mbedtls_pk_free(ctx.get());
      }
    }

    /**
     * Verify that a signature was produced on contents with the private key
     * associated with the public key held by the object.
     *
     * @param contents Sequence of bytes that was signed
     * @param signature Signature as a sequence of bytes
     *
     * @return Whether the signature matches the contents and the key
     */
    bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature)
    {
      return verify(
        contents.data(), contents.size(), signature.data(), signature.size());
    }

    /**
     * Verify that a signature was produced on contents with the private key
     * associated with the public key held by the object.
     *
     * @param contents address of contents
     * @param contents_size size of contents
     * @param sig address of signature
     * @param sig_size size of signature
     * @param md_type Digest algorithm to use. Derived from the
     * public key if MBEDTLS_MD_NONE.
     *
     * @return Whether the signature matches the contents and the key
     */
    bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size,
      mbedtls_md_type_t md_type = MBEDTLS_MD_NONE)
    {
      HashBytes hash;
      do_hash(*ctx, contents, contents_size, hash, md_type);

      return verify_hash(hash.data(), hash.size(), sig, sig_size);
    }

    /**
     * Verify that a signature was produced on a hash with the private key
     * associated with the public key held by the object.
     *
     * @param hash Hash produced from contents as a sequence of bytes
     * @param signature Signature as a sequence of bytes
     *
     * @return Whether the signature matches the hash and the key
     */
    bool verify_hash(
      const std::vector<uint8_t>& hash, const std::vector<uint8_t>& signature)
    {
      return verify_hash(
        hash.data(), hash.size(), signature.data(), signature.size());
    }

    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size)
    {
      const auto md_type = get_md_for_ec(get_ec_from_context(*ctx));

      int rc =
        mbedtls_pk_verify(ctx.get(), md_type, hash, hash_size, sig, sig_size);

      if (rc)
        LOG_DEBUG_FMT("Failed to verify signature: {}", error_string(rc));

      return rc == 0;
    }

    /**
     * Get the public key in PEM format
     */
    Pem public_key_pem()
    {
      uint8_t data[max_pem_key_size];

      int rc = mbedtls_pk_write_pubkey_pem(ctx.get(), data, max_pem_key_size);
      if (rc != 0)
      {
        throw std::logic_error(
          "mbedtls_pk_write_pubkey_pem: " + error_string(rc));
      }

      const size_t len = strlen((char const*)data);
      return Pem(data, len);
    }

    mbedtls_pk_context* get_raw_context() const
    {
      return ctx.get();
    }
  };

  class PublicKey_k1Bitcoin : public PublicKey
  {
  protected:
    BCk1ContextPtr bc_ctx = make_bc_context(SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey bc_pub;

  public:
    template <typename... Ts>
    PublicKey_k1Bitcoin(Ts... ts) : PublicKey(std::forward<Ts>(ts)...)
    {
      parse_secp256k_bc(*ctx, bc_ctx->p, &bc_pub);
    }

    bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size) override
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

        auto ctx = std::make_unique<mbedtls_pk_context>();
        mbedtls_pk_init(ctx.get());

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

  class RSAPublicKey : public PublicKey
  {
  protected:
    // Compatible with Azure HSM encryption schemes (see
    // https://docs.microsoft.com/en-gb/azure/key-vault/keys/about-keys#wrapkeyunwrapkey-encryptdecrypt)
    static constexpr auto rsa_padding_mode = MBEDTLS_RSA_PKCS_V21;
    static constexpr auto rsa_padding_digest_id = MBEDTLS_MD_SHA256;

  public:
    RSAPublicKey() = default;

    RSAPublicKey(std::unique_ptr<mbedtls_pk_context>&& c) :
      PublicKey(std::move(c))
    {}

    std::vector<uint8_t> wrap(
      const std::vector<uint8_t>& input,
      std::optional<std::string> label = std::nullopt)
    {
      mbedtls_rsa_context* rsa_ctx = mbedtls_pk_rsa(*ctx.get());
      mbedtls_rsa_set_padding(rsa_ctx, rsa_padding_mode, rsa_padding_digest_id);

      std::vector<uint8_t> output_buf(rsa_ctx->len);
      auto entropy = tls::create_entropy();

      const unsigned char* label_ = NULL;
      size_t label_size = 0;
      if (label.has_value())
      {
        label_ = reinterpret_cast<const unsigned char*>(label->c_str());
        label_size = label->size();
      }

      auto rc = mbedtls_rsa_rsaes_oaep_encrypt(
        rsa_ctx,
        entropy->get_rng(),
        entropy->get_data(),
        MBEDTLS_RSA_PUBLIC,
        label_,
        label_size,
        input.size(),
        input.data(),
        output_buf.data());
      if (rc != 0)
      {
        throw std::logic_error(
          fmt::format("Error during RSA OEAP wrap: {}", error_string(rc)));
      }

      return output_buf;
    }
  };

  using PublicKeyPtr = std::shared_ptr<PublicKey>;
  using RSAPublicKeyPtr = std::shared_ptr<RSAPublicKey>;

  /**
   * Construct PublicKey from a raw public key in PEM format
   *
   * @param public_pem Sequence of bytes containing the key in PEM format
   * @param use_bitcoin_impl If true, and the key is on secp256k1, then the
   * bitcoin secp256k1 library will be used as the implementation rather than
   * mbedtls
   */
  inline PublicKeyPtr make_public_key(
    const Pem& public_pem, bool use_bitcoin_impl = prefer_bitcoin_secp256k1)
  {
    auto ctx = std::make_unique<mbedtls_pk_context>();
    mbedtls_pk_init(ctx.get());

    int rc = mbedtls_pk_parse_public_key(
      ctx.get(), public_pem.data(), public_pem.size());

    if (rc != 0)
    {
      throw std::logic_error(fmt::format(
        "Could not parse public key PEM: {}\n\n(Key: {})",
        error_string(rc),
        public_pem.str()));
    }

    const auto curve = get_ec_from_context(*ctx);

    if (curve == MBEDTLS_ECP_DP_SECP256K1 && use_bitcoin_impl)
    {
      return std::make_shared<PublicKey_k1Bitcoin>(std::move(ctx));
    }
    else
    {
      return std::make_shared<PublicKey>(std::move(ctx));
    }
  }

  /**
   * Construct PublicKey from a raw public key in DER format
   *
   * @param public_der Sequence of bytes containing the key in DER format
   * @param use_bitcoin_impl If true, and the key is on secp256k1, then the
   * bitcoin secp256k1 library will be used as the implementation rather than
   * mbedtls
   */
  inline PublicKeyPtr make_public_key(
    const std::vector<uint8_t> public_der,
    bool use_bitcoin_impl = prefer_bitcoin_secp256k1)
  {
    auto ctx = std::make_unique<mbedtls_pk_context>();
    mbedtls_pk_init(ctx.get());

    int rc = mbedtls_pk_parse_public_key(
      ctx.get(), public_der.data(), public_der.size());

    if (rc != 0)
    {
      throw std::logic_error(
        fmt::format("Could not parse public key DER: {}", error_string(rc)));
    }

    const auto curve = get_ec_from_context(*ctx);

    if (curve == MBEDTLS_ECP_DP_SECP256K1 && use_bitcoin_impl)
    {
      return std::make_shared<PublicKey_k1Bitcoin>(std::move(ctx));
    }
    else
    {
      return std::make_shared<PublicKey>(std::move(ctx));
    }
  }

  inline RSAPublicKeyPtr make_rsa_public_key(const Pem& public_pem)
  {
    auto ctx = std::make_unique<mbedtls_pk_context>();
    mbedtls_pk_init(ctx.get());

    int rc = mbedtls_pk_parse_public_key(
      ctx.get(), public_pem.data(), public_pem.size());

    if (rc != 0)
    {
      throw std::logic_error(fmt::format(
        "Could not parse public key PEM: {}\n\n(Key: {})",
        error_string(rc),
        public_pem.str()));
    }

    return std::make_shared<RSAPublicKey>(std::move(ctx));
  }

  class KeyPair : public PublicKey
  {
  private:
    struct SignCsr
    {
      EntropyPtr entropy;
      mbedtls_x509_csr csr;
      mbedtls_mpi serial;
      mbedtls_x509write_cert crt;

      SignCsr() : entropy(create_entropy())
      {
        mbedtls_x509_csr_init(&csr);
        mbedtls_mpi_init(&serial);
        mbedtls_x509write_crt_init(&crt);
      }

      ~SignCsr()
      {
        mbedtls_x509_csr_free(&csr);
        mbedtls_x509write_crt_free(&crt);
        mbedtls_mpi_free(&serial);
      }
    };

  protected:
    KeyPair() = default;

    /**
     * Initialise from existing pre-parsed key
     */
    KeyPair(std::unique_ptr<mbedtls_pk_context>&& k) : PublicKey(std::move(k))
    {}

    KeyPair(const KeyPair&) = delete;

  public:
    /**
     * Get the private key in PEM format
     */
    Pem private_key_pem()
    {
      uint8_t data[max_pem_key_size];

      int rc = mbedtls_pk_write_key_pem(ctx.get(), data, max_pem_key_size);
      if (rc != 0)
      {
        throw std::logic_error("mbedtls_pk_write_key_pem: " + error_string(rc));
      }

      const size_t len = strlen((char const*)data);
      return Pem(data, len);
    }

    /**
     * Create signature over hash of data from private key.
     *
     * @param d data
     *
     * @return Signature as a vector
     */
    std::vector<uint8_t> sign(CBuffer d, mbedtls_md_type_t md_type = {}) const
    {
      HashBytes hash;
      do_hash(*ctx, d.p, d.rawSize(), hash, md_type);

      return sign_hash(hash.data(), hash.size());
    }

    /**
     * Write signature over hash of data, and the size of that signature to
     * specified locations.
     *
     * Important: sig must point somewhere that's at least
     * MBEDTLS_E{C,D}DSA_MAX_LEN.
     *
     * @param d data
     * @param sig_size location to which the signature size will be written.
     * Initial value should be max size of sig
     * @param sig location to which the signature will be written
     *
     * @return 0 if successful, error code of mbedtls_pk_sign otherwise,
     *         or 0xf if the signature_size exceeds that of a uint8_t.
     */
    int sign(
      CBuffer d,
      size_t* sig_size,
      uint8_t* sig,
      mbedtls_md_type_t md_type = {}) const
    {
      HashBytes hash;
      do_hash(*ctx, d.p, d.rawSize(), hash, md_type);

      return sign_hash(hash.data(), hash.size(), sig_size, sig);
    }

    /**
     * Create signature over hashed data.
     *
     * @param hash First byte in hash sequence
     * @param hash_size Number of bytes in hash sequence
     *
     * @return Signature as a vector
     */
    std::vector<uint8_t> sign_hash(const uint8_t* hash, size_t hash_size) const
    {
      uint8_t sig[MBEDTLS_ECDSA_MAX_LEN];

      size_t written = MBEDTLS_ECDSA_MAX_LEN;
      if (sign_hash(hash, hash_size, &written, sig) != 0)
      {
        return {};
      }

      return {sig, sig + written};
    }

    virtual int sign_hash(
      const uint8_t* hash,
      size_t hash_size,
      size_t* sig_size,
      uint8_t* sig) const
    {
      EntropyPtr entropy = create_entropy();

      const auto ec = get_ec_from_context(*ctx);
      const auto md_type = get_md_for_ec(ec, true);

      return mbedtls_pk_sign(
        ctx.get(),
        md_type,
        hash,
        hash_size,
        sig,
        sig_size,
        entropy->get_rng(),
        entropy->get_data());
    }

    /**
     * Create a certificate signing request for this key pair. If we were
     * loaded from a private key, there will be no public key available for
     * this call.
     */
    Pem create_csr(const std::string& name)
    {
      Csr csr;

      if (mbedtls_x509write_csr_set_subject_name(&csr.req, name.c_str()) != 0)
        return {};

      mbedtls_x509write_csr_set_key(&csr.req, ctx.get());

      uint8_t buf[4096];
      memset(buf, 0, sizeof(buf));
      EntropyPtr entropy = create_entropy();

      if (
        mbedtls_x509write_csr_pem(
          &csr.req,
          buf,
          sizeof(buf),
          entropy->get_rng(),
          entropy->get_data()) != 0)
        return {};

      auto len = strlen((char*)buf);
      return Pem(buf, len);
    }

    Pem sign_csr(
      const Pem& csr,
      const std::string& issuer,
      const std::vector<SubjectAltName> subject_alt_names,
      bool ca = false)
    {
      SignCsr sign;

      if (mbedtls_x509_csr_parse(&sign.csr, csr.data(), csr.size()) != 0)
        return {};

      char subject[512];
      auto r =
        mbedtls_x509_dn_gets(subject, sizeof(subject), &sign.csr.subject);

      if (r < 0)
        return {};

      mbedtls_x509write_crt_set_md_alg(
        &sign.crt, get_md_for_ec(get_ec_from_context(*ctx)));
      mbedtls_x509write_crt_set_subject_key(&sign.crt, &sign.csr.pk);
      mbedtls_x509write_crt_set_issuer_key(&sign.crt, ctx.get());

      if (
        mbedtls_mpi_fill_random(
          &sign.serial,
          16,
          sign.entropy->get_rng(),
          sign.entropy->get_data()) != 0)
        return {};

      if (mbedtls_x509write_crt_set_subject_name(&sign.crt, subject) != 0)
        return {};

      if (mbedtls_x509write_crt_set_issuer_name(&sign.crt, issuer.c_str()) != 0)
        return {};

      if (mbedtls_x509write_crt_set_serial(&sign.crt, &sign.serial) != 0)
        return {};

      // Note: 825-day validity range
      // https://support.apple.com/en-us/HT210176
      if (
        mbedtls_x509write_crt_set_validity(
          &sign.crt, "20191101000000", "20211231235959") != 0)
        return {};

      if (
        mbedtls_x509write_crt_set_basic_constraints(&sign.crt, ca ? 1 : 0, 0) !=
        0)
        return {};

      if (mbedtls_x509write_crt_set_subject_key_identifier(&sign.crt) != 0)
        return {};

      if (mbedtls_x509write_crt_set_authority_key_identifier(&sign.crt) != 0)
        return {};

      // Because mbedtls does not support parsing x509v3 extensions from a
      // CSR (https://github.com/ARMmbed/mbedtls/issues/2912), the CA sets the
      // SAN directly instead of reading it from the CSR
      try
      {
        auto rc =
          x509write_crt_set_subject_alt_names(&sign.crt, subject_alt_names);
        if (rc != 0)
        {
          LOG_FAIL_FMT("Failed to set subject alternative names ({})", rc);
          return {};
        }
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT(err.what());
        return {};
      }

      uint8_t buf[4096];
      memset(buf, 0, sizeof(buf));

      if (
        mbedtls_x509write_crt_pem(
          &sign.crt,
          buf,
          sizeof(buf),
          sign.entropy->get_rng(),
          sign.entropy->get_data()) != 0)
        return {};

      auto len = strlen((char*)buf);
      return Pem(buf, len);
    }

    Pem self_sign(
      const std::string& name,
      const std::optional<SubjectAltName> subject_alt_name = std::nullopt,
      bool ca = true)
    {
      std::vector<SubjectAltName> sans;
      if (subject_alt_name.has_value())
        sans.push_back(subject_alt_name.value());
      auto csr = create_csr(name);
      return sign_csr(csr, name, sans, ca);
    }

    Pem self_sign(
      const std::string& name,
      const std::vector<SubjectAltName> subject_alt_names,
      bool ca = true)
    {
      auto csr = create_csr(name);
      return sign_csr(csr, name, subject_alt_names, ca);
    }
  };

}
