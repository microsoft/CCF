// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "asn1_san.h"
#include "curve.h"
#include "entropy.h"
#include "error_string.h"
#include "hash.h"
#include "mbedtls_wrappers.h"
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
    mbedtls::PKContext ctx = mbedtls::make_unique<mbedtls::PKContext>();

    PublicKey() {}

  public:
    /**
     * Construct from a pre-initialised pk context
     */
    PublicKey(mbedtls::PKContext&& c) : ctx(std::move(c)) {}

    virtual ~PublicKey() = default;

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

  using PublicKeyPtr = std::shared_ptr<PublicKey>;

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
    auto ctx = mbedtls::make_unique<mbedtls::PKContext>();

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
    auto ctx = mbedtls::make_unique<mbedtls::PKContext>();

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

  class KeyPair : public PublicKey
  {
  public:
    /**
     * Create a new public / private ECDSA key pair
     */
    KeyPair(mbedtls_ecp_group_id ec)
    {
      EntropyPtr entropy = create_entropy();

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

    /**
     * Initialise from existing pre-parsed key
     */
    KeyPair(mbedtls::PKContext&& k) : PublicKey(std::move(k)) {}

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
      auto csr = mbedtls::make_unique<mbedtls::X509WriteCsr>();
      mbedtls_x509write_csr_set_md_alg(csr.get(), MBEDTLS_MD_SHA512);

      if (mbedtls_x509write_csr_set_subject_name(csr.get(), name.c_str()) != 0)
        return {};

      mbedtls_x509write_csr_set_key(csr.get(), ctx.get());

      uint8_t buf[4096];
      memset(buf, 0, sizeof(buf));
      EntropyPtr entropy = create_entropy();

      if (
        mbedtls_x509write_csr_pem(
          csr.get(),
          buf,
          sizeof(buf),
          entropy->get_rng(),
          entropy->get_data()) != 0)
        return {};

      auto len = strlen((char*)buf);
      return Pem(buf, len);
    }

    Pem sign_csr(
      const Pem& pem,
      const std::string& issuer,
      const std::vector<SubjectAltName> subject_alt_names,
      bool ca = false)
    {
      auto entropy = create_entropy();
      auto csr = mbedtls::make_unique<mbedtls::X509Csr>();
      auto serial = mbedtls::make_unique<mbedtls::MPI>();
      auto crt = mbedtls::make_unique<mbedtls::X509WriteCrt>();

      if (mbedtls_x509_csr_parse(csr.get(), pem.data(), pem.size()) != 0)
        return {};

      char subject[512];
      auto r = mbedtls_x509_dn_gets(subject, sizeof(subject), &csr->subject);

      if (r < 0)
        return {};

      mbedtls_x509write_crt_set_md_alg(
        crt.get(), get_md_for_ec(get_ec_from_context(*ctx)));
      mbedtls_x509write_crt_set_subject_key(crt.get(), &csr->pk);
      mbedtls_x509write_crt_set_issuer_key(crt.get(), ctx.get());

      if (
        mbedtls_mpi_fill_random(
          serial.get(), 16, entropy->get_rng(), entropy->get_data()) != 0)
        return {};

      if (mbedtls_x509write_crt_set_subject_name(crt.get(), subject) != 0)
        return {};

      if (mbedtls_x509write_crt_set_issuer_name(crt.get(), issuer.c_str()) != 0)
        return {};

      if (mbedtls_x509write_crt_set_serial(crt.get(), serial.get()) != 0)
        return {};

      // Note: 825-day validity range
      // https://support.apple.com/en-us/HT210176
      if (
        mbedtls_x509write_crt_set_validity(
          crt.get(), "20191101000000", "20211231235959") != 0)
        return {};

      if (
        mbedtls_x509write_crt_set_basic_constraints(crt.get(), ca ? 1 : 0, 0) !=
        0)
        return {};

      if (mbedtls_x509write_crt_set_subject_key_identifier(crt.get()) != 0)
        return {};

      if (mbedtls_x509write_crt_set_authority_key_identifier(crt.get()) != 0)
        return {};

      // Because mbedtls does not support parsing x509v3 extensions from a
      // CSR (https://github.com/ARMmbed/mbedtls/issues/2912), the CA sets the
      // SAN directly instead of reading it from the CSR
      try
      {
        auto rc =
          x509write_crt_set_subject_alt_names(crt.get(), subject_alt_names);
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
          crt.get(),
          buf,
          sizeof(buf),
          entropy->get_rng(),
          entropy->get_data()) != 0)
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

  class KeyPair_k1Bitcoin : public KeyPair
  {
  protected:
    BCk1ContextPtr bc_ctx =
      make_bc_context(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    secp256k1_pubkey bc_pub;

    static constexpr size_t privk_size = 32;
    uint8_t c4_priv[privk_size] = {0};

  public:
    template <typename... Ts>
    KeyPair_k1Bitcoin(Ts... ts) : KeyPair(std::forward<Ts>(ts)...)
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

  inline mbedtls::PKContext parse_private_key(
    const Pem& pkey, CBuffer pw = nullb)
  {
    auto key = mbedtls::make_unique<mbedtls::PKContext>();

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
   * Create a new public / private ECDSA key pair on specified curve and
   * implementation
   */
  inline KeyPairPtr make_key_pair(
    CurveImpl curve = CurveImpl::service_identity_curve_choice)
  {
    const auto ec = get_ec_for_curve_impl(curve);
    if (curve == CurveImpl::secp256k1_bitcoin)
    {
      return KeyPairPtr(new KeyPair_k1Bitcoin(ec));
    }
    else
    {
      return KeyPairPtr(new KeyPair(ec));
    }
  }

  /**
   * Create a public / private ECDSA key pair from existing private key data
   */
  inline KeyPairPtr make_key_pair(
    const Pem& pkey,
    CBuffer pw = nullb,
    bool use_bitcoin_impl = prefer_bitcoin_secp256k1)
  {
    auto key = parse_private_key(pkey, pw);

    const auto curve = get_ec_from_context(*key);

    if (curve == MBEDTLS_ECP_DP_SECP256K1 && use_bitcoin_impl)
    {
      return std::make_shared<KeyPair_k1Bitcoin>(std::move(key));
    }
    else
    {
      return std::make_shared<KeyPair>(std::move(key));
    }
  }

  static inline tls::Pem public_key_pem_from_cert(const tls::Pem& cert)
  {
    auto c = mbedtls::make_unique<mbedtls::X509Crt>();
    int rc = mbedtls_x509_crt_parse(c.get(), cert.data(), cert.size());
    if (rc != 0)
    {
      throw std::runtime_error(fmt::format(
        "Failed to parse certificate, mbedtls_x509_crt_parse: {}", rc));
    }
    uint8_t data[2048];
    rc = mbedtls_pk_write_pubkey_pem(&c->pk, data, max_pem_key_size);
    if (rc != 0)
    {
      throw std::runtime_error(fmt::format(
        "Failed to serialise public key, mbedtls_pk_write_pubkey_pem: {}", rc));
    }

    size_t len = strlen((char const*)data);
    return tls::Pem(data, len);
  }

  inline void check_is_cert(CBuffer der)
  {
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int rc = mbedtls_x509_crt_parse(&cert, der.p, der.n);
    mbedtls_x509_crt_free(&cert);
    if (rc != 0)
    {
      throw std::invalid_argument(fmt::format(
        "Failed to parse certificate, mbedtls_x509_crt_parse: {}",
        tls::error_string(rc)));
    }
  }
}
