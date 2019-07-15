// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../crypto/hash.h"
#include "../ds/logger.h"
#include "cert.h"
#include "csr.h"
#include "entropy.h"
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_recovery.h"

#include <cstring>
#include <iomanip>
#include <limits>
#include <mbedtls/bignum.h>
#include <mbedtls/eddsa.h>
#include <memory>

namespace tls
{
  enum class CurveImpl
  {
    secp384r1 = 1,
    curve25519 = 2,
    secp256k1_mbedtls = 3,
    secp256k1_bitcoin = 4,

#if SERVICE_IDENTITY_CURVE_CHOICE_SECP384R1
    service_identity_curve_choice = secp384r1,
#elif SERVICE_IDENTITY_CURVE_CHOICE_CURVE25519
    service_identity_curve_choice = curve25519,
#elif SERVICE_IDENTITY_CURVE_CHOICE_SECP256K1_MBEDTLS
    service_identity_curve_choice = secp256k1_mbedtls,
#elif SERVICE_IDENTITY_CURVE_CHOICE_SECP256K1_BITCOIN
    service_identity_curve_choice = secp256k1_bitcoin,
#endif
  };

  using HashBytes = std::vector<uint8_t>;

  // 2 implementations of secp256k1 are available - mbedtls and bitcoin. Either
  // can be asked for explicitly via the CurveImpl enum. For cases where we
  // receive a raw 256k1 key/signature/cert only, this flag determines which
  // implementation is used
  static constexpr bool prefer_bitcoin_secp256k1 = true;

  static constexpr size_t ecp_num_size = 100;

  // Helper to access elliptic curve id from context
  inline mbedtls_ecp_group_id get_ec_from_context(const mbedtls_pk_context& ctx)
  {
    return mbedtls_pk_ec(ctx)->grp.id;
  }

  // Get mbedtls elliptic curve for given CCF curve implementation
  inline mbedtls_ecp_group_id get_ec_for_curve_impl(CurveImpl curve)
  {
    switch (curve)
    {
      case CurveImpl::secp384r1:
      {
        return MBEDTLS_ECP_DP_SECP384R1;
      }
      case CurveImpl::curve25519:
      {
        return MBEDTLS_ECP_DP_CURVE25519;
      }
      case CurveImpl::secp256k1_mbedtls:
      case CurveImpl::secp256k1_bitcoin:
      {
        return MBEDTLS_ECP_DP_SECP256K1;
      }
      default:
      {
        throw std::logic_error(
          "Unhandled curve type: " +
          std::to_string(static_cast<size_t>(curve)));
      }
    }
  }

  // Get message digest algorithm to use for given elliptic curve
  inline mbedtls_md_type_t get_md_for_ec(mbedtls_ecp_group_id ec)
  {
    switch (ec)
    {
      case MBEDTLS_ECP_DP_SECP384R1:
      {
        return MBEDTLS_MD_SHA384;
      }
      case MBEDTLS_ECP_DP_CURVE25519:
      {
        return MBEDTLS_MD_SHA512;
      }
      case MBEDTLS_ECP_DP_SECP256K1:
      {
        return MBEDTLS_MD_SHA256;
      }
      default:
      {
        throw std::logic_error(
          std::string("Unhandled ecp group id: ") +
          mbedtls_ecp_curve_info_from_grp_id(ec)->name);
      }
    }
  }

  /**
   * Hash the given data, with an algorithm chosen by key type
   *
   * @return 0 on success
   */
  inline int do_hash(
    const mbedtls_pk_context& ctx,
    const uint8_t* data_ptr,
    size_t data_size,
    HashBytes& o_hash)
  {
    const auto ec = get_ec_from_context(ctx);
    const auto md_type = get_md_for_ec(ec);
    const auto md_info = mbedtls_md_info_from_type(md_type);
    const auto hash_size = mbedtls_md_get_size(md_info);

    if (o_hash.size() < hash_size)
      o_hash.resize(hash_size);

    return mbedtls_md(md_info, data_ptr, data_size, o_hash.data());
  }

  inline bool verify_secp256k_bc(
    secp256k1_context* ctx,
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* hash,
    size_t hash_size,
    const secp256k1_pubkey* public_key)
  {
    if (hash_size != 32)
      return false;

    secp256k1_ecdsa_signature sig;
    if (
      secp256k1_ecdsa_signature_parse_der(
        ctx, &sig, signature, signature_size) != 1)
      return false;

    secp256k1_ecdsa_signature norm_sig;
    if (secp256k1_ecdsa_signature_normalize(ctx, &norm_sig, &sig) == 1)
    {
      LOG_TRACE_FMT("secp256k1 normalized a signature to lower-S form");
    }

    return secp256k1_ecdsa_verify(ctx, &norm_sig, hash, public_key) == 1;
  }

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
        "mbedtls_ecp_point_write_binary failed: " + std::to_string(rc));
    }

    rc = secp256k1_ec_pubkey_parse(bc_ctx, bc_pub, pub_buf, pub_len);
    if (rc != 1)
    {
      throw std::logic_error("secp256k1_ec_pubkey_parse failed");
    }
  }

  class KeyPair
  {
  private:
    static constexpr size_t MAX_SIZE_PEM = 2048;

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
    std::unique_ptr<mbedtls_pk_context> key =
      std::make_unique<mbedtls_pk_context>();

  public:
    /**
     * Create a new public / private key pair
     */
    KeyPair(mbedtls_ecp_group_id ec)
    {
      EntropyPtr entropy = create_entropy();
      mbedtls_pk_init(key.get());

      int rc = 0;

      switch (ec)
      {
        case MBEDTLS_ECP_DP_CURVE25519:
        case MBEDTLS_ECP_DP_CURVE448:
        {
          // These curves are technically not ECDSA, but EdDSA.
          rc = mbedtls_pk_setup(
            key.get(), mbedtls_pk_info_from_type(MBEDTLS_PK_EDDSA));
          if (rc != 0)
          {
            throw std::logic_error(
              "Could not set up EdDSA context: " + std::to_string(rc));
          }

          rc = mbedtls_eddsa_genkey(
            mbedtls_pk_eddsa(*key),
            ec,
            entropy->get_rng(),
            entropy->get_data());
          if (rc != 0)
          {
            throw std::logic_error(
              "Could not generate EdDSA keypair: " + std::to_string(rc));
          }
          break;
        }

        default:
        {
          rc = mbedtls_pk_setup(
            key.get(), mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
          if (rc != 0)
          {
            throw std::logic_error(
              "Could not set up ECDSA context: " + std::to_string(rc));
          }

          rc = mbedtls_ecp_gen_key(
            ec, mbedtls_pk_ec(*key), entropy->get_rng(), entropy->get_data());
          if (rc != 0)
          {
            throw std::logic_error(
              "Could not generate ECDSA keypair: " + std::to_string(rc));
          }
          break;
        }
      }

      const auto actual_ec = get_ec_from_context(*key);
      if (actual_ec != ec)
      {
        throw std::logic_error(
          "Created key and received unexpected type: " +
          std::to_string(actual_ec) + " != " + std::to_string(ec));
      }
    }

    /**
     * Initialise from existing pre-parsed key
     */
    KeyPair(std::unique_ptr<mbedtls_pk_context>&& k) : key(std::move(k)) {}

    KeyPair(const KeyPair&) = delete;

    virtual ~KeyPair()
    {
      if (key)
        mbedtls_pk_free(key.get());
    }

    /**
     * Get the private key in PEM format
     */
    std::vector<uint8_t> private_key()
    {
      std::vector<uint8_t> pem(MAX_SIZE_PEM);
      if (mbedtls_pk_write_key_pem(key.get(), pem.data(), pem.size()))
        return {};

      auto len = strlen((char*)pem.data());
      if (len >= pem.size())
        return {};
      return {pem.data(), pem.data() + len + 1};
    }

    /**
     * Get the public key in PEM format
     */
    std::vector<uint8_t> public_key()
    {
      std::vector<uint8_t> pem(MAX_SIZE_PEM);
      if (mbedtls_pk_write_pubkey_pem(key.get(), pem.data(), pem.size()))
        return {};

      auto len = strlen((char*)pem.data());
      if (len >= pem.size())
        return {};
      return {pem.data(), pem.data() + len + 1};
    }

    /**
     * Create signature over hash of data from private key.
     *
     * @param d data
     *
     * @return Signature as a vector
     */
    std::vector<uint8_t> sign(CBuffer d) const
    {
      HashBytes hash;
      do_hash(*key, d.p, d.rawSize(), hash);

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
    int sign(CBuffer d, size_t* sig_size, uint8_t* sig) const
    {
      HashBytes hash;
      do_hash(*key, d.p, d.rawSize(), hash);

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
      int rc = 0;
      EntropyPtr entropy = create_entropy();

      const auto ec = get_ec_from_context(*key);
      const auto md_type = get_md_for_ec(ec);

      rc = mbedtls_pk_sign(
        key.get(),
        md_type,
        hash,
        hash_size,
        sig,
        sig_size,
        entropy->get_rng(),
        entropy->get_data());

      return rc;
    }

    /**
     * Create a certificate signing request for this key pair. If we were
     * loaded from a private key, there will be no public key available for
     * this call.
     */
    std::vector<uint8_t> create_csr(const std::string& name)
    {
      Csr csr;

      if (mbedtls_x509write_csr_set_subject_name(&csr.req, name.c_str()) != 0)
        return {};

      mbedtls_x509write_csr_set_key(&csr.req, key.get());

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

      auto len = strlen((char*)buf) + 1;
      std::vector<uint8_t> pem(buf, buf + len);
      return pem;
    }

    std::vector<uint8_t> sign_csr(
      CBuffer csr, const std::string& issuer, bool ca = false)
    {
      SignCsr sign;

      Pem pemCsr(csr);
      if (mbedtls_x509_csr_parse(&sign.csr, pemCsr.p, pemCsr.n) != 0)
        return {};

      char subject[512];
      auto r =
        mbedtls_x509_dn_gets(subject, sizeof(subject), &sign.csr.subject);

      if (r < 0)
        return {};

      mbedtls_x509write_crt_set_md_alg(
        &sign.crt, get_md_for_ec(get_ec_from_context(*key)));
      mbedtls_x509write_crt_set_subject_key(&sign.crt, &sign.csr.pk);
      mbedtls_x509write_crt_set_issuer_key(&sign.crt, key.get());

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

      if (
        mbedtls_x509write_crt_set_validity(
          &sign.crt, "20010101000000", "21001231235959") != 0)
        return {};

      if (
        mbedtls_x509write_crt_set_basic_constraints(&sign.crt, ca ? 1 : 0, 0) !=
        0)
        return {};

      if (mbedtls_x509write_crt_set_subject_key_identifier(&sign.crt) != 0)
        return {};

      if (mbedtls_x509write_crt_set_authority_key_identifier(&sign.crt) != 0)
        return {};

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

      auto len = strlen((char*)buf) + 1;
      std::vector<uint8_t> pem(buf, buf + len);
      return pem;
    }

    std::vector<uint8_t> self_sign(const std::string& name, bool ca = true)
    {
      auto csr = create_csr(name);
      return sign_csr(csr, name, ca);
    }

    const mbedtls_pk_context& get_raw_context() const
    {
      return *key;
    }
  };

  class KeyPair_k1Bitcoin : public KeyPair
  {
  protected:
    secp256k1_context* bc_ctx = secp256k1_context_create(
      SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    static constexpr size_t privk_size = 32;
    uint8_t c4_priv[privk_size] = {0};

  public:
    template <typename... Ts>
    KeyPair_k1Bitcoin(Ts... ts) : KeyPair(std::forward<Ts>(ts)...)
    {
      int rc = 0;

      rc = mbedtls_mpi_write_binary(
        &(mbedtls_pk_ec(*key)->d), c4_priv, privk_size);
      if (rc != 0)
      {
        throw std::logic_error(
          "Could not extract raw private key: " + std::to_string(rc));
      }

      if (secp256k1_ec_seckey_verify(bc_ctx, c4_priv) != 1)
      {
        throw std::logic_error("secp256k1 private key is not valid");
      }
    }

    ~KeyPair_k1Bitcoin()
    {
      if (bc_ctx)
        secp256k1_context_destroy(bc_ctx);
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
          bc_ctx, &k1_sig, hash, c4_priv, nullptr, nullptr) != 1)
        return -2;

      if (
        secp256k1_ecdsa_signature_serialize_der(
          bc_ctx, sig, sig_size, &k1_sig) != 1)
        return -3;

      return 0;
    }
  };

  using KeyPairPtr = std::shared_ptr<KeyPair>;

  /**
   * Create a new public / private key pair on specified curve and
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
   * Create a public / private from existing raw private key data
   */
  inline KeyPairPtr make_key_pair(
    CBuffer pkey,
    CBuffer pw = nullb,
    bool use_bitcoin_impl = prefer_bitcoin_secp256k1)
  {
    std::unique_ptr<mbedtls_pk_context> key =
      std::make_unique<mbedtls_pk_context>();
    mbedtls_pk_init(key.get());

    Pem pemPk(pkey);
    int rc = mbedtls_pk_parse_key(key.get(), pemPk.p, pemPk.n, pw.p, pw.n);
    if (rc != 0)
    {
      throw std::logic_error("Could not parse key: " + std::to_string(rc));
    }

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

  class PublicKey
  {
  protected:
    mbedtls_pk_context ctx;

  public:
    /**
     * Construct from a pre-constructed pk context
     */
    PublicKey(const mbedtls_pk_context& c) : ctx(c) {}

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
     *
     * @return Whether the signature matches the contents and the key
     */
    bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size)
    {
      HashBytes hash;
      do_hash(ctx, contents, contents_size, hash);

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
      const auto md_type = get_md_for_ec(get_ec_from_context(ctx));

      int rc = mbedtls_pk_verify(&ctx, md_type, hash, hash_size, sig, sig_size);

      if (rc)
        LOG_DEBUG_FMT("Failed to verify signature: {}", rc);

      return rc == 0;
    }

    virtual ~PublicKey()
    {
      mbedtls_pk_free(&ctx);
    }
  };

  class PublicKey_k1Bitcoin : public PublicKey
  {
  protected:
    secp256k1_context* bc_ctx = secp256k1_context_create(
      SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    secp256k1_pubkey bc_pub;

  public:
    template <typename... Ts>
    PublicKey_k1Bitcoin(Ts... ts) : PublicKey(std::forward<Ts>(ts)...)
    {
      parse_secp256k_bc(ctx, bc_ctx, &bc_pub);
    }

    ~PublicKey_k1Bitcoin()
    {
      if (bc_ctx)
        secp256k1_context_destroy(bc_ctx);
    }

    bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size) override
    {
      return verify_secp256k_bc(
        bc_ctx, sig, sig_size, hash, hash_size, &bc_pub);
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
    const std::vector<uint8_t>& public_pem,
    bool use_bitcoin_impl = prefer_bitcoin_secp256k1)
  {
    mbedtls_pk_context ctx;

    mbedtls_pk_init(&ctx);
    mbedtls_pk_parse_public_key(&ctx, public_pem.data(), public_pem.size());

    const auto curve = get_ec_from_context(ctx);

    if (curve == MBEDTLS_ECP_DP_SECP256K1 && use_bitcoin_impl)
    {
      return std::make_shared<PublicKey_k1Bitcoin>(ctx);
    }
    else
    {
      return std::make_shared<PublicKey>(ctx);
    }
  }

  class Verifier
  {
  protected:
    mutable mbedtls_x509_crt cert;

  public:
    /**
     * Construct from a pre-parsed cert
     *
     * @param c Initialised and parsed x509 cert
     */
    Verifier(const mbedtls_x509_crt& c) : cert(c) {}

    Verifier(const Verifier&) = delete;

    /**
     * Verify that a signature was produced on a hash with the private key
     * associated with the public key contained in the certificate.
     *
     * @param hash First byte in hash sequence
     * @param hash_size Number of bytes in hash sequence
     * @param signature First byte in signature sequence
     * @param signature_size Number of bytes in signature sequence
     *
     * @return Whether the signature matches the hash and the key
     */
    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* signature,
      size_t signature_size) const
    {
      const auto md_type = get_md_for_ec(get_ec_from_context(cert.pk));

      int rc = mbedtls_pk_verify(
        &cert.pk, md_type, hash, hash_size, signature, signature_size);

      if (rc)
        LOG_DEBUG_FMT("Failed to verify signature: {}", rc);

      return rc == 0;
    }

    /**
     * Verify that a signature was produced on a hash with the private key
     * associated with the public key contained in the certificate.
     *
     * @param hash Hash produced from contents as a sequence of bytes
     * @param signature Signature as a sequence of bytes
     *
     * @return Whether the signature matches the hash and the key
     */
    bool verify_hash(
      const std::vector<uint8_t>& hash,
      const std::vector<uint8_t>& signature) const
    {
      return verify_hash(
        hash.data(), hash.size(), signature.data(), signature.size());
    }

    /**
     * Verify that a signature was produced on contents with the private key
     * associated with the public key contained in the certificate.
     *
     * @param contents Sequence of bytes that was signed
     * @param signature Signature as a sequence of bytes
     *
     * @return Whether the signature matches the contents and the key
     */
    bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature) const
    {
      HashBytes hash;
      do_hash(cert.pk, contents.data(), contents.size(), hash);

      return verify_hash(hash, signature);
    }

    const mbedtls_x509_crt* raw()
    {
      return &cert;
    }

    std::vector<uint8_t> raw_cert_data()
    {
      const auto crt = raw();
      return {crt->raw.p, crt->raw.p + crt->raw.len};
    }

    virtual ~Verifier()
    {
      mbedtls_x509_crt_free(&cert);
    }
  };

  class Verifier_k1Bitcoin : public Verifier
  {
  protected:
    secp256k1_context* bc_ctx =
      secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey bc_pub;

  public:
    template <typename... Ts>
    Verifier_k1Bitcoin(Ts... ts) : Verifier(std::forward<Ts>(ts)...)
    {
      parse_secp256k_bc(cert.pk, bc_ctx, &bc_pub);
    }

    bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* signature,
      size_t signature_size) const override
    {
      bool ok = verify_secp256k_bc(
        bc_ctx, signature, signature_size, hash, hash_size, &bc_pub);

      return ok;
    }

    ~Verifier_k1Bitcoin()
    {
      if (bc_ctx)
        secp256k1_context_destroy(bc_ctx);
    }
  };

  using VerifierPtr = std::shared_ptr<Verifier>;

  /**
   * Construct Verifier from a certificate in PEM format
   *
   * @param public_pem Sequence of bytes containing the certificate in PEM
   * format
   */
  inline VerifierPtr make_verifier(
    const std::vector<uint8_t>& cert_pem,
    bool use_bitcoin_impl = prefer_bitcoin_secp256k1)
  {
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int rc = mbedtls_x509_crt_parse(&cert, cert_pem.data(), cert_pem.size());
    if (rc)
    {
      std::stringstream s;
      s << "Failed to parse certificate: " << rc;
      throw std::invalid_argument(s.str());
    }

    const auto curve = get_ec_from_context(cert.pk);

    if (curve == MBEDTLS_ECP_DP_SECP256K1 && use_bitcoin_impl)
    {
      return std::make_shared<Verifier_k1Bitcoin>(cert);
    }
    else
    {
      return std::make_shared<Verifier>(cert);
    }
  }
}
