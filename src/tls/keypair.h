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

// 2 implementations of secp256k1 are available - mbedtls and bitcoin. Either
// can be asked for explicitly via the CurveImpl enum. For cases where we
// receive a raw 256k1 key/signature/cert only, this flag determines which
// implementation is used
#define PREFER_BITCOIN_SECP256K1 true

namespace tls
{
  enum class CurveImpl
  {
    secp384r1 = 1,
    curve25519 = 2,
    secp256k1_mbedtls = 3,
    secp256k1_bitcoin = 4,

#if LEDGER_CURVE_CHOICE_SECP384R1
    ledger_curve_choice = secp384r1,
#elif LEDGER_CURVE_CHOICE_CURVE25519
    ledger_curve_choice = curve25519,
#elif LEDGER_CURVE_CHOICE_SECP256K1_MBEDTLS
    ledger_curve_choice = secp256k1_mbedtls,
#elif LEDGER_CURVE_CHOICE_SECP256K1_BITCOIN
    ledger_curve_choice = secp256k1_bitcoin,
#endif
  };

  using HashBytes = std::vector<uint8_t>;

  inline int do_hash(
    mbedtls_ecp_group_id curve,
    const uint8_t* data_ptr,
    size_t data_size,
    HashBytes& o_hash)
  {
    switch (curve)
    {
      case MBEDTLS_ECP_DP_SECP384R1:
      {
        constexpr auto hash_size = 384 / 8;
        if (o_hash.size() < hash_size)
          o_hash.resize(hash_size);

        return mbedtls_sha512_ret(data_ptr, data_size, o_hash.data(), true);
      }
      case MBEDTLS_ECP_DP_CURVE25519:
      {
        constexpr auto hash_size = 512 / 8;
        if (o_hash.size() < hash_size)
          o_hash.resize(hash_size);

        return mbedtls_sha512_ret(data_ptr, data_size, o_hash.data(), false);
      }
      case MBEDTLS_ECP_DP_SECP256K1:
      {
        constexpr auto hash_size = 256 / 8;
        if (o_hash.size() < hash_size)
          o_hash.resize(hash_size);

        return mbedtls_sha256_ret(data_ptr, data_size, o_hash.data(), false);
      }
      default:
      {
        throw std::logic_error("Unhandled curve type");
      }
    }
  }

  static constexpr size_t REC_ID_IDX = 64;

  inline bool verify_secp256k_bc(
    secp256k1_context* ctx,
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* hash,
    const secp256k1_pubkey* public_key)
  {
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

  struct CurveParams
  {
    mbedtls_md_type_t md_type;
    size_t md_size;

    mbedtls_ecp_group_id ecp_group_id;
  };

  static constexpr CurveParams params_secp384r1{
    MBEDTLS_MD_SHA384, 384 / 8, MBEDTLS_ECP_DP_SECP384R1};

  static constexpr CurveParams params_curve25519{
    MBEDTLS_MD_SHA512, 512 / 8, MBEDTLS_ECP_DP_CURVE25519};

  static constexpr CurveParams params_secp256k1_mbedtls{
    MBEDTLS_MD_SHA256, 256 / 8, MBEDTLS_ECP_DP_SECP256K1};

  static constexpr CurveParams params_secp256k1_bitcoin{
    MBEDTLS_MD_SHA256, 256 / 8, MBEDTLS_ECP_DP_SECP256K1};

  const CurveParams& get_curve_params(CurveImpl curve)
  {
    switch (curve)
    {
      case CurveImpl::secp384r1:
      {
        return params_secp384r1;
      }
      case CurveImpl::curve25519:
      {
        return params_curve25519;
      }
      case CurveImpl::secp256k1_mbedtls:
      {
        return params_secp256k1_mbedtls;
      }
      case CurveImpl::secp256k1_bitcoin:
      {
        return params_secp256k1_bitcoin;
      }
    }
  }

  class KeyPair
  {
  private:
    static constexpr size_t MAX_SIZE_PEM = 2048;

    struct SignCsr
    {
      Entropy entropy;
      mbedtls_x509_csr csr;
      mbedtls_mpi serial;
      mbedtls_x509write_cert crt;

      SignCsr()
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

    const CurveParams params;

  public:
    /**
     * Create a new public / private key pair
     */
    KeyPair(const CurveParams& cp) : params(cp)
    {
      Entropy entropy;
      mbedtls_pk_init(key.get());

      switch (params.ecp_group_id)
      {
        case MBEDTLS_ECP_DP_CURVE25519:
        case MBEDTLS_ECP_DP_CURVE448:
          // These curves are technically not ECDSA, but EdDSA.
          if (
            mbedtls_pk_setup(
              key.get(), mbedtls_pk_info_from_type(MBEDTLS_PK_EDDSA)) != 0)
            throw std::logic_error("Could not set up EdDSA context");

          if (
            mbedtls_eddsa_genkey(
              mbedtls_pk_eddsa(*key),
              params.ecp_group_id,
              &Entropy::rng,
              &entropy) != 0)
            throw std::logic_error("Could not generate EdDSA keypair");
          break;

        default:
          if (
            mbedtls_pk_setup(
              key.get(), mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0)
            throw std::logic_error("Could not set up ECDSA context");

          if (
            mbedtls_ecp_gen_key(
              params.ecp_group_id,
              mbedtls_pk_ec(*key),
              &Entropy::rng,
              &entropy) != 0)
            throw std::logic_error("Could not generate ECDSA keypair");
      }
    }

    /**
     * Initialise from just a private key
     */
    KeyPair(const CurveParams& cp, CBuffer pkey, CBuffer pw = nullb) :
      params(cp)
    {
      mbedtls_pk_init(key.get());

      Pem pemPk(pkey);
      if (mbedtls_pk_parse_key(key.get(), pemPk.p, pemPk.n, pw.p, pw.n) != 0)
      {
        throw std::logic_error("Could not parse key");
      }
    }

    KeyPair(const KeyPair&) = delete;
    // KeyPair(KeyPair&& other)
    // {
    //   key = std::move(other.key);
    //   params = std::move(other.params);
    // }

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
      do_hash(params.ecp_group_id, d.p, d.rawSize(), hash);

      return sign_hash(hash);
    }

    /**
     * Write signature over hash of data, and the size of that signature to
     * specified locations.
     *
     * Important: While sig_size will always be written to as a single
     * uint8_t, sig must point somewhere that's at least
     * MBEDTLS_E{C,D}DSA_MAX_LEN.
     *
     * @param d data
     * @param sig_size location to which the signature size will be written
     * @param sig location to which the signature will be written
     *
     * @return 0 if successful, error code of mbedtls_pk_sign otherwise,
     *         or 0xf if the signature_size exceeds that of a uint8_t.
     */
    int sign(CBuffer d, uint8_t* sig_size, uint8_t* sig) const
    {
      HashBytes hash;
      do_hash(params.ecp_group_id, d.p, d.rawSize(), hash);

      return sign_hash(hash, sig_size, sig);
    }

    /**
     * Create signature over hashed data.
     *
     * @param hash Data to be signed. Should be of expected length for this
     * key's signature algorithm
     *
     * @return Signature as a vector
     */
    virtual std::vector<uint8_t> sign_hash(const HashBytes& hash) const
    {
      uint8_t sig[MBEDTLS_ECDSA_MAX_LEN];

      uint8_t written = 0;
      if (sign_hash(hash, &written, sig) != 0)
      {
        return {};
      }

      return {sig, sig + written};
    }

    virtual int sign_hash(
      const HashBytes& hash, uint8_t* sig_size, uint8_t* sig) const
    {
      int rc = 0;
      Entropy entropy;

      size_t written = 0;

      if (params.ecp_group_id == MBEDTLS_ECP_DP_SECP256K1)
      {
        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);

        rc = mbedtls_ecdsa_from_keypair(&ecdsa, mbedtls_pk_ec(*key));
        if (rc != 0)
          return rc;

        rc = mbedtls_ecdsa_write_signature(
          &ecdsa,
          params.md_type,
          hash.data(),
          hash.size(),
          sig,
          &written,
          &Entropy::rng,
          &entropy);
      }
      else
      {
        rc = mbedtls_pk_sign(
          key.get(),
          params.md_type,
          hash.data(),
          hash.size(),
          sig,
          &written,
          &Entropy::rng,
          &entropy);
      }

      if (rc == 0 && written > std::numeric_limits<uint8_t>::max())
        rc = 0xf;

      *sig_size = written;

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
      Entropy entropy;

      if (
        mbedtls_x509write_csr_pem(
          &csr.req, buf, sizeof(buf), &Entropy::rng, &entropy) != 0)
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

      mbedtls_x509write_crt_set_md_alg(&sign.crt, params.md_type);
      mbedtls_x509write_crt_set_subject_key(&sign.crt, &sign.csr.pk);
      mbedtls_x509write_crt_set_issuer_key(&sign.crt, key.get());

      if (
        mbedtls_mpi_fill_random(
          &sign.serial, 16, &Entropy::rng, &sign.entropy) != 0)
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
          &sign.crt, buf, sizeof(buf), &Entropy::rng, &sign.entropy) != 0)
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
  };

  class KeyPair_k1Bitcoin : public KeyPair
  {
  protected:
    secp256k1_context* k1_ctx = secp256k1_context_create(
      SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    static constexpr size_t privk_size = 32;
    uint8_t c4_priv[privk_size] = {0};

  public:
    KeyPair_k1Bitcoin(const CurveParams& cp) : KeyPair(cp)
    {
      if (
        mbedtls_mpi_write_binary(
          &(mbedtls_pk_ec(*key)->d), c4_priv, privk_size) != 0)
        throw std::logic_error("Could not extract raw private key");

      if (secp256k1_ec_seckey_verify(k1_ctx, c4_priv) != 1)
        throw std::logic_error("secp256k1 private key is not valid");
    }

    KeyPair_k1Bitcoin(const CurveParams& cp, CBuffer pkey, CBuffer pw = nullb) :
      KeyPair(cp, pkey, pw)
    {
      if (
        mbedtls_mpi_write_binary(
          &(mbedtls_pk_ec(*key)->d), c4_priv, privk_size) != 0)
        throw std::logic_error("Could not extract raw private key");

      if (secp256k1_ec_seckey_verify(k1_ctx, c4_priv) != 1)
        throw std::logic_error("secp256k1 private key is not valid");
    }

    ~KeyPair_k1Bitcoin()
    {
      if (k1_ctx)
        secp256k1_context_destroy(k1_ctx);
    }

    int sign_hash(
      const HashBytes& hash, uint8_t* sig_size, uint8_t* sig) const override
    {
      secp256k1_ecdsa_signature k1_sig;
      if (
        secp256k1_ecdsa_sign(
          k1_ctx, &k1_sig, hash.data(), c4_priv, nullptr, nullptr) != 1)
        return -1;

      size_t written = MBEDTLS_ECDSA_MAX_LEN;
      if (
        secp256k1_ecdsa_signature_serialize_der(
          k1_ctx, sig, &written, &k1_sig) != 1)
        return -2;

      *sig_size = written;
      return 0;
    }
  };

  using KeyPairPtr = std::shared_ptr<KeyPair>;

  template <typename... Ts>
  KeyPairPtr make_key_pair(CurveImpl curve, Ts... ts)
  {
    const auto& params = get_curve_params(curve);

    if (curve == CurveImpl::secp256k1_bitcoin)
    {
      return KeyPairPtr(new KeyPair_k1Bitcoin(params, std::forward<Ts>(ts)...));
    }
    else
    {
      return KeyPairPtr(new KeyPair(params, std::forward<Ts>(ts)...));
    }
  }

  class PublicKey
  {
  protected:
    mbedtls_pk_context ctx;

    const CurveParams params;

  public:
    /**
     * Construct from a public key in PEM format
     *
     * @param public_pem Sequence of bytes containing the key in PEM format
     */
    PublicKey(const CurveParams& cp, const std::vector<uint8_t>& public_pem) :
      params(cp)
    {
      mbedtls_pk_init(&ctx);
      mbedtls_pk_parse_public_key(&ctx, public_pem.data(), public_pem.size());
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
     *
     * @return Whether the signature matches the contents and the key
     */
    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size)
    {
      HashBytes hash;
      do_hash(params.ecp_group_id, contents, contents_size, hash);

      return (
        mbedtls_pk_verify(
          &ctx, params.md_type, hash.data(), hash.size(), sig, sig_size) == 0);
    }

    virtual ~PublicKey()
    {
      mbedtls_pk_free(&ctx);
    }
  };

  class PublicKey_k1Bitcoin : public PublicKey
  {
  protected:
    secp256k1_context* k1_ctx = secp256k1_context_create(
      SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    secp256k1_pubkey c4_pub;

  public:
    PublicKey_k1Bitcoin(
      const CurveParams& cp, const std::vector<uint8_t>& public_pem) :
      PublicKey(cp, public_pem)
    {
      auto k = mbedtls_pk_ec(ctx);
      size_t pub_len;
      uint8_t pub_buf[100];

      int rc = mbedtls_ecp_point_write_binary(
        &k->grp, &k->Q, MBEDTLS_ECP_PF_COMPRESSED, &pub_len, pub_buf, 100);
      if (rc)
        throw std::logic_error("mbedtls_ecp_point_write_binary failed");

      rc = secp256k1_ec_pubkey_parse(k1_ctx, &c4_pub, pub_buf, pub_len);
      if (rc != 1)
        throw std::logic_error("ecp256k1_ec_pubkey_parse failed");
    }

    ~PublicKey_k1Bitcoin()
    {
      if (k1_ctx)
        secp256k1_context_destroy(k1_ctx);
    }

    bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size) override
    {
      HashBytes hash;
      do_hash(params.ecp_group_id, contents, contents_size, hash);

      return verify_secp256k_bc(k1_ctx, sig, sig_size, hash.data(), &c4_pub);
    }
  };

  using PublicKeyPtr = std::shared_ptr<PublicKey>;

  template <typename... Ts>
  PublicKeyPtr make_public_key(CurveImpl curve, Ts... ts)
  {
    const auto& params = get_curve_params(curve);

    if (curve == CurveImpl::secp256k1_bitcoin)
    {
      return PublicKeyPtr(
        new PublicKey_k1Bitcoin(params, std::forward<Ts>(ts)...));
    }
    else
    {
      return PublicKeyPtr(new PublicKey(params, std::forward<Ts>(ts)...));
    }
  }

  class Verifier
  {
  protected:
    mutable mbedtls_x509_crt cert;

    // TODO: Remove this, should be retrievable from cert
    const CurveParams params;

  public:
    /**
     * Construct from a pre-parsed cert
     *
     * @param c Initialised and parsed x509 cert
     */
    Verifier(const CurveParams& cp, const mbedtls_x509_crt& c) :
      cert(c),
      params(cp)
    {}

    Verifier(const Verifier&) = delete;

    /**
     * Verify that a signature was produced on a hash with the private key
     * associated with the public key contained in the certificate.
     *
     * @param hash Hash produced from contents as a sequence of bytes
     * @param signature Signature as a sequence of bytes
     *
     * @return Whether the signature matches the hash and the key
     */
    virtual bool verify_hash(
      const std::vector<uint8_t>& hash,
      const std::vector<uint8_t>& signature) const
    {
      int rc = mbedtls_pk_verify(
        &cert.pk,
        params.md_type,
        hash.data(),
        hash.size(),
        signature.data(),
        signature.size());

      if (rc)
        LOG_DEBUG_FMT("Failed to verify signature: {}", rc);

      return rc == 0;
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
      do_hash(params.ecp_group_id, contents.data(), contents.size(), hash);

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

    virtual CurveImpl get_curve() const
    {
      switch (params.ecp_group_id)
      {
        case MBEDTLS_ECP_DP_SECP384R1:
        {
          return CurveImpl::secp384r1;
        }
        case MBEDTLS_ECP_DP_CURVE25519:
        {
          return CurveImpl::curve25519;
        }
        case MBEDTLS_ECP_DP_SECP256K1:
        {
          return CurveImpl::secp256k1_mbedtls;
        }
        default:
        {
          throw std::logic_error("Unhandled curve type");
        }
      }
    }

    virtual ~Verifier()
    {
      mbedtls_x509_crt_free(&cert);
    }
  };

  class Verifier_k1Bitcoin : public Verifier
  {
  protected:
    secp256k1_context* k1_ctx =
      secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey c4_pub;

  public:
    Verifier_k1Bitcoin(const CurveParams& cp, const mbedtls_x509_crt& c) :
      Verifier(cp, c)
    {
      auto k = mbedtls_pk_ec(cert.pk);
      size_t pub_len;
      uint8_t pub_buf[100];

      int rc = mbedtls_ecp_point_write_binary(
        &k->grp, &k->Q, MBEDTLS_ECP_PF_COMPRESSED, &pub_len, pub_buf, 100);
      if (rc)
        throw std::logic_error("mbedtls_ecp_point_write_binary failed");

      rc = secp256k1_ec_pubkey_parse(k1_ctx, &c4_pub, pub_buf, pub_len);
      if (rc != 1)
        throw std::logic_error("ecp256k1_ec_pubkey_parse failed");
    }

    bool verify_hash(
      const std::vector<uint8_t>& hash,
      const std::vector<uint8_t>& signature) const override
    {
      int rc = verify_secp256k_bc(
        k1_ctx, signature.data(), signature.size(), hash.data(), &c4_pub);

      if (rc)
        LOG_DEBUG_FMT("Failed to verify signature: {}", rc);

      return rc;
    }

    CurveImpl get_curve() const override
    {
      return CurveImpl::secp256k1_bitcoin;
    }

    ~Verifier_k1Bitcoin()
    {
      if (k1_ctx)
        secp256k1_context_destroy(k1_ctx);
    }
  };

  using VerifierPtr = std::shared_ptr<Verifier>;

  /**
   * Construct Verifier from a certificate in PEM format
   *
   * @param public_pem Sequence of bytes containing the certificate in PEM
   * format
   */
  VerifierPtr make_verifier(const std::vector<uint8_t>& cert_pem)
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

    const auto curve = mbedtls_pk_ec(cert.pk)->grp.id;

    switch (curve)
    {
      case MBEDTLS_ECP_DP_SECP384R1:
      {
        return VerifierPtr(new Verifier(params_secp384r1, cert));
      }
      case MBEDTLS_ECP_DP_CURVE25519:
      {
        return VerifierPtr(new Verifier(params_curve25519, cert));
      }
      case MBEDTLS_ECP_DP_SECP256K1:
      {
#if PREFER_BITCOIN_SECP256K1
        return VerifierPtr(
          new Verifier_k1Bitcoin(params_secp256k1_bitcoin, cert));
#else
        return VerifierPtr(new Verifier(params_secp256k1_mbedtls, cert));
#endif
      }
      default:
      {
        throw std::logic_error("Unhandled curve type");
      }
    }
  }
}
