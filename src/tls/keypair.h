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

#if CURVE_CHOICE_SECP384R1

#  define HASH(data_ptr, data_size, hash_ptr) \
    do \
    { \
      mbedtls_sha512_ret(data_ptr, data_size, hash_ptr, true); \
    } while (0)

#elif CURVE_CHOICE_CURVE25519

#  define HASH(data_ptr, data_size, hash_ptr) \
    do \
    { \
      mbedtls_sha512_ret(data_ptr, data_size, hash_ptr, false); \
    } while (0)

#elif CURVE_CHOICE_SECP256K1_MBEDTLS || CURVE_CHOICE_SECP256K1_BITCOIN

#  define HASH(data_ptr, data_size, hash_ptr) \
    do \
    { \
      mbedtls_sha256_ret(data_ptr, data_size, hash_ptr, false); \
    } while (0)

#endif

namespace tls
{
#if CURVE_CHOICE_SECP384R1
  static constexpr mbedtls_md_type_t MD_TYPE = MBEDTLS_MD_SHA384;
  static constexpr size_t MD_SIZE = 384 / 8;
#elif CURVE_CHOICE_CURVE25519
  static constexpr mbedtls_md_type_t MD_TYPE = MBEDTLS_MD_SHA512;
  static constexpr size_t MD_SIZE = 512 / 8;
#elif CURVE_CHOICE_SECP256K1_MBEDTLS || CURVE_CHOICE_SECP256K1_BITCOIN
  static constexpr mbedtls_md_type_t MD_TYPE = MBEDTLS_MD_SHA256;
  static constexpr size_t MD_SIZE = 256 / 8;
#endif

  static constexpr size_t REC_ID_IDX = 64;

  using Hash = std::array<uint8_t, MD_SIZE>;

  inline bool verify_secp256k_bc(
    secp256k1_context* ctx, const uint8_t* signature, const uint8_t* hash)
  {
    secp256k1_pubkey public_key;
    secp256k1_ecdsa_recoverable_signature sig;

    if (
      secp256k1_ecdsa_recoverable_signature_parse_compact(
        ctx, &sig, signature, signature[REC_ID_IDX]) != 1)
    {
      LOG_INFO_FMT(
        "secp256k1_ecdsa_recoverable_signature_parse_compact failed");
      return false;
    }

    secp256k1_ecdsa_signature nsig;
    if (secp256k1_ecdsa_recover(ctx, &public_key, &sig, hash) != 1)
    {
      LOG_INFO_FMT("secp256k1_ecdsa_sign_recoverable failed");
      return false;
    }
    if (secp256k1_ecdsa_recoverable_signature_convert(ctx, &nsig, &sig) != 1)
    {
      LOG_INFO_FMT("secp256k1_ecdsa_recoverable_signature_convert failed");
      return false;
    }
    if (secp256k1_ecdsa_verify(ctx, &nsig, hash, &public_key) != 1)
    {
      LOG_INFO_FMT("secp256k1_ecdsa_verify failed");
      return false;
    }
    return true;
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

#if CURVE_CHOICE_SECP256K1_BITCOIN
    secp256k1_context* ctx = secp256k1_context_create(
      SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    static constexpr size_t PK_SIZE = 32;
    uint8_t c4_priv[PK_SIZE] = {0};
#endif

  public:
    /**
     * Create a new public / private key pair
     */
    KeyPair(
      mbedtls_ecp_group_id ec =
#if CURVE_CHOICE_SECP384R1
        MBEDTLS_ECP_DP_SECP384R1
#elif CURVE_CHOICE_CURVE25519
        MBEDTLS_ECP_DP_CURVE25519
#elif CURVE_CHOICE_SECP256K1_MBEDTLS || CURVE_CHOICE_SECP256K1_BITCOIN
        MBEDTLS_ECP_DP_SECP256K1
#endif
    )
    {
      Entropy entropy;
      mbedtls_pk_init(key.get());

      switch (ec)
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
              mbedtls_pk_eddsa(*key), ec, &Entropy::rng, &entropy) != 0)
            throw std::logic_error("Could not generate EdDSA keypair");
          break;
        default:
          if (
            mbedtls_pk_setup(
              key.get(), mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0)
            throw std::logic_error("Could not set up ECDSA context");

          if (
            mbedtls_ecp_gen_key(
              ec, mbedtls_pk_ec(*key), &Entropy::rng, &entropy) != 0)
            throw std::logic_error("Could not generate ECDSA keypair");
      }

#if CURVE_CHOICE_SECP256K1_BITCOIN
      if (
        mbedtls_mpi_write_binary(&(mbedtls_pk_ec(*key)->d), c4_priv, PK_SIZE) !=
        0)
        throw std::logic_error("Could not extract raw private key");
#endif
    }

    KeyPair(const KeyPair&) = delete;
    KeyPair(KeyPair&& other)
    {
      key = std::move(other.key);
      other.key = nullptr;
#if CURVE_CHOICE_SECP256K1_BITCOIN
      ctx = std::move(other.ctx);
      other.ctx = nullptr;
#endif
    }

    /**
     * Initialise from just a private key
     */
    KeyPair(CBuffer pkey, CBuffer pw = nullb)
    {
      mbedtls_pk_init(key.get());

      Pem pemPk(pkey);
      if (mbedtls_pk_parse_key(key.get(), pemPk.p, pemPk.n, pw.p, pw.n) != 0)
      {
        throw std::logic_error("Could not parse key");
      }

#if CURVE_CHOICE_SECP256K1_BITCOIN
      if (
        mbedtls_mpi_write_binary(&(mbedtls_pk_ec(*key)->d), c4_priv, PK_SIZE) !=
        0)
        throw std::logic_error("Could not extract raw private key");
#endif
    }

    ~KeyPair()
    {
      if (key)
        mbedtls_pk_free(key.get());
#if CURVE_CHOICE_SECP256K1_BITCOIN
      if (ctx)
        secp256k1_context_destroy(ctx);
#endif
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
     * Create signature over data from private key.
     *
     * @param d data
     *
     * @return Signature as a vector
     */
    std::vector<uint8_t> sign(CBuffer d) const
    {
      Hash hash;
      HASH(d.p, d.rawSize(), hash.data());

      Entropy entropy;
      uint8_t sig[MBEDTLS_ECDSA_MAX_LEN];
      size_t written = 0;

#if CURVE_CHOICE_SECP256K1_BITCOIN
      int rc = 0;
      secp256k1_ecdsa_recoverable_signature sig_;
      rc = secp256k1_ecdsa_sign_recoverable(
        ctx, &sig_, hash.data(), c4_priv, nullptr, nullptr);
      if (rc != 1)
      {
        LOG_FAIL_FMT("secp256k1_ecdsa_sign_recoverable failed with {}", rc);
        return {};
      }
      int rcode = 0;
      rc = secp256k1_ecdsa_recoverable_signature_serialize_compact(
        ctx, sig, &rcode, &sig_);
      if (rc != 1)
      {
        LOG_FAIL_FMT(
          "secp256k1_ecdsa_recoverable_signature_serialize_compact failed with "
          "{}",
          rc);
        return {};
      }
      sig[REC_ID_IDX] = static_cast<uint8_t>(rcode);
      written = REC_ID_IDX + 1;
#else
      if (
        mbedtls_pk_sign(
          key.get(),
          MD_TYPE,
          hash.data(),
          hash.size(),
          sig,
          &written,
          &Entropy::rng,
          &entropy) != 0)
      {
        return {};
      }
#endif
      return {sig, sig + written};
    }

    /**
     * Write signature over data, and the size of that signature to
     * specified locations.
     *
     * Important: While sig_size will always be written to as a single
     * unint8_t, sig must point somewhere that's at least
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
      Hash hash;
      HASH(d.p, d.rawSize(), hash.data());

      size_t written = 0;
#if CURVE_CHOICE_SECP256K1_BITCOIN
      int rc = 0;
      secp256k1_ecdsa_recoverable_signature sig_;
      if (
        secp256k1_ecdsa_sign_recoverable(
          ctx, &sig_, hash.data(), c4_priv, nullptr, nullptr) != 1)
        rc = 0xf;
      int rcode;
      if (
        secp256k1_ecdsa_recoverable_signature_serialize_compact(
          ctx, sig, &rcode, &sig_) != 1)
        rc = 0xf;
      sig[REC_ID_IDX] = static_cast<uint8_t>(rcode);
      written = REC_ID_IDX + 1;
#else
      Entropy entropy;

      int rc = mbedtls_pk_sign(
                 key.get(),
                 MD_TYPE,
                 hash.data(),
                 hash.size(),
                 sig,
                 &written,
                 &Entropy::rng,
                 &entropy) != 0;

      if (!rc && written > std::numeric_limits<uint8_t>::max())
        rc = 0xf;

      *sig_size = written;
#endif
      return rc;
    }

    std::vector<uint8_t> sign_hash(const crypto::Sha256Hash& hash) const
    {
      Entropy entropy;
      uint8_t sig[MBEDTLS_ECDSA_MAX_LEN];

      size_t written = 0;
#if CURVE_CHOICE_SECP256K1_BITCOIN
      int rc = 0;
      secp256k1_ecdsa_recoverable_signature sig_;
      rc = secp256k1_ecdsa_sign_recoverable(
        ctx, &sig_, hash.h, c4_priv, nullptr, nullptr);
      if (rc != 1)
      {
        LOG_FAIL_FMT("secp256k1_ecdsa_sign_recoverable failed with {}", rc);
        return {};
      }
      int rcode = 0;
      rc = secp256k1_ecdsa_recoverable_signature_serialize_compact(
        ctx, sig, &rcode, &sig_);
      if (rc != 1)
      {
        LOG_FAIL_FMT(
          "secp256k1_ecdsa_recoverable_signature_serialize_compact failed with "
          "{}",
          rc);
        return {};
      }
      sig[REC_ID_IDX] = static_cast<uint8_t>(rcode);
      written = REC_ID_IDX + 1;
#else

      if (
        mbedtls_pk_sign(
          key.get(),
          MD_TYPE,
          hash.h,
          hash.SIZE,
          sig,
          &written,
          &Entropy::rng,
          &entropy) != 0)
      {
        return {};
      }
#endif

      return {sig, sig + written};
    }

    /**
     * Create a certificate signing request for this key pair. If we were loaded
     * from a private key, there will be no public key available for this call.
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

      mbedtls_x509write_crt_set_md_alg(&sign.crt, MD_TYPE);
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

  class PublicKey
  {
  protected:
    mbedtls_pk_context ctx;

#if CURVE_CHOICE_SECP256K1_BITCOIN
    secp256k1_context* ctx_ = secp256k1_context_create(
      SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey c4_pub;
#endif

  public:
    /**
     * Construct from a public key in PEM format
     *
     * @param public_pem Sequence of bytes containing the key in PEM format
     */
    PublicKey(const std::vector<uint8_t>& public_pem)
    {
      mbedtls_pk_init(&ctx);
      mbedtls_pk_parse_public_key(&ctx, public_pem.data(), public_pem.size());

#if CURVE_CHOICE_SECP256K1_BITCOIN
      auto k = mbedtls_pk_ec(ctx);
      size_t pub_len;
      uint8_t pub_buf[100];
      int rc = mbedtls_ecp_point_write_binary(
        &k->grp, &k->Q, MBEDTLS_ECP_PF_COMPRESSED, &pub_len, pub_buf, 100);
      if (rc)
        throw std::logic_error("mbedtls_ecp_point_write_binary failed");
      rc = secp256k1_ec_pubkey_parse(ctx_, &c4_pub, pub_buf, pub_len);
      if (rc != 1)
        throw std::logic_error("ecp256k1_ec_pubkey_parse failed");
#endif
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
      Hash hash;
      HASH(contents.data(), contents.size(), hash.data());

#if CURVE_CHOICE_SECP256K1_BITCOIN
      if (signature.size() != REC_ID_IDX + 1)
        return false;
      return verify_secp256k_bc(ctx_, signature.data(), hash.data());
#else
      auto rc = mbedtls_pk_verify(
        &ctx,
        MD_TYPE,
        hash.data(),
        hash.size(),
        signature.data(),
        signature.size());

      if (rc)
        LOG_DEBUG_FMT("Failed to verify signature: {}", rc);

      return rc;
#endif
    }

    /**
     * Verify that a signature was produced on contents with the private key
     * associated with the public key held by the object.
     *
     * @param contents address of contents
     * @param contents_size size of contents
     * @param contents address of signature
     * @param contents_size size of signature
     *
     * @return Whether the signature matches the contents and the key
     */
    bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      uint8_t sig_size)
    {
      Hash hash;
      HASH(contents, contents_size, hash.data());

#if CURVE_CHOICE_SECP256K1_BITCOIN
      return verify_secp256k_bc(ctx_, sig, hash.data());
#else

      return (
        mbedtls_pk_verify(
          &ctx, MD_TYPE, hash.data(), hash.size(), sig, sig_size) == 0);
#endif
    }

    ~PublicKey()
    {
      mbedtls_pk_free(&ctx);
#if CURVE_CHOICE_SECP256K1_BITCOIN
      if (ctx_)
        secp256k1_context_destroy(ctx_);
#endif
    }
  };

  class Verifier
  {
  protected:
    mutable mbedtls_x509_crt cert;

#if CURVE_CHOICE_SECP256K1_BITCOIN
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey c4_pub;
#endif

  public:
    Verifier(const Verifier&) = delete;

    /**
     * Construct from a certificate in PEM format
     *
     * @param public_pem Sequence of bytes containing the certificate in PEM
     * format
     */
    Verifier(const std::vector<uint8_t>& cert_pem)
    {
      mbedtls_x509_crt_init(&cert);
      int rc = mbedtls_x509_crt_parse(&cert, cert_pem.data(), cert_pem.size());
      if (rc)
      {
        std::stringstream s;
        s << "Failed to parse certificate: " << rc;
        throw std::invalid_argument(s.str());
      }

#if CURVE_CHOICE_SECP256K1_BITCOIN
      auto k = mbedtls_pk_ec(cert.pk);
      size_t pub_len;
      uint8_t pub_buf[100];
      rc = mbedtls_ecp_point_write_binary(
        &k->grp, &k->Q, MBEDTLS_ECP_PF_COMPRESSED, &pub_len, pub_buf, 100);
      if (rc)
        throw std::logic_error("mbedtls_ecp_point_write_binary failed");
      rc = secp256k1_ec_pubkey_parse(ctx, &c4_pub, pub_buf, pub_len);
      if (rc != 1)
        throw std::logic_error("ecp256k1_ec_pubkey_parse failed");
#endif
    }

    /**
     * Verify that a signature was produced on a hash with the private key
     * associated with the public key contained in the certificate.
     *
     * @param contents Sequence of bytes that was signed
     * @param signature Signature as a sequence of bytes
     *
     * @return Whether the signature matches the contents and the key
     */
    bool verify_hash(
      const crypto::Sha256Hash& hash,
      const std::vector<uint8_t>& signature) const
    {
#if CURVE_CHOICE_SECP256K1_BITCOIN
      if (signature.size() != REC_ID_IDX + 1)
        return false;
      return verify_secp256k_bc(ctx, signature.data(), hash.h);
#else
      int rc = mbedtls_pk_verify(
        &cert.pk,
        MD_TYPE,
        hash.h,
        hash.SIZE,
        signature.data(),
        signature.size());

      if (rc)
        LOG_DEBUG_FMT("Failed to verify signature: {}", rc);

      return rc == 0;
#endif
    }

    /**
     * Verify that a signature was produced on a hash with the private key
     * associated with the public key contained in the certificate.
     *
     * @param contents Sequence of bytes that was signed
     * @param signature Signature as a sequence of bytes
     *
     * @return Whether the signature matches the contents and the key
     */
    bool verify_hash(
      const Hash& hash, const std::vector<uint8_t>& signature) const
    {
#if CURVE_CHOICE_SECP256K1_BITCOIN
      if (signature.size() != REC_ID_IDX + 1)
        return false;
      return verify_secp256k_bc(ctx, signature.data(), hash.data());
#else
      int rc = mbedtls_pk_verify(
        &cert.pk,
        MD_TYPE,
        hash.data(),
        hash.size(),
        signature.data(),
        signature.size());

      if (rc)
        LOG_DEBUG_FMT("Failed to verify signature: {}", rc);

      return rc == 0;
#endif
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
      Hash hash;
      HASH(contents.data(), contents.size(), hash.data());

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

    ~Verifier()
    {
      mbedtls_x509_crt_free(&cert);
#if CURVE_CHOICE_SECP256K1_BITCOIN
      if (ctx)
        secp256k1_context_destroy(ctx);
#endif
    }
  };
}
