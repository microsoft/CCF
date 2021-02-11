// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "key_pair_base.h"
#include "mbedtls_wrappers.h"

#include <mbedtls/bignum.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>

namespace tls
{
  class PublicKey_mbedTLS : public PublicKeyBase
  {
  protected:
    mbedtls::PKContext ctx = mbedtls::make_unique<mbedtls::PKContext>();

    PublicKey_mbedTLS() {}

    inline mbedtls_md_type_t get_md_type(MDType mdt) const
    {
      switch (mdt)
      {
        case MDType::NONE:
          return MBEDTLS_MD_NONE;
        case MDType::SHA1:
          return MBEDTLS_MD_SHA1;
        case MDType::SHA256:
          return MBEDTLS_MD_SHA256;
        case MDType::SHA384:
          return MBEDTLS_MD_SHA384;
        case MDType::SHA512:
          return MBEDTLS_MD_SHA512;
        default:
          return MBEDTLS_MD_NONE;
      }
      return MBEDTLS_MD_NONE;
    }

  public:
    PublicKey_mbedTLS(PublicKey_mbedTLS&& pk) = default;

    /**
     * Construct from PEM
     */
    PublicKey_mbedTLS(const Pem& pem)
    {
      int rc = mbedtls_pk_parse_public_key(ctx.get(), pem.data(), pem.size());

      if (rc != 0)
      {
        throw std::logic_error(fmt::format(
          "Could not parse public key PEM: {}\n\n(Key: {})",
          error_string(rc),
          pem.str()));
      }
    }

    /**
     * Construct from DER
     */
    PublicKey_mbedTLS(const std::vector<uint8_t>& der)
    {
      int rc = mbedtls_pk_parse_public_key(ctx.get(), der.data(), der.size());

      if (rc != 0)
      {
        throw std::logic_error(
          fmt::format("Could not parse public key DER: {}", error_string(rc)));
      }
    }

    virtual CurveID get_curve_id() const override
    {
      return get_curve_id(ctx.get());
    }

    static CurveID get_curve_id(const mbedtls_pk_context* pk_ctx)
    {
      if (mbedtls_pk_can_do(pk_ctx, MBEDTLS_PK_ECKEY))
      {
        auto grp_id = mbedtls_pk_ec(*pk_ctx)->grp.id;
        switch (grp_id)
        {
          case MBEDTLS_ECP_DP_SECP384R1:
            return CurveID::SECP384R1;
          case MBEDTLS_ECP_DP_SECP256R1:
            return CurveID::SECP256R1;
          default:
            throw std::logic_error(
              fmt::format("unsupported mbedTLS group ID {}", grp_id));
        }
      }

      return CurveID::NONE;
    }

    /**
     * Construct from a pre-initialised pk context
     */
    PublicKey_mbedTLS(mbedtls::PKContext&& c) : ctx(std::move(c)) {}

    virtual ~PublicKey_mbedTLS() = default;

    using PublicKeyBase::verify;
    using PublicKeyBase::verify_hash;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type,
      HashBytes& bytes) override
    {
      if (md_type == MDType::NONE)
      {
        md_type = get_md_for_ec(get_curve_id());
      }
      MBedHashProvider hp;
      bytes = hp.Hash(contents, contents_size, md_type);
      return verify_hash(bytes.data(), bytes.size(), sig, sig_size, md_type);
    }

    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type) override
    {
      if (md_type == MDType::NONE)
      {
        md_type = get_md_for_ec(get_curve_id(), true);
      }

      // mbedTLS wants an MD algorithm; even when it doesn't use it, it still
      // checks that the hash size matches.
      const auto mmdt = get_md_type(md_type);

      int rc =
        mbedtls_pk_verify(ctx.get(), mmdt, hash, hash_size, sig, sig_size);

      if (rc)
        LOG_DEBUG_FMT("Failed to verify signature: {}", error_string(rc));

      return rc == 0;
    }

    /**
     * Get the public key in PEM format
     */
    virtual Pem public_key_pem() const override
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

  class KeyPair_mbedTLS : public PublicKey_mbedTLS, public KeyPairBase
  {
  public:
    inline mbedtls_ecp_group_id get_mbedtls_group_id(CurveID gid)
    {
      switch (gid)
      {
        case CurveID::NONE:
          return MBEDTLS_ECP_DP_NONE;
        case CurveID::SECP384R1:
          return MBEDTLS_ECP_DP_SECP384R1;
        case CurveID::SECP256R1:
          return MBEDTLS_ECP_DP_SECP256R1;
        default:
          throw std::logic_error(fmt::format("unsupported CurveID {}", gid));
      }
      return MBEDTLS_ECP_DP_NONE;
    }

    /**
     * Create a new public / private ECDSA key pair
     */
    KeyPair_mbedTLS(CurveID cid) : PublicKey_mbedTLS()
    {
      mbedtls_ecp_group_id ec = get_mbedtls_group_id(cid);
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

      const auto actual_ec = get_mbedtls_ec_from_context(*ctx);
      if (actual_ec != ec)
      {
        throw std::logic_error(
          "Created key and received unexpected type: " +
          std::to_string(actual_ec) + " != " + error_string(ec));
      }
    }

    KeyPair_mbedTLS(const Pem& pem, CBuffer pw = nullb)
    {
      // keylen is +1 to include terminating null byte
      int rc =
        mbedtls_pk_parse_key(ctx.get(), pem.data(), pem.size(), pw.p, pw.n);
      if (rc != 0)
      {
        throw std::logic_error(
          "Could not parse private key: " + error_string(rc));
      }
    }

    /**
     * Initialise from existing pre-parsed key
     */
    KeyPair_mbedTLS(mbedtls::PKContext&& k) : PublicKey_mbedTLS(std::move(k)) {}

    KeyPair_mbedTLS(const KeyPair_mbedTLS&) = delete;

    using PublicKey_mbedTLS::verify;

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature) override
    {
      return PublicKey_mbedTLS::verify(contents, signature);
    }

    /**
     * Get the private key in PEM format
     */
    virtual Pem private_key_pem() const override
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
     * Get the public key in PEM format
     */
    virtual Pem public_key_pem() const override
    {
      return PublicKey_mbedTLS::public_key_pem();
    }

    /**
     * Create signature over hash of data from private key.
     *
     * @param d data
     *
     * @return Signature as a vector
     */
    virtual std::vector<uint8_t> sign(
      CBuffer d, MDType md_type = {}) const override
    {
      if (md_type == MDType::NONE)
      {
        md_type = get_md_for_ec(get_curve_id());
      }
      MBedHashProvider hp;
      HashBytes hash = hp.Hash(d.p, d.rawSize(), md_type);
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
      CBuffer d, size_t* sig_size, uint8_t* sig, MDType md_type = {}) const
    {
      if (md_type == MDType::NONE)
      {
        md_type = get_md_for_ec(get_curve_id());
      }
      MBedHashProvider hp;
      HashBytes hash = hp.Hash(d.p, d.rawSize(), md_type);
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
    std::vector<uint8_t> sign_hash(
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

    virtual int sign_hash(
      const uint8_t* hash,
      size_t hash_size,
      size_t* sig_size,
      uint8_t* sig) const override
    {
      EntropyPtr entropy = create_entropy();

      // mbedTLS wants an MD algorithm; even when it doesn't use it, it stil
      // checks that the hash size matches.
      const auto mmdt = get_md_type(get_md_for_ec(get_curve_id()));

      int r = mbedtls_pk_sign(
        ctx.get(),
        mmdt,
        hash,
        hash_size,
        sig,
        sig_size,
        entropy->get_rng(),
        entropy->get_data());

      return r;
    }

    /**
     * Create a certificate signing request for this key pair. If we were
     * loaded from a private key, there will be no public key available for
     * this call.
     */
    virtual Pem create_csr(const std::string& name) const override
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

    void MCHK(int rc) const
    {
      if (rc != 0)
      {
        throw std::logic_error(fmt::format("mbedTLS error: {}", error_string(rc)));
      }
    }

    virtual Pem sign_csr(
      const Pem& issuer_cert,
      const Pem& signing_request,
      const std::vector<SubjectAltName> subject_alt_names,
      bool ca = false) const override
    {
      auto entropy = create_entropy();
      auto csr = mbedtls::make_unique<mbedtls::X509Csr>();
      auto serial = mbedtls::make_unique<mbedtls::MPI>();
      auto crt = mbedtls::make_unique<mbedtls::X509WriteCrt>();
      auto icrt = mbedtls::make_unique<mbedtls::X509Crt>();

      std::cout << "CSR:" << std::endl << signing_request.str() << std::endl;

      MCHK(mbedtls_x509_csr_parse(csr.get(), signing_request.data(), signing_request.size()));

      char subject[512];
      mbedtls_x509_dn_gets(subject, sizeof(subject), &csr->subject);

      mbedtls_x509write_crt_set_md_alg(
        crt.get(), get_mbedtls_md_for_ec(get_mbedtls_ec_from_context(*ctx)));
      mbedtls_x509write_crt_set_subject_key(crt.get(), &csr->pk);

      if (!issuer_cert.empty()) {
        MCHK(mbedtls_x509_crt_parse(icrt.get(), issuer_cert.data(), issuer_cert.size()));
        mbedtls_x509write_crt_set_issuer_key(crt.get(), ctx.get());
        char issuer_name[512];
        mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name), &icrt->subject);
        MCHK(mbedtls_x509write_crt_set_issuer_name(crt.get(), issuer_name));
      }
      else {
        mbedtls_x509write_crt_set_issuer_key(crt.get(), ctx.get());
        MCHK(mbedtls_x509write_crt_set_issuer_name(crt.get(), subject));
      }

      MCHK(mbedtls_mpi_fill_random(
          serial.get(), 16, entropy->get_rng(), entropy->get_data()));
      MCHK(mbedtls_x509write_crt_set_subject_name(crt.get(), subject));
      MCHK(mbedtls_x509write_crt_set_serial(crt.get(), serial.get()));

      // Note: 825-day validity range
      // https://support.apple.com/en-us/HT210176
      MCHK(
        mbedtls_x509write_crt_set_validity(
          crt.get(), "20191101000000", "20211231235959"));

      MCHK(mbedtls_x509write_crt_set_basic_constraints(crt.get(), ca ? 1 : 0, 0));
      MCHK(mbedtls_x509write_crt_set_subject_key_identifier(crt.get()));
      MCHK(mbedtls_x509write_crt_set_authority_key_identifier(crt.get()));

      // Because mbedtls does not support parsing x509v3 extensions from a
      // CSR (https://github.com/ARMmbed/mbedtls/issues/2912), the CA sets the
      // SAN directly instead of reading it from the CSR
      try
      {
        MCHK(
          x509write_crt_set_subject_alt_names(crt.get(), subject_alt_names));
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT("Error writing SAN: {}", err.what());
        return {};
      }

      uint8_t buf[4096];
      memset(buf, 0, sizeof(buf));

      MCHK(
        mbedtls_x509write_crt_pem(
          crt.get(),
          buf,
          sizeof(buf),
          entropy->get_rng(),
          entropy->get_data()));

      auto len = strlen((char*)buf);
      return Pem(buf, len);
    }
  };

}
