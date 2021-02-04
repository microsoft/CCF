// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "key_pair_base.h"

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace tls
{
  inline void OPENSSL_CHECK1(int rc)
  {
    unsigned long ec = ERR_get_error();
    if (rc != 1 && ec != 0)
    {
      throw std::runtime_error(
        fmt::format("OpenSSL error: {}", ERR_error_string(ec, NULL)));
    }
  }

  class PublicKey_OpenSSL : public PublicKeyBase
  {
  protected:
    EVP_PKEY* key = nullptr;

    PublicKey_OpenSSL() {}

    inline const EVP_MD* get_md_type(MDType mdt) const
    {
      switch (mdt)
      {
        case MDType::NONE:
          return nullptr;
        case MDType::SHA1:
          return EVP_sha1();
        case MDType::SHA256:
          return EVP_sha256();
        case MDType::SHA384:
          return EVP_sha384();
        case MDType::SHA512:
          return EVP_sha512();
        default:
          return nullptr;
      }
      return nullptr;
    }

  public:
    /**
     * Construct from PEM
     */
    PublicKey_OpenSSL(const Pem& pem)
    {
      BIO* mem = BIO_new_mem_buf(pem.data(), -1);
      key = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
      BIO_free(mem);
      if (!key)
        throw std::runtime_error("could not parse PEM");
    }

    /**
     * Construct from DER
     */
    PublicKey_OpenSSL(const std::vector<uint8_t>& der)
    {
      const unsigned char* pp = der.data();
      key = d2i_PublicKey(EVP_PKEY_EC, &key, &pp, der.size());
      if (!key)
      {
        throw new std::runtime_error("Could not read DER");
      }
    }

    virtual ~PublicKey_OpenSSL()
    {
      if (key)
        EVP_PKEY_free(key);
    }

    virtual CurveID get_curve_id() const override
    {
      int nid =
        EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(key)));
      switch (nid)
      {
        case NID_secp384r1:
          return CurveID::SECP384R1;
        case NID_secp256k1:
          return CurveID::SECP256K1;
        case NID_X9_62_prime256v1:
          return CurveID::SECP256R1;
        default:
          throw std::runtime_error(
            fmt::format("Unknown OpenSSL curve {}", nid));
      }
      return CurveID::NONE;
    }

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
      OpenSSLHashProvider hp;
      bytes = hp.Hash(contents, contents_size, md_type);
      return verify_hash(bytes.data(), bytes.size(), sig, sig_size, md_type);
    }

    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type = MDType::NONE) override
    {
      std::cout << "MD:" << (int)md_type << std::endl;
      const EVP_MD* md = get_md_type(md_type);

      if (md_type == MDType::NONE)
      {
        md = get_md_type(get_md_for_ec(get_curve_id()));
      }

      auto pk = public_key_pem();
      std::cout << "VPK:" << std::endl << pk.str() << std::endl;
      hexdump("HASH", hash, hash_size);
      hexdump("SIG ", sig, sig_size);

      EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
      OPENSSL_CHECK1(EVP_DigestVerifyInit(mdctx, NULL, md, NULL, key));
      bool ok = EVP_DigestVerify(mdctx, sig, sig_size, hash, hash_size) == 1;
      if (!ok)
      {
        // LOG_DEBUG_FMT(
        throw std::runtime_error(fmt::format(
          "OpenSSL digest verification failure: {}",
          ERR_error_string(ERR_get_error(), NULL)));
      }
      EVP_MD_CTX_free(mdctx);

      return ok;
    }

    /**
     * Get the public key in PEM format
     */
    virtual Pem public_key_pem() const override
    {
      BIO* buf = BIO_new(BIO_s_mem());
      if (!buf)
        throw std::runtime_error("out of memory");

      OPENSSL_CHECK1(PEM_write_bio_PUBKEY(buf, key));

      BUF_MEM* bptr;
      BIO_get_mem_ptr(buf, &bptr);
      Pem result = Pem((uint8_t*)bptr->data, bptr->length);
      BIO_free(buf);

      return result;
    }

    // EVP_PKEY* get_raw_context() const
    // {
    //   return key;
    // }
  };

  class KeyPair_OpenSSL : public PublicKey_OpenSSL, public KeyPairBase
  {
  protected:
    inline int get_openssl_group_id(CurveID gid)
    {
      switch (gid)
      {
        case CurveID::NONE:
          return NID_undef;
        case CurveID::SECP384R1:
          return NID_secp384r1;
        case CurveID::SECP256K1:
          return NID_secp256k1;
        case CurveID::SECP256R1:
          return NID_X9_62_prime256v1;
        default:
          throw std::logic_error(
            fmt::format("unsupported OpenSSL CurveID {}", gid));
      }
      return MBEDTLS_ECP_DP_NONE;
    }

  public:
    /**
     * Generate a fresh key
     */
    KeyPair_OpenSSL(CurveID curve_id = service_identity_curve_choice)
    {
      int curve_nid = get_openssl_group_id(curve_id);
      key = EVP_PKEY_new();
      EVP_PKEY_CTX* pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
      if (
        EVP_PKEY_paramgen_init(pkctx) < 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, curve_nid) < 0 ||
        EVP_PKEY_CTX_set_ec_param_enc(pkctx, OPENSSL_EC_NAMED_CURVE) < 0)
        throw std::runtime_error("could not initialize PK context");
      if (EVP_PKEY_keygen_init(pkctx) < 0 || EVP_PKEY_keygen(pkctx, &key) < 0)
        throw std::runtime_error("could not generate new EC key");
      EVP_PKEY_CTX_free(pkctx);
    }

    KeyPair_OpenSSL(const KeyPair_OpenSSL&) = delete;

    KeyPair_OpenSSL(const Pem& pem, CBuffer pw = nullb)
    {
      BIO* mem = BIO_new_mem_buf(pem.data(), -1);
      key = PEM_read_bio_PrivateKey(mem, NULL, NULL, (void*)pw.p);
      BIO_free(mem);
      if (!key)
        throw std::runtime_error("could not parse PEM");
    }

    virtual ~KeyPair_OpenSSL() = default;

    using PublicKey_OpenSSL::verify;

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature) override
    {
      return PublicKey_OpenSSL::verify(contents, signature);
    }

    /**
     * Get the private key in PEM format
     */
    virtual Pem private_key_pem() const override
    {
      BIO* buf = BIO_new(BIO_s_mem());
      if (!buf)
        throw std::runtime_error("out of memory");

      OPENSSL_CHECK1(
        PEM_write_bio_PrivateKey(buf, key, NULL, NULL, 0, NULL, NULL));

      BUF_MEM* bptr;
      BIO_get_mem_ptr(buf, &bptr);
      Pem result = Pem((uint8_t*)bptr->data, bptr->length);
      BIO_free(buf);

      return result;
    }

    /**
     * Get the public key in PEM format
     */
    virtual Pem public_key_pem() const override
    {
      return PublicKey_OpenSSL::public_key_pem();
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
      OpenSSLHashProvider hp;
      HashBytes hash = hp.Hash(d.p, d.rawSize(), md_type);
      return sign_hash(hash.data(), hash.size(), md_type);
    }

    /**
     * Write signature over hash of data, and the size of that signature to
     * specified locations.
     *
     * @param d data
     * @param sig_size location to which the signature size will be written.
     * Initial value should be max size of sig
     * @param sig location to which the signature will be written
     *
     * @return 0 if successful, otherwise OpenSSL error code
     */
    int sign(
      CBuffer d, size_t* sig_size, uint8_t* sig, MDType md_type = {}) const
    {
      if (md_type == MDType::NONE)
      {
        md_type = get_md_for_ec(get_curve_id());
      }
      OpenSSLHashProvider hp;
      HashBytes hash = hp.Hash(d.p, d.rawSize(), md_type);
      return sign_hash(hash.data(), hash.size(), sig_size, sig, md_type);
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
      const uint8_t* hash,
      size_t hash_size,
      MDType md_type = MDType::NONE) const override
    {
      std::vector<uint8_t> sig(EVP_PKEY_size(key));
      size_t written = sig.size();

      if (sign_hash(hash, hash_size, &written, sig.data(), md_type) != 0)
      {
        return {};
      }

      sig.resize(written);
      return sig;
    }

    virtual int sign_hash(
      const uint8_t* hash,
      size_t hash_size,
      size_t* sig_size,
      uint8_t* sig,
      MDType md_type = MDType::NONE) const override
    {
      if (md_type == MDType::NONE)
        md_type = get_md_for_ec(get_curve_id());
      EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
      const EVP_MD* omdt = get_md_type(md_type);
      OPENSSL_CHECK1(EVP_DigestSignInit(mdctx, NULL, omdt, NULL, key));
      OPENSSL_CHECK1(EVP_DigestSign(mdctx, sig, sig_size, hash, hash_size));
      EVP_MD_CTX_free(mdctx);
      return 0;
    }

    /**
     * Create a certificate signing request for this key pair. If we were
     * loaded from a private key, there will be no public key available for
     * this call.
     */
    virtual Pem create_csr(const std::string& name) override
    {
      X509_REQ* req = NULL;

      if (!(req = X509_REQ_new()))
      {
        throw std::runtime_error("failed to create X509_REQ object");
      }

      OPENSSL_CHECK1(X509_REQ_set_pubkey(req, key));

      X509_NAME* subj_name = X509_REQ_get_subject_name(req);

      OPENSSL_CHECK1(X509_NAME_add_entry_by_txt(
        subj_name,
        "CN",
        MBSTRING_ASC,
        (unsigned char*)name.c_str(),
        -1,
        -1,
        0));

      if (key)
        X509_REQ_sign(req, key, EVP_sha512());

      BIO* mem = BIO_new(BIO_s_mem());
      OPENSSL_CHECK1(PEM_write_bio_X509_REQ(mem, req));

      BUF_MEM* bptr;
      BIO_get_mem_ptr(mem, &bptr);
      Pem result = Pem((uint8_t*)bptr->data, bptr->length);
      BIO_free(mem);

      X509_REQ_free(req);

      return result;
    }

    virtual Pem sign_csr(
      const Pem& pem,
      const std::string& issuer,
      const std::vector<SubjectAltName> subject_alt_names,
      bool ca = false) override
    {
      (void)issuer;
      (void)subject_alt_names;
      (void)ca;
      X509_REQ* csr = NULL;

      BIO* mem = BIO_new_mem_buf(pem.data(), -1);
      if (!(csr = PEM_read_bio_X509_REQ(mem, NULL, NULL, NULL)))
      {
        std::cout << "PEM:" << std::endl << pem.str() << std::endl;
        throw std::runtime_error("could not read CSR");
      }
      BIO_free(mem);

      // int size = X509_REQ_sign(csr, key, EVP_sha512());

      // auto serial = mbedtls::make_unique<mbedtls::MPI>();
      // auto crt = mbedtls::make_unique<mbedtls::X509WriteCrt>();

      // char subject[512];
      // auto r = mbedtls_x509_dn_gets(subject, sizeof(subject),
      // &csr->subject);

      // if (r < 0)
      //   return {};

      // mbedtls_x509write_crt_set_md_alg(
      //   crt.get(),
      //   get_mbedtls_md_for_ec(get_mbedtls_ec_from_context(*ctx)));
      // mbedtls_x509write_crt_set_subject_key(crt.get(), &csr->pk);
      // mbedtls_x509write_crt_set_issuer_key(crt.get(), ctx.get());

      // if (
      //   mbedtls_mpi_fill_random(
      //     serial.get(), 16, entropy->get_rng(), entropy->get_data()) != 0)
      //   return {};

      // if (mbedtls_x509write_crt_set_subject_name(crt.get(), subject) != 0)
      //   return {};

      // if (mbedtls_x509write_crt_set_issuer_name(crt.get(), issuer.c_str())
      // != 0)
      //   return {};

      // if (mbedtls_x509write_crt_set_serial(crt.get(), serial.get()) != 0)
      //   return {};

      // // Note: 825-day validity range
      // // https://support.apple.com/en-us/HT210176
      // if (
      //   mbedtls_x509write_crt_set_validity(
      //     crt.get(), "20191101000000", "20211231235959") != 0)
      //   return {};

      // if (
      //   mbedtls_x509write_crt_set_basic_constraints(crt.get(), ca ? 1 : 0,
      //   0)
      //   != 0) return {};

      // if (mbedtls_x509write_crt_set_subject_key_identifier(crt.get()) != 0)
      //   return {};

      // if (mbedtls_x509write_crt_set_authority_key_identifier(crt.get()) !=
      // 0)
      //   return {};

      // // Because mbedtls does not support parsing x509v3 extensions from a
      // // CSR (https://github.com/ARMmbed/mbedtls/issues/2912), the CA sets
      // the
      //   // SAN directly instead of reading it from the CSR
      //   try
      // {
      //   auto rc =
      //     x509write_crt_set_subject_alt_names(crt.get(),
      //     subject_alt_names);
      //   if (rc != 0)
      //   {
      //     LOG_FAIL_FMT("Failed to set subject alternative names ({})", rc);
      //     return {};
      //   }
      // }
      // catch (const std::logic_error& err)
      // {
      //   LOG_FAIL_FMT("Error writing SAN: {}", err.what());
      //   return {};
      // }

      // uint8_t buf[4096];
      // memset(buf, 0, sizeof(buf));

      // // if (
      // //   mbedtls_x509write_crt_pem(
      // //     crt.get(),
      // //     buf,
      // //     sizeof(buf),
      // //     entropy->get_rng(),
      // //     entropy->get_data()) != 0)
      // //   return {};

      // auto len = strlen((char*)buf);
      // return Pem(buf, len);
      return Pem();
    }
  };
}
