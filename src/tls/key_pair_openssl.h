// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "key_pair_base.h"

#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

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

  inline void OPENSSL_CHECKNULL(void* ptr)
  {
    unsigned long ec = ERR_get_error();
    if (ptr == NULL && ec != 0)
    {
      throw std::runtime_error(
        fmt::format("OpenSSL error: {}", ERR_error_string(ec, NULL)));
    }
  }

  class PublicKey_OpenSSL : public PublicKeyBase
  {
  protected:
    EVP_PKEY* key = nullptr;
    ENGINE* engine = nullptr;

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

    void set_rng_engine()
    {
      OPENSSL_CHECK1(ENGINE_load_rdrand());
      OPENSSL_CHECKNULL(engine = ENGINE_by_id("rdrand"));
      OPENSSL_CHECK1(ENGINE_init(engine));
      OPENSSL_CHECK1(ENGINE_set_default(engine, ENGINE_METHOD_RAND));
    }

  public:
    /**
     * Construct from PEM
     */
    PublicKey_OpenSSL(const Pem& pem)
    {
      set_rng_engine();
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
      set_rng_engine();
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
      if (engine)
      {
        ENGINE_finish(engine);
        ENGINE_free(engine);
      }
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
      return verify_hash(bytes.data(), bytes.size(), sig, sig_size);
    }

    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size) override
    {
      EVP_PKEY_CTX* pctx = NULL;
      OPENSSL_CHECKNULL(pctx = EVP_PKEY_CTX_new(key, NULL));
      OPENSSL_CHECK1(EVP_PKEY_verify_init(pctx));
      int rc = EVP_PKEY_verify(pctx, sig, sig_size, hash, hash_size);
      EVP_PKEY_CTX_free(pctx);

      bool ok = rc == 1;
      if (!ok)
      {
        int ec = ERR_get_error();
        LOG_DEBUG_FMT(
          "OpenSSL signature verification failure: {}",
          ERR_error_string(ec, NULL));
      }

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

    static std::vector<std::pair<std::string, std::string>> parse_name(
      const std::string& name)
    {
      std::vector<std::pair<std::string, std::string>> r;

      char* name_cpy = strdup(name.c_str());
      char* p = std::strtok(name_cpy, ",");
      while (p)
      {
        char* eq = strchr(p, '=');
        *eq = '\0';
        r.push_back(std::make_pair(p, eq + 1));
        p = std::strtok(NULL, ",");
      }
      free(name_cpy);

      return r;
    }

  public:
    /**
     * Generate a fresh key
     */
    KeyPair_OpenSSL(CurveID curve_id = service_identity_curve_choice)
    {
      PublicKey_OpenSSL::set_rng_engine();
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
      PublicKey_OpenSSL::set_rng_engine();
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
      return sign_hash(hash.data(), hash.size());
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
      std::vector<uint8_t> sig(EVP_PKEY_size(key));
      size_t written = sig.size();

      if (sign_hash(hash, hash_size, &written, sig.data()) != 0)
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
      uint8_t* sig) const override
    {
      EVP_PKEY_CTX* pctx = NULL;
      OPENSSL_CHECKNULL(pctx = EVP_PKEY_CTX_new(key, NULL));
      OPENSSL_CHECK1(EVP_PKEY_sign_init(pctx));
      OPENSSL_CHECK1(EVP_PKEY_sign(pctx, sig, sig_size, hash, hash_size));
      EVP_PKEY_CTX_free(pctx);
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

      X509_NAME* subj_name = NULL;
      OPENSSL_CHECKNULL(subj_name = X509_NAME_new());

      for (auto kv : parse_name(name))
      {
        OPENSSL_CHECK1(X509_NAME_add_entry_by_txt(
          subj_name,
          kv.first.c_str(),
          MBSTRING_ASC,
          (const unsigned char*)kv.second.c_str(),
          -1,
          -1,
          0));
      }

      OPENSSL_CHECK1(X509_REQ_set_subject_name(req, subj_name));
      X509_NAME_free(subj_name);

      if (key)
        OPENSSL_CHECK1(X509_REQ_sign(req, key, EVP_sha512()));

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
      X509_REQ* csr = NULL;

      BIO* mem = BIO_new_mem_buf(pem.data(), -1);
      OPENSSL_CHECKNULL(csr = PEM_read_bio_X509_REQ(mem, NULL, NULL, NULL));
      BIO_free(mem);

      X509* crt = NULL;
      OPENSSL_CHECKNULL(crt = X509_new());

      X509_set_version(crt, 2);

      // Add serial number
      unsigned char rndbytes[16];
      OPENSSL_CHECK1(RAND_bytes(rndbytes, sizeof(rndbytes)));
      BIGNUM* bn = NULL;
      OPENSSL_CHECKNULL(bn = BN_new());
      BN_bin2bn(rndbytes, sizeof(rndbytes), bn);
      ASN1_INTEGER* serial = ASN1_INTEGER_new();
      BN_to_ASN1_INTEGER(bn, serial);
      OPENSSL_CHECK1(X509_set_serialNumber(crt, serial));
      ASN1_INTEGER_free(serial);
      BN_free(bn);

      // Add issuer name
      X509_NAME* issuer_name = NULL;
      OPENSSL_CHECKNULL(issuer_name = X509_NAME_new());
      for (auto kv : parse_name(issuer))
      {
        OPENSSL_CHECK1(X509_NAME_add_entry_by_txt(
          issuer_name,
          kv.first.c_str(),
          MBSTRING_ASC,
          (const unsigned char*)kv.second.c_str(),
          -1,
          -1,
          0));
      }
      OPENSSL_CHECK1(X509_set_issuer_name(crt, issuer_name));
      X509_NAME_free(issuer_name);

      // Note: 825-day validity range
      // https://support.apple.com/en-us/HT210176
      ASN1_TIME *before = NULL, *after = NULL;
      OPENSSL_CHECKNULL(before = ASN1_TIME_new());
      OPENSSL_CHECKNULL(after = ASN1_TIME_new());
      OPENSSL_CHECK1(ASN1_TIME_set_string(before, "20191101000000Z"));
      OPENSSL_CHECK1(ASN1_TIME_set_string(after, "20211231235959Z"));
      X509_set1_notBefore(crt, before);
      X509_set1_notAfter(crt, after);
      ASN1_TIME_free(before);
      ASN1_TIME_free(after);

      X509_set_subject_name(crt, X509_REQ_get_subject_name(csr));
      EVP_PKEY* req_pubkey = X509_REQ_get_pubkey(csr);
      X509_set_pubkey(crt, req_pubkey);
      EVP_PKEY_free(req_pubkey);

      // Extensions
      X509V3_CTX v3ctx;
      X509V3_set_ctx_nodb(&v3ctx);
      // Self-signed, otherwise we would need an issuer certificate
      X509V3_set_ctx(&v3ctx, crt, NULL, csr, NULL, 0);

      // Add basic constraints
      X509_EXTENSION* ext = NULL;
      OPENSSL_CHECKNULL(
        ext = X509V3_EXT_conf_nid(
          NULL, NULL, NID_basic_constraints, ca ? "CA:TRUE" : "CA:FALSE"));
      OPENSSL_CHECK1(X509_add_ext(crt, ext, -1));
      X509_EXTENSION_free(ext);

      // Add subject key identifier
      OPENSSL_CHECKNULL(
        ext = X509V3_EXT_conf_nid(
          NULL, &v3ctx, NID_subject_key_identifier, "hash"));
      OPENSSL_CHECK1(X509_add_ext(crt, ext, -1));
      X509_EXTENSION_free(ext);

      // Add auhtority key identifier
      OPENSSL_CHECKNULL(
        ext = X509V3_EXT_conf_nid(
          NULL, &v3ctx, NID_authority_key_identifier, "keyid,issuer"));
      OPENSSL_CHECK1(X509_add_ext(crt, ext, -1));
      X509_EXTENSION_free(ext);

      // Subject alternative names (Necessary? Shouldn't they be in the CSR?)
      if (!subject_alt_names.empty())
      {
        std::string all_alt_names;
        bool first = true;
        for (auto san : subject_alt_names)
        {
          if (first)
          {
            first = !first;
          }
          else
          {
            all_alt_names += ", ";
          }

          all_alt_names += san.san;
        }

        OPENSSL_CHECKNULL(
          ext = X509V3_EXT_conf_nid(
            NULL, &v3ctx, NID_subject_alt_name, all_alt_names.c_str()));
        OPENSSL_CHECK1(X509_add_ext(crt, ext, -1));
        X509_EXTENSION_free(ext);
      }

      // Sign
      auto md = get_md_type(get_md_for_ec(get_curve_id()));
      int size = X509_sign(crt, key, md);
      if (size <= 0)
        throw std::runtime_error("could not sign CRT");

      mem = BIO_new(BIO_s_mem());
      OPENSSL_CHECK1(PEM_write_bio_X509(mem, crt));

      // Export
      BUF_MEM* bptr;
      BIO_get_mem_ptr(mem, &bptr);
      Pem result = Pem((uint8_t*)bptr->data, bptr->length);
      BIO_free(mem);

      X509_REQ_free(csr);
      X509_free(crt);

      return result;
    }
  };
}
