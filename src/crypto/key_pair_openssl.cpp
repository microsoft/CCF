// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "key_pair_openssl.h"

#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdexcept>
#include <string>

namespace crypto
{
  PublicKey_OpenSSL::PublicKey_OpenSSL() {}

  static inline const EVP_MD* get_md_type(MDType mdt)
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

  PublicKey_OpenSSL::PublicKey_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem.data(), -1);
    key = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    if (!key)
      throw std::runtime_error("could not parse PEM");
  }

  PublicKey_OpenSSL::PublicKey_OpenSSL(const std::vector<uint8_t>& der)
  {
    const unsigned char* pp = der.data();
    key = d2i_PublicKey(EVP_PKEY_EC, &key, &pp, der.size());
    if (!key)
    {
      throw new std::runtime_error("Could not read DER");
    }
  }

  PublicKey_OpenSSL::PublicKey_OpenSSL(EVP_PKEY* key) : key(key) {}

  PublicKey_OpenSSL::~PublicKey_OpenSSL()
  {
    if (key)
      EVP_PKEY_free(key);
  }

  CurveID PublicKey_OpenSSL::get_curve_id() const
  {
    int nid =
      EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(key)));
    switch (nid)
    {
      case NID_secp384r1:
        return CurveID::SECP384R1;
      case NID_X9_62_prime256v1:
        return CurveID::SECP256R1;
      default:
        throw std::runtime_error(fmt::format("Unknown OpenSSL curve {}", nid));
    }
    return CurveID::NONE;
  }

  bool PublicKey_OpenSSL::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* sig,
    size_t sig_size,
    MDType md_type,
    HashBytes& bytes)
  {
    if (md_type == MDType::NONE)
    {
      md_type = get_md_for_ec(get_curve_id());
    }
    OpenSSLHashProvider hp;
    bytes = hp.Hash(contents, contents_size, md_type);
    return verify_hash(bytes.data(), bytes.size(), sig, sig_size, md_type);
  }

  bool PublicKey_OpenSSL::verify_hash(
    const uint8_t* hash,
    size_t hash_size,
    const uint8_t* sig,
    size_t sig_size,
    MDType md_type)
  {
    if (md_type == MDType::NONE)
    {
      md_type = get_md_for_ec(get_curve_id());
    }

    Unique_EVP_PKEY_CTX pctx(key);
    OPENSSL_CHECK1(EVP_PKEY_verify_init(pctx));
    if (md_type != MDType::NONE)
    {
      OPENSSL_CHECK1(EVP_PKEY_CTX_set_signature_md(pctx, get_md_type(md_type)));
    }
    int rc = EVP_PKEY_verify(pctx, sig, sig_size, hash, hash_size);

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

  Pem PublicKey_OpenSSL::public_key_pem() const
  {
    Unique_BIO buf;

    OPENSSL_CHECK1(PEM_write_bio_PUBKEY(buf, key));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }

  std::string PublicKey_OpenSSL::error_string(int ec)
  {
    return ERR_error_string((unsigned long)ec, NULL);
  }

  static inline int get_openssl_group_id(CurveID gid)
  {
    switch (gid)
    {
      case CurveID::NONE:
        return NID_undef;
      case CurveID::SECP384R1:
        return NID_secp384r1;
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

  KeyPair_OpenSSL::KeyPair_OpenSSL(CurveID curve_id)
  {
    int curve_nid = get_openssl_group_id(curve_id);
    key = EVP_PKEY_new();
    Unique_EVP_PKEY_CTX pkctx;
    if (
      EVP_PKEY_paramgen_init(pkctx) < 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, curve_nid) < 0 ||
      EVP_PKEY_CTX_set_ec_param_enc(pkctx, OPENSSL_EC_NAMED_CURVE) < 0)
      throw std::runtime_error("could not initialize PK context");
    if (EVP_PKEY_keygen_init(pkctx) < 0 || EVP_PKEY_keygen(pkctx, &key) < 0)
      throw std::runtime_error("could not generate new EC key");
  }

  KeyPair_OpenSSL::KeyPair_OpenSSL(const Pem& pem, CBuffer pw)
  {
    Unique_BIO mem(pem.data(), -1);
    key = PEM_read_bio_PrivateKey(mem, NULL, NULL, (void*)pw.p);
    if (!key)
      throw std::runtime_error("could not parse PEM");
  }

  Pem KeyPair_OpenSSL::private_key_pem() const
  {
    Unique_BIO buf;

    OPENSSL_CHECK1(
      PEM_write_bio_PrivateKey(buf, key, NULL, NULL, 0, NULL, NULL));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }

  Pem KeyPair_OpenSSL::public_key_pem() const
  {
    return PublicKey_OpenSSL::public_key_pem();
  }

  bool KeyPair_OpenSSL::verify(
    const std::vector<uint8_t>& contents, const std::vector<uint8_t>& signature)
  {
    return PublicKey_OpenSSL::verify(contents, signature);
  }

  std::vector<uint8_t> KeyPair_OpenSSL::sign(CBuffer d, MDType md_type) const
  {
    if (md_type == MDType::NONE)
    {
      md_type = get_md_for_ec(get_curve_id());
    }
    OpenSSLHashProvider hp;
    HashBytes hash = hp.Hash(d.p, d.rawSize(), md_type);
    return sign_hash(hash.data(), hash.size());
  }

  int KeyPair_OpenSSL::sign(
    CBuffer d, size_t* sig_size, uint8_t* sig, MDType md_type) const
  {
    if (md_type == MDType::NONE)
    {
      md_type = get_md_for_ec(get_curve_id());
    }
    OpenSSLHashProvider hp;
    HashBytes hash = hp.Hash(d.p, d.rawSize(), md_type);
    return sign_hash(hash.data(), hash.size(), sig_size, sig);
  }

  std::vector<uint8_t> KeyPair_OpenSSL::sign_hash(
    const uint8_t* hash, size_t hash_size) const
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

  int KeyPair_OpenSSL::sign_hash(
    const uint8_t* hash, size_t hash_size, size_t* sig_size, uint8_t* sig) const
  {
    Unique_EVP_PKEY_CTX pctx(key);
    OPENSSL_CHECK1(EVP_PKEY_sign_init(pctx));
    OPENSSL_CHECK1(EVP_PKEY_sign(pctx, sig, sig_size, hash, hash_size));
    return 0;
  }

  Pem KeyPair_OpenSSL::create_csr(const std::string& name) const
  {
    Unique_X509_REQ req;

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

    Unique_BIO mem;
    OPENSSL_CHECK1(PEM_write_bio_X509_REQ(mem, req));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    Pem result((uint8_t*)bptr->data, bptr->length);

    return result;
  }

  Pem KeyPair_OpenSSL::sign_csr(
    const Pem& issuer_cert,
    const Pem& signing_request,
    const std::vector<SubjectAltName> subject_alt_names,
    bool ca) const
  {
    X509* icrt = NULL;
    Unique_BIO mem(signing_request.data(), -1);
    Unique_X509_REQ csr(mem);
    Unique_X509 crt;

    OPENSSL_CHECK1(X509_set_version(crt, 2));

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
    if (!issuer_cert.empty())
    {
      Unique_BIO imem(issuer_cert.data(), -1);
      OPENSSL_CHECKNULL(icrt = PEM_read_bio_X509(imem, NULL, NULL, NULL));
      OPENSSL_CHECK1(X509_set_issuer_name(crt, X509_get_subject_name(icrt)));
    }
    else
    {
      OPENSSL_CHECK1(X509_set_issuer_name(crt, X509_REQ_get_subject_name(csr)));
    }

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
    X509V3_set_ctx(&v3ctx, icrt ? icrt : crt, NULL, csr, NULL, 0);

    // Add basic constraints
    X509_EXTENSION* ext = NULL;
    OPENSSL_CHECKNULL(
      ext = X509V3_EXT_conf_nid(
        NULL, &v3ctx, NID_basic_constraints, ca ? "CA:TRUE" : "CA:FALSE"));
    OPENSSL_CHECK1(X509_add_ext(crt, ext, -1));
    X509_EXTENSION_free(ext);

    // Add subject key identifier
    OPENSSL_CHECKNULL(
      ext =
        X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_key_identifier, "hash"));
    OPENSSL_CHECK1(X509_add_ext(crt, ext, -1));
    X509_EXTENSION_free(ext);

    // Add authority key identifier
    OPENSSL_CHECKNULL(
      ext = X509V3_EXT_conf_nid(
        NULL, &v3ctx, NID_authority_key_identifier, "keyid:always"));
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

        if (san.is_ip)
          all_alt_names += "IP:";
        else
          all_alt_names += "DNS:";

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

    Unique_BIO omem;
    OPENSSL_CHECK1(PEM_write_bio_X509(omem, crt));

    // Export
    BUF_MEM* bptr;
    BIO_get_mem_ptr(omem, &bptr);
    Pem result((uint8_t*)bptr->data, bptr->length);

    if (icrt)
      X509_free(icrt);

    return result;
  }
}
