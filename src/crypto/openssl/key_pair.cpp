// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/key_pair.h"

#include "ccf/crypto/curve.h"
#include "crypto/openssl/hash.h"
#include "crypto/openssl/public_key.h"
#include "openssl_wrappers.h"
#include "x509_time.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <openssl/asn1.h>
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
  using namespace OpenSSL;

  static std::map<std::string, std::string> parse_name(const std::string& name)
  {
    std::map<std::string, std::string> result;
    const auto ns = nonstd::split(name, ",");
    for (const auto& n : ns)
    {
      const auto& [key, value] = nonstd::split_1(n, "=");
      result.emplace(
        std::string(key.data(), key.size()),
        std::string(value.data(), value.size()));
    }
    return result;
  }

  KeyPair_OpenSSL::KeyPair_OpenSSL(CurveID curve_id)
  {
    int curve_nid = get_openssl_group_id(curve_id);
    key = EVP_PKEY_new();
    Unique_EVP_PKEY_CTX pkctx;
    if (
      EVP_PKEY_keygen_init(pkctx) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, curve_nid) <= 0 ||
      EVP_PKEY_CTX_set_ec_param_enc(pkctx, OPENSSL_EC_NAMED_CURVE) <= 0)
    {
      throw std::runtime_error("could not initialize PK context");
    }
    if (EVP_PKEY_keygen(pkctx, &key) <= 0)
    {
      throw std::runtime_error("could not generate new EC key");
    }
  }

  KeyPair_OpenSSL::KeyPair_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem);
    key = PEM_read_bio_PrivateKey(mem, NULL, NULL, nullptr);
    if (!key)
      throw std::runtime_error("could not parse PEM");
  }

  KeyPair_OpenSSL::KeyPair_OpenSSL(const JsonWebKeyECPrivate& jwk)
  {
    auto ec_key = PublicKey_OpenSSL::ec_key_public_from_jwk(jwk);

    Unique_BIGNUM d;
    auto d_raw = raw_from_b64url(jwk.d);
    BN_bin2bn(d_raw.data(), d_raw.size(), d);

    CHECK1(EC_KEY_set_private_key(ec_key, d));

    key = EVP_PKEY_new();
    CHECK1(EVP_PKEY_set1_EC_KEY(key, ec_key));
  }

  Pem KeyPair_OpenSSL::private_key_pem() const
  {
    Unique_BIO buf;

    OpenSSL::CHECK1(
      PEM_write_bio_PrivateKey(buf, key, NULL, NULL, 0, NULL, NULL));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }

  Pem KeyPair_OpenSSL::public_key_pem() const
  {
    return PublicKey_OpenSSL::public_key_pem();
  }

  std::vector<uint8_t> KeyPair_OpenSSL::public_key_der() const
  {
    return PublicKey_OpenSSL::public_key_der();
  }

  std::vector<uint8_t> KeyPair_OpenSSL::private_key_der() const
  {
    Unique_BIO buf;

    OpenSSL::CHECK1(i2d_PrivateKey_bio(buf, key));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return {bptr->data, bptr->data + bptr->length};
  }

  bool KeyPair_OpenSSL::verify(
    const std::vector<uint8_t>& contents, const std::vector<uint8_t>& signature)
  {
    return PublicKey_OpenSSL::verify(contents, signature);
  }

  bool KeyPair_OpenSSL::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* signature,
    size_t signature_size)
  {
    return PublicKey_OpenSSL::verify(
      contents, contents_size, signature, signature_size);
  }

  std::vector<uint8_t> KeyPair_OpenSSL::sign(
    std::span<const uint8_t> d, MDType md_type) const
  {
    if (md_type == MDType::NONE)
    {
      md_type = get_md_for_ec(get_curve_id());
    }
    OpenSSLHashProvider hp;
    HashBytes hash = hp.Hash(d.data(), d.size(), md_type);
    return sign_hash(hash.data(), hash.size());
  }

  int KeyPair_OpenSSL::sign(
    std::span<const uint8_t> d,
    size_t* sig_size,
    uint8_t* sig,
    MDType md_type) const
  {
    if (md_type == MDType::NONE)
    {
      md_type = get_md_for_ec(get_curve_id());
    }
    OpenSSLHashProvider hp;
    HashBytes hash = hp.Hash(d.data(), d.size(), md_type);
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
    OpenSSL::CHECK1(EVP_PKEY_sign_init(pctx));
    OpenSSL::CHECK1(EVP_PKEY_sign(pctx, sig, sig_size, hash, hash_size));
    return 0;
  }

  Unique_X509_REQ KeyPair_OpenSSL::create_req(
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::optional<Pem>& public_key) const
  {
    Unique_X509_REQ req;

    if (public_key)
    {
      Unique_BIO mem(*public_key);
      Unique_PKEY pubkey(mem);
      OpenSSL::CHECK1(X509_REQ_set_pubkey(req, pubkey));
    }
    else
    {
      OpenSSL::CHECK1(X509_REQ_set_pubkey(req, key));
    }

    X509_NAME* subj_name = NULL;
    OpenSSL::CHECKNULL(subj_name = X509_NAME_new());

    for (const auto& [k, v] : parse_name(subject_name))
    {
      OpenSSL::CHECK1(X509_NAME_add_entry_by_txt(
        subj_name,
        k.data(),
        MBSTRING_ASC,
        (const unsigned char*)v.data(),
        -1,
        -1,
        0));
    }

    OpenSSL::CHECK1(X509_REQ_set_subject_name(req, subj_name));
    X509_NAME_free(subj_name);

    if (!subject_alt_names.empty())
    {
      Unique_STACK_OF_X509_EXTENSIONS exts;

      X509_EXTENSION* ext = NULL;
      OpenSSL::CHECKNULL(
        ext = X509V3_EXT_conf_nid(
          NULL,
          NULL,
          NID_subject_alt_name,
          fmt::format("{}", fmt::join(subject_alt_names, ", ")).c_str()));
      sk_X509_EXTENSION_push(exts, ext);
      X509_REQ_add_extensions(req, exts);
    }

    if (key)
      OpenSSL::CHECK1(X509_REQ_sign(req, key, EVP_sha512()));

    return req;
  }

  Pem KeyPair_OpenSSL::create_csr(
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::optional<Pem>& public_key) const
  {
    Unique_X509_REQ req =
      create_req(subject_name, subject_alt_names, public_key);

    Unique_BIO mem;
    OpenSSL::CHECK1(PEM_write_bio_X509_REQ(mem, req));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    Pem result((uint8_t*)bptr->data, bptr->length);

    return result;
  }

  std::vector<uint8_t> KeyPair_OpenSSL::create_csr_der(
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::optional<Pem>& public_key) const
  {
    Unique_X509_REQ req =
      create_req(subject_name, subject_alt_names, public_key);

    Unique_BIO mem;
    CHECK1(i2d_X509_REQ_bio(mem, req));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    std::vector<uint8_t> result(
      (uint8_t*)bptr->data, (uint8_t*)bptr->data + bptr->length);

    return result;
  }

  Pem KeyPair_OpenSSL::sign_csr_impl(
    const std::optional<Pem>& issuer_cert,
    const Pem& signing_request,
    const std::string& valid_from,
    const std::string& valid_to,
    bool ca,
    Signer signer) const
  {
    X509* icrt = NULL;
    Unique_BIO mem(signing_request);
    Unique_X509_REQ csr(mem);
    Unique_X509 crt;
    EVP_PKEY* req_pubkey = NULL;

    // First, verify self-signed CSR
    if (signer == Signer::SUBJECT)
    {
      req_pubkey = X509_REQ_get0_pubkey(csr);
      OpenSSL::CHECK1(X509_REQ_verify(csr, req_pubkey));
    }

    // Add version
    OpenSSL::CHECK1(X509_set_version(crt, 2));

    // Add serial number
    unsigned char rndbytes[16];
    OpenSSL::CHECK1(RAND_bytes(rndbytes, sizeof(rndbytes)));
    BIGNUM* bn = NULL;
    OpenSSL::CHECKNULL(bn = BN_new());
    BN_bin2bn(rndbytes, sizeof(rndbytes), bn);
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    BN_to_ASN1_INTEGER(bn, serial);
    OpenSSL::CHECK1(X509_set_serialNumber(crt, serial));
    ASN1_INTEGER_free(serial);
    BN_free(bn);

    // Add issuer name
    if (issuer_cert.has_value())
    {
      Unique_BIO imem(*issuer_cert);
      OpenSSL::CHECKNULL(icrt = PEM_read_bio_X509(imem, NULL, NULL, NULL));
      OpenSSL::CHECK1(X509_set_issuer_name(crt, X509_get_subject_name(icrt)));

      if (signer == Signer::ISSUER)
      {
        // Verify issuer-signed CSR
        req_pubkey = X509_REQ_get0_pubkey(csr);
        auto issuer_pubkey = X509_get0_pubkey(icrt);
        OpenSSL::CHECK1(X509_REQ_verify(csr, issuer_pubkey));
      }
    }
    else
    {
      OpenSSL::CHECK1(
        X509_set_issuer_name(crt, X509_REQ_get_subject_name(csr)));
    }

    Unique_X509_TIME not_before(valid_from);
    Unique_X509_TIME not_after(valid_to);
    if (!validate_chronological_times(not_before, not_after))
    {
      throw std::logic_error(fmt::format(
        "Certificate cannot be created with not_before date {} > not_after "
        "date {}",
        to_x509_time_string(not_before),
        to_x509_time_string(not_after)));
    }

    OpenSSL::CHECK1(X509_set1_notBefore(crt, not_before));
    OpenSSL::CHECK1(X509_set1_notAfter(crt, not_after));

    X509_set_subject_name(crt, X509_REQ_get_subject_name(csr));
    X509_set_pubkey(crt, req_pubkey);

    // Extensions
    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, icrt ? icrt : crt, NULL, csr, NULL, 0);

    // Add basic constraints
    X509_EXTENSION* ext = NULL;
    OpenSSL::CHECKNULL(
      ext = X509V3_EXT_conf_nid(
        NULL, &v3ctx, NID_basic_constraints, ca ? "CA:TRUE" : "CA:FALSE"));
    OpenSSL::CHECK1(X509_add_ext(crt, ext, -1));
    X509_EXTENSION_free(ext);

    // Add subject key identifier
    OpenSSL::CHECKNULL(
      ext =
        X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_key_identifier, "hash"));
    OpenSSL::CHECK1(X509_add_ext(crt, ext, -1));
    X509_EXTENSION_free(ext);

    // Add authority key identifier
    OpenSSL::CHECKNULL(
      ext = X509V3_EXT_conf_nid(
        NULL, &v3ctx, NID_authority_key_identifier, "keyid:always"));
    OpenSSL::CHECK1(X509_add_ext(crt, ext, -1));
    X509_EXTENSION_free(ext);

    // Add subject alternative names (read from csr)
    Unique_STACK_OF_X509_EXTENSIONS exts = X509_REQ_get_extensions(csr);
    int extension_count = sk_X509_EXTENSION_num(exts);
    if (extension_count > 0)
    {
      for (size_t i = 0; i < extension_count; i++)
      {
        X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
        auto nid = OBJ_obj2nid(obj);
        if (nid == NID_subject_alt_name)
        {
          OpenSSL::CHECK1(X509_add_ext(crt, ext, -1));
        }
      }
    }

    // Sign
    auto md = get_md_type(get_md_for_ec(get_curve_id()));
    int size = X509_sign(crt, key, md);
    if (size <= 0)
      throw std::runtime_error("could not sign CRT");

    Unique_BIO omem;
    OpenSSL::CHECK1(PEM_write_bio_X509(omem, crt));

    // Export
    BUF_MEM* bptr;
    BIO_get_mem_ptr(omem, &bptr);
    Pem result((uint8_t*)bptr->data, bptr->length);

    if (icrt)
      X509_free(icrt);

    return result;
  }

  CurveID KeyPair_OpenSSL::get_curve_id() const
  {
    return PublicKey_OpenSSL::get_curve_id();
  }

  std::vector<uint8_t> KeyPair_OpenSSL::public_key_raw() const
  {
    return PublicKey_OpenSSL::public_key_raw();
  }

  std::vector<uint8_t> KeyPair_OpenSSL::derive_shared_secret(
    const PublicKey& peer_key)
  {
    crypto::CurveID cid = peer_key.get_curve_id();
    int nid = crypto::PublicKey_OpenSSL::get_openssl_group_id(cid);
    auto pk = key_from_raw_ec_point(peer_key.public_key_raw(), nid);

    std::vector<uint8_t> shared_secret;
    size_t shared_secret_length = 0;
    Unique_EVP_PKEY_CTX ctx(key);
    CHECK1(EVP_PKEY_derive_init(ctx));
    CHECK1(EVP_PKEY_derive_set_peer(ctx, pk));
    CHECK1(EVP_PKEY_derive(ctx, NULL, &shared_secret_length));
    shared_secret.resize(shared_secret_length);
    CHECK1(EVP_PKEY_derive(ctx, shared_secret.data(), &shared_secret_length));

    EVP_PKEY_free(pk);

    return shared_secret;
  }

  PublicKey::Coordinates KeyPair_OpenSSL::coordinates() const
  {
    return PublicKey_OpenSSL::coordinates();
  }

  JsonWebKeyECPrivate KeyPair_OpenSSL::private_key_jwk(
    const std::optional<std::string>& kid) const
  {
    JsonWebKeyECPrivate jwk = {PublicKey_OpenSSL::public_key_jwk(kid)};

    // As per https://www.openssl.org/docs/man1.0.2/man3/BN_num_bytes.html, size
    // should not be calculated with BN_num_bytes(d)!
    size_t size = EVP_PKEY_bits(key) / 8;
    Unique_EC_KEY eckey(EVP_PKEY_get1_EC_KEY(key));
    const BIGNUM* d = EC_KEY_get0_private_key(eckey);

    std::vector<uint8_t> bytes(size);
    auto rc = BN_bn2binpad(d, bytes.data(), size);
    if (rc != size)
    {
      throw std::runtime_error(fmt::format("BN_bn2binpad failed: {}", rc));
    }
    jwk.d = b64url_from_raw(bytes, false /* with_padding */);

    return jwk;
  }
}
