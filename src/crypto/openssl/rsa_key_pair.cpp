// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/rsa_key_pair.h"

#include "crypto/openssl/hash.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
#  include <openssl/core_names.h>
#endif

namespace ccf::crypto
{
  using namespace OpenSSL;

  RSAKeyPair_OpenSSL::RSAKeyPair_OpenSSL(
    size_t public_key_size, size_t public_exponent)
  {
    CHECKNULL(key = EVP_PKEY_new());
    Unique_BIGNUM big_exp;
    CHECK1(BN_set_word(big_exp, public_exponent));

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    Unique_EVP_PKEY_CTX pctx("RSA");
    CHECK1(EVP_PKEY_keygen_init(pctx));
    CHECKPOSITIVE(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, public_key_size));
    CHECKPOSITIVE(EVP_PKEY_CTX_set1_rsa_keygen_pubexp(pctx, big_exp));
    CHECK1(EVP_PKEY_generate(pctx, &key));
#else
    Unique_RSA rsa;
    CHECK1(RSA_generate_key_ex(rsa, public_key_size, big_exp, NULL));
    CHECK1(EVP_PKEY_set1_RSA(key, rsa));
#endif
  }

  RSAKeyPair_OpenSSL::RSAKeyPair_OpenSSL(EVP_PKEY* k) :
    RSAPublicKey_OpenSSL(std::move(k))
  {}

  RSAKeyPair_OpenSSL::RSAKeyPair_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem);
    key = PEM_read_bio_PrivateKey(mem, NULL, NULL, nullptr);
    if (!key)
    {
      throw std::runtime_error("could not parse PEM");
    }
  }

  RSAKeyPair_OpenSSL::RSAKeyPair_OpenSSL(const JsonWebKeyRSAPrivate& jwk)
  {
    key = EVP_PKEY_new();

    Unique_BIGNUM d, p, q, dp, dq, qi;
    auto d_raw = raw_from_b64url(jwk.d);
    auto p_raw = raw_from_b64url(jwk.p);
    auto q_raw = raw_from_b64url(jwk.q);
    auto dp_raw = raw_from_b64url(jwk.dp);
    auto dq_raw = raw_from_b64url(jwk.dq);
    auto qi_raw = raw_from_b64url(jwk.qi);

    CHECKNULL(BN_bin2bn(d_raw.data(), d_raw.size(), d));
    CHECKNULL(BN_bin2bn(p_raw.data(), p_raw.size(), p));
    CHECKNULL(BN_bin2bn(q_raw.data(), q_raw.size(), q));
    CHECKNULL(BN_bin2bn(dp_raw.data(), dp_raw.size(), dp));
    CHECKNULL(BN_bin2bn(dq_raw.data(), dq_raw.size(), dq));
    CHECKNULL(BN_bin2bn(qi_raw.data(), qi_raw.size(), qi));

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    // Note: raw vectors are big endians while OSSL_PARAM_construct_BN expects
    // native endianness
    std::vector<uint8_t> d_raw_native(d_raw.size());
    std::vector<uint8_t> p_raw_native(p_raw.size());
    std::vector<uint8_t> q_raw_native(q_raw.size());
    std::vector<uint8_t> dp_raw_native(dp_raw.size());
    std::vector<uint8_t> dq_raw_native(dq_raw.size());
    std::vector<uint8_t> qi_raw_native(qi_raw.size());
    CHECKPOSITIVE(BN_bn2nativepad(d, d_raw_native.data(), d_raw_native.size()));
    CHECKPOSITIVE(BN_bn2nativepad(p, p_raw_native.data(), p_raw_native.size()));
    CHECKPOSITIVE(BN_bn2nativepad(q, q_raw_native.data(), q_raw_native.size()));
    CHECKPOSITIVE(
      BN_bn2nativepad(dp, dp_raw_native.data(), dp_raw_native.size()));
    CHECKPOSITIVE(
      BN_bn2nativepad(dq, dq_raw_native.data(), dq_raw_native.size()));
    CHECKPOSITIVE(
      BN_bn2nativepad(qi, qi_raw_native.data(), qi_raw_native.size()));

    auto [n_raw, e_raw] = RSAPublicKey_OpenSSL::rsa_public_raw_from_jwk(jwk);

    OSSL_PARAM params[9];
    params[0] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_RSA_N, n_raw.data(), n_raw.size());
    params[1] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_RSA_E, e_raw.data(), e_raw.size());
    params[2] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_RSA_D, d_raw_native.data(), d_raw_native.size());
    params[3] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_RSA_FACTOR1, p_raw_native.data(), p_raw_native.size());
    params[4] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_RSA_FACTOR2, q_raw_native.data(), q_raw_native.size());
    params[5] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_RSA_EXPONENT1,
      dp_raw_native.data(),
      dp_raw_native.size());
    params[6] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_RSA_EXPONENT2,
      dq_raw_native.data(),
      dq_raw_native.size());
    params[7] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
      qi_raw_native.data(),
      qi_raw_native.size());
    params[8] = OSSL_PARAM_construct_end();

    Unique_EVP_PKEY_CTX pctx("RSA");
    CHECK1(EVP_PKEY_fromdata_init(pctx));
    CHECK1(EVP_PKEY_fromdata(pctx, &key, EVP_PKEY_KEYPAIR, params));
#else
    auto rsa = RSAPublicKey_OpenSSL::rsa_public_from_jwk(jwk);
    CHECK1(RSA_set0_key(rsa, nullptr, nullptr, d));
    d.release();

    CHECK1(RSA_set0_factors(rsa, p, q));
    p.release();
    q.release();

    CHECK1(RSA_set0_crt_params(rsa, dp, dq, qi));
    dp.release();
    dq.release();
    qi.release();

    CHECK1(EVP_PKEY_set1_RSA(key, rsa));
#endif
  }

  size_t RSAKeyPair_OpenSSL::key_size() const
  {
    return RSAPublicKey_OpenSSL::key_size();
  }

  std::vector<uint8_t> RSAKeyPair_OpenSSL::rsa_oaep_unwrap(
    const std::vector<uint8_t>& input,
    const std::optional<std::vector<std::uint8_t>>& label)
  {
    const unsigned char* label_ = NULL;
    size_t label_size = 0;
    if (label.has_value())
    {
      if (label->empty())
      {
        throw std::logic_error("empty wrapping label");
      }
      label_ = label->data();
      label_size = label->size();
    }

    Unique_EVP_PKEY_CTX ctx(key);
    CHECK1(EVP_PKEY_decrypt_init(ctx));
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());

    if (label_)
    {
      unsigned char* openssl_label = (unsigned char*)OPENSSL_malloc(label_size);
      std::copy(label_, label_ + label_size, openssl_label);
      EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, openssl_label, label_size);
    }
    else
    {
      EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, NULL, 0);
    }

    size_t olen;
    CHECK1(EVP_PKEY_decrypt(ctx, NULL, &olen, input.data(), input.size()));

    std::vector<uint8_t> output(olen);
    CHECK1(
      EVP_PKEY_decrypt(ctx, output.data(), &olen, input.data(), input.size()));

    output.resize(olen);
    return output;
  }

  Pem RSAKeyPair_OpenSSL::private_key_pem() const
  {
    Unique_BIO buf;

    CHECK1(PEM_write_bio_PrivateKey(buf, key, NULL, NULL, 0, NULL, NULL));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }

  Pem RSAKeyPair_OpenSSL::public_key_pem() const
  {
    return PublicKey_OpenSSL::public_key_pem();
  }

  std::vector<uint8_t> RSAKeyPair_OpenSSL::public_key_der() const
  {
    return PublicKey_OpenSSL::public_key_der();
  }

  std::vector<uint8_t> RSAKeyPair_OpenSSL::sign(
    std::span<const uint8_t> d, MDType md_type, size_t salt_length) const
  {
    std::vector<uint8_t> r(2048);
    auto hash = OpenSSLHashProvider().Hash(d.data(), d.size(), md_type);
    Unique_EVP_PKEY_CTX pctx(key);
    CHECK1(EVP_PKEY_sign_init(pctx));
    CHECK1(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING));
    CHECK1(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt_length));
    CHECK1(EVP_PKEY_CTX_set_signature_md(pctx, get_md_type(md_type)));
    size_t olen = r.size();
    CHECK1(EVP_PKEY_sign(pctx, r.data(), &olen, hash.data(), hash.size()));
    r.resize(olen);
    return r;
  }

  bool RSAKeyPair_OpenSSL::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* signature,
    size_t signature_size,
    MDType md_type,
    size_t salt_length)
  {
    return RSAPublicKey_OpenSSL::verify(
      contents, contents_size, signature, signature_size, md_type, salt_length);
  }

  JsonWebKeyRSAPrivate RSAKeyPair_OpenSSL::private_key_jwk_rsa(
    const std::optional<std::string>& kid) const
  {
    JsonWebKeyRSAPrivate jwk = {RSAPublicKey_OpenSSL::public_key_jwk_rsa(kid)};

    Unique_BIGNUM d, p, q, dp, dq, qi;

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    d = RSAPublicKey_OpenSSL::get_bn_param(OSSL_PKEY_PARAM_RSA_D);
    p = RSAPublicKey_OpenSSL::get_bn_param(OSSL_PKEY_PARAM_RSA_FACTOR1);
    q = RSAPublicKey_OpenSSL::get_bn_param(OSSL_PKEY_PARAM_RSA_FACTOR2);
    dp = RSAPublicKey_OpenSSL::get_bn_param(OSSL_PKEY_PARAM_RSA_EXPONENT1);
    dq = RSAPublicKey_OpenSSL::get_bn_param(OSSL_PKEY_PARAM_RSA_EXPONENT2);
    qi = RSAPublicKey_OpenSSL::get_bn_param(OSSL_PKEY_PARAM_RSA_COEFFICIENT1);
#else
    const RSA* rsa = EVP_PKEY_get0_RSA(key);
    if (!rsa)
    {
      throw std::logic_error("invalid RSA key");
    }

    d = RSA_get0_d(rsa);
    p = RSA_get0_p(rsa);
    q = RSA_get0_q(rsa);
    dp = RSA_get0_dmp1(rsa);
    dq = RSA_get0_dmq1(rsa);
    qi = RSA_get0_iqmp(rsa);
#endif

    jwk.d = b64url_from_raw(RSAPublicKey_OpenSSL::bn_bytes(d), false);
    jwk.p = b64url_from_raw(RSAPublicKey_OpenSSL::bn_bytes(p), false);
    jwk.q = b64url_from_raw(RSAPublicKey_OpenSSL::bn_bytes(q), false);
    jwk.dp = b64url_from_raw(RSAPublicKey_OpenSSL::bn_bytes(dp), false);
    jwk.dq = b64url_from_raw(RSAPublicKey_OpenSSL::bn_bytes(dq), false);
    jwk.qi = b64url_from_raw(RSAPublicKey_OpenSSL::bn_bytes(qi), false);

    return jwk;
  }
}
