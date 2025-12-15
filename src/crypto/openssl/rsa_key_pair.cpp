// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/rsa_key_pair.h"

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/hash.h"

#include <openssl/core_names.h>

namespace ccf::crypto
{
  using namespace OpenSSL;

  RSAKeyPair_OpenSSL::RSAKeyPair_OpenSSL(
    size_t public_key_size, size_t public_exponent)
  {
    CHECKNULL(key = EVP_PKEY_new());
    Unique_BIGNUM big_exp;
    CHECK1(BN_set_word(big_exp, public_exponent));

    Unique_EVP_PKEY_CTX pctx("RSA");
    CHECK1(EVP_PKEY_keygen_init(pctx));
    CHECKPOSITIVE(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, public_key_size));
    CHECKPOSITIVE(EVP_PKEY_CTX_set1_rsa_keygen_pubexp(pctx, big_exp));
    CHECK1(EVP_PKEY_generate(pctx, &key));
  }

  RSAKeyPair_OpenSSL::RSAKeyPair_OpenSSL(EVP_PKEY* k) : RSAPublicKey_OpenSSL(k)
  {}

  RSAKeyPair_OpenSSL::RSAKeyPair_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem);
    key = PEM_read_bio_PrivateKey(mem, nullptr, nullptr, nullptr);
    if (key == nullptr)
    {
      throw std::runtime_error("could not parse PEM");
    }
  }

  RSAKeyPair_OpenSSL::RSAKeyPair_OpenSSL(const JsonWebKeyRSAPrivate& jwk)
  {
    key = EVP_PKEY_new();

    Unique_BIGNUM d;
    Unique_BIGNUM p;
    Unique_BIGNUM q;
    Unique_BIGNUM dp;
    Unique_BIGNUM dq;
    Unique_BIGNUM qi;
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

    auto [n_raw, e_raw] = rsa_public_raw_from_jwk(jwk);

    // NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
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
    // NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    Unique_EVP_PKEY_CTX pctx("RSA");
    CHECK1(EVP_PKEY_fromdata_init(pctx));
    CHECK1(EVP_PKEY_fromdata(
      pctx, &key, EVP_PKEY_KEYPAIR, static_cast<OSSL_PARAM*>(params)));
  }

  std::vector<uint8_t> RSAKeyPair_OpenSSL::rsa_oaep_unwrap(
    const std::vector<uint8_t>& input,
    const std::optional<std::vector<std::uint8_t>>& label)
  {
    const unsigned char* label_ = nullptr;
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

    if (label_ != nullptr)
    {
      auto* openssl_label =
        static_cast<unsigned char*>(OPENSSL_malloc(label_size));
      std::copy(label_, label_ + label_size, openssl_label);
      EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, openssl_label, label_size);
    }
    else
    {
      EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, nullptr, 0);
    }

    size_t olen = 0;
    CHECK1(EVP_PKEY_decrypt(ctx, nullptr, &olen, input.data(), input.size()));

    std::vector<uint8_t> output(olen);
    CHECK1(
      EVP_PKEY_decrypt(ctx, output.data(), &olen, input.data(), input.size()));

    output.resize(olen);
    return output;
  }

  Pem RSAKeyPair_OpenSSL::private_key_pem() const
  {
    Unique_BIO buf;

    CHECK1(PEM_write_bio_PrivateKey(
      buf, key, nullptr, nullptr, 0, nullptr, nullptr));

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(buf, &bptr);
    return {reinterpret_cast<uint8_t*>(bptr->data), bptr->length};
  }

  std::vector<uint8_t> RSAKeyPair_OpenSSL::private_key_der() const
  {
    Unique_BIO buf;

    OpenSSL::CHECK1(i2d_PrivateKey_bio(buf, key));

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(buf, &bptr);
    return {bptr->data, bptr->data + bptr->length};
  }

  JsonWebKeyRSAPrivate RSAKeyPair_OpenSSL::private_key_jwk(
    const std::optional<std::string>& kid) const
  {
    JsonWebKeyRSAPrivate jwk = {RSAPublicKey_OpenSSL::public_key_jwk(kid)};

    Unique_BIGNUM d;
    Unique_BIGNUM p;
    Unique_BIGNUM q;
    Unique_BIGNUM dp;
    Unique_BIGNUM dq;
    Unique_BIGNUM qi;

    d = RSAPublicKey_OpenSSL::get_bn_param(OSSL_PKEY_PARAM_RSA_D);
    p = RSAPublicKey_OpenSSL::get_bn_param(OSSL_PKEY_PARAM_RSA_FACTOR1);
    q = RSAPublicKey_OpenSSL::get_bn_param(OSSL_PKEY_PARAM_RSA_FACTOR2);
    dp = RSAPublicKey_OpenSSL::get_bn_param(OSSL_PKEY_PARAM_RSA_EXPONENT1);
    dq = RSAPublicKey_OpenSSL::get_bn_param(OSSL_PKEY_PARAM_RSA_EXPONENT2);
    qi = RSAPublicKey_OpenSSL::get_bn_param(OSSL_PKEY_PARAM_RSA_COEFFICIENT1);

    jwk.d = b64url_from_raw(bn_to_bytes(d), false);
    jwk.p = b64url_from_raw(bn_to_bytes(p), false);
    jwk.q = b64url_from_raw(bn_to_bytes(q), false);
    jwk.dp = b64url_from_raw(bn_to_bytes(dp), false);
    jwk.dq = b64url_from_raw(bn_to_bytes(dq), false);
    jwk.qi = b64url_from_raw(bn_to_bytes(qi), false);

    return jwk;
  }

  std::vector<uint8_t> RSAKeyPair_OpenSSL::sign(
    std::span<const uint8_t> d, MDType md_type, size_t salt_length) const
  {
    constexpr size_t MAX_SIG_SIZE = 2048;

    std::vector<uint8_t> r(MAX_SIG_SIZE);
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

  RSAKeyPairPtr make_rsa_key_pair(
    size_t public_key_size, size_t public_exponent)
  {
    return std::make_shared<RSAKeyPair_OpenSSL>(
      public_key_size, public_exponent);
  }

  RSAKeyPairPtr make_rsa_key_pair(const Pem& pem)
  {
    return std::make_shared<RSAKeyPair_OpenSSL>(pem);
  }

  RSAKeyPairPtr make_rsa_key_pair(const JsonWebKeyRSAPrivate& jwk)
  {
    return std::make_shared<RSAKeyPair_OpenSSL>(jwk);
  }
}
