// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/hash.h"
#include "crypto/openssl/rsa_key_pair.h"

#include <openssl/core_names.h>
#include <openssl/encoder.h>

namespace ccf::crypto
{
  using namespace OpenSSL;

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(EVP_PKEY* c) : PublicKey_OpenSSL(c)
  {
    if (EVP_PKEY_get_base_id(key) != EVP_PKEY_RSA)
    {
      throw std::logic_error("invalid RSA key");
    }
  }

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem);
    key = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    if (!key || EVP_PKEY_get_base_id(key) != EVP_PKEY_RSA)
    {
      throw std::logic_error("invalid RSA key");
    }
  }

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(std::span<const uint8_t> der)
  {
    const unsigned char* pp = der.data();
    key = EVP_PKEY_new();
    if (
      ((key = d2i_PUBKEY(&key, &pp, der.size())) ==
       NULL) && // "SubjectPublicKeyInfo structure" format
      ((key = d2i_PublicKey(EVP_PKEY_RSA, &key, &pp, der.size())) ==
       NULL)) // PKCS#1 structure format
    {
      unsigned long ec = ERR_get_error();
      auto msg = OpenSSL::error_string(ec);
      throw std::runtime_error(fmt::format("OpenSSL error: {}", msg));
    }

    // As it's a common pattern to rely on successful key wrapper construction
    // as a confirmation of a concrete key type, this must fail for non-RSA
    // keys.
    if (!key || EVP_PKEY_get_base_id(key) != EVP_PKEY_RSA)
    {
      throw std::logic_error("invalid RSA key");
    }
  }

  std::pair<Unique_BIGNUM, Unique_BIGNUM> get_modulus_and_exponent(
    const JsonWebKeyRSAPublic& jwk)
  {
    if (jwk.kty != JsonWebKeyType::RSA)
    {
      throw std::logic_error("Cannot construct public key from non-RSA JWK");
    }

    std::pair<Unique_BIGNUM, Unique_BIGNUM> ne;
    auto n_raw = raw_from_b64url(jwk.n);
    auto e_raw = raw_from_b64url(jwk.e);
    OpenSSL::CHECKNULL(BN_bin2bn(n_raw.data(), n_raw.size(), ne.first));
    OpenSSL::CHECKNULL(BN_bin2bn(e_raw.data(), e_raw.size(), ne.second));

    return ne;
  }

  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> RSAPublicKey_OpenSSL::
    rsa_public_raw_from_jwk(const JsonWebKeyRSAPublic& jwk)
  {
    auto [n, e] = get_modulus_and_exponent(jwk);
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> r(
      BN_num_bytes(n), BN_num_bytes(e));

    CHECKPOSITIVE(BN_bn2nativepad(n, r.first.data(), r.first.size()));
    CHECKPOSITIVE(BN_bn2nativepad(e, r.second.data(), r.second.size()));

    return r;
  }

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(const JsonWebKeyRSAPublic& jwk)
  {
    key = EVP_PKEY_new();
    auto [n_raw, e_raw] = rsa_public_raw_from_jwk(jwk);

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_RSA_N, n_raw.data(), n_raw.size());
    params[1] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_RSA_E, e_raw.data(), e_raw.size());
    params[2] = OSSL_PARAM_construct_end();

    Unique_EVP_PKEY_CTX pctx("RSA");
    CHECK1(EVP_PKEY_fromdata_init(pctx));
    CHECK1(EVP_PKEY_fromdata(pctx, &key, EVP_PKEY_PUBLIC_KEY, params));
  }

  size_t RSAPublicKey_OpenSSL::key_size() const
  {
    return EVP_PKEY_bits(key);
  }

  std::vector<uint8_t> RSAPublicKey_OpenSSL::rsa_oaep_wrap(
    const uint8_t* input,
    size_t input_size,
    const uint8_t* label,
    size_t label_size)
  {
    Unique_EVP_PKEY_CTX ctx(key);
    OpenSSL::CHECK1(EVP_PKEY_encrypt_init(ctx));
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());

    if (label)
    {
      unsigned char* openssl_label = (unsigned char*)OPENSSL_malloc(label_size);
      std::copy(label, label + label_size, openssl_label);
      EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, openssl_label, label_size);
    }
    else
    {
      EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, NULL, 0);
    }

    size_t olen;
    OpenSSL::CHECK1(EVP_PKEY_encrypt(ctx, NULL, &olen, input, input_size));

    std::vector<uint8_t> output(olen);
    OpenSSL::CHECK1(
      EVP_PKEY_encrypt(ctx, output.data(), &olen, input, input_size));

    output.resize(olen);
    return output;
  }

  std::vector<uint8_t> RSAPublicKey_OpenSSL::rsa_oaep_wrap(
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

    return rsa_oaep_wrap(input.data(), input.size(), label_, label_size);
  }

  Pem RSAPublicKey_OpenSSL::public_key_pem() const
  {
    return PublicKey_OpenSSL::public_key_pem();
  }

  std::vector<uint8_t> RSAPublicKey_OpenSSL::public_key_der() const
  {
    return PublicKey_OpenSSL::public_key_der();
  }

  bool RSAPublicKey_OpenSSL::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* signature,
    size_t signature_size,
    MDType md_type,
    size_t salt_length)
  {
    auto hash = OpenSSLHashProvider().Hash(contents, contents_size, md_type);
    Unique_EVP_PKEY_CTX pctx(key);
    CHECK1(EVP_PKEY_verify_init(pctx));
    CHECK1(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING));
    CHECK1(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt_length));
    CHECK1(EVP_PKEY_CTX_set_signature_md(pctx, get_md_type(md_type)));
    return EVP_PKEY_verify(
             pctx, signature, signature_size, hash.data(), hash.size()) == 1;
  }

  bool RSAPublicKey_OpenSSL::verify_pkcs1(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* signature,
    size_t signature_size,
    MDType md_type)
  {
    auto hash = OpenSSLHashProvider().Hash(contents, contents_size, md_type);
    Unique_EVP_PKEY_CTX pctx(key);
    CHECK1(EVP_PKEY_verify_init(pctx));
    CHECK1(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING));
    CHECK1(EVP_PKEY_CTX_set_signature_md(pctx, get_md_type(md_type)));
    return EVP_PKEY_verify(
             pctx, signature, signature_size, hash.data(), hash.size()) == 1;
  }

  std::vector<uint8_t> RSAPublicKey_OpenSSL::bn_bytes(const BIGNUM* bn)
  {
    std::vector<uint8_t> r(BN_num_bytes(bn));
    BN_bn2bin(bn, r.data());
    return r;
  }

  Unique_BIGNUM RSAPublicKey_OpenSSL::get_bn_param(const char* key_name) const
  {
    Unique_BIGNUM r;
    BIGNUM* bn = NULL;
    CHECK1(EVP_PKEY_get_bn_param(key, key_name, &bn));
    r.reset(bn);
    return r;
  }

  RSAPublicKey::Components RSAPublicKey_OpenSSL::components() const
  {
    Components r;
    r.n = bn_bytes(get_bn_param(OSSL_PKEY_PARAM_RSA_N));
    r.e = bn_bytes(get_bn_param(OSSL_PKEY_PARAM_RSA_E));
    return r;
  }

  JsonWebKeyRSAPublic RSAPublicKey_OpenSSL::public_key_jwk_rsa(
    const std::optional<std::string>& kid) const
  {
    JsonWebKeyRSAPublic jwk;
    auto comps = components();
    jwk.n = b64url_from_raw(comps.n, false /* with_padding */);
    jwk.e = b64url_from_raw(comps.e, false /* with_padding */);
    jwk.kid = kid;
    jwk.kty = JsonWebKeyType::RSA;
    return jwk;
  }
}