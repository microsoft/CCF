// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/hash.h"
#include "crypto/openssl/rsa_key_pair.h"

#include <openssl/core_names.h>
#include <openssl/encoder.h>

namespace
{
  using namespace ccf::crypto;
  using namespace OpenSSL;

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

  const std::unordered_map<RSAPadding, size_t> rsa_padding_openssl{
    {RSAPadding::PKCS1v15, RSA_PKCS1_PADDING},
    {RSAPadding::PKCS_PSS, RSA_PKCS1_PSS_PADDING}};

  void cleanup_pkey(EVP_PKEY** pkey)
  {
    if (*pkey != nullptr)
    {
      EVP_PKEY_free(*pkey);
      *pkey = nullptr;
    }
  }
}

namespace ccf::crypto
{
  using namespace OpenSSL;

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL() = default;
  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(EVP_PKEY* key) :
    PublicKey_OpenSSL(key)
  {
    if (EVP_PKEY_get_base_id(key) != EVP_PKEY_RSA)
    {
      throw std::logic_error(
        "Cannot construct RSAPublicKey_OpenSSL from non-RSA key");
    }
  }
  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(const Pem& pem) :
    PublicKey_OpenSSL(pem)
  {
    if (EVP_PKEY_get_base_id(key) != EVP_PKEY_RSA)
    {
      throw std::logic_error(
        "Cannot construct RSAPublicKey_OpenSSL from non-RSA key");
    }
  }
  RSAPublicKey_OpenSSL::~RSAPublicKey_OpenSSL() = default;

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(std::span<const uint8_t> der)
  {
    const unsigned char* pp = der.data();
    key = EVP_PKEY_new(); // NOLINT(cppcoreguidelines-prefer-member-initializer)
    if (
      ((key = d2i_PUBKEY(&key, &pp, der.size())) ==
       nullptr) && // "SubjectPublicKeyInfo structure" format
      ((key = d2i_PublicKey(EVP_PKEY_RSA, &key, &pp, der.size())) ==
       nullptr)) // PKCS#1 structure format
    {
      cleanup_pkey(&key);
      unsigned long ec = ERR_get_error();
      auto msg = OpenSSL::error_string(ec);
      throw std::runtime_error(fmt::format("OpenSSL error: {}", msg));
    }

    if (EVP_PKEY_get_base_id(key) != EVP_PKEY_RSA)
    {
      throw std::logic_error(
        "Cannot construct RSAPublicKey_OpenSSL from non-RSA key");
    }
  }

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(const JsonWebKeyRSAPublic& jwk)
  {
    key = EVP_PKEY_new(); // NOLINT(cppcoreguidelines-prefer-member-initializer)
    auto [n_raw, e_raw] = rsa_public_raw_from_jwk(jwk);

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_RSA_N, n_raw.data(), n_raw.size());
    params[1] = OSSL_PARAM_construct_BN(
      OSSL_PKEY_PARAM_RSA_E, e_raw.data(), e_raw.size());
    params[2] = OSSL_PARAM_construct_end();

    Unique_EVP_PKEY_CTX pctx("RSA");
    CHECK1(EVP_PKEY_fromdata_init(pctx));
    CHECK1(EVP_PKEY_fromdata(
      pctx, &key, EVP_PKEY_PUBLIC_KEY, static_cast<OSSL_PARAM*>(params)));
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

    if (label != nullptr && label_size > 0)
    {
      auto* openssl_label =
        static_cast<unsigned char*>(OPENSSL_malloc(label_size));
      std::copy(label, label + label_size, openssl_label);
      EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, openssl_label, label_size);
    }
    else
    {
      EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, nullptr, 0);
    }

    size_t olen = 0;
    OpenSSL::CHECK1(EVP_PKEY_encrypt(ctx, nullptr, &olen, input, input_size));

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

    return rsa_oaep_wrap(input.data(), input.size(), label_, label_size);
  }

  Pem RSAPublicKey_OpenSSL::public_key_pem() const
  {
    Unique_BIO buf;

    OpenSSL::CHECK1(PEM_write_bio_PUBKEY(buf, key));

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(buf, &bptr);
    return {reinterpret_cast<uint8_t*>(bptr->data), bptr->length};
  }

  std::vector<uint8_t> RSAPublicKey_OpenSSL::public_key_der() const
  {
    Unique_BIO buf;

    OpenSSL::CHECK1(i2d_PUBKEY_bio(buf, key));

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(buf, &bptr);
    return {bptr->data, bptr->data + bptr->length};
  }

  bool RSAPublicKey_OpenSSL::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* signature,
    size_t signature_size,
    MDType md_type,
    RSAPadding padding,
    size_t salt_length)
  {
    auto hash = OpenSSLHashProvider().Hash(contents, contents_size, md_type);
    return verify_hash(
      hash.data(),
      hash.size(),
      signature,
      signature_size,
      md_type,
      padding,
      salt_length);
  }

  bool RSAPublicKey_OpenSSL::verify_hash(
    const uint8_t* hash,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size,
    MDType md_type,
    RSAPadding padding,
    size_t salt_length)
  {
    auto ossl_padding = rsa_padding_openssl.find(padding);
    if (ossl_padding == rsa_padding_openssl.end())
    {
      throw std::logic_error("unsupported RSA padding");
    }

    Unique_EVP_PKEY_CTX pctx(key);
    CHECK1(EVP_PKEY_verify_init(pctx));
    CHECK1(EVP_PKEY_CTX_set_rsa_padding(pctx, ossl_padding->second));
    if (ossl_padding->first == RSAPadding::PKCS_PSS)
    {
      CHECK1(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt_length));
    }
    CHECK1(EVP_PKEY_CTX_set_signature_md(pctx, get_md_type(md_type)));
    return EVP_PKEY_verify(pctx, signature, signature_size, hash, hash_size) ==
      1;
  }

  Unique_BIGNUM RSAPublicKey_OpenSSL::get_bn_param(const char* key_name) const
  {
    Unique_BIGNUM r;
    BIGNUM* bn = nullptr;
    CHECK1(EVP_PKEY_get_bn_param(key, key_name, &bn));
    r.reset(bn);
    return r;
  }

  JsonWebKeyRSAPublic RSAPublicKey_OpenSSL::public_key_jwk(
    const std::optional<std::string>& kid) const
  {
    JsonWebKeyRSAPublic jwk;
    auto n = bn_to_bytes(get_bn_param(OSSL_PKEY_PARAM_RSA_N));
    auto e = bn_to_bytes(get_bn_param(OSSL_PKEY_PARAM_RSA_E));
    jwk.n = b64url_from_raw(n, false /* with_padding */);
    jwk.e = b64url_from_raw(e, false /* with_padding */);
    jwk.kid = kid;
    jwk.kty = JsonWebKeyType::RSA;
    return jwk;
  }

  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> rsa_public_raw_from_jwk(
    const JsonWebKeyRSAPublic& jwk)
  {
    auto [n, e] = get_modulus_and_exponent(jwk);
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> r(
      BN_num_bytes(n), BN_num_bytes(e));

    CHECKPOSITIVE(BN_bn2nativepad(n, r.first.data(), r.first.size()));
    CHECKPOSITIVE(BN_bn2nativepad(e, r.second.data(), r.second.size()));

    return r;
  }

  std::vector<uint8_t> bn_to_bytes(const BIGNUM* bn)
  {
    std::vector<uint8_t> r(BN_num_bytes(bn));
    BN_bn2bin(bn, r.data());
    return r;
  }

  RSAPublicKeyPtr make_rsa_public_key(const uint8_t* data, size_t size)
  {
    static constexpr auto PEM_BEGIN = "-----BEGIN";
    static constexpr auto PEM_BEGIN_LEN =
      std::char_traits<char>::length(PEM_BEGIN);

    if (
      size < PEM_BEGIN_LEN ||
      strncmp(PEM_BEGIN, reinterpret_cast<const char*>(data), PEM_BEGIN_LEN) !=
        0)
    {
      std::span<const uint8_t> der{data, size};
      return std::make_shared<RSAPublicKey_OpenSSL>(der);
    }

    Pem pem(data, size);
    return std::make_shared<RSAPublicKey_OpenSSL>(pem);
  }

  RSAPublicKeyPtr make_rsa_public_key(const Pem& public_pem)
  {
    return make_rsa_public_key(public_pem.data(), public_pem.size());
  }

  RSAPublicKeyPtr make_rsa_public_key(const std::vector<uint8_t>& der)
  {
    return std::make_shared<RSAPublicKey_OpenSSL>(der);
  }

  RSAPublicKeyPtr make_rsa_public_key(const JsonWebKeyRSAPublic& jwk)
  {
    return std::make_shared<RSAPublicKey_OpenSSL>(jwk);
  }
}