// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/hash.h"
#include "crypto/openssl/rsa_key_pair.h"
#include "openssl_wrappers.h"

namespace crypto
{
  using namespace OpenSSL;

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(EVP_PKEY* c) : PublicKey_OpenSSL(c)
  {
    if (!EVP_PKEY_get0_RSA(key))
    {
      throw std::logic_error("invalid RSA key");
    }
  }

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem);
    key = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    if (!key || !EVP_PKEY_get0_RSA(key))
    {
      throw std::logic_error("invalid RSA key");
    }
  }

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(const std::vector<uint8_t>& der)
  {
    const unsigned char* pp = der.data();
    RSA* rsa = NULL;
    if (
      ((rsa = d2i_RSA_PUBKEY(NULL, &pp, der.size())) ==
       NULL) && // "SubjectPublicKeyInfo structure" format
      ((rsa = d2i_RSAPublicKey(NULL, &pp, der.size())) ==
       NULL)) // PKCS#1 structure format
    {
      unsigned long ec = ERR_get_error();
      auto msg = OpenSSL::error_string(ec);
      throw std::runtime_error(fmt::format("OpenSSL error: {}", msg));
    }

    key = EVP_PKEY_new();
    OpenSSL::CHECK1(EVP_PKEY_set1_RSA(key, rsa));
    RSA_free(rsa);
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
    MDType md_type)
  {
    auto hash = OpenSSLHashProvider().Hash(contents, contents_size, md_type);
    Unique_EVP_PKEY_CTX pctx(key);
    CHECK1(EVP_PKEY_verify_init(pctx));
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

  RSAPublicKey::Components RSAPublicKey_OpenSSL::components() const
  {
    RSA* rsa = EVP_PKEY_get0_RSA(key);
    if (!rsa)
    {
      throw std::logic_error("invalid RSA key");
    }

    Components r;
    r.n = bn_bytes(RSA_get0_n(rsa));
    r.e = bn_bytes(RSA_get0_e(rsa));
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