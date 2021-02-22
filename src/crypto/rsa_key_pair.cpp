// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "rsa_key_pair.h"

#include "key_pair_mbedtls.h"
#include "key_pair_openssl.h"
#include "rsa_key_pair_mbedtls.h"
#include "rsa_key_pair_openssl.h"

namespace crypto
{
  // Compatible with Azure HSM encryption schemes (see
  // https://docs.microsoft.com/en-gb/azure/key-vault/keys/about-keys#wrapkeyunwrapkey-encryptdecrypt)
  static constexpr auto rsa_padding_mode = MBEDTLS_RSA_PKCS_V21;
  static constexpr auto rsa_padding_digest_id = MBEDTLS_MD_SHA256;

  RSAPublicKey_mbedTLS::RSAPublicKey_mbedTLS(mbedtls::PKContext&& c) :
    PublicKey_mbedTLS(std::move(c))
  {}

  RSAPublicKey_mbedTLS::RSAPublicKey_mbedTLS(const Pem& pem) :
    PublicKey_mbedTLS(pem)
  {
    if (!mbedtls_pk_can_do(ctx.get(), MBEDTLS_PK_RSA))
    {
      throw std::logic_error("invalid RSA key");
    }
  }

  RSAPublicKey_mbedTLS::RSAPublicKey_mbedTLS(const std::vector<uint8_t>& der) :
    PublicKey_mbedTLS(der)
  {
    if (!mbedtls_pk_can_do(ctx.get(), MBEDTLS_PK_RSA))
    {
      throw std::logic_error("invalid RSA key");
    }
  }

  std::vector<uint8_t> RSAPublicKey_mbedTLS::wrap(
    const uint8_t* input,
    size_t input_size,
    const uint8_t* label,
    size_t label_size)
  {
    mbedtls_rsa_context* rsa_ctx = mbedtls_pk_rsa(*ctx.get());
    mbedtls_rsa_set_padding(rsa_ctx, rsa_padding_mode, rsa_padding_digest_id);

    std::vector<uint8_t> output_buf(rsa_ctx->len);
    auto entropy = create_entropy();

    // Note that the maximum input size to wrap is k - 2*hLen - 2
    // where hLen is the hash size (32 bytes = SHA256) and
    // k the wrapping key modulus size (e.g. 256 bytes = 2048 bits).
    // In this example, it would be 190 bytes (1520 bits) max.
    // This is enough for wrapping AES keys for example.
    auto rc = mbedtls_rsa_rsaes_oaep_encrypt(
      rsa_ctx,
      entropy->get_rng(),
      entropy->get_data(),
      MBEDTLS_RSA_PUBLIC,
      label,
      label_size,
      input_size,
      input,
      output_buf.data());
    if (rc != 0)
    {
      throw std::logic_error(
        fmt::format("Error during RSA OEAP wrap: {}", error_string(rc)));
    }

    return output_buf;
  }

  std::vector<uint8_t> RSAPublicKey_mbedTLS::wrap(
    const std::vector<uint8_t>& input, std::optional<std::string> label)
  {
    const unsigned char* label_ = NULL;
    size_t label_size = 0;
    if (label.has_value())
    {
      label_ = reinterpret_cast<const unsigned char*>(label->c_str());
      label_size = label->size();
    }

    return wrap(input.data(), input.size(), label_, label_size);
  }

  Pem RSAPublicKey_mbedTLS::public_key_pem() const
  {
    return PublicKey_mbedTLS::public_key_pem();
  }

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(EVP_PKEY* c) : PublicKey_OpenSSL(c)
  {
    if (!EVP_PKEY_get0_RSA(key))
    {
      throw std::logic_error("invalid RSA key");
    }
  }

  RSAPublicKey_OpenSSL::RSAPublicKey_OpenSSL(const Pem& pem)
  {
    Unique_BIO mem(pem.data(), -1);
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
      const char* msg = ERR_error_string(ec, NULL);
      throw new std::runtime_error(fmt::format("OpenSSL error: {}", msg));
    }

    key = EVP_PKEY_new();
    OPENSSL_CHECK1(EVP_PKEY_set1_RSA(key, rsa));
    RSA_free(rsa);
  }

  std::vector<uint8_t> RSAPublicKey_OpenSSL::wrap(
    const uint8_t* input,
    size_t input_size,
    const uint8_t* label,
    size_t label_size)
  {
    Unique_EVP_PKEY_CTX ctx(key);
    OPENSSL_CHECK1(EVP_PKEY_encrypt_init(ctx));
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
    OPENSSL_CHECK1(EVP_PKEY_encrypt(ctx, NULL, &olen, input, input_size));

    std::vector<uint8_t> output(olen);
    OPENSSL_CHECK1(
      EVP_PKEY_encrypt(ctx, output.data(), &olen, input, input_size));

    output.resize(olen);
    return output;
  }

  std::vector<uint8_t> RSAPublicKey_OpenSSL::wrap(
    const std::vector<uint8_t>& input, std::optional<std::string> label)
  {
    const unsigned char* label_ = NULL;
    size_t label_size = 0;
    if (label.has_value())
    {
      label_ = reinterpret_cast<const unsigned char*>(label->c_str());
      label_size = label->size();
    }

    return wrap(input.data(), input.size(), label_, label_size);
  }

  Pem RSAPublicKey_OpenSSL::public_key_pem() const
  {
    return PublicKey_OpenSSL::public_key_pem();
  }

  RSAKeyPair_mbedTLS::RSAKeyPair_mbedTLS(
    size_t public_key_size, size_t public_exponent)
  {
    EntropyPtr entropy = create_entropy();

    int rc =
      mbedtls_pk_setup(ctx.get(), mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (rc != 0)
    {
      throw std::logic_error(
        "Could not set up RSA context: " + error_string(rc));
    }

    rc = mbedtls_rsa_gen_key(
      mbedtls_pk_rsa(*ctx.get()),
      entropy->get_rng(),
      entropy->get_data(),
      public_key_size,
      public_exponent);
    if (rc != 0)
    {
      throw std::logic_error(
        "Could not generate RSA keypair: " + error_string(rc));
    }
  }

  RSAKeyPair_mbedTLS::RSAKeyPair_mbedTLS(mbedtls::PKContext&& k) :
    RSAPublicKey_mbedTLS(std::move(k))
  {}

  RSAKeyPair_mbedTLS::RSAKeyPair_mbedTLS(const Pem& pem, CBuffer pw) :
    RSAPublicKey_mbedTLS()
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

  std::vector<uint8_t> RSAKeyPair_mbedTLS::unwrap(
    const std::vector<uint8_t>& input, std::optional<std::string> label)
  {
    mbedtls_rsa_context* rsa_ctx = mbedtls_pk_rsa(*ctx.get());
    mbedtls_rsa_set_padding(rsa_ctx, rsa_padding_mode, rsa_padding_digest_id);

    std::vector<uint8_t> output_buf(rsa_ctx->len);
    auto entropy = create_entropy();

    const unsigned char* label_ = NULL;
    size_t label_size = 0;
    if (label.has_value())
    {
      label_ = reinterpret_cast<const unsigned char*>(label->c_str());
      label_size = label->size();
    }

    size_t olen;
    auto rc = mbedtls_rsa_rsaes_oaep_decrypt(
      rsa_ctx,
      entropy->get_rng(),
      entropy->get_data(),
      MBEDTLS_RSA_PRIVATE,
      label_,
      label_size,
      &olen,
      input.data(),
      output_buf.data(),
      output_buf.size());
    if (rc != 0)
    {
      throw std::logic_error(
        fmt::format("Error during RSA OEAP unwrap: {}", error_string(rc)));
    }

    output_buf.resize(olen);
    return output_buf;
  }

  Pem RSAKeyPair_mbedTLS::public_key_pem() const
  {
    return PublicKey_mbedTLS::public_key_pem();
  }

  RSAKeyPair_OpenSSL::RSAKeyPair_OpenSSL(
    size_t public_key_size, size_t public_exponent)
  {
    RSA* rsa = NULL;
    BIGNUM* big_exp = NULL;
    OPENSSL_CHECKNULL(big_exp = BN_new());
    OPENSSL_CHECK1(BN_set_word(big_exp, public_exponent));
    OPENSSL_CHECKNULL(rsa = RSA_new());
    OPENSSL_CHECK1(RSA_generate_key_ex(rsa, public_key_size, big_exp, NULL));
    OPENSSL_CHECKNULL(key = EVP_PKEY_new());
    OPENSSL_CHECK1(EVP_PKEY_set1_RSA(key, rsa));
    BN_free(big_exp);
    RSA_free(rsa);
  }

  RSAKeyPair_OpenSSL::RSAKeyPair_OpenSSL(EVP_PKEY* k) :
    RSAPublicKey_OpenSSL(std::move(k))
  {}

  RSAKeyPair_OpenSSL::RSAKeyPair_OpenSSL(const Pem& pem, CBuffer pw)
  {
    Unique_BIO mem(pem.data(), -1);
    key = PEM_read_bio_PrivateKey(mem, NULL, NULL, (void*)pw.p);
    if (!key)
    {
      throw std::runtime_error("could not parse PEM");
    }
  }

  std::vector<uint8_t> RSAKeyPair_OpenSSL::unwrap(
    const std::vector<uint8_t>& input, std::optional<std::string> label)
  {
    const unsigned char* label_ = NULL;
    size_t label_size = 0;
    if (label.has_value())
    {
      label_ = reinterpret_cast<const unsigned char*>(label->c_str());
      label_size = label->size();
    }

    Unique_EVP_PKEY_CTX ctx(key);
    OPENSSL_CHECK1(EVP_PKEY_decrypt_init(ctx));
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
    OPENSSL_CHECK1(
      EVP_PKEY_decrypt(ctx, NULL, &olen, input.data(), input.size()));

    std::vector<uint8_t> output(olen);
    OPENSSL_CHECK1(
      EVP_PKEY_decrypt(ctx, output.data(), &olen, input.data(), input.size()));

    output.resize(olen);
    return output;
  }

  Pem RSAKeyPair_OpenSSL::public_key_pem() const
  {
    return PublicKey_OpenSSL::public_key_pem();
  }

#ifdef CRYPTO_PROVIDER_IS_MBEDTLS
  using RSAPublicKeyImpl = RSAPublicKey_mbedTLS;
  using RSAKeyPairImpl = RSAKeyPair_mbedTLS;
#else
  using RSAPublicKeyImpl = RSAPublicKey_OpenSSL;
  using RSAKeyPairImpl = RSAKeyPair_OpenSSL;
#endif

  RSAPublicKeyPtr make_rsa_public_key(const Pem& public_pem)
  {
    return make_rsa_public_key(public_pem.data(), public_pem.size());
  }

  RSAPublicKeyPtr make_rsa_public_key(const std::vector<uint8_t>& der)
  {
    return std::make_shared<RSAPublicKeyImpl>(der);
  }

  RSAPublicKeyPtr make_rsa_public_key(const uint8_t* data, size_t size)
  {
    if (size < 10 || strncmp("-----BEGIN", (char*)data, 10) != 0)
    {
      std::vector<uint8_t> der = {data, data + size};
      return std::make_shared<RSAPublicKeyImpl>(der);
    }
    else
    {
      Pem pem(data, size);
      return std::make_shared<RSAPublicKeyImpl>(pem);
    }
  }

  /**
   * Create a new public / private RSA key pair with specified size and exponent
   */
  RSAKeyPairPtr make_rsa_key_pair(
    size_t public_key_size, size_t public_exponent)
  {
    return std::make_shared<RSAKeyPairImpl>(public_key_size, public_exponent);
  }

  /**
   * Create a public / private RSA key pair from existing private key data
   */
  RSAKeyPairPtr make_rsa_key_pair(const Pem& pem, CBuffer pw)
  {
    return std::make_shared<RSAKeyPairImpl>(pem, pw);
  }
}
