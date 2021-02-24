// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "rsa_key_pair.h"

#include "entropy.h"
#include "mbedtls_wrappers.h"

namespace crypto
{
  using namespace mbedtls;

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
}
