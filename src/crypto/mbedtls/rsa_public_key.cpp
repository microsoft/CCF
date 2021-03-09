// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "rsa_public_key.h"

#include "entropy.h"
#include "mbedtls_wrappers.h"

namespace crypto
{
  using namespace mbedtls;

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

  size_t RSAPublicKey_mbedTLS::key_size() const
  {
    return mbedtls_rsa_get_len(mbedtls_pk_rsa(*ctx.get())) * 8;
  }

  std::vector<uint8_t> RSAPublicKey_mbedTLS::rsa_oaep_wrap(
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

  std::vector<uint8_t> RSAPublicKey_mbedTLS::rsa_oaep_wrap(
    const std::vector<uint8_t>& input,
    std::optional<std::vector<std::uint8_t>> label)
  {
    const unsigned char* label_ = NULL;
    size_t label_size = 0;
    if (label.has_value())
    {
      label_ = reinterpret_cast<const unsigned char*>(label->data());
      label_size = label->size();
    }

    return rsa_oaep_wrap(input.data(), input.size(), label_, label_size);
  }

  Pem RSAPublicKey_mbedTLS::public_key_pem() const
  {
    return PublicKey_mbedTLS::public_key_pem();
  }

  std::vector<uint8_t> RSAPublicKey_mbedTLS::public_key_der() const
  {
    return PublicKey_mbedTLS::public_key_der();
  }
}