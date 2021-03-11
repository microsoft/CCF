// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "rsa_key_pair.h"

#include "crypto/mbedtls/rsa_public_key.h"
#include "entropy.h"
#include "mbedtls_wrappers.h"

namespace crypto
{
  using namespace mbedtls;

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

  size_t RSAKeyPair_mbedTLS::key_size() const
  {
    return RSAPublicKey_mbedTLS::key_size();
  }

  std::vector<uint8_t> RSAKeyPair_mbedTLS::rsa_oaep_unwrap(
    const std::vector<uint8_t>& input,
    std::optional<std::vector<std::uint8_t>> label)
  {
    mbedtls_rsa_context* rsa_ctx = mbedtls_pk_rsa(*ctx.get());
    mbedtls_rsa_set_padding(rsa_ctx, rsa_padding_mode, rsa_padding_digest_id);

    std::vector<uint8_t> output_buf(rsa_ctx->len);
    auto entropy = create_entropy();

    const unsigned char* label_ = NULL;
    size_t label_size = 0;
    if (label.has_value())
    {
      label_ = reinterpret_cast<const unsigned char*>(label->data());
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

  Pem RSAKeyPair_mbedTLS::private_key_pem() const
  {
    unsigned char data[max_pem_key_size];

    int rc = mbedtls_pk_write_key_pem(ctx.get(), data, sizeof(data));
    if (rc != 0)
    {
      throw std::logic_error("mbedtls_pk_write_key_pem: " + error_string(rc));
    }

    const size_t len = strlen((char const*)data);
    return Pem(data, len);
  }

  Pem RSAKeyPair_mbedTLS::public_key_pem() const
  {
    return PublicKey_mbedTLS::public_key_pem();
  }

  std::vector<uint8_t> RSAKeyPair_mbedTLS::public_key_der() const
  {
    return PublicKey_mbedTLS::public_key_der();
  }
}
