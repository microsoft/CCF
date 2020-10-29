// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "key_pair.h"

namespace tls
{
  class RSAKeyPair : public KeyPair
  {
  public:
    static constexpr size_t default_public_key_size = 2048;
    static constexpr size_t default_public_exponent = 65537;

    // TODO: Duplicated!
    // Compatible with Azure HSM encryption schemes (see
    // https://docs.microsoft.com/en-gb/azure/key-vault/keys/about-keys#wrapkeyunwrapkey-encryptdecrypt)
    static constexpr auto rsa_padding_mode = MBEDTLS_RSA_PKCS_V21;
    static constexpr auto rsa_padding_digest_id = MBEDTLS_MD_SHA256;

    /**
     * Create a new public / private RSA key pair
     */
    RSAKeyPair(
      size_t public_key_size = default_public_key_size,
      size_t public_exponent = default_public_exponent)
    {
      EntropyPtr entropy = create_entropy();
      mbedtls_pk_init(ctx.get());

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

    RSAKeyPair(std::unique_ptr<mbedtls_pk_context>&& k) : KeyPair(std::move(k))
    {}

    RSAKeyPair(const RSAKeyPair&) = delete;

    /**
     * Wrap data using RSAOAEP
     *
     * @param input Raw data to wrap
     * @param label Optional string used as label during wrapping
     *
     * @return Wrapped data
     */
    std::vector<uint8_t> unwrap(
      const std::vector<uint8_t>& input,
      std::optional<std::string> label = std::nullopt)
    {
      mbedtls_rsa_context* rsa_ctx = mbedtls_pk_rsa(*ctx.get());
      mbedtls_rsa_set_padding(rsa_ctx, rsa_padding_mode, rsa_padding_digest_id);

      std::vector<uint8_t> output_buf(rsa_ctx->len);
      auto entropy = tls::create_entropy();

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
  };

  using RSAKeyPairPtr = std::shared_ptr<RSAKeyPair>;

  inline RSAKeyPairPtr make_rsa_key_pair(
    size_t public_key_size = RSAKeyPair::default_public_key_size,
    size_t public_exponent = RSAKeyPair::default_public_exponent)
  {
    return RSAKeyPairPtr(new RSAKeyPair(public_key_size, public_exponent));
  }
}