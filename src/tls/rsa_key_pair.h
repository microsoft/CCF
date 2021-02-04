// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "key_pair.h"

#include <optional>
#include <vector>

namespace tls
{
  // Compatible with Azure HSM encryption schemes (see
  // https://docs.microsoft.com/en-gb/azure/key-vault/keys/about-keys#wrapkeyunwrapkey-encryptdecrypt)
  static constexpr auto rsa_padding_mode = MBEDTLS_RSA_PKCS_V21;
  static constexpr auto rsa_padding_digest_id = MBEDTLS_MD_SHA256;

  class RSAPublicKey_mbedTLS : public PublicKey_mbedTLS
  {
  public:
    RSAPublicKey_mbedTLS() = default;

    RSAPublicKey_mbedTLS(mbedtls::PKContext&& c) :
      PublicKey_mbedTLS(std::move(c))
    {}

    /**
     * Construct from PEM
     */
    RSAPublicKey_mbedTLS(const Pem& pem) : PublicKey_mbedTLS(pem)
    {
      if (!mbedtls_pk_can_do(ctx.get(), MBEDTLS_PK_RSA))
      {
        throw std::logic_error("invalid RSA key");
      }
    }

    /**
     * Construct from DER
     */
    RSAPublicKey_mbedTLS(const std::vector<uint8_t>& der) :
      PublicKey_mbedTLS(der)
    {
      if (!mbedtls_pk_can_do(ctx.get(), MBEDTLS_PK_RSA))
      {
        throw std::logic_error("invalid RSA key");
      }
    }

    /**
     * Wrap data using RSA-OAEP-256
     *
     * @param input Pointer to raw data to wrap
     * @param input_size Size of raw data
     * @param label Optional string used as label during wrapping
     * @param label Optional string used as label during wrapping
     *
     * @return Wrapped data
     */
    std::vector<uint8_t> wrap(
      const uint8_t* input,
      size_t input_size,
      const uint8_t* label = nullptr,
      size_t label_size = 0)
    {
      mbedtls_rsa_context* rsa_ctx = mbedtls_pk_rsa(*ctx.get());
      mbedtls_rsa_set_padding(rsa_ctx, rsa_padding_mode, rsa_padding_digest_id);

      std::vector<uint8_t> output_buf(rsa_ctx->len);
      auto entropy = tls::create_entropy();

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

    /**
     * Wrap data using RSA-OAEP-256
     *
     * @param input Raw data to wrap
     * @param label Optional string used as label during wrapping
     *
     * @return Wrapped data
     */
    std::vector<uint8_t> wrap(
      const std::vector<uint8_t>& input,
      std::optional<std::string> label = std::nullopt)
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
  };

  class RSAKeyPair_MbedTLS : public RSAPublicKey_mbedTLS
  {
  public:
    static constexpr size_t default_public_key_size = 2048;
    static constexpr size_t default_public_exponent = 65537;

    /**
     * Create a new public / private RSA key pair
     */
    RSAKeyPair_MbedTLS(
      size_t public_key_size = default_public_key_size,
      size_t public_exponent = default_public_exponent)
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

    RSAKeyPair_MbedTLS(mbedtls::PKContext&& k) :
      RSAPublicKey_mbedTLS(std::move(k))
    {}

    RSAKeyPair_MbedTLS(const RSAKeyPair_MbedTLS&) = delete;

    RSAKeyPair_MbedTLS(const Pem& pem, CBuffer pw = nullb) :
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

    /**
     * Unwrap data using RSA-OAEP-256
     *
     * @param input Raw data to unwrap
     * @param label Optional string used as label during unwrapping
     *
     * @return Unwrapped data
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

  using RSAPublicKey = RSAPublicKey_mbedTLS;
  using RSAKeyPair = RSAKeyPair_MbedTLS;
  using RSAKeyPairPtr = std::shared_ptr<RSAKeyPair>;
  using RSAPublicKeyPtr = std::shared_ptr<RSAPublicKey>;

  /**
   * Create a new public / private RSA key pair with specified size and exponent
   */
  inline RSAKeyPairPtr make_rsa_key_pair(
    size_t public_key_size = RSAKeyPair::default_public_key_size,
    size_t public_exponent = RSAKeyPair::default_public_exponent)
  {
    return RSAKeyPairPtr(new RSAKeyPair(public_key_size, public_exponent));
  }

  /**
   * Create a public / private RSA key pair from existing private key data
   */
  inline RSAKeyPairPtr make_rsa_key_pair(const Pem& pkey, CBuffer pw = nullb)
  {
    return std::make_shared<RSAKeyPair_MbedTLS>(pkey, pw);
  }

  inline RSAPublicKeyPtr make_rsa_public_key(
    const uint8_t* public_pem_data, size_t public_pem_size)
  {
    auto ctx = mbedtls::make_unique<mbedtls::PKContext>();

    int rc =
      mbedtls_pk_parse_public_key(ctx.get(), public_pem_data, public_pem_size);
    if (rc != 0)
    {
      throw std::logic_error(
        fmt::format("Could not parse public key PEM: {}", error_string(rc)));
    }

    if (ctx->pk_info != mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))
    {
      throw std::logic_error(
        "Could not make RSA public key as PEM does not appear to be valid RSA");
    }

    return std::make_shared<RSAPublicKey>(std::move(ctx));
  }

  inline RSAPublicKeyPtr make_rsa_public_key(const Pem& public_pem)
  {
    return make_rsa_public_key(public_pem.data(), public_pem.size());
  }
}