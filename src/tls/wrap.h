// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls/entropy.h"
#include "tls/error_string.h"
#include "tls/key_pair.h"

#include <mbedtls/rsa.h>
#include <string>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

// TODO: Delete
namespace tls
{
  class RSAOEAPWrap
  {
  private:
    // Compatible with Azure HSM encryption schemes (see
    // https://docs.microsoft.com/en-gb/azure/key-vault/keys/about-keys#wrapkeyunwrapkey-encryptdecrypt)
    static constexpr auto rsa_padding_mode = MBEDTLS_RSA_PKCS_V21;
    static constexpr auto rsa_padding_digest_id = MBEDTLS_MD_SHA256;

  public:
    static std::vector<uint8_t> wrap(
      PublicKeyPtr wrapping_pub_key,
      const std::vector<uint8_t>& input,
      std::optional<std::string> label = std::nullopt)
    {
      mbedtls_rsa_context* rsa_ctx =
        mbedtls_pk_rsa(*wrapping_pub_key->get_raw_context());
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

      auto rc = mbedtls_rsa_rsaes_oaep_encrypt(
        rsa_ctx,
        entropy->get_rng(),
        entropy->get_data(),
        MBEDTLS_RSA_PUBLIC,
        label_,
        label_size,
        input.size(),
        input.data(),
        output_buf.data());
      if (rc != 0)
      {
        throw std::logic_error(
          fmt::format("Error during RSA OEAP wrap: {}", error_string(rc)));
      }

      return output_buf;
    }

    // static std::vector<uint8_t> unwrap(
    //   RSAKeyPairPtr wrapping_key_pair,
    //   const std::vector<uint8_t>& input,
    //   std::optional<std::string> label = std::nullopt)
    // {
    //   mbedtls_rsa_context* rsa_ctx =
    //     mbedtls_pk_rsa(*wrapping_key_pair->get_raw_context());
    //   mbedtls_rsa_set_padding(rsa_ctx, rsa_padding_mode,
    //   rsa_padding_digest_id);

    //   std::vector<uint8_t> output_buf(rsa_ctx->len);
    //   auto entropy = tls::create_entropy();

    //   const unsigned char* label_ = NULL;
    //   size_t label_size = 0;
    //   if (label.has_value())
    //   {
    //     label_ = reinterpret_cast<const unsigned char*>(label->c_str());
    //     label_size = label->size();
    //   }

    //   size_t olen;
    //   auto rc = mbedtls_rsa_rsaes_oaep_decrypt(
    //     rsa_ctx,
    //     entropy->get_rng(),
    //     entropy->get_data(),
    //     MBEDTLS_RSA_PRIVATE,
    //     label_,
    //     label_size,
    //     &olen,
    //     input.data(),
    //     output_buf.data(),
    //     output_buf.size());
    //   if (rc != 0)
    //   {
    //     throw std::logic_error(
    //       fmt::format("Error during RSA OEAP unwrap: {}", error_string(rc)));
    //   }

    //   output_buf.resize(olen);
    //   return output_buf;
    // }
  };

}