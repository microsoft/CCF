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

namespace tls
{
  class RSAOEAPWrap
  {
  public:
    static std::vector<uint8_t> wrap(
      PublicKeyPtr wrapping_key_pair,
      const std::vector<uint8_t>& input,
      std::optional<std::string> label = std::nullopt)
    {
      mbedtls_rsa_context* rsa_ctx =
        mbedtls_pk_rsa(*wrapping_key_pair->get_raw_context());

      // TODO: Hardcoded to these for now. However, is this compatible with
      // Azure HSMs?
      mbedtls_rsa_set_padding(rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

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
          fmt::format("Error during RSA OEAP wrapping: {}", error_string(rc)));
      }

      return output_buf;
    }

    static void unwrap() {}
  };

}