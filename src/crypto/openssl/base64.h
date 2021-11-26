// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/openssl/openssl_wrappers.h"
#include "ds/logger.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

// Inspired by openssl/test/evp_test.c
// Ref: https://www.openssl.org/docs/man1.1.1/man3/EVP_DecodeBlock.html

namespace crypto
{
  struct Base64_openssl
  {
    // Decode Base64 into byte stream
    static std::vector<uint8_t> raw_from_b64(const std::string_view& b64_string)
    {
      const auto data = reinterpret_cast<const uint8_t*>(b64_string.data());
      const auto size = b64_string.size();

      if (size == 0)
        return {};

      // Initialise the encode context
      auto ctx = EVP_ENCODE_CTX_new();
      EVP_DecodeInit(ctx);
      int encoded_len = 0;

      // Calculate the output buffer size: b64 is 6 bits per byte
      int max_size = EVP_DECODE_LENGTH(size);
      unsigned char output[max_size];
      memset(output, '\0', max_size);

      // Decode
      int chunk_len = 0;
      int rc = EVP_DecodeUpdate(ctx, output, &chunk_len, data, size);
      if (rc < 0)
      {
        auto err_str = OpenSSL::error_string(ERR_get_error());
        throw std::invalid_argument(fmt::format(
          "OSSL: Could not decode update from base64 string: {}", err_str));
      }
      encoded_len = chunk_len;

      rc = EVP_DecodeFinal(ctx, output + chunk_len, &chunk_len);
      if (rc != 1)
      {
        auto err_str = OpenSSL::error_string(ERR_get_error());
        throw std::logic_error(fmt::format(
          "OSSL: Could not decode final from base64 string: {}", err_str));
      }
      encoded_len += chunk_len;

      std::vector<uint8_t> ret(output, output + encoded_len);

      EVP_ENCODE_CTX_free(ctx);

      return ret;
    }

    // Encode byte stream into Base64
    static std::string b64_from_raw(const uint8_t* data, size_t size)
    {
      if (size == 0)
        return "";

      // Initialise the encode context
      auto ctx = EVP_ENCODE_CTX_new();
      EVP_EncodeInit(ctx);
      int encoded_len = 0;

      // Calculate the output buffer size: b64 is 6 bits per byte
      int max_size = EVP_ENCODE_LENGTH(size);
      unsigned char output[max_size];
      memset(output, '\0', max_size);

      // Encode Main Block (if size > 48)
      int chunk_len = 0;
      EVP_EncodeUpdate(ctx, output, &chunk_len, data, size);
      auto err = ERR_get_error();
      if (err != 0)
      {
        char err_str[256];
        ERR_error_string(err, err_str);
        throw std::logic_error(fmt::format(
          "OSSL: Could not encode update to base64 string: {}", err_str));
      }
      encoded_len = chunk_len;

      // Encode Final Line (after previous lines, if any)
      EVP_EncodeFinal(ctx, output + chunk_len, &chunk_len);
      err = ERR_get_error();
      if (err != 0)
      {
        char err_str[256];
        ERR_error_string(err, err_str);
        throw std::logic_error(fmt::format(
          "OSSL: Could not encode final to base64 string: {}", err_str));
      }
      encoded_len += chunk_len;

      // Clean up result (last \0, newlines)
      std::string ret = (const char*)output;
      ret.pop_back();
      ret.erase(std::remove(ret.begin(), ret.end(), '\n'), ret.end());

      EVP_ENCODE_CTX_free(ctx);

      return ret;
    }
  };
}
