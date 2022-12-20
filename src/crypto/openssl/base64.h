// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "crypto/openssl/openssl_wrappers.h"

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

      // Make sure the error queue is clean before we start
      // Trying to ameliorate #3677 and #3368
      ERR_clear_error();

      // Initialise the encode context
      OpenSSL::Unique_EVP_ENCODE_CTX ctx;
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
          "OSSL: Could not decode update from base64 string: {} [{} bytes out "
          "of {}, chunk_len = {}]",
          err_str,
          size,
          max_size,
          chunk_len));
      }
      encoded_len = chunk_len;

      rc = EVP_DecodeFinal(ctx, output + chunk_len, &chunk_len);
      if (rc != 1)
      {
        auto err_str = OpenSSL::error_string(ERR_get_error());
        throw std::logic_error(fmt::format(
          "OSSL: Could not decode final from base64 string: {} [{} bytes out "
          "of {}, chunk_len = {}]",
          err_str,
          size,
          max_size,
          chunk_len));
      }
      encoded_len += chunk_len;

      std::vector<uint8_t> ret(output, output + encoded_len);

      return ret;
    }

    // Encode byte stream into Base64
    static std::string b64_from_raw(const uint8_t* data, size_t size)
    {
      if (size == 0)
        return "";

      // Make sure the error queue is clean before we start
      // Trying to ameliorate #3677 and #3368
      ERR_clear_error();

      // Initialise the encode context
      OpenSSL::Unique_EVP_ENCODE_CTX ctx;
      EVP_EncodeInit(ctx);

      // Calculate the output buffer size: b64 is 6 bits per byte
      int max_size = EVP_ENCODE_LENGTH(size);
      unsigned char output[max_size];
      memset(output, '\0', max_size);

      // Encode Main Block (if size > 48)
      int chunk_len = 0;
      int rc = EVP_EncodeUpdate(ctx, output, &chunk_len, data, size);
      if (rc < 0)
      {
        auto err_str = OpenSSL::error_string(ERR_get_error());
        throw std::logic_error(fmt::format(
          "OSSL: Could not encode update to base64 string: {} [{} bytes out of "
          "{}, chunk_len = {}]",
          err_str,
          size,
          max_size,
          chunk_len));
      }

      // Encode Final Line (after previous lines, if any)
      EVP_EncodeFinal(ctx, output + chunk_len, &chunk_len);
      auto err = ERR_get_error();
      if (err != 0)
      {
        auto err_str = OpenSSL::error_string(err);
        throw std::logic_error(fmt::format(
          "OSSL: Could not encode final to base64 string: {} [{} bytes out of "
          "{}, chunk_len = {}]",
          err_str,
          size,
          max_size,
          chunk_len));
      }

      // Clean up result (last \0, newlines)
      std::string ret = (const char*)output;
      ret.pop_back();
      ret.erase(std::remove(ret.begin(), ret.end(), '\n'), ret.end());

      return ret;
    }
  };
}
