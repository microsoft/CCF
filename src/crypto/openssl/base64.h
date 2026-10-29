// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ds/internal_logger.h"

#include <climits>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

// Inspired by openssl/test/evp_test.c
// Ref: https://www.openssl.org/docs/man1.1.1/man3/EVP_DecodeBlock.html

namespace ccf::crypto
{
  struct Base64_openssl
  {
    // Decode Base64 into byte stream
    static std::vector<uint8_t> raw_from_b64(const std::string_view& b64_string)
    {
      const auto* const data =
        reinterpret_cast<const uint8_t*>(b64_string.data());
      const auto size = b64_string.size();

      if (size == 0)
      {
        return {};
      }

      // The update call takes and returns int lengths, for both the input
      // and the output buffer.
      if (size > INT_MAX || EVP_DECODE_LENGTH(size) > INT_MAX)
      {
        throw std::invalid_argument(fmt::format(
          "OSSL: Base64 input of {} bytes is too large to decode", size));
      }

      // Make sure the error queue is clean before we start
      // Trying to ameliorate #3677 and #3368
      ERR_clear_error();

      // Initialise the encode context
      OpenSSL::Unique_EVP_ENCODE_CTX ctx;
      EVP_DecodeInit(ctx);
      int encoded_len = 0;

      // Calculate the output buffer size: b64 is 6 bits per byte
      const auto max_size = static_cast<int>(EVP_DECODE_LENGTH(size));
      std::vector<unsigned char> output(max_size, '\0');

      // Decode
      int chunk_len = 0;
      int rc = EVP_DecodeUpdate(
        ctx, output.data(), &chunk_len, data, static_cast<int>(size));
      if (rc < 0)
      {
        auto err_str = OpenSSL::first_error();
        throw std::invalid_argument(fmt::format(
          "OSSL: Could not decode update from base64 string: {} [{} bytes out "
          "of {}, chunk_len = {}]",
          err_str,
          size,
          max_size,
          chunk_len));
      }
      encoded_len = chunk_len;

      rc = EVP_DecodeFinal(ctx, output.data() + chunk_len, &chunk_len);
      if (rc != 1)
      {
        auto err_str = OpenSSL::first_error();
        throw std::logic_error(fmt::format(
          "OSSL: Could not decode final from base64 string: {} [{} bytes out "
          "of {}, chunk_len = {}]",
          err_str,
          size,
          max_size,
          chunk_len));
      }
      encoded_len += chunk_len;

      std::vector<uint8_t> ret(output.data(), output.data() + encoded_len);

      return ret;
    }

    // Encode byte stream into Base64
    static std::string b64_from_raw(const uint8_t* data, size_t size)
    {
      if (size == 0)
      {
        return "";
      }

      // The update call takes and returns int lengths, for both the input
      // and the output buffer.
      if (size > INT_MAX || EVP_ENCODE_LENGTH(size) > INT_MAX)
      {
        throw std::invalid_argument(fmt::format(
          "OSSL: Base64 input of {} bytes is too large to encode", size));
      }

      // Make sure the error queue is clean before we start
      // Trying to ameliorate #3677 and #3368
      ERR_clear_error();

      // Initialise the encode context
      OpenSSL::Unique_EVP_ENCODE_CTX ctx;
      EVP_EncodeInit(ctx);

      // Calculate the output buffer size: b64 is 6 bits per byte
      const auto max_size = static_cast<int>(EVP_ENCODE_LENGTH(size));
      std::vector<unsigned char> output(max_size, '\0');

      // Encode Main Block (if size > 48)
      int chunk_len = 0;
      int rc = EVP_EncodeUpdate(
        ctx, output.data(), &chunk_len, data, static_cast<int>(size));
      // Returns 0 on error and 1 on success
      if (rc != 1)
      {
        auto err_str = OpenSSL::first_error();
        throw std::logic_error(fmt::format(
          "OSSL: Could not encode update to base64 string: {} [{} bytes out of "
          "{}, chunk_len = {}]",
          err_str,
          size,
          max_size,
          chunk_len));
      }
      int encoded_len = chunk_len;

      // Encode Final Line (after previous lines, if any)
      EVP_EncodeFinal(ctx, output.data() + chunk_len, &chunk_len);
      if (ERR_peek_error() != 0)
      {
        auto err_str = OpenSSL::first_error();
        throw std::logic_error(fmt::format(
          "OSSL: Could not encode final to base64 string: {} [{} bytes out of "
          "{}, chunk_len = {}]",
          err_str,
          size,
          max_size,
          chunk_len));
      }
      encoded_len += chunk_len;

      // Clean up result (newlines after every 64 characters and at the end)
      std::string ret(
        reinterpret_cast<const char*>(output.data()), encoded_len);
      ret.erase(std::remove(ret.begin(), ret.end(), '\n'), ret.end());

      return ret;
    }
  };
}
