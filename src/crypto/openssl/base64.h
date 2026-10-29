// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ds/internal_logger.h"

#include <algorithm>
#include <climits>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <span>
#include <string>
#include <vector>

// Inspired by openssl/test/evp_test.c
// Ref: https://www.openssl.org/docs/man1.1.1/man3/EVP_DecodeBlock.html

namespace ccf::crypto
{
  // Chosen chunk size, not a Base64 limit. EVP_EncodeUpdate and
  // EVP_DecodeUpdate take and return int lengths, and buffer partial groups
  // in the context, so input may be fed in chunks of any size. 16 MiB keeps
  // each call, and its output, well below INT_MAX.
  constexpr size_t BASE64_MAX_UPDATE_SIZE = size_t{16} * 1024 * 1024;

  struct Base64_openssl
  {
    // Decode Base64 into byte stream. The input is fed to OpenSSL in chunks
    // of at most chunk_size bytes; smaller sizes than the default only serve
    // to test chunk boundaries.
    static std::vector<uint8_t> raw_from_b64(
      const std::string_view& b64_string,
      size_t chunk_size = BASE64_MAX_UPDATE_SIZE)
    {
      std::span<const uint8_t> input(
        reinterpret_cast<const uint8_t*>(b64_string.data()), b64_string.size());
      const auto size = input.size();

      if (size == 0)
      {
        return {};
      }

      // Make sure the error queue is clean before we start
      // Trying to ameliorate #3677 and #3368
      ERR_clear_error();

      // Initialise the encode context
      OpenSSL::Unique_EVP_ENCODE_CTX ctx;
      EVP_DecodeInit(ctx);

      // Calculate the output buffer size: b64 is 6 bits per byte
      const size_t max_size = EVP_DECODE_LENGTH(size);
      std::vector<unsigned char> output(max_size, '\0');
      size_t decoded_len = 0;

      // EVP_DecodeUpdate returns 0 once it has seen the end of the content:
      // either padding, after which only whitespace may follow, or '-', which
      // it treats as an end marker and after which it ignores the rest of the
      // same call. The context remembers neither across calls, so a single
      // call's behaviour is reproduced here. The '-' case is told apart by
      // its position in the input.
      const auto eof_pos = b64_string.find('-');
      bool padded = false;
      size_t consumed = 0;

      while (!input.empty())
      {
        const auto chunk = input.first(std::min(input.size(), chunk_size));
        int chunk_len = 0;
        const int rc = EVP_DecodeUpdate(
          ctx,
          output.data() + decoded_len,
          &chunk_len,
          chunk.data(),
          static_cast<int>(chunk.size()));
        if (rc < 0)
        {
          auto err_str = OpenSSL::first_error();
          throw std::invalid_argument(fmt::format(
            "OSSL: Could not decode update from base64 string: {} [{} bytes "
            "out of {}, chunk_len = {}]",
            err_str,
            size,
            max_size,
            chunk_len));
        }
        decoded_len += static_cast<size_t>(chunk_len);
        consumed += chunk.size();
        input = input.subspan(chunk.size());

        // After padding, any output or buffered character is trailing data,
        // which a single call would have rejected
        if (padded && (chunk_len != 0 || EVP_ENCODE_CTX_num(ctx) != 0))
        {
          throw std::invalid_argument(
            "OSSL: Could not decode base64 string: data after padding");
        }

        if (rc == 0)
        {
          if (eof_pos < consumed)
          {
            break;
          }
          padded = true;
        }
      }

      int final_len = 0;
      const int rc =
        EVP_DecodeFinal(ctx, output.data() + decoded_len, &final_len);
      if (rc != 1)
      {
        auto err_str = OpenSSL::first_error();
        throw std::logic_error(fmt::format(
          "OSSL: Could not decode final from base64 string: {} [{} bytes out "
          "of {}, chunk_len = {}]",
          err_str,
          size,
          max_size,
          final_len));
      }
      decoded_len += static_cast<size_t>(final_len);

      std::vector<uint8_t> ret(output.data(), output.data() + decoded_len);

      return ret;
    }

    // Encode byte stream into Base64. The input is fed to OpenSSL in chunks
    // of at most chunk_size bytes; smaller sizes than the default only serve
    // to test chunk boundaries.
    static std::string b64_from_raw(
      const uint8_t* data,
      size_t size,
      size_t chunk_size = BASE64_MAX_UPDATE_SIZE)
    {
      if (size == 0)
      {
        return "";
      }

      std::span<const uint8_t> input(data, size);

      // Make sure the error queue is clean before we start
      // Trying to ameliorate #3677 and #3368
      ERR_clear_error();

      // Initialise the encode context
      OpenSSL::Unique_EVP_ENCODE_CTX ctx;
      EVP_EncodeInit(ctx);

      // Calculate the output buffer size: b64 is 6 bits per byte
      const size_t max_size = EVP_ENCODE_LENGTH(size);
      std::vector<unsigned char> output(max_size, '\0');
      size_t encoded_len = 0;

      // Encode Main Block (if size > 48)
      while (!input.empty())
      {
        const auto chunk = input.first(std::min(input.size(), chunk_size));
        int chunk_len = 0;
        // Returns 0 on error and 1 on success
        const int rc = EVP_EncodeUpdate(
          ctx,
          output.data() + encoded_len,
          &chunk_len,
          chunk.data(),
          static_cast<int>(chunk.size()));
        if (rc != 1)
        {
          auto err_str = OpenSSL::first_error();
          throw std::logic_error(fmt::format(
            "OSSL: Could not encode update to base64 string: {} [{} bytes out "
            "of {}, chunk_len = {}]",
            err_str,
            size,
            max_size,
            chunk_len));
        }
        encoded_len += static_cast<size_t>(chunk_len);
        input = input.subspan(chunk.size());
      }

      // Encode Final Line (after previous lines, if any)
      int final_len = 0;
      EVP_EncodeFinal(ctx, output.data() + encoded_len, &final_len);
      if (ERR_peek_error() != 0)
      {
        auto err_str = OpenSSL::first_error();
        throw std::logic_error(fmt::format(
          "OSSL: Could not encode final to base64 string: {} [{} bytes out of "
          "{}, chunk_len = {}]",
          err_str,
          size,
          max_size,
          final_len));
      }
      encoded_len += static_cast<size_t>(final_len);

      // Clean up result (newlines after every 64 characters and at the end)
      std::string ret(
        reinterpret_cast<const char*>(output.data()), encoded_len);
      ret.erase(std::remove(ret.begin(), ret.end(), '\n'), ret.end());

      return ret;
    }
  };
}
