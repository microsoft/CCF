// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "httpparser.h"
#include "node/clientsignatures.h"

#include <fmt/format_header_only.h>
#include <mbedtls/base64.h>
#include <optional>
#include <string>

namespace enclave
{
  // Implements verification of "Signature" scheme from
  // https://tools.ietf.org/html/draft-cavage-http-signatures-12
  //
  // Tested with RequestClient in tests/infra/clients.py
  //
  class HttpSignatureVerifier
  {
  private:
    static constexpr auto HTTP_HEADER_AUTHORIZATION = "Authorization";
    static constexpr auto HTTP_HEADER_DIGEST = "Digest";

    static constexpr auto DIGEST_SHA256 = "SHA-256";

    static constexpr auto AUTH_SCHEME = "Signature";
    static constexpr auto SIGN_PARAMS_KEYID = "keyId";
    static constexpr auto SIGN_PARAMS_SIGNATURE = "signature";
    static constexpr auto SIGN_PARAMS_ALGORITHM = "algorithm";
    static constexpr auto SIGN_PARAMS_HEADERS = "headers";

    static constexpr auto SIGN_PARAMS_DELIMITER = ",";
    static constexpr auto SIGN_PARAMS_HEADERS_DELIMITER = " ";

    const http::HeaderMap& headers;
    const std::vector<uint8_t>& body;

    struct SignatureParams
    {
      std::string_view signature = {};
      std::string_view algo = {};
      std::vector<std::string_view> signed_headers;
    };

    bool parse_auth_scheme(std::string_view& auth_header_value)
    {
      auto next_space = auth_header_value.find(" ");
      if (next_space == std::string::npos)
      {
        LOG_FAIL_FMT("Authz header only contains one field!");
        return false;
      }
      auto auth_scheme = auth_header_value.substr(0, next_space);
      if (auth_scheme != AUTH_SCHEME)
      {
        LOG_FATAL_FMT("{} is the only supported scheme", AUTH_SCHEME);
        return false;
      }
      auth_header_value = auth_header_value.substr(next_space + 1);
      return true;
    }

    // Parses a delimited string with no delimiter at the end
    // (e.g. "foo,bar,baz") and returns a vector parsed strings
    std::vector<std::string_view> parse_delimited_string(
      std::string_view& s, const std::string& delimiter)
    {
      std::vector<std::string_view> strings;

      auto next_delimiter = s.find(delimiter);
      bool last_string;

      while (next_delimiter != std::string::npos || !last_string)
      {
        auto token = s.substr(0, next_delimiter);
        if (next_delimiter == std::string::npos)
        {
          last_string = true;
        }

        strings.emplace_back(token);

        if (!last_string)
        {
          s = s.substr(next_delimiter + 1);
          next_delimiter = s.find(delimiter);
        }
      }

      return strings;
    }

    SignatureParams parse_signature_params(std::string_view& auth_header_value)
    {
      SignatureParams sig_params = {};

      auto next_comma = auth_header_value.find(SIGN_PARAMS_DELIMITER);
      bool last_key = false;

      auto parsed_params =
        parse_delimited_string(auth_header_value, SIGN_PARAMS_DELIMITER);

      for (auto& p : parsed_params)
      {
        auto eq_pos = p.find("=");
        if (eq_pos != std::string::npos)
        {
          auto k = p.substr(0, eq_pos);
          auto v = p.substr(eq_pos + 1);

          // Remove inverted commas around value
          v.remove_prefix(1);
          v.remove_suffix(1);

          if (k == SIGN_PARAMS_KEYID)
          {
            // keyId is ignored
          }
          else if (k == SIGN_PARAMS_ALGORITHM)
          {
            sig_params.algo = v;
          }
          else if (k == SIGN_PARAMS_SIGNATURE)
          {
            sig_params.signature = v;
          }
          else if (k == SIGN_PARAMS_HEADERS)
          {
            auto parsed_signed_headers =
              parse_delimited_string(v, SIGN_PARAMS_HEADERS_DELIMITER);
            for (const auto& h : parsed_signed_headers)
            {
              sig_params.signed_headers.emplace_back(h);
            }
          }
        }
        else
        {
          throw std::logic_error(fmt::format(
            "Authorization parameter {} does not contain \"=\"", p));
        }
      }

      return sig_params;
    }

    std::vector<uint8_t> construct_raw_signed_string(
      const std::vector<std::string_view>& signed_headers)
    {
      std::string signed_string = {};
      for (auto& f : signed_headers)
      {
        // Signed headers are listed in lowercase in Authorization headers
        // Uppercase first letter to find corresponding HTTP header
        auto f_ = std::string(f);
        f_[0] = std::toupper(f_[0]);

        auto h = headers.find(f_);
        if (h == headers.end())
        {
          throw std::logic_error(
            fmt::format("Signed header {} does not exist in request", f_));
        }
        signed_string.append(f);
        signed_string.append(": ");
        signed_string.append(h->second);
        signed_string.append("\n");
      }
      signed_string.pop_back(); // Remove the last \n

      LOG_FAIL_FMT("Signed string is {}", signed_string);

      return {signed_string.begin(), signed_string.end()};
    }

    // TODO: This should move to a specific base64 encoding-decoding file
    std::vector<uint8_t> raw_from_b64(const std::string_view& b64_string)
    {
      // TODO: Calculate the size of decoded bytes based on size of input base64
      // string
      std::vector<uint8_t> decoded(255);
      size_t len_written;
      std::vector<uint8_t> raw(b64_string.begin(), b64_string.end());

      auto rc = mbedtls_base64_decode(
        decoded.data(), decoded.size(), &len_written, raw.data(), raw.size());
      if (rc != 0)
      {
        LOG_FAIL_FMT(fmt::format(
          "Could not decode base64 string: {}", tls::error_string(rc)));
      }

      // TODO: Remove when size of decoded bytes is calculated properly
      decoded.resize(len_written);

      return decoded;
    }

    bool verify_digest()
    {
      // First, retrieve digest from header
      auto digest = headers.find(HTTP_HEADER_DIGEST);
      if (digest == headers.end())
      {
        throw std::logic_error(
          fmt::format("HTTP header does not contain {}", HTTP_HEADER_DIGEST));
      }

      auto equal_pos = digest->second.find("=");
      if (equal_pos == std::string::npos)
      {
        throw std::logic_error(fmt::format(
          "{} header does not contain key=value", HTTP_HEADER_DIGEST));
      }

      auto sha_key = digest->second.substr(0, equal_pos);
      if (sha_key != DIGEST_SHA256)
      {
        throw std::logic_error(
          fmt::format("Only {} digest is supported", DIGEST_SHA256));
      }

      auto raw_digest = raw_from_b64(digest->second.substr(equal_pos + 1));

      // Then, hash the request body
      tls::HashBytes body_digest;
      tls::do_hash(body.data(), body.size(), body_digest, MBEDTLS_MD_SHA256);
      LOG_FAIL_FMT(
        "Calculated digest is: {}",
        std::string(body_digest.begin(), body_digest.end()));

      if (raw_digest != body_digest)
      {
        throw std::logic_error(fmt::format(
          "Request body does not match {} header", HTTP_HEADER_DIGEST));
      }

      return true;
    }

  public:
    HttpSignatureVerifier(
      const http::HeaderMap& headers_, const std::vector<uint8_t>& body_) :
      headers(headers_),
      body(body_)
    {}

    std::optional<ccf::SignedReq> parse()
    {
      auto auth = headers.find(HTTP_HEADER_AUTHORIZATION);
      if (auth != headers.end())
      {
        std::string_view authz_header = auth->second;

        if (!verify_digest())
        {
          throw std::logic_error("Digest does not match request body");
        }

        if (!parse_auth_scheme(authz_header))
        {
          throw std::logic_error("Cannot parse authorization header");
        }

        auto parsed_sign_params = parse_signature_params(authz_header);
        auto signed_raw =
          construct_raw_signed_string(parsed_sign_params.signed_headers);

        auto sig_raw = raw_from_b64(parsed_sign_params.signature);

        LOG_FAIL_FMT("Returning sig_raw and signed_raw");
        ccf::SignedReq ret = {sig_raw, signed_raw};
        return ret;
      }
      return {};
    }
  };
}