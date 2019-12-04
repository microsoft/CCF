// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "httpparser.h"

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
    static constexpr auto HTTP_HEADER_AUTHORIZATION = "Authorization";
    static constexpr auto HTTP_HEADER_DIGEST = "Digest";

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
      std::string signature = {};
      std::string algo = {};
      std::vector<std::string> signed_headers;
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

  public:
    HttpSignatureVerifier(
      const http::HeaderMap& headers_, const std::vector<uint8_t>& body_) :
      headers(headers_),
      body(body_)
    {}

    std::optional<SignatureParams> parse()
    {
      auto auth = headers.find(HTTP_HEADER_AUTHORIZATION);
      if (auth != headers.end())
      {
        std::string_view authz_header = auth->second;

        if (!parse_auth_scheme(authz_header))
        {
          throw std::logic_error("Cannot parse authorization header");
        }

        return parse_signature_params(authz_header);
      }
      return {};
    }
  };
}