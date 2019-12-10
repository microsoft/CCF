// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "httpparser.h"
#include "node/clientsignatures.h"
#include "tls/base64.h"

#include <fmt/format_header_only.h>
#include <optional>
#include <string>
#include <tls/keypair.h> // TODO: Only used for hashing

namespace enclave
{
  // All HTTP headers are expected to be lowercase
  static constexpr auto HTTP_HEADER_AUTHORIZATION = "authorization";
  static constexpr auto HTTP_HEADER_DIGEST = "digest";

  static constexpr auto DIGEST_SHA256 = "SHA-256";

  static constexpr auto AUTH_SCHEME = "Signature";
  static constexpr auto SIGN_PARAMS_KEYID = "keyId";
  static constexpr auto SIGN_PARAMS_SIGNATURE = "signature";
  static constexpr auto SIGN_PARAMS_ALGORITHM = "algorithm";
  static constexpr auto SIGN_PARAMS_HEADERS = "headers";
  static constexpr auto SIGN_ALGORITHM = "ecdsa-sha256";

  static constexpr auto SIGN_PARAMS_DELIMITER = ",";
  static constexpr auto SIGN_PARAMS_HEADERS_DELIMITER = " ";

  std::optional<std::vector<uint8_t>> construct_raw_signed_string(
    const http::HeaderMap& headers,
    const std::vector<std::string_view>& headers_to_sign)
  {
    std::string signed_string = {};

    bool first = true;
    bool has_digest = false;

    for (const auto f : headers_to_sign)
    {
      const auto h = headers.find(f);
      if (h == headers.end())
      {
        LOG_FAIL_FMT("Signed header {} does not exist", f);
        return {};
      }

      // Digest field should be signed.
      if (f == HTTP_HEADER_DIGEST)
      {
        has_digest = true;
      }

      if (!first)
      {
        signed_string.append("\n");
      }
      first = false;

      signed_string.append(f);
      signed_string.append(": ");
      signed_string.append(h->second);
    }

    if (!has_digest)
    {
      LOG_FAIL_FMT("{} is not signed", HTTP_HEADER_DIGEST);
      return {};
    }

    auto ret =
      std::vector<uint8_t>({signed_string.begin(), signed_string.end()});
    return ret;
  }

  // Implements verification of "Signature" scheme from
  // https://tools.ietf.org/html/draft-cavage-http-signatures-12
  //
  // Tested with RequestClient in tests/infra/clients.py
  //
  // TODO:
  //    - Only supports public key crytography (i.e. no HMAC)
  //    - Only supports SHA-256 as digest algorithm
  //    - Only supports ecdsa-sha256 as signature algorithm
  //    - keyId is ignored
  class HttpSignatureVerifier
  {
  private:
    const http::HeaderMap& headers;
    const std::vector<uint8_t>& body;

    struct SignatureParams
    {
      std::string_view signature = {};
      std::string_view signature_algorithm = {};
      std::vector<std::string_view> signed_headers;
    };

    bool parse_auth_scheme(std::string_view& auth_header_value)
    {
      auto next_space = auth_header_value.find(" ");
      if (next_space == std::string::npos)
      {
        LOG_FAIL_FMT("Authorization header only contains one field!");
        return false;
      }
      auto auth_scheme = auth_header_value.substr(0, next_space);
      if (auth_scheme != AUTH_SCHEME)
      {
        LOG_FAIL_FMT("{} is the only supported scheme", AUTH_SCHEME);
        return false;
      }
      auth_header_value = auth_header_value.substr(next_space + 1);
      return true;
    }

    bool verify_digest()
    {
      // First, retrieve digest from header
      auto digest = headers.find(HTTP_HEADER_DIGEST);
      if (digest == headers.end())
      {
        LOG_FAIL_FMT("HTTP header does not contain {}", HTTP_HEADER_DIGEST);
        return false;
      }

      auto equal_pos = digest->second.find("=");
      if (equal_pos == std::string::npos)
      {
        LOG_FAIL_FMT(
          "{} header does not contain key=value", HTTP_HEADER_DIGEST);
        return false;
      }

      auto sha_key = digest->second.substr(0, equal_pos);
      if (sha_key != DIGEST_SHA256)
      {
        LOG_FAIL_FMT("Only {} digest is supported", DIGEST_SHA256);
        return false;
      }

      auto raw_digest = tls::raw_from_b64(digest->second.substr(equal_pos + 1));

      // Then, hash the request body
      tls::HashBytes body_digest;
      tls::do_hash(body.data(), body.size(), body_digest, MBEDTLS_MD_SHA256);

      if (raw_digest != body_digest)
      {
        LOG_FAIL_FMT(
          "Request body does not match {} header", HTTP_HEADER_DIGEST);
        return false;
      }

      return true;
    }

    // Parses a delimited string with no delimiter at the end
    // (e.g. "foo,bar,baz") and returns a vector parsed string views (e.g.
    // ["foo", "bar", "baz"])
    std::vector<std::string_view> parse_delimited_string(
      std::string_view& s, const std::string& delimiter)
    {
      std::vector<std::string_view> strings;
      bool last_string = false;

      auto next_delimiter = s.find(delimiter);
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

    std::optional<SignatureParams> parse_signature_params(
      std::string_view& auth_header_value)
    {
      SignatureParams sig_params = {};

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
          v.remove_prefix(v.find_first_of("\"") + 1);
          v.remove_suffix(v.size() - v.find_last_of("\""));

          if (k == SIGN_PARAMS_KEYID)
          {
            // keyId is ignored
          }
          else if (k == SIGN_PARAMS_ALGORITHM)
          {
            sig_params.signature_algorithm = v;
            if (v != SIGN_ALGORITHM)
            {
              LOG_FAIL_FMT("Signature algorithm {} is not supported", v);
              return {};
            }
          }
          else if (k == SIGN_PARAMS_SIGNATURE)
          {
            sig_params.signature = v;
          }
          else if (k == SIGN_PARAMS_HEADERS)
          {
            auto parsed_signed_headers =
              parse_delimited_string(v, SIGN_PARAMS_HEADERS_DELIMITER);

            if (parsed_signed_headers.size() == 0)
            {
              LOG_FAIL_FMT(
                "No headers specified in {} field", SIGN_PARAMS_HEADERS);
              return {};
            }

            for (const auto& h : parsed_signed_headers)
            {
              sig_params.signed_headers.emplace_back(h);
            }
          }
        }
        else
        {
          LOG_FAIL_FMT("Authorization parameter {} does not contain \"=\"", p);
          return {};
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

    std::optional<ccf::SignedReq> parse()
    {
      auto auth = headers.find(HTTP_HEADER_AUTHORIZATION);
      if (auth != headers.end())
      {
        std::string_view authz_header = auth->second;

        if (!parse_auth_scheme(authz_header))
        {
          throw std::logic_error(fmt::format(
            "Error parsing {} scheme. Only {} is supported",
            HTTP_HEADER_AUTHORIZATION,
            AUTH_SCHEME));
        }

        if (!verify_digest())
        {
          throw std::logic_error(
            fmt::format("Error verifying HTTP {} header", HTTP_HEADER_DIGEST));
        }

        auto parsed_sign_params = parse_signature_params(authz_header);
        if (!parsed_sign_params.has_value())
        {
          throw std::logic_error(
            fmt::format("Error parsing {} fields", HTTP_HEADER_AUTHORIZATION));
        }

        auto signed_raw = construct_raw_signed_string(
          headers, parsed_sign_params->signed_headers);
        if (!signed_raw.has_value())
        {
          throw std::logic_error(
            fmt::format("Error constructing signed string"));
        }

        auto sig_raw = tls::raw_from_b64(parsed_sign_params->signature);
        auto raw_req = std::vector<uint8_t>({body.begin(), body.end()});
        ccf::SignedReq ret = {
          sig_raw, signed_raw.value(), raw_req, MBEDTLS_MD_SHA256};
        return ret;
      }

      // The request does not contain the Authorization header
      return {};
    }
  };
}