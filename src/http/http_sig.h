// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http_consts.h"
#include "http_parser.h"
#include "node/client_signatures.h"
#include "tls/base64.h"
#include "tls/hash.h"
#include "tls/key_pair.h"

#include <fmt/format_header_only.h>
#include <optional>
#include <string>

namespace http
{
  inline std::optional<std::vector<uint8_t>> construct_raw_signed_string(
    std::string verb,
    const std::string_view& path,
    const std::string_view& query,
    const http::HeaderMap& headers,
    const std::vector<std::string_view>& headers_to_sign)
  {
    std::string signed_string = {};
    std::string value = {};
    bool has_digest = false;
    bool first = true;

    for (const auto f : headers_to_sign)
    {
      if (f == auth::SIGN_HEADER_REQUEST_TARGET)
      {
        // Store verb as lowercase
        std::transform(
          verb.begin(), verb.end(), verb.begin(), [](unsigned char c) {
            return std::tolower(c);
          });
        value = fmt::format("{} {}", verb, path);
        if (!query.empty())
        {
          value.append(fmt::format("?{}", query));
        }
      }
      else
      {
        const auto h = headers.find(f);
        if (h == headers.end())
        {
          LOG_FAIL_FMT("Signed header {} does not exist", f);
          return {};
        }

        value = h->second;

        // Digest field should be signed.
        if (f == headers::DIGEST)
        {
          has_digest = true;
        }
      }

      if (!first)
      {
        signed_string.append("\n");
      }
      first = false;

      signed_string.append(f);
      signed_string.append(": ");
      signed_string.append(value);
    }

    if (!has_digest)
    {
      LOG_FAIL_FMT("{} is not signed", headers::DIGEST);
      return {};
    }

    auto ret =
      std::vector<uint8_t>({signed_string.begin(), signed_string.end()});
    return ret;
  }

  struct SigningDetails
  {
    std::vector<uint8_t> to_sign;
    std::vector<uint8_t> signature;
  };

  inline void sign_request(
    http::Request& request,
    const tls::KeyPairPtr& kp,
    SigningDetails* details = nullptr)
  {
    std::vector<std::string_view> headers_to_sign;
    headers_to_sign.emplace_back(auth::SIGN_HEADER_REQUEST_TARGET);
    headers_to_sign.emplace_back(headers::DIGEST);
    headers_to_sign.emplace_back(headers::CONTENT_LENGTH);

    {
      // Ensure digest present and up-to-date
      const auto& headers = request.get_headers();

      tls::HashBytes body_digest;
      tls::do_hash(
        request.get_content_data(),
        request.get_content_length(),
        body_digest,
        MBEDTLS_MD_SHA256);
      request.set_header(
        headers::DIGEST,
        fmt::format(
          "{}={}",
          "SHA-256",
          tls::b64_from_raw(body_digest.data(), body_digest.size())));

      if (headers.find(headers::CONTENT_TYPE) != headers.end())
      {
        headers_to_sign.emplace_back(headers::CONTENT_TYPE);
      }
    }

    const auto to_sign = construct_raw_signed_string(
      http_method_str(request.get_method()),
      request.get_path(),
      request.get_formatted_query(),
      request.get_headers(),
      headers_to_sign);

    if (!to_sign.has_value())
    {
      throw std::logic_error("Unable to sign HTTP request");
    }

    const auto signature = kp->sign(to_sign.value(), MBEDTLS_MD_SHA256);

    auto auth_value = fmt::format(
      "Signature "
      "keyId=\"ignored\",algorithm=\"{}\",headers=\"{}\",signature="
      "\"{}\"",
      auth::SIGN_ALGORITHM_SHA256,
      fmt::format("{}", fmt::join(headers_to_sign, " ")),
      tls::b64_from_raw(signature.data(), signature.size()));

    request.set_header(headers::AUTHORIZATION, auth_value);

    if (details != nullptr)
    {
      details->to_sign = to_sign.value();
      details->signature = signature;
    }
  }

  // Implements verification of "Signature" scheme from
  // https://tools.ietf.org/html/draft-cavage-http-signatures-12
  //
  // Tested with RequestClient in tests/infra/clients.py
  //
  // Notes:
  //    - Only supports public key crytography (i.e. no HMAC)
  //    - Only supports SHA-256 as digest algorithm
  //    - Only supports ecdsa-sha256 as signature algorithm
  //    - keyId is ignored
  class HttpSignatureVerifier
  {
  public:
    struct SignatureParams
    {
      std::string_view signature = {};
      std::string_view signature_algorithm = {};
      std::vector<std::string_view> signed_headers;
    };

    static bool parse_auth_scheme(std::string_view& auth_header_value)
    {
      auto next_space = auth_header_value.find(" ");
      if (next_space == std::string::npos)
      {
        LOG_FAIL_FMT("Authorization header only contains one field!");
        return false;
      }
      auto auth_scheme = auth_header_value.substr(0, next_space);
      if (auth_scheme != auth::AUTH_SCHEME)
      {
        LOG_FAIL_FMT("{} is the only supported scheme", auth::AUTH_SCHEME);
        return false;
      }
      auth_header_value = auth_header_value.substr(next_space + 1);
      return true;
    }

    static bool verify_digest(
      const http::HeaderMap& headers, const std::vector<uint8_t>& body)
    {
      // First, retrieve digest from header
      auto digest = headers.find(headers::DIGEST);
      if (digest == headers.end())
      {
        LOG_FAIL_FMT("HTTP header does not contain {}", headers::DIGEST);
        return false;
      }

      auto equal_pos = digest->second.find("=");
      if (equal_pos == std::string::npos)
      {
        LOG_FAIL_FMT("{} header does not contain key=value", headers::DIGEST);
        return false;
      }

      auto sha_key = digest->second.substr(0, equal_pos);
      if (sha_key != auth::DIGEST_SHA256)
      {
        LOG_FAIL_FMT("Only {} digest is supported", auth::DIGEST_SHA256);
        return false;
      }

      auto raw_digest = tls::raw_from_b64(digest->second.substr(equal_pos + 1));

      // Then, hash the request body
      tls::HashBytes body_digest;
      tls::do_hash(body.data(), body.size(), body_digest, MBEDTLS_MD_SHA256);

      if (raw_digest != body_digest)
      {
        LOG_FAIL_FMT("Request body does not match {} header", headers::DIGEST);
        return false;
      }

      return true;
    }

    // Parses a delimited string with no delimiter at the end
    // (e.g. "foo,bar,baz") and returns a vector parsed string views (e.g.
    // ["foo", "bar", "baz"])
    static std::vector<std::string_view> parse_delimited_string(
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

    static std::optional<SignatureParams> parse_signature_params(
      std::string_view& auth_header_value)
    {
      SignatureParams sig_params = {};

      auto parsed_params =
        parse_delimited_string(auth_header_value, auth::SIGN_PARAMS_DELIMITER);

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

          if (k == auth::SIGN_PARAMS_KEYID)
          {
            // keyId is ignored
          }
          else if (k == auth::SIGN_PARAMS_ALGORITHM)
          {
            sig_params.signature_algorithm = v;
            if (v != auth::SIGN_ALGORITHM_SHA256)
            {
              LOG_FAIL_FMT("Signature algorithm {} is not supported", v);
              return {};
            }
          }
          else if (k == auth::SIGN_PARAMS_SIGNATURE)
          {
            sig_params.signature = v;
          }
          else if (k == auth::SIGN_PARAMS_HEADERS)
          {
            auto parsed_signed_headers =
              parse_delimited_string(v, auth::SIGN_PARAMS_HEADERS_DELIMITER);

            if (parsed_signed_headers.size() == 0)
            {
              LOG_FAIL_FMT(
                "No headers specified in {} field", auth::SIGN_PARAMS_HEADERS);
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

    static std::optional<ccf::SignedReq> parse(
      const std::string& verb,
      const std::string_view& path,
      const std::string_view& query,
      const http::HeaderMap& headers,
      const std::vector<uint8_t>& body)
    {
      auto auth = headers.find(headers::AUTHORIZATION);
      if (auth != headers.end())
      {
        std::string_view authz_header = auth->second;

        if (!parse_auth_scheme(authz_header))
        {
          throw std::logic_error(fmt::format(
            "Error parsing {} scheme. Only {} is supported",
            headers::AUTHORIZATION,
            auth::AUTH_SCHEME));
        }

        if (!verify_digest(headers, body))
        {
          throw std::logic_error(
            fmt::format("Error verifying HTTP {} header", headers::DIGEST));
        }

        auto parsed_sign_params = parse_signature_params(authz_header);
        if (!parsed_sign_params.has_value())
        {
          throw std::logic_error(
            fmt::format("Error parsing {} fields", headers::AUTHORIZATION));
        }

        auto signed_raw = construct_raw_signed_string(
          verb, path, query, headers, parsed_sign_params->signed_headers);
        if (!signed_raw.has_value())
        {
          throw std::logic_error(
            fmt::format("Error constructing signed string"));
        }

        auto sig_raw = tls::raw_from_b64(parsed_sign_params->signature);
        ccf::SignedReq ret = {
          sig_raw, signed_raw.value(), body, MBEDTLS_MD_SHA256};
        return ret;
      }

      // The request does not contain the Authorization header
      return std::nullopt;
    }
  };
}