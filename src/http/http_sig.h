// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/base64.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/sha256_hash.h"
#include "ccf/http_consts.h"
#include "ccf/service/signed_req.h"
#include "http_parser.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <optional>
#include <string>

namespace http
{
  inline std::vector<uint8_t> construct_raw_signed_string(
    std::string verb,
    const std::string_view& url,
    const http::HeaderMap& headers,
    const std::vector<std::string_view>& headers_to_sign)
  {
    std::string signed_string = {};
    std::string value = {};
    bool first = true;

    for (const auto f : headers_to_sign)
    {
      if (f == auth::SIGN_HEADER_REQUEST_TARGET)
      {
        // Store verb as lowercase
        nonstd::to_lower(verb);
        value = fmt::format("{} {}", verb, url);
      }
      else
      {
        const auto h = headers.find(f);
        if (h == headers.end())
        {
          throw std::logic_error(
            fmt::format("Signed header '{}' does not exist", f));
        }

        value = h->second;
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

    return std::vector<uint8_t>({signed_string.begin(), signed_string.end()});
  }

  inline void add_digest_header(http::Request& request)
  {
    // Ensure digest is present and up-to-date
    crypto::Sha256Hash body_digest(
      request.get_content_data(), request.get_content_length());
    request.set_header(
      headers::DIGEST,
      fmt::format(
        "{}={}",
        "SHA-256",
        crypto::b64_from_raw(body_digest.h.data(), body_digest.SIZE)));
  }

  inline void sign_request(
    http::Request& request,
    const crypto::KeyPairPtr& kp,
    const std::string& key_id,
    const std::vector<std::string_view>& headers_to_sign)
  {
    add_digest_header(request);

    const auto to_sign = construct_raw_signed_string(
      llhttp_method_name(request.get_method()),
      fmt::format("{}{}", request.get_path(), request.get_formatted_query()),
      request.get_headers(),
      headers_to_sign);

    const auto signature = kp->sign(to_sign);

    auto auth_value = fmt::format(
      "Signature "
      "keyId=\"{}\",algorithm=\"{}\",headers=\"{}\",signature="
      "\"{}\"",
      key_id,
      auth::SIGN_ALGORITHM_HS_2019,
      fmt::format("{}", fmt::join(headers_to_sign, " ")),
      crypto::b64_from_raw(signature.data(), signature.size()));

    request.set_header(headers::AUTHORIZATION, auth_value);
  }

  inline void sign_request(
    http::Request& request,
    const crypto::KeyPairPtr& kp,
    const std::string& key_id)
  {
    std::vector<std::string_view> headers_to_sign;
    headers_to_sign.emplace_back(auth::SIGN_HEADER_REQUEST_TARGET);
    headers_to_sign.emplace_back(headers::DIGEST);
    headers_to_sign.emplace_back(headers::CONTENT_LENGTH);

    sign_request(request, kp, key_id, headers_to_sign);
  }

  // Implements verification of "Signature" scheme from
  // https://tools.ietf.org/html/draft-cavage-http-signatures-12
  //
  // Notes:
  //    - Only supports public key crytography (i.e. no HMAC)
  //    - Only supports SHA-256 as request digest algorithm
  //    - Only supports ecdsa-sha256 and hs2019 as signature algorithms
  //    - keyId can be set to a SHA-256 digest of a cert against which the
  //    signature verifies
  class HttpSignatureVerifier
  {
  public:
    struct SignatureParams
    {
      std::string_view signature = {};
      std::string_view signature_algorithm = {};
      std::vector<std::string_view> signed_headers;
      std::string key_id = {};
    };

    static void parse_auth_scheme(std::string_view& auth_header_value)
    {
      auto next_space = auth_header_value.find(" ");
      if (next_space == std::string::npos)
      {
        throw std::logic_error(fmt::format(
          "'{}' header only contains one field", headers::AUTHORIZATION));
      }
      auto auth_scheme = auth_header_value.substr(0, next_space);
      if (auth_scheme != auth::SIGN_AUTH_SCHEME)
      {
        throw std::logic_error(fmt::format(
          "'{}' scheme for signature should be '{}'",
          headers::AUTHORIZATION,
          auth::SIGN_AUTH_SCHEME));
      }
      auth_header_value = auth_header_value.substr(next_space + 1);
    }

    static bool verify_digest(
      const http::HeaderMap& headers,
      const std::vector<uint8_t>& body,
      std::string& error_reason)
    {
      // First, retrieve digest from header
      auto digest = headers.find(headers::DIGEST);
      if (digest == headers.end())
      {
        error_reason = fmt::format("Missing '{}' header", headers::DIGEST);
        return false;
      }

      auto equal_pos = digest->second.find("=");
      if (equal_pos == std::string::npos)
      {
        error_reason = fmt::format(
          "'{}' header does not contain key=value", headers::DIGEST);
        return false;
      }

      auto sha_key = digest->second.substr(0, equal_pos);
      if (sha_key != auth::DIGEST_SHA256)
      {
        error_reason = fmt::format(
          "'{}' for request digest is not supported, allowed: '{}'",
          sha_key,
          auth::DIGEST_SHA256);
        return false;
      }

      auto raw_digest =
        crypto::raw_from_b64(digest->second.substr(equal_pos + 1));

      // Then, hash the request body
      crypto::Sha256Hash body_digest({body.data(), body.size()});

      if (!std::equal(
            raw_digest.begin(),
            raw_digest.end(),
            body_digest.h.begin(),
            body_digest.h.end()))
      {
        error_reason = fmt::format(
          "Request body does not match '{}' header, calculated body "
          "digest = {:02x}",
          headers::DIGEST,
          fmt::join(body_digest.h, ""));
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

    static SignatureParams parse_signature_params(
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

          // Remove quotes around value, if present
          const bool begins_with_quote = v.front() == '"';
          const bool ends_with_quote = v.back() == '"';
          if (v.size() >= 2 && (begins_with_quote || ends_with_quote))
          {
            if (!(begins_with_quote && ends_with_quote))
            {
              throw std::logic_error(fmt::format(
                "Unbalanced quotes in '{}' header: {}",
                headers::AUTHORIZATION,
                p));
            }

            v = v.substr(1, v.size() - 2);
          }

          if (k == auth::SIGN_PARAMS_KEYID)
          {
            sig_params.key_id = v;
          }
          else if (k == auth::SIGN_PARAMS_ALGORITHM)
          {
            sig_params.signature_algorithm = v;
            if (
              v != auth::SIGN_ALGORITHM_ECDSA_SHA256 &&
              v != auth::SIGN_ALGORITHM_HS_2019)
            {
              throw std::logic_error(
                fmt::format("Signature algorithm '{}' is not supported", v));
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
              throw std::logic_error(fmt::format(
                "No headers specified in '{}' field",
                auth::SIGN_PARAMS_HEADERS));
            }

            for (const auto& h : parsed_signed_headers)
            {
              sig_params.signed_headers.emplace_back(h);
            }
          }
        }
        else
        {
          throw std::logic_error(fmt::format(
            "authorization parameter '{}' does not contain \"=\"", p));
        }
      }

      // If any sig params were not found, this is invalid
      if (sig_params.key_id.empty())
      {
        throw std::logic_error(fmt::format(
          "Signature params: Missing '{}'", auth::SIGN_PARAMS_KEYID));
      }
      if (sig_params.signature_algorithm.empty())
      {
        throw std::logic_error(fmt::format(
          "Signature params: Missing '{}'", auth::SIGN_PARAMS_ALGORITHM));
      }
      if (sig_params.signature.empty())
      {
        throw std::logic_error(fmt::format(
          "Signature params: Missing '{}'", auth::SIGN_PARAMS_SIGNATURE));
      }
      if (sig_params.signed_headers.empty())
      {
        throw std::logic_error(fmt::format(
          "Signature params: Missing '{}'", auth::SIGN_PARAMS_HEADERS));
      }

      return sig_params;
    }

    static std::optional<ccf::SignedReq> parse(
      const std::string& verb,
      const std::string_view& url,
      const http::HeaderMap& headers,
      const std::vector<uint8_t>& body)
    {
      auto auth = headers.find(headers::AUTHORIZATION);
      if (auth != headers.end())
      {
        std::string_view authz_header = auth->second;

        parse_auth_scheme(authz_header);

        std::string verify_error_reason;
        if (!verify_digest(headers, body, verify_error_reason))
        {
          throw std::logic_error(fmt::format(
            "Error verifying HTTP '{}' header: {}",
            headers::DIGEST,
            verify_error_reason));
        }

        auto parsed_sign_params = parse_signature_params(authz_header);

        const auto& signed_headers = parsed_sign_params.signed_headers;
        std::vector<std::string> missing_required_headers;
        for (const auto& required_header : http::required_signature_headers)
        {
          const auto it = std::find(
            signed_headers.begin(), signed_headers.end(), required_header);
          if (it == signed_headers.end())
          {
            missing_required_headers.push_back(required_header);
          }
        }

        if (!missing_required_headers.empty())
        {
          throw std::logic_error(fmt::format(
            "HTTP signature does not cover required fields: '{}'",
            fmt::join(missing_required_headers, ", ")));
        }

        auto signed_raw =
          construct_raw_signed_string(verb, url, headers, signed_headers);

        auto sig_raw = crypto::raw_from_b64(parsed_sign_params.signature);

        crypto::MDType md_type = crypto::MDType::NONE;
        if (
          parsed_sign_params.signature_algorithm ==
          auth::SIGN_ALGORITHM_ECDSA_SHA256)
        {
          md_type = crypto::MDType::SHA256;
        }

        return ccf::SignedReq{
          sig_raw, signed_raw, body, md_type, parsed_sign_params.key_id};
      }

      // Request does not contain authorization header
      return std::nullopt;
    }
  };
}
