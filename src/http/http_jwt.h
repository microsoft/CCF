// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "http_consts.h"
#include "http_parser.h"
#include "tls/base64.h"
#include "tls/key_pair.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <optional>
#include <string>

namespace http
{
  enum class JwtCryptoAlgorithm
  {
    RS256
  };
  DECLARE_JSON_ENUM(JwtCryptoAlgorithm, {{JwtCryptoAlgorithm::RS256, "RS256"}});

  struct JwtHeader
  {
    JwtCryptoAlgorithm alg;
    std::string kid;
  };
  DECLARE_JSON_TYPE(JwtHeader)
  DECLARE_JSON_REQUIRED_FIELDS(JwtHeader, alg, kid)

  class JwtVerifier
  {
  public:
    struct Token
    {
      nlohmann::json header;
      JwtHeader header_typed;
      nlohmann::json payload;
      std::vector<uint8_t> signature;
      std::string_view signed_content;
    };

    static bool parse_auth_scheme(
      std::string_view& auth_header_value, std::string& error_reason)
    {
      auto next_space = auth_header_value.find(" ");
      if (next_space == std::string::npos)
      {
        error_reason = "Authorization header only contains one field";
        return false;
      }
      auto auth_scheme = auth_header_value.substr(0, next_space);
      if (auth_scheme != auth::BEARER_AUTH_SCHEME)
      {
        error_reason = fmt::format(
          "Authorization header does not have {} scheme",
          auth::BEARER_AUTH_SCHEME);
        return false;
      }
      auth_header_value = auth_header_value.substr(next_space + 1);
      return true;
    }

    static std::optional<Token> parse_token(
      std::string_view& token, std::string& error_reason)
    {
      constexpr char separator = '.';
      size_t first_dot = token.find(separator);
      size_t second_dot = std::string::npos;
      if (first_dot != std::string::npos)
      {
        second_dot = token.find(separator, first_dot + 1);
      }
      size_t extra_dot = std::string::npos;
      if (second_dot != std::string::npos)
      {
        extra_dot = token.find(separator, second_dot + 1);
      }
      if (
        first_dot == std::string::npos || second_dot == std::string::npos ||
        extra_dot != std::string::npos)
      {
        error_reason = "Malformed JWT: must contain exactly 3 parts";
        return std::nullopt;
      }
      size_t header_size = first_dot;
      size_t payload_size = second_dot - first_dot - 1;
      std::string_view header_b64url = token.substr(0, header_size);
      std::string_view payload_b64url =
        token.substr(first_dot + 1, payload_size);
      std::string_view signature_b64url = token.substr(second_dot + 1);
      auto header_raw = tls::raw_from_b64url(header_b64url);
      auto payload_raw = tls::raw_from_b64url(payload_b64url);
      auto signature_raw = tls::raw_from_b64url(signature_b64url);
      auto signed_content = token.substr(0, second_dot);
      nlohmann::json header;
      nlohmann::json payload;
      try
      {
        header = nlohmann::json::parse(header_raw);
        payload = nlohmann::json::parse(payload_raw);
      }
      catch (const nlohmann::json::parse_error& e)
      {
        error_reason =
          fmt::format("JWT header or payload is not valid JSON: {}", e.what());
        return std::nullopt;
      }
      if (!header.is_object() || !payload.is_object())
      {
        error_reason = "JWT header or payload is not an object";
        return std::nullopt;
      }
      JwtHeader header_typed;
      try
      {
        header_typed = header.get<JwtHeader>();
      }
      catch (const nlohmann::json::exception& e)
      {
        error_reason =
          fmt::format("JWT header does not follow schema: {}", e.what());
        return std::nullopt;
      }
      Token parsed = {
        header, header_typed, payload, signature_raw, signed_content};
      return parsed;
    }

    static std::optional<Token> extract_token(
      const http::HeaderMap& headers, std::string& error_reason)
    {
      const auto auth_it = headers.find(headers::AUTHORIZATION);
      if (auth_it == headers.end())
      {
        error_reason = fmt::format("Missing {} header", headers::AUTHORIZATION);
        return std::nullopt;
      }
      std::string_view token = auth_it->second;
      if (!parse_auth_scheme(token, error_reason))
      {
        return std::nullopt;
      }
      auto parsed = parse_token(token, error_reason);
      return parsed;
    }

    static bool validate_token_signature(
      const Token& token, std::vector<uint8_t> cert_der)
    {
      auto verifier = tls::make_unique_verifier(cert_der);
      bool valid = verifier->verify(
        (uint8_t*)token.signed_content.data(),
        token.signed_content.size(),
        token.signature.data(),
        token.signature.size(),
        crypto::MDType::SHA256);
      return valid;
    }
  };
}