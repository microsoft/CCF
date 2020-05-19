// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http_parser.h"
#include "tls/base64.h"
#include "tls/hash.h"

#include <optional>
#include <string>

namespace http
{
  class WebSocketUpgrader
  {
  private:
    // Constructs base64 acccept string (as per
    // https://tools.ietf.org/html/rfc6455#section-1.3)
    static std::optional<std::string> construct_accept_string(
      const std::string& client_key)
    {
      const auto string_to_hash =
        fmt::format("{}{}", client_key, WEBSOCKET_HANDSHAKE_GUID);

      const auto data = reinterpret_cast<const uint8_t*>(string_to_hash.data());
      const auto size = string_to_hash.size();

      tls::HashBytes accept_string_hash;
      tls::do_hash(data, size, accept_string_hash, MBEDTLS_MD_SHA1);

      return tls::b64_from_raw(
        accept_string_hash.data(), accept_string_hash.size());
    }

  public:
    // All HTTP headers are expected to be lowercase
    static constexpr auto HTTP_HEADER_UPGRADE = "upgrade";
    static constexpr auto HTTP_HEADER_CONNECTION = "connection";
    static constexpr auto HTTP_HEADER_WEBSOCKET_KEY = "sec-websocket-key";
    static constexpr auto HTTP_HEADER_WEBSOCKET_ACCEPT = "sec-websocket-accept";

    static constexpr auto UPGRADE_HEADER_WEBSOCKET = "websocket";
    static constexpr auto CONNECTION_HEADER_UPGRADE = "Upgrade";

    static constexpr auto WEBSOCKET_HANDSHAKE_GUID =
      "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    WebSocketUpgrader() {}

    static std::optional<std::vector<uint8_t>> upgrade_if_necessary(
      const http::HeaderMap& headers)
    {
      auto const upgrade_header = headers.find(HTTP_HEADER_UPGRADE);
      if (upgrade_header != headers.end())
      {
        auto const header_key = headers.find(HTTP_HEADER_WEBSOCKET_KEY);
        if (header_key == headers.end())
        {
          throw std::logic_error(fmt::format(
            "{} header missing from upgrade request",
            HTTP_HEADER_WEBSOCKET_KEY));
        }

        auto accept_string = construct_accept_string(header_key->second);
        if (!accept_string.has_value())
        {
          throw std::logic_error(fmt::format(
            "Error constructing {} header", HTTP_HEADER_WEBSOCKET_ACCEPT));
        }

        auto r = Response(HTTP_STATUS_SWITCHING_PROTOCOLS);
        r.set_header(HTTP_HEADER_UPGRADE, UPGRADE_HEADER_WEBSOCKET);
        r.set_header(HTTP_HEADER_CONNECTION, CONNECTION_HEADER_UPGRADE);
        r.set_header(HTTP_HEADER_WEBSOCKET_ACCEPT, accept_string.value());

        return r.build_response();
      }
      else
      {
        return {};
      }
    }
  };
}