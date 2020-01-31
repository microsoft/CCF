// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <arpa/inet.h> // For inet_addr()
#include <fmt/format_header_only.h>
#include <optional>

namespace ds
{
  static constexpr size_t ipv4_binary_size = 4;
  static constexpr size_t ipv6_binary_size = 16;

  struct IPAddr
  {
    char buf[ipv6_binary_size]; // Large enough buffer to hold IPv6
    size_t size;
  };

  inline std::optional<IPAddr> ip_to_binary(const char* hostname)
  {
    IPAddr ip_bin;
    ip_bin.size = ipv4_binary_size;
    if (inet_pton(AF_INET, hostname, ip_bin.buf) != 1)
    {
      ip_bin.size = ipv6_binary_size;
      if (inet_pton(AF_INET6, hostname, ip_bin.buf) != 1)
      {
        return {};
      }
    }
    return ip_bin;
  }

  inline bool is_valid_ip(const char* hostname)
  {
    return ip_to_binary(hostname).has_value();
  }
}