// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"

#include <fmt/format.h>
#include <string>
#include <utility>

namespace ccf
{
  // Splits a network address ("host:port") into its host and port components.
  // IPv6 literals are expected in bracketed form ("[host]:port"), and the
  // brackets are stripped from the returned host so that it can be used
  // directly for resolution, certificate SANs and comparison. A port-less
  // address ("host" or "[host]") returns the host with an empty port. The
  // inverse of make_net_address.
  // See https://www.rfc-editor.org/info/rfc3986/#section-3.2.3
  inline std::pair<std::string, std::string> split_net_address(
    const std::string& addr)
  {
    if (addr.starts_with('['))
    {
      // Only treat as a bracketed IPv6 literal if it is well-formed, i.e.
      // exactly "[host]" or "[host]:port". Anything else (e.g.
      // "[::1]foo:8000") falls through to the generic parsing below rather
      // than being silently mis-parsed.
      const auto close = addr.find(']');
      if (
        close != std::string::npos &&
        (close + 1 == addr.size() || addr[close + 1] == ':'))
      {
        std::string host = addr.substr(1, close - 1);
        std::string port;
        if (close + 1 < addr.size())
        {
          port = addr.substr(close + 2);
        }
        return std::make_pair(std::move(host), std::move(port));
      }
    }

    // rsplit_1 splits on the last ':'. When the address has no port it returns
    // ("", addr), which would wrongly put the host in the port slot; handle the
    // port-less case explicitly so the host stays in the first position.
    if (!addr.contains(':'))
    {
      return std::make_pair(addr, std::string());
    }

    auto [host, port] = ccf::nonstd::rsplit_1(addr, ":");
    return std::make_pair(std::string(host), std::string(port));
  }

  // Combines a host and port into a network address ("host:port"). IPv6
  // literals (hosts containing ':') are wrapped in brackets to produce an
  // unambiguous, URL-safe "[host]:port" form. Idempotent for already-bracketed
  // hosts. The inverse of split_net_address.
  inline std::string make_net_address(
    const std::string& host, const std::string& port)
  {
    if (host.contains(':') && !host.starts_with('['))
    {
      return fmt::format("[{}]:{}", host, port);
    }
    return fmt::format("{}:{}", host, port);
  }
}