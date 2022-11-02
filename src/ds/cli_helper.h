// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/san.h"
#include "ccf/ds/nonstd.h"
#include "ccf/service/node_info_network.h"

#include <CLI11/CLI11.hpp>
#include <charconv>
#include <optional>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace cli
{
  using ParsedAddress = ccf::NodeInfoNetwork::NetAddress;

  static std::pair<std::string, std::string> validate_address(
    const ParsedAddress& addr, const std::string& default_port = "0")
  {
    auto found = addr.find_last_of(":");
    auto hostname = addr.substr(0, found);

    const auto port =
      found == std::string::npos ? default_port : addr.substr(found + 1);

    // Check if port is in valid range
    uint16_t port_n = 0;
    const auto [_, ec] =
      std::from_chars(port.data(), port.data() + port.size(), port_n);
    if (ec == std::errc::invalid_argument)
    {
      throw std::logic_error(fmt::format("Port '{}' is not a number", port));
    }
    else if (ec == std::errc::result_out_of_range)
    {
      throw std::logic_error(
        fmt::format("Port '{}' is not in range 0-65535", port));
    }
    else if (ec != std::errc())
    {
      throw std::logic_error(fmt::format("Error parsing port '{}'", port));
    }

    return std::make_pair(hostname, port);
  }

  static bool parse_address(
    const std::string& addr,
    ParsedAddress& parsed,
    const std::string& option_name,
    const std::string& default_port = "0")
  {
    try
    {
      validate_address(addr, default_port);
    }
    catch (const std::exception& e)
    {
      throw CLI::ValidationError(option_name, e.what());
    }

    parsed = addr;

    return true;
  }

  static CLI::Option* add_address_option(
    CLI::App& app,
    ParsedAddress& parsed,
    const std::string& option_name,
    const std::string& option_desc,
    const std::string& default_port = "0")
  {
    CLI::callback_t fun = [&parsed, option_name, default_port](
                            CLI::results_t results) {
      if (results.size() != 1)
      {
        throw CLI::ValidationError(option_name, "Address could not be parsed");
      }

      auto addr = results[0];
      return parse_address(addr, parsed, option_name, default_port);
    };

    auto* option = app.add_option(option_name, fun, option_desc, true);
    option->type_name("HOST:PORT");

    return option;
  }

  static const std::string IP_ADDRESS_PREFIX("iPAddress:");
  static const std::string DNS_NAME_PREFIX("dNSName:");

  static CLI::Option* add_subject_alternative_name_option(
    CLI::App& app,
    std::vector<crypto::SubjectAltName>& parsed,
    const std::string& option_name,
    const std::string& option_desc)
  {
    CLI::callback_t fun = [&parsed, option_name](CLI::results_t results) {
      for (auto& result : results)
      {
        if (result.starts_with(IP_ADDRESS_PREFIX))
        {
          parsed.push_back({result.substr(IP_ADDRESS_PREFIX.size()), true});
        }
        else if (result.starts_with(DNS_NAME_PREFIX))
        {
          parsed.push_back({result.substr(DNS_NAME_PREFIX.size()), false});
        }
        else
        {
          throw CLI::ValidationError(
            option_name,
            fmt::format(
              "SAN could not be parsed: {}, must be (iPAddress|dNSName):VALUE",
              result));
        }
      }

      return true;
    };

    auto* option = app.add_option(option_name, fun, option_desc, true);
    option->type_name("(iPAddress|dNSName):VALUE")->type_size(-1);

    return option;
  }
}