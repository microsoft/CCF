// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/san.h"
#include "ds/ccf_assert.h"
#include "ds/nonstd.h"
#include "node/node_info_network.h"

#include <CLI11/CLI11.hpp>
#include <charconv>
#include <optional>

#define FMT_HEADER_ONLY
#include "ds/logger.h"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

namespace cli
{
  using ParsedAddress = ccf::NodeInfoNetwork_v2::NetAddress;

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

  bool parse_address(
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

  CLI::Option* add_address_option(
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

  CLI::Option* add_subject_alternative_name_option(
    CLI::App& app,
    std::vector<crypto::SubjectAltName>& parsed,
    const std::string& option_name,
    const std::string& option_desc)
  {
    CLI::callback_t fun = [&parsed, option_name](CLI::results_t results) {
      for (auto& result : results)
      {
        if (nonstd::starts_with(result, IP_ADDRESS_PREFIX))
        {
          parsed.push_back({result.substr(IP_ADDRESS_PREFIX.size()), true});
        }
        else if (nonstd::starts_with(result, DNS_NAME_PREFIX))
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

  // TODO: Move to unit_strings.h
  static size_t convert_size_string(const std::string& input)
  {
    // TODO: Use string view!
    if (input.empty())
    {
      throw std::logic_error("Cannot convert empty string to size string");
    }

    auto unit_begin = input.end();
    while (unit_begin > input.begin() && std::isalpha(*(unit_begin - 1)))
    {
      unit_begin--;
    }

    auto unit = std::string(unit_begin, input.end());
    nonstd::to_lower(unit);
    auto value = std::string(input.begin(), unit_begin);

    size_t ret = 0;
    auto res = std::from_chars(value.data(), value.data() + value.size(), ret);
    if (res.ec != std::errc())
    {
      throw std::logic_error(fmt::format(
        "Could not convert value from size string \"{}\": {}", value, res.ec));
    }

    if (unit.empty())
    {
      return ret;
    }

    std::map<std::string, size_t> unit_mapping_power = {
      {"b", 0}, {"kb", 1}, {"mb", 2}, {"gb", 3}, {"tb", 4}, {"pb", 5}};

    auto power = unit_mapping_power.find(unit);
    if (power == unit_mapping_power.end())
    {
      // TODO: Return allowed units map
      std::string allowed_units_str;
      for (auto it = unit_mapping_power.begin(); it != unit_mapping_power.end();
           ++it)
      {
        allowed_units_str += it->first;
        if (std::next(it) != unit_mapping_power.end())
        {
          allowed_units_str += ", ";
        }
      }
      throw std::logic_error(fmt::format(
        "Unit {} is invalid. Allowed: {}", unit, allowed_units_str));
    }

    ret = ret * std::pow(1024, power->second);

    return ret;
  }

  inline static size_t convert_size_string2(std::string input)
  {
    size_t ret = 0;
    CLI::AsSizeValue(false)(input); // Parse all values as multiple of 1024
    auto rc = CLI::detail::integral_conversion(input, ret);
    CCF_ASSERT_FMT(rc, "Could not convert {} to size_t: {}", input, rc);
    return ret;
  }
}