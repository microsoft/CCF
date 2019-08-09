// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <CLI11/CLI11.hpp>

namespace cli
{
  struct ParsedAddress
  {
    std::string hostname;
    std::string port;
  };

  CLI::Option* add_address_option(
    CLI::App& app,
    ParsedAddress& parsed,
    const std::string& option_name,
    const std::string& option_desc)
  {
    CLI::callback_t fun = [&parsed, option_name](CLI::results_t results) {
      if (results.size() != 1)
        throw std::logic_error(
          "Address for " + option_name + "could not be parsed");

      auto addr = results[0];
      auto found = addr.find_last_of(":");
      if (found == std::string::npos)
        throw std::logic_error(
          "Address for " + option_name + " is not in format host:port");

      auto hostname = addr.substr(0, found);
      auto port = addr.substr(found + 1);

      // Check if port is in valid range
      int port_int;
      try
      {
        port_int = std::stoi(port);
      }
      catch (const std::exception& e)
      {
        throw std::logic_error("Port for " + option_name + " is not a number");
      }
      if (port_int <= 0 || port_int > 65535)
        throw std::logic_error(
          "Port number is not in range 1-65535 for " + option_name);

      parsed.hostname = hostname;
      parsed.port = port;

      return true;
    };

    auto* option = app.add_option(option_name, fun, option_desc, true);

    return option;
  }

}