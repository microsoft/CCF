// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <CLI11/CLI11.hpp>

namespace cli
{
  struct ParsedAddress
  {
    std::string hostname = {};
    std::string port = {};
  };

  CLI::Option* add_address_option(
    CLI::App& app,
    ParsedAddress& parsed,
    const std::string& option_name,
    const std::string& option_desc)
  {
    CLI::callback_t fun = [&parsed, option_name](CLI::results_t results) {
      if (results.size() != 1)
      {
        throw CLI::ValidationError(option_name, "Address could not be parsed");
      }

      auto addr = results[0];
      auto found = addr.find_last_of(":");
      if (found == std::string::npos)
      {
        throw CLI::ValidationError(
          option_name, "Address is not in format host:port");
      }

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
        throw CLI::ValidationError(option_name, "Port is not a number");
      }
      if (port_int <= 0 || port_int > 65535)
      {
        throw CLI::ValidationError(
          option_name, "Port number is not in range 1-65535");
      }

      parsed.hostname = hostname;
      parsed.port = port;

      return true;
    };

    auto* option = app.add_option(option_name, fun, option_desc, true);
    option->type_name("HOST:PORT");

    return option;
  }

  struct ParsedMemberInfo
  {
    std::string cert_file;
    std::string keyshare_pub_file;

    ParsedMemberInfo(const std::string& cert, const std::string& keyshare_pub) :
      cert_file(cert),
      keyshare_pub_file(keyshare_pub)
    {}
  };

  CLI::Option* add_member_info_option(
    CLI::App& app,
    std::vector<ParsedMemberInfo>& parsed,
    const std::string& option_name,
    const std::string& option_desc)
  {
    CLI::callback_t fun = [&option_name, &parsed](CLI::results_t res) {
      parsed.clear();
      for (const auto& r : res)
      {
        auto found = r.find_last_of(",");
        if (found == std::string::npos)
        {
          throw CLI::ValidationError(
            option_name,
            "Member info is not in format "
            "member_cert.pem,member_encryption_public_key.pem");
        }

        auto cert = r.substr(0, found);
        auto keyshare_pub = r.substr(found + 1);

        // Validate that member certificate and public encryption key exist
        auto validator = CLI::detail::ExistingFileValidator();
        auto err_str = validator(cert);
        if (!err_str.empty())
        {
          throw CLI::ValidationError(option_name, err_str);
        }
        err_str = validator(keyshare_pub);
        if (!err_str.empty())
        {
          throw CLI::ValidationError(option_name, err_str);
        }

        parsed.emplace_back(cert, keyshare_pub);
      }
      return true;
    };

    auto* option = app.add_option(option_name, fun, option_desc, true);
    option->type_name("member_cert.pem,member_kshare_pub.pem")->type_size(-1);

    return option;
  }
}