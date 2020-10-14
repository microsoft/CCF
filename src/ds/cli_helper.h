// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/nonstd.h"
#include "tls/san.h"

#include <CLI11/CLI11.hpp>
#include <optional>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

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
      auto found = addr.find_last_of(":");
      auto hostname = addr.substr(0, found);

      const auto port =
        found == std::string::npos ? default_port : addr.substr(found + 1);

      // Check if port is in valid range
      int port_int;
      try
      {
        port_int = std::stoi(port);
      }
      catch (const std::exception&)
      {
        throw CLI::ValidationError(option_name, "Port is not a number");
      }
      if (port_int < 0 || port_int > 65535)
      {
        throw CLI::ValidationError(
          option_name, "Port number is not in range 0-65535");
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
    std::optional<std::string> member_data_file;

    ParsedMemberInfo(
      const std::string& cert,
      const std::string& keyshare_pub,
      const std::optional<std::string>& data_file) :
      cert_file(cert),
      keyshare_pub_file(keyshare_pub),
      member_data_file(data_file)
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
        std::stringstream ss(r);
        std::string chunk;
        std::vector<std::string> chunks;

        while (std::getline(ss, chunk, ','))
        {
          chunks.emplace_back(chunk);
        }

        if (chunks.size() < 2 || chunks.size() > 3)
        {
          throw CLI::ValidationError(
            option_name,
            "Member info is not in format "
            "member_cert.pem,member_encryption_public_key.pem[,member_data."
            "json]");
        }

        auto cert = chunks[0];
        auto keyshare_pub = chunks[1];

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

        std::optional<std::string> member_data = std::nullopt;

        if (chunks.size() == 3)
        {
          member_data = chunks[2];
          err_str = validator(member_data.value());
          if (!err_str.empty())
          {
            throw CLI::ValidationError(option_name, err_str);
          }
        }
        parsed.emplace_back(cert, keyshare_pub, member_data);
      }
      return true;
    };

    auto* option = app.add_option(option_name, fun, option_desc, true);
    option->type_name("member_cert.pem,member_enc_pubk.pem")->type_size(-1);

    return option;
  }

  static const std::string IP_ADDRESS_PREFIX("iPAddress:");
  static const std::string DNS_NAME_PREFIX("dNSName:");

  CLI::Option* add_subject_alternative_name_option(
    CLI::App& app,
    std::vector<tls::SubjectAltName>& parsed,
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
}