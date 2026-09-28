// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/json.h"
#include "ccf/node/configuration.h"
#include "node/rpc/node_call_types.h"

#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace ccf
{
  // Reads a file named by the operator configuration. Unlike files::slurp,
  // which exits the process, failures throw so that node creation fails with
  // an error naming the input.
  inline std::vector<uint8_t> read_startup_file(
    const std::string& path, const std::string& description)
  {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    std::ifstream f(path, std::ios::binary);
    if (ec || !f)
    {
      throw std::logic_error(
        fmt::format("Could not read {} from {}", description, path));
    }

    std::vector<uint8_t> contents(size);
    f.read(
      reinterpret_cast<char*>(contents.data()),
      static_cast<std::streamsize>(contents.size()));
    if (!f)
    {
      throw std::logic_error(
        fmt::format("Could not read {} from {}", description, path));
    }
    return contents;
  }

  // If allow_empty is set, an empty file is read as null, as by
  // files::slurp_json.
  inline nlohmann::json read_startup_json(
    const std::string& path, const std::string& description, bool allow_empty)
  {
    const auto contents = read_startup_file(path, description);
    if (allow_empty && contents.empty())
    {
      return nullptr;
    }

    try
    {
      return nlohmann::json::parse(contents.begin(), contents.end());
    }
    catch (const nlohmann::json::parse_error& e)
    {
      throw std::logic_error(fmt::format(
        "Could not parse {} from {}: {}", description, path, e.what()));
    }
  }

  inline CreateNetworkNodeToNode::GenesisInfo resolve_genesis_info(
    const CCFConfig::Command::Start& start)
  {
    CreateNetworkNodeToNode::GenesisInfo genesis;
    genesis.service_configuration = start.service_configuration;

    for (const auto& member : start.members)
    {
      std::optional<ccf::crypto::Pem> public_encryption_key = std::nullopt;
      std::optional<ccf::MemberRecoveryRole> recovery_role = std::nullopt;
      if (
        member.encryption_public_key_file.has_value() &&
        !member.encryption_public_key_file->empty())
      {
        public_encryption_key = ccf::crypto::Pem(read_startup_file(
          member.encryption_public_key_file.value(),
          "member encryption public key"));
        recovery_role = member.recovery_role;
      }

      nlohmann::json member_data = nullptr;
      if (member.data_json_file.has_value() && !member.data_json_file->empty())
      {
        member_data = read_startup_json(
          member.data_json_file.value(),
          "member data",
          false /* allow_empty */);
      }

      genesis.members.emplace_back(
        ccf::crypto::Pem(
          read_startup_file(member.certificate_file, "member certificate")),
        public_encryption_key,
        member_data,
        recovery_role);
    }

    for (const auto& path : start.constitution_files)
    {
      // Separate with single newlines
      if (!genesis.constitution.empty())
      {
        genesis.constitution += '\n';
      }
      const auto contents = read_startup_file(path, "constitution");
      genesis.constitution.append(contents.begin(), contents.end());
    }

    return genesis;
  }
}
