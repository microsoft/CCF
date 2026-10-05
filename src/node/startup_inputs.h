// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/json.h"
#include "ccf/node/configuration.h"
#include "ccf/node/start_type.h"
#include "ccf/service_signing_keys.h"
#include "ds/internal_logger.h"
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

  // Resolved startup inputs from the operator configuration, other than the SNP
  // attestation files (read during quote generation) and the join transparent
  // statement (read on each join attempt).
  struct StartupInputs
  {
    nlohmann::json node_data = nullptr;
    // Start and Recover only
    nlohmann::json service_data = nullptr;
    // Start only
    std::optional<CreateNetworkNodeToNode::GenesisInfo> genesis_info =
      std::nullopt;
    // Join only
    std::vector<uint8_t> join_service_cert;
    // Recover only
    std::string service_cert_subject_name;
    std::optional<std::vector<uint8_t>> previous_service_identity =
      std::nullopt;
    std::optional<ServiceSigningKeys> previous_service_signing_keys =
      std::nullopt;
  };

  // Reads each input required by start_type exactly once, throwing if any
  // cannot be read, so that such failures happen when the node is created.
  inline StartupInputs resolve_startup_inputs(
    const CCFConfig& config, StartType start_type)
  {
    StartupInputs inputs;

    if (config.node_data_json_file.has_value())
    {
      inputs.node_data = read_startup_json(
        config.node_data_json_file.value(),
        "node data",
        true /* allow_empty */);
      LOG_TRACE_FMT("Read node_data: {}", inputs.node_data.dump());
    }

    if (
      config.service_data_json_file.has_value() &&
      start_type != StartType::Join)
    {
      inputs.service_data = read_startup_json(
        config.service_data_json_file.value(),
        "service data",
        true /* allow_empty */);
    }

    switch (start_type)
    {
      case StartType::Start:
      {
        inputs.genesis_info = resolve_genesis_info(config.command.start);
        break;
      }
      case StartType::Join:
      {
        inputs.join_service_cert = read_startup_file(
          config.command.service_certificate_file, "service certificate");
        break;
      }
      case StartType::Recover:
      {
        const auto& identity_file =
          config.command.recover.previous_service_identity_file;
        const auto& key_files =
          config.command.recover.previous_service_signing_key_files;
        if (!identity_file.has_value() && !key_files.has_value())
        {
          throw std::logic_error(
            "Recovery requires previous service signing keys or a previous "
            "service certificate");
        }

        if (identity_file.has_value())
        {
          LOG_INFO_FMT(
            "Reading previous service identity from {}", *identity_file);
          inputs.previous_service_identity =
            read_startup_file(*identity_file, "previous service identity");
          // The recovered service certificate inherits the previous subject
          inputs.service_cert_subject_name = ccf::crypto::get_subject_name(
            ccf::crypto::Pem(*inputs.previous_service_identity));
        }
        else
        {
          const auto& configured_subject =
            config.command.recover.service_cert_subject_name;
          if (!configured_subject.has_value())
          {
            throw std::logic_error(
              "Recovery without command.recover.previous_service_identity_file "
              "requires command.recover.service_cert_subject_name");
          }
          inputs.service_cert_subject_name = configured_subject.value();
        }
        if (key_files.has_value())
        {
          auto& keys = inputs.previous_service_signing_keys.emplace();
          const auto& path = key_files->at(SigningKeyType::CLASSICAL);
          LOG_INFO_FMT(
            "Reading previous CLASSICAL service signing public key from {}",
            path);
          keys.emplace(
            SigningKeyType::CLASSICAL,
            ccf::crypto::Pem(read_startup_file(
              path, "previous CLASSICAL service signing public key")));
        }
        break;
      }
      default:
      {
        // Unknown start types are rejected by NodeState::create()
        break;
      }
    }

    return inputs;
  }
}
