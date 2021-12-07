// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "common/configuration.h"
#include "ds/unit_strings.h"

#include <optional>
#include <string>

namespace host
{
  enum class EnclaveType
  {
    RELEASE,
    DEBUG,
    VIRTUAL
  };
  DECLARE_JSON_ENUM(
    EnclaveType,
    {{EnclaveType::RELEASE, "release"},
     {EnclaveType::DEBUG, "debug"},
     {EnclaveType::VIRTUAL, "virtual"}});

  enum class LogFormat
  {
    TEXT,
    JSON
  };
  DECLARE_JSON_ENUM(
    LogFormat, {{LogFormat::TEXT, "text"}, {LogFormat::JSON, "json"}});

  struct ParsedMemberInfo
  {
    std::string certificate_file;
    std::optional<std::string> encryption_public_key_file = std::nullopt;
    std::optional<std::string> data_json_file = std::nullopt;

    bool operator==(const ParsedMemberInfo& other) const = default;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ParsedMemberInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ParsedMemberInfo, certificate_file);
  DECLARE_JSON_OPTIONAL_FIELDS(
    ParsedMemberInfo, encryption_public_key_file, data_json_file);

  struct CCHostConfig : CCFConfig
  {
    struct Enclave
    {
      std::string file;
      EnclaveType type = EnclaveType::RELEASE;
    };
    Enclave enclave = {};

    std::string node_certificate_file = "nodecert.pem";
    std::string node_pid_file = "cchost.pid";

    std::string network_certificate_file = "networkcert.pem";

    // Addresses files
    std::string node_address_file = "";
    std::string rpc_addresses_file = "";

    // Other
    ds::TimeString tick_period = std::string("10ms");
    ds::TimeString io_logging_threshold = std::string("10ms");
    std::optional<std::string> node_client_interface = std::nullopt;
    ds::TimeString client_connection_timeout = std::string("2000ms");

    struct Ledger
    {
      std::string directory = "ledger";
      std::vector<std::string> read_only_directories = {};
      ds::SizeString chunk_size = std::string("5MB");

      bool operator==(const Ledger&) const = default;
    };
    Ledger ledger = {};

    struct Snapshots
    {
      std::string directory = "snapshots";
      size_t interval_size = 10'000;

      bool operator==(const Snapshots&) const = default;
    };
    Snapshots snapshots = {};

    struct Logging
    {
      logger::Level host_level = logger::Level::INFO;
      LogFormat format = LogFormat::TEXT;

      bool operator==(const Logging&) const = default;
    };
    Logging logging = {};

    struct Memory
    {
      ds::SizeString circuit_size = std::string("4MB");
      ds::SizeString max_msg_size = std::string("16MB");
      ds::SizeString max_fragment_size = std::string("64KB");

      bool operator==(const Memory&) const = default;
    };
    Memory memory = {};

    struct Command
    {
      StartType type = StartType::Start;

      struct Start
      {
        std::vector<ParsedMemberInfo> members = {};
        std::vector<std::string> constitution_files = {};
        ccf::ServiceConfiguration service_configuration;

        bool operator==(const Start&) const = default;
      };
      Start start = {};

      struct Join
      {
        ccf::NodeInfoNetwork_v2::NetAddress target_rpc_address;
        ds::TimeString retry_timeout = std::string("1000ms");

        bool operator==(const Join&) const = default;
      };
      Join join = {};
    };
    Command command = {};
  };

  DECLARE_JSON_TYPE(CCHostConfig::Enclave);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Enclave, type, file);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Ledger);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Ledger);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::Ledger, directory, read_only_directories, chunk_size);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Snapshots);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Snapshots);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::Snapshots, directory, interval_size);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Logging);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Logging);
  DECLARE_JSON_OPTIONAL_FIELDS(CCHostConfig::Logging, host_level, format);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Memory);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Memory);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::Memory, circuit_size, max_msg_size, max_fragment_size);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Command::Start);
  DECLARE_JSON_REQUIRED_FIELDS(
    CCHostConfig::Command::Start, members, constitution_files);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::Command::Start, service_configuration);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Command::Join);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Command::Join, target_rpc_address);
  DECLARE_JSON_OPTIONAL_FIELDS(CCHostConfig::Command::Join, retry_timeout);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Command);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Command, type);
  DECLARE_JSON_OPTIONAL_FIELDS(CCHostConfig::Command, start, join);

  DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(CCHostConfig, CCFConfig);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig, enclave, command);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig,
    node_certificate_file,
    node_pid_file,
    node_address_file,
    rpc_addresses_file,
    tick_period,
    io_logging_threshold,
    node_client_interface,
    client_connection_timeout,
    network_certificate_file,
    ledger,
    snapshots,
    logging,
    memory);
}