// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/unit_strings.h"
#include "common/configuration.h"

#include <optional>
#include <string>

namespace host
{
  enum class EnclaveType
  {
    RELEASE,
    DEBUG
  };
  DECLARE_JSON_ENUM(
    EnclaveType,
    {{EnclaveType::RELEASE, "Release"}, {EnclaveType::DEBUG, "Debug"}});

  enum class EnclavePlatform
  {
    SGX,
    SNP,
    VIRTUAL,
  };
  DECLARE_JSON_ENUM(
    EnclavePlatform,
    {{EnclavePlatform::SGX, "SGX"},
     {EnclavePlatform::SNP, "SNP"},
     {EnclavePlatform::VIRTUAL, "Virtual"}});

  enum class LogFormat
  {
    TEXT,
    JSON
  };
  DECLARE_JSON_ENUM(
    LogFormat, {{LogFormat::TEXT, "Text"}, {LogFormat::JSON, "Json"}});

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
      EnclaveType type;
      EnclavePlatform platform;
    };
    Enclave enclave = {};

    // Other
    ds::TimeString tick_interval = {"10ms"};
    ds::TimeString slow_io_logging_threshold = {"10ms"};
    std::optional<std::string> node_client_interface = std::nullopt;
    ds::TimeString client_connection_timeout = {"2000ms"};
    std::optional<std::string> node_data_json_file = std::nullopt;
    std::optional<std::string> service_data_json_file = std::nullopt;

    struct OutputFiles
    {
      std::string node_certificate_file = "nodecert.pem";
      std::string pid_file = "cchost.pid";

      // Addresses files
      std::string node_to_node_address_file = "";
      std::string rpc_addresses_file = "";

      bool operator==(const OutputFiles&) const = default;
    };
    OutputFiles output_files = {};

    struct Ledger
    {
      std::string directory = "ledger";
      std::vector<std::string> read_only_directories = {};
      ds::SizeString chunk_size = {"5MB"};

      bool operator==(const Ledger&) const = default;
    };
    Ledger ledger = {};

    struct Snapshots
    {
      std::string directory = "snapshots";
      size_t tx_count = 10'000;
      std::optional<std::string> read_only_directory = std::nullopt;

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
      ds::SizeString circuit_size = {"4MB"};
      ds::SizeString max_msg_size = {"16MB"};
      ds::SizeString max_fragment_size = {"64KB"};

      bool operator==(const Memory&) const = default;
    };
    Memory memory = {};

    struct Command
    {
      StartType type = StartType::Start;
      std::string service_certificate_file = "service_cert.pem";

      struct Start
      {
        std::vector<ParsedMemberInfo> members = {};
        std::vector<std::string> constitution_files = {};
        ccf::ServiceConfiguration service_configuration;
        size_t initial_service_certificate_validity_days = 1;

        bool operator==(const Start&) const = default;
      };
      Start start = {};

      struct Join
      {
        ccf::NodeInfoNetwork::NetAddress target_rpc_address;
        ds::TimeString retry_timeout = {"1000ms"};

        bool operator==(const Join&) const = default;
      };
      Join join = {};

      struct Recover
      {
        size_t initial_service_certificate_validity_days = 1;
        std::string previous_service_identity_file;
        bool operator==(const Recover&) const = default;
      };
      Recover recover = {};
    };
    Command command = {};
  };

  DECLARE_JSON_TYPE(CCHostConfig::Enclave);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Enclave, type, file, platform);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::OutputFiles);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::OutputFiles);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::OutputFiles,
    node_certificate_file,
    pid_file,
    node_to_node_address_file,
    rpc_addresses_file);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Ledger);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Ledger);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::Ledger, directory, read_only_directories, chunk_size);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Snapshots);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Snapshots);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::Snapshots, directory, tx_count, read_only_directory);

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
    CCHostConfig::Command::Start,
    service_configuration,
    initial_service_certificate_validity_days);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Command::Join);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Command::Join, target_rpc_address);
  DECLARE_JSON_OPTIONAL_FIELDS(CCHostConfig::Command::Join, retry_timeout);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Command::Recover);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Command::Recover);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::Command::Recover,
    initial_service_certificate_validity_days,
    previous_service_identity_file);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Command);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Command, type);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::Command, service_certificate_file, start, join, recover);

  DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(CCHostConfig, CCFConfig);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig, enclave, command);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig,
    tick_interval,
    slow_io_logging_threshold,
    node_client_interface,
    client_connection_timeout,
    node_data_json_file,
    service_data_json_file,
    output_files,
    ledger,
    snapshots,
    logging,
    memory);
}