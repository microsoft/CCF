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
    DEBUG,
    VIRTUAL // Deprecated (use EnclavePlatform instead)
  };
  DECLARE_JSON_ENUM(
    EnclaveType,
    {{EnclaveType::RELEASE, "Release"},
     {EnclaveType::DEBUG, "Debug"},
     {EnclaveType::VIRTUAL, "Virtual"}});

  enum class EnclavePlatform
  {
    SGX,
    SNP,
    VIRTUAL,
  };
  DECLARE_JSON_ENUM(
    EnclavePlatform,
    {{EnclavePlatform::SNP, "SNP"}, {EnclavePlatform::VIRTUAL, "Virtual"}});

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
    std::optional<ccf::MemberRecoveryRole> recovery_role = std::nullopt;

    bool operator==(const ParsedMemberInfo& other) const = default;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ParsedMemberInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ParsedMemberInfo, certificate_file);
  DECLARE_JSON_OPTIONAL_FIELDS(
    ParsedMemberInfo,
    encryption_public_key_file,
    data_json_file,
    recovery_role);

  struct CCHostConfig : public ccf::CCFConfig
  {
    struct Enclave
    {
      std::string file;
      EnclaveType type;
      EnclavePlatform platform;

      bool operator==(const Enclave&) const = default;
    };
    Enclave enclave = {};

    // Other
    ccf::ds::TimeString tick_interval = {"10ms"};
    ccf::ds::TimeString slow_io_logging_threshold = {"10ms"};
    std::optional<std::string> node_client_interface = std::nullopt;
    ccf::ds::TimeString client_connection_timeout = {"2000ms"};
    std::optional<ccf::ds::TimeString> idle_connection_timeout =
      ccf::ds::TimeString("60s");
    std::optional<std::string> node_data_json_file = std::nullopt;
    std::optional<std::string> service_data_json_file = std::nullopt;
    bool ignore_first_sigterm = false;

    struct OutputFiles
    {
      std::string node_certificate_file = "nodecert.pem";
      std::string pid_file = "cchost.pid";

      // Addresses files
      std::string node_to_node_address_file = "";
      std::string rpc_addresses_file = "";

      std::optional<std::string> sealed_ledger_secret_location = std::nullopt;

      bool operator==(const OutputFiles&) const = default;
    };
    OutputFiles output_files = {};

    struct Logging
    {
      ccf::LoggerLevel host_level = ccf::LoggerLevel::INFO;
      LogFormat format = LogFormat::TEXT;

      bool operator==(const Logging&) const = default;
    };
    Logging logging = {};

    struct Memory
    {
      ccf::ds::SizeString circuit_size = {"16MB"};
      ccf::ds::SizeString max_msg_size = {"64MB"};
      ccf::ds::SizeString max_fragment_size = {"256KB"};

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
        std::string service_subject_name = "CN=CCF Service";
        ccf::COSESignaturesConfig cose_signatures;

        bool operator==(const Start&) const = default;
      };
      Start start = {};

      struct Join
      {
        ccf::NodeInfoNetwork::NetAddress target_rpc_address;
        ccf::ds::TimeString retry_timeout = {"1000ms"};
        bool follow_redirect = true;
        bool fetch_recent_snapshot = true;

        bool operator==(const Join&) const = default;
      };
      Join join = {};

      struct Recover
      {
        size_t initial_service_certificate_validity_days = 1;
        std::string previous_service_identity_file;
        std::optional<std::string> previous_sealed_ledger_secret_location =
          std::nullopt;
        bool operator==(const Recover&) const = default;
      };
      Recover recover = {};
    };
    Command command = {};
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Enclave);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Enclave, type, platform);
  DECLARE_JSON_OPTIONAL_FIELDS(CCHostConfig::Enclave, file);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::OutputFiles);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::OutputFiles);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::OutputFiles,
    node_certificate_file,
    pid_file,
    node_to_node_address_file,
    rpc_addresses_file,
    sealed_ledger_secret_location);

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
    initial_service_certificate_validity_days,
    service_subject_name,
    cose_signatures);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Command::Join);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Command::Join, target_rpc_address);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::Command::Join,
    retry_timeout,
    follow_redirect,
    fetch_recent_snapshot);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Command::Recover);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Command::Recover);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::Command::Recover,
    initial_service_certificate_validity_days,
    previous_service_identity_file,
    previous_sealed_ledger_secret_location);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Command);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Command, type);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig::Command, service_certificate_file, start, join, recover);

  DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(CCHostConfig, ccf::CCFConfig);
  DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig, enclave, command);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCHostConfig,
    tick_interval,
    slow_io_logging_threshold,
    node_client_interface,
    client_connection_timeout,
    idle_connection_timeout,
    node_data_json_file,
    service_data_json_file,
    ignore_first_sigterm,
    output_files,
    snapshots,
    logging,
    memory);
}