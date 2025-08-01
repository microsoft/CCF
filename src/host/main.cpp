// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/logger.h"
#include "ccf/ds/unit_strings.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/platform.h"
#include "ccf/version.h"
#include "config_schema.h"
#include "configuration.h"
#include "ds/cli_helper.h"
#include "ds/files.h"
#include "ds/non_blocking.h"
#include "ds/nonstd.h"
#include "ds/oversized.h"
#include "ds/x509_time_fmt.h"
#include "enclave.h"
#include "handle_ring_buffer.h"
#include "host/env.h"
#include "json_schema.h"
#include "lfs_file_handler.h"
#include "load_monitor.h"
#include "node_connections.h"
#include "process_launcher.h"
#include "rpc_connections.h"
#include "sig_term.h"
#include "snapshots.h"
#include "ticker.h"
#include "time_updater.h"

#include <CLI11/CLI11.hpp>
#include <codecvt>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <locale>
#include <string>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;

extern char** environ;

using namespace std::string_literals;
using namespace std::chrono_literals;

using ResolvedAddresses = std::
  map<ccf::NodeInfoNetwork::RpcInterfaceID, ccf::NodeInfoNetwork::NetAddress>;

size_t asynchost::TCPImpl::remaining_read_quota =
  asynchost::TCPImpl::max_read_quota;
bool asynchost::TCPImpl::alloc_quota_logged = false;

size_t asynchost::UDPImpl::remaining_read_quota =
  asynchost::UDPImpl::max_read_quota;

std::chrono::microseconds asynchost::TimeBoundLogger::default_max_time(10'000);

void print_version(size_t)
{
  std::cout << "CCF host: " << ccf::ccf_version << std::endl;
  std::cout << "Platform: "
            << nlohmann::json(ccf::pal::platform).get<std::string>()
            << std::endl;
  exit(0);
}

int main(int argc, char** argv)
{
  // ignore SIGPIPE
  signal(SIGPIPE, SIG_IGN);
  CLI::App app{
    "CCF Host launcher. Runs a single CCF node, based on the given "
    "configuration file.\n"
    "Some parameters are marked \"(security critical)\" - these must be passed "
    "on the CLI rather than within a configuration file, so that (on relevant "
    "platforms) their value is captured in an attestation even if the "
    "configuration file itself is unattested.\n"};

  std::string config_file_path = "config.json";
  app.add_option(
    "-c,--config", config_file_path, "Path to JSON configuration file");

  ccf::ds::TimeString config_timeout = {"0s"};
  app.add_option(
    "--config-timeout",
    config_timeout,
    "Configuration file read timeout, for example 5s or 1min");

  bool check_config_only = false;
  app.add_flag(
    "--check", check_config_only, "Verify configuration file and exit");

  app.add_flag(
    "-v, --version", print_version, "Display CCF host version and exit");

  LoggerLevel enclave_log_level = LoggerLevel::INFO;
  std::map<std::string, LoggerLevel> log_level_options;
  for (size_t i = ccf::logger::MOST_VERBOSE; i < LoggerLevel::MAX_LOG_LEVEL;
       ++i)
  {
    const auto l = (LoggerLevel)i;
    log_level_options[ccf::logger::to_string(l)] = l;
  }

  app
    .add_option(
      "--enclave-log-level",
      enclave_log_level,
      "Logging level for the enclave code (security critical)")
    ->transform(CLI::CheckedTransformer(log_level_options, CLI::ignore_case));

  std::string enclave_file_path;
  app.add_option(
    "--enclave-file",
    enclave_file_path,
    "Path to enclave application (security critical)");

  try
  {
    app.parse(argc, argv);
  }
  catch (const CLI::ParseError& e)
  {
    return app.exit(e);
  }

  std::string config_str = files::slurp_string(
    config_file_path,
    true /* return an empty string if the file does not exist */);
  nlohmann::json config_json;
  auto config_timeout_end = std::chrono::high_resolution_clock::now() +
    std::chrono::microseconds(config_timeout);
  std::string config_parsing_error = "";
  do
  {
    config_str = files::slurp_string(
      config_file_path,
      true /* return an empty string if the file does not exist */);
    try
    {
      config_json = nlohmann::json::parse(config_str);
      config_parsing_error = "";
      break;
    }
    catch (const std::exception& e)
    {
      config_parsing_error = fmt::format(
        "Error parsing configuration file {}: {}", config_file_path, e.what());
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  } while (std::chrono::high_resolution_clock::now() < config_timeout_end);

  if (!config_parsing_error.empty())
  {
    throw std::logic_error(config_parsing_error);
  }
  auto schema_json = nlohmann::json::parse(host::host_config_schema);

  auto schema_error_msg = json::validate_json(config_json, schema_json);
  if (schema_error_msg.has_value())
  {
    throw std::logic_error(fmt::format(
      "Error validating JSON schema for configuration file {}: {}",
      config_file_path,
      schema_error_msg.value()));
  }

  host::CCHostConfig config = config_json;

  if (config.logging.format == host::LogFormat::JSON)
  {
    ccf::logger::config::add_json_console_logger();
  }
  else
  {
    ccf::logger::config::add_text_console_logger();
  }

  LOG_INFO_FMT("CCF version: {}", ccf::ccf_version);

  LOG_INFO_FMT("CLI args: \"{}\"", fmt::join(argv, argv + argc, "\" \""));

  if (check_config_only)
  {
    LOG_INFO_FMT("Configuration file successfully verified");
    return 0;
  }

  LOG_INFO_FMT("Configuration file {}:\n{}", config_file_path, config_str);

  nlohmann::json environment;
  for (int i = 0; environ[i] != nullptr; i++)
  {
    auto [k, v] = ccf::nonstd::split_1(environ[i], "=");
    environment[k] = v;
  }

  LOG_INFO_FMT("Environment: {}\n", environment.dump(2));

  size_t recovery_threshold = 0;
  try
  {
    if (config.command.type == StartType::Start)
    {
      if (
        files::exists(config.ledger.directory) &&
        !fs::is_empty(config.ledger.directory))
      {
        throw std::logic_error(fmt::format(
          "On start, ledger directory should not exist or be empty ({})",
          config.ledger.directory));
      }
      // Count members with public encryption key as only these members will be
      // handed a recovery share.
      // Note that it is acceptable to start a network without any member having
      // a recovery share. The service will check that at least one recovery
      // member is added before the service can be opened.
      size_t members_with_pubk_count = 0;
      for (auto const& m : config.command.start.members)
      {
        if (m.encryption_public_key_file.has_value())
        {
          members_with_pubk_count++;
        }
      }

      recovery_threshold =
        config.command.start.service_configuration.recovery_threshold;
      if (recovery_threshold == 0)
      {
        LOG_INFO_FMT(
          "Recovery threshold unset. Defaulting to number of initial "
          "consortium members with a public encryption key ({}).",
          members_with_pubk_count);
        recovery_threshold = members_with_pubk_count;
      }
      else if (recovery_threshold > members_with_pubk_count)
      {
        throw std::logic_error(fmt::format(
          "Recovery threshold ({}) cannot be greater than total number ({})"
          "of initial consortium members with a public encryption "
          "key (specified via --member-info options)",
          recovery_threshold,
          members_with_pubk_count));
      }
    }
  }
  catch (const std::logic_error& e)
  {
    LOG_FATAL_FMT("{}. Exiting.", e.what());
    return static_cast<int>(CLI::ExitCodes::ValidationError);
  }

  std::filesystem::path pid_file_path{config.output_files.pid_file};
  if (std::filesystem::exists(pid_file_path))
  {
    LOG_FATAL_FMT(
      "PID file {} already exists. Exiting.", pid_file_path.string());
    return static_cast<int>(CLI::ExitCodes::FileError);
  }

  // Write PID to disk
  files::dump(fmt::format("{}", ::getpid()), config.output_files.pid_file);

  // set the host log level
  ccf::logger::config::level() = config.logging.host_level;

  asynchost::TimeBoundLogger::default_max_time =
    config.slow_io_logging_threshold;

  // create the enclave
  if (!config.enclave.file.empty())
  {
    LOG_FAIL_FMT(
      "DEPRECATED: Enclave path was specified in config file! This should be "
      "removed from the config, and passed directly to the CLI instead");

    if (enclave_file_path.empty())
    {
      enclave_file_path = config.enclave.file;
    }
  }

  if (enclave_file_path.empty())
  {
    LOG_FATAL_FMT("No enclave file path specified");
    return static_cast<int>(CLI::ExitCodes::ValidationError);
  }

  host::Enclave enclave(
    enclave_file_path, config.enclave.type, config.enclave.platform);

  // messaging ring buffers
  const auto buffer_size = config.memory.circuit_size;

  std::vector<uint8_t> to_enclave_buffer(buffer_size);
  ringbuffer::Offsets to_enclave_offsets;
  ringbuffer::BufferDef to_enclave_def{
    to_enclave_buffer.data(), to_enclave_buffer.size(), &to_enclave_offsets};
  if (!ringbuffer::Const::find_acceptable_sub_buffer(
        to_enclave_def.data, to_enclave_def.size))
  {
    LOG_FATAL_FMT(
      "Unable to construct valid inbound buffer of size {}", buffer_size);
    return static_cast<int>(CLI::ExitCodes::ValidationError);
  }

  std::vector<uint8_t> from_enclave_buffer(buffer_size);
  ringbuffer::Offsets from_enclave_offsets;
  ringbuffer::BufferDef from_enclave_def{
    from_enclave_buffer.data(),
    from_enclave_buffer.size(),
    &from_enclave_offsets};
  if (!ringbuffer::Const::find_acceptable_sub_buffer(
        from_enclave_def.data, from_enclave_def.size))
  {
    LOG_FATAL_FMT(
      "Unable to construct valid outbound buffer of size {}", buffer_size);
    return static_cast<int>(CLI::ExitCodes::ValidationError);
  }

  ringbuffer::Circuit circuit(to_enclave_def, from_enclave_def);
  messaging::BufferProcessor bp("Host");

  // To prevent deadlock, all blocking writes from the host to the ringbuffer
  // will be queued if the ringbuffer is full
  ringbuffer::WriterFactory base_factory(circuit);
  ringbuffer::NonBlockingWriterFactory non_blocking_factory(base_factory);

  // Factory for creating writers which will handle writing of large messages
  oversized::WriterConfig writer_config{
    config.memory.max_fragment_size, config.memory.max_msg_size};
  oversized::WriterFactory writer_factory(non_blocking_factory, writer_config);

  // reconstruct oversized messages sent to the host
  oversized::FragmentReconstructor fr(bp.get_dispatcher());

  asynchost::ProcessLauncher process_launcher;
  process_launcher.register_message_handlers(bp.get_dispatcher());

  {
    // provide regular ticks to the enclave
    asynchost::Ticker ticker(config.tick_interval, writer_factory);

    // reset the inbound-TCP processing quota each iteration
    asynchost::ResetTCPReadQuota reset_tcp_quota;

    // reset the inbound-UDP processing quota each iteration
    asynchost::ResetUDPReadQuota reset_udp_quota;

    // regularly update the time given to the enclave
    asynchost::TimeUpdater time_updater(1ms);

    // regularly record some load statistics
    asynchost::LoadMonitor load_monitor(500ms, bp);

    // handle outbound logging and admin messages from the enclave
    asynchost::HandleRingbuffer handle_ringbuffer(
      1ms, bp, circuit.read_from_inside(), non_blocking_factory);

    // graceful shutdown on sigterm
    asynchost::Sigterm sigterm(writer_factory, config.ignore_first_sigterm);
    // graceful shutdown on sighup
    asynchost::Sighup sighup(writer_factory, false /* never ignore */);

    asynchost::Ledger ledger(
      config.ledger.directory,
      writer_factory,
      config.ledger.chunk_size,
      asynchost::ledger_max_read_cache_files_default,
      config.ledger.read_only_directories);
    ledger.register_message_handlers(bp.get_dispatcher());

    asynchost::SnapshotManager snapshots(
      config.snapshots.directory,
      writer_factory,
      config.snapshots.read_only_directory);
    snapshots.register_message_handlers(bp.get_dispatcher());

    // handle LFS-related messages from the enclave
    asynchost::LFSFileHandler lfs_file_handler(
      writer_factory.create_writer_to_inside());
    lfs_file_handler.register_message_handlers(bp.get_dispatcher());

    // Begin listening for node-to-node and RPC messages.
    // This includes DNS resolution and potentially dynamic port assignment (if
    // requesting port 0). The hostname and port may be modified - after calling
    // it holds the final assigned values.
    auto [node_host, node_port] =
      cli::validate_address(config.network.node_to_node_interface.bind_address);
    asynchost::NodeConnections node(
      bp.get_dispatcher(),
      ledger,
      writer_factory,
      node_host,
      node_port,
      config.node_client_interface,
      config.client_connection_timeout);
    config.network.node_to_node_interface.bind_address =
      ccf::make_net_address(node_host, node_port);
    if (config.network.node_to_node_interface.published_address.empty())
    {
      config.network.node_to_node_interface.published_address =
        config.network.node_to_node_interface.bind_address;
    }
    if (!config.output_files.node_to_node_address_file.empty())
    {
      ResolvedAddresses resolved_node_address;
      resolved_node_address[node_to_node_interface_name] =
        config.network.node_to_node_interface.bind_address;
      files::dump(
        nlohmann::json(resolved_node_address).dump(),
        config.output_files.node_to_node_address_file);
    }

    asynchost::ConnIDGenerator idGen;

    asynchost::RPCConnections<asynchost::TCP> rpc(
      1s, // Tick once-per-second to track idle connections,
      writer_factory,
      idGen,
      config.client_connection_timeout,
      config.idle_connection_timeout);
    rpc->behaviour.register_message_handlers(bp.get_dispatcher());

    // This is a temporary solution to keep UDP RPC handlers in the same
    // way as the TCP ones without having to parametrize per connection,
    // which is not yet possible, due to UDP and TCP not being derived
    // from the same abstract class.
    asynchost::RPCConnections<asynchost::UDP> rpc_udp(
      1s,
      writer_factory,
      idGen,
      config.client_connection_timeout,
      config.idle_connection_timeout);
    rpc_udp->behaviour.register_udp_message_handlers(bp.get_dispatcher());

    ResolvedAddresses resolved_rpc_addresses;
    for (auto& [name, interface] : config.network.rpc_interfaces)
    {
      auto [rpc_host, rpc_port] = cli::validate_address(interface.bind_address);
      LOG_INFO_FMT(
        "Registering RPC interface {}, on {} {}:{}",
        name,
        interface.protocol,
        rpc_host,
        rpc_port);
      if (interface.protocol == "udp")
      {
        rpc_udp->behaviour.listen(0, rpc_host, rpc_port, name);
      }
      else
      {
        rpc->behaviour.listen(0, rpc_host, rpc_port, name);
      }
      LOG_INFO_FMT(
        "Registered RPC interface {}, on {} {}:{}",
        name,
        interface.protocol,
        rpc_host,
        rpc_port);

      resolved_rpc_addresses[name] = fmt::format("{}:{}", rpc_host, rpc_port);

      interface.bind_address = ccf::make_net_address(rpc_host, rpc_port);

      // If public RPC address is not set, default to local RPC address
      if (interface.published_address.empty())
      {
        interface.published_address = interface.bind_address;
      }

      auto [pub_host, pub_port] =
        cli::validate_address(interface.published_address);
      if (pub_port == "0")
      {
        pub_port = rpc_port;
        interface.published_address = ccf::make_net_address(pub_host, pub_port);
      }
    }
    if (!config.output_files.rpc_addresses_file.empty())
    {
      files::dump(
        nlohmann::json(resolved_rpc_addresses).dump(),
        config.output_files.rpc_addresses_file);
    }

    // Initialise the enclave and create a CCF node in it
    const size_t certificate_size = 4096;
    std::vector<uint8_t> node_cert(certificate_size);
    std::vector<uint8_t> service_cert(certificate_size);

    EnclaveConfig enclave_config;
    enclave_config.to_enclave_buffer_start = to_enclave_def.data;
    enclave_config.to_enclave_buffer_size = to_enclave_def.size;
    enclave_config.to_enclave_buffer_offsets = &to_enclave_offsets;
    enclave_config.from_enclave_buffer_start = from_enclave_def.data;
    enclave_config.from_enclave_buffer_size = from_enclave_def.size;
    enclave_config.from_enclave_buffer_offsets = &from_enclave_offsets;

    enclave_config.writer_config = writer_config;

    StartupConfig startup_config(config);

    startup_config.snapshot_tx_interval = config.snapshots.tx_count;

    if (startup_config.attestation.snp_security_policy_file.has_value())
    {
      auto security_policy_file =
        startup_config.attestation.snp_security_policy_file.value();
      LOG_DEBUG_FMT(
        "Resolving snp_security_policy_file: {}", security_policy_file);
      security_policy_file =
        ccf::env::expand_envvars_in_path(security_policy_file);
      LOG_DEBUG_FMT(
        "Resolved snp_security_policy_file: {}", security_policy_file);

      startup_config.attestation.environment.security_policy =
        files::try_slurp_string(security_policy_file);
    }

    if (startup_config.attestation.snp_uvm_endorsements_file.has_value())
    {
      auto snp_uvm_endorsements_file =
        startup_config.attestation.snp_uvm_endorsements_file.value();
      LOG_DEBUG_FMT(
        "Resolving snp_uvm_endorsements_file: {}", snp_uvm_endorsements_file);
      snp_uvm_endorsements_file =
        ccf::env::expand_envvars_in_path(snp_uvm_endorsements_file);
      LOG_DEBUG_FMT(
        "Resolved snp_uvm_endorsements_file: {}", snp_uvm_endorsements_file);

      startup_config.attestation.environment.uvm_endorsements =
        files::try_slurp_string(snp_uvm_endorsements_file);
    }

    for (auto endorsement_servers_it =
           startup_config.attestation.snp_endorsements_servers.begin();
         endorsement_servers_it !=
         startup_config.attestation.snp_endorsements_servers.end();
         ++endorsement_servers_it)
    {
      LOG_DEBUG_FMT(
        "Resolving snp_endorsements_server url: {}",
        endorsement_servers_it->url.value());
      if (endorsement_servers_it->url.has_value())
      {
        auto& url = endorsement_servers_it->url.value();
        auto pos = url.find(':');
        if (pos == std::string::npos)
        {
          endorsement_servers_it->url = ccf::env::expand_envvar(url);
        }
        else
        {
          endorsement_servers_it->url = fmt::format(
            "{}:{}",
            ccf::env::expand_envvar(url.substr(0, pos)),
            ccf::env::expand_envvar(url.substr(pos + 1)));
        }
        LOG_DEBUG_FMT(
          "Resolved snp_endorsements_server url: {}",
          endorsement_servers_it->url);
      }
    }

    if (config.node_data_json_file.has_value())
    {
      startup_config.node_data =
        files::slurp_json(config.node_data_json_file.value());
      LOG_TRACE_FMT("Read node_data: {}", startup_config.node_data.dump());
    }

    if (config.service_data_json_file.has_value())
    {
      if (
        config.command.type == StartType::Start ||
        config.command.type == StartType::Recover)
      {
        startup_config.service_data =
          files::slurp_json(config.service_data_json_file.value());
      }
      else
      {
        LOG_FAIL_FMT(
          "Service data is ignored for start type {}", config.command.type);
      }
    }

    auto startup_host_time = std::chrono::system_clock::now();
    LOG_INFO_FMT("Startup host time: {}", startup_host_time);

    startup_config.startup_host_time =
      ::ds::to_x509_time_string(startup_host_time);

    if (config.command.type == StartType::Start)
    {
      for (auto const& m : config.command.start.members)
      {
        std::optional<ccf::crypto::Pem> public_encryption_key = std::nullopt;
        if (
          m.encryption_public_key_file.has_value() &&
          !m.encryption_public_key_file.value().empty())
        {
          public_encryption_key = ccf::crypto::Pem(
            files::slurp(m.encryption_public_key_file.value()));
        }

        nlohmann::json md = nullptr;
        if (m.data_json_file.has_value() && !m.data_json_file.value().empty())
        {
          md = nlohmann::json::parse(files::slurp(m.data_json_file.value()));
        }

        startup_config.start.members.emplace_back(
          ccf::crypto::Pem(files::slurp(m.certificate_file)),
          public_encryption_key,
          md);
      }
      startup_config.start.constitution = "";
      for (const auto& constitution_path :
           config.command.start.constitution_files)
      {
        // Separate with single newlines
        if (!startup_config.start.constitution.empty())
        {
          startup_config.start.constitution += '\n';
        }

        startup_config.start.constitution +=
          files::slurp_string(constitution_path);
      }
      startup_config.start.service_configuration =
        config.command.start.service_configuration;
      startup_config.start.service_configuration.recovery_threshold =
        recovery_threshold;
      startup_config.initial_service_certificate_validity_days =
        config.command.start.initial_service_certificate_validity_days;
      startup_config.service_subject_name =
        config.command.start.service_subject_name;
      LOG_INFO_FMT(
        "Creating new node: new network (with {} initial member(s) and {} "
        "member(s) required for recovery)",
        config.command.start.members.size(),
        recovery_threshold);
    }
    else if (config.command.type == StartType::Join)
    {
      LOG_INFO_FMT(
        "Creating new node - join existing network at {}",
        config.command.join.target_rpc_address);
      startup_config.join.target_rpc_address =
        config.command.join.target_rpc_address;
      startup_config.join.retry_timeout = config.command.join.retry_timeout;
      startup_config.join.service_cert =
        files::slurp(config.command.service_certificate_file);
      startup_config.join.follow_redirect = config.command.join.follow_redirect;
    }
    else if (config.command.type == StartType::Recover)
    {
      LOG_INFO_FMT("Creating new node - recover");
      startup_config.initial_service_certificate_validity_days =
        config.command.recover.initial_service_certificate_validity_days;
      auto idf = config.command.recover.previous_service_identity_file;
      if (!files::exists(idf))
      {
        throw std::logic_error(fmt::format(
          "Recovery requires a previous service identity certificate; cannot "
          "open '{}'",
          idf));
      }
      LOG_INFO_FMT("Reading previous service identity from {}", idf);
      startup_config.recover.previous_service_identity = files::slurp(idf);

      if (!config.command.recover.constitution_files.empty())
      {
        LOG_INFO_FMT(
          "Reading [{}] constitution file(s) for recovery",
          fmt::join(config.command.recover.constitution_files, ", "));
        startup_config.recover.constitution = "";
        for (const auto& constitution_path :
             config.command.recover.constitution_files)
        {
          // Separate with single newlines
          if (!startup_config.recover.constitution->empty())
          {
            startup_config.recover.constitution.value() += '\n';
          }

          startup_config.recover.constitution.value() +=
            files::slurp_string(constitution_path);
        }
      }
    }
    else
    {
      LOG_FATAL_FMT("Start command should be start|join|recover. Exiting.");
      return static_cast<int>(CLI::ExitCodes::ValidationError);
    }

    std::vector<uint8_t> startup_snapshot = {};

    if (
      config.command.type == StartType::Join ||
      config.command.type == StartType::Recover)
    {
      auto latest_committed_snapshot =
        snapshots.find_latest_committed_snapshot();
      if (latest_committed_snapshot.has_value())
      {
        auto& [snapshot_dir, snapshot_file] = latest_committed_snapshot.value();
        startup_snapshot = files::slurp(snapshot_dir / snapshot_file);

        LOG_INFO_FMT(
          "Found latest snapshot file: {} (size: {})",
          snapshot_dir / snapshot_file,
          startup_snapshot.size());
      }
      else
      {
        LOG_INFO_FMT(
          "No snapshot found: Node will replay all historical transactions");
      }
    }

    if (config.network.acme)
    {
      startup_config.network.acme = config.network.acme;
    }
    // Used by GET /node/network/nodes/self to return rpc interfaces
    // prior to the KV being updated
    startup_config.network.rpc_interfaces = config.network.rpc_interfaces;

    LOG_INFO_FMT("Initialising enclave: enclave_create_node");
    std::atomic<bool> ecall_completed = false;
    auto flush_outbound = [&]() {
      do
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        bp.read_all(circuit.read_from_inside());
      } while (!ecall_completed);
    };
    std::thread flusher_thread(flush_outbound);
    auto create_status = enclave.create_node(
      enclave_config,
      startup_config,
      std::move(startup_snapshot),
      node_cert,
      service_cert,
      config.command.type,
      enclave_log_level,
      config.worker_threads,
      time_updater->behaviour.get_value());
    ecall_completed.store(true);
    flusher_thread.join();

    if (create_status != CreateNodeStatus::OK)
    {
      LOG_FAIL_FMT(
        "An error occurred when creating CCF node: {}",
        create_node_result_to_str(create_status));

      // Pull all logs from the enclave via BufferProcessor `bp`
      // and show any logs that came from the ring buffer during setup.
      bp.read_all(circuit.read_from_inside());

      // This returns from main, stopping the program
      return create_status;
    }

    LOG_INFO_FMT("Created new node");

    // Write the node and service certs to disk.
    files::dump(node_cert, config.output_files.node_certificate_file);
    LOG_INFO_FMT(
      "Output self-signed node certificate to {}",
      config.output_files.node_certificate_file);

    if (
      config.command.type == StartType::Start ||
      config.command.type == StartType::Recover)
    {
      files::dump(service_cert, config.command.service_certificate_file);
      LOG_INFO_FMT(
        "Output service certificate to {}",
        config.command.service_certificate_file);
    }

    auto enclave_thread_start = [&]() {
      try
      {
        enclave.run();
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Exception in ccf::run: {}", e.what());

        // This exception should be rethrown, probably aborting the process, but
        // we sleep briefly to allow more outbound messages to be processed. If
        // the enclave sent logging messages, it is useful to read and print
        // them before dying.
        std::this_thread::sleep_for(1s);
        throw;
      }
    };

    LOG_INFO_FMT("Starting enclave thread(s)");
    // Start threads which will ECall and process messages inside the enclave
    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < (config.worker_threads + 1); ++i)
    {
      threads.emplace_back(std::thread(enclave_thread_start));
    }

    LOG_INFO_FMT("Entering event loop");
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    LOG_INFO_FMT("Exited event loop");
    for (auto& t : threads)
    {
      t.join();
    }
  }

  process_launcher.stop();

  // Continue running the loop long enough for the on_close
  // callbacks to be despatched, so as to avoid memory being
  // leaked by handles. Capped out of abundance of caution.
  size_t close_iterations = 100;
  while (uv_loop_alive(uv_default_loop()) && close_iterations > 0)
  {
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    close_iterations--;
  }
  LOG_INFO_FMT("Ran an extra {} cleanup iteration(s)", 100 - close_iterations);

  auto rc = uv_loop_close(uv_default_loop());
  if (rc)
    LOG_FAIL_FMT("Failed to close uv loop cleanly: {}", uv_err_name(rc));

  return rc;
}
