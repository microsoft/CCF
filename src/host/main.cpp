// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/version.h"
#include "configuration.h"
#include "crypto/openssl/x509_time.h"
#include "ds/cli_helper.h"
#include "ds/files.h"
#include "ds/logger.h"
#include "ds/net.h"
#include "ds/non_blocking.h"
#include "ds/oversized.h"
#include "enclave.h"
#include "handle_ring_buffer.h"
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
#include <fstream>
#include <iostream>
#include <locale>
#include <string>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <valijson/adapters/nlohmann_json_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/utils/nlohmann_json_utils.hpp>
#include <valijson/validator.hpp>

using namespace std::string_literals;
using namespace std::chrono_literals;

using ResolvedAddresses = std::
  map<ccf::NodeInfoNetwork::RpcInterfaceID, ccf::NodeInfoNetwork::NetAddress>;

size_t asynchost::TCPImpl::remaining_read_quota;

std::chrono::microseconds asynchost::TimeBoundLogger::default_max_time(10'000);

void print_version(size_t)
{
  std::cout << "CCF host: " << ccf::ccf_version << std::endl;
  exit(0);
}

int main(int argc, char** argv)
{
  // ignore SIGPIPE
  signal(SIGPIPE, SIG_IGN);

  CLI::App app{"ccf"};

  std::string config_file_path = "config.json";
  app
    .add_option(
      "-c,--config", config_file_path, "Path to JSON configuration file")
    ->check(CLI::ExistingFile);

  bool check_config_only = false;
  app.add_flag(
    "--check", check_config_only, "Verify configuration file and exit");

  app.add_flag(
    "-v, --version", print_version, "Display CCF host version and exit");

  try
  {
    app.parse(argc, argv);
  }
  catch (const CLI::ParseError& e)
  {
    return app.exit(e);
  }

  LOG_INFO_FMT("CCF version: {}", ccf::ccf_version);

  std::string config_str = files::slurp_string(config_file_path);

  host::CCHostConfig config = {};
  try
  {
    config = nlohmann::json::parse(config_str);

    // TODO: Validate configuration with schema
    // 1. Load schema (TODO: Bake in binary instead)
    nlohmann::json schema_json;
    if (!valijson::utils::loadDocument(
          "/home/jumaffre/git/CCF/doc/schemas/cchost_config.json", schema_json))
    {
      throw std::runtime_error("Failed to load schema document");
    }

    // 2. Load in parser
    valijson::adapters::NlohmannJsonAdapter schema_adapter(schema_json);
    valijson::Schema schema;
    valijson::SchemaParser parser;
    parser.populateSchema(schema_adapter, schema);

    // 3. Verify configuration
    valijson::Validator validator;
    valijson::adapters::NlohmannJsonAdapter target_adapter(config);
    // valijson::ValidationResults results;
    if (!validator.validate(schema, target_adapter, nullptr))
    {
      // TODO: Print errors
      throw std::logic_error("Validation failed");
      // throw std::runtime_error(fmt::format("Validation failed : {}",
      // results));
    }
  }
  catch (const std::exception& e)
  {
    throw std::logic_error(fmt::format(
      "Error parsing configuration file {}: {}", config_file_path, e.what()));
  }

  if (check_config_only)
  {
    LOG_INFO_FMT("Configuration file successfully verified");
    return 0;
  }

  LOG_INFO_FMT("Configuration file {}:\n{}", config_file_path, config_str);
  if (config.logging.format == host::LogFormat::JSON)
  {
    logger::config::initialize_with_json_console();
  }

  uint32_t oe_flags = 0;
  size_t recovery_threshold = 0;
  try
  {
    if (config.command.type == StartType::Start)
    {
      if (files::exists(config.ledger.directory))
      {
        throw std::logic_error(fmt::format(
          "On start, ledger directory should not exist ({})",
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

    switch (config.enclave.type)
    {
      case host::EnclaveType::RELEASE:
      {
        break;
      }
      case host::EnclaveType::DEBUG:
      {
        oe_flags |= OE_ENCLAVE_FLAG_DEBUG;
        break;
      }
      case host::EnclaveType::VIRTUAL:
      {
        oe_flags = ENCLAVE_FLAG_VIRTUAL;
        break;
      }
      default:
      {
        throw std::logic_error(
          fmt::format("Invalid enclave type: {}", config.enclave.type));
      }
    }
  }
  catch (const std::logic_error& e)
  {
    LOG_FATAL_FMT("{}. Exiting.", e.what());
    return static_cast<int>(CLI::ExitCodes::ValidationError);
  }

  // Write PID to disk
  files::dump(fmt::format("{}", ::getpid()), config.output_files.pid_file);

  // set the host log level
  logger::config::level() = config.logging.host_level;

  asynchost::TimeBoundLogger::default_max_time =
    config.slow_io_logging_threshold;

  // create the enclave
  host::Enclave enclave(config.enclave.file, oe_flags);

  // messaging ring buffers
  const auto buffer_size = config.memory.circuit_size;

  std::vector<uint8_t> to_enclave_buffer(buffer_size);
  ringbuffer::Offsets to_enclave_offsets;
  ringbuffer::BufferDef to_enclave_def{
    to_enclave_buffer.data(), to_enclave_buffer.size(), &to_enclave_offsets};

  std::vector<uint8_t> from_enclave_buffer(buffer_size);
  ringbuffer::Offsets from_enclave_offsets;
  ringbuffer::BufferDef from_enclave_def{
    from_enclave_buffer.data(),
    from_enclave_buffer.size(),
    &from_enclave_offsets};

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

    // regularly update the time given to the enclave
    asynchost::TimeUpdater time_updater(1ms);

    // regularly record some load statistics
    asynchost::LoadMonitor load_monitor(500ms, bp);

    // handle outbound messages from the enclave
    asynchost::HandleRingbuffer handle_ringbuffer(
      1ms, bp, circuit.read_from_inside(), non_blocking_factory);

    // graceful shutdown on sigterm
    asynchost::Sigterm sigterm(writer_factory);

    asynchost::Ledger ledger(
      config.ledger.directory,
      writer_factory,
      config.ledger.chunk_size,
      asynchost::ledger_max_read_cache_files_default,
      config.ledger.read_only_directories);
    ledger.register_message_handlers(bp.get_dispatcher());

    asynchost::SnapshotManager snapshots(config.snapshots.directory, ledger);
    snapshots.register_message_handlers(bp.get_dispatcher());

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
    if (!config.output_files.node_to_node_address_file.empty())
    {
      ResolvedAddresses resolved_node_address;
      resolved_node_address[node_to_node_interface_name] =
        config.network.node_to_node_interface.bind_address;
      files::dump(
        nlohmann::json(resolved_node_address).dump(),
        config.output_files.node_to_node_address_file);
    }

    asynchost::RPCConnections rpc(
      writer_factory, config.client_connection_timeout);
    rpc.register_message_handlers(bp.get_dispatcher());

    ResolvedAddresses resolved_rpc_addresses;
    for (auto& [name, interface] : config.network.rpc_interfaces)
    {
      auto [rpc_host, rpc_port] = cli::validate_address(interface.bind_address);
      rpc.listen(0, rpc_host, rpc_port, name);

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
    enclave_config.to_enclave_buffer_start = to_enclave_buffer.data();
    enclave_config.to_enclave_buffer_size = to_enclave_buffer.size();
    enclave_config.to_enclave_buffer_offsets = &to_enclave_offsets;
    enclave_config.from_enclave_buffer_start = from_enclave_buffer.data();
    enclave_config.from_enclave_buffer_size = from_enclave_buffer.size();
    enclave_config.from_enclave_buffer_offsets = &from_enclave_offsets;

    enclave_config.writer_config = writer_config;

    StartupConfig startup_config;

    startup_config.snapshot_tx_interval = config.snapshots.tx_count;
    startup_config.consensus = config.consensus;
    startup_config.ledger_signatures = config.ledger_signatures;
    startup_config.jwt = config.jwt;
    startup_config.network = config.network;
    startup_config.worker_threads = config.worker_threads;
    startup_config.node_certificate = config.node_certificate;

    auto startup_host_time = std::chrono::system_clock::now();
    LOG_INFO_FMT("Startup host time: {}", startup_host_time);

    startup_config.startup_host_time = crypto::OpenSSL::to_x509_time_string(
      std::chrono::system_clock::to_time_t(startup_host_time));

    if (config.command.type == StartType::Start)
    {
      for (auto const& m : config.command.start.members)
      {
        std::optional<std::vector<uint8_t>> public_encryption_key =
          std::nullopt;
        if (
          m.encryption_public_key_file.has_value() &&
          !m.encryption_public_key_file.value().empty())
        {
          public_encryption_key =
            files::slurp(m.encryption_public_key_file.value());
        }

        nlohmann::json md = nullptr;
        if (m.data_json_file.has_value() && !m.data_json_file.value().empty())
        {
          md = nlohmann::json::parse(files::slurp(m.data_json_file.value()));
        }

        startup_config.start.members.emplace_back(
          files::slurp(m.certificate_file), public_encryption_key, md);
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
    }
    else if (config.command.type == StartType::Recover)
    {
      LOG_INFO_FMT("Creating new node - recover");
      startup_config.initial_service_certificate_validity_days =
        config.command.recover.initial_service_certificate_validity_days;
    }
    else
    {
      LOG_FATAL_FMT("Start command should be start|join|recover. Exiting.");
    }

    if (
      config.command.type == StartType::Join ||
      config.command.type == StartType::Recover)
    {
      auto snapshot_file = snapshots.find_latest_committed_snapshot();
      if (snapshot_file.has_value())
      {
        auto& snapshot = snapshot_file.value();
        startup_config.startup_snapshot = snapshots.read_snapshot(snapshot);

        if (asynchost::is_snapshot_file_1_x(snapshot))
        {
          // Snapshot evidence seqno is only specified for 1.x snapshots which
          // need to be verified by deserialising the ledger suffix.
          startup_config.startup_snapshot_evidence_seqno_for_1_x =
            asynchost::get_snapshot_evidence_idx_from_file_name(snapshot);
        }

        LOG_INFO_FMT(
          "Found latest snapshot file: {} (size: {})",
          snapshot,
          startup_config.startup_snapshot.size());
      }
      else
      {
        LOG_INFO_FMT(
          "No snapshot found: Node will replay all historical transactions");
      }
    }

    if (config.consensus.type == ConsensusType::BFT)
    {
#ifdef ENABLE_BFT
      LOG_INFO_FMT(
        "Selected consensus BFT is experimental in {}", ccf::ccf_version);
#else
      LOG_FAIL_FMT(
        "Selected consensus BFT is not supported in {}", ccf::ccf_version);
#endif
    }

    auto create_status = enclave.create_node(
      enclave_config,
      startup_config,
      node_cert,
      service_cert,
      config.command.type,
      config.worker_threads,
      time_updater->behaviour.get_value());

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
#ifndef VIRTUAL_ENCLAVE
      try
#endif
      {
        enclave.run();
      }
#ifndef VIRTUAL_ENCLAVE
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Exception in enclave::run: {}", e.what());

        // This exception should be rethrown, probably aborting the process, but
        // we sleep briefly to allow more outbound messages to be processed. If
        // the enclave sent logging messages, it is useful to read and print
        // them before dying.
        std::this_thread::sleep_for(1s);
        throw;
      }
#endif
    };

    // Start threads which will ECall and process messages inside the enclave
    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < (config.worker_threads + 1); ++i)
    {
      threads.emplace_back(std::thread(enclave_thread_start));
    }

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
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
