// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/version.h"
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

using namespace std::string_literals;
using namespace std::chrono_literals;

size_t asynchost::TCPImpl::remaining_read_quota;

std::chrono::nanoseconds asynchost::TimeBoundLogger::default_max_time(
  10'000'000);

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

  // app.set_config("--config", "", "Read an INI or TOML file", false);
  // app.allow_config_extras(false);

  std::string config_file_path = "config.json";
  app
    .add_option(
      "-c,--config", config_file_path, "File to JSON configuration file")
    ->check(CLI::ExistingFile);

  app.add_flag(
    "-v, --version", print_version, "Display CCF host version and exit");

  app.require_subcommand(1, 1);

  std::string enclave_file;
  // app.add_option("-e,--enclave-file", enclave_file, "CCF application")
  //   ->required()
  //   ->check(CLI::ExistingFile);

  ConsensusType consensus = ConsensusType::CFT;
  std::vector<std::pair<std::string, ConsensusType>> consensus_map{
    {"cft", ConsensusType::CFT}, {"bft", ConsensusType::BFT}};
  // app.add_option("-c,--consensus", consensus, "Consensus")
  //   ->required()
  //   ->transform(CLI::CheckedTransformer(consensus_map, CLI::ignore_case));

  size_t num_worker_threads = 0;
  // app
  //   .add_option(
  //     "-w,--worker-threads",
  //     num_worker_threads,
  //     "Number of worker threads inside the enclave")
  //   ->capture_default_str();

  cli::ParsedAddress node_address;
  // cli::add_address_option(
  //   app,
  //   node_address,
  //   "--node-address",
  //   "Address on which to listen for commands coming from other nodes")
  //   ->required();

  cli::ParsedAddress public_rpc_address;
  // auto public_rpc_address_option =
  //   cli::add_address_option(
  //     app,
  //     public_rpc_address,
  //     "--public-rpc-address",
  //     "Address to advertise publicly to clients (defaults to same as "
  //     "--rpc-address)",
  //     "443")
  //     ->needs(rpc_address_option);

  size_t memory_reserve_startup = 0;
  //   app
  //     .add_option(
  //       "--memory-reserve-startup",
  //       memory_reserve_startup,
  // #ifdef DEBUG_CONFIG
  //       "Reserve unused memory inside the enclave, to simulate high memory
  //       use"
  // #else
  //       "Unused"
  // #endif
  //       )
  //     ->capture_default_str();

  crypto::CurveID curve_id = crypto::CurveID::SECP384R1;
  std::vector<std::pair<std::string, crypto::CurveID>> curve_id_map = {
    {"secp384r1", crypto::CurveID::SECP384R1},
    {"secp256r1", crypto::CurveID::SECP256R1}};
  // app
  // .add_option(
  //   "--curve-id",
  //   curve_id,
  //   "Elliptic curve to use as for node and network identities (used for TLS
  //   " "and ledger signatures)")
  // ->transform(CLI::CheckedTransformer(curve_id_map, CLI::ignore_case))
  // ->capture_default_str();

  // By default, node certificates are only valid for one day. It is
  // expected that members will submit a proposal to renew the node
  // certificates before expiry, at the point the service is open.
  size_t initial_node_certificate_validity_period_days = 1;
  // app
  //   .add_option(
  //     "--initial-node-cert-validity-days",
  //     initial_node_certificate_validity_period_days,
  //     "Initial validity period (days) for certificates of nodes before the "
  //     "service is open by members")
  //   ->check(CLI::PositiveNumber)
  //   ->type_name("UINT");

  // The network certificate file can either be an input or output parameter,
  // depending on the subcommand.

  auto start = app.add_subcommand("start", "Start new network");
  start->configurable();

  std::vector<std::string> constitution_paths;
  // start
  //   ->add_option(
  //     "--constitution",
  //     constitution_paths,
  //     "Path to one or more JS file that are concatenated to define the "
  //     "contents of the "
  //     "public:ccf.gov.constitution table")
  //   ->type_size(-1);

  std::vector<cli::ParsedMemberInfo> members;
  // cli::add_member_info_option(
  //   *start,
  //   members,
  //   "--member-info",
  //   "Initial consortium members information "
  //   "(member_cert.pem[,member_enc_pubk.pem[,member_data.json]])")
  //   ->required();

  size_t recovery_threshold = 0;
  // start
  //   ->add_option(
  //     "--recovery-threshold",
  //     recovery_threshold,
  //     "Number of member shares required for recovery. Defaults to total
  //     number " "of initial consortium members with a public encryption key.")
  //   ->check(CLI::PositiveNumber)
  //   ->type_name("UINT");

  size_t max_allowed_node_cert_validity_days = 365;
  // start
  //   ->add_option(
  //     "--max-allowed-node-cert-validity-days",
  //     max_allowed_node_cert_validity_days,
  //     "Maximum validity period (days) for certificates of trusted nodes")
  //   ->check(CLI::PositiveNumber)
  //   ->type_name("UINT");

  auto join = app.add_subcommand("join", "Join existing network");
  join->configurable();

  size_t join_timer = 1000;
  // join
  //   ->add_option(
  //     "--join-timer",
  //     join_timer,
  //     "Duration after which the join node will resend join requests to "
  //     "existing network (ms)")
  //   ->capture_default_str();

  cli::ParsedAddress target_rpc_address;
  // cli::add_address_option(
  //   *join,
  //   target_rpc_address,
  //   "--target-rpc-address",
  //   "RPC over TLS listening address of target network node")
  //   ->required();

  auto recover = app.add_subcommand("recover", "Recover crashed network");
  recover->configurable();

  try
  {
    app.parse(argc, argv);

    // nlohmann::json::parse()

    // // Add an additional check not represented by existing ->needs,
    // ->requires
    // // etc
    // if (!(*rpc_address_option || *rpc_interfaces_option))
    // {
    //   const auto option_list = fmt::format(
    //     "{}, {}",
    //     rpc_address_option->get_name(),
    //     rpc_interfaces_option->get_name());
    //   throw CLI::RequiredError::Option(1, 0, 0, option_list);
    // }
  }
  catch (const CLI::ParseError& e)
  {
    return app.exit(e);
  }

  LOG_FAIL_FMT("Config file: {}", config_file_path);

  auto config_str = files::slurp_string(config_file_path);

  LOG_FAIL_FMT("Config: {}", config_str);

  CCHostConfig config = nlohmann::json::parse(config_str);

  // set json log formatter to write to std::out
  if (config.logging.log_format_json)
  {
    logger::config::initialize_with_json_console();
  }

  // Fill in derived default values
  // if (!(*public_rpc_address_option))
  // {
  //   public_rpc_address = rpc_address;
  // }

  // if (!(*mosh_option))
  // {
  //   max_open_sessions_hard =
  //     max_open_sessions + cli::ParsedRpcInterface::default_mosh_diff;
  // }

  // If --rpc-address etc were specified, they populate a single object at the
  // start of the rpc_interfaces list
  // if (*rpc_address_option)
  // {
  //   cli::ParsedRpcInterface first;
  //   first.rpc_address = rpc_address;
  //   first.public_rpc_address = public_rpc_address;
  //   first.max_open_sessions = max_open_sessions;
  //   first.max_open_sessions_hard = max_open_sessions_hard;
  //   rpc_interfaces.insert(rpc_interfaces.begin(), std::move(first));
  // }

  // const auto cli_config = app.config_to_str(true, false);
  LOG_INFO_FMT("Version: {}", ccf::ccf_version);
  // LOG_INFO_FMT("Run with following options:\n{}", cli_config);

  uint32_t oe_flags = 0;
  try
  {
    const auto& ledger_dir = config.ledger.ledger_dir;
    if (*start && files::exists(ledger_dir))
    {
      throw std::logic_error(fmt::format(
        "On start, ledger directory should not exist ({})", ledger_dir));
    }
    else if (*recover && !files::exists(ledger_dir))
    {
      throw std::logic_error(fmt::format(
        "On recovery, ledger directory should exist ({}) ", ledger_dir));
    }

    if (*start)
    {
      // Count members with public encryption key as only these members will be
      // handed a recovery share.
      // Note that it is acceptable to start a network without any member having
      // a recovery share. The service will check that at least one recovery
      // member is added before the service can be opened.
      size_t members_with_pubk_count = 0;
      for (auto const& m : config.start.members)
      {
        if (m.encryption_public_key_file.has_value())
        {
          members_with_pubk_count++;
        }
      }

      recovery_threshold =
        config.start.service_configuration.recovery_threshold;
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

    switch (config.enclave_type)
    {
      case EnclaveType::RELEASE:
      {
        break;
      }
      case EnclaveType::DEBUG:
      {
        oe_flags |= OE_ENCLAVE_FLAG_DEBUG;
        break;
      }
      case EnclaveType::VIRTUAL:
      {
        oe_flags = ENCLAVE_FLAG_VIRTUAL;
        break;
      }
      default:
      {
        throw std::logic_error(
          fmt::format("Invalid enclave type: {}", config.enclave_type));
      }
    }
  }
  catch (const std::logic_error& e)
  {
    LOG_FATAL_FMT("{}. Exiting.", e.what());
    return static_cast<int>(CLI::ExitCodes::ValidationError);
  }

  asynchost::TimeBoundLogger::default_max_time =
    std::chrono::duration_cast<decltype(
      asynchost::TimeBoundLogger::default_max_time)>(
      std::chrono::nanoseconds(config.io_logging_threshold_ns));

  // Write PID to disk
  files::dump(fmt::format("{}", ::getpid()), config.node_pid_file);

  // set the host log level
  logger::config::level() = config.logging.host_log_level;

  // create the enclave
  host::Enclave enclave(config.enclave_file, oe_flags);

  // messaging ring buffers
  const auto buffer_size = 1 << config.memory.circuit_size_shift;

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
    (size_t)(1 << config.memory.max_fragment_size_shift),
    (size_t)(1 << config.memory.max_msg_size_shift)};
  oversized::WriterFactory writer_factory(non_blocking_factory, writer_config);

  // reconstruct oversized messages sent to the host
  oversized::FragmentReconstructor fr(bp.get_dispatcher());

  asynchost::ProcessLauncher process_launcher;
  process_launcher.register_message_handlers(bp.get_dispatcher());

  {
    // provide regular ticks to the enclave
    const std::chrono::milliseconds tick_period(tick_period_ms);
    asynchost::Ticker ticker(tick_period, writer_factory);

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
      config.ledger.ledger_dir,
      writer_factory,
      config.ledger.ledger_chunk_bytes,
      asynchost::ledger_max_read_cache_files_default,
      config.ledger.read_only_ledger_dirs);
    ledger.register_message_handlers(bp.get_dispatcher());

    asynchost::SnapshotManager snapshots(config.snapshots.snapshot_dir, ledger);
    snapshots.register_message_handlers(bp.get_dispatcher());

    // Begin listening for node-to-node and RPC messages.
    // This includes DNS resolution and potentially dynamic port assignment (if
    // requesting port 0). The hostname and port may be modified - after calling
    // it holds the final assigned values.
    asynchost::NodeConnections node(
      bp.get_dispatcher(),
      ledger,
      writer_factory,
      config.network.node_address.hostname,
      config.network.node_address.port,
      config.node_client_interface,
      config.client_connection_timeout_ms);
    if (!config.node_address_file.empty())
    {
      files::dump(
        fmt::format(
          "{}\n{}",
          config.network.node_address.hostname,
          config.network.node_address.port),
        config.node_address_file);
    }

    asynchost::RPCConnections rpc(
      writer_factory, config.client_connection_timeout_ms);
    rpc.register_message_handlers(bp.get_dispatcher());

    std::string rpc_addresses;
    for (auto& interface : config.network.rpc_interfaces)
    {
      rpc.listen(0, interface.rpc_address.hostname, interface.rpc_address.port);
      rpc_addresses += fmt::format(
        "{}\n{}\n", interface.rpc_address.hostname, interface.rpc_address.port);

      if (interface.public_rpc_address.port == "0")
      {
        interface.public_rpc_address.port = interface.rpc_address.port;
      }
    }
    if (!config.rpc_addresses_file.empty())
    {
      files::dump(rpc_addresses, config.rpc_addresses_file);
    }

    // Initialise the enclave and create a CCF node in it
    const size_t certificate_size = 4096;
    std::vector<uint8_t> node_cert(certificate_size);
    std::vector<uint8_t> network_cert(certificate_size);

    StartType start_type = StartType::New;

    EnclaveConfig enclave_config;
    enclave_config.to_enclave_buffer_start = to_enclave_buffer.data();
    enclave_config.to_enclave_buffer_size = to_enclave_buffer.size();
    enclave_config.to_enclave_buffer_offsets = &to_enclave_offsets;
    enclave_config.from_enclave_buffer_start = from_enclave_buffer.data();
    enclave_config.from_enclave_buffer_size = from_enclave_buffer.size();
    enclave_config.from_enclave_buffer_offsets = &from_enclave_offsets;

    enclave_config.writer_config = writer_config;
#ifdef DEBUG_CONFIG
    enclave_config.debug_config = {memory_reserve_startup};
#endif

    StartupConfig startup_config; // TODO: Rename

    startup_config.snapshot_tx_interval = config.snapshots.snapshot_tx_interval;
    startup_config.consensus = config.consensus;
    startup_config.intervals = config.intervals;
    startup_config.network = config.network;
    startup_config.worker_threads = config.worker_threads;
    startup_config.node_certificate = config.node_certificate;

    auto startup_host_time = std::chrono::system_clock::now();
    LOG_INFO_FMT("Startup host time: {}", startup_host_time);

    startup_config.startup_host_time = crypto::OpenSSL::to_x509_time_string(
      std::chrono::system_clock::to_time_t(startup_host_time));

    if (*start)
    {
      start_type = StartType::New;

      for (auto const& m : config.start.members)
      {
        std::optional<std::vector<uint8_t>> public_encryption_key =
          std::nullopt;
        if (m.encryption_public_key_file.has_value())
        {
          public_encryption_key =
            files::slurp(m.encryption_public_key_file.value());
        }

        nlohmann::json md = nullptr;
        if (m.data_json_file.has_value())
        {
          md = nlohmann::json::parse(files::slurp(m.data_json_file.value()));
        }

        startup_config.start.members.emplace_back(
          files::slurp(m.certificate_file), public_encryption_key, md);
      }
      startup_config.start.constitution = "";
      for (const auto& constitution_path : config.start.constitution_files)
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
        config.start.service_configuration;
      startup_config.start.service_configuration.recovery_threshold =
        recovery_threshold;
      LOG_INFO_FMT(
        "Creating new node: new network (with {} initial member(s) and {} "
        "member(s) required for recovery)",
        config.start.members.size(),
        recovery_threshold);
    }
    else if (*join)
    {
      LOG_INFO_FMT(
        "Creating new node - join existing network at {}:{}",
        target_rpc_address.hostname,
        target_rpc_address.port);
      start_type = StartType::Join;
      startup_config.join.target_rpc_address = config.join.target_rpc_address;
      startup_config.join.join_timer_ms = config.join.join_timer_ms;
      startup_config.join.network_cert =
        files::slurp(config.network_certificate_file);
    }
    else if (*recover)
    {
      LOG_INFO_FMT("Creating new node - recover");
      start_type = StartType::Recover;
    }
    else
    {
      LOG_FATAL_FMT("Start command should be start|join|recover. Exiting.");
    }

    if (*join || *recover)
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

    if (consensus == ConsensusType::BFT)
    {
#ifdef ENABLE_BFT
      LOG_INFO_FMT(
        "Selected consensus BFT is experimental in {}", ccf::ccf_version);
#else
      LOG_FAIL_FMT(
        "Selected consensus BFT is not supported in {}", ccf::ccf_version);
#endif
    }

    enclave.create_node(
      enclave_config,
      startup_config,
      node_cert,
      network_cert,
      start_type,
      num_worker_threads,
      time_updater->behaviour.get_value());

    LOG_INFO_FMT("Created new node");

    // Write the node and network certs to disk.
    files::dump(node_cert, config.node_certificate_file);
    if (*start || *recover)
    {
      files::dump(network_cert, network_certificate_file);
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
    for (uint32_t i = 0; i < (num_worker_threads + 1); ++i)
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
