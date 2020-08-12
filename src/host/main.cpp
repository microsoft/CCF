// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/cli_helper.h"
#include "ds/files.h"
#include "ds/logger.h"
#include "ds/net.h"
#include "ds/non_blocking.h"
#include "ds/oversized.h"
#include "ds/stacktrace_utils.h"
#include "enclave.h"
#include "handle_ring_buffer.h"
#include "load_monitor.h"
#include "node_connections.h"
#include "notify_connections.h"
#include "rpc_connections.h"
#include "sig_term.h"
#include "ticker.h"
#include "time_updater.h"
#include "version.h"

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

::timespec logger::config::start{0, 0};

size_t asynchost::TCPImpl::remaining_read_quota;

void print_version(size_t)
{
  std::cout << "CCF host: " << ccf::ccf_version << std::endl;
  exit(0);
}

int main(int argc, char** argv)
{
  // ignore SIGPIPE
  signal(SIGPIPE, SIG_IGN);
  stacktrace::init_sig_handlers();

  CLI::App app{"ccf"};

  app.set_config("--config", "", "Read an INI or TOML file", false);
  app.allow_config_extras(false);

  app.add_flag(
    "-v, --version", print_version, "Display CCF host version and exit");

  app.require_subcommand(1, 1);

  std::string enclave_file;
  app.add_option("-e,--enclave-file", enclave_file, "CCF transaction engine")
    ->required()
    ->check(CLI::ExistingFile);

  enum EnclaveType
  {
    RELEASE,
    DEBUG,
    VIRTUAL
  };

  std::vector<std::pair<std::string, EnclaveType>> enclave_type_map = {
    {"release", EnclaveType::RELEASE},
    {"debug", EnclaveType::DEBUG},
    {"virtual", EnclaveType::VIRTUAL}};

  EnclaveType enclave_type;
  app.add_option("-t,--enclave-type", enclave_type, "Enclave type")
    ->required()
    ->transform(CLI::CheckedTransformer(enclave_type_map, CLI::ignore_case));

  ConsensusType consensus;
  std::vector<std::pair<std::string, ConsensusType>> consensus_map{
    {"raft", ConsensusType::RAFT}, {"pbft", ConsensusType::PBFT}};
  app.add_option("-c,--consensus", consensus, "Consensus")
    ->required()
    ->transform(CLI::CheckedTransformer(consensus_map, CLI::ignore_case));

  size_t num_worker_threads = 0;
  app
    .add_option(
      "-w,--worker-threads",
      num_worker_threads,
      "Number of worker threads inside the enclave")
    ->capture_default_str();

  cli::ParsedAddress node_address;
  cli::add_address_option(
    app,
    node_address,
    "--node-address",
    "Address on which to listen for TLS commands coming from other nodes")
    ->required();

  std::string node_address_file = {};
  app.add_option(
    "--node-address-file",
    node_address_file,
    "Path to which the node's node-to-node address (including potentially "
    "auto-assigned port) will be written. If empty (default), write nothing");

  cli::ParsedAddress rpc_address;
  cli::add_address_option(
    app,
    rpc_address,
    "--rpc-address",
    "Address on which to listen for TLS commands coming from clients")
    ->required();

  std::string rpc_address_file = {};
  app.add_option(
    "--rpc-address-file",
    rpc_address_file,
    "Path to which the node's RPC address (including potentially "
    "auto-assigned port) will be written. If empty (default), write nothing");

  cli::ParsedAddress public_rpc_address;
  auto public_rpc_address_option = cli::add_address_option(
    app,
    public_rpc_address,
    "--public-rpc-address",
    "Address to advertise publicly to clients (defaults to same as "
    "--rpc-address)");

  std::string ledger_dir("ledger");
  app.add_option("--ledger-dir", ledger_dir, "Ledger directory")
    ->capture_default_str();

  size_t ledger_chunk_threshold = 5'000'000;
  app
    .add_option(
      "--ledger-chunk-max-bytes",
      ledger_chunk_threshold,
      "Minimum size (bytes) at which a new ledger chunk is created.")
    ->capture_default_str()
    ->transform(CLI::AsSizeValue(true)); // 1000 is kb

  logger::Level host_log_level{logger::Level::INFO};
  std::vector<std::pair<std::string, logger::Level>> level_map;
  for (int i = logger::TRACE; i < logger::MAX_LOG_LEVEL; i++)
  {
    level_map.emplace_back(
      logger::config::LevelNames[i], static_cast<logger::Level>(i));
  }
  app
    .add_option(
      "-l,--host-log-level",
      host_log_level,
      "Only emit host log messages above that level")
    ->capture_default_str()
    ->transform(CLI::CheckedTransformer(level_map, CLI::ignore_case));

  bool log_format_json = false;
  app.add_flag(
    "--log-format-json", log_format_json, "Set node stdout log format to JSON");

  std::string node_cert_file("nodecert.pem");
  app
    .add_option(
      "--node-cert-file",
      node_cert_file,
      "Path to which the node certificate will be written")
    ->capture_default_str();

  std::string node_pid_file = fmt::format("{}.pid", argv[0]);
  app
    .add_option(
      "--node-pid-file",
      node_pid_file,
      "Path to which the node PID will be written")
    ->capture_default_str();

  size_t sig_max_tx = 5000;
  app
    .add_option(
      "--sig-max-tx",
      sig_max_tx,
      "Maximum number of transactions between signatures")
    ->capture_default_str();

  size_t sig_max_ms = 1000;
  app
    .add_option(
      "--sig-max-ms", sig_max_ms, "Maximum milliseconds between signatures")
    ->capture_default_str();

  size_t circuit_size_shift = 22;
  app
    .add_option(
      "--circuit-size-shift",
      circuit_size_shift,
      "Size of the internal ringbuffers, as a power of 2")
    ->capture_default_str();

  cli::ParsedAddress notifications_address;
  cli::add_address_option(
    app,
    notifications_address,
    "--notify-server-address",
    "Server address to notify progress to");

  size_t raft_timeout = 100;
  app
    .add_option(
      "--raft-timeout-ms",
      raft_timeout,
      "Raft timeout in milliseconds. The Raft leader sends heartbeats to its "
      "followers at regular intervals defined by this timeout. This should be "
      "set to a significantly lower value than --raft-election-timeout-ms.")
    ->capture_default_str();

  size_t raft_election_timeout = 5000;
  app
    .add_option(
      "--raft-election-timeout-ms",
      raft_election_timeout,
      "Raft election timeout in milliseconds. If a follower does not receive "
      "any "
      "heartbeat from the leader after this timeout, the follower triggers a "
      "new "
      "election.")
    ->capture_default_str();

  size_t pbft_view_change_timeout = 5000;
  app
    .add_option(
      "--pbft_view-change-timeout-ms",
      pbft_view_change_timeout,
      "Pbft view change timeout in milliseconds. If a backup does not receive "
      "the pre-prepare message for a request forwarded to the primary after "
      "this "
      "timeout, the backup triggers a new view change.")
    ->capture_default_str();

  size_t pbft_status_interval = 100;
  app
    .add_option(
      "--pbft-status-interval-ms",
      pbft_status_interval,
      "Pbft status timer interval in milliseconds. All pbft nodes send "
      "messages "
      "containing their status to all other known nodes at regular intervals "
      "defined by this timer interval.")
    ->capture_default_str();

  size_t max_msg_size = 24;
  app
    .add_option(
      "--max-msg-size",
      max_msg_size,
      "Determines maximum total number of bytes for a message sent over the "
      "ringbuffer. Messages may be split into multiple fragments, but this "
      "limits the total size of the sum of those fragments. Value is used as a "
      "shift factor, ie - given N, the limit is (1 << N)")
    ->capture_default_str();

  size_t max_fragment_size = 16;
  app
    .add_option(
      "--max-fragment-size",
      max_fragment_size,
      "Determines maximum size of individual ringbuffer message fragments. "
      "Messages larger than this will be split into multiple fragments. Value "
      "is used as a shift factor, ie - given N, the limit is (1 << N)")
    ->capture_default_str();

  size_t tick_period_ms = 10;
  app
    .add_option(
      "--tick-period-ms",
      tick_period_ms,
      "Wait between ticks sent to the enclave. Lower values reduce minimum "
      "latency at a cost to throughput")
    ->capture_default_str();

  std::string domain;
  app.add_option(
    "--domain", domain, "DNS to use for TLS certificate validation");

  size_t memory_reserve_startup = 0;
  app
    .add_option(
      "--memory-reserve-startup",
      memory_reserve_startup,
#ifdef DEBUG_CONFIG
      "Reserve unused memory inside the enclave, to simulate high memory use"
#else
      "Unused"
#endif
      )
    ->capture_default_str();

  // The network certificate file can either be an input or output parameter,
  // depending on the subcommand.
  std::string network_cert_file = "networkcert.pem";
  std::string network_enc_pubk_file = "network_enc_pubk.pem";

  auto start = app.add_subcommand("start", "Start new network");
  start->configurable();

  start
    ->add_option(
      "--network-cert-file",
      network_cert_file,
      "Destination path to freshly created network certificate")
    ->capture_default_str()
    ->check(CLI::NonexistentPath);

  start
    ->add_option(
      "--network-enc-pubk-file",
      network_enc_pubk_file,
      "Destination path to freshly created network encryption public key")
    ->capture_default_str()
    ->check(CLI::NonexistentPath);

  std::string gov_script = "gov.lua";
  start
    ->add_option(
      "--gov-script",
      gov_script,
      "Path to Lua file that defines the contents of the "
      "ccf.governance.scripts table")
    ->capture_default_str()
    ->check(CLI::ExistingFile)
    ->required();

  std::vector<cli::ParsedMemberInfo> members_info;
  cli::add_member_info_option(
    *start,
    members_info,
    "--member-info",
    "Initial consortium members information (public identity,recovery public "
    "key)")
    ->required();

  std::optional<size_t> recovery_threshold;
  start
    ->add_option(
      "--recovery-threshold",
      recovery_threshold,
      "Number of member shares required for recovery. Defaults to total number "
      "of initial consortium members.")
    ->check(CLI::PositiveNumber)
    ->type_name("UINT");

  auto join = app.add_subcommand("join", "Join existing network");
  join->configurable();

  join
    ->add_option(
      "--network-cert-file",
      network_cert_file,
      "Path to certificate of existing network to join")
    ->capture_default_str()
    ->check(CLI::ExistingFile);

  size_t join_timer = 1000;
  join
    ->add_option(
      "--join-timer",
      join_timer,
      "Duration after which the joining node will resend join requests to "
      "existing network (ms)")
    ->capture_default_str();

  cli::ParsedAddress target_rpc_address;
  cli::add_address_option(
    *join,
    target_rpc_address,
    "--target-rpc-address",
    "RPC over TLS listening address of target network node")
    ->required();

  auto recover = app.add_subcommand("recover", "Recover crashed network");
  recover->configurable();

  recover
    ->add_option(
      "--network-cert-file",
      network_cert_file,
      "Destination path to freshly created network certificate")
    ->capture_default_str()
    ->check(CLI::NonexistentPath);

  recover
    ->add_option(
      "--network-enc-pubk-file",
      network_enc_pubk_file,
      "Destination path to freshly created network encryption public key")
    ->capture_default_str()
    ->check(CLI::NonexistentPath);

  CLI11_PARSE(app, argc, argv);

  if (!(*public_rpc_address_option))
  {
    public_rpc_address = rpc_address;
  }

  // set json log formatter to write to std::out
  if (log_format_json)
  {
    logger::config::initialize_with_json_console();
  }

  uint32_t oe_flags = 0;
  try
  {
    if (domain.empty() && !ds::is_valid_ip(rpc_address.hostname.c_str()))
    {
      throw std::logic_error(fmt::format(
        "--rpc-address ({}) does not appear to specify valid IP address. "
        "Please specify a domain name via the --domain option",
        rpc_address.hostname));
    }

    if ((*start || *join) && files::exists(ledger_dir))
    {
      throw std::logic_error(fmt::format(
        "On start/join, ledger directory should not exist ({})", ledger_dir));
    }
    else if (*recover && !files::exists(ledger_dir))
    {
      throw std::logic_error(fmt::format(
        "On recovery, ledger directory should exist ({}) ", ledger_dir));
    }

    if (*start)
    {
      if (!recovery_threshold.has_value())
      {
        LOG_INFO_FMT(
          "--recovery-threshold unset. Defaulting to number of initial "
          "consortium members ({}).",
          members_info.size());
        recovery_threshold = members_info.size();
      }
      else if (recovery_threshold.value() > members_info.size())
      {
        throw std::logic_error(fmt::format(
          "--recovery-threshold cannot be greater than total number "
          "of initial consortium members (specified via --member-info "
          "options)"));
      }
    }

    switch (enclave_type)
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
          fmt::format("Invalid enclave type: {}", enclave_type));
      }
    }
  }
  catch (const std::logic_error& e)
  {
    LOG_FATAL_FMT("{}. Exiting.", e.what());
    return static_cast<int>(CLI::ExitCodes::ValidationError);
  }

  // Write PID to disk
  files::dump(fmt::format("{}", ::getpid()), node_pid_file);

  // set the host log level
  logger::config::level() = host_log_level;

  // create the enclave
  host::Enclave enclave(enclave_file, oe_flags);

  // messaging ring buffers
  ringbuffer::Circuit circuit(1 << circuit_size_shift);
  messaging::BufferProcessor bp("Host");

  // To prevent deadlock, all blocking writes from the host to the ringbuffer
  // will be queued if the ringbuffer is full
  ringbuffer::WriterFactory base_factory(circuit);
  ringbuffer::NonBlockingWriterFactory non_blocking_factory(base_factory);

  // Factory for creating writers which will handle writing of large messages
  oversized::WriterConfig writer_config{(size_t)(1 << max_fragment_size),
                                        (size_t)(1 << max_msg_size)};
  oversized::WriterFactory writer_factory(non_blocking_factory, writer_config);

  // reconstruct oversized messages sent to the host
  oversized::FragmentReconstructor fr(bp.get_dispatcher());

  // provide regular ticks to the enclave
  asynchost::Ticker ticker(tick_period_ms, writer_factory, [](auto s) {
    logger::config::set_start(s);
  });

  // reset the inbound-TCP processing quota each iteration
  asynchost::ResetTCPReadQuota reset_tcp_quota;

  // regularly update the time given to the enclave
  asynchost::TimeUpdater time_updater(1);

  // regularly record some load statistics
  asynchost::LoadMonitor load_monitor(500, bp);

  // handle outbound messages from the enclave
  asynchost::HandleRingbuffer handle_ringbuffer(
    bp, circuit.read_from_inside(), non_blocking_factory);

  // graceful shutdown on sigterm
  asynchost::Sigterm sigterm(writer_factory);

  // write to a ledger
  asynchost::Ledger ledger(ledger_dir, writer_factory, ledger_chunk_threshold);
  ledger.register_message_handlers(bp.get_dispatcher());

  // Begin listening for node-to-node and RPC messages.
  // This includes DNS resolution and potentially dynamic port assignment (if
  // requesting port 0). The hostname and port may be modified - after calling
  // it holds the final assigned values.
  asynchost::NodeConnectionsTickingReconnect node(
    20, //< Flush reconnections every 20ms
    bp.get_dispatcher(),
    ledger,
    writer_factory,
    node_address.hostname,
    node_address.port);
  if (!node_address_file.empty())
  {
    files::dump(
      fmt::format("{}\n{}", node_address.hostname, node_address.port),
      node_address_file);
  }

  asynchost::RPCConnections rpc(writer_factory);
  rpc.register_message_handlers(bp.get_dispatcher());
  rpc.listen(0, rpc_address.hostname, rpc_address.port);
  if (!rpc_address_file.empty())
  {
    files::dump(
      fmt::format("{}\n{}", rpc_address.hostname, rpc_address.port),
      rpc_address_file);
  }

  // Initialise the enclave and create a CCF node in it
  const size_t certificate_size = 4096;
  const size_t pubk_size = 1024;
  std::vector<uint8_t> node_cert(certificate_size);
  std::vector<uint8_t> network_cert(certificate_size);
  std::vector<uint8_t> network_enc_pubk(pubk_size);

  StartType start_type = StartType::Unknown;

  EnclaveConfig enclave_config;
  enclave_config.circuit = &circuit;
  enclave_config.writer_config = writer_config;
#ifdef DEBUG_CONFIG
  enclave_config.debug_config = {memory_reserve_startup};
#endif

  CCFConfig ccf_config;
  ccf_config.consensus_config = {raft_timeout,
                                 raft_election_timeout,
                                 pbft_view_change_timeout,
                                 pbft_status_interval};
  ccf_config.signature_intervals = {sig_max_tx, sig_max_ms};
  ccf_config.node_info_network = {rpc_address.hostname,
                                  public_rpc_address.hostname,
                                  node_address.hostname,
                                  node_address.port,
                                  rpc_address.port};
  ccf_config.domain = domain;

  if (*start)
  {
    start_type = StartType::New;

    for (auto const& m_info : members_info)
    {
      ccf_config.genesis.members_info.emplace_back(
        files::slurp(m_info.cert_file), files::slurp(m_info.keyshare_pub_file));
    }
    ccf_config.genesis.gov_script = files::slurp_string(gov_script);
    ccf_config.genesis.recovery_threshold = recovery_threshold.value();
    LOG_INFO_FMT(
      "Creating new node: new network (with {} initial member(s) and {} "
      "member(s) required for recovery)",
      ccf_config.genesis.members_info.size(),
      ccf_config.genesis.recovery_threshold);
  }
  else if (*join)
  {
    LOG_INFO_FMT(
      "Creating new node - joining existing network at {}:{}",
      target_rpc_address.hostname,
      target_rpc_address.port);
    start_type = StartType::Join;

    ccf_config.joining.target_host = target_rpc_address.hostname;
    ccf_config.joining.target_port = target_rpc_address.port;
    ccf_config.joining.network_cert = files::slurp(network_cert_file);
    ccf_config.joining.join_timer = join_timer;
  }
  else if (*recover)
  {
    LOG_INFO_FMT("Creating new node - recover");
    start_type = StartType::Recover;
  }

  if (start_type == StartType::Unknown)
  {
    LOG_FATAL_FMT("Start command should be start|join|recover. Exiting.");
  }

  enclave.create_node(
    enclave_config,
    ccf_config,
    node_cert,
    network_cert,
    network_enc_pubk,
    start_type,
    consensus,
    num_worker_threads,
    time_updater->behaviour.get_value());

  LOG_INFO_FMT("Created new node");

  asynchost::NotifyConnections report(
    bp.get_dispatcher(),
    notifications_address.hostname,
    notifications_address.port);

  // Write the node and network certs to disk.
  files::dump(node_cert, node_cert_file);
  if (*start || *recover)
  {
    files::dump(network_cert, network_cert_file);
    files::dump(network_enc_pubk, network_enc_pubk_file);
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
      // the enclave sent logging messages, it is useful to read and print them
      // before dying.
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

  return 0;
}
