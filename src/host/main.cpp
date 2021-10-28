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

  app.set_config("--config", "", "Read an INI or TOML file", false);
  app.allow_config_extras(false);

  app.add_flag(
    "-v, --version", print_version, "Display CCF host version and exit");

  app.require_subcommand(1, 1);

  std::string enclave_file;
  app.add_option("-e,--enclave-file", enclave_file, "CCF application")
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
    {"cft", ConsensusType::CFT}, {"bft", ConsensusType::BFT}};
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
    "Address on which to listen for commands coming from other nodes")
    ->required();

  std::string node_address_file = {};
  app.add_option(
    "--node-address-file",
    node_address_file,
    "Path to which the node's node-to-node address (including potentially "
    "auto-assigned port) will be written. If empty (default), write nothing");

  std::optional<std::string> node_client_interface = std::nullopt;
  app.add_option(
    "--node-client-interface",
    node_client_interface,
    "Interface on which to bind to for commands sent to other nodes. If "
    "unspecified (default), this is automatically assigned by the OS");

  std::string rpc_address_file = {};
  app.add_option(
    "--rpc-address-file",
    rpc_address_file,
    "Path to which all node RPC addresses (including potentially "
    "auto-assigned ports) will be written. If empty (default), write nothing");

  cli::ParsedAddress rpc_address;
  auto rpc_address_option = cli::add_address_option(
    app,
    rpc_address,
    "--rpc-address",
    "Address on which to listen for TLS commands coming from clients. Port "
    "defaults to 443 if unspecified.",
    "443");

  cli::ParsedAddress public_rpc_address;
  auto public_rpc_address_option =
    cli::add_address_option(
      app,
      public_rpc_address,
      "--public-rpc-address",
      "Address to advertise publicly to clients (defaults to same as "
      "--rpc-address)",
      "443")
      ->needs(rpc_address_option);

  size_t max_open_sessions = 1'000;
  app
    .add_option(
      "--max-open-sessions",
      max_open_sessions,
      "Soft cap on number of TLS sessions which may be open at the same time. "
      "Once this many connection are open, additional connections will receive "
      "a 503 HTTP error (until the hard cap is reached)")
    ->capture_default_str()
    ->needs(rpc_address_option);

  size_t max_open_sessions_hard = 0;
  auto mosh_option =
    app
      .add_option(
        "--max-open-sessions-hard",
        max_open_sessions_hard,
        fmt::format(
          "Hard cap on number of TLS sessions which may be open at the same "
          "time. "
          "Once this many connections are open, additional connection attempts "
          "will be closed before a TLS handshake is completed. Default is {} "
          "more than --max-open-sessions",
          cli::ParsedRpcInterface::default_mosh_diff))
      ->needs(rpc_address_option);

  std::vector<cli::ParsedRpcInterface> rpc_interfaces;
  auto rpc_interfaces_option = cli::add_rpc_interface_option(
    app,
    rpc_interfaces,
    "--rpc-interface",
    "Specify additional interfaces on which this node should listen for "
    "incoming client commands. Each interface will have its own separate "
    "session caps. Each interface should be specified as a comma-separated "
    "list <rpc-address>,<public-rpc-address>,<max-open-sessions>,<max-"
    "open-sessions-hard>, where all fields after <rpc-address> are optional");

  std::string ledger_dir("ledger");
  app.add_option("--ledger-dir", ledger_dir, "Ledger directory")
    ->capture_default_str();

  std::vector<std::string> read_only_ledger_dirs;
  app
    .add_option(
      "--read-only-ledger-dir",
      read_only_ledger_dirs,
      "Additional read-only ledger directory (optional)")
    ->type_size(-1);

  std::string snapshot_dir("snapshots");
  app.add_option("--snapshot-dir", snapshot_dir, "Snapshots directory")
    ->capture_default_str();

  size_t ledger_chunk_bytes = 5'000'000;
  app
    .add_option(
      "--ledger-chunk-bytes",
      ledger_chunk_bytes,
      "Size (bytes) at which a new ledger chunk is created")
    ->capture_default_str()
    ->transform(CLI::AsSizeValue(true)); // 1000 is kb

  size_t io_logging_threshold_ns =
    std::chrono::duration_cast<std::chrono::nanoseconds>(
      asynchost::TimeBoundLogger::default_max_time)
      .count();
  app
    .add_option(
      "--io-logging-threshold-ns",
      io_logging_threshold_ns,
      "Any IO step that takes longer than this time will be logged at level "
      "FAIL. This time is given in nanoseconds")
    ->capture_default_str();

  size_t snapshot_tx_interval = 10'000;
  app
    .add_option(
      "--snapshot-tx-interval",
      snapshot_tx_interval,
      "Number of transactions between snapshots")
    ->capture_default_str();

  logger::Level host_log_level{logger::Level::INFO};
  std::vector<std::pair<std::string, logger::Level>> level_map;
  for (int i = logger::MOST_VERBOSE; i < logger::MAX_LOG_LEVEL; i++)
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

  size_t sig_tx_interval = 5000;
  app
    .add_option(
      "--sig-tx-interval",
      sig_tx_interval,
      "Number of transactions between signatures")
    ->capture_default_str();

  size_t sig_ms_interval = 1000;
  app
    .add_option(
      "--sig-ms-interval", sig_ms_interval, "Milliseconds between signatures")
    ->capture_default_str();

  size_t circuit_size_shift = 22;
  app
    .add_option(
      "--circuit-size-shift",
      circuit_size_shift,
      "Size of the internal ringbuffers, as a power of 2")
    ->capture_default_str();

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
      "any heartbeat from the leader after this timeout, the follower triggers "
      "a new election.")
    ->capture_default_str();

  size_t bft_view_change_timeout = 5000;
  app
    .add_option(
      "--bft-view-change-timeout-ms",
      bft_view_change_timeout,
      "bft view change timeout in milliseconds. If a backup does not receive "
      "the pre-prepare message for a request forwarded to the primary after "
      "this timeout, the backup triggers a new view change.")
    ->capture_default_str();

  size_t bft_status_interval = 100;
  app
    .add_option(
      "--bft-status-interval-ms",
      bft_status_interval,
      "bft status timer interval in milliseconds. All bft nodes send "
      "messages "
      "containing their status to all other known nodes at regular intervals "
      "defined by this timer interval.")
    ->capture_default_str();

  size_t client_connection_timeout = 2000;
  app
    .add_option(
      "--client-connection-timeout-ms",
      client_connection_timeout,
      "TCP client connection timeout in milliseconds after which a"
      "non-established client connection is automatically re-created. This "
      "should be set to a significantly lower value than the "
      "--raft-election-timeout-ms.")
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

  crypto::CertificateSubjectIdentity node_certificate_subject_identity(
    "CN=CCF Node");
  app
    .add_option(
      "--sn",
      node_certificate_subject_identity.name,
      "Subject Name in node certificate, eg. CN=CCF Node")
    ->capture_default_str();

  cli::add_subject_alternative_name_option(
    app,
    node_certificate_subject_identity.sans,
    "--san",
    "Subject Alternative Name in node certificate. Can be either "
    "iPAddress:xxx.xxx.xxx.xxx, or dNSName:sub.domain.tld. If not specified, "
    "the address components from --rpc-interface will be used");

  size_t jwt_key_refresh_interval_s = 1800;
  app
    .add_option(
      "--jwt-key-refresh-interval-s",
      jwt_key_refresh_interval_s,
      "Interval in seconds for JWT public signing key refresh.")
    ->capture_default_str();

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

  crypto::CurveID curve_id = crypto::CurveID::SECP384R1;
  std::vector<std::pair<std::string, crypto::CurveID>> curve_id_map = {
    {"secp384r1", crypto::CurveID::SECP384R1},
    {"secp256r1", crypto::CurveID::SECP256R1}};
  app
    .add_option(
      "--curve-id",
      curve_id,
      "Elliptic curve to use as for node and network identities (used for TLS "
      "and ledger signatures)")
    ->transform(CLI::CheckedTransformer(curve_id_map, CLI::ignore_case))
    ->capture_default_str();

  // By default, node certificates are only valid for one day. It is expected
  // that members will submit a proposal to renew the node certificates before
  // expiry, at the point the service is open.
  size_t initial_node_certificate_validity_period_days = 1;
  app
    .add_option(
      "--initial-node-cert-validity-days",
      initial_node_certificate_validity_period_days,
      "Initial validity period (days) for certificates of nodes before the "
      "service is open by members")
    ->check(CLI::PositiveNumber)
    ->type_name("UINT");

  // The network certificate file can either be an input or output parameter,
  // depending on the subcommand.
  std::string network_cert_file = "networkcert.pem";

  auto start = app.add_subcommand("start", "Start new network");
  start->configurable();

  start
    ->add_option(
      "--network-cert-file",
      network_cert_file,
      "Destination path to freshly created network certificate")
    ->capture_default_str()
    ->check(CLI::NonexistentPath);

  std::vector<std::string> constitution_paths;
  start
    ->add_option(
      "--constitution",
      constitution_paths,
      "Path to one or more JS file that are concatenated to define the "
      "contents of the "
      "public:ccf.gov.constitution table")
    ->type_size(-1);

  std::vector<cli::ParsedMemberInfo> members_info;
  cli::add_member_info_option(
    *start,
    members_info,
    "--member-info",
    "Initial consortium members information "
    "(member_cert.pem[,member_enc_pubk.pem[,member_data.json]])")
    ->required();

  std::optional<size_t> recovery_threshold = std::nullopt;
  start
    ->add_option(
      "--recovery-threshold",
      recovery_threshold,
      "Number of member shares required for recovery. Defaults to total number "
      "of initial consortium members with a public encryption key.")
    ->check(CLI::PositiveNumber)
    ->type_name("UINT");

  size_t max_allowed_node_cert_validity_days = 365;
  start
    ->add_option(
      "--max-allowed-node-cert-validity-days",
      max_allowed_node_cert_validity_days,
      "Maximum validity period (days) for certificates of trusted nodes")
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

  try
  {
    app.parse(argc, argv);

    // Add an additional check not represented by existing ->needs, ->requires
    // etc
    if (!(*rpc_address_option || *rpc_interfaces_option))
    {
      const auto option_list = fmt::format(
        "{}, {}",
        rpc_address_option->get_name(),
        rpc_interfaces_option->get_name());
      throw CLI::RequiredError::Option(1, 0, 0, option_list);
    }
  }
  catch (const CLI::ParseError& e)
  {
    return app.exit(e);
  }

  // set json log formatter to write to std::out
  if (log_format_json)
  {
    logger::config::initialize_with_json_console();
  }

  // Fill in derived default values
  if (!(*public_rpc_address_option))
  {
    public_rpc_address = rpc_address;
  }

  if (!(*mosh_option))
  {
    max_open_sessions_hard =
      max_open_sessions + cli::ParsedRpcInterface::default_mosh_diff;
  }

  // If --rpc-address etc were specified, they populate a single object at the
  // start of the rpc_interfaces list
  if (*rpc_address_option)
  {
    cli::ParsedRpcInterface first;
    first.rpc_address = rpc_address;
    first.public_rpc_address = public_rpc_address;
    first.max_open_sessions = max_open_sessions;
    first.max_open_sessions_hard = max_open_sessions_hard;
    rpc_interfaces.insert(rpc_interfaces.begin(), std::move(first));
  }

  const auto cli_config = app.config_to_str(true, false);
  LOG_INFO_FMT("Version: {}", ccf::ccf_version);
  LOG_INFO_FMT("Run with following options:\n{}", cli_config);

  uint32_t oe_flags = 0;
  try
  {
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
      for (auto const& mi : members_info)
      {
        if (mi.enc_pubk_file.has_value())
        {
          members_with_pubk_count++;
        }
      }

      if (!recovery_threshold.has_value())
      {
        LOG_INFO_FMT(
          "Recovery threshold unset. Defaulting to number of initial "
          "consortium members with a public encryption key ({}).",
          members_with_pubk_count);
        recovery_threshold = members_with_pubk_count;
      }
      else if (recovery_threshold.value() > members_with_pubk_count)
      {
        throw std::logic_error(fmt::format(
          "Recovery threshold ({}) cannot be greater than total number ({})"
          "of initial consortium members with a public encryption "
          "key (specified via --member-info options)",
          recovery_threshold.value(),
          members_with_pubk_count));
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

  asynchost::TimeBoundLogger::default_max_time =
    std::chrono::duration_cast<decltype(
      asynchost::TimeBoundLogger::default_max_time)>(
      std::chrono::nanoseconds(io_logging_threshold_ns));

  // Write PID to disk
  files::dump(fmt::format("{}", ::getpid()), node_pid_file);

  // set the host log level
  logger::config::level() = host_log_level;

  // create the enclave
  host::Enclave enclave(enclave_file, oe_flags);

  // messaging ring buffers
  const auto buffer_size = 1 << circuit_size_shift;

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
    (size_t)(1 << max_fragment_size), (size_t)(1 << max_msg_size)};
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
      ledger_dir,
      writer_factory,
      ledger_chunk_bytes,
      asynchost::ledger_max_read_cache_files_default,
      read_only_ledger_dirs);
    ledger.register_message_handlers(bp.get_dispatcher());

    asynchost::SnapshotManager snapshots(snapshot_dir, ledger);
    snapshots.register_message_handlers(bp.get_dispatcher());

    // Begin listening for node-to-node and RPC messages.
    // This includes DNS resolution and potentially dynamic port assignment (if
    // requesting port 0). The hostname and port may be modified - after calling
    // it holds the final assigned values.
    asynchost::NodeConnections node(
      bp.get_dispatcher(),
      ledger,
      writer_factory,
      node_address.hostname,
      node_address.port,
      node_client_interface,
      client_connection_timeout);
    if (!node_address_file.empty())
    {
      files::dump(
        fmt::format("{}\n{}", node_address.hostname, node_address.port),
        node_address_file);
    }

    asynchost::RPCConnections rpc(writer_factory, client_connection_timeout);
    rpc.register_message_handlers(bp.get_dispatcher());

    std::string rpc_addresses;
    for (auto& interface : rpc_interfaces)
    {
      rpc.listen(0, interface.rpc_address.hostname, interface.rpc_address.port);
      rpc_addresses += fmt::format(
        "{}\n{}\n", interface.rpc_address.hostname, interface.rpc_address.port);

      if (interface.public_rpc_address.port == "0")
      {
        interface.public_rpc_address.port = interface.rpc_address.port;
      }
    }
    if (!rpc_address_file.empty())
    {
      files::dump(rpc_addresses, rpc_address_file);
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

    CCFConfig ccf_config;
    ccf_config.consensus_config = {
      consensus,
      raft_timeout,
      raft_election_timeout,
      bft_view_change_timeout,
      bft_status_interval};
    ccf_config.signature_intervals = {sig_tx_interval, sig_ms_interval};

    ccf_config.node_info_network.node_address = {
      node_address.hostname, node_address.port};
    for (const auto& interface : rpc_interfaces)
    {
      ccf::NodeInfoNetwork::RpcAddresses addr;
      addr.rpc_address = {
        interface.rpc_address.hostname, interface.rpc_address.port};
      addr.public_rpc_address = {
        interface.public_rpc_address.hostname,
        interface.public_rpc_address.port};
      addr.max_open_sessions_soft = interface.max_open_sessions;
      addr.max_open_sessions_hard = interface.max_open_sessions_hard;
      ccf_config.node_info_network.rpc_interfaces.push_back(addr);
    }
    ccf_config.snapshot_tx_interval = snapshot_tx_interval;

    ccf_config.node_certificate_subject_identity =
      node_certificate_subject_identity;
    ccf_config.jwt_key_refresh_interval_s = jwt_key_refresh_interval_s;
    ccf_config.curve_id = curve_id;
    ccf_config.initial_node_certificate_validity_period_days =
      initial_node_certificate_validity_period_days;

    auto startup_host_time = std::chrono::system_clock::now();
    LOG_INFO_FMT("Startup host time: {}", startup_host_time);

    ccf_config.startup_host_time = crypto::OpenSSL::to_x509_time_string(
      std::chrono::system_clock::to_time_t(startup_host_time));

    if (*start)
    {
      start_type = StartType::New;

      for (auto const& m_info : members_info)
      {
        std::optional<std::vector<uint8_t>> public_encryption_key_file =
          std::nullopt;
        if (m_info.enc_pubk_file.has_value())
        {
          public_encryption_key_file =
            files::slurp(m_info.enc_pubk_file.value());
        }

        nlohmann::json md = nullptr;
        if (m_info.member_data_file.has_value())
        {
          md = nlohmann::json::parse(
            files::slurp(m_info.member_data_file.value()));
        }

        ccf_config.genesis.members_info.emplace_back(
          files::slurp(m_info.cert_file), public_encryption_key_file, md);
      }
      ccf_config.genesis.constitution = "";
      for (const auto& constitution_path : constitution_paths)
      {
        // Separate with single newlines
        if (!ccf_config.genesis.constitution.empty())
        {
          ccf_config.genesis.constitution += '\n';
        }

        ccf_config.genesis.constitution +=
          files::slurp_string(constitution_path);
      }
      ccf_config.genesis.recovery_threshold = recovery_threshold.value();
      ccf_config.genesis.max_allowed_node_cert_validity_days =
        max_allowed_node_cert_validity_days;
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
        ccf_config.startup_snapshot = snapshots.read_snapshot(snapshot);

        if (asynchost::is_snapshot_file_1_x(snapshot))
        {
          // Snapshot evidence seqno is only specified for 1.x snapshots which
          // need to be verified by deserialising the ledger suffix.
          ccf_config.startup_snapshot_evidence_seqno_for_1_x =
            asynchost::get_snapshot_evidence_idx_from_file_name(snapshot);
        }

        LOG_INFO_FMT(
          "Found latest snapshot file: {} (size: {})",
          snapshot,
          ccf_config.startup_snapshot.size());
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
      ccf_config,
      node_cert,
      network_cert,
      start_type,
      num_worker_threads,
      time_updater->behaviour.get_value());

    LOG_INFO_FMT("Created new node");

    // Write the node and network certs to disk.
    files::dump(node_cert, node_cert_file);
    if (*start || *recover)
    {
      files::dump(network_cert, network_cert_file);
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
