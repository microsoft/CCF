// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/cli_helper.h"
#include "ds/files.h"
#include "ds/logger.h"
#include "ds/oversized.h"
#include "enclave.h"
#include "handle_ringbuffer.h"
#include "nodeconnections.h"
#include "notifyconnections.h"
#include "rpcconnections.h"
#include "sigterm.h"
#include "ticker.h"

#include <CLI11/CLI11.hpp>
#include <codecvt>
#include <fstream>
#include <iostream>
#include <locale>
#include <string>
#include <thread>

using namespace std::string_literals;
using namespace std::chrono_literals;

::timespec logger::config::start{0, 0};

int main(int argc, char** argv)
{
  // ignore SIGPIPE
  signal(SIGPIPE, SIG_IGN);

  CLI::App app{"ccf"};

  app.require_subcommand(1, 1);

  std::string enclave_file;
  app.add_option("-e,--enclave-file", enclave_file, "CCF transaction engine")
    ->required()
    ->check(CLI::ExistingFile);

  std::string enclave_type;
  app
    .add_set(
      "-t,--enclave-type",
      enclave_type,
      {"debug", "virtual"},
      "Enclave type",
      true)
    ->required();

  cli::ParsedAddress node_address;
  cli::add_address_option(
    app, node_address, "--node-address", "Node-to-node listening address")
    ->required();

  cli::ParsedAddress rpc_address;
  cli::add_address_option(
    app, rpc_address, "--rpc-address", "RPC over TLS listening address")
    ->required();

  cli::ParsedAddress public_rpc_address;
  cli::add_address_option(
    app,
    public_rpc_address,
    "--public-rpc-address",
    "Public RPC over TLS listening address")
    ->required();

  std::string ledger_file("ccf.ledger");
  app.add_option("--ledger-file", ledger_file, "Ledger file", true);

  std::string host_log_level("info");
  app.add_set(
    "-l,--host-log-level",
    host_log_level,
    {"fatal", "fail", "info", "debug", "trace"},
    "Only emit host log messages above that level",
    true);

  std::optional<std::string> json_log_path;
  app.add_option(
    "--json-log-path",
    json_log_path,
    "Path to file where the json logs will be written");

  std::string node_cert_file("nodecert.pem");
  app.add_option(
    "--node-cert-file",
    node_cert_file,
    "Path to which the node certificate will be written",
    true);

  std::string quote_file("quote.bin");
  app.add_option("-q,--quote-file", quote_file, "SGX quote file", true);

  size_t sig_max_tx = 1000;
  app.add_option(
    "--sig-max-tx",
    sig_max_tx,
    "Maximum number of transactions between signatures",
    true);

  size_t sig_max_ms = 1000;
  app.add_option(
    "--sig-max-ms",
    sig_max_ms,
    "Maximum milliseconds between signatures",
    true);

  size_t circuit_size_shift = 22;
  app.add_option(
    "--circuit-size-shift",
    circuit_size_shift,
    "Size of the internal ringbuffers, as a power of 2",
    true);

  cli::ParsedAddress notifications_address;
  cli::add_address_option(
    app,
    notifications_address,
    "--notify-server-address",
    "Server address to notify progress to");

  size_t raft_timeout = 100;
  app.add_option(
    "--raft-timeout-ms", raft_timeout, "Raft timeout in milliseconds", true);

  size_t raft_election_timeout = 500;
  app.add_option(
    "--raft-election-timeout-ms",
    raft_election_timeout,
    "Raft election timeout in milliseconds",
    true);

  size_t max_msg_size = 24;
  app.add_option(
    "--max-msg-size",
    max_msg_size,
    "Determines maximum total number of bytes for a message sent over the "
    "ringbuffer. Messages may be split into multiple fragments, but this "
    "limits the total size of the sum of those fragments. Value is used as a "
    "shift factor, ie - given N, the limit is (1 << N)",
    true);

  size_t max_fragment_size = 16;
  app.add_option(
    "--max-fragment-size",
    max_fragment_size,
    "Determines maximum size of individual ringbuffer message fragments. "
    "Messages larger than this will be split into multiple fragments. Value is "
    "used as a shift factor, ie - given N, the limit is (1 << N)",
    true);

  size_t tick_period_ms = 10;
  app.add_option(
    "--tick-period-ms",
    tick_period_ms,
    "Wait between ticks sent to the enclave. Lower values reduce minimum "
    "latency at a cost to throughput",
    true);

  size_t memory_reserve_startup = 0;
  app.add_option(
    "--memory-reserve-startup",
    memory_reserve_startup,
#ifdef DEBUG_CONFIG
    "Reserve unused memory inside the enclave, to simulate high memory use",
#else
    "Unused",
#endif
    true);

  // The network certificate file can either be an input or output parameter,
  // depending on the subcommand.
  std::string network_cert_file = "networkcert.pem";

  auto start = app.add_subcommand("start", "Start new network");
  start
    ->add_option(
      "--network-cert-file",
      network_cert_file,
      "Destination path to freshly created network certificate",
      true)
    ->check(CLI::NonexistentPath);

  std::string gov_script = "gov.lua";
  start
    ->add_option(
      "--gov-script",
      gov_script,
      "Path to Lua file that defines the contents of the gov_scripts table",
      true)
    ->check(CLI::ExistingFile)
    ->required();

  std::vector<std::string> member_cert_files;
  start
    ->add_option(
      "--member-cert",
      member_cert_files,
      "Consortium member certificates",
      true)
    ->required();

  auto join = app.add_subcommand("join", "Join existing network");
  join
    ->add_option(
      "--network-cert-file",
      network_cert_file,
      "Path to certificate of existing network to join",
      true)
    ->check(CLI::ExistingFile);

  cli::ParsedAddress target_rpc_address;
  cli::add_address_option(
    *join,
    target_rpc_address,
    "--target-rpc-address",
    "RPC over TLS listening address of target network node")
    ->required();

  auto recover = app.add_subcommand("recover", "Recover crashed network");
  recover
    ->add_option(
      "--network-cert-file",
      network_cert_file,
      "Destination path to freshly created network certificate",
      true)
    ->check(CLI::NonexistentPath);

  CLI11_PARSE(app, argc, argv);

  uint32_t oe_flags = 0;
  if (enclave_type == "debug")
    oe_flags |= OE_ENCLAVE_FLAG_DEBUG;
  else if (enclave_type == "virtual")
    oe_flags = ENCLAVE_FLAG_VIRTUAL;
  else
    throw std::logic_error("invalid enclave type: "s + enclave_type);

  // log level
  auto host_log_level_ = logger::config::to_level(host_log_level.c_str());
  if (!host_log_level_)
    throw std::logic_error("No such logging level: "s + host_log_level);

  // set the host log level
  logger::config::level() = host_log_level_.value();

  // set the custom log formatter path
  if (json_log_path.has_value())
  {
    logger::config::loggers().emplace_back(
      std::make_unique<logger::JsonLogger>(json_log_path.value()));
  }
  // create the enclave
  host::Enclave enclave(enclave_file, oe_flags);

  // messaging ring buffers
  ringbuffer::Circuit circuit(1 << circuit_size_shift);
  messaging::BufferProcessor bp("Host");

  // Factory for creating writers which will handle writing of large messages
  oversized::WriterConfig writer_config{(size_t)(1 << max_fragment_size),
                                        (size_t)(1 << max_msg_size)};
  oversized::WriterFactory writer_factory(&circuit, writer_config);

  // reconstruct oversized messages sent to the host
  oversized::FragmentReconstructor fr(bp.get_dispatcher());

  // provide regular ticks to the enclave
  asynchost::Ticker ticker(tick_period_ms, writer_factory, [](auto s) {
    logger::config::set_start(s);
  });

  // handle outbound messages from the enclave
  asynchost::HandleRingbuffer handle_ringbuffer(bp, circuit.read_from_inside());

  // graceful shutdown on sigterm
  asynchost::Sigterm sigterm(writer_factory);

  // Initialise the enclave and create a CCF node in it
  const size_t certificate_size = 4096;
  std::vector<uint8_t> node_cert(certificate_size);
  std::vector<uint8_t> quote(OE_MAX_REPORT_SIZE);
  std::vector<uint8_t> network_cert(certificate_size);

  StartType start_type;

  EnclaveConfig enclave_config;
  enclave_config.circuit = &circuit;
  enclave_config.writer_config = writer_config;
#ifdef DEBUG_CONFIG
  enclave_config.debug_config = {memory_reserve_startup};
#endif

  CCFConfig ccf_config;
  ccf_config.raft_config = {raft_timeout, raft_election_timeout};
  ccf_config.signature_intervals = {sig_max_tx, sig_max_ms};
  ccf_config.node_info_network = {rpc_address.hostname,
                                  public_rpc_address.hostname,
                                  node_address.port,
                                  rpc_address.port};

  if (*start)
  {
    start_type = StartType::New;

    for (auto const& cert_file : member_cert_files)
    {
      ccf_config.genesis.member_certs.emplace_back(
        tls::make_verifier(files::slurp(cert_file))->raw_cert_data());
    }
    ccf_config.genesis.gov_script = files::slurp_string(gov_script);
    LOG_INFO_FMT(
      "Creating new node: new network (with {} initial member(s))",
      ccf_config.genesis.member_certs.size());
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
  }
  else if (*recover)
  {
    LOG_INFO_FMT("Creating new node - recover");
    start_type = StartType::Recover;
  }

  enclave.create_node(
    enclave_config, ccf_config, node_cert, quote, network_cert, start_type);

  LOG_INFO_FMT("Created new node");

  // ledger
  asynchost::Ledger ledger(ledger_file, writer_factory);
  ledger.register_message_handlers(bp.get_dispatcher());

  asynchost::NodeConnections node(
    ledger, writer_factory, node_address.hostname, node_address.port);
  node.register_message_handlers(bp.get_dispatcher());

  asynchost::NotifyConnections report(
    bp.get_dispatcher(),
    notifications_address.hostname,
    notifications_address.port);

  asynchost::RPCConnections rpc(writer_factory);
  rpc.register_message_handlers(bp.get_dispatcher());
  rpc.listen(0, rpc_address.hostname, rpc_address.port);

  // Write the node and network certs and quote to disk.
  files::dump(node_cert, node_cert_file);
  if (*start || *recover)
  {
    files::dump(network_cert, network_cert_file);
  }

#ifdef GET_QUOTE
  files::dump(quote, quote_file);

  if (!enclave.verify_quote(quote, node_cert))
    LOG_FATAL_FMT("Verification of local node quote failed");
#endif

  // Start a thread which will ECall and process messages inside the enclave
  auto enclave_thread = std::thread([&]() {
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
  });

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  enclave_thread.join();

  return 0;
}
