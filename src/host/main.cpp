// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
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

using namespace std;

int main(int argc, char** argv)
{
  // ignore SIGPIPE
  signal(SIGPIPE, SIG_IGN);

  CLI::App app{"ccf"};

  std::string enclave_file("");
  app.add_option("-e,--enclave-file", enclave_file, "CCF transaction engine")
    ->required()
    ->check(CLI::ExistingFile);

  std::string enclave_type("debug");
  app.add_set(
    "-t,--enclave-type",
    enclave_type,
    {"debug", "simulate", "virtual"},
    "Enclave type",
    true);

  std::string start("new");
  app.add_set(
    "-s,--start",
    start,
    {"new", "verify", "recover"},
    "Startup mode: new for a fresh network, verify to verify an enclave quote, "
    "recover to start a recovery",
    true);

  std::string log_level("info");
  app.add_set(
    "-l,--log-level",
    log_level,
    {"fatal", "fail", "info", "debug", "trace"},
    "Only emit log messages above that level",
    true);

  std::string quote_file("quote.bin");
  app.add_option("-q,--quote-file", quote_file, "SGX quote file", true);

  std::string quoted_data("nodecert.pem");
  app.add_option(
    "-c,--quoted-data", quoted_data, "SGX quoted certificate", true);

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

  std::string raft_hostname("0.0.0.0");
  app.add_option("--raft-host", raft_hostname, "Raft listening hostname", true);

  std::string raft_port("4568");
  app.add_option("--raft-port", raft_port, "Raft listening port", true);

  std::string ledger_file("ccf.ledger");
  app.add_option("--ledger-file", ledger_file, "Ledger file", true);

  size_t raft_timeout = 100;
  app.add_option(
    "--raft-timeout-ms", raft_timeout, "Raft timeout in milliseconds", true);

  size_t raft_election_timeout = 500;
  app.add_option(
    "--raft-election-timeout-ms",
    raft_election_timeout,
    "Raft election timeout in milliseconds",
    true);

  std::string node_cert_file("nodecert.pem");
  app.add_option(
    "--node-cert-file",
    node_cert_file,
    "Path to which the node certificate will be written",
    true);

  std::string tls_hostname("0.0.0.0");
  app.add_option("--tls-host", tls_hostname, "TLS listening hostname", true);

  std::string tls_pubhostname("0.0.0.0");
  app.add_option(
    "--tls-pubhost", tls_pubhostname, "TLS public listening hostname", true);

  std::string tls_port("4567");
  app.add_option("--tls-port", tls_port, "TLS listening port", true);

  std::string notify_server_hostname;
  app.add_option(
    "--notify-server-host",
    notify_server_hostname,
    "Server host to notify progress to",
    true);

  std::string notify_server_port;
  app.add_option(
    "--notify-server-port",
    notify_server_port,
    "Server port to notify progress to",
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

  CLI11_PARSE(app, argc, argv);

  uint32_t oe_flags = 0;
  if (enclave_type == "debug")
    oe_flags |= OE_ENCLAVE_FLAG_DEBUG;
  else if (enclave_type == "simulate")
    oe_flags |= OE_ENCLAVE_FLAG_SIMULATE;
  else if (enclave_type == "virtual")
    oe_flags = ENCLAVE_FLAG_VIRTUAL;
  else
    throw logic_error("invalid enclave type: "s + enclave_type);

  // log level
  auto host_log_level = logger::config::to_level(log_level.c_str());
  if (!host_log_level)
    throw logic_error("No such logging level: "s + log_level);

  // set the host log level
  logger::config::level() = host_log_level.value();

  // create the enclave
  host::Enclave enclave(enclave_file, oe_flags);

#ifdef GET_QUOTE
  if (start == "verify")
  {
    auto q = files::slurp(quote_file);
    auto d = files::slurp(quoted_data);

    auto passed = enclave.verify_quote(q, d);
    if (!passed)
    {
      throw runtime_error("Quote verification failed");
    }
    else
    {
      LOG_INFO << "Quote verified" << std::endl;
      return 0;
    }
  }
#endif

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
  asynchost::Ticker ticker(tick_period_ms, writer_factory);

  // handle outbound messages from the enclave
  asynchost::HandleRingbuffer handle_ringbuffer(bp, circuit.read_from_inside());

  // graceful shutdown on sigterm
  asynchost::Sigterm sigterm(writer_factory);

  // Initialise the enclave and create a CCF node in it
  const size_t node_size = 4096;
  vector<uint8_t> node_cert(node_size);
  vector<uint8_t> quote(OE_MAX_REPORT_SIZE);
  LOG_INFO << "Starting new node" << (start == "recover" ? " (recovery)." : ".")
           << std::endl;
  raft::Config raft_config{
    chrono::milliseconds(raft_timeout),
    chrono::milliseconds(raft_election_timeout),
  };

  EnclaveConfig config;
  config.circuit = &circuit;
  config.writer_config = writer_config;
  config.raft_config = raft_config;
  config.signature_intervals = {sig_max_tx, sig_max_ms};
#ifdef DEBUG_CONFIG
  config.debug_config = {memory_reserve_startup};
#endif

  enclave.create_node(config, node_cert, quote, start == "recover");

  LOG_INFO << "Created new node." << std::endl;

  // Write the node cert and quote to disk. Actors can use the node cert
  // as a CA on their end of the TLS connection.
  files::dump(node_cert, node_cert_file);

#ifdef GET_QUOTE
  files::dump(quote, quote_file);

  if (!enclave.verify_quote(quote, node_cert))
    LOG_FATAL << "Verification of local node quote failed" << std::endl;
#endif

  // ledger
  asynchost::Ledger ledger(ledger_file, writer_factory);
  ledger.register_message_handlers(bp.get_dispatcher());

  asynchost::NodeConnections node(
    ledger, writer_factory, raft_hostname, raft_port);
  node.register_message_handlers(bp.get_dispatcher());

  asynchost::NotifyConnections report(
    notify_server_hostname, notify_server_port);
  report.register_message_handlers(bp.get_dispatcher());

  asynchost::RPCConnections rpc(writer_factory);
  rpc.register_message_handlers(bp.get_dispatcher());
  rpc.listen(0, tls_hostname, tls_port);

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
      LOG_FAIL << "Exception in enclave::run: " << e.what() << std::endl;

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
