// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/run.h"

#include "ccf/crypto/pem.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/ds/logger_level.h"
#include "ccf/ds/nonstd.h"
#include "ccf/ds/unit_strings.h"
#include "ccf/ds/x509_time_fmt.h"
#include "ccf/node/startup_config.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/platform.h"
#include "ccf/pal/snp_ioctl.h"
#include "ccf/service/node_info_network.h"
#include "ccf/version.h"
#include "common/configuration.h"
#include "common/enclave_interface_types.h"
#include "config_schema.h"
#include "configuration.h"
#include "crypto/openssl/hash.h"
#include "ds/cli_helper.h"
#include "ds/files.h"
#include "ds/internal_logger.h"
#include "ds/non_blocking.h"
#include "ds/notifying.h"
#include "ds/oversized.h"
#include "enclave/entry_points.h"
#include "handle_ring_buffer.h"
#include "host/env.h"
#include "http/curl.h"
#include "json_schema.h"
#include "lfs_file_handler.h"
#include "load_monitor.h"
#include "node_connections.h"
#include "pal/quote_generation.h"
#include "process_launcher.h"
#include "rpc_connections.h"
#include "sig_term.h"
#include "snapshots/fetch.h"
#include "snapshots/filenames.h"
#include "snapshots/snapshot_manager.h"
#include "tcp.h"
#include "ticker.h"
#include "time_bound_logger.h"
#include "udp.h"

#include <CLI11/CLI11.hpp>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <uv.h>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace fs = std::filesystem;

using namespace std::chrono_literals;

using namespace std::string_literals;
using namespace std::chrono_literals;

using ResolvedAddresses = std::
  map<ccf::NodeInfoNetwork::RpcInterfaceID, ccf::NodeInfoNetwork::NetAddress>;

size_t asynchost::TCPImpl::remaining_read_quota =
  asynchost::TCPImpl::max_read_quota;
bool asynchost::TCPImpl::alloc_quota_logged = false;

size_t asynchost::UDPImpl::remaining_read_quota =
  asynchost::UDPImpl::max_read_quota;

void print_version(int64_t ignored)
{
  (void)ignored;
  std::cout << "CCF host: " << ccf::ccf_version << std::endl;
  std::cout << "Platform: "
            << nlohmann::json(ccf::pal::platform).get<std::string>()
            << std::endl;
  exit(0); // NOLINT(concurrency-mt-unsafe)
}

static constexpr size_t max_time_us = 10'000;
std::chrono::microseconds asynchost::TimeBoundLogger::default_max_time(
  max_time_us);

static constexpr size_t retry_interval_ms = 100;

namespace ccf
{
  void validate_and_adjust_recovery_threshold(host::CCHostConfig& config)
  {
    if (config.command.type != StartType::Start)
    {
      return;
    }

    // Count members with public encryption key as only these members will
    // be handed a recovery share. Note that it is acceptable to start a
    // network without any member having a recovery share. The service will
    // check that at least one recovery member (participant or owner) is
    // added before the service can be opened.
    size_t recovery_participants_count = 0;
    size_t recovery_owners_count = 0;
    for (auto const& member : config.command.start.members)
    {
      if (member.encryption_public_key_file.has_value())
      {
        auto role =
          member.recovery_role.value_or(ccf::MemberRecoveryRole::Participant);
        if (role == ccf::MemberRecoveryRole::Participant)
        {
          recovery_participants_count++;
        }
        else if (role == ccf::MemberRecoveryRole::Owner)
        {
          recovery_owners_count++;
        }
      }
    }

    auto& recovery_threshold =
      config.command.start.service_configuration.recovery_threshold;
    if (recovery_threshold == 0)
    {
      if (recovery_participants_count == 0 && recovery_owners_count != 0)
      {
        LOG_INFO_FMT(
          "Recovery threshold unset. Defaulting to 1 as only consortium "
          "members that are recovery owners ({}) are specified.",
          recovery_owners_count);
        recovery_threshold = 1;
      }
      else
      {
        LOG_INFO_FMT(
          "Recovery threshold unset. Defaulting to number of initial "
          "consortium members with a public encryption key ({}).",
          recovery_participants_count);
        recovery_threshold = recovery_participants_count;
      }
    }
    else
    {
      if (recovery_participants_count == 0 && recovery_owners_count != 0)
      {
        if (recovery_threshold > 1)
        {
          throw std::logic_error(fmt::format(
            "Recovery threshold ({}) cannot be greater than 1 when all "
            "initial consortium members ({}) are of type recovery owner "
            "(specified via --member-info options)",
            recovery_threshold,
            recovery_participants_count));
        }
      }
      else if (recovery_threshold > recovery_participants_count)
      {
        throw std::logic_error(fmt::format(
          "Recovery threshold ({}) cannot be greater than total number ({})"
          "of initial consortium members with a public encryption "
          "key (specified via --member-info options)",
          recovery_threshold,
          recovery_participants_count));
      }
    }
  }

  struct WriterFactories
  {
    ringbuffer::WriterFactory base_factory;
    ringbuffer::NotifyingWriterFactory notifying_factory;
    ringbuffer::NonBlockingWriterFactory non_blocking_factory;
    oversized::WriterFactory writer_factory;

    WriterFactories(
      ringbuffer::Circuit& circuit, const oversized::WriterConfig& config) :
      base_factory(circuit),
      notifying_factory(base_factory),
      non_blocking_factory(notifying_factory),
      writer_factory(non_blocking_factory, config)
    {}
  };

  void setup_rpc_interfaces(
    host::CCHostConfig& config,
    asynchost::RPCConnections<asynchost::TCP>& rpc,
    asynchost::RPCConnections<asynchost::UDP>& rpc_udp)
  {
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
  }

  void configure_snp_attestation(ccf::StartupConfig& startup_config)
  {
    if (ccf::pal::platform != ccf::pal::Platform::SNP)
    {
      return;
    }

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
      if (!startup_config.attestation.environment.security_policy.has_value())
      {
        LOG_FAIL_FMT(
          "Could not read snp_security_policy from {}", security_policy_file);
      }
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
      if (!startup_config.attestation.environment.uvm_endorsements.has_value())
      {
        LOG_FAIL_FMT(
          "Could not read snp_uvm_endorsements from {}",
          snp_uvm_endorsements_file);
      }
    }

    for (auto& server : startup_config.attestation.snp_endorsements_servers)
    {
      auto& url = server.url;
      if (url.has_value())
      {
        LOG_DEBUG_FMT("Resolving snp_endorsements_server url: {}", url.value());
        auto pos = url->find(':');
        if (pos == std::string::npos)
        {
          url = ccf::env::expand_envvar(url.value());
        }
        else
        {
          url = fmt::format(
            "{}:{}",
            ccf::env::expand_envvar(url->substr(0, pos)),
            ccf::env::expand_envvar(url->substr(pos + 1)));
        }
        LOG_DEBUG_FMT("Resolved snp_endorsements_server url: {}", url.value());
      }
    }

    if (startup_config.attestation.snp_endorsements_file.has_value())
    {
      auto snp_endorsements_file =
        startup_config.attestation.snp_endorsements_file.value();
      LOG_DEBUG_FMT(
        "Resolving snp_endorsements_file: {}", snp_endorsements_file);
      snp_endorsements_file =
        ccf::env::expand_envvars_in_path(snp_endorsements_file);
      LOG_DEBUG_FMT(
        "Resolved snp_endorsements_file: {}", snp_endorsements_file);

      startup_config.attestation.environment.snp_endorsements =
        files::try_slurp_string(snp_endorsements_file);

      if (!startup_config.attestation.environment.snp_endorsements.has_value())
      {
        LOG_FAIL_FMT(
          "Could not read snp_endorsements from {}", snp_endorsements_file);
      }
    }
  }

  void populate_config_for_start(
    const host::CCHostConfig& config, ccf::StartupConfig& startup_config)
  {
    for (auto const& member : config.command.start.members)
    {
      std::optional<ccf::crypto::Pem> public_encryption_key = std::nullopt;
      std::optional<ccf::MemberRecoveryRole> recovery_role = std::nullopt;
      if (
        member.encryption_public_key_file.has_value() &&
        !member.encryption_public_key_file.value().empty())
      {
        public_encryption_key = ccf::crypto::Pem(
          files::slurp(member.encryption_public_key_file.value()));
        recovery_role = member.recovery_role;
      }

      nlohmann::json member_data = nullptr;
      if (
        member.data_json_file.has_value() &&
        !member.data_json_file.value().empty())
      {
        member_data =
          nlohmann::json::parse(files::slurp(member.data_json_file.value()));
      }

      startup_config.start.members.emplace_back(
        ccf::crypto::Pem(files::slurp(member.certificate_file)),
        public_encryption_key,
        member_data,
        recovery_role);
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
      config.command.start.service_configuration.recovery_threshold;
    startup_config.initial_service_certificate_validity_days =
      config.command.start.initial_service_certificate_validity_days;
    startup_config.service_subject_name =
      config.command.start.service_subject_name;
    startup_config.cose_signatures = config.command.start.cose_signatures;

    LOG_INFO_FMT(
      "Creating new node: new network (with {} initial member(s) and {} "
      "member(s) required for recovery)",
      config.command.start.members.size(),
      config.command.start.service_configuration.recovery_threshold);
  }

  void populate_config_for_join(
    const host::CCHostConfig& config, ccf::StartupConfig& startup_config)
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

  void populate_config_for_recover(
    const host::CCHostConfig& config, ccf::StartupConfig& startup_config)
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

    if (config.command.recover.previous_sealed_ledger_secret_location
          .has_value())
    {
      CCF_ASSERT_FMT(
        ccf::pal::platform == ccf::pal::Platform::SNP,
        "Local unsealing is only supported on SEV-SNP platforms");
      startup_config.recover.previous_sealed_ledger_secret_location =
        config.command.recover.previous_sealed_ledger_secret_location;
    }
  }

  std::vector<uint8_t> load_startup_snapshot(
    const host::CCHostConfig& config, snapshots::SnapshotManager& snapshots)
  {
    std::vector<uint8_t> startup_snapshot = {};

    if (
      config.command.type != StartType::Join &&
      config.command.type != StartType::Recover)
    {
      return startup_snapshot;
    }

    auto latest_local_snapshot = snapshots.find_latest_committed_snapshot();

    if (
      config.command.type == StartType::Join &&
      config.command.join.fetch_recent_snapshot)
    {
      // Try to fetch a recent snapshot from peer
      auto latest_peer_snapshot = snapshots::fetch_from_peer(
        config.command.join.target_rpc_address,
        config.command.service_certificate_file,
        std::nullopt,
        config.command.join.fetch_snapshot_max_attempts,
        config.command.join.fetch_snapshot_retry_interval.count_ms(),
        config.command.join.fetch_snapshot_max_size.count_bytes());

      if (latest_peer_snapshot.has_value())
      {
        LOG_INFO_FMT(
          "Received snapshot {} from peer (size: {}) - writing this to "
          "disk "
          "and using for join startup",
          latest_peer_snapshot->snapshot_name,
          latest_peer_snapshot->snapshot_data.size());

        const auto dst_path = fs::path(config.snapshots.directory) /
          fs::path(latest_peer_snapshot->snapshot_name);
        if (files::exists(dst_path))
        {
                    LOG_FAIL_FMT(
                "Overwriting existing snapshot at {} with data retrieved from "
                "peer",
                dst_path);
        }
        files::dump(latest_peer_snapshot->snapshot_data, dst_path);
        startup_snapshot = latest_peer_snapshot->snapshot_data;
      }
    }

    if (startup_snapshot.empty() && latest_local_snapshot.has_value())
    {
      auto& [snapshot_dir, snapshot_file] = latest_local_snapshot.value();
      startup_snapshot = files::slurp(snapshot_dir / snapshot_file);

      LOG_INFO_FMT(
        "Found latest local snapshot file: {} (size: {})",
        snapshot_dir / snapshot_file,
        startup_snapshot.size());
    }
    else if (startup_snapshot.empty())
    {
      LOG_INFO_FMT(
        "No snapshot found: Node will replay all historical transactions");
    }

    return startup_snapshot;
  }

  std::optional<size_t> create_enclave_node(
    const host::CCHostConfig& config,
    messaging::BufferProcessor& buffer_processor,
    ringbuffer::Circuit& circuit,
    EnclaveConfig& enclave_config,
    ccf::StartupConfig& startup_config,
    std::vector<uint8_t> startup_snapshot,
    std::vector<uint8_t>& node_cert,
    std::vector<uint8_t>& service_cert,
    ccf::LoggerLevel log_level,
    ringbuffer::NotifyingWriterFactory& notifying_factory)
  {
    LOG_INFO_FMT("Initialising enclave: enclave_create_node");
    std::atomic<bool> ecall_completed = false;
    auto flush_outbound = [&]() {
      do
      {
        std::this_thread::sleep_for(
          std::chrono::milliseconds(retry_interval_ms));

        buffer_processor.read_all(circuit.read_from_inside());
      } while (!ecall_completed);
    };
    std::thread flusher_thread(flush_outbound);
    auto create_status = enclave_create_node(
      enclave_config,
      startup_config,
      std::move(startup_snapshot),
      node_cert,
      service_cert,
      config.command.type,
      log_level,
      config.worker_threads,
      notifying_factory.get_inbound_work_beacon());
    ecall_completed.store(true);
    flusher_thread.join();

    // Reset the thread ID generator. This function will exit before any
    // thread calls enclave_run, and without creating any new threads, so it
    // is safe for the first thread that calls enclave_run to re-use this
    // thread_id. That way they are both considered MAIN_THREAD_ID, even if
    // they are actually distinct std::threads.
    ccf::threading::reset_thread_id_generator();

    if (create_status != CreateNodeStatus::OK)
    {
      LOG_FAIL_FMT(
        "An error occurred when creating CCF node: {}",
        create_node_result_to_str(create_status));

      // Pull all logs from the enclave via BufferProcessor `buffer_processor`
      // and show any logs that came from the ring buffer during setup.
      buffer_processor.read_all(circuit.read_from_inside());

      // This returns from main, stopping the program
      return create_status;
    }

    LOG_INFO_FMT("Created new node");
    return std::nullopt;
  }

  void write_certificates_to_disk(
    const host::CCHostConfig& config,
    const std::vector<uint8_t>& node_cert,
    const std::vector<uint8_t>& service_cert)
  {
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
  }

  void run_enclave_threads(const host::CCHostConfig& config)
  {
    auto enclave_thread_start = [&](threading::ThreadID thread_id) {
      threading::set_current_thread_id(thread_id);
      try
      {
        bool ret = enclave_run();

        if (!ret)
        {
          throw std::logic_error(fmt::format("Failure in enclave_run"));
        }
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Exception in ccf::run: {}", e.what());

        // This exception should be rethrown, probably aborting the process,
        // but we sleep briefly to allow more outbound messages to be
        // processed. If the enclave sent logging messages, it is useful to
        // read and print them before dying.
        std::this_thread::sleep_for(1s);
        throw;
      }
    };

    LOG_INFO_FMT("Starting enclave thread(s)");
    // Start threads which will ECall and process messages inside the enclave
    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < (config.worker_threads + 1); ++i)
    {
      threads.emplace_back(enclave_thread_start, i);
    }

    LOG_INFO_FMT("Entering event loop");
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    LOG_INFO_FMT("Exited event loop");
    for (auto& thread : threads)
    {
      thread.join();
    }
  }

  std::optional<size_t> run_main_loop(
    host::CCHostConfig& config,
    messaging::BufferProcessor& buffer_processor,
    ringbuffer::Circuit& circuit,
    EnclaveConfig& enclave_config,
    ccf::LoggerLevel log_level)
  {
    // Construct hierarchy of ringbuffer writer factories
    WriterFactories factories(circuit, enclave_config.writer_config);
    auto& writer_factory = factories.writer_factory;

    // provide regular ticks to the enclave
    const asynchost::Ticker ticker(config.tick_interval, writer_factory);

    // reset the inbound-TCP processing quota each iteration
    const asynchost::ResetTCPReadQuota reset_tcp_quota;

    // reset the inbound-UDP processing quota each iteration
    const asynchost::ResetUDPReadQuota reset_udp_quota;

    // regularly record some load statistics
    const asynchost::LoadMonitor load_monitor(500ms, buffer_processor);

    // handle outbound logging and admin messages from the enclave
    const asynchost::HandleRingbuffer handle_ringbuffer(
      1ms,
      buffer_processor,
      circuit.read_from_inside(),
      factories.non_blocking_factory);

    // graceful shutdown on sigterm
    asynchost::Sigterm sigterm(writer_factory, config.ignore_first_sigterm);
    // graceful shutdown on sighup
    asynchost::Sighup sighup(writer_factory, false /* never ignore */);

    asynchost::Ledger ledger(
      config.ledger.directory,
      writer_factory,
      asynchost::ledger_max_read_cache_files_default,
      config.ledger.read_only_directories);
    ledger.register_message_handlers(buffer_processor.get_dispatcher());

    snapshots::SnapshotManager snapshots(
      config.snapshots.directory,
      writer_factory,
      config.snapshots.read_only_directory);
    snapshots.register_message_handlers(buffer_processor.get_dispatcher());

    // handle LFS-related messages from the enclave
    asynchost::LFSFileHandler lfs_file_handler(
      writer_factory.create_writer_to_inside());
    lfs_file_handler.register_message_handlers(
      buffer_processor.get_dispatcher());

    // Setup node-to-node connections
    auto [node_host, node_port] =
      cli::validate_address(config.network.node_to_node_interface.bind_address);
    asynchost::NodeConnections node(
      buffer_processor.get_dispatcher(),
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

    asynchost::ConnIDGenerator id_gen;

    asynchost::RPCConnections<asynchost::TCP> rpc(
      1s, // Tick once-per-second to track idle connections,
      writer_factory,
      id_gen,
      config.client_connection_timeout,
      config.idle_connection_timeout);
    rpc->behaviour.register_message_handlers(buffer_processor.get_dispatcher());

    asynchost::RPCConnections<asynchost::UDP> rpc_udp(
      1s,
      writer_factory,
      id_gen,
      config.client_connection_timeout,
      config.idle_connection_timeout);
    rpc_udp->behaviour.register_udp_message_handlers(
      buffer_processor.get_dispatcher());

    // Initialise the curlm singleton
    curl_global_init(CURL_GLOBAL_DEFAULT);
    auto curl_libuv_context =
      curl::CurlmLibuvContextSingleton(uv_default_loop());

    // Setup RPC interfaces
    setup_rpc_interfaces(config, rpc, rpc_udp);

    // Prepare startup configuration
    const size_t certificate_size = 4096;
    std::vector<uint8_t> node_cert(certificate_size);
    std::vector<uint8_t> service_cert(certificate_size);

    ccf::StartupConfig startup_config(config);

    // Configure SNP attestation if on SNP platform
    configure_snp_attestation(startup_config);

    if (ccf::pal::platform == ccf::pal::Platform::Virtual)
    {
      ccf::pal::emit_virtual_measurement();
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
      ccf::ds::to_x509_time_string(startup_host_time);

    if (config.output_files.sealed_ledger_secret_location.has_value())
    {
      CCF_ASSERT_FMT(
        ccf::pal::platform == ccf::pal::Platform::SNP,
        "Local sealing is only supported on SEV-SNP platforms");
      startup_config.network.will_locally_seal_ledger_secrets = true;
      startup_config.sealed_ledger_secret_location =
        config.output_files.sealed_ledger_secret_location;
    }

    // Configure startup based on command type
    if (config.command.type == StartType::Start)
    {
      if (
        files::exists(config.ledger.directory) &&
        !fs::is_empty(config.ledger.directory))
      {
        LOG_FATAL_FMT(
          "On start, ledger directory should not exist or be empty ({})",
          config.ledger.directory);
        return static_cast<int>(CLI::ExitCodes::ValidationError);
      }

      populate_config_for_start(config, startup_config);
    }
    else if (config.command.type == StartType::Join)
    {
      populate_config_for_join(config, startup_config);
    }
    else if (config.command.type == StartType::Recover)
    {
      populate_config_for_recover(config, startup_config);
    }
    else
    {
      LOG_FATAL_FMT("Start command should be start|join|recover. Exiting.");
      return static_cast<int>(CLI::ExitCodes::ValidationError);
    }

    // Load startup snapshot if needed
    auto startup_snapshot = load_startup_snapshot(config, snapshots);

    if (config.network.acme)
    {
      startup_config.network.acme = config.network.acme;
    }
    // Used by GET /node/network/nodes/self to return rpc interfaces
    // prior to the KV being updated
    startup_config.network.rpc_interfaces = config.network.rpc_interfaces;

    // Create the enclave node
    auto enclave_creation_result = create_enclave_node(
      config,
      buffer_processor,
      circuit,
      enclave_config,
      startup_config,
      std::move(startup_snapshot),
      node_cert,
      service_cert,
      log_level,
      factories.notifying_factory);

    if (enclave_creation_result.has_value())
    {
      return enclave_creation_result;
    }

    // Output certificates to disk
    write_certificates_to_disk(config, node_cert, service_cert);

    // Run enclave threads and event loop
    run_enclave_threads(config);

    return std::nullopt;
  }

  int run(int argc, char** argv) // NOLINT(bugprone-exception-escape)
  {
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
      LOG_FAIL_FMT("Failed to ignore SIGPIPE");
      return 1;
    }

    CLI::App app{
      "Run a single CCF node, based on the given configuration file.\n"
      "Some parameters are marked \"(security critical)\" - these must be "
      "passed on the CLI rather than within a configuration file, so that (on "
      "relevant platforms) their value is captured in an attestation even if "
      "the configuration file itself is unattested.\n"};

    std::string config_file_path;
    app
      .add_option(
        "-c,--config", config_file_path, "Path to JSON configuration file")
      ->required();

    ccf::ds::TimeString config_timeout = {"0s"};
    app.add_option(
      "--config-timeout",
      config_timeout,
      "Configuration file read timeout, for example 5s or 1min");

    bool check_config_only = false;
    app.add_flag(
      "--check", check_config_only, "Verify configuration file and exit");

    app.add_flag(
      "-v, --version", print_version, "Display CCF version and exit");

    ccf::LoggerLevel log_level = ccf::LoggerLevel::INFO;
    std::map<std::string, ccf::LoggerLevel> log_level_options;
    for (size_t i = ccf::logger::MOST_VERBOSE;
         i < ccf::LoggerLevel::MAX_LOG_LEVEL;
         ++i)
    {
      const auto level = (ccf::LoggerLevel)i;
      log_level_options[ccf::logger::to_string(level)] = level;
    }

    app
      .add_option(
        "--log-level",
        log_level,
        "Logging level for the node (security critical)")
      ->transform(CLI::CheckedTransformer(log_level_options, CLI::ignore_case));

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
    const auto
      config_timeout_end = // NOLINT(clang-analyzer-deadcode.DeadStores)
                           // line 195
      std::chrono::high_resolution_clock::now() +
      std::chrono::microseconds(config_timeout);
    std::string config_parsing_error;
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
          "Error parsing configuration file {}: {}",
          config_file_path,
          e.what());
        std::this_thread::sleep_for(
          std::chrono::milliseconds(retry_interval_ms));
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

    LOG_INFO_FMT(
      "CLI args: \"{}\"",
      fmt::join(
        argv,
        argv + argc, // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        "\" \""));

    if (check_config_only)
    {
      LOG_INFO_FMT("Configuration file successfully verified");
      return 0;
    }

    LOG_INFO_FMT("Configuration file {}:\n{}", config_file_path, config_str);

    nlohmann::json environment;
    for (int i = 0;
         environ
           [i] != // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
         nullptr;
         i++)
    {
      auto [k, v] = ccf::nonstd::split_1(
        environ[i], // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        "=");
      environment[k] = v;
    }

    LOG_INFO_FMT("Environment: {}\n", environment.dump(2));

    try
    {
      validate_and_adjust_recovery_threshold(config);
    }
    catch (const std::logic_error& e)
    {
      LOG_FATAL_FMT("{}. Exiting.", e.what());
      return static_cast<int>(CLI::ExitCodes::ValidationError);
    }

    const std::filesystem::path pid_file_path{config.output_files.pid_file};
    if (std::filesystem::exists(pid_file_path))
    {
      LOG_FATAL_FMT(
        "PID file {} already exists. Exiting.", pid_file_path.string());
      return static_cast<int>(CLI::ExitCodes::FileError);
    }

    // Write PID to disk
    files::dump(fmt::format("{}", ::getpid()), config.output_files.pid_file);

    // set the host log level
    ccf::logger::config::level() = log_level;

    asynchost::TimeBoundLogger::default_max_time =
      config.slow_io_logging_threshold;

    // create the enclave:

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
    messaging::BufferProcessor buffer_processor("Host");

    // reconstruct oversized messages sent to the host
    const oversized::FragmentReconstructor fragment_reconstructor(
      buffer_processor.get_dispatcher());

    asynchost::ProcessLauncher process_launcher;
    process_launcher.register_message_handlers(
      buffer_processor.get_dispatcher());

    {
      EnclaveConfig enclave_config;
      enclave_config.to_enclave_buffer_start = to_enclave_def.data;
      enclave_config.to_enclave_buffer_size = to_enclave_def.size;
      enclave_config.to_enclave_buffer_offsets = &to_enclave_offsets;
      enclave_config.from_enclave_buffer_start = from_enclave_def.data;
      enclave_config.from_enclave_buffer_size = from_enclave_def.size;
      enclave_config.from_enclave_buffer_offsets = &from_enclave_offsets;

      const oversized::WriterConfig writer_config{
        config.memory.max_fragment_size, config.memory.max_msg_size};
      enclave_config.writer_config = writer_config;

      const auto inner_ret = run_main_loop(
        config, buffer_processor, circuit, enclave_config, log_level);

      if (inner_ret.has_value())
      {
        return inner_ret.value();
      }
    }

    process_launcher.stop();

    constexpr size_t max_close_iterations = 1000;
    size_t close_iterations = max_close_iterations;
    int loop_close_rc = 0;
    while (close_iterations > 0)
    {
      loop_close_rc = uv_loop_close(uv_default_loop());
      if (loop_close_rc != UV_EBUSY)
      {
        break;
      }
      uv_run(uv_default_loop(), UV_RUN_NOWAIT);
      --close_iterations;
      std::this_thread::sleep_for(10ms);
    }
    LOG_INFO_FMT(
      "Ran an extra {} cleanup iteration(s)",
      max_close_iterations - close_iterations);
    if (loop_close_rc != 0)
    {
      LOG_FAIL_FMT(
        "Failed to close uv loop cleanly: {}", uv_err_name(loop_close_rc));
      // walk loop to diagnose unclosed handles
      auto cb = [](uv_handle_t* handle, void* arg) {
        (void)arg;
        LOG_FAIL_FMT(
          "Leaked handle: type={}, ptr={}",
          uv_handle_type_name(handle->type),
          fmt::ptr(handle));
      };
      uv_walk(uv_default_loop(), cb, nullptr);
    }
    curl_global_cleanup();

    return loop_close_rc;
  }
}
