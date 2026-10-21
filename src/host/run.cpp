// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/run.h"

#include "ccf/crypto/pem.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/ds/logger_level.h"
#include "ccf/ds/nonstd.h"
#include "ccf/ds/unit_strings.h"
#include "ccf/node/configuration.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/platform.h"
#include "ccf/pal/snp_ioctl.h"
#include "ccf/service/node_info_network.h"
#include "ccf/version.h"
#include "common/cli_helper.h"
#include "common/configuration.h"
#include "common/create_node_status.h"
#include "config_schema.h"
#include "consensus/ledger_enclave_types.h"
#include "crypto/openssl/hash.h"
#include "ds/files.h"
#include "ds/internal_logger.h"
#include "ds/time_bound_logger.h"
#include "enclave/enclave.h"
#include "host/files_cleanup_timer.h"
#include "host/ledger_subsystem.h"
#include "http_client/curl.h"
#include "json_schema.h"
#include "node_connections.h"
#include "pal/quote_generation.h"
#include "runtime_control.h"
#include "sig_term.h"
#include "task_ticker.h"
#include "tcp.h"
#include "tracing/fluentd_sink.h"

#include <CLI11/CLI11.hpp>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <latch>
#include <map>
#include <memory>
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

void print_version(int64_t ignored)
{
  (void)ignored;
  std::cout << "CCF host: " << ccf::ccf_version << std::endl;
  std::cout << "Platform: "
            << nlohmann::json(ccf::pal::platform).get<std::string>()
            << std::endl;
  exit(0); // NOLINT(concurrency-mt-unsafe)
}

static constexpr size_t retry_interval_ms = 100;

namespace ccf
{
  void validate_ledger_transaction_size(const ccf::CCFConfig& config)
  {
    const auto max_read_size = config.get_max_ledger_read_size();
    const auto max_transaction_size =
      config.ledger.max_transaction_size.count_bytes();
    if (max_read_size == 0 || max_transaction_size > max_read_size)
    {
      throw std::logic_error(fmt::format(
        "ledger.max_read_size ({}) must be nonzero and at least "
        "ledger.max_transaction_size ({}) so a single ledger entry fits in a "
        "ledger range read",
        max_read_size,
        max_transaction_size));
    }
  }

  void validate_and_coerce_worker_threads(ccf::CCFConfig& config)
  {
    // Replace the task execution capacity of the coordination thread, which no
    // longer executes tasks itself, without requiring configuration changes.
    if (config.worker_threads == 0)
    {
      LOG_FAIL_FMT(
        "worker_threads is configured as 0; using 1 (the enforced minimum) "
        "instead");
    }
    ++config.worker_threads;
  }

  void validate_and_adjust_recovery_threshold(ccf::CCFConfig& config)
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

  void write_certificates_to_disk(
    const ccf::CCFConfig& config,
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

  void run_enclave_threads(const ccf::CCFConfig& config, Enclave& enclave)
  {
    const auto thread_count = config.worker_threads + 1;
    std::latch ready(thread_count);
    std::atomic<bool> cancelled = false;
    // Startup ran on the launcher thread. Runtime threads reuse its main ID.
    ccf::threading::reset_thread_id_generator();
    auto enclave_thread_start = [&](threading::ThreadID thread_id) {
      threading::set_current_thread_id(thread_id);
      ready.arrive_and_wait();
      if (cancelled.load())
      {
        return;
      }
      ccf::tracing::FluentdSink::bind_producer(thread_id);
      try
      {
        LOG_INFO_FMT("Starting thread: {}", thread_id);
        const bool ret = thread_id == threading::MAIN_THREAD_ID ?
          enclave.run_main() :
          enclave.run_worker();

        if (!ret)
        {
          throw std::logic_error("Failure in enclave runtime thread");
        }
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Exception in ccf::run: {}", e.what());

        throw;
      }
    };

    LOG_INFO_FMT("Starting enclave thread(s)");
    std::vector<std::jthread> threads;
    threads.reserve(thread_count);
    try
    {
      for (uint32_t i = 0; i < thread_count; ++i)
      {
        threads.emplace_back(enclave_thread_start, i);
      }
    }
    catch (...)
    {
      cancelled.store(true);
      ready.count_down(thread_count - threads.size());
      throw;
    }

    LOG_INFO_FMT("Entering event loop");
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    LOG_INFO_FMT("Exited event loop");
    for (auto& thread : threads)
    {
      thread.join();
    }
  }

  std::optional<size_t> run_main_loop(ccf::CCFConfig& config)
  {
    const asynchost::TaskTicker task_ticker(config.tick_interval);

    std::unique_ptr<Enclave> enclave;
    const auto request_enclave_stop = [&enclave]() {
      if (enclave == nullptr)
      {
        return false;
      }
      enclave->request_stop();
      return true;
    };
    asynchost::RuntimeControl runtime_control(request_enclave_stop);

    // Register before startup, but libuv delivers signals only when the loop
    // runs. This preserves signals received during initialization.
    const auto request_node_shutdown = [&request_enclave_stop]() {
      if (!request_enclave_stop())
      {
        LOG_FAIL_FMT("Cannot request node shutdown before it has been created");
      }
    };
    const auto notify_node_stopping = [&enclave]() {
      if (enclave == nullptr)
      {
        LOG_FAIL_FMT(
          "Cannot notify node of stopping before it has been created");
        return;
      }
      enclave->request_stop_notice();
    };
    asynchost::Sigterm sigterm(
      config.ignore_first_sigterm, request_node_shutdown, notify_node_stopping);
    asynchost::Sighup sighup(
      false, request_node_shutdown, notify_node_stopping);

    // reset the inbound-TCP processing quota each iteration
    const asynchost::ResetTCPReadQuota reset_tcp_quota;

    asynchost::Ledger ledger(
      config.ledger.directory,
      asynchost::ledger_max_read_cache_files_default,
      config.ledger.read_only_directories);

    // Typed ledger access for the enclave. Only valid while the ledger above
    // is alive, and shut down before it is destroyed.
    auto ledger_subsystem = std::make_shared<asynchost::LedgerSubsystem>(
      ledger,
      config.get_max_ledger_read_size(),
      ccf::tasks::get_main_job_board(),
      config.get_max_pending_append_bytes());

    if (config.snapshots.read_only_directory.has_value())
    {
      LOG_INFO_FMT(
        "snapshots.read_only_directory is deprecated and will be removed in a "
        "future release");
    }
    std::optional<asynchost::FilesCleanupTimer> files_cleanup;
    if (
      (config.files_cleanup.max_snapshots.has_value() ||
       config.files_cleanup.max_committed_ledger_chunks.has_value()) &&
      std::chrono::milliseconds(config.files_cleanup.interval) >
        std::chrono::milliseconds::zero())
    {
      files_cleanup.emplace(
        std::chrono::milliseconds(config.files_cleanup.interval),
        config.snapshots.directory,
        config.files_cleanup.max_snapshots,
        config.ledger.directory,
        config.ledger.read_only_directories,
        config.files_cleanup.max_committed_ledger_chunks);
    }

    // Setup node-to-node connections, which the node uses as its typed
    // transport. Outbound messages are ordered behind the ledger mutations
    // submitted before them, then written on the loop thread by a 1ms flush
    // timer. Inbound frames use the configured maximum message size.
    auto [node_host, node_port] =
      cli::validate_address(config.network.node_to_node_interface.bind_address);
    auto node = std::make_shared<asynchost::NodeConnections>(
      ledger,
      *ledger_subsystem,
      node_host,
      node_port,
      config.get_node_to_node_max_message_size(),
      config.node_client_interface,
      config.client_connection_timeout);
    const asynchost::FlushNodeOutbound flush_node_outbound(1ms, *node);
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

    // Initialise the curlm singleton
    if (const auto curl_rc = curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_rc != CURLE_OK)
    {
      throw std::logic_error(fmt::format(
        "Failed to initialise libcurl: {}", curl_easy_strerror(curl_rc)));
    }
    std::optional<http_client::CurlmLibuvContextSingleton> curl_libuv_context(
      std::in_place, uv_default_loop());

    // Validate and normalise the configured RPC addresses here, at the input
    // boundary, so that everything downstream sees a well-formed "host:port"
    // with a port in range. ccf::split_net_address, used to bind them, is
    // deliberately lenient and does no validation of its own.
    for (auto& [name, interface] : config.network.rpc_interfaces)
    {
      try
      {
        const auto [rpc_host, rpc_port] =
          cli::validate_address(interface.bind_address);
        interface.bind_address = ccf::make_net_address(rpc_host, rpc_port);

        if (!interface.published_address.empty())
        {
          const auto [pub_host, pub_port] =
            cli::validate_address(interface.published_address);
          interface.published_address =
            ccf::make_net_address(pub_host, pub_port);
        }
      }
      catch (const std::exception& e)
      {
        LOG_FATAL_FMT(
          "Invalid address for RPC interface {}: {}. Exiting.", name, e.what());
        return static_cast<int>(CLI::ExitCodes::ValidationError);
      }
    }

    if (ccf::pal::platform == ccf::pal::Platform::Virtual)
    {
      ccf::pal::emit_virtual_measurement();
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

      for (const auto& readonly_ledger_directory :
           config.ledger.read_only_directories)
      {
        if (
          files::exists(readonly_ledger_directory) &&
          !fs::is_empty(readonly_ledger_directory))
        {
          LOG_FATAL_FMT(
            "On start, read-only ledger directories should not exist or be "
            "empty ({})",
            readonly_ledger_directory);
          return static_cast<int>(CLI::ExitCodes::ValidationError);
        }
      }
    }
    else if (
      config.command.type != StartType::Join &&
      config.command.type != StartType::Recover)
    {
      LOG_FATAL_FMT("Start command should be start|join|recover. Exiting.");
      return static_cast<int>(CLI::ExitCodes::ValidationError);
    }

    if (
      config.command.type == StartType::Start &&
      config.command.start.service_configuration.reconfiguration_type.value_or(
        ccf::ReconfigurationType::ONE_TRANSACTION) !=
        ccf::ReconfigurationType::ONE_TRANSACTION)
    {
      LOG_FAIL_FMT(
        "2TX reconfiguration is experimental, disabled in release mode");
      return CreateNodeStatus::ReconfigurationMethodNotSupported;
    }

    ccf::tracing::FluentdSink::configure(
      config.observability.fluentd, config.worker_threads + 2);
    ccf::tracing::FluentdSink::bind_producer(config.worker_threads + 1);
    ccf::tracing::FluentdSink::Lifetime trace_lifetime;

    // The stop callback's owner must outlive RuntimeControl, but the runtime
    // itself must be destroyed before its host dependencies.
    struct RuntimeCleanup
    {
      std::unique_ptr<Enclave>& enclave;
      asynchost::NodeConnections& transport;
      std::optional<http_client::CurlmLibuvContextSingleton>& curl_context;
      asynchost::Sigterm& sigterm;
      asynchost::Sighup& sighup;

      ~RuntimeCleanup()
      {
        sigterm = nullptr;
        sighup = nullptr;
        // Curl cancellation invokes callbacks borrowing NodeState.
        if (enclave != nullptr)
        {
          enclave->request_stop();
        }
        curl_context.reset();
        enclave.reset();
        transport.shutdown();
      }
    } cleanup{enclave, *node, curl_libuv_context, sigterm, sighup};

    auto failure_status = CreateNodeStatus::EnclaveInitFailed;
    try
    {
      enclave = std::make_unique<Enclave>(
        config, *runtime_control, ledger_subsystem, node);
      failure_status = CreateNodeStatus::InternalError;
      const auto startup = enclave->initialise(config);
      LOG_INFO_FMT("Created new node");
      if (!config.output_files.rpc_addresses_file.empty())
      {
        files::dump(
          startup.rpc_addresses, config.output_files.rpc_addresses_file);
      }
      write_certificates_to_disk(
        config, startup.node_cert, startup.service_cert);
    }
    catch (const std::exception& e)
    {
      // Startup diagnostics are safe here: no runtime thread has executed,
      // and locally generated secrets will be discarded.
      LOG_FAIL_FMT("Error starting node: {}", e.what());
      return failure_status;
    }

    run_enclave_threads(config, *enclave);
    runtime_control->throw_if_fatal_error();

    return std::nullopt;
  }

  void apply_stdlib_workarounds()
  {
    // A data race happens in the libstdc++ implementation of ctype::narrow.
    // See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=77704
    // This workaround is from the mailing list - avoid unprotected lazy
    // initialisation by eagerly initialising every value now.
#if defined(__GLIBCXX__)
    {
      const auto& ct(std::use_facet<std::ctype<char>>(std::locale()));

      for (size_t i(0); i != 256; ++i)
      {
        ct.narrow(static_cast<char>(i), '\0');
      }
    }
#endif
  }

  int run(int argc, char** argv) // NOLINT(bugprone-exception-escape)
  {
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
      LOG_FAIL_FMT("Failed to ignore SIGPIPE");
      return 1;
    }

    apply_stdlib_workarounds();

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
    for (auto i = static_cast<uint8_t>(ccf::logger::MOST_VERBOSE);
         i < static_cast<uint8_t>(ccf::LoggerLevel::MAX_LOG_LEVEL);
         ++i)
    {
      const auto level = static_cast<ccf::LoggerLevel>(i);
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

    ccf::CCFConfig config = config_json;

    if (config.logging.format == ccf::LogFormat::JSON)
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

    // Validate before --check returns, not just when starting the node.
    try
    {
      validate_ledger_transaction_size(config);
      if (config.observability.fluentd)
      {
        ccf::tracing::FluentdSink::validate(
          *config.observability.fluentd, config.worker_threads + 3);
      }
      const auto pending_node_timeout =
        std::chrono::microseconds(config.pending_node_timeout);
      if (
        pending_node_timeout > std::chrono::microseconds::zero() &&
        pending_node_timeout < std::chrono::milliseconds(1))
      {
        throw std::logic_error(
          "pending_node_timeout must be 0s or at least 1ms");
      }
    }
    catch (const std::logic_error& e)
    {
      LOG_FATAL_FMT("{}. Exiting.", e.what());
      return static_cast<int>(CLI::ExitCodes::ValidationError);
    }

    // Coerces rather than rejects, so no try/catch is needed here.
    validate_and_coerce_worker_threads(config);

    if (config_json.contains("memory"))
    {
      const auto& memory = config_json.at("memory");
      if (memory.contains("circuit_size"))
      {
        LOG_INFO_FMT(
          "memory.circuit_size is deprecated and will be removed in 8.0; use "
          "ledger.max_pending_append_bytes instead. The legacy value is {}.",
          config.ledger.max_pending_append_bytes.has_value() ? "ignored" :
                                                               "used");
      }
      if (memory.contains("max_msg_size"))
      {
        LOG_INFO_FMT(
          "memory.max_msg_size is deprecated and will be removed in 8.0; use "
          "ledger.max_read_size and node_to_node.max_message_size instead. "
          "The legacy value is {} for ledger.max_read_size and {} for "
          "node_to_node.max_message_size.",
          config.ledger.max_read_size.has_value() ? "ignored" : "used",
          config.node_to_node.max_message_size.has_value() ? "ignored" :
                                                             "used");
      }
      if (memory.contains("max_fragment_size"))
      {
        LOG_INFO_FMT(
          "memory.max_fragment_size is deprecated and ignored; remove it "
          "from the configuration. It will be removed in 8.0.");
      }
    }

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

    ccf::ds::TimeBoundLogger::default_max_time =
      config.slow_io_logging_threshold;

    std::optional<int> inner_ret;
    try
    {
      inner_ret = run_main_loop(config);
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Exception in ccf::run: {}", e.what());
      inner_ret = CreateNodeStatus::InternalError;
    }

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

    return inner_ret.value_or(loop_close_rc);
  }
}
