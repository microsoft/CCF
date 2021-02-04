// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Local
#include "timing.h"

// CCF
#include "clients/rpc_tls_client.h"
#include "ds/cli_helper.h"
#include "ds/files.h"
#include "ds/logger.h"

// STL/3rdparty
#include <CLI11/CLI11.hpp>
#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>
#include <random>
#include <thread>
#include <unistd.h>

namespace client
{
  constexpr auto perf_summary = "perf_summary.csv";

  bool pin_to_core(int core_id)
  {
    int threads = std::thread::hardware_concurrency();
    if (core_id > threads || core_id < 0)
    {
      LOG_FATAL_FMT("Invalid core id: {}", core_id);
      return false;
    }

    cpu_set_t set;
    LOG_INFO_FMT("Pinning to core: {}", core_id);
    CPU_ZERO(&set);
    CPU_SET(core_id, &set);

    if (sched_setaffinity(0, sizeof(cpu_set_t), &set) < 0)
    {
      LOG_FATAL_FMT("Unable to set affinity");
      return false;
    }

    return true;
  }

  struct PerfOptions
  {
    /// Options set from command line
    ///@{
    std::string label; //< Default set in constructor
    std::string pid_file; //< Default set in constructor

    cli::ParsedAddress server_address;
    std::string cert_file, key_file, ca_file, verification_file, bearer_token;

    size_t num_transactions = 10000;
    size_t thread_count = 1;
    size_t session_count = 1;
    size_t max_writes_ahead = 0;
    size_t latency_rounds = 1;
    size_t generator_seed = 42u;
    size_t transactions_per_s = 0;

    bool sign = false;
    bool no_create = false;
    bool no_wait = false;
    bool write_tx_times = false;
    bool randomise = false;
    bool check_responses = false;
    bool relax_commit_target = false;
    bool websockets = false;
    ///@}

    PerfOptions(
      const std::string& default_label,
      const std::string& default_pid_file,
      CLI::App& app) :
      label(default_label),
      pid_file(fmt::format("{}.pid", default_pid_file))
    {
      // Enable config from file
      app.set_config("--config");

      app
        .add_option(
          "--label",
          label,
          fmt::format(
            "Identifier for this client, written to {}", perf_summary))
        ->capture_default_str();

      app
        .add_option(
          "--pid-file",
          pid_file,
          "Path to which the client PID will be written")
        ->capture_default_str();

      // Connection details
      cli::add_address_option(
        app,
        server_address,
        "--rpc-address",
        "Remote node JSON RPC address to which requests should be sent")
        ->required(true);

      app.add_option("--cert", cert_file)
        ->required(true)
        ->check(CLI::ExistingFile);
      app.add_option("--pk", key_file)
        ->required(true)
        ->check(CLI::ExistingFile);
      app.add_option("--ca", ca_file)->required(true)->check(CLI::ExistingFile);
      app.add_option("--bearer-token", bearer_token)->required(false);

      app
        .add_option(
          "--verify",
          verification_file,
          "Verify results against expectation, specified in file")
        ->required(false)
        ->check(CLI::ExistingFile);
      app.add_option("--generator-seed", generator_seed);

      app.add_option(
        "--transaction-rate",
        transactions_per_s,
        "The number of transactions per second to send");

      // Transaction counts and batching details
      app
        .add_option(
          "--transactions",
          num_transactions,
          "The basic number of transactions to send (will actually send this "
          "many for each thread, in each session)")
        ->capture_default_str();
      app.add_option("-t,--threads", thread_count)->capture_default_str();
      app.add_option("-s,--sessions", session_count)->capture_default_str();
      app
        .add_option(
          "--max-writes-ahead",
          max_writes_ahead,
          "How many transactions the client should send without waiting for "
          "responses. 0 will send all transactions before blocking for any "
          "responses, 1 will minimise latency by serially waiting for each "
          "transaction's response, other values may provide a balance between "
          "throughput and latency")
        ->capture_default_str();

      app.add_option("--latency-rounds", latency_rounds)->capture_default_str();

      // Boolean flags
      app.add_flag("--sign", sign, "Send client-signed transactions")
        ->capture_default_str();
      app
        .add_flag("--no-create", no_create, "Skip creation/setup transactions")
        ->capture_default_str();
      app
        .add_flag(
          "--no-wait",
          no_wait,
          "Don't wait for transactions to be globally committed")
        ->capture_default_str();
      app
        .add_flag(
          "--write-tx-times",
          write_tx_times,
          "Write tx sent and received times to csv")
        ->capture_default_str();
      app
        .add_flag(
          "--randomise",
          randomise,
          "Use non-deterministically random transaction contents each run")
        ->capture_default_str();
      app
        .add_flag(
          "--check-responses",
          check_responses,
          "Check every JSON response for errors. Potentially slow")
        ->capture_default_str();
      app
        .add_flag(
          "--use-websockets", websockets, "Use websockets to send transactions")
        ->capture_default_str();
    }
  };

  /** Base class for perf-testing clients. Provides hooks to set initial state,
   * prepare a batch of transactions, and then measure the latency and
   * throughput of processing those batched transactions */
  template <typename TOptions>
  class PerfBase
  {
  protected:
    struct PreparedTx
    {
      RpcTlsClient::PreparedRpc rpc;
      std::string method;
      bool expects_commit;
    };

  private:
    tls::Pem key = {};
    std::string key_id = "Invalid";
    std::shared_ptr<tls::Cert> tls_cert = nullptr;

    // Process reply to an RPC. Records time reply was received. Calls
    // check_response for derived-overridable validation
    void process_reply(const RpcTlsClient::Response& reply)
    {
      if (options.check_responses)
      {
        if (!check_response(reply))
        {
          throw std::logic_error("Response failed check");
        }
      }

      if (response_times.is_timing_active() && reply.status == HTTP_STATUS_OK)
      {
        const auto tx_id = timing::extract_transaction_id(reply);

        if (!tx_id.has_value())
        {
          throw std::logic_error("No transaction ID found in response headers");
        }

        // Record time of received responses
        response_times.record_receive(reply.id, tx_id);

        if (tx_id->view < last_response_tx_id.view)
        {
          throw std::logic_error(fmt::format(
            "View went backwards (expected {}, saw {})!",
            last_response_tx_id.view,
            tx_id->view));
        }
        else if (
          tx_id->view > last_response_tx_id.view &&
          tx_id->seqno <= last_response_tx_id.seqno)
        {
          throw std::logic_error(fmt::format(
            "There has been an election and transactions have "
            "been lost! (saw {}.{}, currently at {}.{})",
            last_response_tx_id.view,
            last_response_tx_id.seqno,
            tx_id->view,
            tx_id->seqno));
        }

        last_response_tx_id = tx_id.value();
      }
    }

    void append_prepared_tx(
      const PreparedTx& tx, const std::optional<size_t>& index)
    {
      if (index.has_value())
      {
        assert(index.value() < prepared_txs.size());
        prepared_txs[index.value()] = tx;
      }
      else
      {
        prepared_txs.push_back(tx);
      }
    }

  protected:
    TOptions options;

    std::mt19937 rand_generator;

    nlohmann::json verification_target;

    using PreparedTxs = std::vector<PreparedTx>;

    std::shared_ptr<RpcTlsClient> rpc_connection;
    PreparedTxs prepared_txs;

    timing::ResponseTimes response_times;
    timing::TransactionID last_response_tx_id = {0, 0};

    std::chrono::high_resolution_clock::time_point last_write_time;
    std::chrono::nanoseconds write_delay_ns = std::chrono::nanoseconds::zero();

    std::shared_ptr<RpcTlsClient> create_connection(
      bool force_unsigned = false, bool upgrade = false)
    {
      // Create a cert if this is our first rpc_connection
      const bool is_first_time = tls_cert == nullptr;

      if (is_first_time)
      {
        const auto raw_cert = files::slurp(options.cert_file);
        const auto raw_key = files::slurp(options.key_file);
        const auto ca = files::slurp(options.ca_file);

        key = tls::Pem(raw_key);

        crypto::Sha256Hash hash({raw_cert.data(), raw_cert.size()});
        key_id = fmt::format("{:02x}", fmt::join(hash.h, ""));

        tls_cert = std::make_shared<tls::Cert>(
          std::make_shared<tls::CA>(ca), raw_cert, key);
      }

      auto conn = std::make_shared<RpcTlsClient>(
        options.server_address.hostname,
        options.server_address.port,
        nullptr,
        tls_cert,
        key_id);

      if (options.sign && !force_unsigned)
      {
        LOG_INFO_FMT("Creating key pair");
        conn->create_key_pair(key);
      }

      conn->set_prefix("app");

      // Report ciphersuite of first client (assume it is the same for each)
      if (is_first_time)
      {
        LOG_DEBUG_FMT(
          "Connected to server via TLS ({})", conn->get_ciphersuite_name());
      }

      if (upgrade)
        conn->upgrade_to_ws();

      return conn;
    }

    void add_prepared_tx(
      const std::string& method,
      const CBuffer params,
      bool expects_commit,
      const std::optional<size_t>& index)
    {
      const PreparedTx tx{rpc_connection->gen_request(
                            method,
                            params,
                            http::headervalues::contenttype::JSON,
                            HTTP_POST,
                            options.bearer_token.size() == 0 ?
                              nullptr :
                              options.bearer_token.c_str()),
                          method,
                          expects_commit};

      append_prepared_tx(tx, index);
    }

    void add_prepared_tx(
      const std::string& method,
      const nlohmann::json& params,
      bool expects_commit,
      const std::optional<size_t>& index,
      const serdes::Pack& serdes)
    {
      auto body = serdes::pack(params, serdes);

      const PreparedTx tx{rpc_connection->gen_request(
                            method,
                            body,
                            serdes == serdes::Pack::Text ?
                              http::headervalues::contenttype::JSON :
                              http::headervalues::contenttype::MSGPACK,
                            HTTP_POST,
                            options.bearer_token.size() == 0 ?
                              nullptr :
                              options.bearer_token.c_str()),
                          method,
                          expects_commit};

      append_prepared_tx(tx, index);
    }

    void add_prepared_tx(
      const std::string& method,
      const nlohmann::json& params,
      bool expects_commit,
      const std::optional<size_t>& index)
    {
      const PreparedTx tx{
        rpc_connection->gen_request(method, params), method, expects_commit};
      append_prepared_tx(tx, index);
    }

    static size_t total_byte_size(const PreparedTxs& txs)
    {
      return std::accumulate(
        txs.begin(), txs.end(), 0, [](size_t n, const PreparedTx& tx) {
          return n + tx.rpc.encoded.size();
        });
    }

    // Everything else has empty stubs and can optionally be overridden. This
    // must be provided by derived class
    virtual void prepare_transactions() = 0;

    virtual std::optional<RpcTlsClient::Response> send_creation_transactions()
    {
      return std::nullopt;
    }

    virtual bool check_response(const RpcTlsClient::Response& r)
    {
      // Default behaviour is to accept anything that doesn't contain an error
      return r.status == HTTP_STATUS_OK;
    }

    virtual void pre_creation_hook(){};
    virtual void post_creation_hook(){};

    virtual void pre_timing_body_hook(){};
    virtual void post_timing_body_hook(){};

    virtual timing::Results call_raw_batch(
      std::shared_ptr<RpcTlsClient>& connection, const PreparedTxs& txs)
    {
      size_t read;
      size_t written;

      if (options.transactions_per_s > 0)
      {
        write_delay_ns =
          std::chrono::nanoseconds{1000000000 / options.transactions_per_s};
        connection->set_tcp_nodelay(true);
      }

      last_write_time = std::chrono::high_resolution_clock::now();
      kick_off_timing();

      // Repeat for each session
      for (size_t session = 1; session <= options.session_count; ++session)
      {
        read = 0;
        written = 0;

        // Write everything
        while (written < txs.size())
          write(txs[written], read, written, connection);

        blocking_read(read, written, connection);

        // Reconnect for each session (except the last)
        if (session != options.session_count)
        {
          reconnect(connection);
        }
      }

      if (!options.no_wait)
      {
        // Create a new connection, because we need to do some GETs
        // and when all you have is a WebSocket, everything looks like a POST!
        auto c = create_connection(true, false);
        wait_for_global_commit(last_response_tx_id);
      }
      const auto last_commit = last_response_tx_id.seqno;
      auto timing_results = end_timing(last_commit);
      LOG_INFO_FMT("Timing ended");
      return timing_results;
    }

    void kick_off_timing()
    {
      LOG_INFO_FMT("About to begin timing");
      begin_timing();
      LOG_INFO_FMT("Began timing");
    }

    inline void write(
      const PreparedTx& tx,
      size_t& read,
      size_t& written,
      const std::shared_ptr<RpcTlsClient>& connection)
    {
      while (std::chrono::high_resolution_clock::now() - last_write_time <
             write_delay_ns)
      {
        continue;
      }

      // Record time of sent requests
      if (response_times.is_timing_active())
      {
        response_times.record_send(tx.method, tx.rpc.id, tx.expects_commit);
      }

      connection->write(tx.rpc.encoded);
      last_write_time = std::chrono::high_resolution_clock::now();

      ++written;

      // Optimistically read (non-blocking) any current responses
      while (read < written)
      {
        const auto r = connection->read_response_non_blocking();
        if (!r.has_value())
        {
          // If we have no responses waiting, move on to the next thing
          break;
        }

        process_reply(r.value());
        ++read;
      }

      // Do blocking reads if we're beyond our write-ahead limit
      if (options.max_writes_ahead > 0) // 0 is a special value allowing
                                        // unlimited write-ahead
      {
        while (written - read >= options.max_writes_ahead)
        {
          process_reply(connection->read_response());
          ++read;
        }
      }
    }

    void blocking_read(
      size_t& read,
      size_t written,
      const std::shared_ptr<RpcTlsClient>& connection)
    {
      // Read response (blocking) for all pending txs
      while (read < written)
      {
        process_reply(connection->read_response());
        ++read;
      }
    }

    void reconnect(std::shared_ptr<RpcTlsClient>& connection)
    {
      connection.reset(new RpcTlsClient(*connection.get()));
    }

    RpcTlsClient::Response get_tx_status(
      const std::shared_ptr<RpcTlsClient>& connection,
      size_t view,
      size_t seqno)
    {
      nlohmann::json p;
      p["seqno"] = seqno;
      p["view"] = view;
      return connection->get("tx", p);
    }

    virtual void verify_params(const nlohmann::json& expected)
    {
      // It's only reasonable to compare against expected state if the initial
      // parameters match, so check a few obvious ones

      {
        const auto it = expected.find("seed");
        if (it != expected.end())
        {
          const auto expected_seed =
            it->get<decltype(options.generator_seed)>();
          if (expected_seed != options.generator_seed)
          {
            throw std::runtime_error(fmt::format(
              "Verification file expects seed {}, but currently using {}",
              expected_seed,
              options.generator_seed));
          }
        }
      }

      {
        const auto it = expected.find("transactions");
        if (it != expected.end())
        {
          const auto expected_txs =
            it->get<decltype(options.num_transactions)>();
          if (expected_txs != options.num_transactions)
          {
            throw std::runtime_error(fmt::format(
              "Verification file is only applicable for {} transactions, but "
              "currently running {}",
              expected_txs,
              options.num_transactions));
          }
        }
      }

      {
        const auto it = expected.find("sessions");
        if (it != expected.end())
        {
          const auto expected_sessions =
            it->get<decltype(options.session_count)>();
          if (expected_sessions != options.session_count)
          {
            throw std::runtime_error(fmt::format(
              "Verification file is only applicable for {} sessions, but "
              "currently running {}",
              expected_sessions,
              options.session_count));
          }
        }
      }

      {
        bool expected_randomise = false;
        const auto it = expected.find("randomise");
        if (it != expected.end())
        {
          expected_randomise = it->get<bool>();
        }

        if (expected_randomise != options.randomise)
        {
          throw std::runtime_error(fmt::format(
            "Verification file is only applicable when randomisation is {}, "
            "but this option is currently {}",
            expected_randomise ? "ON" : "OFF",
            options.randomise ? "ON" : "OFF"));
        }
      }
    }
    virtual void verify_initial_state(const nlohmann::json& expected) {}
    virtual void verify_final_state(const nlohmann::json& expected) {}

  public:
    PerfBase(const TOptions& o) :
      options(o),
      rand_generator(),
      // timing gets its own new connection for any requests it wants to send -
      // these are never signed
      response_times(create_connection(true, false))
    {}

    void init_connection()
    {
      // Make sure the connection we're about to use has been initialised
      if (!rpc_connection)
      {
        rpc_connection = create_connection(false, options.websockets);
      }
    }

    std::shared_ptr<RpcTlsClient> get_connection()
    {
      init_connection();
      return rpc_connection;
    }

    void send_all_creation_transactions()
    {
      if (!options.no_create)
      {
        try
        {
          const auto last_response = send_creation_transactions();

          if (
            last_response.has_value() &&
            http::status_success(last_response->status))
          {
            // Ensure creation transactions are globally committed before
            // proceeding
            wait_for_global_commit(last_response.value());
          }
        }
        catch (std::exception& e)
        {
          LOG_FAIL_FMT("Exception during creation steps: {}", e.what());
          throw e;
        }
      }
    }

    void prepare_all_transactions()
    {
      init_connection();
      try
      {
        prepare_transactions();
      }
      catch (std::exception& e)
      {
        LOG_FAIL_FMT("Preparation exception: {}", e.what());
        throw e;
      }
    }

    timing::Results send_all_prepared_transactions()
    {
      init_connection();
      try
      {
        // ...send any transactions which were previously prepared
        return call_raw_batch(rpc_connection, prepared_txs);
      }
      catch (std::exception& e)
      {
        LOG_FAIL_FMT("Transaction exception: {}", e.what());
        throw e;
      }
    }

    void wait_for_global_commit(const timing::TransactionID& target)
    {
      response_times.wait_for_global_commit(target);
    }

    void wait_for_global_commit(const RpcTlsClient::Response& response)
    {
      check_response(response);

      const auto tx_id = timing::extract_transaction_id(response);
      if (!tx_id.has_value())
      {
        throw std::logic_error(
          "Cannot wait for response to commit - it does not have a TxID");
      }

      wait_for_global_commit(tx_id.value());
    }

    void begin_timing()
    {
      if (response_times.is_timing_active())
      {
        throw std::logic_error(
          "timing is already set - has begin_timing been called multiple "
          "times?");
      }

      response_times.start_timing();
    }

    timing::Results end_timing(size_t end_highest_local_commit)
    {
      if (!response_times.is_timing_active())
      {
        throw std::logic_error(
          "timing is not set - has begin_timing not been called?");
      }

      timing::Results results;
      try
      {
        results = response_times.produce_results(
          options.no_wait, end_highest_local_commit, options.latency_rounds);
      }
      catch (const std::runtime_error& e)
      {
        response_times.write_to_file(options.label);
        throw;
      }

      if (options.write_tx_times)
      {
        response_times.write_to_file(options.label);
      }

      response_times.stop_timing();

      return results;
    }

    void summarize_results(const timing::Results& timing_results)
    {
      using namespace std;
      using namespace chrono;

      // Write tx/s to std out
      const auto total_txs = timing_results.total_sends;
      const auto dur_ms =
        duration_cast<milliseconds>(timing_results.duration).count();
      const auto duration = dur_ms / 1000.0;
      const auto tx_per_sec = total_txs / duration;

      LOG_INFO_FMT(
        "{} transactions took {}ms.\n"
        "=> {}tx/s\n", //< This is grepped for by _get_perf in Python
        total_txs,
        dur_ms,
        tx_per_sec);

      LOG_DEBUG_FMT(
        "  Sends: {}\n"
        "  Receives: {}\n"
        "  All txs (local_commit): {}\n"
        "  Global commit: {}\n",
        timing_results.total_sends,
        timing_results.total_receives,
        timing_results.total_local_commit,
        timing_results.total_global_commit);

      for (size_t round = 0; round < timing_results.per_round.size(); ++round)
      {
        const auto& round_info = timing_results.per_round[round];

        LOG_TRACE_FMT(
          "  Round {} (req ids #{} to #{})\n"
          "    Local: {}\n"
          "    Global: {}\n",
          round,
          round_info.begin_rpc_id,
          round_info.end_rpc_id,
          round_info.local_commit,
          round_info.global_commit);
      }

      // Write perf summary to csv
      std::ofstream perf_summary_csv(
        perf_summary, std::ofstream::out | std::ofstream::app);
      if (perf_summary_csv.is_open())
      {
        // Total number of bytes sent is:
        // sessions * sum-per-tx of tx-bytes)
        const auto total_bytes =
          options.session_count * total_byte_size(prepared_txs);

        perf_summary_csv << duration_cast<milliseconds>(
                              timing_results.start_time.time_since_epoch())
                              .count(); // timeStamp
        perf_summary_csv << "," << dur_ms; // elapsed
        perf_summary_csv << ","
                         << (options.server_address.hostname.find("127.") == 0 ?
                               options.label :
                               options.label + string("_distributed")); // label
        perf_summary_csv << "," << total_bytes; // bytes
        perf_summary_csv << "," << options.thread_count; // allThreads
        perf_summary_csv << "," << (double)dur_ms / total_txs; // latency
        perf_summary_csv << "," << total_txs; // SampleCount

        const auto& lc = timing_results.total_local_commit;
        perf_summary_csv << "," << lc.average; // local_commit_latency
        perf_summary_csv << "," << lc.sample_count; // local_commit_samples

        const auto& gc = timing_results.total_global_commit;
        perf_summary_csv << "," << gc.average; // global_commit_latency
        perf_summary_csv << "," << gc.sample_count; // global_commit_samples

        perf_summary_csv << endl;
      }
    }

    virtual void run()
    {
      // Write PID to disk
      files::dump(fmt::format("{}", ::getpid()), options.pid_file);

      if (options.randomise)
      {
        options.generator_seed = std::random_device()();
      }

      LOG_INFO_FMT(
        "Random choices determined by seed: {}", options.generator_seed);
      rand_generator.seed(options.generator_seed);

      /*
      const auto target_core = 0;
      if (!pin_to_core(target_core))
      {
        LOG_FAIL_FMT("Failed to pin to core: {}", target_core);
      }
      */

      const bool verifying = !options.verification_file.empty();

      if (verifying)
      {
        verification_target = files::slurp_json(options.verification_file);
        verify_params(verification_target["params"]);
      }

      // Pre- and post- hooks allow derived classes to gather/log initial state
      pre_creation_hook();
      send_all_creation_transactions();
      post_creation_hook();

      if (verifying)
      {
        verify_initial_state(verification_target["initial"]);
      }

      prepare_all_transactions();

      pre_timing_body_hook();

      LOG_TRACE_FMT(
        "Sending {} transactions from {} clients {} times...",
        options.num_transactions,
        options.thread_count,
        options.session_count);

      auto timing_results = send_all_prepared_transactions();

      LOG_INFO_FMT("Done");

      post_timing_body_hook();

      if (verifying)
      {
        verify_final_state(verification_target["final"]);
      }

      summarize_results(timing_results);
    }

    template <typename T>
    T rand_range()
    {
      std::uniform_int_distribution<T> dist;
      return dist(rand_generator);
    }

    template <typename T>
    T rand_range(T exclusive_upper_bound)
    {
      std::uniform_int_distribution<T> dist(0, exclusive_upper_bound - 1);
      return dist(rand_generator);
    }

    template <typename T>
    T rand_range(T inclusive_lower_bound, T exclusive_upper_bound)
    {
      std::uniform_int_distribution<T> dist(
        inclusive_lower_bound, exclusive_upper_bound - 1);
      return dist(rand_generator);
    }
  };
}
