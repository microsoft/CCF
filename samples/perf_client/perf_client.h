// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Local
#include "timing.h"

// CCF
#include "clients/rpc_tls_client.h"
#include "clients/sig_rpc_tls_client.h"
#include "ds/cli_helper.h"
#include "ds/files.h"

// STL/3rdparty
#include <CLI11/CLI11.hpp>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <random>
#include <thread>

namespace client
{
  constexpr auto perf_summary = "perf_summary.csv";

  bool pin_to_core(int core_id)
  {
    int threads = std::thread::hardware_concurrency();
    if (core_id > threads || core_id < 0)
    {
      std::cerr << "Invalid core id: " << core_id << std::endl;
      return false;
    }

    cpu_set_t set;
    std::cout << "Pinning to core:" << core_id << std::endl;
    CPU_ZERO(&set);
    CPU_SET(core_id, &set);

    if (sched_setaffinity(0, sizeof(cpu_set_t), &set) < 0)
    {
      std::cerr << "Unable to set affinity" << std::endl;
      return false;
    }

    return true;
  }

  /** Base class for perf-testing clients. Provides hooks to set initial state,
   * prepare a batch of transactions, and then measure the latency and
   * throughput of processing those batched transactions */
  class PerfBase
  {
  private:
    tls::Pem key = {};
    std::shared_ptr<tls::Cert> tls_cert;

    // Create tls_cert if it doesn't exist, and return it
    bool get_cert()
    {
      if (tls_cert == nullptr)
      {
        const auto raw_cert = files::slurp(cert_file);
        const auto raw_key = files::slurp(key_file);
        const auto ca = files::slurp(ca_file);

        key = tls::Pem(raw_key);

        tls_cert = std::make_shared<tls::Cert>(
          std::make_shared<tls::CA>(ca), raw_cert, key);

        return true;
      }

      return false;
    }

    // Process reply to an RPC. Records time reply was received. Calls
    // check_response for derived-overridable validation
    void process_reply(const std::vector<uint8_t>& reply)
    {
      auto j = nlohmann::json::from_msgpack(reply);
      if (!j.is_object())
      {
        throw std::logic_error(j.dump());
      }

      if (check_responses)
      {
        if (!check_response(j))
        {
          throw std::logic_error("Response failed check: " + j.dump());
        }
      }

      std::optional<timing::CommitIDs> commits = std::nullopt;

      if (timing.has_value())
      {
        const auto id_it = j.find("id");
        if (id_it == j.end())
          throw std::logic_error("Missing RPC ID: " + j.dump());

        const auto commit_it = j.find("commit");
        const auto global_it = j.find("global_commit");
        const auto term_it = j.find("term");

        // If any of these are missing, we'll write no commits and consider
        // this a failed request
        if (commit_it != j.end() && global_it != j.end() && term_it != j.end())
        {
          commits.emplace(timing::CommitIDs{*commit_it, *global_it, *term_it});

          highest_local_commit =
            std::max<size_t>(highest_local_commit, *commit_it);
        }

        // Record time of received responses
        timing->record_receive(*id_it, commits);
      }
    }

  protected:
    std::mt19937 rand_generator;

    nlohmann::json verification_target;

    struct PreparedTx
    {
      RpcTlsClient::PreparedRpc rpc;
      std::string method;
      bool expects_commit;
    };

    using PreparedTxs = std::vector<PreparedTx>;

    std::shared_ptr<RpcTlsClient> rpc_connection;
    PreparedTxs prepared_txs;

    std::optional<timing::ResponseTimes> timing;
    size_t highest_local_commit = 0;

    std::shared_ptr<RpcTlsClient> create_connection(bool force_unsigned = false)
    {
      // Create a cert if this is our first rpc_connection
      const bool is_first = get_cert();

      const auto conn = (sign && !force_unsigned) ?
        std::make_shared<SigRpcTlsClient>(
          key,
          server_address.hostname,
          server_address.port,
          nullptr,
          tls_cert) :
        std::make_shared<RpcTlsClient>(
          server_address.hostname, server_address.port, nullptr, tls_cert);
      conn->set_prefix("users");

      // Report ciphersuite of first client (assume it is the same for each)
      if (verbosity >= 1 && is_first)
      {
        std::cout << "Connected to server via TLS ("
                  << conn->get_ciphersuite_name() << ")" << std::endl;
      }

      return conn;
    }

    void add_prepared_tx(
      const std::string& method,
      const nlohmann::json& params,
      bool expects_commit,
      const std::optional<size_t>& index)
    {
      const PreparedTx tx{
        rpc_connection->gen_rpc(method, params), method, expects_commit};

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

    static size_t total_byte_size(const PreparedTxs& txs)
    {
      return std::accumulate(
        txs.begin(), txs.end(), 0, [](size_t n, const PreparedTx& tx) {
          return n + tx.rpc.encoded.size();
        });
    }

    /// Options set from command line
    ///@{
    std::string label; //< Default set in constructor

    cli::ParsedAddress server_address;
    std::string cert_file, key_file, ca_file, verification_file;

    size_t num_transactions = 10000;
    size_t thread_count = 1;
    size_t session_count = 1;
    size_t max_writes_ahead = 0;
    size_t latency_rounds = 1;
    size_t verbosity = 0;
    size_t generator_seed = 42u;

    bool sign = false;
    bool no_create = false;
    bool no_wait = false;
    bool write_tx_times = false;
    bool randomise = false;
    bool check_responses = false;
    bool relax_commit_target = false;
    ///@}

    // Everything else has empty stubs and can optionally be overridden. This
    // must be provided by derived class
    virtual void prepare_transactions() = 0;

    virtual void send_creation_transactions(
      const std::shared_ptr<RpcTlsClient>& connection)
    {}

    virtual bool check_response(const nlohmann::json& j)
    {
      // Default behaviour is to accept anything that doesn't contain an error
      return j.find("error") == j.end();
    }

    virtual void pre_creation_hook(){};
    virtual void post_creation_hook(){};

    virtual void pre_timing_body_hook(){};
    virtual void post_timing_body_hook(){};

    virtual timing::Results call_raw_batch(
      const std::shared_ptr<RpcTlsClient>& connection, const PreparedTxs& txs)
    {
      size_t read;
      size_t written;

      kick_off_timing();
      std::optional<size_t> end_highest_local_commit;

      // Repeat for each session
      for (size_t session = 1; session <= session_count; ++session)
      {
        read = 0;
        written = 0;

        // Write everything
        while (written < txs.size())
          write(txs[written], read, written, connection);

        blocking_read(read, written, connection);

        // Reconnect for each session (except the last)
        if (session != session_count)
        {
          reconnect(connection);
        }
      }

      force_global_commit(connection);
      wait_for_global_commit();
      auto timing_results = end_timing(end_highest_local_commit);
      std::cout << timing::timestamp() << "Timing ended" << std::endl;
      return timing_results;
    }

    void kick_off_timing()
    {
      std::cout << timing::timestamp() << "About to begin timing" << std::endl;
      begin_timing();
      std::cout << timing::timestamp() << "Began timing" << std::endl;
    }

    inline void write(
      const PreparedTx& tx,
      size_t& read,
      size_t& written,
      const std::shared_ptr<RpcTlsClient>& connection)
    {
      // Record time of sent requests
      if (timing.has_value())
        timing->record_send(tx.method, tx.rpc.id, tx.expects_commit);

      connection->write(tx.rpc.encoded);
      ++written;

      // Optimistically read (non-blocking) any current responses
      while (read < written)
      {
        const auto r = connection->read_rpc_non_blocking();
        if (!r.has_value())
        {
          // If we have no responses waiting, move on to the next thing
          break;
        }

        process_reply(r.value());
        ++read;
      }

      // Do blocking reads if we're beyond our write-ahead limit
      if (max_writes_ahead > 0) // 0 is a special value allowing unlimited
                                // write-ahead
      {
        while (written - read >= max_writes_ahead)
        {
          process_reply(connection->read_rpc());
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
        process_reply(connection->read_rpc());
        ++read;
      }
    }

    void reconnect(const std::shared_ptr<RpcTlsClient>& connection)
    {
      connection->disconnect();
      connection->connect();
    }

    void force_global_commit(const std::shared_ptr<RpcTlsClient>& connection)
    {
      // End with a mkSign RPC to force a final global commit
      const auto method = "mkSign";
      const auto mk_sign = connection->gen_rpc(method);
      if (timing.has_value())
      {
        timing->record_send(method, mk_sign.id, true);
      }
      connection->write(mk_sign.encoded);

      // Do a blocking read for this final response
      process_reply(connection->read_rpc());
    }

    virtual void verify_params(const nlohmann::json& expected)
    {
      // It's only reasonable to compare against expected state if the initial
      // parameters match, so check a few obvious ones

      {
        const auto it = expected.find("seed");
        if (it != expected.end())
        {
          const auto expected_seed = it->get<decltype(generator_seed)>();
          if (expected_seed != generator_seed)
          {
            throw std::runtime_error(
              "Verification file expects seed " +
              std::to_string(expected_seed) + ", but currently using " +
              std::to_string(generator_seed));
          }
        }
      }

      {
        const auto it = expected.find("transactions");
        if (it != expected.end())
        {
          const auto expected_txs = it->get<decltype(num_transactions)>();
          if (expected_txs != num_transactions)
          {
            throw std::runtime_error(
              "Verification file is only applicable for " +
              std::to_string(expected_txs) +
              " transactions, but currently running " +
              std::to_string(num_transactions));
          }
        }
      }

      {
        const auto it = expected.find("sessions");
        if (it != expected.end())
        {
          const auto expected_sessions = it->get<decltype(session_count)>();
          if (expected_sessions != session_count)
          {
            throw std::runtime_error(
              "Verification file is only applicable for " +
              std::to_string(expected_sessions) +
              " sessions, but currently running " +
              std::to_string(session_count));
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

        if (expected_randomise != randomise)
        {
          throw std::runtime_error(
            "Verification file is only applicable when randomisation is " +
            std::string(expected_randomise ? "ON" : "OFF") +
            ", but this option is currently " +
            std::string(randomise ? "ON" : "OFF"));
        }
      }
    }
    virtual void verify_initial_state(const nlohmann::json& expected) {}
    virtual void verify_final_state(const nlohmann::json& expected) {}

  public:
    PerfBase(const std::string& default_label) :
      label(default_label),
      rand_generator()
    {}

    virtual void setup_parser(CLI::App& app)
    {
      // Enable config from file
      app.set_config("--config");

      app.add_option(
        "--label",
        label,
        "Identifier for this client, written to " + std::string(perf_summary));

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

      app
        .add_option(
          "--verify",
          verification_file,
          "Verify results against expectation, specified in file")
        ->required(false)
        ->check(CLI::ExistingFile);
      app.add_option("--generator-seed", generator_seed);

      // Transaction counts and batching details
      app.add_option(
        "--transactions",
        num_transactions,
        "The basic number of transactions to send (will actually send this "
        "many for each thread, in each session)");
      app.add_option("-t,--threads", thread_count);
      app.add_option("-s,--sessions", session_count);
      app.add_option(
        "--max-writes-ahead",
        max_writes_ahead,
        "How many transactions the client should send without waiting for "
        "responses. 0 will send all transactions before blocking for any "
        "responses, 1 will minimise latency by serially waiting for each "
        "transaction's response, other values may provide a balance between "
        "throughput and latency");

      app.add_option("--latency-rounds", latency_rounds);
      app.add_flag("-v,-V,--verbose", verbosity);

      // Boolean flags
      app.add_flag("--sign", sign, "Send client-signed transactions");
      app.add_flag(
        "--no-create", no_create, "Skip creation/setup transactions");
      app.add_flag(
        "--no-wait",
        no_wait,
        "Don't wait for transactions to be globally committed");
      app.add_flag(
        "--write-tx-times",
        write_tx_times,
        "Write tx sent and received times to csv");
      app.add_flag(
        "--randomise",
        randomise,
        "Use non-deterministically random transaction contents each run");
      app.add_flag(
        "--check-responses",
        check_responses,
        "Check every JSON response for errors. Potentially slow");
    }

    void init_connection()
    {
      // Make sure the connection we're about to use has been initialised
      if (!rpc_connection)
      {
        rpc_connection = create_connection();
      }
    }

    void send_all_creation_transactions()
    {
      if (!no_create)
      {
        try
        {
          // Create a new connection for these, rather than a connection which
          // will be reused for bulk transactions later
          send_creation_transactions(create_connection());
        }
        catch (std::exception& e)
        {
          std::cout << "Exception during creation steps: " << e.what()
                    << std::endl;
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
        std::cout << "Preparation exception: " << e.what() << std::endl;
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
        std::cout << "Transaction exception: " << e.what() << std::endl;
        throw e;
      }
    }

    void wait_for_global_commit()
    {
      if (!no_wait)
      {
        if (!timing.has_value())
        {
          throw std::logic_error("Unexpected call to wait_for_global_commit");
        }

        auto commit = timing->wait_for_global_commit({highest_local_commit});

        if (verbosity >= 1)
        {
          std::cout << timing::timestamp() << "Reached stable global commit at "
                    << commit << std::endl;
        }
      }
    }

    void begin_timing()
    {
      if (timing.has_value())
      {
        throw std::logic_error(
          "timing is already set - has begin_timing been called multiple "
          "times?");
      }

      // timing gets its own new connection for any requests it wants to send -
      // these are never signed
      timing.emplace(create_connection(true));
      timing->reset_start_time();
    }

    timing::Results end_timing(std::optional<size_t> end_highest_local_commit)
    {
      if (!timing.has_value())
      {
        throw std::logic_error(
          "timing is not set - has begin_timing not been called?");
      }

      auto results = timing->produce_results(
        no_wait, end_highest_local_commit, latency_rounds);

      if (write_tx_times)
      {
        timing->write_to_file(label);
      }

      timing.reset();

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

      cout << total_txs << " transactions took " << dur_ms << "ms." << endl;
      cout << "\t=> " << tx_per_sec << "tx/s" << endl;

      // Write latency information, depending on verbosity
      if (verbosity >= 1)
      {
        const auto indent_1 = "  ";

        cout << "Sends: " << timing_results.total_sends << endl;
        cout << "Receives: " << timing_results.total_receives << endl;

        cout << indent_1
             << "All txs (local commit): " << timing_results.total_local_commit
             << endl;
        cout << indent_1
             << "Global commit: " << timing_results.total_global_commit << endl;

        if (verbosity >= 2 && !timing_results.per_round.empty())
        {
          const auto indent_2 = "    ";

          for (size_t round = 0; round < timing_results.per_round.size();
               ++round)
          {
            const auto& round_info = timing_results.per_round[round];
            cout << indent_1 << "Round " << round << " (req ids #"
                 << round_info.begin_rpc_id << " to #" << round_info.end_rpc_id
                 << ")" << endl;

            cout << indent_2 << "Local: " << round_info.local_commit << endl;
            cout << indent_2 << "Global: " << round_info.global_commit << endl;
          }
        }
      }

      // Write perf summary to csv
      std::ofstream perf_summary_csv(
        perf_summary, std::ofstream::out | std::ofstream::app);
      if (perf_summary_csv.is_open())
      {
        // Total number of bytes sent is:
        // sessions * sum-per-tx of tx-bytes)
        const auto total_bytes = session_count * total_byte_size(prepared_txs);

        perf_summary_csv << duration_cast<milliseconds>(
                              timing_results.start_time.time_since_epoch())
                              .count(); // timeStamp
        perf_summary_csv << "," << dur_ms; // elapsed
        perf_summary_csv << ","
                         << (server_address.hostname.find("127.") == 0 ?
                               label :
                               label + string("_distributed")); // label
        perf_summary_csv << "," << total_bytes; // bytes
        perf_summary_csv << "," << thread_count; // allThreads
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
      if (randomise)
      {
        generator_seed = std::random_device()();
      }

      std::cout << "Random choices determined by seed: " << generator_seed
                << std::endl;
      rand_generator.seed(generator_seed);

      /*
      const auto target_core = 0;
      if (!pin_to_core(target_core))
      {
        std::cout << "Failed to pin to core: " << target_core << std::endl;
      }
      */

      const bool verifying = !verification_file.empty();

      if (verifying)
      {
        verification_target = files::slurp_json(verification_file);
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

      if (verbosity >= 1)
      {
        std::cout << std::endl
                  << "Sending " << num_transactions << " transactions from "
                  << thread_count << " clients " << session_count << " times..."
                  << std::endl;
      }

      auto timing_results = send_all_prepared_transactions();

      if (verbosity >= 1)
      {
        std::cout << "Done" << std::endl;
      }

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
