// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// CCF
#include "clients/rpc_tls_client.h"

// STL/3rdparty
#include <chrono>
#include <fstream>
#include <iomanip>
#include <thread>
#include <vector>

namespace timing
{
  using namespace std;
  using namespace chrono;

  using Clock = high_resolution_clock;
  using TimeDelta = duration<double>;

  struct SentRequest
  {
    const TimeDelta send_time;
    const std::string method;
    const size_t rpc_id;
    const bool expects_commit;
  };

  struct CommitIDs
  {
    size_t local;
    size_t global;
    size_t term;
  };

  struct ReceivedReply
  {
    const TimeDelta receive_time;
    const size_t rpc_id;
    const optional<CommitIDs> commit;
  };

  struct Measure
  {
    size_t sample_count;
    double average;
    double variance;
  };

  std::string timestamp()
  {
    std::stringstream ss;

    const auto now = Clock::now();
    auto now_tt = Clock::to_time_t(now);
    auto now_tm = std::localtime(&now_tt);

    ss << "[" << std::put_time(now_tm, "%T.");

    const auto remainder =
      duration_cast<microseconds>(now.time_since_epoch()) % seconds(1);
    ss << std::setfill('0') << std::setw(6) << remainder.count() << "] ";

    return ss.str();
  }

  // NaNs are ignored (treated as though they are not present)
  Measure measure(const vector<double>& samples)
  {
    vector<double> non_nans;
    non_nans.reserve(samples.size());
    for (double d : samples)
    {
      if (!isnan(d))
        non_nans.push_back(d);
    }

    const double average =
      accumulate(non_nans.begin(), non_nans.end(), 0.0) / non_nans.size();

    vector<double> sq_diffs(non_nans.size());
    transform(
      non_nans.begin(), non_nans.end(), sq_diffs.begin(), [average](double d) {
        return (d - average) * (d - average);
      });

    const double variance =
      accumulate(sq_diffs.begin(), sq_diffs.end(), 0.0) / sq_diffs.size();

    return {non_nans.size(), average, variance};
  }

  ostream& operator<<(ostream& stream, const Measure& m)
  {
    stream << m.sample_count << " samples with average latency " << m.average
           << "s";
    const auto prev_precision = stream.precision(3);
    stream << " (variance " << std::scientific << m.variance
           << std::defaultfloat << ")";
    stream.precision(prev_precision);
    return stream;
  }

  struct Results
  {
    size_t total_sends;
    size_t total_receives;
    Clock::time_point start_time;
    TimeDelta duration;

    Measure total_local_commit;
    Measure total_global_commit;

    struct PerRound
    {
      size_t begin_rpc_id;
      size_t end_rpc_id;

      Measure local_commit;
      Measure global_commit;
    };

    vector<PerRound> per_round;
  };

  class ResponseTimes
  {
    const shared_ptr<RpcTlsClient> net_client;
    time_point<Clock> start_time;

    vector<SentRequest> sends;
    vector<ReceivedReply> receives;

    bool try_get_commit(
      const shared_ptr<RpcTlsClient>& client,
      size_t& local,
      size_t& global,
      size_t& term,
      bool record = false)
    {
      if (record)
      {
        record_send("getCommit", client->id, false);
      }

      const auto j = nlohmann::json::from_msgpack(client->call("getCommit"));

      if (!j.is_object())
        return false;

      const auto error_it = j.find("error");
      if (error_it != j.end())
        throw runtime_error("getCommit failed with error: " + error_it->dump());

      const auto local_commit_it = j.find("commit");
      if (local_commit_it == j.end())
        return false;

      const auto global_commit_it = j.find("global_commit");
      if (global_commit_it == j.end())
        return false;

      const auto term_it = j.find("term");
      if (term_it == j.end())
        return false;

      local = *local_commit_it;
      global = *global_commit_it;
      term = *term_it;

      const auto id_it = j.find("id");
      if (id_it == j.end())
        return false;

      if (record)
      {
        record_receive(*id_it, {{local, global, term}});
      }

      return true;
    }

  public:
    ResponseTimes(const shared_ptr<RpcTlsClient>& client) :
      net_client(client),
      start_time(Clock::now())
    {}

    ResponseTimes(const ResponseTimes& other) = default;

    void reset_start_time()
    {
      start_time = Clock::now();
    }

    auto get_start_time() const
    {
      return start_time;
    }

    void record_send(
      const std::string& method, size_t rpc_id, bool expects_commit)
    {
      sends.push_back(
        {Clock::now() - start_time, method, rpc_id, expects_commit});
    }

    void record_receive(size_t rpc_id, const optional<CommitIDs>& commit)
    {
      receives.push_back({Clock::now() - start_time, rpc_id, commit});
    }

    // Repeatedly calls getCommit RPC until local and global_commit match, then
    // returns that commit. Calls received_response for each response.
    size_t wait_for_global_commit(
      std::optional<size_t> at_least = {}, bool record = true)
    {
      size_t local = 0u;
      size_t global = 0u;
      size_t term = 0u;

      bool success = try_get_commit(net_client, local, global, term, true);
      auto target = at_least.has_value() ? max(*at_least, local) : local;

      using LastPrinted = std::pair<decltype(target), decltype(global)>;
      std::optional<LastPrinted> last_printed = std::nullopt;

      while (!success || (global < target))
      {
        auto current = std::make_pair(target, global);
        if (!last_printed.has_value() || *last_printed != current)
        {
          std::cout << timestamp() << "Waiting for " << target << ", at "
                    << global << std::endl;
          last_printed = current;
        }
        this_thread::sleep_for(10us);
        success = try_get_commit(net_client, local, global, term, record);
      }

      return global;
    }

    Results produce_results(
      bool allow_pending,
      std::optional<size_t> highest_local_commit,
      size_t desired_rounds = 1)
    {
      TimeDelta end_time_delta = Clock::now() - start_time;

      const auto rounds = min(max(sends.size(), 1ul), desired_rounds);
      const auto round_size = sends.size() / rounds;

      // Assume we receive responses in the same order requests were sent, then
      // duplicate IDs shouldn't cause a problem
      size_t next_recv = 0u;

      using Latencies = vector<double>;

      Results res;
      Latencies all_local_commits;
      Latencies all_global_commits;

      if (highest_local_commit.has_value())
      {
        // get test duration for last sent message's global commit
        for (auto i = next_recv; i < receives.size(); ++i)
        {
          auto receive = receives[i];

          if (receive.commit.has_value())
          {
            if (receive.commit->global >= highest_local_commit.value())
            {
              std::cout << "global commit match: " << receive.commit->global
                        << " for highest local commit: "
                        << highest_local_commit.value() << std::endl;
              auto was =
                duration_cast<milliseconds>(end_time_delta).count() / 1000.0;
              auto is =
                duration_cast<milliseconds>(receive.receive_time).count() /
                1000.0;
              std::cout << "duration changing from: " << was << " s to: " << is
                        << " s" << std::endl;
              end_time_delta = receive.receive_time;
              break;
            }
          }
        }
      }

      for (auto round = 1; round <= rounds; ++round)
      {
        const auto round_begin = sends.begin() + (round_size * (round - 1));
        const auto round_end =
          round == rounds ? sends.end() : round_begin + round_size;

        Latencies round_local_commit;
        Latencies round_global_commit;

        struct PendingGlobalCommit
        {
          TimeDelta send_time;
          size_t target_commit;
        };
        vector<PendingGlobalCommit> pending_global_commits;

        auto complete_pending = [&](const ReceivedReply& receive) {
          if (receive.commit.has_value())
          {
            auto pending_it = pending_global_commits.begin();
            while (pending_it != pending_global_commits.end())
            {
              if (receive.commit->global >= pending_it->target_commit)
              {
                round_global_commit.push_back(
                  (receive.receive_time - pending_it->send_time).count());
                pending_it = pending_global_commits.erase(pending_it);
              }
              else
              {
                // Assuming the target_commits within pending_global_commits are
                // monotonic, we can break here. If this receive didn't satisfy
                // the first pending commit, it can't satisfy any later
                break;
              }
            }
          }
        };

        for (auto send_it = round_begin; send_it != round_end; ++send_it)
        {
          const auto& send = *send_it;

          double tx_latency;
          optional<CommitIDs> response_commit;
          for (auto i = next_recv; i < receives.size(); ++i)
          {
            const auto& receive = receives[i];

            complete_pending(receive);

            if (receive.rpc_id == send.rpc_id)
            {
              tx_latency = (receive.receive_time - send.send_time).count();

              if (tx_latency < 0)
              {
                std::cerr << "Calculated a negative latency (" << tx_latency
                          << ") for RPC " << receive.rpc_id
                          << " - duplicate ID causing mismatch?" << std::endl;
                continue;
              }

              response_commit = receive.commit;
              next_recv = i + 1;
              break;
            }
          }

          if (send.expects_commit)
          {
            if (response_commit.has_value())
            {
              // Successful write - measure local tx time AND try to find global
              // commit time
              round_local_commit.push_back(tx_latency);

              if (response_commit->global >= response_commit->local)
              {
                // Global commit already already
                round_global_commit.push_back(tx_latency);
              }
              else
              {
                // Store expected global commit to find later
                pending_global_commits.push_back(
                  {send.send_time, response_commit->local});
              }
            }
            else
            {
              // Write failed - measure local tx time
              round_local_commit.push_back(tx_latency);
            }
          }
          else
          {
            // Read-only - measure local tx time
            round_local_commit.push_back(tx_latency);
          }
        }

        // After every tracked send has been processed, consider every remaining
        // receive to satisfy outstanding pending global commits
        for (auto i = next_recv; i < receives.size(); ++i)
        {
          if (pending_global_commits.empty())
          {
            break;
          }

          complete_pending(receives[i]);
        }

        all_local_commits.insert(
          all_local_commits.end(),
          round_local_commit.begin(),
          round_local_commit.end());
        all_global_commits.insert(
          all_global_commits.end(),
          round_global_commit.begin(),
          round_global_commit.end());

        if (rounds > 1)
        {
          res.per_round.push_back({round_begin->rpc_id,
                                   (round_end - 1)->rpc_id,
                                   measure(round_local_commit),
                                   measure(round_global_commit)});
        }

        if (!allow_pending)
        {
          if (!pending_global_commits.empty())
          {
            const auto& first = pending_global_commits[0];
            throw runtime_error(
              "Still waiting for " + to_string(pending_global_commits.size()) +
              " global commits. First expected is " +
              to_string(first.target_commit) + " for a transaction sent at " +
              to_string(first.send_time.count()));
          }
        }

        const auto expected_local_samples = distance(round_begin, round_end);
        const auto actual_local_samples = round_local_commit.size();
        if (actual_local_samples != expected_local_samples)
        {
          throw runtime_error(
            "Measured " + to_string(actual_local_samples) +
            " response times, yet sent " + to_string(expected_local_samples) +
            " requests");
        }
      }

      res.total_sends = sends.size();
      res.total_receives = receives.size();
      res.start_time = start_time;
      res.duration = end_time_delta;

      res.total_local_commit = measure(all_local_commits);
      res.total_global_commit = measure(all_global_commits);
      return res;
    }

    void write_to_file(const string& filename)
    {
      std::cout << "Writing timing data to file" << std::endl;

      const auto sent_path = filename + "_sent.csv";
      ofstream sent_csv(sent_path, ofstream::out);
      if (sent_csv.is_open())
      {
        sent_csv << "sent_sec,idx,method,expects_commit" << endl;
        for (const auto& sent : sends)
        {
          sent_csv << sent.send_time.count() << "," << sent.rpc_id << ","
                   << sent.method << "," << sent.expects_commit << endl;
        }
        std::cout << "Wrote " << sends.size() << " entries to " << sent_path
                  << std::endl;
      }

      const auto recv_path = filename + "_recv.csv";
      ofstream recv_csv(recv_path, ofstream::out);
      if (recv_csv.is_open())
      {
        recv_csv << "recv_sec,idx,has_commits,commit,term,global_commit"
                 << endl;
        for (const auto& reply : receives)
        {
          recv_csv << reply.receive_time.count();
          recv_csv << "," << reply.rpc_id;
          recv_csv << "," << reply.commit.has_value();

          if (reply.commit.has_value())
          {
            recv_csv << "," << reply.commit->local;
            recv_csv << "," << reply.commit->term;
            recv_csv << "," << reply.commit->global;
          }
          else
          {
            recv_csv << "," << 0;
            recv_csv << "," << 0;
            recv_csv << "," << 0;
          }
          recv_csv << endl;
        }
        std::cout << "Wrote " << receives.size() << " entries to " << recv_path
                  << std::endl;
      }
    }
  };
}