// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// CCF
#include "ccf/tx_id.h"
#include "clients/rpc_tls_client.h"

// STL/3rdparty
#include <chrono>
#include <fstream>
#include <iomanip>
#include <thread>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace timing
{
  struct Measure
  {
    size_t sample_count;
    double average;
    double variance;
  };
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<timing::Measure>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const timing::Measure& e, FormatContext& ctx) const
  {
    return format_to(
      ctx.out(),
      "sample_count: {}, average: {}, variance: {}",
      e.sample_count,
      e.average,
      e.variance);
  }
};
FMT_END_NAMESPACE

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

  struct ReceivedReply
  {
    TimeDelta receive_time;
    size_t rpc_id;
    optional<ccf::TxID> commit;
    size_t global_seqno;
  };

  std::string timestamp()
  {
    std::stringstream ss;

    const auto now = Clock::now();
    time_t now_tt = now.time_since_epoch().count();
    tm now_tm;
    ::localtime_r(&now_tt, &now_tm);

    ss << "[" << std::put_time(&now_tm, "%T.");

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

  static std::optional<ccf::TxID> extract_transaction_id(
    const client::RpcTlsClient::Response& response)
  {
    const auto& h = response.headers;
    const auto it = h.find(ccf::http::headers::CCF_TX_ID);
    if (it == h.end())
    {
      return std::nullopt;
    }

    return ccf::TxID::from_str(it->second);
  }

  class ResponseTimes
  {
    const shared_ptr<client::RpcTlsClient> net_client;
    time_point<Clock> start_time;

    vector<SentRequest> sends;
    vector<ReceivedReply> receives;

    bool active = false;

  public:
    ResponseTimes(const shared_ptr<client::RpcTlsClient>& client) :
      net_client(client),
      start_time(Clock::now())
    {}

    ResponseTimes(const ResponseTimes& other) = default;

    void start_timing()
    {
      active = true;
      start_time = Clock::now();
    }

    bool is_timing_active()
    {
      return active;
    }

    void stop_timing()
    {
      active = false;
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

    void record_receive(
      size_t rpc_id, const optional<ccf::TxID>& tx_id, size_t global_seqno = 0)
    {
      receives.push_back(
        {Clock::now() - start_time, rpc_id, tx_id, global_seqno});
    }

    // Repeatedly calls GET /tx RPC until the target seqno has been
    // committed (or will never be committed), returns first confirming
    // response. Calls record_[send/response], if record is true.
    // Throws on errors, or if target is rolled back
    void wait_for_global_commit(const ccf::TxID& target, bool record = true)
    {
      auto params = nlohmann::json::object();
      params["transaction_id"] = target.to_str();

      constexpr auto get_tx_status = "tx";

      CCF_APP_INFO(
        "Waiting for transaction ID {}.{}", target.view, target.seqno);

      while (true)
      {
        const auto response = net_client->get(get_tx_status, params);

        if (record)
        {
          record_send(get_tx_status, response.id, false);
        }

        const auto body = net_client->unpack_body(response);
        if (response.status != HTTP_STATUS_OK)
        {
          throw runtime_error(fmt::format(
            "{} failed with status {}: {}",
            get_tx_status,
            ccf::http_status_str(response.status),
            body.dump()));
        }

        const auto tx_id = extract_transaction_id(response);

        // NB: Eventual header re-org should be exposing API types so
        // they can be consumed cleanly from C++ clients
        const std::string tx_status = body["status"];
        if (tx_status == "Pending" || tx_status == "Unknown")
        {
          if (record)
          {
            record_receive(response.id, tx_id);
          }

          // Commit is pending, poll again
          this_thread::sleep_for(10us);
          continue;
        }
        else if (tx_status == "Committed")
        {
          CCF_APP_INFO("Found global commit {}.{}", target.view, target.seqno);
          if (tx_id.has_value())
          {
            CCF_APP_INFO(
              " (headers view: {}, seqno: {})", tx_id->view, tx_id->seqno);
          }

          if (record)
          {
            if (tx_id.has_value())
            {
              record_receive(response.id, tx_id, target.seqno);
            }
            else
            {
              // If this response didn't contain commit IDs in headers, we can
              // still construct them from the body
              record_receive(
                response.id, {{target.view, target.seqno}}, target.seqno);
            }
          }
          return;
        }
        else if (tx_status == "Invalid")
        {
          throw std::logic_error(fmt::format(
            "Transaction {}.{} is now marked as invalid",
            target.view,
            target.seqno));
        }
        else
        {
          throw std::logic_error(
            fmt::format("Unhandled tx status: {}", tx_status));
        }
      }
    }

    Results produce_results(
      bool allow_pending,
      size_t highest_local_commit,
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

      // get test duration for last sent message's global commit
      for (auto i = next_recv; i < receives.size(); ++i)
      {
        auto receive = receives[i];

        if (receive.commit.has_value())
        {
          if (receive.global_seqno >= highest_local_commit)
          {
            CCF_APP_INFO(
              "Global commit match {} for highest local commit {}",
              receive.global_seqno,
              highest_local_commit);
            auto was =
              duration_cast<milliseconds>(end_time_delta).count() / 1000.0;
            auto is =
              duration_cast<milliseconds>(receive.receive_time).count() /
              1000.0;
            CCF_APP_INFO("Duration changing from {}s to {}s", was, is);
            end_time_delta = receive.receive_time;
            break;
          }
        }
      }

      for (size_t round = 1; round <= rounds; ++round)
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
          if (receive.global_seqno > 0)
          {
            auto pending_it = pending_global_commits.begin();
            while (pending_it != pending_global_commits.end())
            {
              if (receive.global_seqno >= pending_it->target_commit)
              {
                round_global_commit.push_back(
                  (receive.receive_time - pending_it->send_time).count());
                ++pending_it;
              }
              else
              {
                // Assuming the target_commits within pending_global_commits are
                // monotonic, we can break here. If this receive didn't satisfy
                // the first pending commit, it can't satisfy any later
                break;
              }
            }
            if (pending_it != pending_global_commits.begin())
            {
              pending_global_commits.erase(
                pending_global_commits.begin(), pending_it);
            }
          }
        };

        for (auto send_it = round_begin; send_it != round_end; ++send_it)
        {
          const auto& send = *send_it;

          double tx_latency;
          optional<ReceivedReply> matching_reply;
          for (auto i = next_recv; i < receives.size(); ++i)
          {
            const auto& receive = receives[i];

            complete_pending(receive);

            if (receive.rpc_id == send.rpc_id)
            {
              tx_latency = (receive.receive_time - send.send_time).count();

              if (tx_latency < 0)
              {
                CCF_APP_FAIL(
                  "Calculated a negative latency ({}) for RPC {} - duplicate "
                  "ID causing mismatch?",
                  tx_latency,
                  receive.rpc_id);
                continue;
              }

              matching_reply = receive;
              next_recv = i + 1;
              break;
            }
          }

          if (send.expects_commit)
          {
            if (matching_reply.has_value())
            {
              // Successful write - measure local tx time AND try to find global
              // commit time
              round_local_commit.push_back(tx_latency);

              if (matching_reply->global_seqno >= matching_reply->commit->seqno)
              {
                // Global commit already already
                round_global_commit.push_back(tx_latency);
              }
              else
              {
                if (matching_reply->commit->seqno <= highest_local_commit)
                {
                  // Store expected global commit to find later
                  pending_global_commits.push_back(
                    {send.send_time, matching_reply->commit->seqno});
                }
                else
                {
                  CCF_APP_DEBUG(
                    "Ignoring request with ID {} because it committed too late "
                    "({} > {})",
                    send.rpc_id,
                    matching_reply->commit->seqno,
                    highest_local_commit);
                }
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
          res.per_round.push_back(
            {round_begin->rpc_id,
             (round_end - 1)->rpc_id,
             measure(round_local_commit),
             measure(round_global_commit)});
        }

        if (!allow_pending)
        {
          if (!pending_global_commits.empty())
          {
            const auto& first = pending_global_commits[0];
            throw runtime_error(fmt::format(
              "Still waiting for {} global commits. First expected is {} for "
              "a transaction sent at {} (NB: Highest local commit is {})",
              pending_global_commits.size(),
              first.target_commit,
              first.send_time.count(),
              highest_local_commit));
          }
        }

        const auto expected_local_samples = distance(round_begin, round_end);
        const auto actual_local_samples = round_local_commit.size();
        if (actual_local_samples != expected_local_samples)
        {
          throw runtime_error(fmt::format(
            "Measured {} response times, yet sent {} requests",
            actual_local_samples,
            expected_local_samples));
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
      CCF_APP_INFO("Writing timing data to files");

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
        CCF_APP_INFO("Wrote {} entries to {}", sends.size(), sent_path);
      }

      const auto recv_path = filename + "_recv.csv";
      ofstream recv_csv(recv_path, ofstream::out);
      if (recv_csv.is_open())
      {
        recv_csv << "recv_sec,idx,has_commits,commit,view,global_commit"
                 << endl;
        for (const auto& reply : receives)
        {
          recv_csv << reply.receive_time.count();
          recv_csv << "," << reply.rpc_id;
          recv_csv << "," << reply.commit.has_value();

          if (reply.commit.has_value())
          {
            recv_csv << "," << reply.commit->seqno;
            recv_csv << "," << reply.commit->view;
          }
          else
          {
            recv_csv << "," << 0;
            recv_csv << "," << 0;
          }

          recv_csv << "," << reply.global_seqno;
          recv_csv << endl;
        }
        CCF_APP_INFO("Wrote {} entries to {}", receives.size(), recv_path);
      }
    }
  };
}
