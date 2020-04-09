// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/histogram.h"
#include "ds/logger.h"
#include "serialization.h"

#include <nlohmann/json.hpp>

#define HIST_MAX (1 << 17)
#define HIST_MIN 1
#define HIST_BUCKET_GRANULARITY 5
#define TX_RATE_BUCKETS_LEN 4000

namespace metrics
{
  class Metrics
  {
  private:
    size_t tick_count = 0;
    double tx_time_passed[TX_RATE_BUCKETS_LEN] = {};
    size_t tx_rates[TX_RATE_BUCKETS_LEN] = {};
    std::chrono::milliseconds rate_time_elapsed = std::chrono::milliseconds(0);
    using Hist =
      histogram::Histogram<int, HIST_MIN, HIST_MAX, HIST_BUCKET_GRANULARITY>;
    histogram::Global<Hist> global =
      histogram::Global<Hist>("histogram", __FILE__, __LINE__);
    Hist histogram = Hist(global);
    struct TxStatistics
    {
      uint32_t tx_count = 0;
      uint32_t cumulative_time = 0;
      uint32_t time_samples = 0;
    };
    std::array<TxStatistics, 100> times;

    ccf::GetMetrics::HistogramResults get_histogram_results()
    {
      ccf::GetMetrics::HistogramResults result;
      result.low = histogram.get_low();
      result.high = histogram.get_high();
      result.overflow = histogram.get_overflow();
      result.underflow = histogram.get_underflow();
      auto range_counts = histogram.get_range_count();
      nlohmann::json buckets;
      for (auto const& e : range_counts)
      {
        const auto count = e.second;
        if (count > 0)
        {
          buckets.push_back(e);
        }
      }
      result.buckets = buckets;
      return result;
    }

    nlohmann::json get_tx_rates()
    {
      nlohmann::json result;
      for (size_t i = 0; i < TX_RATE_BUCKETS_LEN; ++i)
      {
        if (tx_rates[i] > 0)
        {
          result[std::to_string(i)]["rate"] = tx_rates[i];
          result[std::to_string(i)]["duration"] = tx_time_passed[i];
        }
      }

      LOG_INFO << "Printing time series"
               << ", this:" << (uint64_t)this << std::endl;
      for (uint32_t i = 0; i < times.size(); ++i)
      {
        uint32_t latency = 0;
        if (times[i].time_samples != 0)
        {
          latency = (times[i].cumulative_time / times[i].time_samples);
        }

        LOG_INFO_FMT("{} - {}, {}", i, times[i].tx_count, latency);
      }

      return result;
    }

  public:
    ccf::GetMetrics::Out get_metrics()
    {
      nlohmann::json result;
      result["histogram"] = get_histogram_results();
      result["tx_rates"] = get_tx_rates();

      return result;
    }

    void track_tx_rates(
      const std::chrono::milliseconds& elapsed, kv::Consensus::Statistics stats)
    {
      // calculate how many tx/sec we have processed in this tick
      auto duration = elapsed.count() / 1000.0;
      auto tx_rate = stats.tx_count / duration;
      histogram.record(tx_rate);
      // keep time since beginning
      rate_time_elapsed += elapsed;
      if (tx_rate > 0)
      {
        if (tick_count < TX_RATE_BUCKETS_LEN)
        {
          auto rate_duration = rate_time_elapsed.count() / 1000.0;
          tx_rates[tick_count] = tx_rate;
          tx_time_passed[tick_count] = rate_duration;
        }
        tick_count++;
      }
      uint32_t bucket = rate_time_elapsed.count() / 1000.0;
      if (bucket < times.size())
      {
        times[bucket].tx_count += stats.tx_count;
        times[bucket].cumulative_time += stats.time_spent;
        times[bucket].time_samples += stats.count_num_samples;
      }
    }
  };
}