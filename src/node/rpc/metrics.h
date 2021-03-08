// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/histogram.h"
#include "ds/logger.h"

#include <nlohmann/json.hpp>

#define HIST_MAX (1 << 17)
#define HIST_MIN 1
#define HIST_BUCKET_GRANULARITY 5
#define TX_RATE_BUCKETS_LEN 4000

namespace metrics
{
  struct HistogramResults
  {
    int low = {};
    int high = {};
    size_t overflow = {};
    size_t underflow = {};
    nlohmann::json buckets = {};
  };
  DECLARE_JSON_TYPE(HistogramResults)
  DECLARE_JSON_REQUIRED_FIELDS(
    HistogramResults, low, high, overflow, underflow, buckets)

  struct Report
  {
    HistogramResults histogram;
    nlohmann::json tx_rates;
  };
  DECLARE_JSON_TYPE(Report)
  DECLARE_JSON_REQUIRED_FIELDS(Report, histogram, tx_rates)

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
    };
    std::array<TxStatistics, 100> times;

    HistogramResults get_histogram_results()
    {
      HistogramResults result;
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

      return result;
    }

  public:
    Report get_metrics_report()
    {
      return {get_histogram_results(), get_tx_rates()};
    }

    void track_tx_rates(
      const std::chrono::milliseconds& elapsed, size_t tx_count)
    {
      if (elapsed.count() == 0)
      {
        return;
      }

      // calculate how many tx/sec we have processed in this tick
      double duration = elapsed.count() / 1000.0;
      double tx_rate = tx_count / duration;
      histogram.record(tx_rate);
      // keep time since beginning
      rate_time_elapsed += elapsed;
      if (tx_rate > 0)
      {
        if (tick_count < TX_RATE_BUCKETS_LEN)
        {
          double rate_duration = rate_time_elapsed.count() / 1000.0;
          tx_rates[tick_count] = tx_rate;
          tx_time_passed[tick_count] = rate_duration;
        }
        tick_count++;
      }
      uint32_t bucket = rate_time_elapsed.count() / 1000.0;
      if (bucket < times.size())
      {
        times[bucket].tx_count += tx_count;
      }
    }
  };

}
