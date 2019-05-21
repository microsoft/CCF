// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/histogram.h"
#include "ds/logger.h"

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

    nlohmann::json get_histogram_results()
    {
      nlohmann::json result;
      nlohmann::json hist;
      result["low"] = histogram.get_low();
      result["high"] = histogram.get_high();
      result["overflow"] = histogram.get_overflow();
      result["underflow"] = histogram.get_underflow();
      auto range_counts = histogram.get_range_count();
      for (auto const& [range, count] : range_counts)
      {
        if (count > 0)
        {
          hist[range] = count;
        }
      }
      result["buckets"] = hist;
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
    nlohmann::json get_metrics()
    {
      nlohmann::json result;
      result["histogram"] = get_histogram_results();
      result["tx_rates"] = get_tx_rates();

      return result;
    }

    void track_tx_rates(
      const std::chrono::milliseconds& elapsed, size_t tx_count)
    {
      // calculate how many tx/sec we have processed in this tick
      auto duration = elapsed.count() / 1000.0;
      auto tx_rate = tx_count / duration;
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
    }
  };
}