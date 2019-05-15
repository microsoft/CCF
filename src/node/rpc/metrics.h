// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/histogram.h"

#include <fstream>
#include <nlohmann/json.hpp>

#define HIST_MAX (1 << 17)
#define HIST_MIN 1
#define HIST_BUCKET_GRANULARITY 5
#define TX_RATES 1000

namespace metrics
{
  class Metrics
  {
  private:
    size_t tick_count = 0;
    double tx_time_passed[TX_RATES] = {};
    int tx_rates[TX_RATES] = {};
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
      for (int i = 0; i < TX_RATES; ++i)
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
    ~Metrics() {}

    nlohmann::json get_metrics()
    {
      nlohmann::json result;
      result["histogram"] = get_histogram_results();
      result["tx_rates"] = get_tx_rates();

      std::ofstream file("metrics.json");
      file << result;
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
        auto rate_duration = rate_time_elapsed.count() / 1000.0;
      }
      tick_count++;
    }
  }
};
        tick_count++;
      }
    }
  };
}