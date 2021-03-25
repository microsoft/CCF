// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef _MSC_VER
#  include <intrin.h>
#endif

#include <cassert>
#include <chrono>
#include <limits>
#include <map>
#include <mutex>
#include <utility>

namespace histogram
{
  static constexpr size_t bits = sizeof(size_t) * 8;

  constexpr bool bits64()
  {
    return bits == 64;
  }

  inline size_t clz(size_t x)
  {
#if defined(_MSC_VER)
    unsigned long index;

    if (bits64())
      _BitScanReverse64(&index, x);
    else
      _BitScanReverse(&index, (unsigned long)x);

    return bits - index - 1;
#else
    return __builtin_clzl(x);
#endif
  }

  constexpr size_t clz_const(size_t x)
  {
    size_t n = 0;

    for (int i = bits - 1; i >= 0; i--)
    {
      size_t mask = (size_t)1 << i;

      if ((x & mask) == mask)
        return n;

      n++;
    }

    return n;
  }

  inline size_t next_pow2(size_t x)
  {
    // Correct for numbers [0..MAX_SIZE >> 1).
    // Returns 1 for x > (MAX_SIZE >> 1).
    if (x <= 2)
      return x;

    return (size_t)1 << (bits - clz(x - 1));
  }

  inline size_t next_pow2_bits(size_t x)
  {
    // Correct for numbers [1..MAX_SIZE].
    // Returns -1 for 0. Approximately 7 cycles.
    return bits - clz(x) - (!(x & (x - 1)));
  }

  constexpr size_t next_pow2_const(size_t x)
  {
    if (x <= 2)
      return x;

    return (size_t)1 << (bits - clz_const(x - 1));
  }

  constexpr size_t next_pow2_bits_const(size_t x)
  {
    return bits - clz_const(x) - (!(x & (x - 1)));
  }

  template <class H>
  class Global;

  template <class V, V LOW, V HIGH, size_t SIGNIFICANT_BITS = 3>
  class Histogram
  {
  public:
    using Value = V;
    using This = Histogram<V, LOW, HIGH, SIGNIFICANT_BITS>;

  private:
    friend Global<This>;

    static_assert(LOW >= 1, "LOW must be at least 1");
    static_assert(LOW < HIGH, "LOW must be less than HIGH");
    static_assert(LOW == next_pow2_const(LOW), "LOW must be a power of 2");
    static_assert(HIGH == next_pow2_const(HIGH), "HIGH must be a power of 2");
    static_assert(
      (SIGNIFICANT_BITS >= 1) && (SIGNIFICANT_BITS <= 6),
      "SIGNIFICANT_BITS must be from 1 to 6");

    static constexpr size_t LOW_BITS = next_pow2_bits_const(LOW);
    static constexpr size_t HIGH_BITS = next_pow2_bits_const(HIGH);
    static constexpr size_t BUCKETS = (HIGH_BITS - LOW_BITS - 1)
      << (SIGNIFICANT_BITS - 1);
    static constexpr size_t SIGNIFICANT = (size_t)1 << SIGNIFICANT_BITS;
    static constexpr size_t SIGNIFICANT_MASK = (SIGNIFICANT >> 1) - 1;

    V low;
    V high;

    size_t underflow = 0;
    size_t overflow = 0;
    size_t count[BUCKETS];

    This* next;

  public:
    Histogram(Global<This>& g) :
      low((std::numeric_limits<V>::max)()),
      high((std::numeric_limits<V>::min)()),
      next(nullptr)
    {
      g.add(*this);
    }

    void record(V value)
    {
      if (value < low)
        low = value;

      if (value > high)
        high = value;

      if (value < LOW)
      {
        underflow++;
      }
      else if (value >= HIGH)
      {
        overflow++;
      }
      else
      {
        auto i = get_index(value);
        assert(i < BUCKETS);
        count[i]++;
      }
    }

    V get_low()
    {
      return low;
    }

    V get_high()
    {
      return high;
    }

    size_t get_underflow()
    {
      return underflow;
    }

    size_t get_overflow()
    {
      return overflow;
    }

    size_t get_buckets()
    {
      return BUCKETS;
    }

    size_t get_count(size_t index)
    {
      if (index >= BUCKETS)
        return 0;

      return count[index];
    }

    std::pair<V, V> get_range(size_t index)
    {
      if (index >= BUCKETS)
        return std::make_pair(HIGH, HIGH);

      return std::make_pair(get_value(index), get_value(index + 1) - 1);
    }

    void add(Histogram<V, LOW, HIGH, SIGNIFICANT_BITS>& that)
    {
      low = std::min(low, that.low);
      high = std::max(high, that.high);
      underflow += that.underflow;
      overflow += that.overflow;

      for (size_t i = 0; i < BUCKETS; i++)
        count[i] += that.count[i];
    }

    std::map<std::pair<size_t, size_t>, size_t> get_range_count()
    {
      std::map<std::pair<size_t, size_t>, size_t> range_counts;

      for (size_t i = 0; i < BUCKETS; i++)
      {
        auto r = get_range(i);
        range_counts.insert({{std::get<0>(r), std::get<1>(r)}, count[i]});
      }
      return range_counts;
    }

  private:
    size_t get_index(V value)
    {
      auto v = value >> LOW_BITS;
      auto s = bits - clz(v);

      if (s <= SIGNIFICANT_BITS)
        return v - 1;

      auto shift = s - SIGNIFICANT_BITS;
      auto m1 = (v >> shift) & SIGNIFICANT_MASK;
      auto m2 = (shift + 1) << (SIGNIFICANT_BITS - 1);
      return m1 + m2 - 1;
    }

    V get_value(size_t index)
    {
      auto i = index + 1;

      if (i < SIGNIFICANT)
        return (V)i;

      auto shift = (i >> (SIGNIFICANT_BITS - 1)) - 1;
      auto m1 = (i & SIGNIFICANT_MASK) << shift;
      auto m2 = (size_t)1 << (shift + SIGNIFICANT_BITS - 1);
      return (m1 + m2) << LOW_BITS;
    }
  };

  template <class H>
  class Global
  {
  private:
    std::mutex m;
    std::string name;
    std::string file;
    size_t line;
    H* head;

  public:
    Global(const std::string& name_, const std::string& file_, size_t line_) :
      name(name_),
      file(file_),
      line(line_),
      head(nullptr)
    {}

    ~Global() {}

    void add(H& histogram)
    {
      std::lock_guard<std::mutex> lock(m);
      histogram.next = head;
      head = &histogram;
    }
  };

  template <class H>
  class Measure
  {
  private:
    H& histogram;
    std::chrono::high_resolution_clock::time_point t;
    bool stopped;

  public:
    Measure(H& histogram_) : histogram(histogram_), stopped(false)
    {
      t = std::chrono::high_resolution_clock::now();
    }

    virtual ~Measure()
    {
      stop();
    }

    void stop()
    {
      auto e = std::chrono::high_resolution_clock::now() - t;

      if (!stopped)
      {
        histogram.record((H::Value)(e.count()));
        stopped = true;
      }
    }
  };

#ifdef USE_MEASURE
#  define MEASURE(id) \
    static histogram::Global<histogram::Histogram<uint64_t, 1, 1 << 16>> \
      id##_global(#id, __FILE__, __LINE__); \
    static thread_local histogram::Histogram<uint64_t, 1, 1 << 16> id##_local( \
      id##_global); \
    histogram::Measure<histogram::Histogram<uint64_t, 1, 1 << 16>> id( \
      id##_local);

#  define STOP_MEASURE(id) id.stop();
#else
#  define MEASURE(id)
#  define STOP_MEASURE(id)
#endif
}
