// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/json.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>

#define BENCHMARK_TYPES \
  struct Record \
  { \
    uint64_t id = 0; \
    std::string msg; \
    bool record_claim = false; \
  }; \
  struct Batch \
  { \
    std::vector<Record> records; \
    std::optional<std::string> next_link; \
  };

namespace json_bench
{
  BENCHMARK_TYPES

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Record);
  DECLARE_JSON_REQUIRED_FIELDS(Record, id, msg);
  DECLARE_JSON_OPTIONAL_FIELDS(Record, record_claim);
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Batch);
  DECLARE_JSON_REQUIRED_FIELDS(Batch, records);
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(Batch, next_link, "@nextLink");
}

#include "ccf/json.h"

#undef BENCHMARK_TYPES

#define PICOBENCH_UNIQUE_SYM_SUFFIX __COUNTER__
#define PICOBENCH_IMPLEMENT
#include <picobench/picobench.hpp>

namespace
{
  using Json = nlohmann::json;
  constexpr size_t input_count = 8;

  enum class Payload : std::uint8_t
  {
    Small,
    Large,
    Batch
  };

  enum class Path : std::uint8_t
  {
    Dom,
    Direct,
    Reused
  };

  template <class T>
  inline void do_not_optimize(const T& value)
  {
    asm volatile("" : : "r,m"(value) : "memory");
  }

  inline void clobber_memory()
  {
    asm volatile("" : : : "memory");
  }

  template <typename Record>
  Record make_record(size_t index, size_t message_size)
  {
    Record value{};
    value.id = 42 + index;
    value.msg =
      std::string(message_size, static_cast<char>('a' + (index % 26)));
    value.msg.replace(0, 7, "line\n\"\\");
    value.record_claim = index % 2 != 0;
    return value;
  }

  template <Payload P, typename Record, typename Batch>
  auto make_payload(size_t index)
  {
    if constexpr (P == Payload::Batch)
    {
      Batch value{};
      for (size_t i = 0; i < 64; ++i)
      {
        value.records.push_back(make_record<Record>((index * 64) + i, 64));
      }
      if (index % 2 != 0)
      {
        value.next_link = "/records?from=" + std::to_string(index + 1);
      }
      return value;
    }
    else
    {
      return make_record<Record>(index, P == Payload::Small ? 32 : 4096);
    }
  }

  template <Payload P>
  struct Inputs
  {
    using Value =
      decltype(make_payload<P, json_bench::Record, json_bench::Batch>(0));
    std::array<Value, input_count> values;
    std::array<std::string, input_count> wire;
  };

  template <Payload P>
  const Inputs<P>& inputs()
  {
    static const auto data = [] {
      Inputs<P> value{};
      for (size_t i = 0; i < input_count; ++i)
      {
        value.values[i] =
          make_payload<P, json_bench::Record, json_bench::Batch>(i);
        value.wire[i] = Json(value.values[i]).dump();
      }
      return value;
    }();
    return data;
  }

  template <Payload P>
  void verify()
  {
    const auto& data = inputs<P>();
    for (size_t i = 0; i < input_count; ++i)
    {
      const auto expected = Json::parse(data.wire[i]);
      const auto encoded = ccf::json::write(data.values[i]);
      std::string reused = "replace previous output";
      ccf::json::write(data.values[i], reused);
      const auto original_decoded =
        ccf::parse_json_safe(data.wire[i])
          .template get<typename Inputs<P>::Value>();
      const auto direct_decoded =
        ccf::json::read<typename Inputs<P>::Value>(data.wire[i]);
      if (
        Json(data.values[i]) != expected || Json::parse(encoded) != expected ||
        Json::parse(reused) != expected || Json(original_decoded) != expected ||
        Json(direct_decoded) != expected ||
        encoded.size() != data.wire[i].size() || reused != encoded)
      {
        throw std::logic_error(
          "Benchmark paths do not preserve equivalent payloads");
      }
    }
  }

  template <typename T>
  size_t observe(const T& value)
  {
    if constexpr (requires { value.records; })
    {
      return value.records.size() + value.records.front().id +
        value.records.back().id + value.records.front().msg.size();
    }
    else
    {
      return value.id + value.msg.size() + value.record_claim;
    }
  }

  template <Payload P, Path Method>
  void serialise(picobench::state& state)
  {
    const auto& data = inputs<P>();
    std::string reused;
    if constexpr (Method == Path::Reused)
    {
      size_t capacity = 0;
      for (const auto& wire : data.wire)
      {
        capacity = std::max(capacity, wire.size());
      }
      reused.reserve(capacity);
    }
    size_t result = 0;
    clobber_memory();
    {
      picobench::scope scope(state);
      for (int i = 0; i < state.iterations(); ++i)
      {
        const auto index = static_cast<size_t>(i) % input_count;
        if constexpr (Method == Path::Reused)
        {
          ccf::json::write(data.values[index], reused);
          result += reused.size();
          do_not_optimize(reused);
        }
        else
        {
          const auto output = [&] {
            if constexpr (Method == Path::Dom)
            {
              return Json(data.values[index]).dump();
            }
            else
            {
              return ccf::json::write(data.values[index]);
            }
          }();
          result += output.size();
          do_not_optimize(output);
        }
        clobber_memory();
      }
    }
    state.set_result(result);
  }

  template <Payload P, Path Method>
  void deserialise(picobench::state& state)
  {
    const auto& data = inputs<P>();
    size_t result = 0;
    clobber_memory();
    {
      picobench::scope scope(state);
      for (int i = 0; i < state.iterations(); ++i)
      {
        const auto& wire = data.wire[static_cast<size_t>(i) % input_count];
        const auto output = [&] {
          if constexpr (Method == Path::Dom)
          {
            return ccf::parse_json_safe(wire)
              .template get<typename Inputs<P>::Value>();
          }
          else
          {
            return ccf::json::read<typename Inputs<P>::Value>(wire);
          }
        }();
        result += observe(output);
        do_not_optimize(output);
        clobber_memory();
      }
    }
    state.set_result(result);
  }
}

#define SERIALISE_SUITE(PAYLOAD, NAME) \
  PICOBENCH_SUITE(NAME); \
  PICOBENCH((serialise<Payload::PAYLOAD, Path::Dom>)).label("dom").baseline(); \
  PICOBENCH((serialise<Payload::PAYLOAD, Path::Direct>)) \
    .label("direct_fresh"); \
  PICOBENCH((serialise<Payload::PAYLOAD, Path::Reused>)).label("direct_reused");

#define DESERIALISE_SUITE(PAYLOAD, NAME) \
  PICOBENCH_SUITE(NAME); \
  PICOBENCH((deserialise<Payload::PAYLOAD, Path::Dom>)) \
    .label("dom") \
    .baseline(); \
  PICOBENCH((deserialise<Payload::PAYLOAD, Path::Direct>)) \
    .label("direct_fresh");

SERIALISE_SUITE(Small, "small serialise")
DESERIALISE_SUITE(Small, "small deserialise")
SERIALISE_SUITE(Large, "large serialise")
DESERIALISE_SUITE(Large, "large deserialise")
SERIALISE_SUITE(Batch, "batch serialise")
DESERIALISE_SUITE(Batch, "batch deserialise")

int main(int argc, char** argv)
{
  try
  {
    verify<Payload::Small>();
    verify<Payload::Large>();
    verify<Payload::Batch>();
    if (argc == 2 && std::string_view(argv[1]) == "--verify-only")
    {
      std::cout << "All paths preserve 8 distinct inputs per payload\n";
      const auto print_sizes = [](const char* name, const auto& wires) {
        const auto [smallest, largest] = std::minmax_element(
          wires.begin(), wires.end(), [](const auto& a, const auto& b) {
            return a.size() < b.size();
          });
        std::cout << name << ": " << smallest->size() << "-" << largest->size()
                  << " bytes\n";
      };
      print_sizes("small", inputs<Payload::Small>().wire);
      print_sizes("large", inputs<Payload::Large>().wire);
      print_sizes("batch", inputs<Payload::Batch>().wire);
      return 0;
    }
#ifndef NDEBUG
    std::cerr << "Warning: use a Release build for performance comparisons\n";
#endif
    picobench::runner runner;
    runner.set_default_state_iterations({1000, 10000});
    runner.set_default_samples(5);
    runner.set_compare_results_across_benchmarks(true);
    runner.set_compare_results_across_samples(true);
    if (!runner.parse_cmd_line(argc, argv))
    {
      return 1;
    }
    return runner.run();
  }
  catch (const std::exception& error)
  {
    std::cerr << "JSON serialization benchmark failed: " << error.what()
              << '\n';
    return 1;
  }
}
