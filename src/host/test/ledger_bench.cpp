// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/serialized.h"
#include "host/ledger.h"
#include "kv/serialised_entry_format.h"

#define PICOBENCH_IMPLEMENT
#include <picobench/picobench.hpp>

using namespace asynchost;

namespace
{
  static constexpr size_t kibibyte = 1024;
  static constexpr size_t mebibyte = 1024 * kibibyte;
  static constexpr size_t entry_count = 10'000;

  struct RemoveDirectory
  {
    fs::path path;

    ~RemoveDirectory()
    {
      std::error_code error;
      fs::remove_all(path, error);
    }
  };

  std::vector<uint8_t> make_entry(size_t body_size)
  {
    std::vector<uint8_t> entry(
      ccf::kv::serialised_entry_header_size + body_size);
    auto* data = entry.data();
    auto size = entry.size();

    ccf::kv::SerialisedEntryHeader header = {};
    header.set_size(body_size);
    serialized::write(data, size, header);
    return entry;
  }

  void prepare_empty(LedgerFile&) {}

  void prepare_10000_entries(LedgerFile& file)
  {
    const auto entry = make_entry(sizeof(uint32_t));
    for (size_t index = 0; index < entry_count; ++index)
    {
      file.write_entry(entry.data(), entry.size(), false);
    }
    file.complete();
  }

  template <size_t FileSize>
  void prepare_sized_file(LedgerFile& file)
  {
    static_assert(
      FileSize > sizeof(size_t) + sizeof(uint32_t) +
        ccf::kv::serialised_entry_header_size);
    const auto entry_size = FileSize - sizeof(size_t) - sizeof(uint32_t);
    const auto body_size = entry_size - ccf::kv::serialised_entry_header_size;
    const auto entry = make_entry(body_size);
    file.write_entry(entry.data(), entry.size(), false);
    file.complete();
  }

  template <bool CloseAndReopen>
  void benchmark_rename(
    picobench::state& state,
    const std::string& fixture_name,
    void (*prepare)(LedgerFile&))
  {
    const auto directory = fs::path(
      fmt::format("ledger_rename_bench_{}_{}", fixture_name, CloseAndReopen));
    fs::remove_all(directory);
    fs::create_directory(directory);
    RemoveDirectory remove_directory{directory};

    {
      LedgerFile file(directory, 1);
      prepare(file);

      bool renamed = false;
      state.start_timer();
      for ([[maybe_unused]] auto iteration : state)
      {
        file.rename(renamed ? "ledger_1" : "ledger_1.renamed", CloseAndReopen);
        renamed = !renamed;
      }
      state.stop_timer();
    }
  }

  static void rename_empty(picobench::state& state)
  {
    benchmark_rename<false>(state, "empty", prepare_empty);
  }

  static void rename_empty_close_and_reopen(picobench::state& state)
  {
    benchmark_rename<true>(state, "empty", prepare_empty);
  }

  static void rename_10000_entries(picobench::state& state)
  {
    benchmark_rename<false>(state, "10000_entries", prepare_10000_entries);
  }

  static void rename_10000_entries_close_and_reopen(picobench::state& state)
  {
    benchmark_rename<true>(state, "10000_entries", prepare_10000_entries);
  }

  static void rename_1_mib(picobench::state& state)
  {
    benchmark_rename<false>(state, "1_mib", prepare_sized_file<mebibyte>);
  }

  static void rename_1_mib_close_and_reopen(picobench::state& state)
  {
    benchmark_rename<true>(state, "1_mib", prepare_sized_file<mebibyte>);
  }

  static void rename_10_mib(picobench::state& state)
  {
    benchmark_rename<false>(state, "10_mib", prepare_sized_file<10 * mebibyte>);
  }

  static void rename_10_mib_close_and_reopen(picobench::state& state)
  {
    benchmark_rename<true>(state, "10_mib", prepare_sized_file<10 * mebibyte>);
  }

  static void rename_100_mib(picobench::state& state)
  {
    benchmark_rename<false>(
      state, "100_mib", prepare_sized_file<100 * mebibyte>);
  }

  static void rename_100_mib_close_and_reopen(picobench::state& state)
  {
    benchmark_rename<true>(
      state, "100_mib", prepare_sized_file<100 * mebibyte>);
  }

  const std::vector<int> rename_iterations = {20};
}

PICOBENCH_SUITE("rename empty ledger file");
PICOBENCH(rename_empty).iterations(rename_iterations).baseline();
PICOBENCH(rename_empty_close_and_reopen).iterations(rename_iterations);

PICOBENCH_SUITE("rename ledger file with 10000 entries");
PICOBENCH(rename_10000_entries).iterations(rename_iterations).baseline();
PICOBENCH(rename_10000_entries_close_and_reopen).iterations(rename_iterations);

PICOBENCH_SUITE("rename 1 MiB ledger file");
PICOBENCH(rename_1_mib).iterations(rename_iterations).baseline();
PICOBENCH(rename_1_mib_close_and_reopen).iterations(rename_iterations);

PICOBENCH_SUITE("rename 10 MiB ledger file");
PICOBENCH(rename_10_mib).iterations(rename_iterations).baseline();
PICOBENCH(rename_10_mib_close_and_reopen).iterations(rename_iterations);

PICOBENCH_SUITE("rename 100 MiB ledger file");
PICOBENCH(rename_100_mib).iterations(rename_iterations).baseline();
PICOBENCH(rename_100_mib_close_and_reopen).iterations(rename_iterations);

int main(int argc, char* argv[])
{
  ccf::logger::config::level() = ccf::LoggerLevel::FATAL;

  picobench::runner runner;
  runner.parse_cmd_line(argc, argv);
  return runner.run();
}