// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/strategies/seqnos_by_key_bucketed.h"
#include "ccf/indexing/strategies/seqnos_by_key_paged.h"
#include "indexing/enclave_lfs_access.h"
#include "indexing/test/common.h"

#include <CLI11/CLI11.hpp>
#include <algorithm>
#include <cmath>
#include <iostream>
#include <numeric>
#include <random>
#include <sys/stat.h>

namespace
{
  using namespace ccf::indexing;
  using ccf::SeqNo;
  using ccf::SeqNoCollection;
  using Clock = std::chrono::steady_clock;
  using Bucketed = strategies::SeqnosByKey_Bucketed<MapA>;
  using Paged = strategies::SeqnosByKey_Paged<MapA>;

  double elapsed_ms(Clock::time_point start)
  {
    return std::chrono::duration<double, std::milli>(Clock::now() - start)
      .count();
  }

  struct Options
  {
    size_t entries = 4096;
    size_t queries = 16;
    size_t repetitions = 3;
    size_t page_bytes = 4096;
    size_t cache_bytes = 65536;
    size_t bucket_size = 1000;
    size_t bucket_cache = 10;
    std::string workload;
    std::string output;
  };

  struct Counters
  {
    size_t writes = 0;
    size_t write_bytes = 0;
    size_t removals = 0;
    size_t reads = 0;
    size_t read_bytes = 0;
    size_t peak_queue = 0;

    nlohmann::json since(const Counters& before) const
    {
      return {
        {"writes", writes - before.writes},
        {"write_plaintext_bytes", write_bytes - before.write_bytes},
        {"removals", removals - before.removals},
        {"reads", reads - before.reads},
        {"read_plaintext_bytes", read_bytes - before.read_bytes}};
    }
  };

  class MeasuredLFS : public EnclaveLFSAccess
  {
    std::vector<FetchResultPtr> reads;

  public:
    Counters counters;

    using EnclaveLFSAccess::EnclaveLFSAccess;

    void observe_queue()
    {
      size_t n = 0;
      bool active = false;
      bool paused = false;
      tasks->get_queue_summary(n, active, paused);
      counters.peak_queue = std::max(counters.peak_queue, n);
    }

    size_t queued()
    {
      observe_queue();
      size_t n = 0;
      bool active = false;
      bool paused = false;
      tasks->get_queue_summary(n, active, paused);
      return n;
    }

    void collect()
    {
      for (auto it = reads.begin(); it != reads.end();)
      {
        const auto status = (*it)->fetch_result.load();
        if (status == FetchResult::FetchResultType::Fetching)
        {
          ++it;
          continue;
        }
        if (status != FetchResult::FetchResultType::Loaded)
          throw std::runtime_error("Benchmark LFS read failed: " + (*it)->key);
        ++counters.reads;
        counters.read_bytes += (*it)->contents.size();
        it = reads.erase(it);
      }
    }

    void store(const LFSKey& key, LFSContents&& contents) override
    {
      ++counters.writes;
      counters.write_bytes += contents.size();
      EnclaveLFSAccess::store(key, std::move(contents));
      observe_queue();
    }

    LFSBatchResult apply_batch(
      LFSWrites&& writes, std::vector<LFSKey>&& removals) override
    {
      counters.writes += writes.size();
      counters.removals += removals.size();
      for (const auto& [key, blob] : writes)
        counters.write_bytes += blob.size();
      auto result =
        EnclaveLFSAccess::apply_batch(std::move(writes), std::move(removals));
      observe_queue();
      return result;
    }

    FetchResultPtr fetch(
      const LFSKey& key,
      size_t max_bytes = std::numeric_limits<size_t>::max()) override
    {
      auto result = EnclaveLFSAccess::fetch(key, max_bytes);
      if (std::find(reads.begin(), reads.end(), result) == reads.end())
        reads.push_back(result);
      observe_queue();
      return result;
    }
  };

  struct Workload
  {
    std::string name;
    size_t width = 1;
  };

  struct Dataset
  {
    std::vector<std::vector<uint8_t>> ledger;
    std::map<std::string, std::vector<SeqNo>> model;
    std::vector<std::string> query_keys;
    SeqNo base_transactions = 0;
    size_t base_entries = 0;
  };

  Dataset make_dataset(const Workload& workload, size_t entries)
  {
    Dataset dataset;
    ccf::kv::Store store;
    store.initialise_term(1);
    auto consensus = std::make_shared<AllCommittableConsensus>();
    store.set_consensus(consensus);
    store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
    std::mt19937 random(42);
    size_t entry = 0;
    const auto generate = [&](size_t count, bool base) {
      for (size_t emitted = 0; emitted < count;)
      {
        const auto width = std::min(workload.width, count - emitted);
        std::vector<std::string> keys;
        auto tx = store.create_tx();
        for (size_t i = 0; i < width; ++i, ++entry)
        {
          std::string key;
          if (workload.name == "hot")
            key = "hot";
          else if (workload.name == "uniform")
            key = fmt::format("key-{:08}", random() % 256);
          else if (workload.name == "skewed")
            key = fmt::format(
              "key-{:08}",
              random() % 10 == 0 ? 16 + random() % 1024 : random() % 16);
          else if (workload.name == "sparse")
            key = entry % 128 == 0 ?
              fmt::format("rare-{:08}", (entry / 128) % 16) :
              "noise";
          else
            key = fmt::format("key-{:08}", entry);
          tx.rw(map_a)->put(key, "value");
          keys.push_back(key);
          if (base && key != "noise")
            dataset.query_keys.push_back(key);
        }
        if (tx.commit() != ccf::kv::CommitResult::SUCCESS)
          throw std::runtime_error("Benchmark transaction commit failed");
        const auto seqno = tx.get_txid()->seqno;
        for (const auto& key : keys)
          dataset.model[key].push_back(seqno);
        emitted += width;
      }
    };
    generate(entries, true);
    dataset.base_transactions = store.current_version();
    dataset.base_entries = entries;
    generate(std::max<size_t>(1, entries / 8), false);
    for (const auto& entry_ : consensus->replica)
    {
      const auto& data = std::get<1>(entry_);
      dataset.ledger.emplace_back(data->begin(), data->end());
    }
    return dataset;
  }

  // Return one historical store at a time, avoiding wasted speculative
  // deserialisation while the paged strategy is applying backpressure.
  class ReplayFetcher : public TestTransactionFetcher
  {
    const Dataset& dataset;
    std::optional<SeqNo> pending;
    ccf::kv::ReadOnlyStorePtr ready;

  public:
    size_t decoded = 0;

    ReplayFetcher(const Dataset& dataset_) : dataset(dataset_) {}

    std::vector<ccf::kv::ReadOnlyStorePtr> fetch_transactions(
      const SeqNoCollection& seqnos) override
    {
      if (seqnos.empty())
        return {};
      const auto first = *seqnos.begin();
      if (ready)
      {
        if (ready->current_txid().seqno != first)
          throw std::logic_error("Out-of-order benchmark replay");
        return {std::exchange(ready, nullptr)};
      }
      pending = first;
      return {};
    }

    void complete()
    {
      if (pending)
      {
        const auto& data = dataset.ledger.at(*pending - 1);
        ready = deserialise_transaction(*pending, data.data(), data.size());
        if (!ready)
          throw std::runtime_error("Benchmark ledger deserialisation failed");
        ++decoded;
        pending.reset();
      }
    }
  };

  nlohmann::json storage()
  {
    size_t files = 0;
    size_t bytes = 0;
    size_t allocated = 0;
    for (const auto& file : std::filesystem::directory_iterator(".index"))
    {
      struct stat st = {};
      if (::stat(file.path().c_str(), &st) != 0)
        throw std::runtime_error("Cannot stat benchmark LFS file");
      ++files;
      bytes += file.file_size();
      allocated += st.st_blocks * 512;
    }
    return {
      {"files", files},
      {"encrypted_bytes", bytes},
      {"allocated_bytes", allocated}};
  }

  nlohmann::json distribution(std::vector<double> samples)
  {
    std::sort(samples.begin(), samples.end());
    const auto percentile = [&](double p) {
      return samples.at(static_cast<size_t>(std::ceil(p * samples.size())) - 1);
    };
    return {
      {"p50", percentile(0.5)},
      {"p95", percentile(0.95)},
      {"mean",
       std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size()}};
  }

  void check_result(
    const Dataset& dataset,
    const std::string& key,
    SeqNo from,
    SeqNo to,
    const SeqNoCollection& actual)
  {
    std::vector<SeqNo> expected;
    if (const auto it = dataset.model.find(key); it != dataset.model.end())
      for (auto seqno : it->second)
        if (seqno >= from && seqno <= to)
          expected.push_back(seqno);
    if (
      expected.size() != actual.size() ||
      !std::equal(expected.begin(), expected.end(), actual.begin()))
      throw std::runtime_error(fmt::format(
        "Incomplete/incorrect {} query [{}, {}]: expected {}, got {}",
        key,
        from,
        to,
        expected.size(),
        actual.size()));
  }

  template <typename Index>
  nlohmann::json run(
    const Options& options,
    const Workload& workload,
    const Dataset& dataset,
    size_t repetition)
  {
    ccf::tasks::JobBoard board;
    auto lfs = std::make_shared<MeasuredLFS>(board);
    ccf::AbstractNodeContext context;
    context.install_subsystem(lfs);
    std::shared_ptr<Index> index;
    if constexpr (std::is_same_v<Index, Paged>)
      index = std::make_shared<Index>(
        map_a, context, options.page_bytes, options.cache_bytes);
    else
      index = std::make_shared<Index>(
        map_a, context, options.bucket_size, options.bucket_cache);
    auto fetcher = std::make_shared<ReplayFetcher>(dataset);
    Strategy& strategy = *index;
    Indexer indexer(fetcher);
    if (!indexer.install_strategy(index))
      throw std::logic_error("Cannot install benchmark strategy");
    SeqNo committed = dataset.base_transactions;
    const auto pump = [&]() {
      fetcher->complete();
      // get_task() uses a zero-duration condition-variable wait when empty.
      // Do not charge idle worker scheduling to every in-memory retry.
      if (board.get_summary().pending_tasks != 0)
      {
        if (auto task = board.get_task())
          task->do_task();
      }
      lfs->collect();
    };
    const auto check_deadline = [](Clock::time_point start) {
      if (elapsed_ms(start) > 60000)
        throw std::runtime_error("Benchmark phase exceeded 60 seconds");
    };
    const auto catch_up = [&]() {
      const auto start = Clock::now();
      while (index->get_indexed_watermark().seqno < committed ||
             !index->next_requested().has_value() || lfs->queued())
      {
        check_deadline(start);
        indexer.update_strategies(step_time, {1, committed});
        pump();
      }
      while (board.get_summary().pending_tasks != 0)
      {
        if (auto task = board.get_task())
          task->do_task();
      }
      lfs->collect();
      if (strategy.describe().value("failed", false))
        throw std::runtime_error("Benchmark index failed");
    };

    const auto build_start = Clock::now();
    catch_up();
    const auto build_ms = elapsed_ms(build_start);
    nlohmann::json output{
      {"strategy", std::is_same_v<Index, Paged> ? "paged" : "bucketed"},
      {"workload", workload.name},
      {"keys_per_transaction", workload.width},
      {"repetition", repetition},
      {"entries", dataset.base_entries},
      {"transactions", dataset.base_transactions},
      {"build_ms", build_ms},
      {"build_lfs", lfs->counters.since({})},
      {"build_peak_queue", lfs->counters.peak_queue},
      {"storage", storage()},
      {"index_after_build", strategy.describe()}};

    size_t api_calls = 0;
    size_t chunks = 0;
    const auto query = [&](const std::string& key, SeqNo from, SeqNo to) {
      SeqNoCollection result;
      const auto start = Clock::now();
      SeqNo span = to - from;
      if constexpr (std::is_same_v<Index, Bucketed>)
        span = index->max_requestable_range();
      for (auto begin = from; begin <= to;)
      {
        const auto end = begin + std::min(span, to - begin);
        ++chunks;
        while (true)
        {
          ++api_calls;
          auto part = index->get_write_txs_in_range(key, begin, end);
          if (part)
          {
            for (auto seqno : *part)
              result.insert(seqno);
            break;
          }
          check_deadline(start);
          indexer.update_strategies(step_time, {1, committed});
          pump();
          if (index->get_indexed_watermark().seqno == 0)
            throw std::runtime_error("Benchmark query triggered index rebuild");
        }
        begin = end + 1;
      }
      lfs->collect();
      return result;
    };

    std::mt19937 random(1234 + repetition);
    auto queries = nlohmann::json::array();
    for (const std::string pattern :
         {"recent", "historical-window", "full-history", "missing"})
    {
      std::vector<double> first;
      std::vector<double> warm;
      const auto before = lfs->counters;
      const auto calls_before = api_calls;
      const auto chunks_before = chunks;
      for (size_t sample = 0; sample < options.queries; ++sample)
      {
        const auto& key =
          dataset.query_keys.at(random() % dataset.query_keys.size());
        const auto selected_key = pattern != "missing" ? key :
          sample % 3 == 0                              ? "__missing__" :
          sample % 3 == 1                              ? key + "-missing" :
                                                         "zz-missing";
        SeqNo from = 1;
        SeqNo to = dataset.base_transactions;
        if (pattern == "recent")
          from = to > 63 ? to - 63 : 1;
        else if (pattern == "historical-window")
        {
          from = std::max<SeqNo>(1, to / 3);
          to = std::min(to, from + 63);
        }
        for (size_t pass = 0; pass < 2; ++pass)
        {
          const auto start = Clock::now();
          const auto result = query(selected_key, from, to);
          const auto ms = elapsed_ms(start);
          check_result(dataset, selected_key, from, to, result);
          (pass == 0 ? first : warm).push_back(ms);
        }
      }
      queries.push_back(
        {{"pattern", pattern},
         {"first_ms", distribution(first)},
         {"warm_ms", distribution(warm)},
         {"first_samples_ms", first},
         {"warm_samples_ms", warm},
         {"api_calls", api_calls - calls_before},
         {"chunks", chunks - chunks_before},
         {"lfs", lfs->counters.since(before)}});
    }
    output["queries"] = queries;
    const auto mixed_start = Clock::now();
    const auto mixed_before = lfs->counters;
    size_t rounds = 0;
    while (committed < dataset.ledger.size())
    {
      const auto old = committed;
      committed = std::min<SeqNo>(dataset.ledger.size(), committed + 16);
      const auto& key =
        dataset.query_keys.at(random() % dataset.query_keys.size());
      const auto result = query(key, 1, old);
      check_result(dataset, key, 1, old, result);
      catch_up();
      ++rounds;
    }
    output["mixed"] = {
      {"ms", elapsed_ms(mixed_start)},
      {"rounds", rounds},
      {"additional_transactions",
       dataset.ledger.size() - dataset.base_transactions},
      {"lfs", lfs->counters.since(mixed_before)}};
    output["decoded_transactions"] = fetcher->decoded;
    if (fetcher->decoded != dataset.ledger.size())
      throw std::logic_error("Benchmark did not replay every transaction once");
    board.shutdown();
    return output;
  }
}

int main(int argc, char** argv)
{
  Options options;
  CLI::App app{"Compare complete indexing pipelines using encrypted disk LFS"};
  app.add_option("--entries", options.entries)->check(CLI::PositiveNumber);
  app.add_option("--queries", options.queries)->check(CLI::PositiveNumber);
  app.add_option("--repetitions", options.repetitions)
    ->check(CLI::PositiveNumber);
  app.add_option("--page-bytes", options.page_bytes)
    ->check(CLI::Range(512, 1048576));
  app.add_option("--cache-bytes", options.cache_bytes)
    ->check(CLI::NonNegativeNumber);
  app.add_option("--bucket-size", options.bucket_size)
    ->check(CLI::PositiveNumber);
  app.add_option("--bucket-cache", options.bucket_cache)
    ->check(CLI::Range(2, 1000000));
  app.add_option("--workload", options.workload, "Run only this workload");
  app.add_option("--output", options.output, "JSON results path")->required();
  CLI11_PARSE(app, argc, argv);
  ccf::logger::config::level() = ccf::LoggerLevel::FAIL;
  try
  {
    const auto output_path = std::filesystem::absolute(options.output);
    const auto previous = std::filesystem::current_path();
    const auto directory = std::filesystem::temp_directory_path() /
      ("ccf-indexing-compare-" +
       ccf::ds::to_hex(ccf::crypto::get_entropy()->random(16)));
    if (!std::filesystem::create_directory(directory))
      throw std::runtime_error("Cannot create isolated benchmark directory");
    std::cerr << "Benchmark scratch directory: " << directory << '\n';
    std::filesystem::current_path(directory);
    std::vector<Workload> workloads{
      {"hot"}, {"uniform"}, {"skewed"}, {"sparse"}, {"distinct"}};
    for (const size_t width : {8, 64, 512})
      if (width < options.entries)
        workloads.push_back({"batch-" + std::to_string(width), width});
    workloads.push_back(
      {"batch-" + std::to_string(options.entries), options.entries});
    nlohmann::json report{
      {"method",
       "In-process committed-ledger replay, Indexer, encrypted LFS "
       "and complete model-checked queries. Queue tasks are pumped "
       "deterministically, without periodic/HTTP/network delays. "
       "OS file caches are uncontrolled. First-pass queries follow "
       "build and earlier queries; warm immediately repeats each."},
      {"entries", options.entries},
      {"queries_per_pattern", options.queries},
      {"repetitions", options.repetitions},
      {"page_bytes", options.page_bytes},
      {"paged_cache_bytes", options.cache_bytes},
      {"bucket_size", options.bucket_size},
      {"bucket_cache_count", options.bucket_cache},
      {"runs", nlohmann::json::array()}};
    for (const auto& workload : workloads)
    {
      if (!options.workload.empty() && workload.name != options.workload)
        continue;
      auto dataset = make_dataset(workload, options.entries);
      for (size_t repetition = 0; repetition < options.repetitions;
           ++repetition)
      {
        for (size_t order = 0; order < 2; ++order)
        {
          const bool paged = (order + repetition) % 2 == 1;
          auto result = paged ?
            run<Paged>(options, workload, dataset, repetition) :
            run<Bucketed>(options, workload, dataset, repetition);
          std::cerr << workload.name << ' ' << result["strategy"]
                    << " repetition=" << repetition
                    << " build_ms=" << result["build_ms"] << '\n';
          report["runs"].push_back(std::move(result));
        }
      }
    }
    if (report["runs"].empty())
      throw std::invalid_argument("No matching benchmark workload");
    std::filesystem::current_path(previous);
    std::filesystem::remove_all(directory);
    std::ofstream output(output_path);
    output << report.dump(2) << '\n';
    output.close();
    if (!output)
      throw std::runtime_error("Cannot write benchmark report");
    std::cout << "Model-checked results: " << output_path << '\n';
    return 0;
  }
  catch (const std::exception& e)
  {
    std::cerr << "Indexing comparison failed: " << e.what() << '\n';
    return 1;
  }
}
