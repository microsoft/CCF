// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/kv/map.h"
#include "kv/compacted_version_conflict.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <doctest/doctest.h>
#include <exception>
#include <iostream>
#include <limits>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

namespace
{
  using Map = ccf::kv::MapSerialisedWith<
    std::string,
    std::string,
    ccf::kv::serialisers::BlitSerialiser>;
  using Tx = ccf::kv::CommittableTx;
  using Result = ccf::kv::CommitResult;
  using Json = nlohmann::json;

  constexpr size_t MAP_COUNT = 6;
  constexpr size_t KEY_COUNT = 8;
  constexpr size_t MAX_VISITS = 2;

  void ensure(bool condition, const char* message)
  {
    if (!condition)
    {
      throw std::runtime_error(message);
    }
  }

  uint64_t option(
    const char* name, uint64_t fallback, uint64_t minimum, uint64_t maximum)
  {
    const auto* raw = std::getenv(name);
    if (raw == nullptr)
    {
      return fallback;
    }
    const std::string_view text(raw);
    uint64_t value = 0;
    const auto [end, error] =
      std::from_chars(text.data(), text.data() + text.size(), value);
    if (
      error != std::errc{} || end != text.data() + text.size() ||
      value < minimum || value > maximum)
    {
      throw std::invalid_argument(
        std::string(name) + " must be a decimal integer in [" +
        std::to_string(minimum) + ", " + std::to_string(maximum) + "]");
    }
    return value;
  }

  struct Config
  {
    uint64_t seed =
      option("CCF_KV_FUZZ_SEED", 0, 0, std::numeric_limits<uint64_t>::max());
    size_t threads = option("CCF_KV_FUZZ_THREADS", 4, 1, 16);
    size_t transactions = option("CCF_KV_FUZZ_TRANSACTIONS", 24, 1, 256);
    size_t operations = option("CCF_KV_FUZZ_OPERATIONS", 8, 1, 32);

    Config()
    {
      if (threads * transactions * operations > 65536)
      {
        throw std::invalid_argument(
          "CCF_KV_FUZZ_THREADS * CCF_KV_FUZZ_TRANSACTIONS * "
          "CCF_KV_FUZZ_OPERATIONS must not exceed 65536");
      }
    }

    Json recipe() const
    {
      return {
        {"version", 1},
        {"seed", std::to_string(seed)},
        {"threads", threads},
        {"transactions", transactions},
        {"operations", operations},
        {"maps", MAP_COUNT},
        {"keys", KEY_COUNT}};
    }
  };

  uint64_t derive_seed(uint64_t seed, uint64_t stream)
  {
    auto value = seed + 0x9e3779b97f4a7c15ULL * (stream + 1);
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
  }

  struct Universe
  {
    const std::array<Map, MAP_COUNT> maps = {
      Map("fuzz.0"),
      Map("fuzz.1"),
      Map("fuzz.2"),
      Map("fuzz.3"),
      Map("fuzz.4"),
      Map("fuzz.5")};
    const std::array<std::string, KEY_COUNT> keys = {
      "",
      "k0",
      "k1",
      "k2",
      "k3",
      "k4",
      std::string("\0k", 2),
      std::string("\xff\0", 2)};
    const std::array<std::string, 8> values = {
      "",
      "v0",
      "v1",
      "v2",
      "v3",
      std::string("\0\xff", 2),
      "same",
      std::string("x\0y", 3)};
  };

  enum class Counter : size_t
  {
    Get,
    Has,
    GetGlobal,
    HasGlobal,
    PreviousWrite,
    Put,
    Remove,
    Clear,
    Size,
    Foreach,
    ForeachKey,
    ForeachValue,
    NestedForeach,
    CallbackWrite,
    Alias,
    ReadOnly,
    Abandon,
    CommitSuccess,
    CommitConflict,
    CommitNoReplicate,
    Compact,
    Rollback,
    RollbackRejected,
    SnapshotUnavailable,
    SameValueWrite,
    RemoveMissing,
    EmptyKey,
    BinaryValue,
    WorkerOperations,
    WorkerTransactions,
    WorkerCommitSuccess,
    MaxLiveWorkers,
    RandomCompactions,
    CoordinatedPhases,
    BinaryKey,
    Count
  };

  constexpr std::array<std::string_view, static_cast<size_t>(Counter::Count)>
    COUNTER_NAMES = {
      "get",
      "has",
      "get_global",
      "has_global",
      "previous_write",
      "put",
      "remove",
      "clear",
      "size",
      "foreach",
      "foreach_key",
      "foreach_value",
      "nested_foreach",
      "callback_write",
      "alias",
      "read_only",
      "abandon",
      "commit_success",
      "commit_conflict",
      "commit_no_replicate",
      "compact",
      "rollback",
      "rollback_rejected",
      "snapshot_unavailable",
      "same_value_write",
      "remove_missing",
      "empty_key",
      "binary_value",
      "worker_operations",
      "worker_transactions",
      "worker_commit_success",
      "max_live_workers",
      "random_compactions",
      "coordinated_phases",
      "binary_key"};

  class Coverage
  {
    std::array<std::atomic<uint64_t>, COUNTER_NAMES.size()> counts = {};
    std::atomic<uint64_t> live_workers = 0;

  public:
    void add(Counter counter, uint64_t count = 1)
    {
      counts[static_cast<size_t>(counter)].fetch_add(
        count, std::memory_order_relaxed);
    }

    void enter_worker()
    {
      // Worker-body lifetimes exclude the main thread and compactor. The
      // initial gate also pins one live attempt per configured worker.
      const auto live = live_workers.fetch_add(1) + 1;
      auto& maximum = counts[static_cast<size_t>(Counter::MaxLiveWorkers)];
      auto old = maximum.load();
      while (old < live && !maximum.compare_exchange_weak(old, live))
      {
      }
    }

    void leave_worker()
    {
      --live_workers;
    }

    Json finish(const Config& config) const
    {
      ensure(live_workers == 0, "Fuzzer worker escaped its joining scope");
      Json result = Json::object();
      for (size_t i = 0; i < counts.size(); ++i)
      {
        const auto count = counts[i].load();
        if (count == 0)
        {
          throw std::runtime_error(
            "Fuzzer did not exercise " + std::string(COUNTER_NAMES[i]));
        }
        result[std::string(COUNTER_NAMES[i])] = count;
      }
      ensure(
        result.at("max_live_workers").get<uint64_t>() == config.threads,
        "Fuzzer worker overlap does not match its configuration");
      ensure(
        result.at("worker_transactions").get<uint64_t>() ==
          config.threads * config.transactions,
        "Fuzzer did not finish its bounded random attempt slots");
      ensure(
        result.at("worker_operations").get<uint64_t>() <=
          config.threads * config.transactions * config.operations,
        "Fuzzer exceeded its random instruction budget");
      ensure(
        result.at("random_compactions").get<uint64_t>() ==
          config.threads * config.transactions,
        "Fuzzer compactor did not finish its bounded progress steps");
      return result;
    }
  };

  class LiveWorker
  {
    Coverage& coverage;

  public:
    explicit LiveWorker(Coverage& coverage_) : coverage(coverage_)
    {
      coverage.enter_worker();
    }
    ~LiveWorker()
    {
      coverage.leave_worker();
    }
    LiveWorker(const LiveWorker&) = delete;
    LiveWorker& operator=(const LiveWorker&) = delete;
  };

  class Control
  {
    std::mutex mutex;
    std::condition_variable changed;
    std::atomic<bool> cancelled = false;
    std::exception_ptr error;
    size_t generation = 0;
    size_t arrivals = 0;
    size_t completed = 0;

  public:
    bool stopped() const
    {
      return cancelled.load();
    }

    void stop()
    {
      std::lock_guard guard(mutex);
      cancelled = true;
      changed.notify_all();
    }

    void fail(std::exception_ptr exception)
    {
      std::lock_guard guard(mutex);
      if (error == nullptr)
      {
        error = exception;
      }
      cancelled = true;
      changed.notify_all();
    }

    void rethrow()
    {
      std::lock_guard guard(mutex);
      if (error != nullptr)
      {
        std::rethrow_exception(error);
      }
      ensure(!cancelled, "Fuzzer phase cancelled without an exception");
    }

    bool checkpoint()
    {
      std::unique_lock guard(mutex);
      const auto entered = generation;
      ++arrivals;
      changed.notify_all();
      changed.wait(guard, [&]() { return cancelled || generation != entered; });
      return !cancelled;
    }

    bool wait_for_workers(size_t count)
    {
      std::unique_lock guard(mutex);
      changed.wait(guard, [&]() { return cancelled || arrivals == count; });
      return !cancelled;
    }

    void resume()
    {
      std::lock_guard guard(mutex);
      arrivals = 0;
      ++generation;
      changed.notify_all();
    }

    void completed_attempt()
    {
      std::lock_guard guard(mutex);
      ++completed;
      changed.notify_all();
    }

    bool wait_for_completion(size_t count)
    {
      std::unique_lock guard(mutex);
      changed.wait(guard, [&]() { return cancelled || completed >= count; });
      return !cancelled;
    }
  };

  class Threads
  {
    Control& control;
    Coverage& coverage;
    std::vector<std::thread> threads;

  public:
    Threads(Control& control_, Coverage& coverage_, size_t capacity) :
      control(control_),
      coverage(coverage_)
    {
      threads.reserve(capacity);
    }

    template <typename F>
    void launch(F function, bool worker = true)
    {
      threads.emplace_back([this, function = std::move(function), worker]() {
        try
        {
          if (worker)
          {
            LiveWorker live(coverage);
            function();
          }
          else
          {
            function();
          }
        }
        catch (...)
        {
          control.fail(std::current_exception());
        }
      });
    }

    void join()
    {
      for (auto& thread : threads)
      {
        if (thread.joinable())
        {
          thread.join();
        }
      }
    }

    ~Threads()
    {
      control.stop();
      join();
    }
    Threads(const Threads&) = delete;
    Threads& operator=(const Threads&) = delete;
  };

  template <typename Worker, typename Coordinator>
  void coordinated(
    size_t count, Coverage& coverage, Worker worker, Coordinator coordinator)
  {
    Control control;
    Threads threads(control, coverage, count);
    try
    {
      for (size_t i = 0; i < count; ++i)
      {
        threads.launch([&, i]() { worker(control, i); });
      }
      coordinator(control);
    }
    catch (...)
    {
      control.fail(std::current_exception());
    }
    threads.join();
    control.rethrow();
    coverage.add(Counter::CoordinatedPhases);
  }

  struct FuzzStore : public ccf::kv::Store
  {
    explicit FuzzStore(bool replicate = true)
    {
      set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
      if (replicate)
      {
        auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
        consensus->force_become_primary();
        set_consensus(consensus);
      }
      else
      {
        set_consensus(std::make_shared<ccf::kv::test::BackupStubConsensus>());
      }
    }
  };

  struct Handles
  {
    Map::Handle* write;
    Map::ReadOnlyHandle* read;
    ccf::kv::untyped::MapHandle* raw;
  };

  class Operations
  {
    Coverage& coverage;

    void key_used(const std::string& key)
    {
      if (key.empty())
      {
        coverage.add(Counter::EmptyKey);
      }
      if (std::any_of(key.begin(), key.end(), [](unsigned char byte) {
            return byte == 0 || byte >= 128;
          }))
      {
        coverage.add(Counter::BinaryKey);
      }
    }

  public:
    explicit Operations(Coverage& coverage_) : coverage(coverage_) {}

    Handles pin(Tx& tx, const Map& map)
    {
      auto* write = tx.rw(map);
      auto* read = tx.ro(map);
      coverage.add(Counter::Alias);
      auto* raw = tx.rw<ccf::kv::untyped::Map>(map.get_name());
      coverage.add(Counter::Alias);
      return {write, read, raw};
    }

    std::optional<std::string> get(
      const Handles& handles, const std::string& key)
    {
      auto result = handles.read->get(key);
      coverage.add(Counter::Get);
      key_used(key);
      return result;
    }

    bool has(const Handles& handles, const std::string& key)
    {
      const auto result = handles.read->has(key);
      coverage.add(Counter::Has);
      key_used(key);
      return result;
    }

    std::optional<ccf::kv::Version> previous(
      const Handles& handles, const std::string& key)
    {
      auto result = handles.read->get_version_of_previous_write(key);
      coverage.add(Counter::PreviousWrite);
      key_used(key);
      return result;
    }

    std::optional<std::string> global(
      const Handles& handles, const std::string& key)
    {
      auto result = handles.read->get_globally_committed(key);
      coverage.add(Counter::GetGlobal);
      key_used(key);
      return result;
    }

    bool has_global(const Handles& handles, const std::string& key)
    {
      const auto result = handles.raw->has_globally_committed(
        Map::KeySerialiser::to_serialised(key));
      coverage.add(Counter::HasGlobal);
      key_used(key);
      return result;
    }

    void put(
      const Handles& handles, const std::string& key, const std::string& value)
    {
      handles.write->put(key, value);
      coverage.add(Counter::Put);
      key_used(key);
      if (std::any_of(value.begin(), value.end(), [](unsigned char byte) {
            return byte == 0 || byte >= 128;
          }))
      {
        coverage.add(Counter::BinaryValue);
      }
    }

    void remove(const Handles& handles, const std::string& key)
    {
      handles.write->remove(key);
      coverage.add(Counter::Remove);
      key_used(key);
    }

    void remove_checked(const Handles& handles, const std::string& key)
    {
      const auto existed = has(handles, key);
      remove(handles, key);
      if (!existed)
      {
        coverage.add(Counter::RemoveMissing);
      }
    }

    void same_value(
      const Handles& handles,
      const std::string& key,
      const std::string& fallback)
    {
      auto value = get(handles, key);
      if (!value.has_value())
      {
        put(handles, key, fallback);
        value = fallback;
      }
      put(handles, key, *value);
      coverage.add(Counter::SameValueWrite);
    }

    void clear(const Handles& handles)
    {
      handles.write->clear();
      coverage.add(Counter::Clear);
    }

    size_t size(const Handles& handles)
    {
      const auto result = handles.read->size();
      coverage.add(Counter::Size);
      return result;
    }

    void foreach(
      const Handles& source,
      const Handles& target,
      const std::string& key,
      const std::string& value,
      bool mutate,
      bool nested,
      size_t limit)
    {
      size_t visited = 0;
      source.read->foreach([&](const auto& entry_key, const auto&) {
        get(source, entry_key);
        if (mutate)
        {
          put(source, entry_key, value);
          coverage.add(Counter::CallbackWrite);
          put(target, key, value);
          coverage.add(Counter::CallbackWrite);
        }
        if (nested)
        {
          target.read->foreach([](const auto&, const auto&) { return false; });
          coverage.add(Counter::Foreach);
          coverage.add(Counter::NestedForeach);
        }
        return ++visited < limit;
      });
      coverage.add(Counter::Foreach);
    }

    void foreach_key(const Handles& handles, size_t limit)
    {
      size_t visited = 0;
      handles.read->foreach_key([&](const auto&) { return ++visited < limit; });
      coverage.add(Counter::ForeachKey);
    }

    void foreach_value(const Handles& handles, size_t limit)
    {
      size_t visited = 0;
      handles.read->foreach_value(
        [&](const auto&) { return ++visited < limit; });
      coverage.add(Counter::ForeachValue);
    }

    Result commit(Tx& tx, bool random_worker = false)
    {
      const auto result = tx.commit();
      switch (result)
      {
        case Result::SUCCESS:
          coverage.add(Counter::CommitSuccess);
          if (random_worker)
          {
            coverage.add(Counter::WorkerCommitSuccess);
          }
          if (tx.commit_version() == ccf::kv::NoVersion)
          {
            coverage.add(Counter::ReadOnly);
          }
          break;
        case Result::FAIL_CONFLICT:
          coverage.add(Counter::CommitConflict);
          break;
        case Result::FAIL_NO_REPLICATE:
          coverage.add(Counter::CommitNoReplicate);
          break;
      }
      return result;
    }

    void compact(FuzzStore& store, ccf::kv::Version version)
    {
      store.compact(version);
      coverage.add(Counter::Compact);
    }

    void rollback(
      FuzzStore& store, ccf::kv::Version version, ccf::kv::Term next_term)
    {
      store.rollback({0, version}, next_term);
      coverage.add(Counter::Rollback);
    }
  };

  struct Selection
  {
    size_t a;
    size_t b;
    size_t c;
    size_t key;
    size_t other_key;
    size_t value;
  };

  Selection select(uint64_t seed, uint64_t stream)
  {
    std::mt19937_64 rng(derive_seed(seed, stream));
    const auto a = rng() % MAP_COUNT;
    const auto key = rng() % KEY_COUNT;
    return {
      a,
      (a + 1) % MAP_COUNT,
      (a + 2) % MAP_COUNT,
      key,
      (key + 1) % KEY_COUNT,
      rng() % 8};
  }

  void write_pair(
    FuzzStore& store,
    const Universe& universe,
    Operations& operations,
    const Selection& selection,
    const std::string& value)
  {
    auto tx = store.create_tx();
    auto a = operations.pin(tx, universe.maps[selection.a]);
    auto b = operations.pin(tx, universe.maps[selection.b]);
    operations.put(a, universe.keys[selection.key], value);
    operations.put(b, universe.keys[selection.key], value);
    ensure(
      operations.commit(tx) == Result::SUCCESS,
      "Coordinated setup write did not commit");
  }

  enum class Kind
  {
    Get,
    Has,
    Previous,
    Global,
    HasGlobal,
    Put,
    Remove,
    Clear,
    Size,
    Foreach,
    ForeachKey,
    ForeachValue,
    Mutate,
    Nested,
    Copy,
    SameValue,
    MissingRemove,
    Alias,
    Count
  };

  enum class Mode
  {
    Commit,
    ReadOnly,
    Abandon
  };

  struct Instruction
  {
    Kind kind;
    size_t key;
    size_t other_key;
    size_t value;
    size_t other_value;
    size_t limit;
    bool reverse;
  };

  struct Program
  {
    size_t a;
    size_t b;
    Mode mode;
    std::vector<Instruction> instructions;
  };

  std::vector<Program> programs(const Config& config, size_t worker)
  {
    std::mt19937_64 rng(derive_seed(config.seed, worker));
    constexpr std::array read_kinds = {
      Kind::Get,
      Kind::Has,
      Kind::Previous,
      Kind::Global,
      Kind::HasGlobal,
      Kind::Size,
      Kind::Foreach,
      Kind::ForeachKey,
      Kind::ForeachValue,
      Kind::Nested,
      Kind::Alias};
    std::vector<Program> result;
    result.reserve(config.transactions);
    for (size_t slot = 0; slot < config.transactions; ++slot)
    {
      const auto a = rng() % MAP_COUNT;
      const auto b = (a + 1 + rng() % (MAP_COUNT - 1)) % MAP_COUNT;
      const auto mode = rng() % 4;
      Program program{
        a,
        b,
        mode < 2    ? Mode::Commit :
          mode == 2 ? Mode::ReadOnly :
                      Mode::Abandon,
        {}};
      program.instructions.reserve(config.operations);
      for (size_t i = 0; i < config.operations; ++i)
      {
        const auto choice = rng();
        program.instructions.push_back(
          {program.mode == Mode::ReadOnly ?
             read_kinds[choice % read_kinds.size()] :
             static_cast<Kind>(choice % static_cast<size_t>(Kind::Count)),
           rng() % KEY_COUNT,
           rng() % KEY_COUNT,
           rng() % 8,
           rng() % 8,
           1 + rng() % MAX_VISITS,
           (rng() % 2) != 0});
      }
      if (slot == 0)
      {
        // At least one first-slot writer must win before another can conflict.
        program.mode = Mode::Commit;
        program.instructions.front().kind = Kind::Put;
      }
      result.push_back(std::move(program));
    }
    return result;
  }

  void execute(
    Tx& tx,
    const Universe& universe,
    Operations& operations,
    const Program& program,
    const Handles& first,
    const Handles& second,
    const Instruction& instruction)
  {
    const auto& a = instruction.reverse ? second : first;
    const auto& b = instruction.reverse ? first : second;
    const auto& key = universe.keys[instruction.key];
    const auto& other_key = universe.keys[instruction.other_key];
    const auto& value = universe.values[instruction.value];
    switch (instruction.kind)
    {
      case Kind::Get:
        operations.get(a, key);
        break;
      case Kind::Has:
        operations.has(a, key);
        break;
      case Kind::Previous:
        operations.previous(a, key);
        break;
      case Kind::Global:
        operations.global(a, key);
        break;
      case Kind::HasGlobal:
        operations.has_global(a, key);
        break;
      case Kind::Put:
        operations.put(a, key, value);
        if (instruction.key == instruction.other_key)
        {
          operations.put(a, key, universe.values[instruction.other_value]);
        }
        break;
      case Kind::Remove:
        operations.remove(a, key);
        break;
      case Kind::Clear:
        operations.clear(a);
        break;
      case Kind::Size:
        operations.size(a);
        break;
      case Kind::Foreach:
      case Kind::Mutate:
      case Kind::Nested:
        operations.foreach(
          a,
          b,
          other_key,
          value,
          instruction.kind == Kind::Mutate,
          instruction.kind == Kind::Nested,
          instruction.limit);
        break;
      case Kind::ForeachKey:
        operations.foreach_key(a, instruction.limit);
        break;
      case Kind::ForeachValue:
        operations.foreach_value(a, instruction.limit);
        break;
      case Kind::Copy:
      {
        const auto observed = operations.get(a, key);
        operations.put(b, other_key, observed.value_or(value));
        break;
      }
      case Kind::SameValue:
        operations.same_value(a, key, value);
        break;
      case Kind::MissingRemove:
        operations.remove(a, key);
        operations.remove_checked(a, key);
        break;
      case Kind::Alias:
        operations.pin(tx, universe.maps[program.a]);
        break;
      case Kind::Count:
        throw std::logic_error("Invalid generated operation");
    }
  }

  void free_running(
    const Config& config, const Universe& universe, Coverage& coverage)
  {
    FuzzStore store;
    Operations operations(coverage);
    {
      auto tx = store.create_tx();
      // Keep an existing empty map and an initially absent map in the pool.
      for (size_t i = 0; i + 1 < MAP_COUNT; ++i)
      {
        auto handles = operations.pin(tx, universe.maps[i]);
        if (i + 2 == MAP_COUNT)
        {
          operations.remove_checked(handles, universe.keys[0]);
        }
        else
        {
          operations.put(handles, universe.keys[1], universe.values[1]);
          operations.put(handles, universe.keys[2], universe.values[2]);
        }
      }
      ensure(
        operations.commit(tx) == Result::SUCCESS,
        "Random phase setup did not commit");
    }
    operations.compact(store, store.current_version());

    Control control;
    Threads threads(control, coverage, config.threads + 1);
    try
    {
      threads.launch(
        [&]() {
          for (size_t i = 1; i <= config.threads * config.transactions; ++i)
          {
            if (!control.wait_for_completion(i))
            {
              return;
            }
            operations.compact(store, store.current_version());
            coverage.add(Counter::RandomCompactions);
            std::this_thread::yield();
          }
        },
        false);
      for (size_t worker = 0; worker < config.threads; ++worker)
      {
        threads.launch([&, worker]() {
          // Choices are generated independently of all observations and timing.
          const auto choices = programs(config, worker);
          for (size_t slot = 0; slot < choices.size(); ++slot)
          {
            if (control.stopped())
            {
              return;
            }
            bool abandoned = false;
            {
              auto tx = store.create_tx();
              if (slot == 0 && !control.checkpoint())
              {
                return;
              }
              try
              {
                const auto& program = choices[slot];
                const auto a = operations.pin(tx, universe.maps[program.a]);
                const auto b = operations.pin(tx, universe.maps[program.b]);
                for (const auto& instruction : program.instructions)
                {
                  if (control.stopped())
                  {
                    return;
                  }
                  execute(tx, universe, operations, program, a, b, instruction);
                  coverage.add(Counter::WorkerOperations);
                  std::this_thread::yield();
                }
                if (program.mode == Mode::Abandon)
                {
                  abandoned = true;
                }
                else
                {
                  operations.commit(tx, true);
                }
              }
              catch (const ccf::kv::CompactedVersionConflict&)
              {
                coverage.add(Counter::SnapshotUnavailable);
              }
            }
            if (abandoned)
            {
              coverage.add(Counter::Abandon);
            }
            // Each slot is one fresh, bounded attempt, not an unbounded retry.
            coverage.add(Counter::WorkerTransactions);
            control.completed_attempt();
          }
        });
      }
      if (control.wait_for_workers(config.threads))
      {
        control.resume();
      }
    }
    catch (...)
    {
      control.fail(std::current_exception());
    }
    threads.join();
    control.rethrow();
  }

  void surface(
    const Config& config, const Universe& universe, Coverage& coverage)
  {
    FuzzStore store;
    Operations operations(coverage);
    const auto selection = select(config.seed, 100);
    const auto& key = universe.keys[selection.key];
    const auto& other_key = universe.keys[selection.other_key];
    const auto& value = universe.values[selection.value];
    write_pair(store, universe, operations, selection, value);
    operations.compact(store, store.current_version());
    coordinated(
      config.threads,
      coverage,
      [&](Control& control, size_t worker) {
        auto tx = store.create_tx();
        const auto a = operations.pin(tx, universe.maps[selection.a]);
        const auto b = operations.pin(tx, universe.maps[selection.b]);
        if (!control.checkpoint())
        {
          return;
        }
        operations.get(a, key);
        operations.has(a, key);
        operations.previous(a, key);
        operations.previous(a, other_key);
        operations.global(a, key);
        operations.has_global(a, key);
        operations.put(a, universe.keys[0], universe.values[5]);
        operations.put(a, universe.keys[6], universe.values[0]);
        ensure(
          operations.get(a, universe.keys[6]) == universe.values[0],
          "Binary key with an empty value did not round trip");
        operations.same_value(a, key, value);
        operations.put(a, other_key, universe.values[(worker + 1) % 8]);
        operations.put(a, other_key, universe.values[(worker + 2) % 8]);
        operations.remove(a, other_key);
        operations.remove_checked(a, other_key);
        operations.put(a, other_key, value);
        operations.size(a);
        operations.foreach(a, b, key, value, true, true, MAX_VISITS);
        operations.foreach_key(a, MAX_VISITS);
        operations.foreach_value(b, 1);
        operations.clear(b);
        ensure(operations.size(b) == 0, "clear left a pending entry");
        operations.remove(a, key);
        operations.get(a, key);
        coverage.add(Counter::Abandon);
      },
      [&](Control& control) {
        if (control.wait_for_workers(config.threads))
        {
          operations.compact(store, store.current_version());
          control.resume();
        }
      });
    auto empty = store.create_tx();
    ensure(
      operations.commit(empty) == Result::SUCCESS,
      "Empty read-only transaction did not complete");
  }

  void global_cuts(
    const Config& config, const Universe& universe, Coverage& coverage)
  {
    FuzzStore store;
    Operations operations(coverage);
    const auto selection = select(config.seed, 101);
    const auto& key = universe.keys[selection.key];
    const auto& first = universe.values[selection.value];
    const auto& second = universe.values[(selection.value + 1) % 8];
    const auto& third = universe.values[(selection.value + 2) % 8];
    write_pair(store, universe, operations, selection, first);
    operations.compact(store, 1);
    write_pair(store, universe, operations, selection, second);
    coordinated(
      config.threads,
      coverage,
      [&](Control& control, size_t) {
        auto tx = store.create_tx();
        const auto a = operations.pin(tx, universe.maps[selection.a]);
        if (!control.checkpoint())
        {
          return;
        }
        const auto b = operations.pin(tx, universe.maps[selection.b]);
        ensure(operations.get(a, key) == second, "Local A snapshot changed");
        ensure(operations.global(a, key) == first, "Pinned global A changed");
        ensure(operations.get(b, key) == second, "Local B snapshot changed");
        ensure(operations.global(b, key) == second, "Late global B is wrong");
        if (!control.checkpoint())
        {
          return;
        }
        ensure(operations.get(a, key) == second, "Compaction changed local A");
        ensure(
          operations.global(a, key) == first, "Compaction changed global A");
        ensure(
          operations.global(b, key) == second, "Compaction changed global B");
        ensure(
          operations.commit(tx) == Result::SUCCESS,
          "Pinned read-only completion failed");
      },
      [&](Control& control) {
        if (!control.wait_for_workers(config.threads))
        {
          return;
        }
        operations.compact(store, 2);
        control.resume();
        if (!control.wait_for_workers(config.threads))
        {
          return;
        }
        write_pair(store, universe, operations, selection, third);
        operations.compact(store, 3);
        control.resume();
      });
  }

  void dependencies(
    const Config& config, const Universe& universe, Coverage& coverage)
  {
    for (size_t kind = 0; kind < 3; ++kind)
    {
      FuzzStore store;
      Operations operations(coverage);
      const auto selection = select(config.seed, 110 + kind);
      const auto& key = universe.keys[selection.key];
      const auto& absent = universe.keys[selection.other_key];
      const auto& value = universe.values[selection.value];
      write_pair(store, universe, operations, selection, value);
      coordinated(
        config.threads,
        coverage,
        [&](Control& control, size_t worker) {
          {
            auto tx = store.create_tx();
            const auto a = operations.pin(tx, universe.maps[selection.a]);
            const auto b = operations.pin(tx, universe.maps[selection.b]);
            if (kind == 0)
            {
              operations.get(a, key);
            }
            else if (kind == 1)
            {
              ensure(
                !operations.has(a, absent), "Absence dependency not absent");
            }
            else
            {
              operations.foreach(a, b, absent, value, false, false, MAX_VISITS);
            }
            operations.put(b, universe.keys[worker % KEY_COUNT], value);
            if (!control.checkpoint())
            {
              return;
            }
            ensure(
              operations.commit(tx) == Result::FAIL_CONFLICT,
              "Coordinated read/absence/phantom dependency did not conflict");
          }
          auto retry = store.create_tx();
          const auto a = operations.pin(retry, universe.maps[selection.a]);
          const auto b = operations.pin(retry, universe.maps[selection.b]);
          operations.get(a, kind == 0 ? key : absent);
          operations.put(b, universe.keys[worker % KEY_COUNT], value);
          ensure(
            operations.commit(retry) == Result::SUCCESS,
            "Fresh bounded retry failed without a changing dependency");
        },
        [&](Control& control) {
          if (!control.wait_for_workers(config.threads))
          {
            return;
          }
          auto writer = store.create_tx();
          const auto a = operations.pin(writer, universe.maps[selection.a]);
          operations.put(
            a,
            kind == 0 ? key : absent,
            universe.values[(selection.value + 1) % 8]);
          ensure(
            operations.commit(writer) == Result::SUCCESS,
            "Dependency-changing write failed");
          control.resume();
        });
    }
  }

  void acquisition(
    const Config& config, const Universe& universe, Coverage& coverage)
  {
    for (size_t kind = 0; kind < 3; ++kind)
    {
      FuzzStore store;
      Operations operations(coverage);
      const auto selection = select(config.seed, 120 + kind);
      const auto& key = universe.keys[selection.key];
      const auto& value = universe.values[selection.value];
      {
        auto creator = store.create_tx();
        const auto a = operations.pin(creator, universe.maps[selection.a]);
        operations.put(a, key, value);
        if (kind != 0)
        {
          const auto b = operations.pin(creator, universe.maps[selection.b]);
          if (kind == 1)
          {
            operations.remove_checked(b, key);
          }
          else
          {
            operations.put(b, key, value);
          }
        }
        ensure(
          operations.commit(creator) == Result::SUCCESS, "Birth setup failed");
      }
      operations.compact(store, 1);
      coordinated(
        config.threads,
        coverage,
        [&](Control& control, size_t) {
          {
            auto tx = store.create_tx();
            const auto a = operations.pin(tx, universe.maps[selection.a]);
            operations.get(a, key);
            if (!control.checkpoint())
            {
              return;
            }
            if (kind == 0)
            {
              const auto b = operations.pin(tx, universe.maps[selection.b]);
              ensure(
                !operations.get(b, key),
                "Later-created map leaked into snapshot");
              ensure(
                !operations.global(b, key),
                "Placeholder global state was not empty");
              coverage.add(Counter::Abandon);
            }
            else
            {
              bool unavailable = false;
              try
              {
                operations.pin(tx, universe.maps[selection.b]);
              }
              catch (const ccf::kv::CompactedVersionConflict&)
              {
                unavailable = true;
                coverage.add(Counter::SnapshotUnavailable);
              }
              ensure(
                unavailable, "Compacted old map snapshot remained available");
            }
          }
          auto fresh = store.create_tx();
          const auto b = operations.pin(fresh, universe.maps[selection.b]);
          ensure(
            operations.get(b, key) == value,
            "Fresh snapshot missed published map");
          ensure(
            operations.commit(fresh) == Result::SUCCESS,
            "Fresh snapshot retry failed");
        },
        [&](Control& control) {
          if (!control.wait_for_workers(config.threads))
          {
            return;
          }
          auto writer = store.create_tx();
          const auto b = operations.pin(writer, universe.maps[selection.b]);
          operations.put(b, key, value);
          ensure(
            operations.commit(writer) == Result::SUCCESS,
            "Map publication failed");
          operations.compact(store, 2);
          control.resume();
        });
    }
  }

  void rollback_lifecycle(
    const Config& config, const Universe& universe, Coverage& coverage)
  {
    FuzzStore store;
    Operations operations(coverage);
    const auto selection = select(config.seed, 130);
    const auto& key = universe.keys[selection.key];
    const auto& durable = universe.values[selection.value];
    const auto& provisional = universe.values[(selection.value + 1) % 8];
    const auto& recreated = universe.values[(selection.value + 2) % 8];
    write_pair(store, universe, operations, selection, durable);
    operations.compact(store, 1);
    {
      auto writer = store.create_tx();
      const auto a = operations.pin(writer, universe.maps[selection.a]);
      const auto c = operations.pin(writer, universe.maps[selection.c]);
      operations.put(a, key, provisional);
      operations.put(c, key, provisional);
      ensure(
        operations.commit(writer) == Result::SUCCESS,
        "Provisional write failed");
    }
    coordinated(
      config.threads,
      coverage,
      [&](Control& control, size_t) {
        {
          auto stale = store.create_tx();
          const auto a = operations.pin(stale, universe.maps[selection.a]);
          const auto c = operations.pin(stale, universe.maps[selection.c]);
          operations.get(a, key);
          operations.get(c, key);
          if (!control.checkpoint())
          {
            return;
          }
          ensure(
            operations.get(a, key) == provisional,
            "Pinned rollback view changed");
          ensure(
            operations.get(c, key) == provisional,
            "Removed map lost pinned view");
          ensure(
            operations.global(a, key) == durable,
            "Rollback changed durable view");
          operations.put(a, key, recreated);
          operations.put(c, key, recreated);
          ensure(
            operations.commit(stale) == Result::FAIL_CONFLICT,
            "Rolled-back writing attempt did not conflict");
        }
        {
          auto stale_term = store.create_tx();
          const auto b = operations.pin(stale_term, universe.maps[selection.b]);
          operations.put(b, key, recreated);
          if (!control.checkpoint())
          {
            return;
          }
          ensure(
            operations.commit(stale_term) == Result::FAIL_NO_REPLICATE,
            "Term-only rollback did not reject stale writes");
        }
        if (!control.checkpoint())
        {
          return;
        }
        auto fresh = store.create_tx();
        const auto a = operations.pin(fresh, universe.maps[selection.a]);
        const auto c = operations.pin(fresh, universe.maps[selection.c]);
        ensure(
          operations.get(a, key) == durable,
          "Discarded suffix remained visible");
        ensure(operations.get(c, key) == recreated, "Recreated map missing");
        ensure(
          !operations.global(c, key),
          "Recreated map became global prematurely");
        if (!control.checkpoint())
        {
          return;
        }
        ensure(
          !operations.global(c, key),
          "Pinned global view refreshed after compact");
        ensure(
          operations.commit(fresh) == Result::SUCCESS,
          "Post-rollback read-only completion failed");
      },
      [&](Control& control) {
        if (!control.wait_for_workers(config.threads))
        {
          return;
        }
        // Every worker is between calls; rollback is never traced in overlap.
        operations.rollback(store, 1, 1);
        control.resume();
        if (!control.wait_for_workers(config.threads))
        {
          return;
        }
        operations.rollback(store, 1, 2);
        control.resume();
        if (!control.wait_for_workers(config.threads))
        {
          return;
        }
        {
          auto writer = store.create_tx();
          const auto c = operations.pin(writer, universe.maps[selection.c]);
          operations.put(c, key, recreated);
          ensure(
            operations.commit(writer) == Result::SUCCESS,
            "Map recreation failed");
        }
        bool rejected = false;
        try
        {
          store.rollback({0, 0}, 3);
        }
        catch (const std::logic_error&)
        {
          rejected = true;
          coverage.add(Counter::RollbackRejected);
        }
        ensure(rejected, "Rollback crossed the durable prefix");
        control.resume();
        if (!control.wait_for_workers(config.threads))
        {
          return;
        }
        operations.compact(store, 2);
        control.resume();
      });
  }

  void replication_failure(
    const Config& config, const Universe& universe, Coverage& coverage)
  {
    FuzzStore store(false);
    Operations operations(coverage);
    const auto selection = select(config.seed, 140);
    const auto& key = universe.keys[selection.key];
    const auto& value = universe.values[selection.value];
    coordinated(
      1,
      coverage,
      [&](Control& control, size_t) {
        {
          auto writer = store.create_tx();
          const auto a = operations.pin(writer, universe.maps[selection.a]);
          operations.put(a, key, value);
          ensure(
            operations.commit(writer) == Result::FAIL_NO_REPLICATE,
            "Nonreplicating consensus unexpectedly accepted a write");
        }
        {
          auto pinned = store.create_tx();
          const auto a = operations.pin(pinned, universe.maps[selection.a]);
          ensure(
            operations.get(a, key) == value,
            "Failed replication hid local apply");
          if (!control.checkpoint())
          {
            return;
          }
          ensure(
            operations.get(a, key) == value,
            "Rollback destroyed pinned local view");
          coverage.add(Counter::Abandon);
        }
        auto fresh = store.create_tx();
        const auto a = operations.pin(fresh, universe.maps[selection.a]);
        ensure(
          !operations.get(a, key),
          "Explicit rollback retained unreplicated write");
        ensure(
          operations.commit(fresh) == Result::SUCCESS,
          "Post-failure read-only completion failed");
      },
      [&](Control& control) {
        if (control.wait_for_workers(1))
        {
          operations.rollback(store, 0, 1);
          control.resume();
        }
      });
  }
}

TEST_CASE("KV trace concurrent operation fuzzer")
{
  const Config config;
  std::cout << "KV_FUZZ_RECIPE " << config.recipe().dump() << std::endl;
  const Universe universe;
  Coverage coverage;
  free_running(config, universe, coverage);
  surface(config, universe, coverage);
  global_cuts(config, universe, coverage);
  dependencies(config, universe, coverage);
  acquisition(config, universe, coverage);
  rollback_lifecycle(config, universe, coverage);
  replication_failure(config, universe, coverage);
  std::cout << "KV_FUZZ_COVERAGE " << coverage.finish(config).dump()
            << std::endl;
}
