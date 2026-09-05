// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "kv/trace.h"

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace ccf::kv::trace
{
  namespace
  {
    struct StoreInfo
    {
      uint64_t id;
      uint64_t global = 0;
      bool rolling_back = false;
      bool term_observed = false;
      size_t acquisitions = 0;
    };

    struct Sink
    {
      std::mutex mutex;
      std::condition_variable ready;
      std::deque<Json> pending;
      std::unordered_map<const void*, StoreInfo> stores;
      std::unordered_set<uint64_t> attempts;
      std::unordered_set<uint64_t> completed_attempts;
      uint64_t seq = 0;
      uint64_t next_store = 0;
      uint64_t next_tx = 0;
      bool stopping = false;
      bool overflow = false;
      std::array<char, 1024 * 1024> output_buffer;
      std::ofstream output;
      std::thread writer;
      std::exception_ptr error;

      explicit Sink(const std::filesystem::path& path)
      {
        if (!path.is_absolute())
        {
          throw std::logic_error("CCF_KV_TRACE_FILE must be absolute");
        }
        output.exceptions(std::ios::failbit | std::ios::badbit);
        output.rdbuf()->pubsetbuf(output_buffer.data(), output_buffer.size());
        output.open(path, std::ios::out | std::ios::trunc);
        std::ofstream metadata;
        metadata.exceptions(std::ios::failbit | std::ios::badbit);
        metadata.open(path.string() + ".metadata.json", std::ios::trunc);
        metadata << Json({{"trace_schema", 1},
                          {"build", "CCF_KV_TRACING"},
                          {"compiler", __VERSION__},
                          {"source_revision", CCF_KV_TRACE_REVISION}})
                      .dump()
                 << '\n';
        metadata.flush();
        writer = std::thread([this]() {
          try
          {
            while (true)
            {
              std::deque<Json> batch;
              {
                std::unique_lock guard(mutex);
                ready.wait(
                  guard, [this]() { return stopping || !pending.empty(); });
                pending.swap(batch);
                if (batch.empty() && stopping)
                {
                  break;
                }
              }
              for (const auto& record : batch)
              {
                output << record.dump() << '\n';
              }
            }
            output.flush();
          }
          catch (...)
          {
            error = std::current_exception();
          }
        });
      }

      ~Sink()
      {
        {
          std::lock_guard guard(mutex);
          stopping = true;
          ready.notify_one();
        }
        if (writer.joinable())
        {
          writer.join();
        }
      }

      // Called only with the observer mutex. File I/O and JSON encoding run
      // on the writer thread, never while a KV lock is held.
      void append(const char* type, Json fields)
      {
        if (std::string_view(type) != "trace_end")
        {
          if (overflow)
          {
            return;
          }
          if (pending.size() >= 100000)
          {
            overflow = true;
            type = "unsupported";
            fields = {{"operation", "trace writer queue capacity exceeded"}};
          }
        }
        fields["type"] = type;
        fields["seq"] = ++seq;
        pending.push_back(std::move(fields));
        ready.notify_one();
      }

      StoreInfo* find(const void* store)
      {
        auto it = stores.find(store);
        if (it == stores.end())
        {
          append("unsupported", {{"operation", "unregistered store"}});
          return nullptr;
        }
        return &it->second;
      }

      void check_boundary(uint64_t id)
      {
        for (const auto& [_, info] : stores)
        {
          if (info.id == id && info.rolling_back)
          {
            append(
              "unsupported",
              {{"store", id}, {"operation", "access overlaps rollback"}});
            break;
          }
        }
      }

      void check_attempt_phase(Identity id)
      {
        if (completed_attempts.contains(id.tx))
        {
          append(
            "unsupported",
            {{"store", id.store},
             {"operation", "handle use after commit result"}});
        }
      }
    };

    std::unique_ptr<Sink> owner;
    std::atomic<Sink*> active = nullptr;
    thread_local Identity current;
    thread_local const Json* current_writes = nullptr;
    thread_local Commit* current_commit = nullptr;
    thread_local bool environment = false;

    void acquisition(Identity id, bool begin)
    {
      if (auto* sink = active.load(std::memory_order_acquire);
          sink && id.tx != 0)
      {
        std::lock_guard guard(sink->mutex);
        for (auto& [_, info] : sink->stores)
        {
          if (info.id == id.store)
          {
            if (begin)
            {
              sink->check_boundary(info.id);
              ++info.acquisitions;
            }
            else
            {
              --info.acquisitions;
            }
            break;
          }
        }
      }
    }
  }

  bool enabled()
  {
    return active.load(std::memory_order_acquire) != nullptr;
  }

  void start()
  {
    const auto* path = std::getenv("CCF_KV_TRACE_FILE");
    if (path == nullptr)
    {
      return;
    }
    if (owner != nullptr)
    {
      throw std::logic_error("KV trace already started");
    }
    owner = std::make_unique<Sink>(path);
    active.store(owner.get(), std::memory_order_release);
    event("trace_start", {{"schema", 1}});
  }

  void finish()
  {
    auto* sink = active.load(std::memory_order_acquire);
    if (sink == nullptr)
    {
      return;
    }
    {
      std::lock_guard guard(sink->mutex);
      if (!sink->stores.empty() || !sink->attempts.empty())
      {
        sink->append(
          "unsupported", {{"operation", "unclosed store or transaction"}});
      }
      sink->append("trace_end", {{"events", sink->seq}});
      sink->stopping = true;
      sink->ready.notify_one();
    }
    sink->writer.join();
    active.store(nullptr, std::memory_order_release);
    auto error = sink->error;
    owner.reset();
    if (error != nullptr)
    {
      std::rethrow_exception(error);
    }
  }

  void event(const char* type, Json fields)
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      sink->append(type, std::move(fields));
    }
  }

  void transaction(Identity id, const char* type, Json fields)
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      if (id.tx == 0 || !sink->attempts.contains(id.tx))
      {
        sink->append(
          "unsupported", {{"operation", "operation outside live attempt"}});
      }
      sink->check_boundary(id.store);
      if (std::string_view(type) == "unsupported")
      {
        sink->append(
          type, {{"store", id.store}, {"operation", fields.at("operation")}});
        return;
      }
      sink->check_attempt_phase(id);
      fields["store"] = id.store;
      fields["tx"] = id.tx;
      sink->append(type, std::move(fields));
      if (std::string_view(type) == "commit_result")
      {
        sink->completed_attempts.insert(id.tx);
      }
    }
  }

  void operation(
    Identity id, const char* type, const std::string& map, Json fields)
  {
    fields["map"] = map;
    transaction(id, type, std::move(fields));
  }

  void unsupported(const void* store, const std::string& operation_)
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      Json fields = {{"operation", operation_}};
      auto it = sink->stores.find(store);
      if (it != sink->stores.end())
      {
        fields["store"] = it->second.id;
      }
      sink->append("unsupported", std::move(fields));
    }
  }

  void store_create(const void* store)
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      const auto id = ++sink->next_store;
      sink->stores.emplace(store, StoreInfo{id});
      sink->append("store_create", {{"store", id}});
    }
  }

  void store_end(const void* store)
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      if (auto* info = sink->find(store))
      {
        sink->append("store_end", {{"store", info->id}});
        sink->stores.erase(store);
      }
    }
  }

  void Attempt::bind(const void* store)
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      if (auto* info = sink->find(store))
      {
        id = {info->id, ++sink->next_tx};
        sink->attempts.insert(id.tx);
        sink->append("tx_create", {{"store", id.store}, {"tx", id.tx}});
      }
    }
  }

  Attempt::~Attempt()
  {
    if (auto* sink = active.load(std::memory_order_acquire); sink && id.tx != 0)
    {
      std::lock_guard guard(sink->mutex);
      sink->append("tx_end", {{"store", id.store}, {"tx", id.tx}});
      sink->attempts.erase(id.tx);
      sink->completed_attempts.erase(id.tx);
    }
  }

  Context::Context(Identity id, const Json* writes, Commit* commit) :
    previous(current),
    previous_writes(current_writes),
    previous_commit(current_commit)
  {
    current = id;
    current_writes = writes;
    current_commit = commit;
    if (writes == nullptr)
    {
      acquisition(id, true);
    }
  }

  Context::~Context()
  {
    if (current_writes == nullptr)
    {
      if (std::uncaught_exceptions() != 0)
      {
        transaction(
          current, "unsupported", {{"operation", "map acquisition exception"}});
      }
      acquisition(current, false);
    }
    current = previous;
    current_writes = previous_writes;
    current_commit = previous_commit;
  }

  Identity context()
  {
    return current;
  }

  Environment::Environment() : previous(environment)
  {
    environment = true;
  }

  Environment::~Environment()
  {
    environment = previous;
  }

  bool in_environment()
  {
    return environment;
  }

  void snapshot(const void* store, uint64_t version, uint64_t term)
  {
    if (auto* sink = active.load(std::memory_order_acquire);
        sink && current.tx != 0)
    {
      std::lock_guard guard(sink->mutex);
      if (auto* info = sink->find(store))
      {
        sink->check_boundary(info->id);
        sink->check_attempt_phase(current);
        info->term_observed = true;
        sink->append(
          "snapshot",
          {{"store", current.store},
           {"tx", current.tx},
           {"version", version},
           {"global", info->global},
           {"term", term}});
      }
    }
  }

  void apply(const void* store, uint64_t version, uint64_t term)
  {
    if (current_writes == nullptr || current.tx == 0)
    {
      unsupported(store, "version allocation outside transaction");
      return;
    }
    transaction(
      current,
      "apply",
      {{"version", version}, {"term", term}, {"writes", *current_writes}});
  }

  void initialise_term(const void* store)
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      if (auto* info = sink->find(store))
      {
        sink->check_boundary(info->id);
        // The wire learns initial term metadata from the first snapshot or
        // accepted rollback, but cannot represent later explicit changes.
        if (info->term_observed)
        {
          sink->append(
            "unsupported",
            {{"store", info->id},
             {"operation", "term initialisation after observation"}});
        }
      }
    }
  }

  void local_result(const char* result, uint64_t version)
  {
    if (current_commit != nullptr && !current_commit->finished())
    {
      current_commit->result(result, version);
    }
  }

  void compact(const void* store, uint64_t version, uint64_t requested)
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      if (auto* info = sink->find(store))
      {
        sink->check_boundary(info->id);
        sink->append(
          "compact",
          {{"store", info->id},
           {"version", version},
           {"requested", requested}});
        info->global = version;
      }
    }
  }

  Rollback::Rollback(const void* store_) : store(store_)
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      if (auto* info = sink->find(store))
      {
        if (info->acquisitions != 0)
        {
          sink->append(
            "unsupported",
            {{"store", info->id},
             {"operation", "map acquisition overlaps rollback"}});
        }
        info->rolling_back = true;
      }
    }
  }

  Rollback::~Rollback()
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      if (auto* info = sink->find(store))
      {
        info->rolling_back = false;
        if (!complete)
        {
          sink->append(
            "unsupported",
            {{"store", info->id}, {"operation", "rollback exception"}});
        }
      }
    }
  }

  void Rollback::result(uint64_t version, uint64_t requested, uint64_t term)
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      if (auto* info = sink->find(store))
      {
        info->term_observed = true;
        sink->append(
          "rollback",
          {{"store", info->id},
           {"version", version},
           {"requested", requested},
           {"term", term}});
        info->rolling_back = false;
      }
    }
    complete = true;
  }

  void Rollback::rejected(uint64_t requested, uint64_t term)
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      if (auto* info = sink->find(store))
      {
        sink->append(
          "rollback_rejected",
          {{"store", info->id}, {"requested", requested}, {"term", term}});
        info->rolling_back = false;
      }
    }
    complete = true;
  }
}
