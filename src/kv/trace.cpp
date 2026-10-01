// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "kv/trace.h"

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string_view>
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

    // The mutex orders every record by seq. It is a leaf lock: tracing never
    // acquires a KV lock while holding it.
    struct Sink
    {
      std::mutex mutex;
      std::ofstream output;
      std::unordered_map<const AbstractStore*, StoreInfo> stores;
      std::unordered_set<uint64_t> attempts;
      std::unordered_set<uint64_t> completed_attempts;
      uint64_t seq = 0;
      uint64_t next_store = 0;
      uint64_t next_tx = 0;

      explicit Sink(const std::filesystem::path& path)
      {
        if (!path.is_absolute())
        {
          throw std::logic_error("CCF_KV_TRACE_FILE must be absolute");
        }
        output.open(path, std::ios::out | std::ios::trunc);
        if (!output)
        {
          throw std::runtime_error("Cannot open CCF_KV_TRACE_FILE");
        }
      }

      // Called only with the mutex held. Encoding errors, such as a map name
      // that is not valid UTF-8, and write errors are reported by finish(),
      // rather than thrown into the traced KV operation.
      void append(const char* type, Json fields)
      {
        fields["type"] = type;
        fields["seq"] = ++seq;
        try
        {
          output << fields.dump() << '\n';
        }
        catch (const std::exception&)
        {
          output.setstate(std::ios::badbit);
        }
      }

      StoreInfo* find(const AbstractStore* store)
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

    // Calls f with the sink locked, if tracing is active and store is
    // registered.
    template <typename F>
    void with_store(const AbstractStore* store, F&& f)
    {
      if (auto* sink = active.load(std::memory_order_acquire))
      {
        std::lock_guard guard(sink->mutex);
        if (auto* info = sink->find(store))
        {
          f(*sink, *info);
        }
      }
    }

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
      sink->output.flush();
    }
    active.store(nullptr, std::memory_order_release);
    const bool written = sink->output.good();
    owner.reset();
    if (!written)
    {
      throw std::runtime_error("Failed to write CCF_KV_TRACE_FILE");
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

  void unsupported(const AbstractStore* store, const std::string& operation_)
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

  void store_create(const AbstractStore* store)
  {
    if (auto* sink = active.load(std::memory_order_acquire))
    {
      std::lock_guard guard(sink->mutex);
      const auto id = ++sink->next_store;
      sink->stores.emplace(store, StoreInfo{id});
      sink->append("store_create", {{"store", id}});
    }
  }

  void store_end(const AbstractStore* store)
  {
    with_store(store, [store](Sink& sink, StoreInfo& info) {
      sink.append("store_end", {{"store", info.id}});
      sink.stores.erase(store);
    });
  }

  void Attempt::bind(const AbstractStore* store)
  {
    with_store(store, [this](Sink& sink, StoreInfo& info) {
      id = {info.id, ++sink.next_tx};
      sink.attempts.insert(id.tx);
      sink.append("tx_create", {{"store", id.store}, {"tx", id.tx}});
    });
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

  void snapshot(const AbstractStore* store, uint64_t version, uint64_t term)
  {
    if (current.tx == 0)
    {
      return;
    }
    with_store(store, [&](Sink& sink, StoreInfo& info) {
      sink.check_boundary(info.id);
      sink.check_attempt_phase(current);
      info.term_observed = true;
      sink.append(
        "snapshot",
        {{"store", current.store},
         {"tx", current.tx},
         {"version", version},
         {"global", info.global},
         {"term", term}});
    });
  }

  void apply(const AbstractStore* store, uint64_t version, uint64_t term)
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

  void initialise_term(const AbstractStore* store)
  {
    with_store(store, [](Sink& sink, StoreInfo& info) {
      sink.check_boundary(info.id);
      // The wire learns initial term metadata from the first snapshot or
      // accepted rollback, but cannot represent later explicit changes.
      if (info.term_observed)
      {
        sink.append(
          "unsupported",
          {{"store", info.id},
           {"operation", "term initialisation after observation"}});
      }
    });
  }

  void local_result(const char* result, uint64_t version)
  {
    if (current_commit != nullptr && !current_commit->finished())
    {
      current_commit->result(result, version);
    }
  }

  void compact(const AbstractStore* store, uint64_t version, uint64_t requested)
  {
    with_store(store, [&](Sink& sink, StoreInfo& info) {
      sink.check_boundary(info.id);
      sink.append(
        "compact",
        {{"store", info.id}, {"version", version}, {"requested", requested}});
      info.global = version;
    });
  }

  Rollback::Rollback(const AbstractStore* store_) : store(store_)
  {
    with_store(store, [](Sink& sink, StoreInfo& info) {
      if (info.acquisitions != 0)
      {
        sink.append(
          "unsupported",
          {{"store", info.id},
           {"operation", "map acquisition overlaps rollback"}});
      }
      info.rolling_back = true;
    });
  }

  Rollback::~Rollback()
  {
    with_store(store, [this](Sink& sink, StoreInfo& info) {
      info.rolling_back = false;
      if (!complete)
      {
        sink.append(
          "unsupported",
          {{"store", info.id}, {"operation", "rollback exception"}});
      }
    });
  }

  void Rollback::result(uint64_t version, uint64_t requested, uint64_t term)
  {
    with_store(store, [&](Sink& sink, StoreInfo& info) {
      info.term_observed = true;
      sink.append(
        "rollback",
        {{"store", info.id},
         {"version", version},
         {"requested", requested},
         {"term", term}});
      info.rolling_back = false;
    });
    complete = true;
  }

  void Rollback::rejected(uint64_t requested, uint64_t term)
  {
    with_store(store, [&](Sink& sink, StoreInfo& info) {
      sink.append(
        "rollback_rejected",
        {{"store", info.id}, {"requested", requested}, {"term", term}});
      info.rolling_back = false;
    });
    complete = true;
  }
}
