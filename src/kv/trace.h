// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef CCF_KV_TRACING
#  include "ccf/ds/hex.h"

#  include <nlohmann/json.hpp>
#  include <string>

namespace ccf::kv::trace
{
  using Json = nlohmann::json;

  struct Identity
  {
    uint64_t store = 0;
    uint64_t tx = 0;
  };

  bool enabled();
  void start();
  void finish();
  void event(const char* type, Json fields = Json::object());
  void operation(
    Identity id,
    const char* type,
    const std::string& map,
    Json fields = Json::object());
  void transaction(Identity id, const char* type, Json fields = Json::object());
  void unsupported(const void* store, const std::string& operation);
  void store_create(const void* store);
  void store_end(const void* store);

  struct Attempt
  {
    Identity id;
    void bind(const void* store);
    ~Attempt();
  };

  // These contexts only identify the caller at existing KV lock boundaries.
  // They never acquire a KV lock, nor extend its lifetime.
  class Commit;

  class Context
  {
    Identity previous;
    const Json* previous_writes;
    Commit* previous_commit;

  public:
    Context(
      Identity id, const Json* writes = nullptr, Commit* commit = nullptr);
    ~Context();
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
  };

  Identity context();
  void snapshot(const void* store, uint64_t version, uint64_t term);
  void initialise_term(const void* store);
  void apply(const void* store, uint64_t version, uint64_t term);
  void local_result(const char* result, uint64_t version);
  void compact(const void* store, uint64_t version, uint64_t requested);

  class Environment
  {
    bool previous;

  public:
    Environment();
    ~Environment();
    Environment(const Environment&) = delete;
    Environment& operator=(const Environment&) = delete;
  };

  bool in_environment();

  class Commit
  {
    Identity id;
    bool complete = false;
    std::string recorded_result;
    uint64_t recorded_version = 0;

  public:
    explicit Commit(Identity id_) : id(id_)
    {
      transaction(id, "commit_begin");
    }
    ~Commit()
    {
      if (!complete)
      {
        transaction(
          id, "unsupported", {{"operation", "commit exited without result"}});
      }
    }
    void result(const char* result_, uint64_t version)
    {
      if (complete)
      {
        if (recorded_result != result_ || recorded_version != version)
        {
          transaction(
            id, "unsupported", {{"operation", "commit result changed"}});
        }
        return;
      }
      transaction(
        id, "commit_result", {{"result", result_}, {"version", version}});
      complete = true;
      recorded_result = result_;
      recorded_version = version;
    }
    bool finished() const
    {
      return complete;
    }
    Commit(const Commit&) = delete;
    Commit& operator=(const Commit&) = delete;
  };

  // Rollback publishes its version before locking maps. Overlapping accesses
  // cannot be represented by the atomic wire event and must fail closed.
  class Rollback
  {
    const void* store;
    bool complete = false;

  public:
    explicit Rollback(const void* store_);
    ~Rollback();
    void result(uint64_t version, uint64_t requested, uint64_t term);
    void rejected(uint64_t requested, uint64_t term);
    Rollback(const Rollback&) = delete;
    Rollback& operator=(const Rollback&) = delete;
  };

  struct MapMetadata
  {
    Identity id;
    size_t suppressed = 0;
    uint64_t iteration = 0;
  };

  class Suppress
  {
    MapMetadata& metadata;

  public:
    explicit Suppress(MapMetadata& metadata_) : metadata(metadata_)
    {
      ++metadata.suppressed;
    }
    ~Suppress()
    {
      --metadata.suppressed;
    }
    Suppress(const Suppress&) = delete;
    Suppress& operator=(const Suppress&) = delete;
  };

  inline void operation(
    const MapMetadata& metadata,
    const char* type,
    const std::string& map,
    Json fields = Json::object())
  {
    if (metadata.suppressed == 0)
    {
      operation(metadata.id, type, map, std::move(fields));
    }
  }

  template <typename T>
  Json bytes(const T* value)
  {
    return value == nullptr ? Json(nullptr) : Json(ccf::ds::to_hex(*value));
  }
}
#  define KV_TRACE(...) \
    do \
    { \
      if (ccf::kv::trace::enabled()) \
      { \
        __VA_ARGS__; \
      } \
    } while (false)
#else
#  define KV_TRACE(...) \
    do \
    { \
    } while (false)
#endif
