// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_endpoint_registry.h"
#include "ccf/ds/logger.h"
#include "ccf/indexing/strategy.h"
#include "ccf/kv/map.h"
#include "ccf/pal/locking.h"
#include "ds/lru.h"
#include "endpoints/grpc/grpc.h"
#include "executor_auth_policy.h"
#include "index.pb.h"
#include "indexing/lfs_interface.h"
#include "kv/kv_types.h"

namespace externalexecutor
{
  class ExecutorIndex;

  using MapIndexPtr = std::shared_ptr<ExecutorIndex>;
  using DetachedIndexStream =
    ccf::grpc::DetachedStreamPtr<externalexecutor::protobuf::IndexWork>;
  using IndexStream =
    ccf::grpc::StreamPtr<externalexecutor::protobuf::IndexWork>;
  using BucketValue = ccf::indexing::FetchResultPtr;

  namespace
  {
    std::string get_blob_name(
      const std::string& map_name, const std::string& key)
    {
      auto hex_key = ds::to_hex(key.begin(), key.end());
      std::string blob_name = fmt::format("{}:{}", map_name, hex_key);
      return blob_name;
    }

    std::string get_storage_type(
      const externalexecutor::protobuf::DataStructure& ds)
    {
      switch (ds)
      {
        case (externalexecutor::protobuf::DataStructure::PREFIX_TREE):
        {
          return "PREFIX_TREE";
        }
        case (externalexecutor::protobuf::DataStructure::MAP):
        {
          return "MAP";
        }
        default:
        {
          return "Unknown";
        }
      }
    }
  } // namespace

  class LRUIndexCache
  {
  public:
    using Entry = std::pair<const std::string, std::string>;
    using List = std::list<Entry>;
    using Map = std::map<std::string, typename List::iterator>;

  private:
    ccf::pal::Mutex results_access;
    // Entries are ordered by when they were most recently accessed, with most
    // recent at the front
    List entries_list;

    // Maps from keys to iterators from entries_list, which must remain valid
    // even when entries_list is modified
    Map iter_map;

    std::shared_ptr<ccf::indexing::AbstractLFSAccess> lfs_access;
    size_t max_size;
    const std::string map_name;

    void flush_to_disk()
    {
      while (entries_list.size() > max_size)
      {
        const auto& least_recent_entry = entries_list.back();
        auto key = least_recent_entry.first;
        auto value = least_recent_entry.second;
        std::string blob_name = get_blob_name(map_name, key);
        ccf::indexing::LFSContents contents(value.begin(), value.end());
        lfs_access->store(blob_name, std::move(contents));
        iter_map.erase(least_recent_entry.first);
        entries_list.pop_back();
      }
    }

  public:
    LRUIndexCache() {}
    LRUIndexCache(
      std::shared_ptr<ccf::indexing::AbstractLFSAccess> lfs_ptr,
      size_t max_size,
      const std::string& map) :
      lfs_access(lfs_ptr),
      max_size(max_size),
      map_name(map)
    {}

    size_t size() const
    {
      return iter_map.size();
    }

    void set_max_size(size_t ms)
    {
      max_size = ms;
    }

    size_t get_max_size() const
    {
      return max_size;
    }

    std::optional<std::string> find(const std::string& k)
    {
      const auto it = iter_map.find(k);
      if (it != iter_map.end())
      {
        // move it to the front and return
        auto& list_it = it->second;
        entries_list.splice(entries_list.begin(), entries_list, list_it);
        return list_it->second;
      }

      return std::nullopt;
    }

    void insert(const std::string& k, const std::string& v)
    {
      std::lock_guard<ccf::pal::Mutex> guard(results_access);
      auto it = iter_map.find(k);
      if (it != iter_map.end())
      {
        // If it already exists, move to the front
        auto& list_it = it->second;
        list_it->second = v;
        entries_list.splice(entries_list.begin(), entries_list, list_it);
      }
      else
      {
        // Else add a new entry to both containers, and flush if necessary
        entries_list.push_front(std::make_pair(k, v));
        const auto list_it = entries_list.begin();
        iter_map.emplace_hint(it, k, list_it);
        flush_to_disk();
      }
    }

    void clear()
    {
      entries_list.clear();
      iter_map.clear();
    }
  };

  class ImplIndex
  {
  public:
    virtual std::optional<std::string> fetch_data(const std::string& key) = 0;
    virtual void store_data(
      const std::string& key, const std::string& value) = 0;
    virtual ~ImplIndex() {}
  };

  class MapIndex : public ImplIndex
  {
    ccf::pal::Mutex results_access;
    std::unordered_map<std::string, BucketValue> results_in_progress;
    std::shared_ptr<ccf::indexing::AbstractLFSAccess> lfs_access;
    LRUIndexCache indexed_data;
    const std::string map_name;

  public:
    MapIndex() {}
    MapIndex(
      const std::shared_ptr<ccf::indexing::AbstractLFSAccess>& lfs_access_,
      const std::string& map_name);

    std::optional<std::string> fetch_data(const std::string& key) override;
    void store_data(const std::string& key, const std::string& value) override;
  };

  class PrefixTreeIndex : public ImplIndex
  {
  public:
    PrefixTreeIndex() {}

    std::optional<std::string> fetch_data(const std::string& key) override
    {
      return std::nullopt;
    };
    void store_data(
      const std::string& key, const std::string& value) override{};
  };

  class ExecutorIndex
  {
  protected:
    const std::string map_name;
    std::string data_structure;
    ccfapp::AbstractNodeContext* node_context;
    std::unique_ptr<ImplIndex> impl_index = nullptr;

  public:
    ExecutorIndex(
      externalexecutor::protobuf::DataStructure& storage_type,
      ccfapp::AbstractNodeContext& node_ctx);

    void store(const std::string& key, const std::string& value);

    std::optional<std::string> fetch(const std::string& key);
  };

  class ExecutorStrategy : public ccf::indexing::Strategy
  {
  protected:
    const std::string map_name;
    ccf::TxID current_txid = {};
    ExecutorId indexer_id;

  public:
    DetachedIndexStream detached_stream;

    ExecutorStrategy(const std::string& map_name_, ExecutorId& id);

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const kv::ReadOnlyStorePtr& store) override;

    std::optional<ccf::SeqNo> next_requested() override;
  };
}