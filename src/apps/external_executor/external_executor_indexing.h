// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

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
  class MapIndex;

  using MapStrategyPtr = std::shared_ptr<MapIndex>;
  using DetachedIndexStream =
    ccf::grpc::DetachedStreamPtr<externalexecutor::protobuf::IndexWork>;
  using IndexStream =
    ccf::grpc::StreamPtr<externalexecutor::protobuf::IndexWork>;
  using BucketValue = std::pair<ccf::indexing::FetchResultPtr, std::string>;

  class ImplMapIndex
  {
    LRU<std::string, std::string> indexed_data;
    std::unordered_map<std::string, BucketValue> results_in_progress;
    std::shared_ptr<ccf::indexing::AbstractLFSAccess> lfs_access;

  public:
    ImplMapIndex(
      const std::shared_ptr<ccf::indexing::AbstractLFSAccess>& lfs_access_);
    std::optional<std::string> fetch_data(std::string& key);
    void store_data(std::string& key, std::string& value);
  };

  class MapIndex : public ccf::indexing::Strategy
  {
  protected:
    const std::string map_name;
    std::string strategy_name = "MapIndex";
    ccf::TxID current_txid = {};
    ExecutorId indexer_id;
    ccf::endpoints::CommandEndpointContext* endpoint_ctx;
    ccfapp::AbstractNodeContext& node_context;
    IndexStream out_stream;
    bool is_indexer_active = false;
    DetachedIndexStream detached_stream;
    std::shared_ptr<ImplMapIndex> impl_index = nullptr;

  public:
    MapIndex(
      const std::string& map_name_,
      const std::string& strategy_prefix,
      ExecutorId& id,
      ccf::endpoints::CommandEndpointContext& ctx,
      ccfapp::AbstractNodeContext& node_context,
      IndexStream&& stream);

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const kv::ReadOnlyStorePtr& store) override;

    std::optional<ccf::SeqNo> next_requested() override;

    void store(std::string& key, std::string& value);

    std::optional<std::string> fetch(std::string& key);
  };

  class LRUIndex
  {
  public:
    using Entry = std::pair<const std::string, std::string>;
    using List = std::list<Entry>;
    using Map = std::map<std::string, typename List::iterator>;
    using Iterator = typename List::iterator;
    using ConstIterator = typename List::const_iterator;

  private:
    // Entries are ordered by when they were most recently accessed, with most
    // recent at the front
    List entries_list;

    // Maps from keys to iterators from entries_list, which must remain valid
    // even when entries_list is modified
    Map iter_map;

    std::shared_ptr<ccf::indexing::AbstractLFSAccess> lfs_access;
    size_t max_size;

    void cull()
    {
      while (entries_list.size() > max_size)
      {
        const auto& least_recent_entry = entries_list.back();
        auto key = least_recent_entry.first;
        auto value = least_recent_entry.second;
        auto hex_key = ds::to_hex(key.begin(), key.end());
        std::string blob_key = fmt::format("{}:{}", "table-name", hex_key);
        ccf::indexing::LFSContents contents(value.begin(), value.end());
        lfs_access->store(blob_key, std::move(contents));
        iter_map.erase(least_recent_entry.first);
        entries_list.pop_back();
      }
    }

  public:
    LRUIndex(
      std::shared_ptr<ccf::indexing::AbstractLFSAccess> lfs_ptr,
      size_t max_size) :
      lfs_access(lfs_ptr),
      max_size(max_size)
    {}

    size_t size() const
    {
      return iter_map.size();
    }

    void set_max_size(size_t ms)
    {
      max_size = ms;
      cull();
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
        return it->second->second;
      }

      return std::nullopt;
    }

    Iterator insert(const std::string& k, std::string&& v)
    {
      auto it = iter_map.find(k);
      if (it != iter_map.end())
      {
        // If it already exists, move to the front
        auto& list_it = it->second;
        entries_list.splice(entries_list.begin(), entries_list, list_it);
      }
      else
      {
        // Else add a new entry to both containers, and cull if necessary
        entries_list.push_front(
          std::make_pair(k, std::forward<std::string>(v)));
        const auto list_it = entries_list.begin();
        iter_map.emplace_hint(it, k, list_it);
        cull();
      }

      return entries_list.begin();
    }

    std::string& operator[](std::string&& k)
    {
      auto it = insert(std::forward<std::string>(k), {});
      return it->second;
    }

    void clear()
    {
      entries_list.clear();
      iter_map.clear();
    }
  };
}