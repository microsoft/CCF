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
#include "lru_indexer.h"

namespace externalexecutor
{
  using DetachedIndexStream =
    ccf::grpc::DetachedStreamPtr<externalexecutor::protobuf::IndexWork>;
  using IndexStream =
    ccf::grpc::StreamPtr<externalexecutor::protobuf::IndexWork>;
  using BucketValue = std::pair<ccf::indexing::FetchResultPtr, std::string>;

  class MapIndex : public ccf::indexing::Strategy
  {
  protected:
    const std::string map_name;
    std::string strategy_name = "MapIndex";
    ccf::TxID current_txid = {};
    ExecutorId indexer_id;
    ccf::endpoints::CommandEndpointContext* endpoint_ctx;
    IndexStream out_stream;
    bool is_indexer_active = false;
    DetachedIndexStream detached_stream;

  public:
    // store unserialized indexed Key-Value data
    // wrap it in LRU?
    LRU<std::string, std::string> indexed_data_;
    std::unordered_map<std::string, std::string> indexed_data;
    std::unordered_map<std::string, BucketValue> results_in_progress;

    MapIndex(
      const std::string& map_name_,
      const std::string& strategy_prefix,
      ExecutorId& id,
      ccf::endpoints::CommandEndpointContext& ctx,
      IndexStream&& stream) :
      Strategy(strategy_prefix),
      map_name(map_name_),
      indexer_id(id),
      endpoint_ctx(&ctx),
      out_stream(std::move(stream)),
      is_indexer_active(true),
      indexed_data_(10)
    {
      if (kv::get_security_domain(map_name_) != kv::SecurityDomain::PUBLIC)
      {
        throw std::logic_error(fmt::format(
          "This Strategy ({}) is currently only implemented for public tables, "
          "so cannot be used for '{}'",
          get_name(),
          map_name_));
      }
      // create a detached stream pointer of the indexer
      detached_stream =
        ccf::grpc::detach_stream(ctx.rpc_ctx, std::move(out_stream), [this]() {
          is_indexer_active = false;
        });
    }

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const kv::ReadOnlyStorePtr& store) override
    {
      auto tx = store->create_read_only_tx();
      auto handle = tx.ro<Map>(map_name);

      handle->foreach([this](const auto& k, const auto& v) {
        externalexecutor::protobuf::IndexWork data;
        externalexecutor::protobuf::IndexKeyValue* index_key_value =
          data.mutable_key_value();
        index_key_value->set_key(k);
        index_key_value->set_value(v);
        if (is_indexer_active)
        {
          // stream transactions to the indexer
          if (!out_stream->stream_msg(data))
          {
            LOG_DEBUG_FMT("Failed to stream request to indexer {}", indexer_id);
          }
        }

        return true;
      });
      current_txid = tx_id;
    }

    std::optional<ccf::SeqNo> next_requested() override
    {
      return current_txid.seqno + 1;
    }
  };

  // Note: move this into a different scope
  using MapStrategyPtr = std::shared_ptr<MapIndex>;
  std::unordered_map<std::string, MapStrategyPtr> map_index_strategies;
  std::shared_ptr<ccf::indexing::AbstractLFSAccess> lfs_access;

  static std::optional<std::string> fetch_data(
    MapStrategyPtr strategy, std::string& key)
  {
    bool complete = true;
    ccf::pal::Mutex results_access;

    while (true)
    {
      std::lock_guard<ccf::pal::Mutex> guard(results_access);

      const auto old_it = strategy->results_in_progress.find(key);
      if (old_it != strategy->results_in_progress.end())
      {
        auto& bucket_value = old_it->second;

        // We were already trying to fetch this. If it's finished fetching,
        // parse and store the result
        if (bucket_value.first != nullptr)
        {
          const auto fetch_result = bucket_value.first->fetch_result;
          switch (fetch_result)
          {
            case (ccf::indexing::FetchResult::Fetching):
            {
              complete = false;
              break;
            }
            case (ccf::indexing::FetchResult::Loaded):
            {
              bool corrupt = false;
              std::string val(
                bucket_value.first->contents.begin(),
                bucket_value.first->contents.end());
              bucket_value.second = val;
              if (!corrupt)
              {
                bucket_value.first = nullptr;
                break;
              }
              else
              {
                // Deliberately fall through to the case below. If this can't
                // deserialise the value, consider the file corrupted
                LOG_FAIL_FMT("Deserialisation failed");
              }
            }
            case (ccf::indexing::FetchResult::NotFound):
            case (ccf::indexing::FetchResult::Corrupt):
            {
              complete = false;
              const auto problem =
                fetch_result == ccf::indexing::FetchResult::NotFound ?
                "missing" :
                "corrupt";
              LOG_FAIL_FMT(
                "A file that indexer requires is {}. Re-indexing.", problem);
              LOG_DEBUG_FMT(
                "The {} file is {}", problem, bucket_value.first->key);

              strategy->results_in_progress.clear();
              strategy->indexed_data.clear();
              return std::nullopt;
              break;
            }
          }
        }
      }
      else
      {
        // We're not currently fetching this. First check if it's in our
        // current results
        const auto current_it = strategy->indexed_data.find(key);
        if (current_it != strategy->indexed_data.end())
        {
          if (complete)
          {
            return strategy->indexed_data[key];
          }
        }

        else
        {
          // Begin fetching this bucket from disk
          auto hex_key = ds::to_hex(key.begin(), key.end());
          std::string blob_key = fmt::format("{}:{}", "table-name", hex_key);
          auto fetch_handle = lfs_access->fetch(blob_key);
          std::string value;
          strategy->results_in_progress[key] =
            std::make_pair(fetch_handle, value);
          complete = false;
        }
      }
    }
  }
}