// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "external_executor_indexing.h"

namespace externalexecutor
{
  MapIndex::MapIndex(
    const std::shared_ptr<ccf::indexing::AbstractLFSAccess>& lfs_access_,
    const std::string& map) :
    lfs_access(lfs_access_),
    indexed_data(lfs_access_, 1000, map),
    map_name(map)
  {}

  std::optional<std::string> MapIndex::fetch_data(const std::string& key)
  {
    std::lock_guard<ccf::pal::Mutex> guard(results_access);

    const auto results = results_in_progress.find(key);
    if (results != results_in_progress.end())
    {
      auto& bucket_value = results->second;

      // We were already trying to fetch this. If it's finished fetching,
      // parse and store the result
      const auto fetch_result = bucket_value->fetch_result;
      switch (fetch_result)
      {
        case (ccf::indexing::FetchResult::Fetching):
        {
          return std::nullopt;
        }
        case (ccf::indexing::FetchResult::Loaded):
        {
          std::string val(
            bucket_value->contents.begin(), bucket_value->contents.end());
          return val;
        }
        case (ccf::indexing::FetchResult::NotFound):
        case (ccf::indexing::FetchResult::Corrupt):
        {
          const auto problem =
            fetch_result == ccf::indexing::FetchResult::NotFound ? "missing" :
                                                                   "corrupt";
          LOG_FAIL_FMT("A file that indexer requires is {}.", problem);
          LOG_DEBUG_FMT("The {} file is {}", problem, bucket_value->key);
          return std::nullopt;
          break;
        }
      }
    }
    else
    {
      // We're not currently fetching this. First check if it's in our
      // current results
      const auto current_result = indexed_data.find(key);
      if (current_result.has_value())
      {
        return current_result.value();
      }
      else
      {
        // Begin fetching this bucket from disk
        std::string blob_name = get_blob_name(map_name, key);
        auto fetch_handle = lfs_access->fetch(blob_name);
        results_in_progress[key] = fetch_handle;
      }
    }
    return std::nullopt;
  }

  void MapIndex::store_data(const std::string& key, const std::string& value)
  {
    indexed_data.insert(key, std::move(value));
  }

  ExecutorIndex::ExecutorIndex(
    const std::string& map_name_,
    const std::string& strategy_prefix,
    IndexDataStructure ds,
    ExecutorId& id,
    ccf::endpoints::CommandEndpointContext& ctx,
    ccfapp::AbstractNodeContext& node_ctx,
    IndexStream&& stream) :
    Strategy(strategy_prefix),
    map_name(map_name_),
    data_structure(ds),
    indexer_id(id),
    endpoint_ctx(&ctx),
    node_context(&node_ctx),
    out_stream(std::move(stream)),
    is_indexer_active(true)
  {
    if (kv::get_security_domain(map_name_) != kv::SecurityDomain::PUBLIC)
    {
      throw std::logic_error(fmt::format(
        "This Strategy ({}) is currently only implemented for public tables, "
        "so cannot be used for '{}'",
        get_name(),
        map_name_));
    }
    if (data_structure == MAP)
    {
      impl_index = std::make_unique<MapIndex>(
        node_context->get_subsystem<ccf::indexing::AbstractLFSAccess>(),
        map_name);
    }
    else if (data_structure == PREFIX_TREE)
    {
      impl_index = std::make_unique<PrefixTreeIndex>();
    }

    // create a detached stream pointer of the indexer
    detached_stream =
      ccf::grpc::detach_stream(ctx.rpc_ctx, std::move(out_stream), [this]() {
        is_indexer_active = false;
      });
  }

  void ExecutorIndex::handle_committed_transaction(
    const ccf::TxID& tx_id, const kv::ReadOnlyStorePtr& store)
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
        if (!detached_stream->stream_msg(data))
        {
          is_indexer_active = false;
          LOG_FAIL_FMT("Failed to stream request to indexer {}", indexer_id);
          return false;
        }
      }

      return true;
    });
    current_txid = tx_id;
  }

  std::optional<ccf::SeqNo> ExecutorIndex::next_requested()
  {
    return current_txid.seqno + 1;
  }

  void ExecutorIndex::store(const std::string& key, const std::string& value)
  {
    impl_index->store_data(key, value);
  }

  std::optional<std::string> ExecutorIndex::fetch(const std::string& key)
  {
    return impl_index->fetch_data(key);
  }
}