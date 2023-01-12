// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/strategy.h"
#include "ccf/kv/map.h"
#include "endpoints/grpc/grpc.h"
#include "executor_auth_policy.h"
#include "index.pb.h"
#include "kv/kv_types.h"

namespace externalexecutor
{
  using DetachedIndexStream =
    ccf::grpc::DetachedStreamPtr<externalexecutor::protobuf::IndexWork>;
  using IndexStream =
    ccf::grpc::StreamPtr<externalexecutor::protobuf::IndexWork>;

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
    std::unordered_map<std::string, std::string> indexed_data;

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
}