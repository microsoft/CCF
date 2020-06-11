// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "kv/store.h"
#include "node/rpc/handler_registry.h"

#include <memory>

namespace ccf::historical
{
  using StorePtr = std::shared_ptr<kv::Store>;

  class AbstractStateCache
  {
  public:
    virtual ~AbstractStateCache() = default;

    virtual StorePtr get_store_at(consensus::Index idx) = 0;
  };

  class StubStateCache : public AbstractStateCache
  {
  public:
    StorePtr get_store_at(consensus::Index idx) override
    {
      return nullptr;
    }
  };

  using HandleHistoricalQuery = std::function<void(
    ccf::RequestArgs& args,
    StorePtr store,
    kv::Consensus::View view,
    kv::Consensus::SeqNo seqno)>;

  static ccf::HandleFunction adapter(
    const HandleHistoricalQuery& f, AbstractStateCache& state_cache)
  {
    return [f, &state_cache](RequestArgs& args) {
      // Extract the requested transaction ID
      kv::Consensus::View target_view;
      kv::Consensus::SeqNo target_seqno;

      {
        const auto target_view_opt =
          args.rpc_ctx->get_request_header(http::headers::CCF_TX_VIEW);
        if (!target_view_opt.has_value())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_body(fmt::format(
            "Historical query is missing '{}' header",
            http::headers::CCF_TX_VIEW));
          return;
        }

        target_view =
          std::strtoul(target_view_opt.value().c_str(), nullptr, 10);
        if (target_view == 0)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_body(fmt::format(
            "The value '{}' in header '{}' could not be converted to a valid "
            "view",
            target_view_opt.value(),
            http::headers::CCF_TX_VIEW));
          return;
        }

        const auto target_seqno_opt =
          args.rpc_ctx->get_request_header(http::headers::CCF_TX_SEQNO);
        if (!target_seqno_opt.has_value())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_body(fmt::format(
            "Historical query is missing '{}' header",
            http::headers::CCF_TX_SEQNO));
          return;
        }

        target_seqno =
          std::strtoul(target_seqno_opt.value().c_str(), nullptr, 10);
        if (target_view == 0)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_body(fmt::format(
            "The value '{}' in header '{}' could not be converted to a valid "
            "seqno",
            target_seqno_opt.value(),
            http::headers::CCF_TX_SEQNO));
          return;
        }
      }

      // TODO: How to access consensus here?
      // // Check that the requested transaction ID is committed
      // {
      //   const auto tx_view = consensus->get_view(in.seqno);
      //   const auto committed_seqno = consensus->get_committed_seqno();
      //   const auto committed_view = consensus->get_view(committed_seqno);

      //   const auto tx_status = ccf::get_tx_status(
      //     in.view, in.seqno, tx_view, committed_view, committed_seqno);
      //   if (tx_status != ccf::TxStatus::Committed)
      //   {
      //     args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
      //     args.rpc_ctx->set_response_header(
      //       http::headers::CONTENT_TYPE,
      //       http::headervalues::contenttype::TEXT);
      //     args.rpc_ctx->set_response_body(fmt::format(
      //       "Only committed transactions can be retrieved historically. "
      //       "Transaction {}.{} is {}",
      //       in.view,
      //       in.seqno,
      //       ccf::tx_status_to_str(tx_status)));
      //     return;
      //   }
      // }

      auto historical_store = state_cache.get_store_at(target_seqno);
      if (historical_store == nullptr)
      {
        args.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
        static constexpr size_t retry_after_seconds = 3;
        args.rpc_ctx->set_response_header(
          http::headers::RETRY_AFTER, retry_after_seconds);
        args.rpc_ctx->set_response_body(fmt::format(
          "Historical transaction at seqno {} in view {} is not currently "
          "available.",
          target_seqno,
          target_view));
        return;
      }

      f(args, historical_store, target_view, target_seqno);
    };
  }
}