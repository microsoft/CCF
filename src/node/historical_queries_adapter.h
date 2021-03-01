// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"
#include "ccf/tx_id.h"
#include "node/rpc/endpoint_registry.h"

namespace ccf::historical
{
  using CheckAvailability = std::function<bool(
    kv::Consensus::View view, kv::SeqNo seqno, std::string& error_reason)>;

  using HandleHistoricalQuery = std::function<void(
    ccf::EndpointContext& args,
    StorePtr store,
    kv::Consensus::View view,
    kv::SeqNo seqno)>;

// Unused in most sample apps
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
  static ccf::EndpointFunction adapter(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckAvailability& available)
  {
    return [f, &state_cache, available](EndpointContext& args) {
      // Extract the requested transaction ID
      ccf::TxID target_tx_id;
      {
        const auto tx_id_header =
          args.rpc_ctx->get_request_header(http::headers::CCF_TX_ID);
        if (!tx_id_header.has_value())
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::MissingRequiredHeader,
            fmt::format(
              "Historical query is missing '{}' header.",
              http::headers::CCF_TX_ID));
          return;
        }

        const auto tx_id_opt = ccf::TxID::from_str(tx_id_header.value());
        if (!tx_id_opt.has_value())
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidHeaderValue,
            fmt::format(
              "The value '{}' in header '{}' could not be converted to a valid "
              "Tx ID.",
              tx_id_header.value(),
              http::headers::CCF_TX_ID));
          return;
        }

        target_tx_id = tx_id_opt.value();
      }

      // Check that the requested transaction ID is available
      {
        auto error_reason = fmt::format(
          "Transaction {} is not available.", target_tx_id.to_str());
        if (!available(target_tx_id.view, target_tx_id.seqno, error_reason))
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::TransactionNotFound,
            std::move(error_reason));
          return;
        }
      }

      // We need a handle to determine whether this request is the 'same' as a
      // previous one. For simplicity we use target_tx_id.seqno. This means we
      // keep a lot of state around for old requests! It should be cleaned up
      // manually
      const auto historic_request_handle = target_tx_id.seqno;

      // Get a store at the target version from the cache, if it is present
      auto historical_store =
        state_cache.get_store_at(historic_request_handle, target_tx_id.seqno);
      if (historical_store == nullptr)
      {
        args.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
        static constexpr size_t retry_after_seconds = 3;
        args.rpc_ctx->set_response_header(
          http::headers::RETRY_AFTER, retry_after_seconds);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(fmt::format(
          "Historical transaction {} is not currently available.",
          target_tx_id.to_str()));
        return;
      }

      // Call the provided handler
      f(args, historical_store, target_tx_id.view, target_tx_id.seqno);
    };
  }
#pragma clang diagnostic pop
}