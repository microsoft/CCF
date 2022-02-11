// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_deprecated.h"
#include "ccf/endpoint_context.h"
#include "ccf/historical_queries_interface.h"
#include "ccf/tx_id.h"
#include "ccf/tx_status.h"

namespace ccf::historical
{
  using CheckAvailability = std::function<bool(
    ccf::View view, ccf::SeqNo seqno, std::string& error_reason)>;

  using HandleHistoricalQuery =
    std::function<void(ccf::endpoints::EndpointContext& args, StatePtr state)>;

  using TxIDExtractor =
    std::function<std::optional<ccf::TxID>(endpoints::EndpointContext& args)>;

  static inline std::optional<ccf::TxID> txid_from_header(
    endpoints::EndpointContext& args)
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
      return std::nullopt;
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
      return std::nullopt;
    }

    return tx_id_opt;
  }

  static inline bool is_tx_committed_v1(
    kv::Consensus* consensus,
    ccf::View view,
    ccf::SeqNo seqno,
    std::string& error_reason)
  {
    if (consensus == nullptr)
    {
      error_reason = "Node is not fully configured";
      return false;
    }

    const auto tx_view = consensus->get_view(seqno);
    const auto committed_seqno = consensus->get_committed_seqno();
    const auto committed_view = consensus->get_view(committed_seqno);

    const auto tx_status = ccf::evaluate_tx_status(
      view, seqno, tx_view, committed_view, committed_seqno);
    if (tx_status != ccf::TxStatus::Committed)
    {
      error_reason = fmt::format(
        "Only committed transactions can be queried. Transaction {}.{} "
        "is "
        "{}",
        view,
        seqno,
        ccf::tx_status_to_str(tx_status));
      return false;
    }

    return true;
  };

  enum class HistoricalTxStatus
  {
    Error,
    PendingOrUnknown,
    Invalid,
    Valid
  };

  using CheckHistoricalTxStatus = std::function<HistoricalTxStatus(
    ccf::View view, ccf::SeqNo seqno, std::string& error_reason)>;

  static inline HistoricalTxStatus is_tx_committed_v2(
    kv::Consensus* consensus,
    ccf::View view,
    ccf::SeqNo seqno,
    std::string& error_reason)
  {
    if (consensus == nullptr)
    {
      error_reason = "Node is not fully configured";
      return HistoricalTxStatus::Error;
    }

    const auto tx_view = consensus->get_view(seqno);
    const auto committed_seqno = consensus->get_committed_seqno();
    const auto committed_view = consensus->get_view(committed_seqno);

    const auto tx_status = ccf::evaluate_tx_status(
      view, seqno, tx_view, committed_view, committed_seqno);
    switch (tx_status)
    {
      case ccf::TxStatus::Unknown:
      case ccf::TxStatus::Pending:
        error_reason = fmt::format(
          "Only committed transactions can be queried. Transaction {}.{} "
          "is "
          "{}",
          view,
          seqno,
          ccf::tx_status_to_str(tx_status));
        return HistoricalTxStatus::PendingOrUnknown;
      case ccf::TxStatus::Invalid:
        error_reason = fmt::format(
          "Only committed transactions can be queried. Transaction {}.{} "
          "is "
          "{}",
          view,
          seqno,
          ccf::tx_status_to_str(tx_status));
        return HistoricalTxStatus::Invalid;
      case ccf::TxStatus::Committed:;
    }

    return HistoricalTxStatus::Valid;
  };

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

  static ccf::endpoints::EndpointFunction adapter_v2(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor = txid_from_header)
  {
    return [f, &state_cache, available, extractor](
             endpoints::EndpointContext& args) {
      // Extract the requested transaction ID
      ccf::TxID target_tx_id;
      {
        const auto tx_id_opt = extractor(args);
        if (tx_id_opt.has_value())
        {
          target_tx_id = tx_id_opt.value();
        }
        else
        {
          return;
        }
      }

      // Check that the requested transaction ID is available
      {
        auto error_reason = fmt::format(
          "Transaction {} is not available.", target_tx_id.to_str());
        auto is_available =
          available(target_tx_id.view, target_tx_id.seqno, error_reason);
        switch (is_available)
        {
          case HistoricalTxStatus::Error:
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::TransactionPendingOrUnknown,
              std::move(error_reason));
            return;
          }
          case HistoricalTxStatus::PendingOrUnknown:
          {
            // Set header No-Cache
            args.rpc_ctx->set_response_header(
              http::headers::CACHE_CONTROL, "no-cache");
            args.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::TransactionPendingOrUnknown,
              std::move(error_reason));
            return;
          }
          case HistoricalTxStatus::Invalid:
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::TransactionInvalid,
              std::move(error_reason));
            return;
          }
          case HistoricalTxStatus::Valid:
          {
          }
        }
      }

      // We need a handle to determine whether this request is the 'same' as a
      // previous one. For simplicity we use target_tx_id.seqno. This means we
      // keep a lot of state around for old requests! It should be cleaned up
      // manually
      const auto historic_request_handle = target_tx_id.seqno;

      // Get a state at the target version from the cache, if it is present
      auto historical_state =
        state_cache.get_state_at(historic_request_handle, target_tx_id.seqno);
      if (historical_state == nullptr)
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
      f(args, historical_state);
    };
  }

  CCF_DEPRECATED(
    "Will be removed in 2.0, switch to ccf::historical::adapter_v2")
  static ccf::endpoints::EndpointFunction adapter_v1(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckAvailability& available,
    const TxIDExtractor& extractor = txid_from_header)
  {
    return [f, &state_cache, available, extractor](
             endpoints::EndpointContext& args) {
      // Extract the requested transaction ID
      ccf::TxID target_tx_id;
      {
        const auto tx_id_opt = extractor(args);
        if (tx_id_opt.has_value())
        {
          target_tx_id = tx_id_opt.value();
        }
        else
        {
          return;
        }
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

      // Get a state at the target version from the cache, if it is present
      auto historical_state =
        state_cache.get_state_at(historic_request_handle, target_tx_id.seqno);
      if (historical_state == nullptr)
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
      f(args, historical_state);
    };
  }

  // These unversioned aliases are here for compatibility reasons,
  // but the intention is to remove them come 2.0, and make all usage
  // explicitly versioned
  CCF_DEPRECATED(
    "Will be removed in 2.0, switch to ccf::historical::adapter_v2")
  static ccf::endpoints::EndpointFunction adapter(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckAvailability& available,
    const TxIDExtractor& extractor = txid_from_header)
  {
    return adapter_v1(f, state_cache, available, extractor);
  }

  const auto is_tx_committed = is_tx_committed_v1;

#pragma clang diagnostic pop
}