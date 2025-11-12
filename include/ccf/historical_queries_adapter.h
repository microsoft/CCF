// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_deprecated.h"
#include "ccf/endpoint_context.h"
#include "ccf/historical_queries_interface.h"
#include "ccf/node_context.h"
#include "ccf/tx_id.h"
#include "ccf/tx_status.h"

namespace ccf::kv
{
  class Consensus;
}

namespace ccf::historical
{
  using CheckAvailability = std::function<bool(
    ccf::View view, ccf::SeqNo seqno, std::string& error_reason)>;

  using HandleReadWriteHistoricalQuery =
    std::function<void(ccf::endpoints::EndpointContext& args, StatePtr state)>;

  using HandleReadOnlyHistoricalQuery = std::function<void(
    ccf::endpoints::ReadOnlyEndpointContext& args, StatePtr state)>;

  using HandleHistoricalQuery = HandleReadWriteHistoricalQuery;

  using CommandTxIDExtractor = std::function<std::optional<ccf::TxID>(
    endpoints::CommandEndpointContext& args)>;

  using ReadOnlyTxIDExtractor = std::function<std::optional<ccf::TxID>(
    endpoints::ReadOnlyEndpointContext& args)>;

  using TxIDExtractor =
    std::function<std::optional<ccf::TxID>(endpoints::EndpointContext& args)>;

  std::optional<ccf::TxID> txid_from_header(
    endpoints::CommandEndpointContext& args);

  enum class HistoricalQueryErrorCode : uint8_t
  {
    InternalError,
    TransactionPending,
    TransactionInvalid,
    TransactionIdMissing,
    TransactionPartiallyReady,
  };

  using ErrorHandler = std::function<void(
    HistoricalQueryErrorCode err,
    std::string reason,
    endpoints::EndpointContext& args)>;

  using ReadOnlyErrorHandler = std::function<void(
    HistoricalQueryErrorCode err,
    std::string reason,
    endpoints::ReadOnlyEndpointContext& args)>;

  void default_error_handler(
    HistoricalQueryErrorCode err,
    std::string reason,
    endpoints::CommandEndpointContext& args);

  enum class HistoricalTxStatus : uint8_t
  {
    Error,
    PendingOrUnknown,
    Invalid,
    Valid
  };

  using CheckHistoricalTxStatus = std::function<HistoricalTxStatus(
    ccf::View view, ccf::SeqNo seqno, std::string& error_reason)>;

  HistoricalTxStatus is_tx_committed_v2(
    ccf::kv::Consensus* consensus,
    ccf::View view,
    ccf::SeqNo seqno,
    std::string& error_reason);

  CCF_DEPRECATED("Replaced by _v4")
  ccf::endpoints::EndpointFunction adapter_v3(
    const HandleHistoricalQuery& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor = txid_from_header);

  CCF_DEPRECATED("Replaced by _v4")
  ccf::endpoints::ReadOnlyEndpointFunction read_only_adapter_v3(
    const HandleReadOnlyHistoricalQuery& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const ReadOnlyTxIDExtractor& extractor = txid_from_header);

  CCF_DEPRECATED("Replaced by _v4")
  ccf::endpoints::EndpointFunction read_write_adapter_v3(
    const HandleReadWriteHistoricalQuery& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor = txid_from_header);

  ccf::endpoints::ReadOnlyEndpointFunction read_only_adapter_v4(
    const HandleReadOnlyHistoricalQuery& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const ReadOnlyTxIDExtractor& extractor = txid_from_header,
    const ReadOnlyErrorHandler& ehandler = default_error_handler);

  ccf::endpoints::EndpointFunction read_write_adapter_v4(
    const HandleReadWriteHistoricalQuery& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor = txid_from_header,
    const ErrorHandler& ehandler = default_error_handler);
}