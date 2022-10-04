// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_deprecated.h"
#include "ccf/endpoint_context.h"
#include "ccf/historical_queries_interface.h"
#include "ccf/node_context.h"
#include "ccf/tx_id.h"
#include "ccf/tx_status.h"

namespace kv
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

  enum class HistoricalTxStatus
  {
    Error,
    PendingOrUnknown,
    Invalid,
    Valid
  };

  using CheckHistoricalTxStatus = std::function<HistoricalTxStatus(
    ccf::View view, ccf::SeqNo seqno, std::string& error_reason)>;

  HistoricalTxStatus is_tx_committed_v2(
    kv::Consensus* consensus,
    ccf::View view,
    ccf::SeqNo seqno,
    std::string& error_reason);

  ccf::endpoints::EndpointFunction adapter_v3(
    const HandleHistoricalQuery& f,
    ccfapp::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor = txid_from_header);

  ccf::endpoints::ReadOnlyEndpointFunction read_only_adapter_v3(
    const HandleReadOnlyHistoricalQuery& f,
    ccfapp::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const ReadOnlyTxIDExtractor& extractor = txid_from_header);

  ccf::endpoints::EndpointFunction read_write_adapter_v3(
    const HandleReadWriteHistoricalQuery& f,
    ccfapp::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor = txid_from_header);

  /// @cond
  // Doxygen cannot parse these declarations; some combination of a macro,
  // attribute syntax, and namespaced types results in the following warning
  // (treated as error):
  //   Found ';' while parsing initializer list! (doxygen could be confused by a
  //   macro call without semicolon)
  // Use label-less cond to unconditionally exclude this block from parsing
  // until the declarations are removed are removed.
  CCF_DEPRECATED(
    "Will be removed in 3.0, switch to ccf::historical::adapter_v3")
  ccf::endpoints::EndpointFunction adapter_v2(
    const HandleHistoricalQuery& f,
    ccfapp::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor = txid_from_header);
  /// @endcond
}