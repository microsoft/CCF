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

  using HandleHistoricalQuery =
    std::function<void(ccf::endpoints::EndpointContext& args, StatePtr state)>;

  using TxIDExtractor =
    std::function<std::optional<ccf::TxID>(endpoints::EndpointContext& args)>;

  std::optional<ccf::TxID> txid_from_header(endpoints::EndpointContext& args);

  bool is_tx_committed_v1(
    kv::Consensus* consensus,
    ccf::View view,
    ccf::SeqNo seqno,
    std::string& error_reason);

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

  CCF_DEPRECATED(
    "Will be removed in 2.0, switch to ccf::historical::adapter_v3")
  ccf::endpoints::EndpointFunction adapter_v1(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckAvailability& available,
    const TxIDExtractor& extractor = txid_from_header);

  // These unversioned aliases are here for compatibility reasons,
  // but the intention is to remove them come 2.0, and make all usage
  // explicitly versioned
  CCF_DEPRECATED(
    "Will be removed in 2.0, switch to ccf::historical::adapter_v3")
  ccf::endpoints::EndpointFunction adapter(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckAvailability& available,
    const TxIDExtractor& extractor = txid_from_header);

  CCF_DEPRECATED(
    "Will be removed in 2.0, switch to ccf::historical::is_tx_committed_v2")
  bool is_tx_committed(
    kv::Consensus* consensus,
    ccf::View view,
    ccf::SeqNo seqno,
    std::string& error_reason);
  /// @endcond
}