// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoints/endpoint_context.h"
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

  /// Selects which endorsements of previous service identities an adapter
  /// attaches to the receipt of the historical state, before calling the
  /// handler. Each of them can delay or fail the request, so handlers should
  /// only ask for the ones they serve.
  enum class ReceiptEndorsements : uint8_t
  {
    /// The receipt is left as produced by the historical state cache.
    None = 0,
    /// X.509 endorsement of the service identity which signed the
    /// transaction, exposed as Receipt::service_endorsements.
    X509 = 1,
    /// Chain of COSE endorsements, exposed by describe_cose_endorsements_v1().
    COSE = 2,
    /// Both of the above.
    All = X509 | COSE
  };

  /// Wraps a handler of a historical query in a read-only endpoint function.
  ///
  /// @param f Handler called once the historical state is available
  /// @param node_context Node context, used to access the historical state
  /// cache and the network identity
  /// @param available Reports whether the requested transaction can be
  /// queried
  /// @param extractor Extracts the requested transaction ID from the request
  /// @param ehandler Produces the response for requests which cannot be
  /// served
  /// @param endorsements Endorsements attached to the receipt before calling
  /// the handler
  ccf::endpoints::ReadOnlyEndpointFunction read_only_adapter_v4(
    const HandleReadOnlyHistoricalQuery& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const ReadOnlyTxIDExtractor& extractor = txid_from_header,
    const ReadOnlyErrorHandler& ehandler = default_error_handler,
    ReceiptEndorsements endorsements = ReceiptEndorsements::All);

  /// Read-write counterpart of read_only_adapter_v4().
  ccf::endpoints::EndpointFunction read_write_adapter_v4(
    const HandleReadWriteHistoricalQuery& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor = txid_from_header,
    const ErrorHandler& ehandler = default_error_handler,
    ReceiptEndorsements endorsements = ReceiptEndorsements::All);
}