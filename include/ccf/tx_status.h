// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/tx_id.h"

namespace ccf
{
  /** Describes the status of a transaction, as seen by this node.
   */
  enum class TxStatus : uint8_t
  {
    /** This node has not received this transaction, and knows nothing about it
     */
    Unknown,

    /** This node has this transaction locally, but has not yet heard that the
       transaction has been committed by the distributed consensus */
    Pending,

    /** This node has seen that this transaction is committed, it is an
       irrevocable and durable part of the service's transaction history */
    Committed,

    /** This node knows that the given transaction cannot be committed. This may
       mean there has been a view change, and a previously pending transaction
       has been lost (the original request should be resubmitted and will be
       given a new Transaction ID). This also describes IDs which are known to
       be impossible given the currently committed IDs */
    Invalid,
  };

  constexpr char const* tx_status_to_str(TxStatus status)
  {
    switch (status)
    {
      case TxStatus::Unknown:
      {
        return "Unknown";
      }
      case TxStatus::Pending:
      {
        return "Pending";
      }
      case TxStatus::Committed:
      {
        return "Committed";
      }
      case TxStatus::Invalid:
      {
        return "Invalid";
      }
      default:
      {
        return "Unhandled value";
      }
    }
  }

  DECLARE_JSON_ENUM(
    TxStatus,
    {{TxStatus::Unknown, tx_status_to_str(TxStatus::Unknown)},
     {TxStatus::Pending, tx_status_to_str(TxStatus::Pending)},
     {TxStatus::Committed, tx_status_to_str(TxStatus::Committed)},
     {TxStatus::Invalid, tx_status_to_str(TxStatus::Invalid)}});

  [[maybe_unused]] static TxStatus evaluate_tx_status(
    View target_view,
    SeqNo target_seqno,
    View local_view,
    View committed_view,
    SeqNo committed_seqno)
  {
    const bool is_committed = committed_seqno >= target_seqno;
    const bool views_match = local_view == target_view;
    const bool view_known = local_view != VIEW_UNKNOWN;

    if (is_committed && !view_known)
    {
      throw std::logic_error(fmt::format(
        "Should know local view for seqnos up to {}, but have no view for {}",
        committed_seqno,
        target_seqno));
    }

    if (is_committed)
    {
      // The requested seqno has been committed, so we know for certain whether
      // the requested tx id is committed or not
      if (views_match)
      {
        return TxStatus::Committed;
      }
      return TxStatus::Invalid;
    }

    if (views_match)
    {
      // This node knows about the requested tx id, but it is not globally
      // committed
      return TxStatus::Pending;
    }

    if (committed_view > target_view)
    {
      // This node has seen the seqno in a different view, and committed
      // further, so the requested tx id is impossible
      return TxStatus::Invalid;
    }

    // Otherwise, we cannot state anything about this tx id. The most common
    // reason is that the local_view is unknown (this transaction has never
    // existed, or has not reached this node yet). It is also possible that
    // this node believes locally that this tx id is impossible, but does not
    // have a global commit to back this up - it will eventually receive
    // either a global commit confirming this belief, or an election and
    // global commit making this tx id invalid
    return TxStatus::Unknown;
  }
}