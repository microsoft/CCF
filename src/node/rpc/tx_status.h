// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"

namespace ccf
{
  enum class TxStatus
  {
    TxUnknown,
    Replicating,
    Committed,
    NotCommitted,
  };

  DECLARE_JSON_ENUM(
    TxStatus,
    {{TxStatus::TxUnknown, "TX_UNKNOWN"},
     {TxStatus::Replicating, "REPLICATING"},
     {TxStatus::Committed, "COMMITTED"},
     {TxStatus::NotCommitted, "NOT_COMMITTED"}});

  constexpr size_t VIEW_UNKNOWN = 0;

  TxStatus get_tx_status(
    size_t target_view,
    size_t target_seqno,
    size_t local_view,
    size_t committed_view,
    size_t committed_seqno)
  {
    if (local_view == VIEW_UNKNOWN)
    {
      // This seqno is not known locally - determine if this tx id is
      // still possible.
      if (committed_view > target_view)
      {
        // We have reached global commit in a later term, so this tx id is
        // now impossible
        return TxStatus::NotCommitted;
      }
      else
      {
        return TxStatus::TxUnknown;
      }
    }
    else
    {
      // This seqno is known - does it match the requested tx id?
      const bool is_committed = committed_seqno >= target_seqno;
      if (local_view == target_view)
      {
        // This tx id matches a known tx - is it globally committed?
        if (is_committed)
        {
          // This tx id is globally committed
          return TxStatus::Committed;
        }
        else
        {
          // Not yet
          return TxStatus::Replicating;
        }
      }
      else
      {
        if (is_committed)
        {
          // A different tx id with the same seqno has been committed -
          // the requested tx is impossible
          return TxStatus::NotCommitted;
        }
        else if (local_view < target_view)
        {
          // This seqno was seen locally in an earlier view - don't know
          // which got committed, but the requested tx id is unknown
          return TxStatus::TxUnknown;
        }
        else if (local_view > target_view)
        {
          // This seqno was seen locally in a later view - this means work
          // is happening in a later view, and the requested tx id is
          // impossible
          return TxStatus::NotCommitted;
        }
      }
    }

    throw std::logic_error("TODO: Make this unreachable");
  }
}