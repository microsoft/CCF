// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"

namespace ccf
{
  enum class TxStatus
  {
    Unknown,
    Pending,
    Committed,
    Invalid,
  };

  DECLARE_JSON_ENUM(
    TxStatus,
    {{TxStatus::Unknown, "UNKNOWN"},
     {TxStatus::Pending, "PENDING"},
     {TxStatus::Committed, "COMMITTED"},
     {TxStatus::Invalid, "INVALID"}});

  constexpr size_t VIEW_UNKNOWN = 0;

  TxStatus get_tx_status(
    size_t target_view,
    size_t target_seqno,
    size_t local_view,
    size_t committed_view,
    size_t committed_seqno)
  {
    const bool is_committed = committed_seqno >= target_seqno;

    if (is_committed && local_view == VIEW_UNKNOWN)
    {
      throw std::logic_error(fmt::format(
        "Should know local view for seqnos up to {}, but have no view for {}",
        committed_seqno,
        target_seqno));
    }

    if (local_view > committed_view)
    {
      throw std::logic_error(fmt::format(
        "Should not believe {} occurred in view {}, ahead of the current "
        "committed view {}",
        target_view,
        local_view,
        committed_view));
    }

    if (local_view == VIEW_UNKNOWN)
    {
      // This seqno is not known locally - determine if this tx id is
      // still possible.
      if (committed_view > target_view)
      {
        // We have reached global commit in a later term, so this tx id is
        // now impossible
        return TxStatus::Invalid;
      }
      else
      {
        return TxStatus::Unknown;
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
          return TxStatus::Pending;
        }
      }
      else
      {
        if (is_committed)
        {
          // A different tx id with the same seqno has been committed -
          // the requested tx is impossible
          return TxStatus::Invalid;
        }
        else if (local_view < target_view)
        {
          // This seqno was seen locally in an earlier view - don't know
          // which got committed, but the requested tx id is unknown
          return TxStatus::Unknown;
        }
        else if (local_view > target_view)
        {
          // This seqno was seen locally in a later view - this means work
          // is happening in a later view, and the requested tx id is
          // impossible
          return TxStatus::Invalid;
        }
      }
    }

    throw std::logic_error("TODO: Make this unreachable");
  }
}