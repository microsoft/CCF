// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx_id.h"
#include "consensus/aft/impl/state.h"

namespace aft
{
  // Notified by consensus each time the commit index advances. Implemented by
  // the node's commit callback subsystem.
  class CommitObserver
  {
  public:
    virtual ~CommitObserver() = default;

    virtual void on_commit(
      ccf::TxID committed, const ViewHistory& view_history) = 0;
  };
}
