// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"
#include "ccf/tx_id.h"
#include "ccf/tx_status.h"

#include <functional>

namespace ccf
{
  using CommitCallback = std::function<void(ccf::TxID, ccf::FinalTxStatus)>;

  class CommitCallbackInterface : public AbstractNodeSubSystem
  {
  public:
    ~CommitCallbackInterface() override = default;

    static char const* get_subsystem_name()
    {
      return "CommitCallback";
    }

    virtual void add_callback(ccf::TxID tx_id, CommitCallback&& callback) = 0;
  };
}
