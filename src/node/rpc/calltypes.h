// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"

namespace ccf
{
  struct GetCommit
  {
    struct Out
    {
      uint64_t term;
      int64_t commit;
    };
  };

  struct GetTxHist
  {
    struct Out
    {
      nlohmann::json tx_hist;
    };
  };
}