// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "kv/change_set.h"

namespace ccf
{
  class ConfigurationChangeHook : public kv::ConsensusHook
  {
  public:
    void call(void *) override
    {
      LOG_INFO_FMT("CONSENSUS HOOK");
    }
  };
}