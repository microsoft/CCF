// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"
#include "js/extensions/iextension.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  class CcfHistoricalExtension : public IExtension
  {
  public:
    ccf::historical::AbstractStateCache* historical_state;

    CcfHistoricalExtension(ccf::historical::AbstractStateCache* hs) :
      historical_state(hs)
    {}

    void install(js::core::Context& ctx) override;

    static JSValue create_historical_state_object(
      js::core::Context& ctx, ccf::historical::StatePtr state);
  };
}
