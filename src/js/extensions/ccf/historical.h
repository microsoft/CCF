// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"
#include "js/extensions/extension_interface.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  class CcfHistoricalExtension : public ExtensionInterface
  {
  public:
    struct Impl;

    std::unique_ptr<Impl> impl;

    CcfHistoricalExtension(ccf::historical::AbstractStateCache* hs);
    ~CcfHistoricalExtension();

    void install(js::core::Context& ctx) override;

    JSValue create_historical_state_object(
      js::core::Context& ctx, ccf::historical::StatePtr state);
  };
}
