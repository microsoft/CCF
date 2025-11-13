// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"
#include "ccf/js/core/wrapped_value.h"
#include "ccf/js/extensions/extension_interface.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  /**
   * Adds the following functions:
   *
   * - ccf.historical.getStateRange
   * - ccf.historical.dropCachedStates
   *
   * Also provides create_historical_state_object for requests operating in
   * historical mode.
   *
   **/
  class HistoricalExtension : public ExtensionInterface
  {
  public:
    struct Impl;

    std::unique_ptr<Impl> impl;

    HistoricalExtension(ccf::historical::AbstractStateCache* hs);
    ~HistoricalExtension() override;

    void install(js::core::Context& ctx) override;

    js::core::JSWrappedValue create_historical_state_object(
      js::core::Context& ctx, ccf::historical::StatePtr state) const;
  };
}
