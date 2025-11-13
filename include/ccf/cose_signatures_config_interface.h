// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/cose_signatures_config.h"
#include "ccf/node_subsystem_interface.h"

#include <chrono>
#include <memory>

namespace ccf::cose
{
  /** Exposes the COSE signatures configuration to the application.
   */
  class AbstractCOSESignaturesConfig : public ccf::AbstractNodeSubSystem
  {
  public:
    ~AbstractCOSESignaturesConfig() override = default;

    static char const* get_subsystem_name()
    {
      return "COSESignaturesConfig";
    }

    [[nodiscard]] virtual const ccf::COSESignaturesConfig&
    get_cose_signatures_config() const = 0;
  };
}