// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/cose_signatures_config_interface.h"

namespace ccf
{
  class AbstractCOSESignaturesConfigSubsystem
    : public cose::AbstractCOSESignaturesConfig
  {
  protected:
    AbstractNodeState& node_state;

  public:
    AbstractCOSESignaturesConfigSubsystem(AbstractNodeState& node_state_) :
      node_state(node_state_)
    {}

    [[nodiscard]] const ccf::COSESignaturesConfig& get_cose_signatures_config()
      const override
    {
      return node_state.get_cose_signatures_config();
    }
  };
}
