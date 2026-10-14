// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/extensions/extension_interface.h"
#include "node/rpc/gov_effects_interface.h"

namespace ccf::js::extensions
{
  /**
   * Adds the following functions:
   *
   * - ccf.node.triggerLedgerRekey
   * - ccf.node.transitionServiceToOpen
   * - ccf.node.triggerRecoverySharesRefresh
   * - ccf.node.triggerLedgerChunk
   * - ccf.node.triggerSnapshot
   *
   **/
  class NodeExtension : public ExtensionInterface
  {
  public:
    ccf::AbstractGovernanceEffects* gov_effects;
    ccf::kv::Tx* tx;

    NodeExtension(ccf::AbstractGovernanceEffects* ge, ccf::kv::Tx* t) :
      gov_effects(ge),
      tx(t)
    {}

    void install(js::core::Context& ctx) override;
  };
}
