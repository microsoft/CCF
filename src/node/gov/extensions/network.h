// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/extensions/extension_interface.h"
#include "node/network_state.h"

namespace ccf::js::extensions
{
  /**
   * Adds the following functions:
   *
   * - ccf.network.getLatestLedgerSecretSeqno
   * - ccf.network.generateEndorsedCertificate
   * - ccf.network.generateNetworkCertificate
   *
   **/
  class NetworkExtension : public ExtensionInterface
  {
  public:
    ccf::NetworkState* network_state;
    ccf::kv::Tx* tx;

    NetworkExtension(ccf::NetworkState* ns, ccf::kv::Tx* t) :
      network_state(ns),
      tx(t)
    {}

    void install(js::core::Context& ctx) override;
  };
}
