// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "js/extensions/iextension.h"
#include "node/network_state.h"

namespace ccf::js::extensions
{
  class CcfNetworkExtension : public IExtension
  {
  public:
    ccf::NetworkState* network_state;
    kv::Tx* tx;

    CcfNetworkExtension(ccf::NetworkState* ns, kv::Tx* t) :
      network_state(ns),
      tx(t)
    {}

    void install(js::core::Context& ctx) override;
  };
}
