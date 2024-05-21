// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/rpc_context.h"
#include "ccf/js/extensions/extension_interface.h"

namespace ccf::js::extensions
{
  /**
   * Adds the following functions:
   *
   * - ccf.rpc.setApplyWrites
   * - ccf.rpc.setClaimsDigest
   *
   **/
  class RpcExtension : public ExtensionInterface
  {
  public:
    ccf::RpcContext* rpc_ctx;

    RpcExtension(ccf::RpcContext* rc) : rpc_ctx(rc) {}

    void install(js::core::Context& ctx) override;
  };
}
