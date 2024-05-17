// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/rpc_context.h"
#include "js/extensions/extension_interface.h"

namespace ccf::js::extensions
{
  class CcfRpcExtension : public ExtensionInterface
  {
  public:
    ccf::RpcContext* rpc_ctx;

    CcfRpcExtension(ccf::RpcContext* rc) : rpc_ctx(rc) {}

    void install(js::core::Context& ctx) override;
  };
}
