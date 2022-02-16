// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/app_interface.h"

#include <memory>

namespace ccfapp
{
  std::shared_ptr<ccf::RpcFrontend> get_rpc_handler_impl(
    kv::Store& store, ccfapp::AbstractNodeContext& context);
}