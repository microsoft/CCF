// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/authentication_types.h"

#include "ccf/rpc_context.h"

namespace ccf
{
  void AuthnPolicy::set_unauthenticated_error(
    std::shared_ptr<ccf::RpcContext> ctx, std::string&& error_reason)
  {
    ctx->set_error(
      HTTP_STATUS_UNAUTHORIZED,
      ccf::errors::InvalidAuthenticationInfo,
      std::move(error_reason));
  }
}