// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http_responder.h"
#include "node/rpc_context_impl.h"

namespace http
{
  inline bool send_rpc_response(
    ccf::http::HTTPResponder& responder, ccf::RpcContextImpl& rpc_ctx)
  {
    return responder.send_response(
      (ccf::http_status)rpc_ctx.get_response_status(),
      rpc_ctx.get_response_headers(),
      rpc_ctx.get_response_trailers(),
      std::move(rpc_ctx.take_response_body()));
  }
}
