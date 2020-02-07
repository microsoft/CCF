// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpccontext.h"
#include "handlerregistry.h"

namespace ccf
{
  /*
   * For simple app methods which require minimal arguments, these
   * handler_adapter functions create a wrapper to reduce handler complexity
   * and repetition.
   *
   * Rather than:
   * auto foo = [](RequestArgs& args) {
   *   auto x = args.tx.get_view...;
   *   auto y = args.params[...];
   *   args.rpc_ctx->set_response(x + y);
   * };
   *
   * it is possible to write the shorter, clearer, return-based lambda:
   * auto foo = handler_adapter([](Store::Tx& tx, const nlohmann::json& params)
   * {
   *   auto x = tx.get_view...;
   *   auto y = params[...];
   *   return x + y;
   * });
   */

  using HandlerParamsOnly = std::function<enclave::RpcResponse(
    Store::Tx& tx, const nlohmann::json& params)>;

  static HandleFunction handler_adapter(const HandlerParamsOnly& f)
  {
    return [f](RequestArgs& args) {
      args.rpc_ctx->set_response(f(args.tx, args.rpc_ctx->get_params()));
    };
  }

  using HandlerParamsAndCaller = std::function<enclave::RpcResponse(
    Store::Tx& tx, CallerId caller_id, const nlohmann::json& params)>;

  static HandleFunction handler_adapter(const HandlerParamsAndCaller& f)
  {
    return [f](RequestArgs& args) {
      args.rpc_ctx->set_response(
        f(args.tx, args.caller_id, args.rpc_ctx->get_params()));
    };
  }
}