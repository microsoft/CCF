// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpccontext.h"
#include "handlerregistry.h"
#include "http/http_consts.h"

#include <http-parser/http_parser.h>

namespace ccf
{
  // TODO: Update this comment
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

  struct ErrorDetails
  {
    http_status status;
    std::string msg;
  };

  using HandlerAdapterResponse = std::variant<ErrorDetails, nlohmann::json>;

  static HandlerAdapterResponse make_success(nlohmann::json&& result_payload)
  {
    return std::move(result_payload);
  }

  static HandlerAdapterResponse make_success(
    const nlohmann::json& result_payload)
  {
    return result_payload;
  }

  static HandlerAdapterResponse make_error(
    http_status status, const std::string& msg = "")
  {
    return ErrorDetails{status, msg};
  }

  // TODO: Implement
  static jsonrpc::Pack detect_json_packing(
    const std::shared_ptr<enclave::RpcContext>& ctx)
  {
    return jsonrpc::Pack::Text;
  }

  static constexpr char const* pack_to_content_type(jsonrpc::Pack p)
  {
    switch (p)
    {
      case jsonrpc::Pack::Text:
      {
        return http::headervalues::contenttype::JSON;
      }
      case jsonrpc::Pack::MsgPack:
      {
        return http::headervalues::contenttype::MSGPACK;
      }
      default:
      {
        return nullptr;
      }
    }
  }

  static std::pair<jsonrpc::Pack, nlohmann::json> get_json_params(
    const std::shared_ptr<enclave::RpcContext>& ctx)
  {
    const auto packing = detect_json_packing(ctx);
    return std::make_pair(
      packing, jsonrpc::unpack(ctx->get_request_body(), packing));
  }

  static void set_response(
    HandlerAdapterResponse&& res,
    std::shared_ptr<enclave::RpcContext>& ctx,
    jsonrpc::Pack packing)
  {
    auto error = std::get_if<ErrorDetails>(&res);
    if (error != nullptr)
    {
      ctx->set_response_status(error->status);
      ctx->set_response_body(std::move(error->msg));
    }
    else
    {
      const auto body = std::get_if<nlohmann::json>(&res);
      ctx->set_response_status(HTTP_STATUS_OK);
      ctx->set_response_body(jsonrpc::pack(*body, packing));
      ctx->set_response_header(
        http::headers::CONTENT_TYPE, pack_to_content_type(packing));
    }
  }

  using HandlerTxOnly = std::function<HandlerAdapterResponse(Store::Tx& tx)>;

  static HandleFunction handler_adapter(const HandlerTxOnly& f)
  {
    return [&f](RequestArgs& args) {
      const auto [packing, params] = get_json_params(args.rpc_ctx);
      set_response(f(args.tx), args.rpc_ctx, packing);
    };
  }

  using HandlerJsonParamsOnly = std::function<HandlerAdapterResponse(
    Store::Tx& tx, nlohmann::json&& params)>;

  static HandleFunction handler_adapter(const HandlerJsonParamsOnly& f)
  {
    return [&f](RequestArgs& args) {
      auto [packing, params] = get_json_params(args.rpc_ctx);
      set_response(f(args.tx, std::move(params)), args.rpc_ctx, packing);
    };
  }

  using HandlerJsonParamsAndCallerId = std::function<HandlerAdapterResponse(
    Store::Tx& tx, CallerId caller_id, nlohmann::json&& params)>;

  static HandleFunction handler_adapter(const HandlerJsonParamsAndCallerId& f)
  {
    return [&f](RequestArgs& args) {
      auto [packing, params] = get_json_params(args.rpc_ctx);
      set_response(
        f(args.tx, args.caller_id, std::move(params)), args.rpc_ctx, packing);
    };
  }

  using HandlerJsonParamsAndForward = std::function<HandlerAdapterResponse(
    RequestArgs& args, nlohmann::json&& params)>;

  static HandleFunction handler_adapter(const HandlerJsonParamsAndForward& f)
  {
    return [&f](RequestArgs& args) {
      auto [packing, params] = get_json_params(args.rpc_ctx);
      set_response(f(args, std::move(params)), args.rpc_ctx, packing);
    };
  }
}