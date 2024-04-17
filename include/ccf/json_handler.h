// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint_registry.h"
#include "ccf/serdes.h"

#include <llhttp/llhttp.h>
#include <variant>

namespace ccf
{
  /*
   * For simple app methods which expect a JSON request, potentially msgpack'd,
   * these functions do the common decoding of the input and setting of response
   * fields, to reduce handler complexity and repetition.
   *
   * Rather than:
   * auto foo = [](auto& ctx) {
   *   nlohmann::json params;
   *   serdes::Pack pack_type;
   *   if (<content-type is JSON>)
   *   {
   *     params = unpack(ctx.rpc_ctx->get_request_body());
   *     pack_type = Text;
   *   }
   *   else
   *   {
   *     ...
   *   }
   *   auto result = fn(params);
   *   if (is_error(result))
   *   {
   *     ctx.rpc_ctx->set_response_status(SOME_ERROR);
   *     ctx.rpc_ctx->set_response_header(content_type, Text);
   *     ctx.rpc_ctx->set_response_body(error_msg(result));
   *   }
   *   if (pack_type == Text)
   *   {
   *     ctx.rpc_ctx->set_response_header(content_type, JSON);
   *     ctx.rpc_ctx->set_response_body(pack(result, Text));
   *   }
   *   else
   *   {
   *     ...
   *   }
   * };
   *
   * it is possible to write the shorter, clearer, return-based lambda:
   * auto foo = json_adapter([](auto& ctx, nlohmann::json&& params)
   * {
   *    auto result = fn(params);
   *    if (is_error(result))
   *    {
   *      return make_error(SOME_ERROR, error_msg(result));
   *    }
   *    else
   *    {
   *      return make_success(result);
   *    }
   * });
   */
  namespace jsonhandler
  {
    using JsonAdapterResponse =
      std::variant<ErrorDetails, RedirectDetails, nlohmann::json>;

    char const* pack_to_content_type(serdes::Pack p);

    serdes::Pack detect_json_pack(const std::shared_ptr<ccf::RpcContext>& ctx);

    serdes::Pack get_response_pack(
      const std::shared_ptr<ccf::RpcContext>& ctx,
      serdes::Pack request_pack = serdes::Pack::Text);

    nlohmann::json get_params_from_body(
      const std::shared_ptr<ccf::RpcContext>& ctx, serdes::Pack pack);

    std::pair<serdes::Pack, nlohmann::json> get_json_params(
      const std::shared_ptr<ccf::RpcContext>& ctx);

    void set_response(
      JsonAdapterResponse&& res,
      std::shared_ptr<ccf::RpcContext>& ctx,
      serdes::Pack request_packing);
  }

  jsonhandler::JsonAdapterResponse make_success();
  jsonhandler::JsonAdapterResponse make_success(
    nlohmann::json&& result_payload);
  jsonhandler::JsonAdapterResponse make_success(
    const nlohmann::json& result_payload);

  jsonhandler::JsonAdapterResponse make_error(
    http_status status, const std::string& code, const std::string& msg);

  jsonhandler::JsonAdapterResponse make_redirect(http_status status);

  using HandlerJsonParamsAndForward =
    std::function<jsonhandler::JsonAdapterResponse(
      endpoints::EndpointContext& ctx, nlohmann::json&& params)>;
  endpoints::EndpointFunction json_adapter(
    const HandlerJsonParamsAndForward& f);

  using ReadOnlyHandlerWithJson =
    std::function<jsonhandler::JsonAdapterResponse(
      endpoints::ReadOnlyEndpointContext& ctx, nlohmann::json&& params)>;
  endpoints::ReadOnlyEndpointFunction json_read_only_adapter(
    const ReadOnlyHandlerWithJson& f);

  using CommandHandlerWithJson = std::function<jsonhandler::JsonAdapterResponse(
    endpoints::CommandEndpointContext& ctx, nlohmann::json&& params)>;
  endpoints::CommandEndpointFunction json_command_adapter(
    const CommandHandlerWithJson& f);
}
