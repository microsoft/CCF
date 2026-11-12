// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint_registry.h"
#include "ccf/json.h"

#include <concepts>
#include <llhttp/llhttp.h>
#include <string>
#include <type_traits>
#include <variant>

namespace ccf
{
  /*
   * For simple app methods which expect a JSON request these functions do the
   * common decoding of the input and setting of response fields, to reduce
   * handler complexity and repetition.
   *
   * Rather than:
   * auto foo = [](auto& ctx) {
   *   nlohmann::json params;
   *   if (<content-type is JSON>)
   *   {
   *     params = ccf::parse_json_safe(ctx.rpc_ctx->get_request_body());
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
   *   ctx.rpc_ctx->set_response_header(content_type, JSON);
   *   ctx.rpc_ctx->set_response_body(result.dump());
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
    struct AlreadyPopulatedResponse
    {};

    struct SerialisedJson
    {
      std::string body;
    };

    using JsonAdapterResponse = std::variant<
      ErrorDetails,
      RedirectDetails,
      AlreadyPopulatedResponse,
      nlohmann::json,
      SerialisedJson>;

    nlohmann::json get_json_params(const std::shared_ptr<ccf::RpcContext>& ctx);

    void set_response(
      JsonAdapterResponse&& res, std::shared_ptr<ccf::RpcContext>& ctx);

  }

  jsonhandler::JsonAdapterResponse make_success();
  jsonhandler::JsonAdapterResponse make_success(
    nlohmann::json&& result_payload);
  jsonhandler::JsonAdapterResponse make_success(
    const nlohmann::json& result_payload);

  /** Serialise a typed response directly, without constructing a JSON DOM.
   * Request parsing and the adapter's status/content negotiation are unchanged.
   */
  template <typename T>
    requires(
      !std::same_as<std::remove_cvref_t<T>, nlohmann::json> &&
      glz::write_supported<T, glz::JSON>)
  jsonhandler::JsonAdapterResponse make_success(const T& result)
  {
    return jsonhandler::SerialisedJson{ccf::json::write(result)};
  }

  jsonhandler::JsonAdapterResponse make_error(
    ccf::http_status status, const std::string& code, const std::string& msg);

  jsonhandler::JsonAdapterResponse make_redirect(ccf::http_status status);

  jsonhandler::JsonAdapterResponse already_populated_response();

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
