// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint_registry.h"
#include "enclave/rpc_context.h"
#include "http/http_consts.h"
#include "node/rpc/error.h"
#include "node/rpc/rpc_exception.h"
#include "node/rpc/serdes.h"

#include <llhttp/llhttp.h>

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
    using JsonAdapterResponse = std::variant<ErrorDetails, nlohmann::json>;

    inline constexpr char const* pack_to_content_type(serdes::Pack p)
    {
      switch (p)
      {
        case serdes::Pack::Text:
        {
          return http::headervalues::contenttype::JSON;
        }
        case serdes::Pack::MsgPack:
        {
          return http::headervalues::contenttype::MSGPACK;
        }
        default:
        {
          return nullptr;
        }
      }
    }

    inline serdes::Pack detect_json_pack(
      const std::shared_ptr<enclave::RpcContext>& ctx)
    {
      std::optional<serdes::Pack> packing = std::nullopt;

      const auto content_type_it =
        ctx->get_request_header(http::headers::CONTENT_TYPE);
      if (content_type_it.has_value())
      {
        const auto& content_type = content_type_it.value();
        if (content_type == http::headervalues::contenttype::JSON)
        {
          packing = serdes::Pack::Text;
        }
        else if (content_type == http::headervalues::contenttype::MSGPACK)
        {
          packing = serdes::Pack::MsgPack;
        }
        else
        {
          throw RpcException(
            HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE,
            ccf::errors::UnsupportedContentType,
            fmt::format(
              "Unsupported content type {}. Only {} and {} are currently "
              "supported",
              content_type,
              http::headervalues::contenttype::JSON,
              http::headervalues::contenttype::MSGPACK));
        }
      }
      else
      {
        packing = serdes::detect_pack(ctx->get_request_body());
      }

      return packing.value_or(serdes::Pack::Text);
    }

    inline serdes::Pack get_response_pack(
      const std::shared_ptr<enclave::RpcContext>& ctx,
      serdes::Pack request_pack = serdes::Pack::Text)
    {
      serdes::Pack packing = request_pack;

      const auto accept_it = ctx->get_request_header(http::headers::ACCEPT);
      if (accept_it.has_value())
      {
        const auto& accept = accept_it.value();
        if (accept == http::headervalues::contenttype::JSON)
        {
          packing = serdes::Pack::Text;
        }
        else if (accept == http::headervalues::contenttype::MSGPACK)
        {
          packing = serdes::Pack::MsgPack;
        }
        else if (accept == "*/*")
        {
          packing = request_pack;
        }
        else
        {
          throw RpcException(
            HTTP_STATUS_NOT_ACCEPTABLE,
            ccf::errors::UnsupportedContentType,
            fmt::format(
              "Unsupported content type {} in accept header. Only {} and {} "
              "are currently supported",
              accept,
              http::headervalues::contenttype::JSON,
              http::headervalues::contenttype::MSGPACK));
        }
      }

      return packing;
    }

    inline nlohmann::json get_params_from_body(
      const std::shared_ptr<enclave::RpcContext>& ctx, serdes::Pack pack)
    {
      return serdes::unpack(ctx->get_request_body(), pack);
    }

    inline std::pair<serdes::Pack, nlohmann::json> get_json_params(
      const std::shared_ptr<enclave::RpcContext>& ctx)
    {
      const auto pack = detect_json_pack(ctx);

      nlohmann::json params = nullptr;
      if (
        !ctx->get_request_body().empty()
        // Body of GET is ignored
        && ctx->get_request_verb() != HTTP_GET)
      {
        params = get_params_from_body(ctx, pack);
      }
      else
      {
        params = nlohmann::json::object();
      }

      return std::make_pair(pack, params);
    }

    inline void set_response(
      JsonAdapterResponse&& res,
      std::shared_ptr<enclave::RpcContext>& ctx,
      serdes::Pack request_packing)
    {
      auto error = std::get_if<ErrorDetails>(&res);
      if (error != nullptr)
      {
        ctx->set_error(std::move(*error));
      }
      else
      {
        const auto body = std::get_if<nlohmann::json>(&res);
        if (body->is_null())
        {
          ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
        }
        else
        {
          ctx->set_response_status(HTTP_STATUS_OK);
          const auto packing = get_response_pack(ctx, request_packing);
          switch (packing)
          {
            case serdes::Pack::Text:
            {
              const auto s = body->dump();
              ctx->set_response_body(std::vector<uint8_t>(s.begin(), s.end()));
              break;
            }
            case serdes::Pack::MsgPack:
            {
              ctx->set_response_body(nlohmann::json::to_msgpack(*body));
              break;
            }
            default:
            {
              throw std::logic_error("Unhandled serdes::Pack");
            }
          }
          ctx->set_response_header(
            http::headers::CONTENT_TYPE, pack_to_content_type(packing));
        }
      }
    }
  }

// -Wunused-function seems to _wrongly_ flag the following functions as unused
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

  inline jsonhandler::JsonAdapterResponse make_success()
  {
    return nlohmann::json();
  }

  inline jsonhandler::JsonAdapterResponse make_success(
    nlohmann::json&& result_payload)
  {
    return std::move(result_payload);
  }

  inline jsonhandler::JsonAdapterResponse make_success(
    const nlohmann::json& result_payload)
  {
    return result_payload;
  }

  inline jsonhandler::JsonAdapterResponse make_error(
    http_status status, const std::string& code, const std::string& msg)
  {
    LOG_DEBUG_FMT(
      "Frontend error: status={} code={} msg={}", status, code, msg);
    return ErrorDetails{status, code, msg};
  }

  using HandlerJsonParamsAndForward =
    std::function<jsonhandler::JsonAdapterResponse(
      endpoints::EndpointContext& ctx, nlohmann::json&& params)>;

  inline endpoints::EndpointFunction json_adapter(
    const HandlerJsonParamsAndForward& f)
  {
    return [f](endpoints::EndpointContext& ctx) {
      auto [packing, params] = jsonhandler::get_json_params(ctx.rpc_ctx);
      jsonhandler::set_response(
        f(ctx, std::move(params)), ctx.rpc_ctx, packing);
    };
  }

  using ReadOnlyHandlerWithJson =
    std::function<jsonhandler::JsonAdapterResponse(
      endpoints::ReadOnlyEndpointContext& ctx, nlohmann::json&& params)>;

  inline endpoints::ReadOnlyEndpointFunction json_read_only_adapter(
    const ReadOnlyHandlerWithJson& f)
  {
    return [f](endpoints::ReadOnlyEndpointContext& ctx) {
      auto [packing, params] = jsonhandler::get_json_params(ctx.rpc_ctx);
      jsonhandler::set_response(
        f(ctx, std::move(params)), ctx.rpc_ctx, packing);
    };
  }
#pragma clang diagnostic pop

  using CommandHandlerWithJson = std::function<jsonhandler::JsonAdapterResponse(
    endpoints::CommandEndpointContext& ctx, nlohmann::json&& params)>;

  inline endpoints::CommandEndpointFunction json_command_adapter(
    const CommandHandlerWithJson& f)
  {
    return [f](endpoints::CommandEndpointContext& ctx) {
      auto [packing, params] = jsonhandler::get_json_params(ctx.rpc_ctx);
      jsonhandler::set_response(
        f(ctx, std::move(params)), ctx.rpc_ctx, packing);
    };
  }
}