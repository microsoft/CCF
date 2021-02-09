// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpc_context.h"
#include "endpoint_registry.h"
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
   * auto foo = [](auto& args) {
   *   nlohmann::json params;
   *   serdes::Pack pack_type;
   *   if (<content-type is JSON>)
   *   {
   *     params = unpack(args.rpc_ctx->get_request_body());
   *     pack_type = Text;
   *   }
   *   else
   *   {
   *     ...
   *   }
   *   auto result = fn(params);
   *   if (is_error(result))
   *   {
   *     args.rpc_ctx->set_response_status(SOME_ERROR);
   *     args.rpc_ctx->set_response_header(content_type, Text);
   *     args.rpc_ctx->set_response_body(error_msg(result));
   *   }
   *   if (pack_type == Text)
   *   {
   *     args.rpc_ctx->set_response_header(content_type, JSON);
   *     args.rpc_ctx->set_response_body(pack(result, Text));
   *   }
   *   else
   *   {
   *     ...
   *   }
   * };
   *
   * it is possible to write the shorter, clearer, return-based lambda:
   * auto foo = json_adapter([](kv::Tx& tx, nlohmann::json&& params)
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

  class UrlQueryParseError : public std::invalid_argument
  {
  public:
    using std::invalid_argument::invalid_argument;
  };

  namespace jsonhandler
  {
    using JsonAdapterResponse = std::variant<ErrorDetails, nlohmann::json>;

    static constexpr char const* pack_to_content_type(serdes::Pack p)
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

    static serdes::Pack detect_json_pack(
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

    static serdes::Pack get_response_pack(
      const std::shared_ptr<enclave::RpcContext>& ctx,
      serdes::Pack request_pack)
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

    static nlohmann::json get_params_from_body(
      const std::shared_ptr<enclave::RpcContext>& ctx, serdes::Pack pack)
    {
      return serdes::unpack(ctx->get_request_body(), pack);
    }

    static nlohmann::json get_params_from_query(
      const std::shared_ptr<enclave::RpcContext>& ctx)
    {
      std::string_view query = ctx->get_request_query();
      auto params = nlohmann::json::object();

      while (true)
      {
        const auto next_split = query.find('&');

        const std::string_view this_entry = query.substr(0, next_split);
        const auto field_split = this_entry.find('=');
        if (field_split == std::string::npos)
        {
          throw UrlQueryParseError(
            fmt::format("No k=v in URL query fragment: {}", query));
        }

        const std::string_view key = this_entry.substr(0, field_split);
        const std::string_view value = this_entry.substr(field_split + 1);
        try
        {
          params[std::string(key)] = nlohmann::json::parse(value);
        }
        catch (const std::exception& e)
        {
          throw UrlQueryParseError(fmt::format(
            "Unable to parse URL query value: {} ({})", query, e.what()));
        }

        if (next_split == std::string::npos)
        {
          break;
        }
        else
        {
          query.remove_prefix(next_split + 1);
        }
      }

      return params;
    }

    static std::pair<serdes::Pack, nlohmann::json> get_json_params(
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
      else if (!ctx->get_request_query().empty())
      {
        params = get_params_from_query(ctx);
      }
      else
      {
        params = nlohmann::json::object();
      }

      return std::make_pair(pack, params);
    }

    static void set_response(
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

  static jsonhandler::JsonAdapterResponse make_success()
  {
    return nlohmann::json();
  }

  static jsonhandler::JsonAdapterResponse make_success(
    nlohmann::json&& result_payload)
  {
    return std::move(result_payload);
  }

  static jsonhandler::JsonAdapterResponse make_success(
    const nlohmann::json& result_payload)
  {
    return result_payload;
  }

  static inline jsonhandler::JsonAdapterResponse make_error(
    http_status status, const std::string& code, const std::string& msg)
  {
    return ErrorDetails{status, code, msg};
  }

  using HandlerTxOnly =
    std::function<jsonhandler::JsonAdapterResponse(kv::Tx& tx)>;

  static EndpointFunction json_adapter(const HandlerTxOnly& f)
  {
    return [f](EndpointContext& args) {
      const auto [packing, params] = jsonhandler::get_json_params(args.rpc_ctx);
      jsonhandler::set_response(f(args.tx), args.rpc_ctx, packing);
    };
  }

  using HandlerJsonParamsOnly = std::function<jsonhandler::JsonAdapterResponse(
    kv::Tx& tx, nlohmann::json&& params)>;
  static EndpointFunction json_adapter(const HandlerJsonParamsOnly& f)
  {
    return [f](EndpointContext& args) {
      auto [packing, params] = jsonhandler::get_json_params(args.rpc_ctx);
      jsonhandler::set_response(
        f(args.tx, std::move(params)), args.rpc_ctx, packing);
    };
  }

  using HandlerJsonParamsAndForward =
    std::function<jsonhandler::JsonAdapterResponse(
      EndpointContext& args, nlohmann::json&& params)>;

  static EndpointFunction json_adapter(const HandlerJsonParamsAndForward& f)
  {
    return [f](EndpointContext& args) {
      auto [packing, params] = jsonhandler::get_json_params(args.rpc_ctx);
      jsonhandler::set_response(
        f(args, std::move(params)), args.rpc_ctx, packing);
    };
  }

  using ReadOnlyHandlerWithJson =
    std::function<jsonhandler::JsonAdapterResponse(
      ReadOnlyEndpointContext& args, nlohmann::json&& params)>;

  static ReadOnlyEndpointFunction json_read_only_adapter(
    const ReadOnlyHandlerWithJson& f)
  {
    return [f](ReadOnlyEndpointContext& args) {
      auto [packing, params] = jsonhandler::get_json_params(args.rpc_ctx);
      jsonhandler::set_response(
        f(args, std::move(params)), args.rpc_ctx, packing);
    };
  }
#pragma clang diagnostic pop

  using CommandHandlerWithJson = std::function<jsonhandler::JsonAdapterResponse(
    CommandEndpointContext& args, nlohmann::json&& params)>;

  static CommandEndpointFunction json_command_adapter(
    const CommandHandlerWithJson& f)
  {
    return [f](CommandEndpointContext& args) {
      auto [packing, params] = jsonhandler::get_json_params(args.rpc_ctx);
      jsonhandler::set_response(
        f(args, std::move(params)), args.rpc_ctx, packing);
    };
  }
}