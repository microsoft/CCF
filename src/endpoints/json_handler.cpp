// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/json_handler.h"

#include "ccf/http_consts.h"
#include "ccf/odata_error.h"
#include "ccf/redirect.h"
#include "ccf/rpc_context.h"
#include "http/http_accept.h"
#include "node/rpc/rpc_exception.h"

#include <llhttp/llhttp.h>

namespace ccf
{
  namespace jsonhandler
  {
    char const* pack_to_content_type(serdes::Pack p)
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

    serdes::Pack detect_json_pack(const std::shared_ptr<ccf::RpcContext>& ctx)
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

    serdes::Pack get_response_pack(
      const std::shared_ptr<ccf::RpcContext>& ctx, serdes::Pack request_pack)
    {
      const auto accept_it = ctx->get_request_header(http::headers::ACCEPT);
      if (accept_it.has_value())
      {
        const auto accept_options =
          ::http::parse_accept_header(accept_it.value());
        for (const auto& option : accept_options)
        {
          if (option.matches(http::headervalues::contenttype::JSON))
          {
            return serdes::Pack::Text;
          }
          if (option.matches(http::headervalues::contenttype::MSGPACK))
          {
            return serdes::Pack::MsgPack;
          }
        }

        throw RpcException(
          HTTP_STATUS_NOT_ACCEPTABLE,
          ccf::errors::UnsupportedContentType,
          fmt::format(
            "No supported content type in accept header: {}\nOnly {} and {} "
            "are currently supported",
            accept_it.value(),
            http::headervalues::contenttype::JSON,
            http::headervalues::contenttype::MSGPACK));
      }

      return request_pack;
    }

    nlohmann::json get_params_from_body(
      const std::shared_ptr<ccf::RpcContext>& ctx, serdes::Pack pack)
    {
      return serdes::unpack(ctx->get_request_body(), pack);
    }

    std::pair<serdes::Pack, nlohmann::json> get_json_params(
      const std::shared_ptr<ccf::RpcContext>& ctx)
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

    void set_response(
      JsonAdapterResponse&& res,
      std::shared_ptr<ccf::RpcContext>& ctx,
      serdes::Pack request_packing)
    {
      auto error = std::get_if<ErrorDetails>(&res);
      if (error != nullptr)
      {
        ctx->set_error(std::move(*error));
      }
      else
      {
        auto redirect = std::get_if<RedirectDetails>(&res);
        if (redirect != nullptr)
        {
          ctx->set_response_status(redirect->status);
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
                ctx->set_response_body(
                  std::vector<uint8_t>(s.begin(), s.end()));
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
  }

  jsonhandler::JsonAdapterResponse make_success()
  {
    return nlohmann::json();
  }

  jsonhandler::JsonAdapterResponse make_success(nlohmann::json&& result_payload)
  {
    return std::move(result_payload);
  }

  jsonhandler::JsonAdapterResponse make_success(
    const nlohmann::json& result_payload)
  {
    return jsonhandler::JsonAdapterResponse(result_payload);
  }

  jsonhandler::JsonAdapterResponse make_error(
    http_status status, const std::string& code, const std::string& msg)
  {
    LOG_DEBUG_FMT(
      "Frontend error: status={} code={} msg={}", status, code, msg);
    return ErrorDetails{status, code, msg};
  }

  jsonhandler::JsonAdapterResponse make_redirect(http_status status)
  {
    return RedirectDetails{status};
  }

  endpoints::EndpointFunction json_adapter(const HandlerJsonParamsAndForward& f)
  {
    return [f](endpoints::EndpointContext& ctx) {
      auto [packing, params] = jsonhandler::get_json_params(ctx.rpc_ctx);
      jsonhandler::set_response(
        f(ctx, std::move(params)), ctx.rpc_ctx, packing);
    };
  }

  endpoints::ReadOnlyEndpointFunction json_read_only_adapter(
    const ReadOnlyHandlerWithJson& f)
  {
    return [f](endpoints::ReadOnlyEndpointContext& ctx) {
      auto [packing, params] = jsonhandler::get_json_params(ctx.rpc_ctx);
      jsonhandler::set_response(
        f(ctx, std::move(params)), ctx.rpc_ctx, packing);
    };
  }

  endpoints::CommandEndpointFunction json_command_adapter(
    const CommandHandlerWithJson& f)
  {
    return [f](endpoints::CommandEndpointContext& ctx) {
      auto [packing, params] = jsonhandler::get_json_params(ctx.rpc_ctx);
      jsonhandler::set_response(
        f(ctx, std::move(params)), ctx.rpc_ctx, packing);
    };
  }
}
