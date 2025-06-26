// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/json_handler.h"

#include "ccf/ds/logger.h"
#include "ccf/http_accept.h"
#include "ccf/http_consts.h"
#include "ccf/odata_error.h"
#include "ccf/redirect.h"
#include "ccf/rpc_context.h"
#include "ccf/rpc_exception.h"

#include <llhttp/llhttp.h>

namespace ccf
{
  namespace jsonhandler
  {
    nlohmann::json get_json_params(const std::shared_ptr<ccf::RpcContext>& ctx)
    {
      nlohmann::json params = nullptr;
      if (
        !ctx->get_request_body().empty()
        // Body of GET is ignored
        && ctx->get_request_verb() != HTTP_GET)
      {
        params = nlohmann::json::parse(ctx->get_request_body());
      }
      else
      {
        params = nlohmann::json::object();
      }

      return params;
    }

    void set_response(
      JsonAdapterResponse&& res, //NOLINT(cppcoreguidelines-rvalue-reference-param-not-moved)
      std::shared_ptr<ccf::RpcContext>& ctx)
    {
      auto * error = std::get_if<ErrorDetails>(&res);
      if (error != nullptr)
      {
        ctx->set_error(std::move(*error));
      }
      else
      {
        auto * redirect = std::get_if<RedirectDetails>(&res);
        if (redirect != nullptr)
        {
          ctx->set_response_status(redirect->status);
        }
        else
        {
          auto * const body = std::get_if<nlohmann::json>(&res);
          if (body->is_null())
          {
            ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
          }
          else
          {
            ctx->set_response_status(HTTP_STATUS_OK);
            const auto accept_it =
              ctx->get_request_header(http::headers::ACCEPT);
            if (accept_it.has_value())
            {
              const auto accept_options =
                ccf::http::parse_accept_header(accept_it.value());
              bool matched = false;
              for (const auto& option : accept_options)
              {
                if (option.matches(http::headervalues::contenttype::JSON))
                {
                  matched = true;
                  break;
                }
              }

              if (!matched)
              {
                throw RpcException(
                  HTTP_STATUS_NOT_ACCEPTABLE,
                  ccf::errors::UnsupportedContentType,
                  fmt::format(
                    "No supported content type in accept header: {}\nOnly {} "
                    "is currently supported",
                    accept_it.value(),
                    http::headervalues::contenttype::JSON));
              }
            }

            const auto s = body->dump();
            ctx->set_response_body(std::vector<uint8_t>(s.begin(), s.end()));

            ctx->set_response_header(
              http::headers::CONTENT_TYPE,
              http::headervalues::contenttype::JSON);
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
    return {result_payload};
  }

  jsonhandler::JsonAdapterResponse make_error(
    ccf::http_status status, const std::string& code, const std::string& msg)
  {
    LOG_DEBUG_FMT(
      "Frontend error: status={} code={} msg={}", status, code, msg);
    return ErrorDetails{status, code, msg};
  }

  jsonhandler::JsonAdapterResponse make_redirect(ccf::http_status status)
  {
    return RedirectDetails{status};
  }

  endpoints::EndpointFunction json_adapter(const HandlerJsonParamsAndForward& f)
  {
    return [f](endpoints::EndpointContext& ctx) {
      auto params = jsonhandler::get_json_params(ctx.rpc_ctx);
      jsonhandler::set_response(f(ctx, std::move(params)), ctx.rpc_ctx);
    };
  }

  endpoints::ReadOnlyEndpointFunction json_read_only_adapter(
    const ReadOnlyHandlerWithJson& f)
  {
    return [f](endpoints::ReadOnlyEndpointContext& ctx) {
      auto params = jsonhandler::get_json_params(ctx.rpc_ctx);
      jsonhandler::set_response(f(ctx, std::move(params)), ctx.rpc_ctx);
    };
  }

  endpoints::CommandEndpointFunction json_command_adapter(
    const CommandHandlerWithJson& f)
  {
    return [f](endpoints::CommandEndpointContext& ctx) {
      auto params = jsonhandler::get_json_params(ctx.rpc_ctx);
      jsonhandler::set_response(f(ctx, std::move(params)), ctx.rpc_ctx);
    };
  }
}
