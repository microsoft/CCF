// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/json_handler.h"

#include "ccf/http_accept.h"
#include "ccf/http_consts.h"
#include "ccf/odata_error.h"
#include "ccf/redirect.h"
#include "ccf/rpc_context.h"
#include "ccf/rpc_exception.h"
#include "ds/internal_logger.h"

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
      JsonAdapterResponse&& res, std::shared_ptr<ccf::RpcContext>& ctx)
    {
      std::visit(
        [&ctx](auto&& response) {
          using T = std::decay_t<decltype(response)>;
          if constexpr (std::is_same_v<T, ErrorDetails>)
          {
            ctx->set_error(std::forward<decltype(response)>(response));
          }
          else if constexpr (std::is_same_v<T, RedirectDetails>)
          {
            ctx->set_response_status(response.status);
          }
          else if constexpr (std::is_same_v<T, AlreadyPopulatedResponse>)
          {
            // Nothing to do here - the caller claims to have built an
            // appropriate response already
          }
          else if constexpr (std::is_same_v<T, nlohmann::json>)
          {
            if (response.is_null())
            {
              ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
            }
            else
            {
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

              ctx->set_response_json(
                std::forward<decltype(response)>(response), HTTP_STATUS_OK);
            }
          }
          else
          {
            static_assert(
              ccf::nonstd::dependent_false<T>::value,
              "Missing type case in visitor");
          }
        },
        std::move(res));
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

  jsonhandler::JsonAdapterResponse already_populated_response()
  {
    return {};
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
