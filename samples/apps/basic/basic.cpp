// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// CCF
#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/ds/hash.h"
#include "ccf/http_query.h"
#include "ccf/json_handler.h"
#include "ccf/version.h"

#include <charconv>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

// Custom Endpoints
#include "ccf/bundle.h"
#include "ccf/endpoints/authentication/js.h"
#include "ccf/service/tables/modules.h"
#include "custom_endpoints/endpoint.h"
#include "js/interpreter_cache_interface.h"

using namespace nlohmann;

namespace basicapp
{
  using RecordsMap = kv::Map<std::string, std::vector<uint8_t>>;
  static constexpr auto PRIVATE_RECORDS = "records";

  class BasicHandlers : public ccf::UserEndpointRegistry
  {
  public:
    BasicHandlers(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      openapi_info.title = "CCF Basic App";
      openapi_info.description =
        "Lightweight application for benchmarking purposes";
      openapi_info.document_version = "0.0.1";

      auto put = [this](ccf::endpoints::EndpointContext& ctx) {
        std::string key;
        std::string error;
        if (!get_path_param(
              ctx.rpc_ctx->get_request_path_params(), "key", key, error))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NO_CONTENT,
            ccf::errors::InvalidResourceName,
            "Missing key");
          return;
        }

        auto records_handle = ctx.tx.template rw<RecordsMap>(PRIVATE_RECORDS);
        records_handle->put(key, ctx.rpc_ctx->get_request_body());
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
      };
      make_endpoint(
        "/records/{key}", HTTP_PUT, put, {ccf::user_cert_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto get = [this](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
        std::string key;
        std::string error;
        if (!get_path_param(
              ctx.rpc_ctx->get_request_path_params(), "key", key, error))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NO_CONTENT,
            ccf::errors::InvalidResourceName,
            "Missing key");
          return;
        }

        auto records_handle = ctx.tx.template ro<RecordsMap>(PRIVATE_RECORDS);
        auto record = records_handle->get(key);

        if (record.has_value())
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          ctx.rpc_ctx->set_response_body(record.value());
          return;
        }

        ctx.rpc_ctx->set_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::InvalidResourceName,
          "No such key");
      };
      make_read_only_endpoint(
        "/records/{key}", HTTP_GET, get, {ccf::user_cert_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto post = [this](ccf::endpoints::EndpointContext& ctx) {
        const nlohmann::json body =
          nlohmann::json::parse(ctx.rpc_ctx->get_request_body());

        const auto records = body.get<std::map<std::string, std::string>>();

        auto records_handle = ctx.tx.template rw<RecordsMap>(PRIVATE_RECORDS);
        for (const auto& [key, value] : records)
        {
          const std::vector<uint8_t> value_vec(value.begin(), value.end());
          records_handle->put(key, value_vec);
        }
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
      };
      make_endpoint("/records", HTTP_POST, post, {ccf::user_cert_auth_policy})
        .install();

      auto put_custom_endpoints = [this](ccf::endpoints::EndpointContext& ctx) {
        const auto& caller_identity =
          ctx.template get_caller<ccf::UserCOSESign1AuthnIdentity>();

        // Authorization Check
        nlohmann::json user_data = nullptr;
        auto result =
          get_user_data_v1(ctx.tx, caller_identity.user_id, user_data);
        if (result == ccf::ApiResult::InternalError)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to get user data for user {}: {}",
              caller_identity.user_id,
              ccf::api_result_to_str(result)));
          return;
        }
        const auto is_admin_it = user_data.find("isAdmin");

        // Not every user gets to define custom endpoints, only users with
        // isAdmin
        if (
          !user_data.is_object() || is_admin_it == user_data.end() ||
          !is_admin_it.value().get<bool>())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Only admins may access this endpoint.");
          return;
        }
        // End of Authorization Check

        const auto j = nlohmann::json::parse(
          caller_identity.content.begin(), caller_identity.content.end());
        const auto wrapper = j.get<ccf::js::BundleWrapper>();

        auto endpoints = ctx.tx.template rw<ccf::endpoints::EndpointsMap>(
          "custom_endpoints.metadata");
        // Similar to set_js_app
        for (const auto& [url, methods] : wrapper.bundle.metadata.endpoints)
        {
          for (const auto& [method, metadata] : methods)
          {
            std::string method_upper = method;
            nonstd::to_upper(method_upper);
            const auto key = ccf::endpoints::EndpointKey{url, method_upper};
            endpoints->put(key, metadata);
          }
        }

        auto modules =
          ctx.tx.template rw<ccf::Modules>("custom_endpoints.modules");
        for (const auto& [name, module] : wrapper.bundle.modules)
        {
          modules->put(name, module);
        }
        // TBD: Bytecode compilation support

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
      };

      make_endpoint(
        "custom_endpoints",
        HTTP_PUT,
        put_custom_endpoints,
        {ccf::user_cose_sign1_auth_policy})
        .set_auto_schema<void, void>()
        .install();
    }

    // Custom Endpoints

    ccf::endpoints::EndpointDefinitionPtr find_endpoint(
      kv::Tx& tx, ccf::RpcContext& rpc_ctx) override
    {
      // Look up the endpoint definition
      // First in the user-defined endpoints, and then fall-back to built-ins
      const auto method = rpc_ctx.get_method();
      const auto verb = rpc_ctx.get_request_verb();

      auto endpoints =
        tx.ro<ccf::endpoints::EndpointsMap>("custom_endpoints.metadata");
      const auto key = ccf::endpoints::EndpointKey{method, verb};

      // Look for a direct match of the given path
      const auto it = endpoints->get(key);
      if (it.has_value())
      {
        auto endpoint_def = std::make_shared<CustomJSEndpoint>();
        endpoint_def->dispatch = key;
        endpoint_def->properties = it.value();
        endpoint_def->full_uri_path =
          fmt::format("/{}{}", method_prefix, endpoint_def->dispatch.uri_path);
        ccf::instantiate_authn_policies(*endpoint_def);
        return endpoint_def;
      }

      // TBD: templated endpoints
      return ccf::endpoints::EndpointRegistry::find_endpoint(tx, rpc_ctx);
    }

    using PreExecutionHook = std::function<void(ccf::js::core::Context&)>;

    void do_execute_request(
      const CustomJSEndpoint* endpoint,
      ccf::endpoints::EndpointContext& endpoint_ctx,
      const std::optional<PreExecutionHook>& pre_exec_hook = std::nullopt)
    {
      // TBD: interpreter re-use logic
      // TBD: runtime options
      const auto interpreter_cache =
        context.get_subsystem<ccf::js::AbstractInterpreterCache>();
    }

    void execute_request(
      const CustomJSEndpoint* endpoint,
      ccf::endpoints::EndpointContext& endpoint_ctx)
    {
      // TBD: historical queries
      do_execute_request(endpoint, endpoint_ctx);
    }

    void execute_endpoint(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::EndpointContext& endpoint_ctx) override
    {
      // Handle endpoint execution
      auto endpoint = dynamic_cast<const CustomJSEndpoint*>(e.get());
      if (endpoint != nullptr)
      {
        execute_request(endpoint, endpoint_ctx);
        return;
      }

      ccf::endpoints::EndpointRegistry::execute_endpoint(e, endpoint_ctx);
    }
  };
}

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    return std::make_unique<basicapp::BasicHandlers>(context);
  }
}
