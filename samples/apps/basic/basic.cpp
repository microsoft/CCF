// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// CCF
#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/ds/hash.h"
#include "ccf/http_query.h"
#include "ccf/js/registry.h"
#include "ccf/json_handler.h"
#include "ccf/version.h"

#include <charconv>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace nlohmann;

namespace basicapp
{
  using RecordsMap = kv::Map<std::string, std::vector<uint8_t>>;
  static constexpr auto PRIVATE_RECORDS = "records";

  // This sample shows the features of DynamicJSEndpointRegistry. This sample
  // adds a PUT /app/custom_endpoints, which calls install_custom_endpoints(),
  // after first authenticating the caller (user_data["isAdmin"] is true), to
  // install custom JavaScript endpoints.
  // PUT /app/custom_endpoints is logically equivalent to passing a set_js_app
  // proposal in governance, except the application resides in the application
  // space.
  class BasicHandlers : public ccf::js::DynamicJSEndpointRegistry
  {
  public:
    BasicHandlers(ccfapp::AbstractNodeContext& context) :
      ccf::js::DynamicJSEndpointRegistry(
        context,
        "public:custom_endpoints" // Internal KV space will be under
                                  // public:custom_endpoints.*
      )
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

      // Restrict what KV tables the JS code can access. Here we make the
      // PRIVATE_RECORDS table, written by the hardcoded C++ endpoints,
      // read-only for JS code. Additionally, we reserve any table beginning
      // with "basic." (public or private) as inaccessible for the JS code, in
      // case we want to use it for the C++ app in future.
      set_js_kv_namespace_restriction(
        [](const std::string& map_name, std::string& explanation)
          -> ccf::js::MapAccessPermissions {
          if (map_name == PRIVATE_RECORDS)
          {
            explanation = fmt::format(
              "The {} table is managed by C++ endpoints, so is read-only in "
              "JS.",
              PRIVATE_RECORDS);
            return ccf::js::MapAccessPermissions::READ_ONLY;
          }

          if (
            map_name.starts_with("public:basic.") ||
            map_name.starts_with("basic."))
          {
            explanation =
              "The 'basic.' prefix is reserved by the C++ endpoints for future "
              "use.";
            return ccf::js::MapAccessPermissions::ILLEGAL;
          }

          return ccf::js::MapAccessPermissions::READ_WRITE;
        });

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
        const auto wrapper = j.get<ccf::js::Bundle>();

        result = install_custom_endpoints_v1(ctx.tx, wrapper);
        if (result != ccf::ApiResult::OK)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to install endpoints: {}",
              ccf::api_result_to_str(result)));
          return;
        }

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
      };

      make_endpoint(
        "/custom_endpoints",
        HTTP_PUT,
        put_custom_endpoints,
        {ccf::user_cose_sign1_auth_policy})
        .set_auto_schema<ccf::js::Bundle, void>()
        .install();

      auto get_custom_endpoints = [this](ccf::endpoints::EndpointContext& ctx) {
        ccf::js::Bundle bundle;

        auto result = get_custom_endpoints_v1(bundle, ctx.tx);
        if (result != ccf::ApiResult::OK)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to get endpoints: {}", ccf::api_result_to_str(result)));
          return;
        }

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        ctx.rpc_ctx->set_response_body(nlohmann::json(bundle).dump(2));
      };

      make_endpoint(
        "/custom_endpoints",
        HTTP_GET,
        get_custom_endpoints,
        {ccf::empty_auth_policy})
        .set_auto_schema<void, ccf::js::Bundle>()
        .install();

      auto get_custom_endpoints_module =
        [this](ccf::endpoints::EndpointContext& ctx) {
          std::string module_name;

          {
            const auto parsed_query =
              http::parse_query(ctx.rpc_ctx->get_request_query());

            std::string error;
            if (!http::get_query_value(
                  parsed_query, "module_name", module_name, error))
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidQueryParameterValue,
                std::move(error));
              return;
            }
          }

          std::string code;

          auto result =
            get_custom_endpoint_module_v1(code, ctx.tx, module_name);
          if (result != ccf::ApiResult::OK)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "Failed to get module: {}", ccf::api_result_to_str(result)));
            return;
          }

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE,
            http::headervalues::contenttype::JAVASCRIPT);
          ctx.rpc_ctx->set_response_body(std::move(code));
        };

      make_endpoint(
        "/custom_endpoints/modules",
        HTTP_GET,
        get_custom_endpoints_module,
        {ccf::empty_auth_policy})
        .add_query_parameter<std::string>("module_name")
        .install();
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
