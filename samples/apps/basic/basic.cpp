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

        install_custom_endpoints(ctx, wrapper);
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
      };

      make_endpoint(
        "/custom_endpoints",
        HTTP_PUT,
        put_custom_endpoints,
        {ccf::user_cose_sign1_auth_policy})
        .set_auto_schema<ccf::js::BundleWrapper, void>()
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
