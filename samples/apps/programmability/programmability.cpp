// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// CCF
#include "audit_info.h"
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

namespace programmabilityapp
{
  using RecordsMap = kv::Map<std::string, std::vector<uint8_t>>;
  using AuditInputValue = kv::Value<std::vector<uint8_t>>;
  using AuditInfoValue = kv::Value<AuditInfo>;
  static constexpr auto PRIVATE_RECORDS = "programmability.records";
  static constexpr auto CUSTOM_ENDPOINTS_NAMESPACE = "public:custom_endpoints";

  // The programmability sample demonstrates how signed payloads can be used to
  // provide offline auditability without requiring trusting the hardware or the
  // service owners/consortium.
  // COSE Sign1 payloads must set these protected headers in order to guarantee
  // the specificity of the payload for the endpoint, and avoid possible replay
  // of payloads signed in the past.
  static constexpr auto MSG_TYPE_NAME = "app.msg.type";
  static constexpr auto CREATED_AT_NAME = "app.msg.created_at";
  // Instances of ccf::TypedUserCOSESign1AuthnPolicy for the endpoints that
  // support COSE Sign1 authentication.
  static auto endpoints_user_cose_sign1_auth_policy =
    std::make_shared<ccf::TypedUserCOSESign1AuthnPolicy>(
      "custom_endpoints", MSG_TYPE_NAME, CREATED_AT_NAME);
  static auto options_user_cose_sign1_auth_policy =
    std::make_shared<ccf::TypedUserCOSESign1AuthnPolicy>(
      "runtime_options", MSG_TYPE_NAME, CREATED_AT_NAME);

  // This sample shows the features of DynamicJSEndpointRegistry. This sample
  // adds a PUT /app/custom_endpoints, which calls install_custom_endpoints(),
  // after first authenticating the caller (user_data["isAdmin"] is true), to
  // install custom JavaScript endpoints.
  // PUT /app/custom_endpoints is logically equivalent to passing a set_js_app
  // proposal in governance, except the application resides in the application
  // space.
  class ProgrammabilityHandlers : public ccf::js::DynamicJSEndpointRegistry
  {
  private:
    std::optional<ccf::UserId> try_get_user_id(
      ccf::endpoints::EndpointContext& ctx)
    {
      if (
        const auto* cose_ident =
          ctx.try_get_caller<ccf::UserCOSESign1AuthnIdentity>())
      {
        return cose_ident->user_id;
      }
      else if (
        const auto* cert_ident =
          ctx.try_get_caller<ccf::UserCertAuthnIdentity>())
      {
        return cert_ident->user_id;
      }
      return std::nullopt;
    }

    std::pair<AuditInputFormat, std::span<const uint8_t>> get_body(
      ccf::endpoints::EndpointContext& ctx)
    {
      if (
        const auto* cose_ident =
          ctx.try_get_caller<ccf::UserCOSESign1AuthnIdentity>())
      {
        return {AuditInputFormat::COSE, cose_ident->content};
      }
      else
      {
        return {AuditInputFormat::JSON, ctx.rpc_ctx->get_request_body()};
      }
    }

  public:
    ProgrammabilityHandlers(ccfapp::AbstractNodeContext& context) :
      ccf::js::DynamicJSEndpointRegistry(
        context,
        CUSTOM_ENDPOINTS_NAMESPACE // Internal KV space will be under
                                   // public:custom_endpoints.*
      )
    {
      openapi_info.title = "CCF Programmabilit App";
      openapi_info.description =
        "Lightweight application demonstrating app-space JS programmability";
      openapi_info.document_version = "0.0.1";

      // This app contains a few hard-coded C++ endpoints, writing to a
      // C++-controlled table, to show that these can co-exist with JS endpoints
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

      // Restrict what KV maps the JS code can access. Here we make the
      // PRIVATE_RECORDS map, written by the hardcoded C++ endpoints,
      // read-only for JS code. Additionally, we reserve any map beginning
      // with "programmability." (public or private) as inaccessible for the JS
      // code, in case we want to use it for the C++ app in future.
      set_js_kv_namespace_restriction(
        [](const std::string& map_name, std::string& explanation)
          -> ccf::js::KVAccessPermissions {
          if (map_name == PRIVATE_RECORDS)
          {
            explanation = fmt::format(
              "The {} map is managed by C++ endpoints, so is read-only in "
              "JS.",
              PRIVATE_RECORDS);
            return ccf::js::KVAccessPermissions::READ_ONLY;
          }

          if (
            map_name.starts_with("public:programmability.") ||
            map_name.starts_with("programmability."))
          {
            explanation =
              "The 'programmability.' prefix is reserved by the C++ endpoints "
              "for future "
              "use.";
            return ccf::js::KVAccessPermissions::ILLEGAL;
          }

          return ccf::js::KVAccessPermissions::READ_WRITE;
        });

      auto put_custom_endpoints = [this](ccf::endpoints::EndpointContext& ctx) {
        const auto user_id = try_get_user_id(ctx);
        if (!user_id.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_UNAUTHORIZED,
            ccf::errors::InternalError,
            "Failed to get user id");
          return;
        }
        // Authorization Check
        nlohmann::json user_data = nullptr;
        auto result = get_user_data_v1(ctx.tx, user_id.value(), user_data);
        if (result == ccf::ApiResult::InternalError)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to get user data for user {}: {}",
              user_id.value(),
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

        const auto [format, bundle] = get_body(ctx);
        const auto j = nlohmann::json::parse(bundle.begin(), bundle.end());
        const auto parsed_bundle = j.get<ccf::js::Bundle>();

        // Make operation auditable by writing user-supplied
        // document to the ledger
        auto audit_input = ctx.tx.template rw<AuditInputValue>(
          fmt::format("{}.audit.input", CUSTOM_ENDPOINTS_NAMESPACE));
        audit_input->put(ctx.rpc_ctx->get_request_body());
        auto audit_info = ctx.tx.template rw<AuditInfoValue>(
          fmt::format("{}.audit.info", CUSTOM_ENDPOINTS_NAMESPACE));
        audit_info->put({format, AuditInputContent::BUNDLE, user_id.value()});
        if (format == AuditInputFormat::COSE)
        {
          const auto* cose_ident =
            ctx.try_get_caller<ccf::UserCOSESign1AuthnIdentity>();
          if (!cose_ident->protected_header.msg_created_at.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::MissingRequiredHeader,
              fmt::format("Missing {} protected header", CREATED_AT_NAME));
            return;
          }
          store_ts_to_action(
            ctx.tx,
            cose_ident->protected_header.msg_created_at.value(),
            ctx.rpc_ctx->get_request_body());
        }

        result = install_custom_endpoints_v1(ctx.tx, parsed_bundle);
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
        {endpoints_user_cose_sign1_auth_policy, ccf::user_cert_auth_policy})
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

      auto patch_runtime_options =
        [this](ccf::endpoints::EndpointContext& ctx) {
          const auto user_id = try_get_user_id(ctx);
          if (!user_id.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_UNAUTHORIZED,
              ccf::errors::InternalError,
              "Failed to get user id");
            return;
          }

          // Authorization Check
          nlohmann::json user_data = nullptr;
          auto result = get_user_data_v1(ctx.tx, user_id.value(), user_data);
          if (result == ccf::ApiResult::InternalError)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "Failed to get user data for user {}: {}",
                user_id.value(),
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

          // Implement patch semantics.
          // - Fetch current options
          ccf::JSRuntimeOptions options;
          get_js_runtime_options_v1(options, ctx.tx);

          // - Convert current options to JSON
          auto j_options = nlohmann::json(options);

          const auto [format, body] = get_body(ctx);
          // - Parse argument as JSON body
          const auto arg_body = nlohmann::json::parse(body.begin(), body.end());

          // - Merge, to overwrite current options with anything from body. Note
          // that nulls mean deletions, which results in resetting to a default
          // value
          j_options.merge_patch(arg_body);

          // - Parse patched options from JSON
          options = j_options.get<ccf::JSRuntimeOptions>();

          // Make operation auditable by writing user-supplied
          // document to the ledger
          auto audit = ctx.tx.template rw<AuditInputValue>(
            fmt::format("{}.audit.input", CUSTOM_ENDPOINTS_NAMESPACE));
          audit->put(ctx.rpc_ctx->get_request_body());
          auto audit_info = ctx.tx.template rw<AuditInfoValue>(
            fmt::format("{}.audit.info", CUSTOM_ENDPOINTS_NAMESPACE));
          audit_info->put({format, AuditInputContent::BUNDLE, user_id.value()});

          result = set_js_runtime_options_v1(ctx.tx, options);
          if (result != ccf::ApiResult::OK)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "Failed to set options: {}", ccf::api_result_to_str(result)));
            return;
          }

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_body(nlohmann::json(options).dump(2));
        };
      make_endpoint(
        "/custom_endpoints/runtime_options",
        HTTP_PATCH,
        patch_runtime_options,
        {options_user_cose_sign1_auth_policy, ccf::user_cert_auth_policy})
        .install();

      auto get_runtime_options = [this](ccf::endpoints::EndpointContext& ctx) {
        ccf::JSRuntimeOptions options;

        auto result = get_js_runtime_options_v1(options, ctx.tx);
        if (result != ccf::ApiResult::OK)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to get runtime options: {}",
              ccf::api_result_to_str(result)));
          return;
        }

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        ctx.rpc_ctx->set_response_body(nlohmann::json(options).dump(2));
      };
      make_endpoint(
        "/custom_endpoints/runtime_options",
        HTTP_GET,
        get_runtime_options,
        {ccf::empty_auth_policy})
        .set_auto_schema<void, ccf::JSRuntimeOptions>()
        .install();
    }
  };
}

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    return std::make_unique<programmabilityapp::ProgrammabilityHandlers>(
      context);
  }
}
