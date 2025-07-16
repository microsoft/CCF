// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// CCF
#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/ds/hash.h"
#include "ccf/http_query.h"
#include "ccf/js/registry.h"
#include "ccf/json_handler.h"
#include "ccf/service/tables/users.h"
#include "ccf/version.h"

#include <charconv>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace nlohmann;

namespace programmabilityapp
{
  using RecordsMap = ccf::kv::Map<std::string, std::vector<uint8_t>>;
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

  // This is a pure helper function which can be called from either C++ or JS,
  // to implement common functionality in a single place
  static inline bool has_role_permitting_action(
    ccf::kv::ReadOnlyTx& tx,
    const std::string& user_id,
    const std::string& action)
  {
    using RoleSet = ccf::kv::Set<std::string>;

    auto * users_handle = tx.ro<ccf::UserInfo>(ccf::Tables::USER_INFO);
    const auto user_info = users_handle->get(user_id);
    if (user_info.has_value())
    {
      const auto roles_it = user_info->user_data.find("roles");
      if (roles_it != user_info->user_data.end())
      {
        const auto roles = roles_it->get<std::vector<std::string>>();
        for (const auto& role : roles)
        {
          auto * role_handle = tx.ro<RoleSet>(
            fmt::format("public:programmability.roles.{}", role));
          if (role_handle->contains(action))
          {
            return true;
          }
        }
      }
    }

    return false;
  }

  class MyExtension : public ccf::js::extensions::ExtensionInterface
  {
  public:
    // Store any objects/state which the extension's functions might need on
    // this extension object.
    // In this case, since the extension adds a function that wants to read from
    // the KV, it needs the current request's Tx.
    ccf::kv::ReadOnlyTx* tx;

    MyExtension(ccf::kv::ReadOnlyTx* t) : tx(t) {}

    void install(ccf::js::core::Context& ctx) override;
  };

  // This is the signature for a function exposed to JS, interacting directly
  // with JS interpreter state
  JSValue js_has_role_permitting_action(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    // Check correct number of args were passed, to avoid unsafe accesses to
    // argv
    if (argc != 2)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 2", argc);
    }

    // Retrieve the CCF context object from QuickJS's opaque pointer
    ccf::js::core::Context& jsctx =
      *(ccf::js::core::Context*)JS_GetContextOpaque(ctx);

    // Get the extension (by type), and the Tx* stashed on it
    auto extension = jsctx.get_extension<MyExtension>();
    if (extension == nullptr)
    {
      return JS_ThrowInternalError(ctx, "Failed to get extension object");
    }

    auto tx_ptr = extension->tx;
    if (tx_ptr == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    ccf::kv::ReadOnlyTx& tx = *tx_ptr;

    // Process the arguments passed to the JS function, confirming they're both
    // strings
    std::optional<std::string> user_id = jsctx.to_str(argv[0]);
    if (!user_id.has_value())
    {
      return JS_ThrowTypeError(ctx, "user_id argument is not a string");
    }

    std::optional<std::string> action = jsctx.to_str(argv[1]);
    if (!action.has_value())
    {
      return JS_ThrowTypeError(ctx, "action argument is not a string");
    }

    try
    {
      // Call function containing shared implementation
      const bool permitted =
        has_role_permitting_action(tx, user_id.value(), action.value());

      // Return result (converting C++ type to QuickJS value)
      return JS_NewBool(ctx, permitted);
    }
    catch (const std::exception& exc)
    {
      // Catch any exceptions from C++ function, report them to the JS layer as
      // error
      return JS_ThrowInternalError(
        ctx, "Error checking for role permissions: %s", exc.what());
    }
  }

  void MyExtension::install(ccf::js::core::Context& ctx)
  {
    // Nest all of this extension's functions in a single object, rather than
    // inserting directly into the global namespace
    auto my_global_object =
      ctx.get_or_create_global_property("my_object", ctx.new_obj());

    // Insert a constant string into the JS environment, accessible at
    // my_object.my_constant
    my_global_object.set("my_constant", ctx.new_string("Hello world"));

    // Insert a function into the JS environment, called at my_object.has_role
    my_global_object.set(
      // Name of field on object
      "hasRole",
      ctx.new_c_function(
        // C/C++ function implementing this JS function
        js_has_role_permitting_action,
        // Repeated name of function, used in callstacks
        "hasRole",
        // Number of arguments to this function
        2));
  }

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

    std::tuple<
      ccf::ActionFormat, // JSON or COSE
      std::span<const uint8_t>, // Content
      std::optional<uint64_t> // Created at timestamp, if passed
      >
    get_action_content(ccf::endpoints::EndpointContext& ctx)
    {
      if (
        const auto* cose_ident =
          ctx.try_get_caller<ccf::UserCOSESign1AuthnIdentity>())
      {
        return {
          ccf::ActionFormat::COSE,
          cose_ident->content,
          cose_ident->protected_header.msg_created_at};
      }
      else
      {
        return {
          ccf::ActionFormat::JSON,
          ctx.rpc_ctx->get_request_body(),
          std::nullopt};
      }
    }

    bool set_error_details(
      ccf::endpoints::EndpointContext& ctx,
      ccf::ApiResult result,
      ccf::InvalidArgsReason reason)
    {
      switch (result)
      {
        case ccf::ApiResult::OK:
        {
          return false;
        }
        case ccf::ApiResult::InvalidArgs:
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InvalidInput,
            reason == ccf::InvalidArgsReason::ActionAlreadyApplied ?
              "Action was already applied" :
              "Action created_at timestamp is too old");
          return true;
        }
        case ccf::ApiResult::InternalError:
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Failed to check if action is original");
          return true;
        }
        default:
        {
          return true;
        }
      }
    }

  public:
    ProgrammabilityHandlers(ccf::AbstractNodeContext& context) :
      ccf::js::DynamicJSEndpointRegistry(
        context,
        CUSTOM_ENDPOINTS_NAMESPACE // Internal KV space will be under
                                   // public:custom_endpoints.*
      )
    {
      openapi_info.title = "CCF Programmability App";
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
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::TEXT);
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

        const auto [format, content, created_at] = get_action_content(ctx);
        const auto parsed_content =
          nlohmann::json::parse(content.begin(), content.end());
        const auto parsed_bundle = parsed_content.get<ccf::js::Bundle>();

        // Make operation auditable
        record_action_for_audit_v1(
          ctx.tx,
          format,
          user_id.value(),
          fmt::format(
            "{} {}",
            ctx.rpc_ctx->get_method(),
            ctx.rpc_ctx->get_request_path()),
          ctx.rpc_ctx->get_request_body());

        // Ensure signed actions are not replayed
        if (format == ccf::ActionFormat::COSE)
        {
          if (!created_at.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::MissingRequiredHeader,
              fmt::format("Missing {} protected header", CREATED_AT_NAME));
            return;
          }
          ccf::InvalidArgsReason reason;
          result = check_action_not_replayed_v1(
            ctx.tx,
            created_at.value(),
            ctx.rpc_ctx->get_request_body(),
            reason);

          if (set_error_details(ctx, result, reason))
          {
            return;
          }
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

        ctx.rpc_ctx->set_response_json(bundle, HTTP_STATUS_OK);
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
              ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

            std::string error;
            if (!ccf::http::get_query_value(
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
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::JAVASCRIPT);
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

          const auto [format, content, created_at] = get_action_content(ctx);
          // - Parse content as JSON options
          const auto arg_content =
            nlohmann::json::parse(content.begin(), content.end());

          // - Merge, to overwrite current options with anything from body. Note
          // that nulls mean deletions, which results in resetting to a default
          // value
          j_options.merge_patch(arg_content);

          // - Parse patched options from JSON
          options = j_options.get<ccf::JSRuntimeOptions>();

          // Make operation auditable
          record_action_for_audit_v1(
            ctx.tx,
            format,
            user_id.value(),
            fmt::format(
              "{} {}",
              ctx.rpc_ctx->get_method(),
              ctx.rpc_ctx->get_request_path()),
            ctx.rpc_ctx->get_request_body());

          // Ensure signed actions are not replayed
          if (format == ccf::ActionFormat::COSE)
          {
            if (!created_at.has_value())
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::MissingRequiredHeader,
                fmt::format("Missing {} protected header", CREATED_AT_NAME));
              return;
            }
            ccf::InvalidArgsReason reason;
            result = check_action_not_replayed_v1(
              ctx.tx,
              created_at.value(),
              ctx.rpc_ctx->get_request_body(),
              reason);

            if (set_error_details(ctx, result, reason))
            {
              return;
            }
          }

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

          ctx.rpc_ctx->set_response_json(options, HTTP_STATUS_OK);
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

        ctx.rpc_ctx->set_response_json(options, HTTP_STATUS_OK);
      };
      make_endpoint(
        "/custom_endpoints/runtime_options",
        HTTP_GET,
        get_runtime_options,
        {ccf::empty_auth_policy})
        .set_auto_schema<void, ccf::JSRuntimeOptions>()
        .install();
    }

    ccf::js::extensions::Extensions get_extensions(
      const ccf::endpoints::EndpointContext& endpoint_ctx) override
    {
      ccf::js::extensions::Extensions extensions;

      extensions.push_back(std::make_shared<MyExtension>(&endpoint_ctx.tx));

      return extensions;
    }
  };
}

namespace ccf
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccf::AbstractNodeContext& context)
  {
    return std::make_unique<programmabilityapp::ProgrammabilityHandlers>(
      context);
  }
}
