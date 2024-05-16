// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/app_interface.h"
#include "ccf/crypto/key_wrap.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/endpoints/authentication/all_of_auth.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/node/host_processes_interface.h"
#include "ccf/service/tables/jsengine.h"
#include "ccf/version.h"
#include "enclave/enclave_time.h"
#include "js/core/context.h"
#include "js/core/wrapped_property_enum.h"
#include "js/extensions/ccf/consensus.h"
#include "js/extensions/ccf/converters.h"
#include "js/extensions/ccf/crypto.h"
#include "js/extensions/ccf/historical.h"
#include "js/extensions/ccf/host.h"
#include "js/extensions/ccf/kv.h"
#include "js/extensions/ccf/rpc.h"
#include "js/extensions/console.h"
#include "js/extensions/math/random.h"
#include "js/global_class_ids.h"
#include "js/interpreter_cache_interface.h"
#include "js/modules.h"
#include "named_auth_policies.h"
#include "node/rpc/rpc_context_impl.h"
#include "service/tables/endpoints.h"

#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>
#include <stdexcept>
#include <vector>

namespace ccfapp
{
  using namespace std;
  using namespace kv;
  using namespace ccf;

  class JSHandlers : public UserEndpointRegistry
  {
  private:
    ccfapp::AbstractNodeContext& context;
    std::shared_ptr<ccf::js::AbstractInterpreterCache> interpreter_cache =
      nullptr;

    js::core::JSWrappedValue create_caller_ident_obj(
      ccf::endpoints::EndpointContext& endpoint_ctx,
      const std::unique_ptr<ccf::AuthnIdentity>& ident,
      js::core::Context& ctx)
    {
      if (ident == nullptr)
      {
        return ctx.null();
      }

      auto caller = ctx.new_obj();

      if (
        auto jwt_ident =
          dynamic_cast<const ccf::JwtAuthnIdentity*>(ident.get()))
      {
        caller.set(
          "policy", ctx.new_string(get_policy_name_from_ident(jwt_ident)));

        auto jwt = ctx.new_obj();
        jwt.set(
          "keyIssuer",
          ctx.new_string_len(
            jwt_ident->key_issuer.data(), jwt_ident->key_issuer.size()));
        jwt.set("header", ctx.parse_json(jwt_ident->header));
        jwt.set("payload", ctx.parse_json(jwt_ident->payload));
        caller.set("jwt", std::move(jwt));

        return caller;
      }
      if (
        auto empty_ident =
          dynamic_cast<const ccf::EmptyAuthnIdentity*>(ident.get()))
      {
        caller.set(
          "policy", ctx.new_string(get_policy_name_from_ident(empty_ident)));
        return caller;
      }
      if (
        auto all_of_ident =
          dynamic_cast<const ccf::AllOfAuthnIdentity*>(ident.get()))
      {
        auto policy = ctx.new_array();
        uint32_t i = 0;
        for (const auto& [name, sub_ident] : all_of_ident->identities)
        {
          policy.set_at_index(i++, ctx.new_string(name));
          caller.set(
            name, create_caller_ident_obj(endpoint_ctx, sub_ident, ctx));
        }
        caller.set("policy", std::move(policy));
        return caller;
      }

      char const* policy_name = nullptr;
      std::string id;
      bool is_member = false;

      if (
        auto user_cert_ident =
          dynamic_cast<const ccf::UserCertAuthnIdentity*>(ident.get()))
      {
        policy_name = get_policy_name_from_ident(user_cert_ident);
        id = user_cert_ident->user_id;
        is_member = false;
      }
      else if (
        auto member_cert_ident =
          dynamic_cast<const ccf::MemberCertAuthnIdentity*>(ident.get()))
      {
        policy_name = get_policy_name_from_ident(member_cert_ident);
        id = member_cert_ident->member_id;
        is_member = true;
      }
      else if (
        auto user_cose_ident =
          dynamic_cast<const ccf::UserCOSESign1AuthnIdentity*>(ident.get()))
      {
        policy_name = get_policy_name_from_ident(user_cose_ident);
        id = user_cose_ident->user_id;
        is_member = false;

        auto cose = ctx.new_obj();
        cose.set(
          "content",
          ctx.new_array_buffer_copy(
            user_cose_ident->content.data(), user_cose_ident->content.size()));
        caller.set("cose", std::move(cose));
      }

      if (policy_name == nullptr)
      {
        throw std::logic_error("Unable to convert caller info to JS object");
      }

      // Retrieve user/member data from authenticated caller id
      nlohmann::json data = nullptr;
      ccf::ApiResult result = ccf::ApiResult::OK;

      if (is_member)
      {
        result = get_member_data_v1(endpoint_ctx.tx, id, data);
      }
      else
      {
        result = get_user_data_v1(endpoint_ctx.tx, id, data);
      }

      if (result == ccf::ApiResult::InternalError)
      {
        throw std::logic_error(
          fmt::format("Failed to get data for caller {}", id));
      }

      crypto::Pem cert;
      if (is_member)
      {
        result = get_member_cert_v1(endpoint_ctx.tx, id, cert);
      }
      else
      {
        result = get_user_cert_v1(endpoint_ctx.tx, id, cert);
      }

      if (result == ccf::ApiResult::InternalError)
      {
        throw std::logic_error(
          fmt::format("Failed to get certificate for caller {}", id));
      }

      caller.set("policy", ctx.new_string(policy_name));
      caller.set("id", ctx.new_string(id));
      caller.set("data", ctx.parse_json(data));
      caller.set("cert", ctx.new_string(cert.str()));

      return caller;
    }

    js::core::JSWrappedValue create_caller_obj(
      ccf::endpoints::EndpointContext& endpoint_ctx, js::core::Context& ctx)
    {
      return create_caller_ident_obj(endpoint_ctx, endpoint_ctx.caller, ctx);
    }

    js::core::JSWrappedValue create_request_obj(
      const ccf::js::JSDynamicEndpoint* endpoint,
      ccf::endpoints::EndpointContext& endpoint_ctx,
      js::core::Context& ctx)
    {
      auto request = ctx.new_obj();

      const auto& r_headers = endpoint_ctx.rpc_ctx->get_request_headers();
      auto headers = ctx.new_obj();
      for (auto& [header_name, header_value] : r_headers)
      {
        headers.set(header_name, ctx.new_string(header_value));
      }
      request.set("headers", std::move(headers));

      const auto& request_query = endpoint_ctx.rpc_ctx->get_request_query();
      auto query_str = ctx.new_string(request_query);
      request.set("query", std::move(query_str));

      const auto& request_path = endpoint_ctx.rpc_ctx->get_request_path();
      auto path_str = ctx.new_string(request_path);
      request.set("path", std::move(path_str));

      const auto& request_method = endpoint_ctx.rpc_ctx->get_request_verb();
      auto method_str = ctx.new_string(request_method.c_str());
      request.set("method", std::move(method_str));

      const auto host_it = r_headers.find(http::headers::HOST);
      if (host_it != r_headers.end())
      {
        const auto& request_hostname = host_it->second;
        auto hostname_str = ctx.new_string(request_hostname);
        request.set("hostname", std::move(hostname_str));
      }
      else
      {
        request.set_null("hostname");
      }

      const auto request_route = endpoint->full_uri_path;
      auto route_str = ctx.new_string(request_route);
      request.set("route", std::move(route_str));

      auto request_url = request_path;
      if (!request_query.empty())
      {
        request_url = fmt::format("{}?{}", request_url, request_query);
      }
      auto url_str = ctx.new_string(request_url);
      request.set("url", std::move(url_str));

      auto params = ctx.new_obj();
      for (auto& [param_name, param_value] :
           endpoint_ctx.rpc_ctx->get_request_path_params())
      {
        params.set(param_name, ctx.new_string(param_value));
      }
      request.set("params", std::move(params));

      auto body_ = ctx.new_obj_class(js::body_class_id);
      ctx.globals.current_request_body =
        &endpoint_ctx.rpc_ctx->get_request_body();
      request.set("body", std::move(body_));

      request.set("caller", create_caller_obj(endpoint_ctx, ctx));

      return request;
    }

    void invalidate_request_obj_body(js::core::Context& ctx)
    {
      ctx.globals.current_request_body = nullptr;
    }

    void execute_request(
      const ccf::js::JSDynamicEndpoint* endpoint,
      ccf::endpoints::EndpointContext& endpoint_ctx)
    {
      if (endpoint->properties.mode == ccf::endpoints::Mode::Historical)
      {
        auto is_tx_committed =
          [this](ccf::View view, ccf::SeqNo seqno, std::string& error_reason) {
            return ccf::historical::is_tx_committed_v2(
              consensus, view, seqno, error_reason);
          };

        ccf::historical::adapter_v3(
          [this, endpoint](
            ccf::endpoints::EndpointContext& endpoint_ctx,
            ccf::historical::StatePtr state) {
            auto add_historical_globals = [&](js::core::Context& ctx) {
              auto ccf =
                ctx.get_or_create_global_property("ccf", ctx.new_obj());
              auto extension =
                ctx
                  .get_extension<ccf::js::extensions::CcfHistoricalExtension>();
              if (extension != nullptr)
              {
                auto val =
                  extension->create_historical_state_object(ctx, state);
                ccf.set("historicalState", std::move(val));
              }
              else
              {
                LOG_FAIL_FMT(
                  "Error while inserting historicalState into JS interpreter - "
                  "no extension found");
              }
            };
            do_execute_request(endpoint, endpoint_ctx, add_historical_globals);
          },
          context,
          is_tx_committed)(endpoint_ctx);
      }
      else
      {
        do_execute_request(endpoint, endpoint_ctx);
      }
    }

    using PreExecutionHook = std::function<void(js::core::Context&)>;

    void do_execute_request(
      const ccf::js::JSDynamicEndpoint* endpoint,
      ccf::endpoints::EndpointContext& endpoint_ctx,
      const std::optional<PreExecutionHook>& pre_exec_hook = std::nullopt)
    {
      // This KV Value should be updated by any governance actions which modify
      // the JS app (including _any_ of its contained modules). We then use the
      // version where it was last modified as a safe approximation of when an
      // interpreter is unsafe to use. If this value is written to, the
      // version_of_previous_write will advance, and all cached interpreters
      // will be flushed.
      const auto interpreter_flush = endpoint_ctx.tx.ro<ccf::InterpreterFlush>(
        ccf::Tables::INTERPRETER_FLUSH);
      const auto flush_marker =
        interpreter_flush->get_version_of_previous_write().value_or(0);

      const std::optional<JSRuntimeOptions> js_runtime_options =
        endpoint_ctx.tx.ro<ccf::JSEngine>(ccf::Tables::JSENGINE)->get();
      if (js_runtime_options.has_value())
      {
        interpreter_cache->set_max_cached_interpreters(
          js_runtime_options->max_cached_interpreters);
      }

      const auto rw_access =
        endpoint->properties.mode == ccf::endpoints::Mode::ReadWrite ?
        js::TxAccess::APP_RW :
        js::TxAccess::APP_RO;
      std::shared_ptr<js::core::Context> interpreter =
        interpreter_cache->get_interpreter(rw_access, *endpoint, flush_marker);
      if (interpreter == nullptr)
      {
        throw std::logic_error("Cache failed to produce interpreter");
      }
      js::core::Context& ctx = *interpreter;

      // Prevent any other thread modifying this interpreter, until this
      // function completes. We could create interpreters per-thread, but then
      // we would get no cross-thread caching benefit (and would need to either
      // enforce, or share, caps across per-thread caches). We choose
      // instead to allow interpreters to be maximally reused, even across
      // threads, at the cost of locking (and potentially stalling another
      // thread's request execution) here.
      std::lock_guard<ccf::pal::Mutex> guard(ctx.lock);
      // Update the top of the stack for the current thread, used by the stack
      // guard Note this is only active outside SGX
      JS_UpdateStackTop(ctx.runtime());
      // Make the heap and stack limits safe while we init the runtime
      ctx.runtime().reset_runtime_options();

      JS_SetModuleLoaderFunc(
        ctx.runtime(), nullptr, js::js_app_module_loader, &endpoint_ctx.tx);

      ctx.register_request_body_class();

      // Extensions with a dependency on this endpoint context (invocation),
      // which must be removed after execution.
      js::extensions::Extensions local_extensions;

      // ccf.kv.*
      local_extensions.emplace_back(
        std::make_shared<ccf::js::extensions::CcfKvExtension>(
          &endpoint_ctx.tx));

      // ccf.rpc.*
      local_extensions.emplace_back(
        std::make_shared<ccf::js::extensions::CcfRpcExtension>(
          endpoint_ctx.rpc_ctx.get()));

      for (auto extension : local_extensions)
      {
        ctx.add_extension(extension);
      }

      if (pre_exec_hook.has_value())
      {
        pre_exec_hook.value()(ctx);
      }

      js::core::JSWrappedValue export_func;
      try
      {
        const auto& props = endpoint->properties;
        auto module_val =
          js::load_app_module(ctx, props.js_module.c_str(), &endpoint_ctx.tx);
        export_func = ctx.get_exported_function(
          module_val, props.js_function, props.js_module);
      }
      catch (const std::exception& exc)
      {
        endpoint_ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          exc.what());
        return;
      }

      // Call exported function
      auto request = create_request_obj(endpoint, endpoint_ctx, ctx);

      auto val = ctx.call_with_rt_options(
        export_func,
        {request},
        &endpoint_ctx.tx,
        ccf::js::core::RuntimeLimitsPolicy::NONE);

      // Clear globals (which potentially reference locals like txctx), from
      // this potentially reused interpreter
      invalidate_request_obj_body(ctx);

      for (auto extension : local_extensions)
      {
        ctx.remove_extension(extension);
      }

      const auto& rt = ctx.runtime();

      if (val.is_exception())
      {
        bool time_out = ctx.interrupt_data.request_timed_out;
        std::string error_msg = "Exception thrown while executing.";
        if (time_out)
        {
          error_msg = "Operation took too long to complete.";
        }

        auto [reason, trace] = ctx.error_message();

        if (rt.log_exception_details)
        {
          CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
        }

        if (rt.return_exception_details)
        {
          std::vector<nlohmann::json> details = {
            ODataJSExceptionDetails{ccf::errors::JSException, reason, trace}};
          endpoint_ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            std::move(error_msg),
            std::move(details));
        }
        else
        {
          endpoint_ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            std::move(error_msg));
        }

        return;
      }

      // Handle return value: {body, headers, statusCode}
      if (!val.is_obj())
      {
        endpoint_ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Invalid endpoint function return value (not an object).");
        return;
      }

      // Response body (also sets a default response content-type header)
      {
        auto response_body_js = val["body"];
        if (!response_body_js.is_undefined())
        {
          std::vector<uint8_t> response_body;
          size_t buf_size;
          size_t buf_offset;
          auto typed_array_buffer = ctx.get_typed_array_buffer(
            response_body_js, &buf_offset, &buf_size, nullptr);
          uint8_t* array_buffer;
          if (!typed_array_buffer.is_exception())
          {
            size_t buf_size_total;
            array_buffer =
              JS_GetArrayBuffer(ctx, &buf_size_total, typed_array_buffer.val);
            array_buffer += buf_offset;
          }
          else
          {
            array_buffer =
              JS_GetArrayBuffer(ctx, &buf_size, response_body_js.val);
          }
          if (array_buffer)
          {
            endpoint_ctx.rpc_ctx->set_response_header(
              http::headers::CONTENT_TYPE,
              http::headervalues::contenttype::OCTET_STREAM);
            response_body =
              std::vector<uint8_t>(array_buffer, array_buffer + buf_size);
          }
          else
          {
            std::optional<std::string> str;
            if (response_body_js.is_str())
            {
              endpoint_ctx.rpc_ctx->set_response_header(
                http::headers::CONTENT_TYPE,
                http::headervalues::contenttype::TEXT);
              str = ctx.to_str(response_body_js);
            }
            else
            {
              endpoint_ctx.rpc_ctx->set_response_header(
                http::headers::CONTENT_TYPE,
                http::headervalues::contenttype::JSON);
              auto rval = ctx.json_stringify(response_body_js);
              if (rval.is_exception())
              {
                auto [reason, trace] = ctx.error_message();

                if (rt.log_exception_details)
                {
                  CCF_APP_FAIL(
                    "Failed to convert return value to JSON:{} {}",
                    reason,
                    trace.value_or("<no trace>"));
                }

                if (rt.return_exception_details)
                {
                  std::vector<nlohmann::json> details = {
                    ODataJSExceptionDetails{
                      ccf::errors::JSException, reason, trace}};
                  endpoint_ctx.rpc_ctx->set_error(
                    HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    ccf::errors::InternalError,
                    "Invalid endpoint function return value (error during JSON "
                    "conversion of body)",
                    std::move(details));
                }
                else
                {
                  endpoint_ctx.rpc_ctx->set_error(
                    HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    ccf::errors::InternalError,
                    "Invalid endpoint function return value (error during JSON "
                    "conversion of body).");
                }
                return;
              }
              str = ctx.to_str(rval);
            }

            if (!str)
            {
              auto [reason, trace] = ctx.error_message();

              if (rt.log_exception_details)
              {
                CCF_APP_FAIL(
                  "Failed to convert return value to JSON:{} {}",
                  reason,
                  trace.value_or("<no trace>"));
              }

              if (rt.return_exception_details)
              {
                std::vector<nlohmann::json> details = {ODataJSExceptionDetails{
                  ccf::errors::JSException, reason, trace}};
                endpoint_ctx.rpc_ctx->set_error(
                  HTTP_STATUS_INTERNAL_SERVER_ERROR,
                  ccf::errors::InternalError,
                  "Invalid endpoint function return value (error during string "
                  "conversion of body).",
                  std::move(details));
              }
              else
              {
                endpoint_ctx.rpc_ctx->set_error(
                  HTTP_STATUS_INTERNAL_SERVER_ERROR,
                  ccf::errors::InternalError,
                  "Invalid endpoint function return value (error during string "
                  "conversion of body).");
              }
              return;
            }

            response_body = std::vector<uint8_t>(str->begin(), str->end());
          }
          endpoint_ctx.rpc_ctx->set_response_body(std::move(response_body));
        }
      }

      // Response headers
      {
        auto response_headers_js = val["headers"];
        if (response_headers_js.is_obj())
        {
          js::core::JSWrappedPropertyEnum prop_enum(ctx, response_headers_js);
          for (size_t i = 0; i < prop_enum.size(); i++)
          {
            auto prop_name = ctx.to_str(prop_enum[i]);
            if (!prop_name)
            {
              endpoint_ctx.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Invalid endpoint function return value (header type).");
              return;
            }
            auto prop_val = response_headers_js[*prop_name];
            auto prop_val_str = ctx.to_str(prop_val);
            if (!prop_val_str)
            {
              endpoint_ctx.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Invalid endpoint function return value (header value type).");
              return;
            }
            endpoint_ctx.rpc_ctx->set_response_header(
              *prop_name, *prop_val_str);
          }
        }
      }

      // Response status code
      int response_status_code = HTTP_STATUS_OK;
      {
        auto status_code_js = val["statusCode"];
        if (!status_code_js.is_undefined() && !JS_IsNull(status_code_js.val))
        {
          if (JS_VALUE_GET_TAG(status_code_js.val) != JS_TAG_INT)
          {
            endpoint_ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Invalid endpoint function return value (status code type).");
            return;
          }
          response_status_code = JS_VALUE_GET_INT(status_code_js.val);
        }
        endpoint_ctx.rpc_ctx->set_response_status(response_status_code);
      }

      // Log execution metrics
      if (ctx.log_execution_metrics)
      {
        const auto time_now = ccf::get_enclave_time();
        // Although enclave time returns a microsecond value, the actual
        // precision/granularity depends on the host's TimeUpdater. By default
        // this only advances each millisecond. Avoid implying more precision
        // than that, by rounding to milliseconds
        const auto exec_time =
          std::chrono::duration_cast<std::chrono::milliseconds>(
            time_now - ctx.interrupt_data.start_time);
        CCF_LOG_FMT(INFO, "js")
        ("JS execution complete: Method={}, Path={}, Status={}, "
         "ExecMilliseconds={}",
         endpoint->dispatch.verb.c_str(),
         endpoint->full_uri_path,
         response_status_code,
         exec_time.count());
      }

      return;
    }

    void execute_request_locally_committed(
      const ccf::js::JSDynamicEndpoint* endpoint,
      ccf::endpoints::CommandEndpointContext& endpoint_ctx,
      const ccf::TxID& tx_id)
    {
      ccf::endpoints::default_locally_committed_func(endpoint_ctx, tx_id);
    }

  public:
    JSHandlers(AbstractNodeContext& context) :
      UserEndpointRegistry(context),
      context(context)
    {
      interpreter_cache =
        context.get_subsystem<ccf::js::AbstractInterpreterCache>();
      if (interpreter_cache == nullptr)
      {
        throw std::logic_error(
          "Unexpected: Could not access AbstractInterpreterCache subsytem");
      }

      // Install dependency-less (ie reusable) extensions on interpreters _at
      // creation_, rather than on every run
      js::extensions::Extensions extensions;
      // override Math.random
      extensions.emplace_back(
        std::make_shared<ccf::js::extensions::MathRandomExtension>());
      // add console.[debug|log|...]
      extensions.emplace_back(
        std::make_shared<ccf::js::extensions::CcfConsoleExtension>());
      // add ccf.[strToBuf|bufToStr|...]
      extensions.emplace_back(
        std::make_shared<ccf::js::extensions::CcfConvertersExtension>());
      // add ccf.crypto.*
      extensions.emplace_back(
        std::make_shared<ccf::js::extensions::CcfCryptoExtension>());
      // add ccf.consensus.*
      extensions.emplace_back(
        std::make_shared<ccf::js::extensions::CcfConsensusExtension>(this));
      // add ccf.host.*
      extensions.emplace_back(
        std::make_shared<ccf::js::extensions::CcfHostExtension>(
          context.get_subsystem<ccf::AbstractHostProcesses>().get()));
      // add ccf.historical.*
      extensions.emplace_back(
        std::make_shared<ccf::js::extensions::CcfHistoricalExtension>(
          &context.get_historical_state()));

      interpreter_cache->set_interpreter_factory(
        [extensions](ccf::js::TxAccess access) {
          auto interpreter = std::make_shared<js::core::Context>(access);

          for (auto extension : extensions)
          {
            interpreter->add_extension(extension);
          }

          return interpreter;
        });
    }

    void instantiate_authn_policies(ccf::js::JSDynamicEndpoint& endpoint)
    {
      for (const auto& policy_desc : endpoint.properties.authn_policies)
      {
        if (policy_desc.is_string())
        {
          const auto policy_name = policy_desc.get<std::string>();
          auto policy = get_policy_by_name(policy_name);
          if (policy == nullptr)
          {
            throw std::logic_error(
              fmt::format("Unknown auth policy: {}", policy_name));
          }
          endpoint.authn_policies.push_back(std::move(policy));
        }
        else
        {
          if (policy_desc.is_object())
          {
            const auto it = policy_desc.find("all_of");
            if (it != policy_desc.end())
            {
              if (it.value().is_array())
              {
                std::vector<std::shared_ptr<ccf::AuthnPolicy>>
                  constituent_policies;
                for (const auto& val : it.value())
                {
                  if (!val.is_string())
                  {
                    constituent_policies.clear();
                    break;
                  }

                  const auto policy_name = val.get<std::string>();
                  auto policy = get_policy_by_name(policy_name);
                  if (policy == nullptr)
                  {
                    throw std::logic_error(
                      fmt::format("Unknown auth policy: {}", policy_name));
                  }
                  constituent_policies.push_back(std::move(policy));
                }

                if (!constituent_policies.empty())
                {
                  endpoint.authn_policies.push_back(
                    std::make_shared<ccf::AllOfAuthnPolicy>(
                      constituent_policies));
                  continue;
                }
              }
            }
          }

          // Any failure in above checks falls through to this detailed error.
          throw std::logic_error(fmt::format(
            "Unsupported auth policy. Policies must be either a string, or an "
            "object containing an \"all_of\" key with list-of-strings value. "
            "Unsupported value: {}",
            policy_desc.dump()));
        }
      }
    }

    ccf::endpoints::EndpointDefinitionPtr find_endpoint(
      kv::Tx& tx, ccf::RpcContext& rpc_ctx) override
    {
      const auto method = rpc_ctx.get_method();
      const auto verb = rpc_ctx.get_request_verb();

      auto endpoints =
        tx.ro<ccf::endpoints::EndpointsMap>(ccf::endpoints::Tables::ENDPOINTS);

      const auto key = ccf::endpoints::EndpointKey{method, verb};

      // Look for a direct match of the given path
      const auto it = endpoints->get(key);
      if (it.has_value())
      {
        auto endpoint_def = std::make_shared<ccf::js::JSDynamicEndpoint>();
        endpoint_def->dispatch = key;
        endpoint_def->properties = it.value();
        endpoint_def->full_uri_path =
          fmt::format("/{}{}", method_prefix, endpoint_def->dispatch.uri_path);
        instantiate_authn_policies(*endpoint_def);
        return endpoint_def;
      }

      // If that doesn't exist, look through _all_ the endpoints to find
      // templated matches. If there is one, that's a match. More is an error,
      // none means delegate to the base class.
      {
        std::vector<ccf::endpoints::EndpointDefinitionPtr> matches;

        endpoints->foreach_key([this, &endpoints, &matches, &key, &rpc_ctx](
                                 const auto& other_key) {
          if (key.verb == other_key.verb)
          {
            const auto opt_spec =
              ccf::endpoints::PathTemplateSpec::parse(other_key.uri_path);
            if (opt_spec.has_value())
            {
              const auto& template_spec = opt_spec.value();
              // This endpoint has templates in its path, and the correct verb
              // - now check if template matches the current request's path
              std::smatch match;
              if (std::regex_match(
                    key.uri_path, match, template_spec.template_regex))
              {
                if (matches.empty())
                {
                  auto ctx_impl = static_cast<ccf::RpcContextImpl*>(&rpc_ctx);
                  if (ctx_impl == nullptr)
                  {
                    throw std::logic_error("Unexpected type of RpcContext");
                  }
                  // Populate the request_path_params while we have the match,
                  // though this will be discarded on error if we later find
                  // multiple matches
                  auto& path_params = ctx_impl->path_params;
                  for (size_t i = 0;
                       i < template_spec.template_component_names.size();
                       ++i)
                  {
                    const auto& template_name =
                      template_spec.template_component_names[i];
                    const auto& template_value = match[i + 1].str();
                    path_params[template_name] = template_value;
                  }
                }

                auto endpoint = std::make_shared<ccf::js::JSDynamicEndpoint>();
                endpoint->dispatch = other_key;
                endpoint->full_uri_path = fmt::format(
                  "/{}{}", method_prefix, endpoint->dispatch.uri_path);
                endpoint->properties = endpoints->get(other_key).value();
                instantiate_authn_policies(*endpoint);
                matches.push_back(endpoint);
              }
            }
          }
          return true;
        });

        if (matches.size() > 1)
        {
          report_ambiguous_templated_path(key.uri_path, matches);
        }
        else if (matches.size() == 1)
        {
          return matches[0];
        }
      }

      return ccf::endpoints::EndpointRegistry::find_endpoint(tx, rpc_ctx);
    }

    std::set<RESTVerb> get_allowed_verbs(
      kv::Tx& tx, const ccf::RpcContext& rpc_ctx) override
    {
      const auto method = rpc_ctx.get_method();

      std::set<RESTVerb> verbs =
        ccf::endpoints::EndpointRegistry::get_allowed_verbs(tx, rpc_ctx);

      auto endpoints =
        tx.ro<ccf::endpoints::EndpointsMap>(ccf::endpoints::Tables::ENDPOINTS);

      endpoints->foreach_key([this, &verbs, &method](const auto& key) {
        const auto opt_spec =
          ccf::endpoints::PathTemplateSpec::parse(key.uri_path);
        if (opt_spec.has_value())
        {
          const auto& template_spec = opt_spec.value();
          // This endpoint has templates in its path - now check if template
          // matches the current request's path
          std::smatch match;
          if (std::regex_match(method, match, template_spec.template_regex))
          {
            verbs.insert(key.verb);
          }
        }
        else if (key.uri_path == method)
        {
          verbs.insert(key.verb);
        }
        return true;
      });

      return verbs;
    }

    void execute_endpoint(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::EndpointContext& endpoint_ctx) override
    {
      auto endpoint = dynamic_cast<const ccf::js::JSDynamicEndpoint*>(e.get());
      if (endpoint != nullptr)
      {
        execute_request(endpoint, endpoint_ctx);
        return;
      }

      ccf::endpoints::EndpointRegistry::execute_endpoint(e, endpoint_ctx);
    }

    void execute_endpoint_locally_committed(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::CommandEndpointContext& endpoint_ctx,
      const ccf::TxID& tx_id) override
    {
      auto endpoint = dynamic_cast<const ccf::js::JSDynamicEndpoint*>(e.get());
      if (endpoint != nullptr)
      {
        execute_request_locally_committed(endpoint, endpoint_ctx, tx_id);
        return;
      }

      ccf::endpoints::EndpointRegistry::execute_endpoint_locally_committed(
        e, endpoint_ctx, tx_id);
    }

    // Since we do our own dispatch within the default handler, report the
    // supported methods here
    void build_api(nlohmann::json& document, kv::ReadOnlyTx& tx) override
    {
      UserEndpointRegistry::build_api(document, tx);

      auto endpoints =
        tx.ro<ccf::endpoints::EndpointsMap>(ccf::endpoints::Tables::ENDPOINTS);

      endpoints->foreach([&document](const auto& key, const auto& properties) {
        const auto http_verb = key.verb.get_http_method();
        if (!http_verb.has_value())
        {
          return true;
        }

        if (!properties.openapi_hidden)
        {
          auto& path_op = ds::openapi::path_operation(
            ds::openapi::path(
              document,
              fmt::format(
                "/{}{}",
                ccf::get_actor_prefix(ccf::ActorsType::users),
                key.uri_path)),
            http_verb.value(),
            false);
          if (!properties.openapi.empty())
          {
            for (const auto& [k, v] : properties.openapi.items())
            {
              LOG_INFO_FMT("Inserting field {}", k);
            }
            path_op.insert(
              properties.openapi.cbegin(), properties.openapi.cend());
          }
        }

        return true;
      });
    }
  };

  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints_impl(
    ccfapp::AbstractNodeContext& context)
  {
    return std::make_unique<JSHandlers>(context);
  }

} // namespace ccfapp
