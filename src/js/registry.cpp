// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// CCF
#include "ccf/js/registry.h"

#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/ds/hash.h"
#include "ccf/ds/logger.h"
#include "ccf/http_query.h"
#include "ccf/json_handler.h"
#include "ccf/service/tables/modules.h"
#include "ccf/version.h"
#include "ds/internal_logger.h"
#include "js/checks.h"

#include <charconv>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

// Custom Endpoints
#include "ccf/crypto/sha256.h"
#include "ccf/ds/hex.h"
#include "ccf/endpoint.h"
#include "ccf/endpoints/authentication/js.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/js/bundle.h"
#include "ccf/js/common_context.h"
#include "ccf/js/core/context.h"
#include "ccf/js/core/wrapped_property_enum.h"
#include "ccf/js/extensions/ccf/consensus.h"
#include "ccf/js/extensions/ccf/historical.h"
#include "ccf/js/extensions/ccf/kv.h"
#include "ccf/js/extensions/ccf/request.h"
#include "ccf/js/extensions/ccf/rpc.h"
#include "ccf/js/interpreter_cache_interface.h"
#include "ds/actors.h"
#include "js/modules/chained_module_loader.h"
#include "js/modules/kv_bytecode_module_loader.h"
#include "js/modules/kv_module_loader.h"
#include "node/rpc_context_impl.h"

namespace ccf::js
{
  std::string normalised_module_path(std::string_view sv)
  {
    if (!sv.starts_with("/"))
    {
      return fmt::format("/{}", sv);
    }

    return std::string(sv);
  }

  void BaseDynamicJSEndpointRegistry::do_execute_request(
    const CustomJSEndpoint* endpoint,
    ccf::endpoints::EndpointContext& endpoint_ctx,
    const std::optional<PreExecutionHook>& pre_exec_hook)
  {
    // This KV Value should be updated by any governance actions which modify
    // the JS app (including _any_ of its contained modules). We then use the
    // version where it was last modified as a safe approximation of when an
    // interpreter is unsafe to use. If this value is written to, the
    // version_of_previous_write will advance, and all cached interpreters
    // will be flushed.
    auto* const interpreter_flush =
      endpoint_ctx.tx.ro<ccf::InterpreterFlush>(interpreter_flush_map);
    const auto flush_marker =
      interpreter_flush->get_version_of_previous_write().value_or(0);

    auto options_opt =
      endpoint_ctx.tx.ro<ccf::JSEngine>(runtime_options_map)->get();
    if (options_opt.has_value())
    {
      interpreter_cache->set_max_cached_interpreters(
        options_opt->max_cached_interpreters);
    }

    const auto rw_access =
      endpoint->properties.mode == ccf::endpoints::Mode::ReadWrite ?
      ccf::js::TxAccess::APP_RW :
      ccf::js::TxAccess::APP_RO;
    std::optional<ccf::endpoints::InterpreterReusePolicy> reuse_policy =
      endpoint->properties.interpreter_reuse;
    std::shared_ptr<ccf::js::core::Context> interpreter =
      interpreter_cache->get_interpreter(rw_access, reuse_policy, flush_marker);
    if (interpreter == nullptr)
    {
      throw std::logic_error("Cache failed to produce interpreter");
    }
    ccf::js::core::Context& ctx = *interpreter;

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

    ccf::js::modules::ModuleLoaders sub_loaders = {
      std::make_shared<ccf::js::modules::KvBytecodeModuleLoader>(
        endpoint_ctx.tx.ro<ccf::ModulesQuickJsBytecode>(
          modules_quickjs_bytecode_map),
        endpoint_ctx.tx.ro<ccf::ModulesQuickJsVersion>(
          modules_quickjs_version_map)),
      std::make_shared<ccf::js::modules::KvModuleLoader>(
        endpoint_ctx.tx.ro<ccf::Modules>(modules_map))};
    auto module_loader =
      std::make_shared<ccf::js::modules::ChainedModuleLoader>(
        std::move(sub_loaders));
    ctx.set_module_loader(std::move(module_loader));

    // Extensions with a dependency on this endpoint context (invocation),
    // which must be removed after execution.
    ccf::js::extensions::Extensions local_extensions =
      get_extensions(endpoint_ctx);

    // ccf.kv.*
    local_extensions.emplace_back(
      std::make_shared<ccf::js::extensions::KvExtension>(
        &endpoint_ctx.tx, namespace_restriction));

    // ccf.rpc.*
    local_extensions.emplace_back(
      std::make_shared<ccf::js::extensions::RpcExtension>(
        endpoint_ctx.rpc_ctx.get()));

    auto request_extension =
      std::make_shared<ccf::js::extensions::RequestExtension>(
        endpoint_ctx.rpc_ctx.get());
    local_extensions.push_back(request_extension);

    for (const auto& extension : local_extensions)
    {
      ctx.add_extension(extension);
    }

    if (pre_exec_hook.has_value())
    {
      pre_exec_hook.value()(ctx);
    }

    ccf::js::core::JSWrappedValue export_func;
    try
    {
      const auto& props = endpoint->properties;
      auto module_val = ctx.get_module(props.js_module);
      if (!module_val.has_value())
      {
        throw std::logic_error(
          fmt::format("Module '{}' could not be loaded", props.js_module));
      }
      export_func = ctx.get_exported_function(
        *module_val, props.js_function, props.js_module);
    }
    catch (const std::exception& exc)
    {
      endpoint_ctx.rpc_ctx->set_error(
        HTTP_STATUS_INTERNAL_SERVER_ERROR,
        ccf::errors::InternalError,
        exc.what());
      return;
    }

    // Call exported function;
    auto request = request_extension->create_request_obj(
      ctx, endpoint->full_uri_path, endpoint_ctx, this);

    const auto options = options_opt.value_or(ccf::JSRuntimeOptions());

    auto val = ctx.call_with_rt_options(
      export_func,
      {request},
      options,
      ccf::js::core::RuntimeLimitsPolicy::NONE);

    for (const auto& extension : local_extensions)
    {
      ctx.remove_extension(extension);
    }

    if (val.is_exception())
    {
      bool time_out = ctx.interrupt_data.request_timed_out;
      std::string error_msg = "Exception thrown while executing.";
      if (time_out)
      {
        error_msg = "Operation took too long to complete.";
      }

      auto [reason, trace] = ctx.error_message();

      if (options.log_exception_details)
      {
        CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
      }

      if (options.return_exception_details)
      {
        std::vector<nlohmann::json> details = {ccf::ODataJSExceptionDetails{
          ccf::errors::JSException, reason, trace}};
        endpoint_ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          std::move(error_msg),
          details);
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
        size_t buf_size = 0;
        size_t buf_offset = 0;
        auto typed_array_buffer = ctx.get_typed_array_buffer(
          response_body_js, &buf_offset, &buf_size, nullptr);
        uint8_t* array_buffer = nullptr;
        if (!typed_array_buffer.is_exception())
        {
          size_t buf_size_total = 0;
          array_buffer =
            JS_GetArrayBuffer(ctx, &buf_size_total, typed_array_buffer.val);
          array_buffer += buf_offset;
        }
        else
        {
          array_buffer =
            JS_GetArrayBuffer(ctx, &buf_size, response_body_js.val);
        }
        if (array_buffer != nullptr)
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

              if (options.log_exception_details)
              {
                CCF_APP_FAIL(
                  "Failed to convert return value to JSON:{} {}",
                  reason,
                  trace.value_or("<no trace>"));
              }

              if (options.return_exception_details)
              {
                std::vector<nlohmann::json> details = {
                  ccf::ODataJSExceptionDetails{
                    ccf::errors::JSException, reason, trace}};
                endpoint_ctx.rpc_ctx->set_error(
                  HTTP_STATUS_INTERNAL_SERVER_ERROR,
                  ccf::errors::InternalError,
                  "Invalid endpoint function return value (error during JSON "
                  "conversion of body)",
                  details);
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

            if (options.log_exception_details)
            {
              CCF_APP_FAIL(
                "Failed to convert return value to JSON:{} {}",
                reason,
                trace.value_or("<no trace>"));
            }

            if (options.return_exception_details)
            {
              std::vector<nlohmann::json> details = {
                ccf::ODataJSExceptionDetails{
                  ccf::errors::JSException, reason, trace}};
              endpoint_ctx.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Invalid endpoint function return value (error during string "
                "conversion of body).",
                details);
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
        ccf::js::core::JSWrappedPropertyEnum prop_enum(
          ctx, response_headers_js);
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
          endpoint_ctx.rpc_ctx->set_response_header(*prop_name, *prop_val_str);
        }
      }
    }

    // Response status code
    int response_status_code = HTTP_STATUS_OK;
    {
      auto status_code_js = val["statusCode"];
      if (
        !status_code_js.is_undefined() && (JS_IsNull(status_code_js.val) == 0))
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
      const auto time_now =
        decltype(ccf::js::core::InterruptData::start_time)::clock::now();

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
  }

  void BaseDynamicJSEndpointRegistry::execute_request(
    const CustomJSEndpoint* endpoint,
    ccf::endpoints::EndpointContext& endpoint_ctx)
  {
    if (endpoint->properties.mode == ccf::endpoints::Mode::Historical)
    {
      auto is_tx_committed =
        [this](ccf::View view, ccf::SeqNo seqno, std::string& error_reason) {
          return ccf::historical::is_tx_committed_v2(
            consensus, view, seqno, error_reason);
        };

      ccf::historical::read_write_adapter_v4(
        [this, endpoint](
          ccf::endpoints::EndpointContext& endpoint_ctx,
          ccf::historical::StatePtr state) {
          auto add_historical_globals = [&](js::core::Context& ctx) {
            auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());
            auto* extension =
              ctx.get_extension<ccf::js::extensions::HistoricalExtension>();
            if (extension != nullptr)
            {
              auto val = extension->create_historical_state_object(ctx, state);
              JS_CHECK_OR_THROW(ccf.set("historicalState", std::move(val)));
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

  BaseDynamicJSEndpointRegistry::BaseDynamicJSEndpointRegistry(
    ccf::AbstractNodeContext& context, const std::string& kv_prefix) :
    ccf::UserEndpointRegistry(context),
    modules_map(fmt::format("{}.modules", kv_prefix)),
    metadata_map(fmt::format("{}.metadata", kv_prefix)),
    interpreter_flush_map(fmt::format("{}.interpreter_flush", kv_prefix)),
    modules_quickjs_version_map(
      fmt::format("{}.modules_quickjs_version", kv_prefix)),
    modules_quickjs_bytecode_map(
      fmt::format("{}.modules_quickjs_bytecode", kv_prefix)),
    runtime_options_map(fmt::format("{}.runtime_options", kv_prefix))
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
    ccf::js::extensions::Extensions extensions;

    // add ccf.consensus.*
    extensions.emplace_back(
      std::make_shared<ccf::js::extensions::ConsensusExtension>(this));
    // add ccf.historical.*
    extensions.emplace_back(
      std::make_shared<ccf::js::extensions::HistoricalExtension>(
        &context.get_historical_state()));

    interpreter_cache->set_interpreter_factory(
      [extensions](ccf::js::TxAccess access) {
        // CommonContext also adds many extensions
        auto interpreter = std::make_shared<ccf::js::CommonContext>(access);

        for (const auto& extension : extensions)
        {
          interpreter->add_extension(extension);
        }

        return interpreter;
      });
  }

  ccf::ApiResult BaseDynamicJSEndpointRegistry::install_custom_endpoints_v1(
    ccf::kv::Tx& tx, const ccf::js::Bundle& bundle)
  {
    try
    {
      auto* endpoints =
        tx.template rw<ccf::endpoints::EndpointsMap>(metadata_map);
      endpoints->clear();
      for (const auto& [url, methods] : bundle.metadata.endpoints)
      {
        for (const auto& [method, metadata] : methods)
        {
          std::string method_upper = method;
          ccf::nonstd::to_upper(method_upper);
          const auto key = ccf::endpoints::EndpointKey{url, method_upper};
          endpoints->put(key, metadata);
        }
      }

      auto* modules = tx.template rw<ccf::Modules>(modules_map);
      modules->clear();
      for (const auto& moduledef : bundle.modules)
      {
        modules->put(normalised_module_path(moduledef.name), moduledef.module);
      }

      // Trigger interpreter flush, in case interpreter reuse
      // is enabled for some endpoints
      auto* interpreter_flush =
        tx.template rw<ccf::InterpreterFlush>(interpreter_flush_map);
      interpreter_flush->put(true);

      // Refresh app bytecode
      ccf::js::core::Context jsctx(ccf::js::TxAccess::APP_RW);
      jsctx.runtime().set_runtime_options(
        tx.ro<ccf::JSEngine>(runtime_options_map)->get(),
        ccf::js::core::RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS);

      auto* quickjs_version =
        tx.wo<ccf::ModulesQuickJsVersion>(modules_quickjs_version_map);
      auto* quickjs_bytecode =
        tx.wo<ccf::ModulesQuickJsBytecode>(modules_quickjs_bytecode_map);

      quickjs_version->put(ccf::quickjs_version);
      quickjs_bytecode->clear();
      jsctx.set_module_loader(
        std::make_shared<ccf::js::modules::KvModuleLoader>(modules));

      modules->foreach([&](const auto& name, const auto& src) {
        auto module_val = jsctx.eval(
          src.c_str(),
          src.size(),
          name.c_str(),
          JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);

        uint8_t* out_buf = nullptr;
        size_t out_buf_len = 0;
        int flags = JS_WRITE_OBJ_BYTECODE;
        out_buf = JS_WriteObject(jsctx, &out_buf_len, module_val.val, flags);
        if (!out_buf)
        {
          throw std::runtime_error(fmt::format(
            "Unable to serialize bytecode for JS module '{}'", name));
        }

        quickjs_bytecode->put(name, {out_buf, out_buf + out_buf_len});
        js_free(jsctx, out_buf);

        return true;
      });

      return ccf::ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ccf::ApiResult BaseDynamicJSEndpointRegistry::get_custom_endpoints_v1(
    ccf::js::Bundle& bundle, ccf::kv::ReadOnlyTx& tx)
  {
    try
    {
      auto* endpoints_handle =
        tx.template ro<ccf::endpoints::EndpointsMap>(metadata_map);
      endpoints_handle->foreach([&endpoints = bundle.metadata.endpoints](
                                  const auto& endpoint_key,
                                  const auto& properties) {
        using PropertiesMap =
          std::map<std::string, ccf::endpoints::EndpointProperties>;

        auto it = endpoints.find(endpoint_key.uri_path);
        if (it == endpoints.end())
        {
          it =
            endpoints.emplace_hint(it, endpoint_key.uri_path, PropertiesMap{});
        }

        PropertiesMap& method_properties = it->second;

        method_properties.emplace_hint(
          method_properties.end(), endpoint_key.verb.c_str(), properties);

        return true;
      });

      auto* modules_handle = tx.template ro<ccf::Modules>(modules_map);
      modules_handle->foreach(
        [&modules =
           bundle.modules](const auto& module_name, const auto& module_src) {
          modules.push_back({module_name, module_src});
          return true;
        });

      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ccf::ApiResult BaseDynamicJSEndpointRegistry::
    get_custom_endpoint_properties_v1(
      ccf::endpoints::EndpointProperties& properties,
      ccf::kv::ReadOnlyTx& tx,
      const ccf::RESTVerb& verb,
      const ccf::endpoints::URI& uri)
  {
    try
    {
      auto* endpoints = tx.ro<ccf::endpoints::EndpointsMap>(metadata_map);
      const auto key = ccf::endpoints::EndpointKey{uri, verb};

      auto it = endpoints->get(key);
      if (it.has_value())
      {
        properties = it.value();
        return ApiResult::OK;
      }

      return ApiResult::NotFound;
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ccf::ApiResult BaseDynamicJSEndpointRegistry::get_custom_endpoint_module_v1(
    std::string& code, ccf::kv::ReadOnlyTx& tx, const std::string& module_name)
  {
    try
    {
      auto* modules = tx.template ro<ccf::Modules>(modules_map);

      auto it = modules->get(normalised_module_path(module_name));
      if (it.has_value())
      {
        code = it.value();
        return ApiResult::OK;
      }

      return ApiResult::NotFound;
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  void BaseDynamicJSEndpointRegistry::set_js_kv_namespace_restriction(
    const ccf::js::NamespaceRestriction& restriction)
  {
    namespace_restriction = restriction;
  }

  ccf::ApiResult BaseDynamicJSEndpointRegistry::set_js_runtime_options_v1(
    ccf::kv::Tx& tx, const ccf::JSRuntimeOptions& options)
  {
    try
    {
      tx.wo<ccf::JSEngine>(runtime_options_map)->put(options);
      return ccf::ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      return ccf::ApiResult::InternalError;
    }
  }

  ccf::ApiResult BaseDynamicJSEndpointRegistry::get_js_runtime_options_v1(
    ccf::JSRuntimeOptions& options, ccf::kv::ReadOnlyTx& tx)
  {
    try
    {
      options = tx.ro<ccf::JSEngine>(runtime_options_map)
                  ->get()
                  .value_or(ccf::JSRuntimeOptions());

      return ccf::ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      return ccf::ApiResult::InternalError;
    }
  }

  ccf::endpoints::EndpointDefinitionPtr BaseDynamicJSEndpointRegistry::
    find_endpoint(ccf::kv::Tx& tx, ccf::RpcContext& rpc_ctx)
  {
    // Look up the endpoint definition
    // First in the user-defined endpoints, and then fall-back to built-ins
    const auto method = rpc_ctx.get_method();
    const auto verb = rpc_ctx.get_request_verb();

    auto* endpoints = tx.ro<ccf::endpoints::EndpointsMap>(metadata_map);
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

    // If that doesn't exist, look through _all_ the endpoints to find
    // templated matches. If there is one, that's a match. More is an error,
    // none means delegate to the base class.
    {
      std::vector<ccf::endpoints::EndpointDefinitionPtr> matches;

      endpoints->foreach_key(
        [this, &endpoints, &matches, &key, &rpc_ctx](const auto& other_key) {
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
                  auto* ctx_impl = dynamic_cast<ccf::RpcContextImpl*>(&rpc_ctx);
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

                auto endpoint = std::make_shared<CustomJSEndpoint>();
                endpoint->dispatch = other_key;
                endpoint->full_uri_path = fmt::format(
                  "/{}{}", method_prefix, endpoint->dispatch.uri_path);
                endpoint->properties = endpoints->get(other_key).value();
                ccf::instantiate_authn_policies(*endpoint);
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

  void BaseDynamicJSEndpointRegistry::execute_endpoint(
    ccf::endpoints::EndpointDefinitionPtr e,
    ccf::endpoints::EndpointContext& endpoint_ctx)
  {
    // Handle endpoint execution
    const auto* endpoint = dynamic_cast<const CustomJSEndpoint*>(e.get());
    if (endpoint != nullptr)
    {
      execute_request(endpoint, endpoint_ctx);
      return;
    }

    ccf::endpoints::EndpointRegistry::execute_endpoint(e, endpoint_ctx);
  }

  void BaseDynamicJSEndpointRegistry::execute_endpoint_locally_committed(
    ccf::endpoints::EndpointDefinitionPtr e,
    ccf::endpoints::CommandEndpointContext& endpoint_ctx,
    const ccf::TxID& tx_id)
  {
    const auto* endpoint = dynamic_cast<const CustomJSEndpoint*>(e.get());
    if (endpoint != nullptr)
    {
      ccf::endpoints::default_locally_committed_func(endpoint_ctx, tx_id);
      return;
    }

    ccf::endpoints::EndpointRegistry::execute_endpoint_locally_committed(
      e, endpoint_ctx, tx_id);
  }

  // Since we do our own dispatch (overriding find_endpoint), make sure we
  // describe those operations in the auto-generated OpenAPI
  void BaseDynamicJSEndpointRegistry::build_api(
    nlohmann::json& document, ccf::kv::ReadOnlyTx& tx)
  {
    ccf::UserEndpointRegistry::build_api(document, tx);

    auto* endpoints = tx.ro<ccf::endpoints::EndpointsMap>(metadata_map);

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
          path_op.insert(
            properties.openapi.cbegin(), properties.openapi.cend());
        }
      }

      return true;
    });
  }

  std::set<RESTVerb> BaseDynamicJSEndpointRegistry::get_allowed_verbs(
    [[maybe_unused]] ccf::kv::Tx& tx, const ccf::RpcContext& rpc_ctx)
  {
    const auto method = rpc_ctx.get_method();

    std::set<RESTVerb> verbs =
      ccf::endpoints::EndpointRegistry::get_allowed_verbs(tx, rpc_ctx);

    auto* endpoints =
      tx.template ro<ccf::endpoints::EndpointsMap>(metadata_map);

    endpoints->foreach_key([&verbs, &method](const auto& key) {
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

  ccf::ApiResult DynamicJSEndpointRegistry::check_action_not_replayed_v1(
    ccf::kv::Tx& tx,
    uint64_t created_at,
    const std::span<const uint8_t> action,
    ccf::InvalidArgsReason& reason)
  {
    try
    {
      const auto created_at_str = fmt::format("{:0>10}", created_at);
      const auto action_digest =
        ccf::crypto::sha256(action.data(), action.size());

      using RecentActions = ccf::kv::Set<std::string>;

      auto* recent_actions = tx.rw<RecentActions>(recent_actions_map);
      auto key =
        fmt::format("{}:{}", created_at_str, ds::to_hex(action_digest));

      if (recent_actions->contains(key))
      {
        reason = ccf::InvalidArgsReason::ActionAlreadyApplied;
        return ApiResult::InvalidArgs;
      }

      // In the absence of in-KV support for sorted sets, we need
      // to extract them and sort them here.
      std::vector<std::string> replay_keys;
      recent_actions->foreach([&replay_keys](const std::string& replay_key) {
        replay_keys.push_back(replay_key);
        return true;
      });
      std::sort(replay_keys.begin(), replay_keys.end());

      // Actions must be more recent than the median of recent actions
      if (!replay_keys.empty())
      {
        const auto [min_created_at, _] =
          ccf::nonstd::split_1(replay_keys[replay_keys.size() / 2], ":");
        auto [key_ts, ignored] = ccf::nonstd::split_1(key, ":");
        if (key_ts < min_created_at)
        {
          reason = ccf::InvalidArgsReason::StaleActionCreatedTimestamp;
          return ApiResult::InvalidArgs;
        }
      }

      // The action is neither stale, nor a replay
      recent_actions->insert(key);

      // Only keep the most recent window_size proposals, do not
      // allow the set to grow indefinitely.
      // Should this be configurable through runtime options?
      constexpr size_t window_size = 100;
      if (replay_keys.size() >= (window_size - 1) /* We just added one */)
      {
        for (size_t i = 0; i < (replay_keys.size() - (window_size - 1)); i++)
        {
          recent_actions->remove(replay_keys[i]);
        }
      }

      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ccf::ApiResult DynamicJSEndpointRegistry::record_action_for_audit_v1(
    ccf::kv::Tx& tx,
    ccf::ActionFormat format,
    const std::string& user_id,
    const std::string& action_name,
    const std::vector<uint8_t>& action_body)
  {
    try
    {
      using AuditInputValue = ccf::kv::Value<std::vector<uint8_t>>;
      using AuditInfoValue = ccf::kv::Value<AuditInfo>;

      auto* audit_input = tx.template rw<AuditInputValue>(audit_input_map);
      audit_input->put(action_body);

      auto* audit_info = tx.template rw<AuditInfoValue>(audit_info_map);
      audit_info->put({format, user_id, action_name});

      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }
}
