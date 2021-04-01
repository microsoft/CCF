// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "apps/utils/metrics_tracker.h"
#include "ccf/app_interface.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/user_frontend.h"
#include "crypto/entropy.h"
#include "crypto/key_wrap.h"
#include "crypto/rsa_key_pair.h"
#include "js/wrap.h"
#include "kv/untyped_map.h"
#include "named_auth_policies.h"

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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  // Modules

  struct JSModuleLoaderArg
  {
    ccf::NetworkTables* network;
    kv::Tx* tx;
  };

  static JSModuleDef* js_module_loader(
    JSContext* ctx, const char* module_name, void* opaque)
  {
    // QuickJS resolves relative paths but in some cases omits leading slashes.
    std::string module_name_kv(module_name);
    if (module_name_kv[0] != '/')
    {
      module_name_kv.insert(0, "/");
    }

    LOG_TRACE_FMT("Loading module '{}'", module_name_kv);

    auto arg = (JSModuleLoaderArg*)opaque;

    const auto modules = arg->tx->ro(arg->network->modules);
    auto module = modules->get(module_name_kv);
    if (!module.has_value())
    {
      JS_ThrowReferenceError(ctx, "module '%s' not found in kv", module_name);
      return nullptr;
    }
    auto& js = module.value();

    const char* buf = js.c_str();
    size_t buf_len = js.size();
    JSValue func_val = JS_Eval(
      ctx,
      buf,
      buf_len,
      module_name,
      JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    if (JS_IsException(func_val))
    {
      js::js_dump_error(ctx);
      return nullptr;
    }

    auto m = (JSModuleDef*)JS_VALUE_GET_PTR(func_val);
    // module already referenced, decrement ref count
    JS_FreeValue(ctx, func_val);
    return m;
  }

  // END modules

  class JSHandlers : public UserEndpointRegistry
  {
  private:
    NetworkTables& network;
    ccfapp::AbstractNodeContext& context;
    metrics::Tracker metrics_tracker;

    static JSValue create_json_obj(const nlohmann::json& j, JSContext* ctx)
    {
      const auto buf = j.dump();
      return JS_ParseJSON(ctx, buf.data(), buf.size(), "<json>");
    }

    JSValue create_caller_obj(
      ccf::endpoints::EndpointContext& args, JSContext* ctx)
    {
      if (args.caller == nullptr)
      {
        return JS_NULL;
      }

      auto caller = JS_NewObject(ctx);

      if (auto jwt_ident = args.try_get_caller<ccf::JwtAuthnIdentity>())
      {
        JS_SetPropertyStr(
          ctx,
          caller,
          "policy",
          JS_NewString(ctx, get_policy_name_from_ident(jwt_ident)));

        auto jwt = JS_NewObject(ctx);
        JS_SetPropertyStr(
          ctx,
          jwt,
          "keyIssuer",
          JS_NewStringLen(
            ctx, jwt_ident->key_issuer.data(), jwt_ident->key_issuer.size()));
        JS_SetPropertyStr(
          ctx, jwt, "header", create_json_obj(jwt_ident->header, ctx));
        JS_SetPropertyStr(
          ctx, jwt, "payload", create_json_obj(jwt_ident->payload, ctx));
        JS_SetPropertyStr(ctx, caller, "jwt", jwt);

        return caller;
      }
      else if (
        auto empty_ident = args.try_get_caller<ccf::EmptyAuthnIdentity>())
      {
        JS_SetPropertyStr(
          ctx,
          caller,
          "policy",
          JS_NewString(ctx, get_policy_name_from_ident(empty_ident)));
        return caller;
      }

      char const* policy_name = nullptr;
      EntityId id;
      bool is_member = false;

      if (
        auto user_cert_ident =
          args.try_get_caller<ccf::UserCertAuthnIdentity>())
      {
        policy_name = get_policy_name_from_ident(user_cert_ident);
        id = user_cert_ident->user_id;
        is_member = false;
      }
      else if (
        auto member_cert_ident =
          args.try_get_caller<ccf::MemberCertAuthnIdentity>())
      {
        policy_name = get_policy_name_from_ident(member_cert_ident);
        id = member_cert_ident->member_id;
        is_member = true;
      }
      else if (
        auto user_sig_ident =
          args.try_get_caller<ccf::UserSignatureAuthnIdentity>())
      {
        policy_name = get_policy_name_from_ident(user_sig_ident);
        id = user_sig_ident->user_id;
        is_member = false;
      }
      else if (
        auto member_sig_ident =
          args.try_get_caller<ccf::MemberSignatureAuthnIdentity>())
      {
        policy_name = get_policy_name_from_ident(member_sig_ident);
        id = member_sig_ident->member_id;
        is_member = true;
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
        result = get_member_data_v1(args.tx, id, data);
      }
      else
      {
        result = get_user_data_v1(args.tx, id, data);
      }

      if (result == ccf::ApiResult::InternalError)
      {
        throw std::logic_error(
          fmt::format("Failed to get data for caller {}", id));
      }

      crypto::Pem cert;
      if (is_member)
      {
        result = get_user_cert_v1(args.tx, id, cert);
      }
      else
      {
        result = get_member_cert_v1(args.tx, id, cert);
      }

      if (result == ccf::ApiResult::InternalError)
      {
        throw std::logic_error(
          fmt::format("Failed to get certificate for caller {}", id));
      }

      JS_SetPropertyStr(ctx, caller, "policy", JS_NewString(ctx, policy_name));
      JS_SetPropertyStr(
        ctx, caller, "id", JS_NewStringLen(ctx, id.data(), id.size()));
      JS_SetPropertyStr(ctx, caller, "data", create_json_obj(data, ctx));
      JS_SetPropertyStr(
        ctx,
        caller,
        "cert",
        JS_NewStringLen(ctx, cert.str().data(), cert.size()));

      return caller;
    }

    JSValue create_request_obj(
      ccf::endpoints::EndpointContext& args, JSContext* ctx)
    {
      auto request = JS_NewObject(ctx);

      auto headers = JS_NewObject(ctx);
      for (auto& [header_name, header_value] :
           args.rpc_ctx->get_request_headers())
      {
        JS_SetPropertyStr(
          ctx,
          headers,
          header_name.c_str(),
          JS_NewStringLen(ctx, header_value.c_str(), header_value.size()));
      }
      JS_SetPropertyStr(ctx, request, "headers", headers);

      const auto& request_query = args.rpc_ctx->get_request_query();
      auto query_str =
        JS_NewStringLen(ctx, request_query.c_str(), request_query.size());
      JS_SetPropertyStr(ctx, request, "query", query_str);

      auto params = JS_NewObject(ctx);
      for (auto& [param_name, param_value] :
           args.rpc_ctx->get_request_path_params())
      {
        JS_SetPropertyStr(
          ctx,
          params,
          param_name.c_str(),
          JS_NewStringLen(ctx, param_value.c_str(), param_value.size()));
      }
      JS_SetPropertyStr(ctx, request, "params", params);

      const auto& request_body = args.rpc_ctx->get_request_body();
      auto body_ = JS_NewObjectClass(ctx, js::body_class_id);
      JS_SetOpaque(body_, (void*)&request_body);
      JS_SetPropertyStr(ctx, request, "body", body_);

      JS_SetPropertyStr(ctx, request, "caller", create_caller_obj(args, ctx));

      return request;
    }

    void execute_request(
      const ccf::endpoints::EndpointProperties& props,
      ccf::endpoints::EndpointContext& args)
    {
      if (props.mode == ccf::endpoints::Mode::Historical)
      {
        auto is_tx_committed =
          [this](ccf::View view, ccf::SeqNo seqno, std::string& error_reason) {
            return ccf::historical::is_tx_committed(
              consensus, view, seqno, error_reason);
          };

        ccf::historical::adapter(
          [this, &props](
            ccf::endpoints::EndpointContext& args,
            ccf::historical::StatePtr state) {
            auto tx = state->store->create_tx();
            auto tx_id = state->transaction_id;
            auto receipt = state->receipt;
            do_execute_request(props, args, tx, tx_id, receipt);
          },
          context.get_historical_state(),
          is_tx_committed)(args);
      }
      else
      {
        do_execute_request(props, args, args.tx, std::nullopt, nullptr);
      }
    }

    void do_execute_request(
      const ccf::endpoints::EndpointProperties& props,
      ccf::endpoints::EndpointContext& args,
      kv::Tx& target_tx,
      const std::optional<ccf::TxID>& transaction_id,
      ccf::historical::TxReceiptPtr receipt)
    {
      const auto modules = args.tx.ro(this->network.modules);

      auto handler_script = modules->get(props.js_module);
      if (!handler_script.has_value())
      {
        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format("Endpoint module not found: {}.", props.js_module));
        return;
      }

      js::Runtime rt;
      rt.add_ccf_classdefs();

      JSModuleLoaderArg js_module_loader_arg{&this->network, &args.tx};
      JS_SetModuleLoaderFunc(
        rt, nullptr, js_module_loader, &js_module_loader_arg);

      js::Context ctx(rt);
      js::TxContext txctx{&target_tx, js::TxAccess::APP};

      js::register_request_body_class(ctx);
      js::populate_global_console(ctx);
      js::populate_global_ccf(
        &txctx, transaction_id, receipt, nullptr, nullptr, ctx);

      // Compile module
      std::string code = handler_script.value();
      const std::string path = props.js_module;

      JSValue export_func;
      try
      {
        export_func = ctx.function(code, props.js_function, path);
      }
      catch (std::exception& exc)
      {
        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          exc.what());
        return;
      }

      // Call exported function
      auto request = create_request_obj(args, ctx);
      int argc = 1;
      JSValueConst* argv = (JSValueConst*)&request;
      auto val = ctx(JS_Call(ctx, export_func, JS_UNDEFINED, argc, argv));
      JS_FreeValue(ctx, request);
      JS_FreeValue(ctx, export_func);

      if (JS_IsException(val))
      {
        js::js_dump_error(ctx);
        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Exception thrown while executing.");
        return;
      }

      // Handle return value: {body, headers, statusCode}
      if (!JS_IsObject(val))
      {
        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Invalid endpoint function return value (not an object).");
        return;
      }

      // Response body (also sets a default response content-type header)
      {
        auto response_body_js = ctx(JS_GetPropertyStr(ctx, val, "body"));
        std::vector<uint8_t> response_body;
        size_t buf_size;
        size_t buf_offset;
        JSValue typed_array_buffer = JS_GetTypedArrayBuffer(
          ctx, response_body_js, &buf_offset, &buf_size, nullptr);
        uint8_t* array_buffer;
        if (!JS_IsException(typed_array_buffer))
        {
          size_t buf_size_total;
          array_buffer =
            JS_GetArrayBuffer(ctx, &buf_size_total, typed_array_buffer);
          array_buffer += buf_offset;
          JS_FreeValue(ctx, typed_array_buffer);
        }
        else
        {
          array_buffer = JS_GetArrayBuffer(ctx, &buf_size, response_body_js);
        }
        if (array_buffer)
        {
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE,
            http::headervalues::contenttype::OCTET_STREAM);
          response_body =
            std::vector<uint8_t>(array_buffer, array_buffer + buf_size);
        }
        else
        {
          const char* cstr = nullptr;
          if (JS_IsString(response_body_js))
          {
            args.rpc_ctx->set_response_header(
              http::headers::CONTENT_TYPE,
              http::headervalues::contenttype::TEXT);
            cstr = JS_ToCString(ctx, response_body_js);
          }
          else
          {
            args.rpc_ctx->set_response_header(
              http::headers::CONTENT_TYPE,
              http::headervalues::contenttype::JSON);
            JSValue rval =
              JS_JSONStringify(ctx, response_body_js, JS_NULL, JS_NULL);
            if (JS_IsException(rval))
            {
              js::js_dump_error(ctx);
              args.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Invalid endpoint function return value (error during JSON "
                "conversion of body).");
              return;
            }
            cstr = JS_ToCString(ctx, rval);
            JS_FreeValue(ctx, rval);
          }
          if (!cstr)
          {
            js::js_dump_error(ctx);
            args.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Invalid endpoint function return value (error during string "
              "conversion of body).");
            return;
          }
          std::string str(cstr);
          JS_FreeCString(ctx, cstr);

          response_body = std::vector<uint8_t>(str.begin(), str.end());
        }
        args.rpc_ctx->set_response_body(std::move(response_body));
      }

      // Response headers
      {
        auto response_headers_js = ctx(JS_GetPropertyStr(ctx, val, "headers"));
        if (JS_IsObject(response_headers_js))
        {
          uint32_t prop_count = 0;
          JSPropertyEnum* props = nullptr;
          JS_GetOwnPropertyNames(
            ctx,
            &props,
            &prop_count,
            response_headers_js,
            JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY);
          for (size_t i = 0; i < prop_count; i++)
          {
            auto prop_name = props[i].atom;
            auto prop_name_cstr = ctx(JS_AtomToCString(ctx, prop_name));
            auto prop_val =
              ctx(JS_GetProperty(ctx, response_headers_js, prop_name));
            auto prop_val_cstr = JS_ToCString(ctx, prop_val);
            if (!prop_val_cstr)
            {
              args.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Invalid endpoint function return value (header value type).");
              return;
            }
            args.rpc_ctx->set_response_header(prop_name_cstr, prop_val_cstr);
            JS_FreeCString(ctx, prop_val_cstr);
          }
          js_free(ctx, props);
        }
      }

      // Response status code
      {
        int response_status_code = HTTP_STATUS_OK;
        auto status_code_js = ctx(JS_GetPropertyStr(ctx, val, "statusCode"));
        if (!JS_IsUndefined(status_code_js) && !JS_IsNull(status_code_js))
        {
          if (JS_VALUE_GET_TAG(status_code_js.val) != JS_TAG_INT)
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Invalid endpoint function return value (status code type).");
            return;
          }
          response_status_code = JS_VALUE_GET_INT(status_code_js.val);
        }
        args.rpc_ctx->set_response_status(response_status_code);
      }

      return;
    }

    struct JSDynamicEndpoint : public ccf::endpoints::EndpointDefinition
    {};

  public:
    JSHandlers(NetworkTables& network, AbstractNodeContext& context) :
      UserEndpointRegistry(context),
      network(network),
      context(context)
    {
      metrics_tracker.install_endpoint(*this);
    }

    void instantiate_authn_policies(JSDynamicEndpoint& endpoint)
    {
      for (const auto& policy_name : endpoint.properties.authn_policies)
      {
        auto policy = get_policy_by_name(policy_name);
        if (policy == nullptr)
        {
          throw std::logic_error(
            fmt::format("Unknown auth policy: {}", policy_name));
        }
        endpoint.authn_policies.push_back(std::move(policy));
      }
    }

    ccf::endpoints::EndpointDefinitionPtr find_endpoint(
      kv::Tx& tx, enclave::RpcContext& rpc_ctx) override
    {
      const auto method = fmt::format("/{}", rpc_ctx.get_method());
      const auto verb = rpc_ctx.get_request_verb();

      auto endpoints =
        tx.ro<ccf::endpoints::EndpointsMap>(ccf::Tables::ENDPOINTS);

      const auto key = ccf::endpoints::EndpointKey{method, verb};

      // Look for a direct match of the given path
      const auto it = endpoints->get(key);
      if (it.has_value())
      {
        auto endpoint_def = std::make_shared<JSDynamicEndpoint>();
        endpoint_def->dispatch = key;
        endpoint_def->properties = it.value();
        instantiate_authn_policies(*endpoint_def);
        return endpoint_def;
      }

      // If that doesn't exist, look through _all_ the endpoints to find
      // templated matches. If there is one, that's a match. More is an error,
      // none means delegate to the base class.
      {
        std::vector<ccf::endpoints::EndpointDefinitionPtr> matches;

        endpoints->foreach([this, &matches, &key, &rpc_ctx](
                             const auto& other_key, const auto& properties) {
          if (key.verb == other_key.verb)
          {
            const auto opt_spec =
              ccf::endpoints::parse_path_template(other_key.uri_path);
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
                  // Populate the request_path_params while we have the match,
                  // though this will be discarded on error if we later find
                  // multiple matches
                  auto& path_params = rpc_ctx.get_request_path_params();
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

                auto endpoint = std::make_shared<JSDynamicEndpoint>();
                endpoint->dispatch = other_key;
                endpoint->properties = properties;
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

    void execute_endpoint(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::EndpointContext& args) override
    {
      auto endpoint = dynamic_cast<const JSDynamicEndpoint*>(e.get());
      if (endpoint != nullptr)
      {
        execute_request(endpoint->properties, args);
        return;
      }

      ccf::endpoints::EndpointRegistry::execute_endpoint(e, args);
    }

    // Since we do our own dispatch within the default handler, report the
    // supported methods here
    void build_api(nlohmann::json& document, kv::ReadOnlyTx& tx) override
    {
      UserEndpointRegistry::build_api(document, tx);

      auto endpoints =
        tx.ro<ccf::endpoints::EndpointsMap>(ccf::Tables::ENDPOINTS);

      endpoints->foreach([&document](const auto& key, const auto& properties) {
        const auto http_verb = key.verb.get_http_method();
        if (!http_verb.has_value())
        {
          return true;
        }

        if (!properties.openapi_hidden)
        {
          auto& path_op = ds::openapi::path_operation(
            ds::openapi::path(document, key.uri_path),
            http_verb.value(),
            false);
          LOG_INFO_FMT(
            "Building OpenAPI for {} {}", key.verb.c_str(), key.uri_path);
          const auto dumped = document.dump(2);
          LOG_INFO_FMT(
            "Starting from: {}", std::string(dumped.begin(), dumped.end()));
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

    void tick(std::chrono::milliseconds elapsed, size_t tx_count) override
    {
      metrics_tracker.tick(elapsed, tx_count);

      ccf::UserEndpointRegistry::tick(elapsed, tx_count);
    }
  };

#pragma clang diagnostic pop

  class JS : public ccf::RpcFrontend
  {
  private:
    JSHandlers js_handlers;

  public:
    JS(NetworkTables& network, ccfapp::AbstractNodeContext& context) :
      ccf::RpcFrontend(*network.tables, js_handlers),
      js_handlers(network, context)
    {}
  };

  std::shared_ptr<ccf::RpcFrontend> get_rpc_handler(
    NetworkTables& network, ccfapp::AbstractNodeContext& context)
  {
    return make_shared<JS>(network, context);
  }
} // namespace ccfapp
