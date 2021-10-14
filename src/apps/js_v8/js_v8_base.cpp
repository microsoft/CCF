// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "apps/utils/metrics_tracker.h"
#include "ccf/app_interface.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/user_frontend.h"
#include "ccf/version.h"
#include "crypto/entropy.h"
#include "crypto/key_wrap.h"
#include "crypto/rsa_key_pair.h"
#include "libplatform/libplatform.h"
#include "kv/untyped_map.h"
#include "named_auth_policies.h"
#include "v8httpproc.h"

#include <memory>
#include <stdexcept>
#include <vector>

namespace ccfapp
{
  using namespace std;
  using namespace kv;
  using namespace ccf;
  using namespace v8;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  /**
   * V8 Handlers, holds the list of handlers from a JavaScript source to be
   * called via RPC (through RPCFrontend).
   */
  class V8Handlers : public UserEndpointRegistry
  {

    /**
     * V8 Endpoint definition
     */
    struct V8DynamicEndpoint : public ccf::endpoints::EndpointDefinition
    {};

    NetworkTables& network;
    ccfapp::AbstractNodeContext& context;
    ::metrics::Tracker metrics_tracker;

    static Persistent<Object> create_json_obj(const nlohmann::json& j, Isolate* iso)
    {
      const auto buf = j.dump();
      HandleScope scope(iso);
      MaybeLocal<String> result = String::NewFromUtf8(
      iso, buf.c_str(), NewStringType::kNormal, static_cast<int>(buf.size()));
    }

    JSValue create_caller_obj(
      ccf::endpoints::EndpointContext& endpoint_ctx, Isolate* iso)
    {
      if (endpoint_ctx.caller == nullptr)
      {
        return Null(iso);
      }

      auto caller = Object::New(iso);

      if (auto jwt_ident = endpoint_ctx.try_get_caller<ccf::JwtAuthnIdentity>())
      {
        V8_SetPropertyStr(
          iso,
          caller,
          "policy",
          String(iso, get_policy_name_from_ident(jwt_ident)));

        auto jwt = Object::New(iso);
        V8_SetPropertyStr(
          iso,
          jwt,
          "keyIssuer",
          StringLen(
            iso, jwt_ident->key_issuer.data(), jwt_ident->key_issuer.size()));
        V8_SetPropertyStr(
          iso, jwt, "header", create_json_obj(jwt_ident->header, iso));
        V8_SetPropertyStr(
          iso, jwt, "payload", create_json_obj(jwt_ident->payload, iso));
        V8_SetPropertyStr(iso, caller, "jwt", jwt);

        return caller;
      }
      else if (
        auto empty_ident =
          endpoint_ctx.try_get_caller<ccf::EmptyAuthnIdentity>())
      {
        V8_SetPropertyStr(
          iso,
          caller,
          "policy",
          String(iso, get_policy_name_from_ident(empty_ident)));
        return caller;
      }

      char const* policy_name = nullptr;
      std::string id;
      bool is_member = false;

      if (
        auto user_cert_ident =
          endpoint_ctx.try_get_caller<ccf::UserCertAuthnIdentity>())
      {
        policy_name = get_policy_name_from_ident(user_cert_ident);
        id = user_cert_ident->user_id;
        is_member = false;
      }
      else if (
        auto member_cert_ident =
          endpoint_ctx.try_get_caller<ccf::MemberCertAuthnIdentity>())
      {
        policy_name = get_policy_name_from_ident(member_cert_ident);
        id = member_cert_ident->member_id;
        is_member = true;
      }
      else if (
        auto user_sig_ident =
          endpoint_ctx.try_get_caller<ccf::UserSignatureAuthnIdentity>())
      {
        policy_name = get_policy_name_from_ident(user_sig_ident);
        id = user_sig_ident->user_id;
        is_member = false;
      }
      else if (
        auto member_sig_ident =
          endpoint_ctx.try_get_caller<ccf::MemberSignatureAuthnIdentity>())
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

      V8_SetPropertyStr(iso, caller, "policy", String(iso, policy_name));
      V8_SetPropertyStr(
        iso, caller, "id", StringLen(iso, id.data(), id.size()));
      V8_SetPropertyStr(iso, caller, "data", create_json_obj(data, iso));
      V8_SetPropertyStr(
        iso,
        caller,
        "cert",
        StringLen(iso, cert.str().data(), cert.size()));

      return caller;
    }

    JSValue create_request_obj(
      ccf::endpoints::EndpointContext& endpoint_ctx, Isolate* iso)
    {
      auto request = Object::New(ctx);

      auto headers = Object::New(ctx);
      for (auto& [header_name, header_value] :
           endpoint_ctx.rpc_ctx->get_request_headers())
      {
        V8_SetPropertyStr(
          ctx,
          headers,
          header_name.c_str(),
          StringLen(ctx, header_value.c_str(), header_value.size()));
      }
      V8_SetPropertyStr(ctx, request, "headers", headers);

      const auto& request_query = endpoint_ctx.rpc_ctx->get_request_query();
      auto query_str =
        StringLen(ctx, request_query.c_str(), request_query.size());
      V8_SetPropertyStr(ctx, request, "query", query_str);

      auto params = Object::New(ctx);
      for (auto& [param_name, param_value] :
           endpoint_ctx.rpc_ctx->get_request_path_params())
      {
        V8_SetPropertyStr(
          ctx,
          params,
          param_name.c_str(),
          StringLen(ctx, param_value.c_str(), param_value.size()));
      }
      V8_SetPropertyStr(ctx, request, "params", params);

      const auto& request_body = endpoint_ctx.rpc_ctx->get_request_body();
      auto body_ = Object::NewClass(ctx, js::body_class_id);
      V8_SetOpaque(body_, (void*)&request_body);
      V8_SetPropertyStr(ctx, request, "body", body_);

      V8_SetPropertyStr(
        ctx, request, "caller", create_caller_obj(endpoint_ctx, ctx));

      return request;
    }

    /// Unpacks the request, load the JavaScript, executes the code
    void do_execute_request(
      const ccf::endpoints::EndpointProperties& props,
      ccf::endpoints::EndpointContext& endpoint_ctx,
      kv::Tx& target_tx,
      // For historical requests
      const std::optional<ccf::TxID>& transaction_id,
      ccf::historical::TxReceiptPtr receipt)
    {
      // Creates an "isolate", which is like a browser tab or a sandbox.
      // We create one per request, which is wasteful if we get the same request multiple times.
      // TODO: Use a cache for existing requests / code.
      // TODO: Compile code to Wasm/obj and cache those!
      Isolate::CreateParams create_params;
      create_params.array_buffer_allocator = ArrayBuffer::Allocator::NewDefaultAllocator();
      Isolate* isolate = Isolate::New(create_params);
      Isolate::Scope scope(isolate);

      // TODO: Populate the global context
      // js::TxContext txctx{&target_tx, js::TxAccess::APP};
      // js::register_request_body_class(ctx);
      // js::populate_global(
      //   &txctx,
      //   endpoint_ctx.rpc_ctx.get(),
      //   transaction_id,
      //   receipt,
      //   nullptr,
      //   &context.get_node_state(),
      //   nullptr,
      //   ctx);

      // Parse the source
      Local<String> source = props.js_module;
      Local<String> function_name = props.js_function;
      
      // TODO: Add process.cc as a header/impl
      /// Processor options (like --jitless?)
      // map<string, string> options;
      // JsHttpRequestProcessor processor(isolate, source);
      // map<string, string> output;
      // if (!processor.Initialize(&options, &output)) {
      //   fprintf(stderr, "Error initializing processor.\n");
      //   return 1;
      // }
      // if (!ProcessEntries(isolate, platform.get(), &processor, kSampleSize,
      //                     kSampleRequests)) {
      //   return 1;
      // }

      // The actual function object
      // Local<Object> = ...;
      JSValue export_func;
      try
      {
        auto module_val =
          js::load_app_module(ctx, props.js_module.c_str(), &endpoint_ctx.tx);
        export_func =
          ctx.function(module_val, props.js_function, props.js_module);
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
      auto request = create_request_obj(endpoint_ctx, ctx);
      int argc = 1;
      JSValueConst* argv = (JSValueConst*)&request;
      auto val = ctx(V8_Call(ctx, export_func, V8_UNDEFINED, argc, argv));
      V8_FreeValue(ctx, request);
      V8_FreeValue(ctx, export_func);

      if (V8_IsException(val))
      {
        js::js_dump_error(ctx);
        endpoint_ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Exception thrown while executing.");
        return;
      }

      // Handle return value: {body, headers, statusCode}
      if (!V8_IsObject(val))
      {
        endpoint_ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Invalid endpoint function return value (not an object).");
        return;
      }

      // Response body (also sets a default response content-type header)
      {
        auto response_body_js = ctx(V8_GetPropertyStr(ctx, val, "body"));

        if (!V8_IsUndefined(response_body_js))
        {
          std::vector<uint8_t> response_body;
          size_t buf_size;
          size_t buf_offset;
          JSValue typed_array_buffer = V8_GetTypedArrayBuffer(
            ctx, response_body_js, &buf_offset, &buf_size, nullptr);
          uint8_t* array_buffer;
          if (!V8_IsException(typed_array_buffer))
          {
            size_t buf_size_total;
            array_buffer =
              V8_GetArrayBuffer(ctx, &buf_size_total, typed_array_buffer);
            array_buffer += buf_offset;
            V8_FreeValue(ctx, typed_array_buffer);
          }
          else
          {
            array_buffer = V8_GetArrayBuffer(ctx, &buf_size, response_body_js);
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
            const char* cstr = nullptr;
            if (V8_IsString(response_body_js))
            {
              endpoint_ctx.rpc_ctx->set_response_header(
                http::headers::CONTENT_TYPE,
                http::headervalues::contenttype::TEXT);
              cstr = V8_ToCString(ctx, response_body_js);
            }
            else
            {
              endpoint_ctx.rpc_ctx->set_response_header(
                http::headers::CONTENT_TYPE,
                http::headervalues::contenttype::JSON);
              JSValue rval =
                V8_JSONStringify(ctx, response_body_js, V8_NULL, V8_NULL);
              if (V8_IsException(rval))
              {
                js::js_dump_error(ctx);
                endpoint_ctx.rpc_ctx->set_error(
                  HTTP_STATUS_INTERNAL_SERVER_ERROR,
                  ccf::errors::InternalError,
                  "Invalid endpoint function return value (error during JSON "
                  "conversion of body).");
                return;
              }
              cstr = V8_ToCString(ctx, rval);
              V8_FreeValue(ctx, rval);
            }
            if (!cstr)
            {
              js::js_dump_error(ctx);
              endpoint_ctx.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Invalid endpoint function return value (error during string "
                "conversion of body).");
              return;
            }
            std::string str(cstr);
            V8_FreeCString(ctx, cstr);

            response_body = std::vector<uint8_t>(str.begin(), str.end());
          }
          endpoint_ctx.rpc_ctx->set_response_body(std::move(response_body));
        }
      }
      // Response headers
      {
        auto response_headers_js = ctx(V8_GetPropertyStr(ctx, val, "headers"));
        if (V8_IsObject(response_headers_js))
        {
          uint32_t prop_count = 0;
          JSPropertyEnum* props = nullptr;
          V8_GetOwnPropertyNames(
            ctx,
            &props,
            &prop_count,
            response_headers_js,
            V8_GPN_STRING_MASK | V8_GPN_ENUM_ONLY);
          for (size_t i = 0; i < prop_count; i++)
          {
            auto prop_name = props[i].atom;
            auto prop_name_cstr = ctx(V8_AtomToCString(ctx, prop_name));
            auto prop_val =
              ctx(V8_GetProperty(ctx, response_headers_js, prop_name));
            auto prop_val_cstr = V8_ToCString(ctx, prop_val);
            if (!prop_val_cstr)
            {
              endpoint_ctx.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Invalid endpoint function return value (header value type).");
              return;
            }
            endpoint_ctx.rpc_ctx->set_response_header(
              prop_name_cstr, prop_val_cstr);
            V8_FreeCString(ctx, prop_val_cstr);
          }
          js_free(ctx, props);
        }
      }

      // Response status code
      {
        int response_status_code = HTTP_STATUS_OK;
        auto status_code_js = ctx(V8_GetPropertyStr(ctx, val, "statusCode"));
        if (!V8_IsUndefined(status_code_js) && !V8_IsNull(status_code_js))
        {
          if (V8_VALUE_GET_TAG(status_code_js.val) != V8_TAG_INT)
          {
            endpoint_ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Invalid endpoint function return value (status code type).");
            return;
          }
          response_status_code = V8_VALUE_GET_INT(status_code_js.val);
        }
        endpoint_ctx.rpc_ctx->set_response_status(response_status_code);
      }

      return;
    }

    /// Execute request
    void execute_request(
      const ccf::endpoints::EndpointProperties& props,
      ccf::endpoints::EndpointContext& endpoint_ctx)
    {
      if (props.mode == ccf::endpoints::Mode::Historical)
      {
        // Historical mode need a v2 adapter (why?)
        auto is_tx_committed =
          [this](ccf::View view, ccf::SeqNo seqno, std::string& error_reason) {
            return ccf::historical::is_tx_committed_v2(
              consensus, view, seqno, error_reason);
          };

        ccf::historical::adapter_v2(
          [this, &props](
            ccf::endpoints::EndpointContext& endpoint_ctx,
            ccf::historical::StatePtr state) {
            auto tx = state->store->create_tx();
            auto tx_id = state->transaction_id;
            auto receipt = state->receipt;
            assert(receipt);
            do_execute_request(props, endpoint_ctx, tx, tx_id, receipt);
          },
          context.get_historical_state(),
          is_tx_committed)(endpoint_ctx);
      }
      else
      {
        // Read/Write mode just execute directly
        do_execute_request(
          props, endpoint_ctx, endpoint_ctx.tx, std::nullopt, nullptr);
      }
    }

    /// Instantiate all auth policies from the endpoint
    void instantiate_authn_policies(V8DynamicEndpoint& endpoint)
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

    // Creates a new endpoint match from key/value pairs.
    ccf::endpoints::EndpointDefinitionPtr new_endpoint_match(
        const ccf::endpoints::EndpointKey& key,
        const ccf::endpoints::EndpointProperties& value)
    {
      auto endpoint = std::make_shared<V8DynamicEndpoint>();
      endpoint->dispatch = key;
      endpoint->properties = value;
      instantiate_authn_policies(*endpoint);
      return endpoint;
    }

  public:
    V8Handlers(NetworkTables& network, AbstractNodeContext& context) :
      UserEndpointRegistry(context),
      network(network),
      context(context)
    {
      metrics_tracker.install_endpoint(*this);
      // Initialize V8 target
      V8::InitializeICUDefaultLocation("v8handler");
      V8::InitializeExternalStartupData("v8handler");
      std::unique_ptr<Platform> platform = v8::platform::NewDefaultPlatform();
      V8::InitializePlatform(platform.get());
      V8::Initialize();
    }

    /// Find an endpoint with the parameters in `tx`
    ccf::endpoints::EndpointDefinitionPtr find_endpoint(
      kv::Tx& tx, enclave::RpcContext& rpc_ctx) override
    {
      // Read-only map handle to all endpoints
      auto endpoints =
        tx.ro<ccf::endpoints::EndpointsMap>(ccf::Tables::ENDPOINTS);

      // Prepare the endpoint key
      const auto method = rpc_ctx.get_method();
      const auto verb = rpc_ctx.get_request_verb();
      const auto key = ccf::endpoints::EndpointKey{method, verb};

      // Look for a direct match of the given path
      const auto it = endpoints->get(key);
      if (it.has_value())
      {
        // Direct matches just return the endpoint
        return new_endpoint_match(key, it.value());
      }

      // If that doesn't exist, look through _all_ the endpoints to find
      // templated matches.
      std::vector<ccf::endpoints::EndpointDefinitionPtr> matches;

      endpoints->foreach_key(
        [this, &endpoints, &matches, &key, &rpc_ctx](const auto& other_key) {
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

                auto endpoint = new_endpoint_match(other_key, endpoints->get(other_key).value());
                matches.push_back(endpoint);
              }
            }
          }
          return true;
        });

      // If there is one, that's a match.
      if (matches.size() == 1)
      {
        return matches[0];
      }
      // More is an error,
      else if (matches.size() > 1)
      {
        report_ambiguous_templated_path(key.uri_path, matches);
      }

      // none means delegate to the base class.
      return ccf::endpoints::EndpointRegistry::find_endpoint(tx, rpc_ctx);
    }

    /// Execute a V8 endpoint.
    void execute_endpoint(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::EndpointContext& endpoint_ctx) override
    {
      // If this is a V8 endpoint, execute.
      auto endpoint = dynamic_cast<const V8DynamicEndpoint*>(e.get());
      if (endpoint != nullptr)
      {
        execute_request(endpoint->properties, endpoint_ctx);
        return;
      }

      // Otherwise, delegate to the base class.
      ccf::endpoints::EndpointRegistry::execute_endpoint(e, endpoint_ctx);
    }

    /// Override `build_api` to show supported local methods.
    void build_api(nlohmann::json& document, kv::ReadOnlyTx& tx) override
    {
      UserEndpointRegistry::build_api(document, tx);

      auto endpoints =
        tx.ro<ccf::endpoints::EndpointsMap>(ccf::Tables::ENDPOINTS);

      // Since we do our own dispatch within the default handler, report the
      // supported methods here
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

    /// Override `tick` to include `metrics_tracker` ticks.
    void tick(std::chrono::milliseconds elapsed, size_t tx_count) override
    {
      metrics_tracker.tick(elapsed, tx_count);
      ccf::UserEndpointRegistry::tick(elapsed, tx_count);
    }
  };

#pragma clang diagnostic pop

  /**
   * V8 Frontend for RPC calls
   */
  class V8Frontend : public ccf::RpcFrontend
  {
  private:
    V8Handlers handlers;

  public:
    V8Frontend(NetworkTables& network, ccfapp::AbstractNodeContext& context) :
      ccf::RpcFrontend(*network.tables, handlers),
      handlers(network, context)
    {}
  };

  /// Returns a new V8 Rpc Frontend
  std::shared_ptr<ccf::RpcFrontend> get_rpc_handler_impl(
    NetworkTables& network, ccfapp::AbstractNodeContext& context)
  {
    return make_shared<V8Frontend>(network, context);
  }
} // namespace ccfapp
