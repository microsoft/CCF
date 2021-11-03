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
#include "kv/untyped_map.h"
#include "named_auth_policies.h"
#include "v8_runner.h"

#include <memory>
#include <stdexcept>
#include <vector>

using namespace std;
using namespace ccf;
using namespace kv;

namespace ccfapp
{
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

    // static Local<Object> create_json_obj(const nlohmann::json& j, Isolate* iso)
    // {
    //   const auto buf = j.dump();
    //   HandleScope scope(iso);
    //   MaybeLocal<String> result = String::NewFromUtf8(
    //   iso, buf.c_str(), NewStringType::kNormal, static_cast<int>(buf.size()));
    //   // TODO: Parse the JSON first
    //   // In theory, JSON is contained in the ECMAScript standard, and V8 supports
    //   // it, so in theory, parsing a JSON object structure could "just work"?
    //   return result;
    // }

    // Local<Object> create_caller_obj(
    //   ccf::endpoints::EndpointContext& endpoint_ctx, Isolate* iso)
    // {
    //   // No callers, return null
    //   if (endpoint_ctx.caller == nullptr)
    //   {
    //     return Null(iso);
    //   }

    //   // Jwt/Empty identity
    //   auto caller = Object::New(iso);
    //   char const* policy_name = nullptr;
    //   Local<Object> jwt = Null(iso);
    //   if (auto jwt_ident = endpoint_ctx.try_get_caller<ccf::JwtAuthnIdentity>())
    //   {
    //     policy_name = get_policy_name_from_ident(jwt_ident);
    //     /**
    //      * TODO: Create structure using ObjectTemplate
    //      *   jwt {
    //      *     keyIssuer: StringLen(iso, jwt_ident->key_issuer.data(), ...size())
    //      *     header: create_json_obj(jwt_ident->header, iso)
    //      *     payload: create_json_obj(jwt_ident->payload, iso)
    //      *   }
    //      */
    //   }
    //   else if (
    //     auto empty_ident =
    //       endpoint_ctx.try_get_caller<ccf::EmptyAuthnIdentity>())
    //   {
    //     policy_name = get_policy_name_from_ident(empty_ident);
    //     // jwt here is null
    //   }
    //   if (policy_name)
    //   {
    //     /**
    //      * TODO: Create structure using ObjectTemplate
    //      *   caller {
    //      *     policy: policy_name
    //      *     jwt: jwt (if not null)
    //      *   }
    //      */
    //     return caller;
    //   }

    //   // If not, it has to be {User/Member} x {Cert/Signature} identity
    //   string id;
    //   bool is_member = false;
    //   if (
    //     auto user_cert_ident =
    //       endpoint_ctx.try_get_caller<ccf::UserCertAuthnIdentity>())
    //   {
    //     policy_name = get_policy_name_from_ident(user_cert_ident);
    //     id = user_cert_ident->user_id;
    //     is_member = false;
    //   }
    //   else if (
    //     auto member_cert_ident =
    //       endpoint_ctx.try_get_caller<ccf::MemberCertAuthnIdentity>())
    //   {
    //     policy_name = get_policy_name_from_ident(member_cert_ident);
    //     id = member_cert_ident->member_id;
    //     is_member = true;
    //   }
    //   else if (
    //     auto user_sig_ident =
    //       endpoint_ctx.try_get_caller<ccf::UserSignatureAuthnIdentity>())
    //   {
    //     policy_name = get_policy_name_from_ident(user_sig_ident);
    //     id = user_sig_ident->user_id;
    //     is_member = false;
    //   }
    //   else if (
    //     auto member_sig_ident =
    //       endpoint_ctx.try_get_caller<ccf::MemberSignatureAuthnIdentity>())
    //   {
    //     policy_name = get_policy_name_from_ident(member_sig_ident);
    //     id = member_sig_ident->member_id;
    //     is_member = true;
    //   }
    //   if (policy_name == nullptr)
    //   {
    //     throw std::logic_error("Unable to convert caller info to JS object");
    //   }

    //   // Retrieve user/member data from authenticated caller id
    //   nlohmann::json data = nullptr;
    //   ccf::ApiResult result = ccf::ApiResult::OK;
    //   if (is_member)
    //   {
    //     result = get_member_data_v1(endpoint_ctx.tx, id, data);
    //   }
    //   else
    //   {
    //     result = get_user_data_v1(endpoint_ctx.tx, id, data);
    //   }
    //   if (result == ccf::ApiResult::InternalError)
    //   {
    //     throw std::logic_error(
    //       fmt::format("Failed to get data for caller {}", id));
    //   }

    //   // Retrieve the certificate
    //   crypto::Pem cert;
    //   if (is_member)
    //   {
    //     result = get_member_cert_v1(endpoint_ctx.tx, id, cert);
    //   }
    //   else
    //   {
    //     result = get_user_cert_v1(endpoint_ctx.tx, id, cert);
    //   }
    //   if (result == ccf::ApiResult::InternalError)
    //   {
    //     throw std::logic_error(
    //       fmt::format("Failed to get certificate for caller {}", id));
    //   }

    //   /**
    //    * TODO: Create structure using ObjectTemplate
    //    *   caller {
    //    *     policy: policy_name
    //    *     id: StringLen(iso, id.data(), id.size())
    //    *     data: create_json_obj(data, iso)
    //    *     cert: StringLen(iso, cert.str().data(), cert.size())
    //    *   }
    //    */
    //   return caller;
    // }

    // Local<Object> create_request_obj(
    //   ccf::endpoints::EndpointContext& endpoint_ctx, Isolate* iso)
    // {
    //   // Request object
    //   auto request = Object::New(iso);

    //   // Set header list (possibly empty)
    //   auto headers = Object::New(iso);
    //   for (auto& [header_name, header_value] :
    //        endpoint_ctx.rpc_ctx->get_request_headers())
    //   {
    //     // JS_SetPropertyStr(
    //     //   ctx,
    //     //   headers,
    //     //   header_name.c_str(),
    //     //   StringLen(iso, header_value.c_str(), header_value.size()));
    //   }

    //   const auto& request_query = endpoint_ctx.rpc_ctx->get_request_query();
    //   // auto query_str =
    //   //   StringLen(iso, request_query.c_str(), request_query.size());

    //   auto params = Object::New(iso);
    //   for (auto& [param_name, param_value] :
    //        endpoint_ctx.rpc_ctx->get_request_path_params())
    //   {
    //     // JS_SetPropertyStr(
    //     //   ctx,
    //     //   params,
    //     //   param_name.c_str(),
    //     //   StringLen(iso, param_value.c_str(), param_value.size()));
    //   }

    //   const auto& request_body = endpoint_ctx.rpc_ctx->get_request_body();
    //   // auto body = Object::NewClass(iso, js::body_class_id);
    //   // JS_SetOpaque(body, (void*)&request_body);

    //   /**
    //    * TODO: Create structure using ObjectTemplate
    //    *   request {
    //    *     headers: headers
    //    *     query: query_str
    //    *     params: params
    //    *     body: body
    //    *     caller: create_caller_obj(endpoint_ctx, ctx)
    //    *   }
    //    */
    //   return request;
    // }

    /// Unpacks the request, load the JavaScript, executes the code
    void do_execute_request(
      const ccf::endpoints::EndpointProperties& props,
      ccf::endpoints::EndpointContext& endpoint_ctx,
      kv::Tx& target_tx,
      // For historical requests
      const std::optional<ccf::TxID>& transaction_id,
      ccf::TxReceiptPtr receipt)
    {
      // For now, create a new isolate for each request.
      // TODO reuse isolate per-thread
      V8Isolate isolate;

      // Each request is executed in a new context
      V8Context ctx(isolate);

      //ctx.set_module_load_callback();

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

      try
      {
        ctx.run(props.js_module, props.js_function);
      }
      catch (std::exception& exc)
      {
        endpoint_ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          exc.what());
        return;
      }
      

      // // Handle return value: {body, headers, statusCode}
      // if (val->))
      // {
      //   endpoint_ctx.rpc_ctx->set_error(
      //     HTTP_STATUS_INTERNAL_SERVER_ERROR,
      //     ccf::errors::InternalError,
      //     "Invalid endpoint function return value (not an object).");
      //   return;
      // }

      // // Response body (also sets a default response content-type header)
      // {
      //   auto response_body_js = ctx(JS_GetPropertyStr(iso, val, "body"));

      //   if (!JS_IsUndefined(response_body_js))
      //   {
      //     std::vector<uint8_t> response_body;
      //     size_t buf_size;
      //     size_t buf_offset;
      //     JSValue typed_array_buffer = JS_GetTypedArrayBuffer(
      //       ctx, response_body_js, &buf_offset, &buf_size, nullptr);
      //     uint8_t* array_buffer;
      //     if (!JS_IsException(typed_array_buffer))
      //     {
      //       size_t buf_size_total;
      //       array_buffer =
      //         JS_GetArrayBuffer(iso, &buf_size_total, typed_array_buffer);
      //       array_buffer += buf_offset;
      //       JS_FreeValue(iso, typed_array_buffer);
      //     }
      //     else
      //     {
      //       array_buffer = JS_GetArrayBuffer(iso, &buf_size, response_body_js);
      //     }
      //     if (array_buffer)
      //     {
      //       endpoint_ctx.rpc_ctx->set_response_header(
      //         http::headers::CONTENT_TYPE,
      //         http::headervalues::contenttype::OCTET_STREAM);
      //       response_body =
      //         std::vector<uint8_t>(array_buffer, array_buffer + buf_size);
      //     }
      //     else
      //     {
      //       const char* cstr = nullptr;
      //       if (JS_IsString(response_body_js))
      //       {
      //         endpoint_ctx.rpc_ctx->set_response_header(
      //           http::headers::CONTENT_TYPE,
      //           http::headervalues::contenttype::TEXT);
      //         cstr = JS_ToCString(iso, response_body_js);
      //       }
      //       else
      //       {
      //         endpoint_ctx.rpc_ctx->set_response_header(
      //           http::headers::CONTENT_TYPE,
      //           http::headervalues::contenttype::JSON);
      //         JSValue rval =
      //           JS_JSONStringify(iso, response_body_js, V8_NULL, V8_NULL);
      //         if (JS_IsException(rval))
      //         {
      //           js::js_dump_error(ctx);
      //           endpoint_ctx.rpc_ctx->set_error(
      //             HTTP_STATUS_INTERNAL_SERVER_ERROR,
      //             ccf::errors::InternalError,
      //             "Invalid endpoint function return value (error during JSON "
      //             "conversion of body).");
      //           return;
      //         }
      //         cstr = JS_ToCString(iso, rval);
      //         JS_FreeValue(iso, rval);
      //       }
      //       if (!cstr)
      //       {
      //         js::js_dump_error(ctx);
      //         endpoint_ctx.rpc_ctx->set_error(
      //           HTTP_STATUS_INTERNAL_SERVER_ERROR,
      //           ccf::errors::InternalError,
      //           "Invalid endpoint function return value (error during string "
      //           "conversion of body).");
      //         return;
      //       }
      //       std::string str(cstr);
      //       JS_FreeCString(iso, cstr);

      //       response_body = std::vector<uint8_t>(str.begin(), str.end());
      //     }
      //     endpoint_ctx.rpc_ctx->set_response_body(std::move(response_body));
      //   }
      // }
      // // Response headers
      // {
      //   auto response_headers_js = ctx(JS_GetPropertyStr(iso, val, "headers"));
      //   if (JS_IsObject(response_headers_js))
      //   {
      //     uint32_t prop_count = 0;
      //     JSPropertyEnum* props = nullptr;
      //     JS_GetOwnPropertyNames(
      //       ctx,
      //       &props,
      //       &prop_count,
      //       response_headers_js,
      //       JS_GPN_STRING_MASK | V8_GPN_ENUM_ONLY);
      //     for (size_t i = 0; i < prop_count; i++)
      //     {
      //       auto prop_name = props[i].atom;
      //       auto prop_name_cstr = ctx(JS_AtomToCString(iso, prop_name));
      //       auto prop_val =
      //         ctx(JS_GetProperty(iso, response_headers_js, prop_name));
      //       auto prop_val_cstr = JS_ToCString(iso, prop_val);
      //       if (!prop_val_cstr)
      //       {
      //         endpoint_ctx.rpc_ctx->set_error(
      //           HTTP_STATUS_INTERNAL_SERVER_ERROR,
      //           ccf::errors::InternalError,
      //           "Invalid endpoint function return value (header value type).");
      //         return;
      //       }
      //       endpoint_ctx.rpc_ctx->set_response_header(
      //         prop_name_cstr, prop_val_cstr);
      //       JS_FreeCString(iso, prop_val_cstr);
      //     }
      //     js_free(ctx, props);
      //   }
      // }

      // // Response status code
      // {
      //   int response_status_code = HTTP_STATUS_OK;
      //   auto status_code_js = ctx(JS_GetPropertyStr(iso, val, "statusCode"));
      //   if (!JS_IsUndefined(status_code_js) && !V8_IsNull(status_code_js))
      //   {
      //     if (JS_VALUE_GET_TAG(status_code_js.val) != V8_TAG_INT)
      //     {
      //       endpoint_ctx.rpc_ctx->set_error(
      //         HTTP_STATUS_INTERNAL_SERVER_ERROR,
      //         ccf::errors::InternalError,
      //         "Invalid endpoint function return value (status code type).");
      //       return;
      //     }
      //     response_status_code = JS_VALUE_GET_INT(status_code_js.val);
      //   }
      //   endpoint_ctx.rpc_ctx->set_response_status(response_status_code);
      // }

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
    // TODO move this elsewhere and also call shutdown()
    v8_initialize();

    return make_shared<V8Frontend>(network, context);
  }

} // namespace ccfapp
