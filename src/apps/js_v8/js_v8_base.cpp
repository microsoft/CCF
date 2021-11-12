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
#include "v8_runner.h"
#include "v8_util.h"
#include "kv_module_loader.h"
#include "tmpl/request.h"
#include "named_auth_policies.h"

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

      // set a callback that loads modules from the KV
      ctx.set_module_load_callback(ccf::v8_kv_module_load_callback, &endpoint_ctx.tx);

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

      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = ctx.get_context();
      v8::TryCatch try_catch(isolate);

      // Call exported function
      v8::Local<v8::Value> request = ccf::v8_tmpl::Request::wrap(context, endpoint_ctx, *this);
      std::vector<v8::Local<v8::Value>> args {request};
      v8::Local<v8::Value> val = ctx.run(props.js_module, props.js_function, args);
      
      if (val.IsEmpty())
      {
        v8_util::ReportException(isolate, &try_catch);
        auto exception_str = v8_util::get_exception_message(isolate, &try_catch);

        endpoint_ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          std::move(exception_str));
        return;
      }
      
      // Handle return value: {body, headers, statusCode}
      if (!val->IsObject())
      {
        endpoint_ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Invalid endpoint function return value (not an object).");
        return;
      }

      // Response body (also sets a default response content-type header)
      v8::Local<v8::Object> obj = val.As<v8::Object>();
      v8::Local<v8::Value> response_body_js;
      if (!obj->Get(context, v8_util::to_v8_str(isolate, "body")).ToLocal(&response_body_js))
      {
        v8_util::ReportException(isolate, &try_catch);
        endpoint_ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Invalid endpoint function return value (cannot access body).");
        return;
      }
      if (!response_body_js->IsUndefined())
      {
        std::vector<uint8_t> response_body;
        size_t buf_size;
        size_t buf_offset;
        v8::Local<v8::ArrayBuffer> array_buffer;
        if (response_body_js->IsArrayBufferView())
        {
          auto view = response_body_js.As<v8::ArrayBufferView>();
          buf_offset = view->ByteOffset();
          buf_size = view->ByteLength();
          array_buffer = view->Buffer();
        }
        else if (response_body_js->IsArrayBuffer())
        {
          array_buffer = response_body_js.As<v8::ArrayBuffer>();
          buf_offset = 0;
          buf_size = array_buffer->ByteLength();
        }
        if (!array_buffer.IsEmpty())
        {
          uint8_t* buf = (uint8_t*)array_buffer->GetBackingStore()->Data();
          buf += buf_offset;
          endpoint_ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE,
            http::headervalues::contenttype::OCTET_STREAM);
          response_body =
            std::vector<uint8_t>(buf, buf + buf_size);
        }
        else
        {
          std::string str;
          if (response_body_js->IsString())
          {
            endpoint_ctx.rpc_ctx->set_response_header(
              http::headers::CONTENT_TYPE,
              http::headervalues::contenttype::TEXT);
            v8::Local<v8::String> str_val = response_body_js.As<v8::String>();
            str = v8_util::ToSTLString(isolate, str_val);
          }
          else
          {
            endpoint_ctx.rpc_ctx->set_response_header(
                http::headers::CONTENT_TYPE,
                http::headervalues::contenttype::JSON);
            v8::Local<v8::String> json;
            if (!v8::JSON::Stringify(context, response_body_js).ToLocal(&json))
            {
              v8_util::ReportException(isolate, &try_catch);
              endpoint_ctx.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Invalid endpoint function return value (error during JSON "
                "conversion of body).");
              return;
            }
            str = v8_util::ToSTLString(isolate, json);
          }
          response_body = std::vector<uint8_t>(str.begin(), str.end());
        }
        endpoint_ctx.rpc_ctx->set_response_body(std::move(response_body));
      }
     
      // Response headers
      v8::Local<v8::Value> response_headers_js;
      if (!obj->Get(context, v8_util::to_v8_str(isolate, "headers")).ToLocal(&response_headers_js))
      {
        v8_util::ReportException(isolate, &try_catch);
        endpoint_ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Invalid endpoint function return value (cannot access headers).");
        return;
      }
      if (!response_headers_js->IsNullOrUndefined())
      {
        if (!response_headers_js->IsObject())
        {
          endpoint_ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Invalid endpoint function return value (headers is not an object).");
          return;
        }
        v8::Local<v8::Object> headers_obj = response_headers_js.As<v8::Object>();
        v8::Local<v8::Array> headers_arr = headers_obj->GetOwnPropertyNames(context).ToLocalChecked();
        for (uint32_t i = 0; i < headers_arr->Length(); i++)
        {
          v8::Local<v8::Value> key = headers_arr->Get(context, i).ToLocalChecked();
          v8::Local<v8::Value> val = headers_obj->Get(context, key).ToLocalChecked();
          if (!key->IsString() || !val->IsString())
          {
            endpoint_ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Invalid endpoint function return value (header key/value type).");
            return;
          }
          std::string key_str = v8_util::ToSTLString(isolate, key.As<v8::String>());
          std::string val_str = v8_util::ToSTLString(isolate, val.As<v8::String>());
          endpoint_ctx.rpc_ctx->set_response_header(key_str, val_str);
        }
      }

      // Response status code
      int response_status_code = HTTP_STATUS_OK;
      v8::Local<v8::Value> status_code_js;
      if (!obj->Get(context, v8_util::to_v8_str(isolate, "statusCode")).ToLocal(&status_code_js))
      {
        v8_util::ReportException(isolate, &try_catch);
        endpoint_ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Invalid endpoint function return value (cannot access statusCode).");
        return;
      }
      if (!status_code_js->IsNullOrUndefined())
      {
        v8::Local<v8::Uint32> status_code;
        if (!status_code_js->IsNumber() || !status_code_js->ToUint32(context).ToLocal(&status_code))
        {
          if (try_catch.HasCaught())
            v8_util::ReportException(isolate, &try_catch);
          endpoint_ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Invalid endpoint function return value (status code type).");
          return;
        }
        response_status_code = status_code->Value();
      }
      endpoint_ctx.rpc_ctx->set_response_status(response_status_code);
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
