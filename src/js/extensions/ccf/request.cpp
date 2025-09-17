// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/ccf/request.h"

#include "ccf/crypto/verifier.h"
#include "ccf/endpoints/authentication/all_of_auth.h"
#include "ccf/endpoints/authentication/cert_auth.h"
#include "ccf/endpoints/authentication/cose_auth.h"
#include "ccf/endpoints/authentication/empty_auth.h"
#include "ccf/endpoints/authentication/js.h"
#include "ccf/endpoints/authentication/jwt_auth.h"
#include "ccf/js/core/context.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    JSValue js_body_text(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      if (argc != 0)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected none", argc);
      }

      ccf::js::core::Context& jsctx =
        *reinterpret_cast<ccf::js::core::Context*>(JS_GetContextOpaque(ctx));

      auto* extension = jsctx.get_extension<RequestExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* rpc_ctx = extension->rpc_ctx;
      if (rpc_ctx == nullptr)
      {
        return JS_ThrowInternalError(ctx, "RPC context is not set");
      }

      auto body = rpc_ctx->get_request_body();

      return JS_NewStringLen(
        ctx, reinterpret_cast<const char*>(body.data()), body.size());
    }

    JSValue js_body_json(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      if (argc != 0)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected none", argc);
      }

      ccf::js::core::Context& jsctx =
        *reinterpret_cast<ccf::js::core::Context*>(JS_GetContextOpaque(ctx));

      auto* extension = jsctx.get_extension<RequestExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* rpc_ctx = extension->rpc_ctx;
      if (rpc_ctx == nullptr)
      {
        return JS_ThrowInternalError(ctx, "RPC context is not set");
      }

      auto body = rpc_ctx->get_request_body();

      std::string body_str(body.begin(), body.end());
      return JS_ParseJSON(ctx, body_str.c_str(), body.size(), "<body>");
    }

    JSValue js_body_array_buffer(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      if (argc != 0)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected none", argc);
      }

      ccf::js::core::Context& jsctx =
        *reinterpret_cast<ccf::js::core::Context*>(JS_GetContextOpaque(ctx));

      const auto* extension = jsctx.get_extension<RequestExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* rpc_ctx = extension->rpc_ctx;
      if (rpc_ctx == nullptr)
      {
        return JS_ThrowInternalError(ctx, "RPC context is not set");
      }

      auto body = rpc_ctx->get_request_body();
      return JS_NewArrayBufferCopy(ctx, body.data(), body.size());
    }

    ccf::js::core::JSWrappedValue create_caller_ident_obj(
      ccf::js::core::Context& ctx,
      ccf::endpoints::EndpointContext& endpoint_ctx,
      const std::unique_ptr<ccf::AuthnIdentity>& ident,
      ccf::BaseEndpointRegistry* registry)
    {
      if (ident == nullptr)
      {
        return ctx.null();
      }

      auto caller = ctx.new_obj();

      if (
        const auto* jwt_ident =
          dynamic_cast<const ccf::JwtAuthnIdentity*>(ident.get()))
      {
        caller.set(
          "policy", ctx.new_string(ccf::get_policy_name_from_ident(jwt_ident)));

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
        const auto* empty_ident =
          dynamic_cast<const ccf::EmptyAuthnIdentity*>(ident.get()))
      {
        caller.set(
          "policy",
          ctx.new_string(ccf::get_policy_name_from_ident(empty_ident)));
        return caller;
      }
      if (
        const auto* all_of_ident =
          dynamic_cast<const ccf::AllOfAuthnIdentity*>(ident.get()))
      {
        auto policy = ctx.new_array();
        uint32_t i = 0;
        for (const auto& [name, sub_ident] : all_of_ident->identities)
        {
          policy.set_at_index(i++, ctx.new_string(name));
          caller.set(
            name,
            create_caller_ident_obj(ctx, endpoint_ctx, sub_ident, registry));
        }
        caller.set("policy", std::move(policy));
        return caller;
      }

      // For any cert, instead of an id-based lookup for the PEM cert and
      // potential associated data, we directly retrieve the cert bytes as
      // DER from the identity object, as provided by the session, and
      // convert them to PEM.
      if (
        const auto* any_cert_ident =
          dynamic_cast<const ccf::AnyCertAuthnIdentity*>(ident.get()))
      {
        const auto* policy_name =
          ccf::get_policy_name_from_ident(any_cert_ident);
        caller.set("policy", ctx.new_string(policy_name));
        auto pem_cert = ccf::crypto::cert_der_to_pem(any_cert_ident->cert);
        caller.set("cert", ctx.new_string(pem_cert.str()));
        return caller;
      }

      char const* policy_name = nullptr;
      std::string id;
      bool is_member = false;

      if (
        const auto* user_cert_ident =
          dynamic_cast<const ccf::UserCertAuthnIdentity*>(ident.get()))
      {
        policy_name = ccf::get_policy_name_from_ident(user_cert_ident);
        id = user_cert_ident->user_id;
        is_member = false;
      }
      else if (
        const auto* member_cert_ident =
          dynamic_cast<const ccf::MemberCertAuthnIdentity*>(ident.get()))
      {
        policy_name = ccf::get_policy_name_from_ident(member_cert_ident);
        id = member_cert_ident->member_id;
        is_member = true;
      }
      else if (
        const auto* user_cose_ident =
          dynamic_cast<const ccf::UserCOSESign1AuthnIdentity*>(ident.get()))
      {
        policy_name = ccf::get_policy_name_from_ident(user_cose_ident);
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
        result = registry->get_member_data_v1(endpoint_ctx.tx, id, data);
      }
      else
      {
        result = registry->get_user_data_v1(endpoint_ctx.tx, id, data);
      }

      if (result == ccf::ApiResult::InternalError)
      {
        throw std::logic_error(
          fmt::format("Failed to get data for caller {}", id));
      }

      ccf::crypto::Pem cert;
      if (is_member)
      {
        result = registry->get_member_cert_v1(endpoint_ctx.tx, id, cert);
      }
      else
      {
        result = registry->get_user_cert_v1(endpoint_ctx.tx, id, cert);
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

    ccf::js::core::JSWrappedValue create_caller_obj(
      ccf::js::core::Context& ctx,
      ccf::endpoints::EndpointContext& endpoint_ctx,
      ccf::BaseEndpointRegistry* registry)
    {
      return create_caller_ident_obj(
        ctx, endpoint_ctx, endpoint_ctx.caller, registry);
    }
  }

  void RequestExtension::install(ccf::js::core::Context& ctx)
  {
    // Nothing to do - does not modify the global object.
  }

  ccf::js::core::JSWrappedValue RequestExtension::create_request_obj(
    ccf::js::core::Context& ctx,
    std::string_view full_request_path,
    ccf::endpoints::EndpointContext& endpoint_ctx,
    ccf::BaseEndpointRegistry* registry)
  {
    auto request = ctx.new_obj();

    const auto& r_headers = endpoint_ctx.rpc_ctx->get_request_headers();
    auto headers = ctx.new_obj();
    for (const auto& [header_name, header_value] : r_headers)
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

    auto route_str = ctx.new_string(full_request_path);
    request.set("route", std::move(route_str));

    auto request_url = request_path;
    if (!request_query.empty())
    {
      request_url = fmt::format("{}?{}", request_url, request_query);
    }
    auto url_str = ctx.new_string(request_url);
    request.set("url", std::move(url_str));

    auto params = ctx.new_obj();
    for (const auto& [param_name, param_value] :
         endpoint_ctx.rpc_ctx->get_request_path_params())
    {
      params.set(param_name, ctx.new_string(param_value));
    }
    request.set("params", std::move(params));

    auto body = ctx.new_obj();
    body.set("text", ctx.new_c_function(js_body_text, "text", 0));
    body.set("json", ctx.new_c_function(js_body_json, "json", 0));
    body.set(
      "arrayBuffer",
      ctx.new_c_function(js_body_array_buffer, "arrayBuffer", 0));
    request.set("body", std::move(body));

    request.set("caller", create_caller_obj(ctx, endpoint_ctx, registry));

    return request;
  }
}
