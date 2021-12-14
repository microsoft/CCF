// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "request.h"

#include "request_authn_identity.h"
#include "request_body.h"
#include "string_map.h"
#include "template.h"

using ccf::BaseEndpointRegistry;
using ccf::endpoints::EndpointContext;

namespace ccf::v8_tmpl
{
  enum class InternalField
  {
    EndpointContext,
    EndpointRegistry,
    END
  };

  static EndpointContext* unwrap_endpoint_ctx(v8::Local<v8::Object> obj)
  {
    return static_cast<EndpointContext*>(
      get_internal_field(obj, InternalField::EndpointContext));
  }

  static BaseEndpointRegistry* unwrap_endpoint_registry(
    v8::Local<v8::Object> obj)
  {
    return static_cast<BaseEndpointRegistry*>(
      get_internal_field(obj, InternalField::EndpointRegistry));
  }

  static void get_headers(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> headers =
      StringMap::wrap(context, &endpoint_ctx->rpc_ctx->get_request_headers());
    info.GetReturnValue().Set(headers);
  }

  static void get_query(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();

    v8::Local<v8::Value> query =
      v8_util::to_v8_str(isolate, endpoint_ctx->rpc_ctx->get_request_query());
    info.GetReturnValue().Set(query);
  }

  static void get_params(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> headers = StringMap::wrap(
      context, &endpoint_ctx->rpc_ctx->get_request_path_params());
    info.GetReturnValue().Set(headers);
  }

  static void get_body(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> body =
      RequestBody::wrap(context, &endpoint_ctx->rpc_ctx->get_request_body());
    info.GetReturnValue().Set(body);
  }

  static void get_caller(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    BaseEndpointRegistry* endpoint_registry =
      unwrap_endpoint_registry(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> body =
      RequestAuthnIdentity::wrap(context, endpoint_ctx, endpoint_registry);
    info.GetReturnValue().Set(body);
  }

  v8::Local<v8::ObjectTemplate> Request::create_template(v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalField>(tmpl);

    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "headers"), get_headers);
    tmpl->SetLazyDataProperty(v8_util::to_v8_istr(isolate, "query"), get_query);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "params"), get_params);
    tmpl->SetLazyDataProperty(v8_util::to_v8_istr(isolate, "body"), get_body);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "caller"), get_caller);

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> Request::wrap(
    v8::Local<v8::Context> context,
    EndpointContext* endpoint_ctx,
    BaseEndpointRegistry* endpoint_registry)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<Request>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    set_internal_fields<InternalField>(
      result,
      {{{InternalField::EndpointContext, endpoint_ctx},
        {InternalField::EndpointRegistry, endpoint_registry}}});

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl
