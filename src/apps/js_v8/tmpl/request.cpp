// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "template.h"
#include "request.h"
#include "request_body.h"
#include "request_authn_identity.h"
#include "string_map.h"

using ccf::endpoints::EndpointContext;
using ccf::BaseEndpointRegistry;

namespace ccf::v8_tmpl
{
  static EndpointContext* unwrap_endpoint_ctx(v8::Local<v8::Object> obj)
  {
    return static_cast<EndpointContext*>(obj->GetAlignedPointerFromInternalField(0));
  }

  static BaseEndpointRegistry* unwrap_endpoint_registry(v8::Local<v8::Object> obj)
  {
    return static_cast<BaseEndpointRegistry*>(obj->GetAlignedPointerFromInternalField(1));
  }

  static void get_headers(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    
    v8::Local<v8::Value> headers = StringMap::wrap(context, endpoint_ctx->rpc_ctx->get_request_headers());
    info.GetReturnValue().Set(headers);
  }

  static void get_query(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();
    
    v8::Local<v8::Value> query = v8_util::to_v8_str(isolate, endpoint_ctx->rpc_ctx->get_request_query());
    info.GetReturnValue().Set(query);
  }

  static void get_params(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    
    v8::Local<v8::Value> headers = StringMap::wrap(context, endpoint_ctx->rpc_ctx->get_request_path_params());
    info.GetReturnValue().Set(headers);
  }

  static void get_body(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    
    v8::Local<v8::Value> body = RequestBody::wrap(context, endpoint_ctx->rpc_ctx->get_request_body());
    info.GetReturnValue().Set(body);
  }

  static void get_caller(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    BaseEndpointRegistry* endpoint_registry = unwrap_endpoint_registry(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    
    v8::Local<v8::Value> body = RequestAuthnIdentity::wrap(context, *endpoint_ctx, *endpoint_registry);
    info.GetReturnValue().Set(body);
  }

  v8::Local<v8::ObjectTemplate> Request::create_template(v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);
    
    // Field 0: EndpointContext
    // Field 0: BaseEndpointRegistry
    tmpl->SetInternalFieldCount(2);

    tmpl->SetLazyDataProperty(
        v8_util::to_v8_istr(isolate, "headers"),
        get_headers);
    tmpl->SetLazyDataProperty(
        v8_util::to_v8_istr(isolate, "query"),
        get_query);
    tmpl->SetLazyDataProperty(
        v8_util::to_v8_istr(isolate, "params"),
        get_params);
    tmpl->SetLazyDataProperty(
        v8_util::to_v8_istr(isolate, "body"),
        get_body);
    tmpl->SetLazyDataProperty(
        v8_util::to_v8_istr(isolate, "caller"),
        get_caller);

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> Request::wrap(v8::Local<v8::Context> context, EndpointContext& endpoint_ctx, BaseEndpointRegistry& endpoint_registry)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = get_cached_object_template<Request>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();
    result->SetAlignedPointerInInternalField(0, &endpoint_ctx);
    result->SetAlignedPointerInInternalField(1, &endpoint_registry);

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl
