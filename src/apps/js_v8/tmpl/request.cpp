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
    EndpointDefinition,
    EndpointContext,
    EndpointRegistry,
    END
  };

  static const EndpointDefinition* unwrap_endpoint_def(
    v8::Local<v8::Object> obj)
  {
    return static_cast<const EndpointDefinition*>(
      get_internal_field(obj, InternalField::EndpointDefinition));
  }

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

  static void get_path(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();

    v8::Local<v8::Value> path =
      v8_util::to_v8_str(isolate, endpoint_ctx->rpc_ctx->get_request_path());
    info.GetReturnValue().Set(path);
  }

  static void get_method(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();

    v8::Local<v8::Value> method = v8_util::to_v8_str(
      isolate, endpoint_ctx->rpc_ctx->get_request_verb().c_str());
    info.GetReturnValue().Set(method);
  }

  static void get_hostname(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();

    const auto& r_headers = endpoint_ctx->rpc_ctx->get_request_headers();
    v8::Local<v8::Value> hostname;
    const auto host_it = r_headers.find(http::headers::HOST);
    if (host_it != r_headers.end())
    {
      hostname = v8_util::to_v8_str(isolate, host_it->second);
    }

    info.GetReturnValue().Set(hostname);
  }

  static void get_route(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    const EndpointDefinition* endpoint_def = unwrap_endpoint_def(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();

    v8::Local<v8::Value> route =
      v8_util::to_v8_str(isolate, endpoint_def->full_uri_path);
    info.GetReturnValue().Set(route);
  }

  static void get_url(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    EndpointContext* endpoint_ctx = unwrap_endpoint_ctx(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();

    auto url = endpoint_ctx->rpc_ctx->get_request_path();
    const auto& query = endpoint_ctx->rpc_ctx->get_request_query();
    if (!query.empty())
    {
      url = fmt::format("{}?{}", url, query);
    }

    v8::Local<v8::Value> url_v8 = v8_util::to_v8_str(isolate, url);
    info.GetReturnValue().Set(url_v8);
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
    tmpl->SetLazyDataProperty(v8_util::to_v8_istr(isolate, "path"), get_path);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "method"), get_method);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "hostname"), get_hostname);
    tmpl->SetLazyDataProperty(v8_util::to_v8_istr(isolate, "route"), get_route);
    tmpl->SetLazyDataProperty(v8_util::to_v8_istr(isolate, "url"), get_url);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "params"), get_params);
    tmpl->SetLazyDataProperty(v8_util::to_v8_istr(isolate, "body"), get_body);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "caller"), get_caller);

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> Request::wrap(
    v8::Local<v8::Context> context,
    const EndpointDefinition* endpoint_def,
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
      {{{InternalField::EndpointDefinition, (void*)endpoint_def},
        {InternalField::EndpointContext, endpoint_ctx},
        {InternalField::EndpointRegistry, endpoint_registry}}});

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl
