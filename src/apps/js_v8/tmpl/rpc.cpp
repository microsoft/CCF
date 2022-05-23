// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "rpc.h"

#include "ccf/ds/logger.h"
#include "template.h"

namespace ccf::v8_tmpl
{
  enum class InternalField
  {
    RpcContext,
    END
  };

  static ccf::RpcContext* unwrap_rpc_context(v8::Local<v8::Object> obj)
  {
    return static_cast<ccf::RpcContext*>(
      get_internal_field(obj, InternalField::RpcContext));
  }

  static void set_apply_writes(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    ccf::RpcContext* rpc_ctx = unwrap_rpc_context(info.Holder());

    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }

    if (!info[0]->IsBoolean())
    {
      v8_util::throw_type_error(
        isolate, "Expected a boolean as the first argument");
      return;
    }
    bool val = info[0]->BooleanValue(isolate);

    rpc_ctx->set_apply_writes(val);

    info.GetReturnValue().Set(v8::Undefined(isolate));
  }

  v8::Local<v8::ObjectTemplate> Rpc::create_template(v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalField>(tmpl);

    tmpl->Set(
      v8_util::to_v8_istr(isolate, "setApplyWrites"),
      v8::FunctionTemplate::New(isolate, set_apply_writes));

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> Rpc::wrap(
    v8::Local<v8::Context> context, ccf::RpcContext* rpc_ctx)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<Rpc>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();
    set_internal_fields<InternalField>(
      result, {{{InternalField::RpcContext, rpc_ctx}}});

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl
