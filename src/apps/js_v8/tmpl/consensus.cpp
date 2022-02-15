// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "consensus.h"

#include "ccf/ds/logger.h"
#include "template.h"

namespace ccf::v8_tmpl
{
  enum class InternalField
  {
    EndpointRegistry,
    END
  };

  static ccf::BaseEndpointRegistry* unwrap_endpoint_registry(
    v8::Local<v8::Object> obj)
  {
    return static_cast<ccf::BaseEndpointRegistry*>(
      get_internal_field(obj, InternalField::EndpointRegistry));
  }

  static void get_last_committed_txid(
    const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    ccf::BaseEndpointRegistry* endpoint_registry =
      unwrap_endpoint_registry(info.Holder());

    if (info.Length() != 0)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 0", info.Length()));
      return;
    }

    ccf::View view;
    ccf::SeqNo seqno;
    auto result = endpoint_registry->get_last_committed_txid_v1(view, seqno);
    if (result != ccf::ApiResult::OK)
    {
      v8_util::throw_error(
        isolate,
        fmt::format(
          "Failed to get last committed txid: {}",
          ccf::api_result_to_str(result)));
      return;
    }

    auto obj = v8::Object::New(isolate);
    obj
      ->Set(
        context,
        v8_util::to_v8_istr(isolate, "view"),
        v8::Number::New(isolate, view))
      .Check();
    obj
      ->Set(
        context,
        v8_util::to_v8_istr(isolate, "seqno"),
        v8::Number::New(isolate, seqno))
      .Check();

    info.GetReturnValue().Set(obj);
  }

  static void get_status_for_txid(
    const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    ccf::BaseEndpointRegistry* endpoint_registry =
      unwrap_endpoint_registry(info.Holder());

    if (info.Length() != 2)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 2", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg1 = info[0];
    v8::Local<v8::Value> arg2 = info[1];
    if (!arg1->IsNumber() || !arg2->IsNumber())
    {
      v8_util::throw_type_error(isolate, "Arguments must be numbers");
      return;
    }
    v8::Local<v8::Number> view_v8 = arg1.As<v8::Number>();
    v8::Local<v8::Number> seqno_v8 = arg2.As<v8::Number>();

    int64_t view = -1;
    int64_t seqno = -1;
    if (!seqno_v8->IntegerValue(context).To(&seqno))
      return;
    if (!view_v8->IntegerValue(context).To(&view))
      return;
    if (view < 0 || seqno < 0)
    {
      v8_util::throw_range_error(
        isolate, "Invalid view or seqno: cannot be negative");
      return;
    }

    ccf::TxStatus status;
    auto result =
      endpoint_registry->get_status_for_txid_v1(view, seqno, status);
    if (result != ccf::ApiResult::OK)
    {
      v8_util::throw_error(
        isolate,
        fmt::format(
          "Failed to get status for txid: {}", ccf::api_result_to_str(result)));
      return;
    }
    auto status_str = ccf::tx_status_to_str(status);
    v8::Local<v8::Value> value = v8_util::to_v8_str(isolate, status_str);
    info.GetReturnValue().Set(value);
  }

  static void get_view_for_seqno(
    const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    ccf::BaseEndpointRegistry* endpoint_registry =
      unwrap_endpoint_registry(info.Holder());

    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg = info[0];
    if (!arg->IsNumber())
    {
      v8_util::throw_type_error(isolate, "Argument must be a number");
      return;
    }
    v8::Local<v8::Number> number = arg.As<v8::Number>();

    int64_t seqno = -1;
    if (!number->IntegerValue(context).To(&seqno))
      return;
    if (seqno < 0)
    {
      v8_util::throw_range_error(isolate, "Invalid seqno: cannot be negative");
      return;
    }

    ccf::View view;
    auto result = endpoint_registry->get_view_for_seqno_v1(seqno, view);
    if (result != ccf::ApiResult::OK)
    {
      v8_util::throw_error(
        isolate,
        fmt::format(
          "Failed to get view for seqno: {}", ccf::api_result_to_str(result)));
      return;
    }

    v8::Local<v8::Value> value;
    if (result == ccf::ApiResult::NotFound)
      value = v8::Null(isolate);
    else
      value = v8::Number::New(isolate, view);
    info.GetReturnValue().Set(value);
  }

  v8::Local<v8::ObjectTemplate> Consensus::create_template(v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalField>(tmpl);

    tmpl->Set(
      v8_util::to_v8_istr(isolate, "getLastCommittedTxId"),
      v8::FunctionTemplate::New(isolate, get_last_committed_txid));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "getStatusForTxId"),
      v8::FunctionTemplate::New(isolate, get_status_for_txid));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "getViewForSeqno"),
      v8::FunctionTemplate::New(isolate, get_view_for_seqno));

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> Consensus::wrap(
    v8::Local<v8::Context> context,
    ccf::BaseEndpointRegistry* endpoint_registry)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<Consensus>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();
    set_internal_fields<InternalField>(
      result, {{{InternalField::EndpointRegistry, endpoint_registry}}});

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl
