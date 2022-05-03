// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "receipt.h"

#include "ccf/ds/logger.h"
#include "ccf/historical_queries_interface.h"
#include "ccf/receipt.h"
#include "template.h"

namespace ccf::v8_tmpl
{
  enum class InternalField
  {
    Receipt,
    END
  };

  static ccf::Receipt* unwrap_receipt(v8::Local<v8::Object> obj)
  {
    auto receipt_smart_ptr = static_cast<ccf::ReceiptPtr*>(
      get_internal_field(obj, InternalField::Receipt));
    return receipt_smart_ptr->get();
  }

  static void get_signature(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::Receipt* receipt = unwrap_receipt(info.Holder());
    const auto sig_b64 = crypto::b64_from_raw(receipt->signature);
    v8::Local<v8::String> value =
      v8_util::to_v8_str(info.GetIsolate(), sig_b64);
    info.GetReturnValue().Set(value);
  }

  static void get_node_cert(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::Receipt* receipt = unwrap_receipt(info.Holder());
    v8::Local<v8::Value> value =
      v8_util::to_v8_str(info.GetIsolate(), receipt->cert.str());
    info.GetReturnValue().Set(value);
  }

  static void get_leaf(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::String> what =
      v8_util::to_v8_str(isolate, "leaf is unimplemented in v8");
    isolate->ThrowException(what);
  }

  static void get_node_id(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::Receipt* receipt = unwrap_receipt(info.Holder());
    v8::Local<v8::String> value =
      v8_util::to_v8_str(info.GetIsolate(), receipt->node_id.value());
    info.GetReturnValue().Set(value);
  }

  static void get_proof(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::String> what =
      v8_util::to_v8_str(isolate, "proof is unimplemented in v8");
    isolate->ThrowException(what);
  }

  v8::Local<v8::ObjectTemplate> Receipt::create_template(v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalField>(tmpl);

    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "signature"), get_signature);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "cert"), get_node_cert);
    tmpl->SetLazyDataProperty(v8_util::to_v8_istr(isolate, "leaf"), get_leaf);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "node_id"), get_node_id);
    tmpl->SetLazyDataProperty(v8_util::to_v8_istr(isolate, "proof"), get_proof);

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> Receipt::wrap(
    v8::Local<v8::Context> context, const ccf::TxReceiptImpl& receipt)
  {
    ccf::ReceiptPtr* receipt_out = new ccf::ReceiptPtr();
    V8Context::from_context(context).register_finalizer(
      [](void* data) { delete static_cast<ccf::Receipt*>(data); }, receipt_out);
    *receipt_out = ccf::describe_receipt_v2(receipt);

    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<Receipt>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    set_internal_fields<InternalField>(
      result, {{{InternalField::Receipt, receipt_out}}});

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl
