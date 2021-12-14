// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "receipt.h"

#include "ccf/receipt.h"
#include "ds/logger.h"
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
    return static_cast<ccf::Receipt*>(
      get_internal_field(obj, InternalField::Receipt));
  }

  static void get_signature(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::Receipt* receipt = unwrap_receipt(info.Holder());
    v8::Local<v8::String> value =
      v8_util::to_v8_str(info.GetIsolate(), receipt->signature);
    info.GetReturnValue().Set(value);
  }

  static void get_node_cert(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::Receipt* receipt = unwrap_receipt(info.Holder());
    v8::Local<v8::Value> value;
    if (receipt->cert.has_value())
      value = v8_util::to_v8_str(info.GetIsolate(), receipt->cert.value());
    else
      value = v8::Undefined(info.GetIsolate());
    info.GetReturnValue().Set(value);
  }

  static void get_leaf(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::Receipt* receipt = unwrap_receipt(info.Holder());
    v8::Local<v8::String> value =
      v8_util::to_v8_str(info.GetIsolate(), receipt->leaf);
    info.GetReturnValue().Set(value);
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
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    ccf::Receipt* receipt = unwrap_receipt(info.Holder());

    size_t size = receipt->proof.size();
    std::vector<v8::Local<v8::Value>> elements;
    elements.reserve(size);
    for (auto& element : receipt->proof)
    {
      auto is_left = element.left.has_value();
      v8::Local<v8::Object> obj = v8::Object::New(isolate);
      obj
        ->Set(
          context,
          v8_util::to_v8_istr(isolate, is_left ? "left" : "right"),
          v8_util::to_v8_str(
            isolate, (is_left ? element.left : element.right).value()))
        .Check();
      elements.push_back(obj);
    }

    v8::Local<v8::Array> array =
      v8::Array::New(info.GetIsolate(), elements.data(), size);

    info.GetReturnValue().Set(array);
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
      v8_util::to_v8_istr(isolate, "nodeId"), get_node_id);
    tmpl->SetLazyDataProperty(v8_util::to_v8_istr(isolate, "proof"), get_proof);

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> Receipt::wrap(
    v8::Local<v8::Context> context, ccf::TxReceipt* receipt)
  {
    ccf::Receipt* receipt_out = new ccf::Receipt();
    V8Context::from_context(context).register_finalizer(
      [](void* data) { delete static_cast<ccf::Receipt*>(data); }, receipt_out);
    receipt->describe(*receipt_out);

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
