// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "request_body.h"

#include "template.h"

namespace ccf::v8_tmpl
{
  enum class InternalField
  {
    Body,
    END
  };

  static const std::vector<uint8_t>* unwrap_body(v8::Local<v8::Object> obj)
  {
    return static_cast<const std::vector<uint8_t>*>(
      get_internal_field(obj, InternalField::Body));
  }

  static void get_text(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    const std::vector<uint8_t>* body = unwrap_body(info.Holder());

    v8::Local<v8::String> str;
    if (!v8::String::NewFromUtf8(
           info.GetIsolate(),
           reinterpret_cast<const char*>(body->data()),
           v8::NewStringType::kNormal,
           body->size())
           .ToLocal(&str))
      return;

    info.GetReturnValue().Set(str);
  }

  static void get_json(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    const std::vector<uint8_t>* body = unwrap_body(info.Holder());

    v8::Local<v8::String> str;
    if (!v8::String::NewFromUtf8(
           info.GetIsolate(),
           reinterpret_cast<const char*>(body->data()),
           v8::NewStringType::kNormal,
           body->size())
           .ToLocal(&str))
      return;

    v8::Local<v8::Value> parsed;
    if (!v8::JSON::Parse(context, str).ToLocal(&parsed))
      return;

    info.GetReturnValue().Set(parsed);
  }

  static void get_array_buffer(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    const std::vector<uint8_t>* body = unwrap_body(info.Holder());

    // Ideally, we'd pass the underlying buffer as read-only ArrayBuffer.
    // ArrayBuffers cannot be marked read-only, though there is an
    // early proposal: https://github.com/tc39/proposal-limited-arraybuffer
    // For performance reasons, a copy is not made here and the buffer
    // is writable from JS.
    // Note that in the QuickJS bindings, a copy is made.
    uint8_t* data = const_cast<uint8_t*>(body->data());
    size_t size = body->size();

    std::unique_ptr<v8::BackingStore> store = v8::ArrayBuffer::NewBackingStore(
      data, size, v8::BackingStore::EmptyDeleter, nullptr);

    v8::Local<v8::ArrayBuffer> buffer =
      v8::ArrayBuffer::New(info.GetIsolate(), std::move(store));

    info.GetReturnValue().Set(buffer);
  }

  v8::Local<v8::ObjectTemplate> RequestBody::create_template(
    v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalField>(tmpl);

    tmpl->Set(
      v8_util::to_v8_istr(isolate, "text"),
      v8::FunctionTemplate::New(isolate, get_text));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "json"),
      v8::FunctionTemplate::New(isolate, get_json));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "arrayBuffer"),
      v8::FunctionTemplate::New(isolate, get_array_buffer));

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> RequestBody::wrap(
    v8::Local<v8::Context> context, const std::vector<uint8_t>* body)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<RequestBody>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    set_internal_fields<InternalField>(
      result,
      {{{InternalField::Body, const_cast<std::vector<uint8_t>*>(body)}}});

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl
