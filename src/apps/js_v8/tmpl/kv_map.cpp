// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "kv_map.h"

#include "template.h"

namespace ccf::v8_tmpl
{
  enum class InternalField
  {
    KVMapHandle,
    END
  };

  static KVMapHandle* unwrap_kv_map_handle(v8::Local<v8::Object> obj)
  {
    return static_cast<KVMapHandle*>(
      get_internal_field(obj, InternalField::KVMapHandle));
  }

  static void js_kv_map_size_getter(
    v8::Local<v8::String> property,
    const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    KVMapHandle* handle = unwrap_kv_map_handle(info.Holder());

    const uint64_t size = handle->size();
    if (size > v8_util::MAX_SAFE_INTEGER)
    {
      // Instead of throwing, a BigInt could be returned,
      // but that would be a breaking change.
      v8_util::throw_error(
        isolate,
        fmt::format(
          "Map size ({}) is too large to represent as Number object", size));
      return;
    }

    v8::Local<v8::Number> value =
      v8::Number::New(isolate, static_cast<double>(size));
    info.GetReturnValue().Set(value);
  }

  static void js_kv_map_has(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    KVMapHandle* handle = unwrap_kv_map_handle(info.Holder());

    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg = info[0];
    if (!arg->IsArrayBuffer())
    {
      v8_util::throw_type_error(isolate, "Argument must be an ArrayBuffer");
      return;
    }
    v8::Local<v8::ArrayBuffer> buffer = arg.As<v8::ArrayBuffer>();

    auto key = v8_util::get_array_buffer_data(buffer);

    auto has = handle->has({key.data(), key.data() + key.size()});
    v8::Local<v8::Boolean> value = v8::Boolean::New(isolate, has);
    info.GetReturnValue().Set(value);
  }

  static void js_kv_map_get(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    KVMapHandle* handle = unwrap_kv_map_handle(info.Holder());

    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg = info[0];
    if (!arg->IsArrayBuffer())
    {
      v8_util::throw_type_error(isolate, "Argument must be an ArrayBuffer");
      return;
    }
    v8::Local<v8::ArrayBuffer> buffer = arg.As<v8::ArrayBuffer>();

    auto key = v8_util::get_array_buffer_data(buffer);

    auto val = handle->get({key.data(), key.data() + key.size()});
    v8::Local<v8::Value> value;
    if (!val.has_value())
      value = v8::Undefined(isolate);
    else
      value =
        v8_util::to_v8_array_buffer_copy(isolate, val->data(), val->size());
    info.GetReturnValue().Set(value);
  }

  static void js_kv_map_foreach(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    KVMapHandle* handle = unwrap_kv_map_handle(info.Holder());

    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg = info[0];
    if (!arg->IsFunction())
    {
      v8_util::throw_type_error(isolate, "Argument must be a function");
      return;
    }
    v8::Local<v8::Function> func = arg.As<v8::Function>();

    bool failed = false;
    handle->foreach(
      [isolate, &context, &info, func, &failed](const auto& k, const auto& v) {
        constexpr int argc = 3;
        v8::Local<v8::Value> argv[argc];

        // JS forEach expects (v, k, map) rather than (k, v)
        argv[0] = v8_util::to_v8_array_buffer_copy(isolate, v.data(), v.size());
        argv[1] = v8_util::to_v8_array_buffer_copy(isolate, k.data(), k.size());
        argv[2] = info.This();

        if (func->Call(context, v8::Undefined(isolate), argc, argv).IsEmpty())
        {
          failed = true;
          return false;
        }

        return true;
      });

    if (failed)
      return;

    info.GetReturnValue().Set(v8::Undefined(isolate));
  }

  static void js_kv_get_version_of_previous_write(
    const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    KVMapHandle* handle = unwrap_kv_map_handle(info.Holder());

    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg = info[0];
    if (!arg->IsArrayBuffer())
    {
      v8_util::throw_type_error(isolate, "Argument must be an ArrayBuffer");
      return;
    }
    v8::Local<v8::ArrayBuffer> buffer = arg.As<v8::ArrayBuffer>();

    auto key = v8_util::get_array_buffer_data(buffer);

    auto val = handle->get_version_of_previous_write(
      {key.data(), key.data() + key.size()});

    v8::Local<v8::Value> value;
    if (!val.has_value())
    {
      value = v8::Undefined(isolate);
    }
    else
    {
      if (val.value() > v8_util::MAX_SAFE_INTEGER)
      {
        // Instead of throwing, a BigInt could be returned,
        // but that would be a breaking change.
        v8_util::throw_error(
          isolate,
          fmt::format(
            "Version ({}) is too large to represent as Number object",
            val.value()));
        return;
      }

      value = v8::Number::New(isolate, static_cast<double>(val.value()));
    }

    info.GetReturnValue().Set(value);
  }

  static void js_kv_map_set(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    KVMapHandle* handle = unwrap_kv_map_handle(info.Holder());

    if (info.Length() != 2)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 2", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg1 = info[0];
    v8::Local<v8::Value> arg2 = info[1];
    if (!arg1->IsArrayBuffer() || !arg2->IsArrayBuffer())
    {
      v8_util::throw_type_error(isolate, "Arguments must be ArrayBuffers");
      return;
    }
    v8::Local<v8::ArrayBuffer> key_buffer = arg1.As<v8::ArrayBuffer>();
    v8::Local<v8::ArrayBuffer> val_buffer = arg2.As<v8::ArrayBuffer>();

    auto key = v8_util::get_array_buffer_data(key_buffer);
    auto val = v8_util::get_array_buffer_data(val_buffer);

    handle->put(
      {key.data(), key.data() + key.size()},
      {val.data(), val.data() + val.size()});

    info.GetReturnValue().Set(info.This());
  }

  static void js_kv_map_delete(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    KVMapHandle* handle = unwrap_kv_map_handle(info.Holder());

    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg = info[0];
    if (!arg->IsArrayBuffer())
    {
      v8_util::throw_type_error(isolate, "Argument must be an ArrayBuffer");
      return;
    }
    v8::Local<v8::ArrayBuffer> buffer = arg.As<v8::ArrayBuffer>();

    auto key = v8_util::get_array_buffer_data(buffer);

    bool val = handle->remove({key.data(), key.data() + key.size()});
    v8::Local<v8::Boolean> value = v8::Boolean::New(isolate, val);
    info.GetReturnValue().Set(value);
  }

  static void js_kv_map_clear(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    KVMapHandle* handle = unwrap_kv_map_handle(info.Holder());

    if (info.Length() != 0)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 0", info.Length()));
      return;
    }

    handle->clear();

    info.GetReturnValue().Set(v8::Undefined(isolate));
  }

  static void js_kv_map_set_read_only(
    const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8_util::throw_type_error(
      info.GetIsolate(), "Cannot call set on read-only map");
  }

  static void js_kv_map_delete_read_only(
    const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8_util::throw_type_error(
      info.GetIsolate(), "Cannot call delete on read-only map");
  }

  static void js_kv_map_clear_read_only(
    const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8_util::throw_type_error(
      info.GetIsolate(), "Cannot call clear on read-only map");
  }

  static v8::Local<v8::ObjectTemplate> create_kv_map_template(
    v8::Isolate* isolate, bool read_only)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalField>(tmpl);

    auto setter = js_kv_map_set;
    auto deleter = js_kv_map_delete;
    auto clearer = js_kv_map_clear;

    if (read_only)
    {
      setter = js_kv_map_set_read_only;
      deleter = js_kv_map_delete_read_only;
      clearer = js_kv_map_clear_read_only;
    }

    tmpl->SetAccessor(
      v8_util::to_v8_istr(isolate, "size"), js_kv_map_size_getter);
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "has"),
      v8::FunctionTemplate::New(isolate, js_kv_map_has));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "get"),
      v8::FunctionTemplate::New(isolate, js_kv_map_get));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "forEach"),
      v8::FunctionTemplate::New(isolate, js_kv_map_foreach));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "getVersionOfPreviousWrite"),
      v8::FunctionTemplate::New(isolate, js_kv_get_version_of_previous_write));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "set"),
      v8::FunctionTemplate::New(isolate, setter));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "delete"),
      v8::FunctionTemplate::New(isolate, deleter));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "clear"),
      v8::FunctionTemplate::New(isolate, clearer));

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::ObjectTemplate> KVMapReadOnly::create_template(
    v8::Isolate* isolate)
  {
    return create_kv_map_template(isolate, true);
  }

  v8::Local<v8::ObjectTemplate> KVMapReadWrite::create_template(
    v8::Isolate* isolate)
  {
    return create_kv_map_template(isolate, false);
  }

  template <typename T>
  static v8::Local<v8::Object> wrap_kv_map(
    v8::Local<v8::Context> context, KVMapHandle* map_handle)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = get_cached_object_template<T>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    set_internal_fields<InternalField>(
      result, {{{InternalField::KVMapHandle, map_handle}}});

    return handle_scope.Escape(result);
  }

  v8::Local<v8::Object> KVMapReadOnly::wrap(
    v8::Local<v8::Context> context, KVMapReadOnlyHandle* map_handle)
  {
    return wrap_kv_map<KVMapReadOnly>(context, map_handle);
  }

  v8::Local<v8::Object> KVMapReadWrite::wrap(
    v8::Local<v8::Context> context, KVMapHandle* map_handle)
  {
    return wrap_kv_map<KVMapReadWrite>(context, map_handle);
  }

} // namespace ccf::v8_tmpl
