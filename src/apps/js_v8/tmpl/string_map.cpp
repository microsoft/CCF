// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "string_map.h"

#include "template.h"

namespace ccf::v8_tmpl
{
  static StringMap::MapType* unwrap_string_map(v8::Local<v8::Object> obj)
  {
    return static_cast<StringMap::MapType*>(
      obj->GetAlignedPointerFromInternalField(0));
  }

  static void map_get(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    if (name->IsSymbol())
      return;

    StringMap::MapType* obj = unwrap_string_map(info.Holder());
    std::string key = v8_util::to_str(info.GetIsolate(), name.As<v8::String>());
    StringMap::MapType::iterator iter = obj->find(key);

    if (iter == obj->end())
      return;

    const std::string& value = (*iter).second;
    info.GetReturnValue().Set(v8_util::to_v8_str(info.GetIsolate(), value));
  }

  v8::Local<v8::ObjectTemplate> StringMap::create_template(v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    // Field 0: std::map
    tmpl->SetInternalFieldCount(1);

    tmpl->SetHandler(v8::NamedPropertyHandlerConfiguration(map_get));

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> StringMap::wrap(
    v8::Local<v8::Context> context, const MapType* map)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<StringMap>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();
    result->SetAlignedPointerInInternalField(0, const_cast<MapType*>(map));

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl
