// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "v8_runner.h"
#include "v8_util.h"

#include <v8.h>

namespace
{
  template <class T>
  static v8::Local<v8::Template> get_cached_template(v8::Isolate* isolate)
  {
    ccf::V8Isolate::TemplateCache& cache =
      ccf::V8Isolate::Data::Get(isolate)->get_template_cache();
    if (!cache.has(T::NAME))
    {
      v8::Local<v8::Template> raw_template = T::create_template(isolate);
      cache.set(T::NAME, raw_template);
    }
    v8::Local<v8::Template> tmpl = cache.get(T::NAME);
    return tmpl;
  }
}

namespace ccf::v8_tmpl
{
  template <class T>
  static v8::Local<v8::ObjectTemplate> get_cached_object_template(
    v8::Isolate* isolate)
  {
    v8::Local<v8::Template> tmpl = get_cached_template<T>(isolate);
    return tmpl.As<v8::ObjectTemplate>();
  }

  template <class T>
  static void set_internal_field_count(v8::Local<v8::ObjectTemplate> tmpl)
  {
    static_assert(std::is_enum_v<T>, "T must be an enum class");
    tmpl->SetInternalFieldCount(static_cast<int>(T::END));
  }

  template <class T, size_t N = static_cast<size_t>(T::END)>
  static void set_internal_fields(
    v8::Local<v8::Object> obj, const std::array<std::pair<T, void*>, N>& fields)
  {
    static_assert(std::is_enum_v<T>, "T must be an enum value");
    for (const auto& [enum_value, value] : fields)
    {
      obj->SetAlignedPointerInInternalField(
        static_cast<int>(enum_value), value);
    }
  }

  template <class T>
  static void* get_internal_field(v8::Local<v8::Object> obj, T enum_value)
  {
    static_assert(std::is_enum_v<T>, "T must be an enum value");
    return obj->GetAlignedPointerFromInternalField(
      static_cast<int>(enum_value));
  }

} // namespace ccf::v8_tmpl
