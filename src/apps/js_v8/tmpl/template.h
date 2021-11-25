// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "v8.h"

// TODO adjust paths
#include "../v8_runner.h"
#include "../v8_util.h"

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
  static v8::Local<v8::FunctionTemplate> get_cached_function_template(
    v8::Isolate* isolate)
  {
    v8::Local<v8::Template> tmpl = get_cached_template<T>(isolate);
    return tmpl.As<v8::FunctionTemplate>();
  }
} // namespace ccf::v8_tmpl
