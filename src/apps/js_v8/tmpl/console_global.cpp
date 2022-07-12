// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "console_global.h"

#include "ccf/ds/logger.h"
#include "template.h"

#include <sstream>

namespace ccf::v8_tmpl
{
  static std::optional<std::stringstream> stringify_args(
    const v8::FunctionCallbackInfo<v8::Value>& fci)
  {
    v8::Isolate* isolate = fci.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();

    std::stringstream ss;
    for (int i = 0; i < fci.Length(); i++)
    {
      if (i != 0)
      {
        ss << ' ';
      }
      v8::Local<v8::String> str;
      if (!fci[i]->IsNativeError() && fci[i]->IsObject())
      {
        if (!v8::JSON::Stringify(context, fci[i]).ToLocal(&str))
          return std::nullopt;
      }
      else
      {
        if (!fci[i]->ToString(context).ToLocal(&str))
          return std::nullopt;
      }
      ss << v8_util::to_str(isolate, str);
    }
    return ss;
  }

  static void info(const v8::FunctionCallbackInfo<v8::Value>& fci)
  {
    const auto ss = stringify_args(fci);
    if (ss.has_value())
    {
      CCF_APP_INFO("{}", ss->str());
    }
  }

  static void fail(const v8::FunctionCallbackInfo<v8::Value>& fci)
  {
    const auto ss = stringify_args(fci);
    if (ss.has_value())
    {
      CCF_APP_FAIL("{}", ss->str());
    }
  }

  static void fatal(const v8::FunctionCallbackInfo<v8::Value>& fci)
  {
    const auto ss = stringify_args(fci);
    if (ss.has_value())
    {
      CCF_APP_FATAL("{}", ss->str());
    }
  }

  v8::Local<v8::ObjectTemplate> ConsoleGlobal::create_template(
    v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    tmpl->Set(
      v8_util::to_v8_istr(isolate, "log"),
      v8::FunctionTemplate::New(isolate, info));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "info"),
      v8::FunctionTemplate::New(isolate, info));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "warn"),
      v8::FunctionTemplate::New(isolate, fail));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "error"),
      v8::FunctionTemplate::New(isolate, fatal));

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> ConsoleGlobal::wrap(v8::Local<v8::Context> context)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<ConsoleGlobal>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl
