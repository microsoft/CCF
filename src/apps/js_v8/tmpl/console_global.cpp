// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "template.h"
#include "console_global.h"
#include "ds/logger.h"
#include <sstream>

namespace ccf::v8_tmpl
{
  static void log(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();

    std::stringstream ss;
    for (int i = 0; i < info.Length(); i++)
    {
      if (i != 0)
        ss << ' ';
      v8::Local<v8::String> str;
      if (!info[i]->IsNativeError() && info[i]->IsObject())
      {
        if (!v8::JSON::Stringify(context, info[i]).ToLocal(&str))
          return;
      }
      else
      {
        if (!info[i]->ToString(context).ToLocal(&str))
          return;
      }
      ss << v8_util::to_str(isolate, str);
    }
    LOG_INFO << ss.str() << std::endl;
  }

  v8::Local<v8::ObjectTemplate> ConsoleGlobal::create_template(v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);
    
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "log"),
      v8::FunctionTemplate::New(isolate, log));

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> ConsoleGlobal::wrap(v8::Local<v8::Context> context)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = get_cached_object_template<ConsoleGlobal>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl
