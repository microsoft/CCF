// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "v8.h"
#include "nlohmann/json.hpp"

#include <string>

namespace ccf::v8_util
{
  const char* ToCString(const v8::String::Utf8Value& value);
  std::string ToSTLString(v8::Isolate* isolate, v8::Local<v8::String> v8_str);
  v8::Local<v8::String> to_v8_str(v8::Isolate* isolate, const std::string& x);
  v8::Local<v8::String> to_v8_str(v8::Isolate* isolate, const char* x);
  v8::Local<v8::Value> to_v8_obj(v8::Isolate* isolate, const nlohmann::json& json);
  
  /**
   * Converts a native string to an internalized v8 string.
   * Use this for any constants.
   */
  v8::Local<v8::String> to_v8_istr(v8::Isolate* isolate, const char* x);
  
  void ReportException(v8::Isolate* isolate, v8::TryCatch* try_catch);
  std::string get_exception_message(v8::Isolate* isolate, v8::TryCatch* try_catch);
}
