// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "nlohmann/json.hpp"

#include <span>
#include <string>
#include <v8.h>

namespace ccf::v8_util
{
  // 2^53 - 1
  constexpr const uint64_t MAX_SAFE_INTEGER = 9007199254740991;

  const char* to_cstr(const v8::String::Utf8Value& value);
  std::string to_str(v8::Isolate* isolate, v8::Local<v8::String> v8_str);
  v8::Local<v8::String> to_v8_str(v8::Isolate* isolate, const std::string& x);
  v8::Local<v8::String> to_v8_str(v8::Isolate* isolate, const char* x);
  v8::Local<v8::Value> to_v8_obj(
    v8::Isolate* isolate, const nlohmann::json& json);

  /**
   * Converts a native string to an internalized v8 string.
   * Use this for any constants.
   */
  v8::Local<v8::String> to_v8_istr(v8::Isolate* isolate, const char* x);
  v8::Local<v8::String> to_v8_istr(v8::Isolate* isolate, const std::string& x);

  v8::Local<v8::ArrayBuffer> to_v8_array_buffer_copy(
    v8::Isolate* isolate, const uint8_t* data, size_t size);
  std::span<uint8_t> get_array_buffer_data(v8::Local<v8::ArrayBuffer> value);

  void throw_error(v8::Isolate* isolate, const std::string& msg);
  void throw_type_error(v8::Isolate* isolate, const std::string& msg);
  void throw_range_error(v8::Isolate* isolate, const std::string& msg);
  void report_exception(v8::Isolate* isolate, v8::TryCatch* try_catch);
  std::string get_exception_message(
    v8::Isolate* isolate, v8::TryCatch* try_catch);
}
