// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/logger.h"

#include <span>
#include <v8.h>

namespace ccf::v8_util
{
#define CHECK(expr) \
  if (!(expr)) \
  LOG_FATAL_FMT("CHECK failed")

  // Extracts a C string from a V8 Utf8Value.
  // Adapted from v8/samples/shell.cc::ToCString.
  const char* to_cstr(const v8::String::Utf8Value& value)
  {
    return *value ? *value : "<string conversion failed>";
  }

  // Adapted from v8/src/d8/d8.cc.
  std::string to_str(v8::Isolate* isolate, v8::Local<v8::String> v8_str)
  {
    v8::String::Utf8Value utf8(isolate, v8_str);
    // Should not be able to fail since the input is a v8::String.
    CHECK(*utf8);
    return *utf8;
  }

  v8::Local<v8::String> to_v8_str(v8::Isolate* isolate, const char* x)
  {
    return v8::String::NewFromUtf8(isolate, x).ToLocalChecked();
  }

  v8::Local<v8::String> to_v8_str(v8::Isolate* isolate, const std::string& x)
  {
    return to_v8_str(isolate, x.c_str());
  }

  v8::Local<v8::String> to_v8_istr(v8::Isolate* isolate, const char* x)
  {
    return v8::String::NewFromUtf8(isolate, x, v8::NewStringType::kInternalized)
      .ToLocalChecked();
  }

  v8::Local<v8::String> to_v8_istr(v8::Isolate* isolate, const std::string& x)
  {
    return v8::String::NewFromUtf8(
             isolate, x.c_str(), v8::NewStringType::kInternalized)
      .ToLocalChecked();
  }

  v8::Local<v8::Value> to_v8_obj(
    v8::Isolate* isolate, const nlohmann::json& json)
  {
    std::string json_str = json.dump();
    return v8::JSON::Parse(
             isolate->GetCurrentContext(), to_v8_str(isolate, json_str))
      .ToLocalChecked();
  }

  v8::Local<v8::ArrayBuffer> to_v8_array_buffer_copy(
    v8::Isolate* isolate, const uint8_t* data, size_t size)
  {
    std::unique_ptr<v8::BackingStore> store =
      v8::ArrayBuffer::NewBackingStore(isolate, size);
    memcpy(store->Data(), data, size);
    return v8::ArrayBuffer::New(isolate, std::move(store));
  }

  std::span<uint8_t> get_array_buffer_data(v8::Local<v8::ArrayBuffer> buffer)
  {
    return std::span<uint8_t>(
      static_cast<uint8_t*>(buffer->GetBackingStore()->Data()),
      buffer->GetBackingStore()->ByteLength());
  }

  void throw_error(v8::Isolate* isolate, const std::string& msg)
  {
    isolate->ThrowError(v8_util::to_v8_str(isolate, msg));
  }

  void throw_type_error(v8::Isolate* isolate, const std::string& msg)
  {
    isolate->ThrowException(
      v8::Exception::TypeError(v8_util::to_v8_str(isolate, msg)));
  }

  void throw_range_error(v8::Isolate* isolate, const std::string& msg)
  {
    isolate->ThrowException(
      v8::Exception::RangeError(v8_util::to_v8_str(isolate, msg)));
  }

  // Adapted from v8/samples/shell.cc::ReportException.
  void report_exception(v8::Isolate* isolate, v8::TryCatch* try_catch)
  {
    v8::HandleScope handle_scope(isolate);
    v8::String::Utf8Value exception(isolate, try_catch->Exception());
    const char* exception_string = to_cstr(exception);
    v8::Local<v8::Message> message = try_catch->Message();
    if (message.IsEmpty())
    {
      // V8 didn't provide any extra information about this error; just
      // print the exception.
      LOG_INFO_FMT("Throw: {}", exception_string);
    }
    else
    {
      // Print (filename):(line number): (message).
      v8::String::Utf8Value filename(
        isolate, message->GetScriptOrigin().ResourceName());
      v8::Local<v8::Context> context(isolate->GetCurrentContext());
      const char* filename_string = to_cstr(filename);
      int linenum = message->GetLineNumber(context).FromJust();
      LOG_INFO_FMT("{}:{}: {}", filename_string, linenum, exception_string);
      // Print line of source code.
      v8::String::Utf8Value sourceline(
        isolate, message->GetSourceLine(context).ToLocalChecked());
      const char* sourceline_string = to_cstr(sourceline);
      LOG_INFO_FMT("{}", sourceline_string);
      v8::Local<v8::Value> stack_trace_string;
      if (
        try_catch->StackTrace(context).ToLocal(&stack_trace_string) &&
        stack_trace_string->IsString() &&
        stack_trace_string.As<v8::String>()->Length() > 0)
      {
        v8::String::Utf8Value stack_trace(isolate, stack_trace_string);
        const char* stack_trace_string = to_cstr(stack_trace);
        LOG_INFO_FMT("{}", stack_trace_string);
      }
    }
  }

  std::string get_exception_message(
    v8::Isolate* isolate, v8::TryCatch* try_catch)
  {
    v8::HandleScope handle_scope(isolate);
    v8::String::Utf8Value exception(isolate, try_catch->Exception());
    const char* str = to_cstr(exception);
    return std::string(str);
  }

}
