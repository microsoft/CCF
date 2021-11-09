// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "v8.h"
#include "ds/logger.h"

namespace ccf::v8_util
{
  #define CHECK(expr) if (!(expr)) LOG_FATAL_FMT("CHECK failed")

  // Extracts a C string from a V8 Utf8Value.
  // Adapted from v8/samples/shell.cc::ToCString.
  const char* ToCString(const v8::String::Utf8Value& value) {
    return *value ? *value : "<string conversion failed>";
  }

  // Adapted from v8/src/d8/d8.cc.
  std::string ToSTLString(v8::Isolate* isolate, v8::Local<v8::String> v8_str) {
    v8::String::Utf8Value utf8(isolate, v8_str);
    // Should not be able to fail since the input is a v8::String.
    CHECK(*utf8);
    return *utf8;
  }

  v8::Local<v8::String> to_v8_str(v8::Isolate* isolate, const char* x) {
    return v8::String::NewFromUtf8(isolate, x).ToLocalChecked();
  }

  // Adapted from v8/samples/shell.cc::ReportException.
  void ReportException(v8::Isolate* isolate, v8::TryCatch* try_catch) {
    v8::HandleScope handle_scope(isolate);
    v8::String::Utf8Value exception(isolate, try_catch->Exception());
    const char* exception_string = ToCString(exception);
    v8::Local<v8::Message> message = try_catch->Message();
    if (message.IsEmpty()) {
      // V8 didn't provide any extra information about this error; just
      // print the exception.
      LOG_INFO_FMT("Throw: {}", exception_string);
    } else {
      // Print (filename):(line number): (message).
      v8::String::Utf8Value filename(isolate,
                                    message->GetScriptOrigin().ResourceName());
      v8::Local<v8::Context> context(isolate->GetCurrentContext());
      const char* filename_string = ToCString(filename);
      int linenum = message->GetLineNumber(context).FromJust();
      LOG_INFO_FMT("{}:{}: {}", filename_string, linenum, exception_string);
      // Print line of source code.
      v8::String::Utf8Value sourceline(
          isolate, message->GetSourceLine(context).ToLocalChecked());
      const char* sourceline_string = ToCString(sourceline);
      LOG_INFO_FMT("{}", sourceline_string);
      // Print wavy underline (GetUnderline is deprecated).
      // int start = message->GetStartColumn(context).FromJust();
      // for (int i = 0; i < start; i++) {
      //   LOG_INFO_FMT((stderr, " ");
      // }
      // int end = message->GetEndColumn(context).FromJust();
      // for (int i = start; i < end; i++) {
      //   fprintf(stderr, "^");
      // }
      // fprintf(stderr, "\n");
      v8::Local<v8::Value> stack_trace_string;
      if (try_catch->StackTrace(context).ToLocal(&stack_trace_string) &&
          stack_trace_string->IsString() &&
          stack_trace_string.As<v8::String>()->Length() > 0) {
        v8::String::Utf8Value stack_trace(isolate, stack_trace_string);
        const char* stack_trace_string = ToCString(stack_trace);
        LOG_INFO_FMT("{}", stack_trace_string);
      }
    }
  }

  std::string get_exception_message(v8::Isolate* isolate, v8::TryCatch* try_catch) {
    v8::HandleScope handle_scope(isolate);
    v8::String::Utf8Value exception(isolate, try_catch->Exception());
    const char* str = ToCString(exception);
    return std::string(str);
  }

}
