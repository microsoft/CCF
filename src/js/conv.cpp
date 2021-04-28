// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "js/wrap.h"

namespace js
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  static void js_free_arraybuffer_cstring(JSRuntime*, void* opaque, void* ptr)
  {
    JS_FreeCString((JSContext*)opaque, (char*)ptr);
  }

  static JSValue js_str_to_buf(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    if (!JS_IsString(argv[0]))
      return JS_ThrowTypeError(ctx, "Argument must be a string");

    size_t str_size = 0;
    const char* str = JS_ToCStringLen(ctx, &str_size, argv[0]);

    if (!str)
    {
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    JSValue buf = JS_NewArrayBuffer(
      ctx, (uint8_t*)str, str_size, js_free_arraybuffer_cstring, ctx, false);

    if (JS_IsException(buf))
      js_dump_error(ctx);

    return buf;
  }

  static JSValue js_buf_to_str(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    size_t buf_size;
    uint8_t* buf = JS_GetArrayBuffer(ctx, &buf_size, argv[0]);

    if (!buf)
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");

    JSValue str = JS_NewStringLen(ctx, (char*)buf, buf_size);

    if (JS_IsException(str))
      js::js_dump_error(ctx);

    return str;
  }

  static JSValue js_json_compatible_to_buf(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    JSValue str = JS_JSONStringify(ctx, argv[0], JS_NULL, JS_NULL);

    if (JS_IsException(str))
    {
      js::js_dump_error(ctx);
      return str;
    }

    JSValue buf = js_str_to_buf(ctx, JS_NULL, 1, &str);
    JS_FreeValue(ctx, str);
    return buf;
  }

  static JSValue js_buf_to_json_compatible(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    size_t buf_size;
    uint8_t* buf = JS_GetArrayBuffer(ctx, &buf_size, argv[0]);

    if (!buf)
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");

    std::vector<uint8_t> buf_null_terminated(buf_size + 1);
    buf_null_terminated[buf_size] = 0;
    buf_null_terminated.assign(buf, buf + buf_size);

    JSValue obj =
      JS_ParseJSON(ctx, (char*)buf_null_terminated.data(), buf_size, "<json>");

    if (JS_IsException(obj))
      js::js_dump_error(ctx);

    return obj;
  }

#pragma clang diagnostic pop
}