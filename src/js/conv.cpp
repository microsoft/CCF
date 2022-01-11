// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "js/wrap.h"
#include "quickjs.h"

namespace ccf::js
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  static JSValue js_str_to_buf(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    if (!JS_IsString(argv[0]))
    {
      return JS_ThrowTypeError(ctx, "Argument must be a string");
    }

    auto str = jsctx.to_str(argv[0]);

    if (!str)
    {
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    auto buf = jsctx.new_array_buffer_copy((uint8_t*)str->c_str(), str->size());

    if (JS_IsException(buf))
    {
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    return buf.take();
  }

  static JSValue js_buf_to_str(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    size_t buf_size;
    uint8_t* buf = JS_GetArrayBuffer(ctx, &buf_size, argv[0]);

    if (!buf)
    {
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
    }

    auto str = jsctx.new_string_len((char*)buf, buf_size);

    if (JS_IsException(str))
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    return str.take();
  }

  static JSValue js_json_compatible_to_buf(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    auto str = jsctx.json_stringify(JSWrappedValue(ctx, argv[0]));

    if (JS_IsException(str))
    {
      js::js_dump_error(ctx);
      return str.take();
    }

    return js_str_to_buf(ctx, JS_NULL, 1, &str.val);
  }

  static JSValue js_buf_to_json_compatible(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    size_t buf_size;
    uint8_t* buf = JS_GetArrayBuffer(ctx, &buf_size, argv[0]);

    if (!buf)
    {
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
    }

    std::vector<uint8_t> buf_null_terminated(buf_size + 1);
    buf_null_terminated[buf_size] = 0;
    buf_null_terminated.assign(buf, buf + buf_size);

    auto obj =
      jsctx.parse_json((char*)buf_null_terminated.data(), buf_size, "<json>");

    if (JS_IsException(obj))
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    return obj.take();
  }

#pragma clang diagnostic pop
}