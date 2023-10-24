// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "js/wrap.h"
#include "quickjs.h"

namespace ccf::js
{
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
      return ccf::js::constants::Exception;
    }

    auto buf = jsctx.new_array_buffer_copy((uint8_t*)str->c_str(), str->size());
    JS_CHECK_EXC(buf);

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
    JS_CHECK_EXC(str);

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
    JS_CHECK_EXC(str);

    return js_str_to_buf(ctx, ccf::js::constants::Null, 1, &str.val);
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
    JS_CHECK_EXC(obj);

    return obj.take();
  }
}