// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "js/context.h"

namespace ccf::js::globals
{
  namespace details
  {
    JSValue js_str_to_buf(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv);

    JSValue js_buf_to_str(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv);

    JSValue js_json_compatible_to_buf(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv);

    JSValue js_buf_to_json_compatible(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv);

    JSValue js_enable_untrusted_date_time(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv);

    JSValue js_enable_metrics_logging(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv);

    JSValue js_pem_to_id(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv);

    JSValue js_refresh_app_bytecode_cache(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

    JSValue js_gov_set_jwt_public_signing_keys(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

    JSValue js_gov_remove_jwt_public_signing_keys(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
  }

  void populate_global_ccf(js::Context& ctx)
  {
    using namespace details;

    auto ccf = ctx.new_obj();

    ccf.set("strToBuf", ctx.new_c_function(js_str_to_buf, "strToBuf", 1));
    ccf.set("bufToStr", ctx.new_c_function(js_buf_to_str, "bufToStr", 1));

    ccf.set(
      "jsonCompatibleToBuf",
      ctx.new_c_function(js_json_compatible_to_buf, "jsonCompatibleToBuf", 1));
    ccf.set(
      "bufToJsonCompatible",
      ctx.new_c_function(js_buf_to_json_compatible, "bufToJsonCompatible", 1));

    ccf.set(
      "enableUntrustedDateTime",
      ctx.new_c_function(
        js_enable_untrusted_date_time, "enableUntrustedDateTime", 1));

    ccf.set(
      "enableMetricsLogging",
      ctx.new_c_function(js_enable_metrics_logging, "enableMetricsLogging", 1));

    ccf.set("pemToId", ctx.new_c_function(js_pem_to_id, "pemToId", 1));

    auto global_obj = ctx.get_global_obj();
    global_obj.set("ccf", std::move(ccf));
  }

  void extend_ccf_object_with_gov_actions(js::Context& ctx)
  {
    using namespace details;

    auto ccf = ctx.get_global_property("ccf");

    ccf.set(
      "refreshAppBytecodeCache",
      ctx.new_c_function(
        js_refresh_app_bytecode_cache, "refreshAppBytecodeCache", 0));
    ccf.set(
      "setJwtPublicSigningKeys",
      ctx.new_c_function(
        js_gov_set_jwt_public_signing_keys, "setJwtPublicSigningKeys", 3));
    ccf.set(
      "removeJwtPublicSigningKeys",
      ctx.new_c_function(
        js_gov_remove_jwt_public_signing_keys,
        "removeJwtPublicSigningKeys",
        1));
  }
}