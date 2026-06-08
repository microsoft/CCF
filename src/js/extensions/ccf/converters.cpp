// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// NB: Despite the naming scheme used elsewhere, this populates functions
// directly on the ccf object.

#include "ccf/js/extensions/ccf/converters.h"

#include "ccf/js/core/context.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/sev_snp_cpuid.h"
#include "ccf/version.h"
#include "js/checks.h"
#include "node/rpc/jwt_management.h"

#include <nlohmann/json.hpp>
#include <quickjs/quickjs.h>
#include <stdexcept>

namespace ccf::js::extensions
{
  namespace
  {
    JSValue js_str_to_buf(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

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
        return ccf::js::core::constants::Exception;
      }

      auto buf =
        jsctx.new_array_buffer_copy((uint8_t*)str->c_str(), str->size());
      JS_CHECK_EXC(buf);

      return buf.take();
    }

    JSValue js_buf_to_str(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

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

    JSValue js_json_compatible_to_buf(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);
      }

      auto str = jsctx.json_stringify(jsctx.wrap(argv[0]));
      JS_CHECK_EXC(str);

      return js_str_to_buf(ctx, ccf::js::core::constants::Null, 1, &str.val);
    }

    JSValue js_buf_to_json_compatible(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

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

    JSValue js_enable_untrusted_date_time(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);
      }

      const auto v = argv[0];
      if (!JS_IsBool(v))
      {
        return JS_ThrowTypeError(ctx, "First argument must be a boolean");
      }
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

      const auto previous = jsctx.implement_untrusted_time;
      jsctx.implement_untrusted_time = JS_ToBool(ctx, v);

      return JS_NewBool(ctx, previous);
    }

    JSValue js_enable_metrics_logging(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);
      }

      const auto v = argv[0];
      if (!JS_IsBool(v))
      {
        return JS_ThrowTypeError(ctx, "First argument must be a boolean");
      }

      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);
      const auto previous = jsctx.log_execution_metrics;
      jsctx.log_execution_metrics = JS_ToBool(ctx, v);

      return JS_NewBool(ctx, previous);
    }

    JSValue js_pem_to_id(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      if (argc != 1)
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);

      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

      auto pem_str = jsctx.to_str(argv[0]);
      if (!pem_str)
      {
        return ccf::js::core::constants::Exception;
      }

      try
      {
        auto pem = ccf::crypto::Pem(*pem_str);
        auto der = ccf::crypto::make_verifier(pem)->cert_der();
        auto id = ccf::crypto::Sha256Hash(der).hex_str();

        return JS_NewString(ctx, id.c_str());
      }
      catch (const std::exception& exc)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to parse PEM: %s", exc.what());
      }
    }

    JSValue js_tcb_hex_to_policy(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      if (argc != 2)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 2", argc);
      }
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

      auto hex_cpuid = jsctx.to_str(argv[0]);
      if (!hex_cpuid.has_value())
      {
        return JS_ThrowTypeError(ctx, "CPUID could not be parsed");
      }
      auto cpuid = pal::snp::cpuid_from_hex(hex_cpuid.value());

      auto hex_tcb = jsctx.to_str(argv[1]);
      if (!hex_tcb.has_value())
      {
        return JS_ThrowTypeError(ctx, "TCB could not be parsed from hex_str");
      }
      pal::snp::TcbVersionRaw tcb =
        pal::snp::TcbVersionRaw::from_hex(hex_tcb.value());
      pal::snp::ProductName product = pal::snp::get_sev_snp_product(
        cpuid.get_family_id(), cpuid.get_model_id());

      pal::snp::TcbVersionPolicy tcb_policy = tcb.to_policy(product);

      auto tcb_policy_obj = jsctx.new_obj();
      JS_CHECK_EXC(tcb_policy_obj);
      if (tcb_policy.hexstring.has_value())
      {
        JS_CHECK_SET(tcb_policy_obj.set(
          "hexstring", jsctx.new_string(tcb_policy.hexstring.value())));
      }
      if (tcb_policy.microcode.has_value())
      {
        JS_CHECK_SET(
          tcb_policy_obj.set_uint32("microcode", tcb_policy.microcode.value()));
      }
      if (tcb_policy.snp.has_value())
      {
        JS_CHECK_SET(tcb_policy_obj.set_uint32("snp", tcb_policy.snp.value()));
      }
      if (tcb_policy.tee.has_value())
      {
        JS_CHECK_SET(tcb_policy_obj.set_uint32("tee", tcb_policy.tee.value()));
      }
      if (tcb_policy.boot_loader.has_value())
      {
        JS_CHECK_SET(tcb_policy_obj.set_uint32(
          "boot_loader", tcb_policy.boot_loader.value()));
      }
      if (tcb_policy.fmc.has_value())
      {
        JS_CHECK_SET(tcb_policy_obj.set_uint32("fmc", tcb_policy.fmc.value()));
      }

      return tcb_policy_obj.take();
    }
  }

  void ConvertersExtension::install(js::core::Context& ctx)
  {
    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());

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

    ccf.set(
      "tcbHexToPolicy",
      ctx.new_c_function(js_tcb_hex_to_policy, "tcbHexToPolicy", 2));
  }
}
