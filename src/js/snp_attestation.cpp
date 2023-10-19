// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js_plugin.h"
#include "ccf/js_snp_attestation_plugin.h"
#include "ccf/pal/attestation.h"
#include "ccf/version.h"
#include "js/wrap.h"
#include "node/uvm_endorsements.h"

#include <algorithm>
#include <quickjs/quickjs.h>
#include <regex>
#include <vector>

namespace ccf::js
{
#pragma clang diagnostic push

  static JSValue make_js_tcb_version(js::Context& jsctx, pal::snp::TcbVersion tcb)
  {
    auto js_tcb = jsctx.new_obj();
    JS_CHECK_EXC(js_tcb);

    JS_CHECK_SET(js_tcb.set_uint32("boot_loader", tcb.boot_loader));
    JS_CHECK_SET(js_tcb.set_uint32("tee", tcb.tee));
    JS_CHECK_SET(js_tcb.set_uint32("snp", tcb.snp));
    JS_CHECK_SET(js_tcb.set_uint32("microcode", tcb.microcode));
    return js_tcb.take();
  }

  static JSValue JS_NewArrayBuffer2(
    JSContext* ctx, std::span<const uint8_t> data)
  {
    return JS_NewArrayBufferCopy(ctx, data.data(), data.size());
  }

  static JSValue js_verify_snp_attestation(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc < 2 && argc > 4)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected between 2 and 4", argc);
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    size_t evidence_size;
    uint8_t* evidence = JS_GetArrayBuffer(ctx, &evidence_size, argv[0]);
    if (!evidence)
    {
      return ccf::js::constants::Exception;
    }

    size_t endorsements_size;
    uint8_t* endorsements = JS_GetArrayBuffer(ctx, &endorsements_size, argv[1]);
    if (!endorsements)
    {
      return ccf::js::constants::Exception;
    }

    std::optional<std::vector<uint8_t>> uvm_endorsements;
    if (!JS_IsUndefined(argv[2]))
    {
      size_t uvm_endorsements_size;
      uint8_t* uvm_endorsements_array =
        JS_GetArrayBuffer(ctx, &uvm_endorsements_size, argv[2]);
      if (!uvm_endorsements_array)
      {
        return ccf::js::constants::Exception;
      }
      uvm_endorsements = std::vector<uint8_t>(
        uvm_endorsements_array, uvm_endorsements_array + uvm_endorsements_size);
    }

    std::optional<std::string> endorsed_tcb;
    if (!JS_IsUndefined(argv[3]))
    {
      endorsed_tcb = jsctx.to_str(argv[3]);
      if (!endorsed_tcb)
      {
        return ccf::js::constants::Exception;
      }
    }

    QuoteInfo quote_info = {};
    quote_info.format = QuoteFormat::amd_sev_snp_v1;
    quote_info.quote = std::vector<uint8_t>(evidence, evidence + evidence_size);
    quote_info.endorsements =
      std::vector<uint8_t>(endorsements, endorsements + endorsements_size);
    if (endorsed_tcb.has_value())
    {
      quote_info.endorsed_tcb = endorsed_tcb.value();
    }

    pal::PlatformAttestationMeasurement measurement = {};
    pal::PlatformAttestationReportData report_data = {};
    std::optional<UVMEndorsements> parsed_uvm_endorsements;

    try
    {
      pal::verify_snp_attestation_report(quote_info, measurement, report_data);
      if (uvm_endorsements.has_value())
      {
        parsed_uvm_endorsements =
          verify_uvm_endorsements(uvm_endorsements.value(), measurement);
      }
    }
    catch (const std::exception& e)
    {
      return JS_ThrowRangeError(ctx, "%s", e.what());
    }

    auto attestation =
      *reinterpret_cast<const pal::snp::Attestation*>(quote_info.quote.data());


    auto r = jsctx.new_obj();
    JS_CHECK_EXC(r);

    auto a = jsctx.new_obj();
    JS_CHECK_EXC(a);

    JS_CHECK_SET(a.set_uint32("version", attestation.version));
    JS_CHECK_SET(a.set_uint32("guest_svn", attestation.guest_svn));

    auto policy = jsctx.new_obj();
    JS_CHECK_EXC(policy);

    JS_CHECK_SET(policy.set_uint32("abi_minor", attestation.policy.abi_minor));
    JS_CHECK_SET(policy.set_uint32("abi_major", attestation.policy.abi_major));
    JS_CHECK_SET(policy.set_uint32("smt", attestation.policy.smt));
    JS_CHECK_SET(policy.set_uint32("migrate_ma", attestation.policy.migrate_ma));
    JS_CHECK_SET(policy.set_uint32("debug", attestation.policy.debug));
    JS_CHECK_SET(policy.set_uint32("single_socket", attestation.policy.single_socket));

    auto policy_atom = JSWrappedAtom(ctx, "policy");
    JS_CHECK_NULL(policy_atom);
    JS_CHECK_SET(a.set(std::move(policy_atom), std::move(policy)));

    auto family_id = jsctx.new_array_buffer_copy(attestation.family_id);
    JS_CHECK_EXC(family_id);
    JS_CHECK_SET(a.set("family_id", std::move(family_id)));

    auto image_id = jsctx.new_array_buffer_copy(attestation.image_id);
    JS_CHECK_EXC(image_id);
    JS_CHECK_SET(a.set("image_id", std::move(image_id)));

    JS_CHECK_SET(a.set_uint32("vmpl", attestation.vmpl));
    JS_CHECK_SET(a.set_uint32("signature_algo", static_cast<uint32_t>(attestation.signature_algo)));

    auto platform_version = JSWrappedValue(ctx, make_js_tcb_version(jsctx, attestation.platform_version));
    JS_CHECK_EXC(platform_version);
    JS_CHECK_SET(a.set("platform_version", std::move(platform_version)));

    auto platform_info = jsctx.new_obj();
    JS_CHECK_EXC(platform_info);
    JS_CHECK_SET(platform_info.set_uint32("smt_en", attestation.platform_info.smt_en));
    JS_CHECK_SET(platform_info.set_uint32("tsme_en", attestation.platform_info.tsme_en));

    auto platform_info_atom = JSWrappedAtom(ctx, "platform_info");
    JS_CHECK_NULL(platform_info_atom);
    JS_CHECK_SET(a.set(std::move(platform_info_atom), std::move(platform_info)));

    auto flags = JS_NewObject(ctx);
    JS_SetPropertyStr(
      ctx,
      flags,
      "author_key_en",
      JS_NewUint32(ctx, attestation.flags.author_key_en));
    JS_SetPropertyStr(
      ctx,
      flags,
      "mask_chip_key",
      JS_NewUint32(ctx, attestation.flags.mask_chip_key));
    JS_SetPropertyStr(
      ctx,
      flags,
      "signing_key",
      JS_NewUint32(ctx, attestation.flags.signing_key));
    JS_SetProperty(ctx, a, JS_NewAtom(ctx, "flags"), flags);

    JS_SetPropertyStr(
      ctx, a, "report_data", JS_NewArrayBuffer2(ctx, attestation.report_data));
    JS_SetPropertyStr(
      ctx, a, "measurement", JS_NewArrayBuffer2(ctx, attestation.measurement));

    JS_SetPropertyStr(
      ctx, a, "host_data", JS_NewArrayBuffer2(ctx, attestation.host_data));
    JS_SetPropertyStr(
      ctx,
      a,
      "id_key_digest",
      JS_NewArrayBuffer2(ctx, attestation.id_key_digest));
    JS_SetPropertyStr(
      ctx,
      a,
      "author_key_digest",
      JS_NewArrayBuffer2(ctx, attestation.author_key_digest));
    JS_SetPropertyStr(
      ctx, a, "report_id", JS_NewArrayBuffer2(ctx, attestation.report_id));
    JS_SetPropertyStr(
      ctx,
      a,
      "report_id_ma",
      JS_NewArrayBuffer2(ctx, attestation.report_id_ma));
    JS_SetProperty(
      ctx,
      a,
      JS_NewAtom(ctx, "reported_tcb"),
      make_js_tcb_version(jsctx, attestation.reported_tcb));
    JS_SetPropertyStr(
      ctx, a, "chip_id", JS_NewArrayBuffer2(ctx, attestation.chip_id));
    JS_SetProperty(
      ctx,
      a,
      JS_NewAtom(ctx, "committed_tcb"),
      make_js_tcb_version(jsctx, attestation.committed_tcb));
    JS_SetPropertyStr(
      ctx, a, "current_minor", JS_NewUint32(ctx, attestation.current_minor));
    JS_SetPropertyStr(
      ctx, a, "current_build", JS_NewUint32(ctx, attestation.current_build));
    JS_SetPropertyStr(
      ctx, a, "current_major", JS_NewUint32(ctx, attestation.current_major));
    JS_SetPropertyStr(
      ctx,
      a,
      "committed_build",
      JS_NewUint32(ctx, attestation.committed_build));
    JS_SetPropertyStr(
      ctx,
      a,
      "committed_minor",
      JS_NewUint32(ctx, attestation.committed_minor));
    JS_SetPropertyStr(
      ctx,
      a,
      "committed_major",
      JS_NewUint32(ctx, attestation.committed_major));
    JS_SetProperty(
      ctx,
      a,
      JS_NewAtom(ctx, "launch_tcb"),
      make_js_tcb_version(jsctx, attestation.launch_tcb));

    auto signature = JS_NewObject(ctx);
    JS_SetProperty(
      ctx,
      signature,
      JS_NewAtom(ctx, "r"),
      JS_NewArrayBuffer2(ctx, attestation.signature.r));
    JS_SetProperty(
      ctx,
      signature,
      JS_NewAtom(ctx, "s"),
      JS_NewArrayBuffer2(ctx, attestation.signature.s));
    JS_SetProperty(ctx, a, JS_NewAtom(ctx, "signature"), signature);
    JS_CHECK_SET(r.set("attestation", std::move(a)));

    if (parsed_uvm_endorsements.has_value())
    {
      auto u = JS_NewObject(ctx);
      JS_SetPropertyStr(
        ctx,
        u,
        "did",
        JS_NewString(ctx, parsed_uvm_endorsements.value().did.c_str()));
      JS_SetPropertyStr(
        ctx,
        u,
        "feed",
        JS_NewString(ctx, parsed_uvm_endorsements.value().feed.c_str()));
      JS_SetPropertyStr(
        ctx,
        u,
        "svn",
        JS_NewString(ctx, parsed_uvm_endorsements.value().svn.c_str()));
      JS_SetProperty(ctx, r, JS_NewAtom(ctx, "uvm_endorsements"), u);
    }

    return r.take();
  }

#pragma clang diagnostic pop

  static JSValue create_snp_attestation_obj(JSContext* ctx)
  {
    auto snp_attestation = JS_NewObject(ctx);

    JS_SetPropertyStr(
      ctx,
      snp_attestation,
      "verifySnpAttestation",
      JS_NewCFunction(
        ctx, js_verify_snp_attestation, "verifySnpAttestation", 4));

    return snp_attestation;
  }

  static void populate_global_snp_attestation(Context& ctx)
  {
    auto global_obj = ctx.get_global_obj();
    global_obj.set("snp_attestation", create_snp_attestation_obj(ctx));
  }

  FFIPlugin snp_attestation_plugin = {
    .name = "SNP Attestation",
    .ccf_version = ccf::ccf_version,
    .extend = populate_global_snp_attestation};
}