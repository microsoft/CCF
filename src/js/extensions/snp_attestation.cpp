// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/snp_attestation.h"

#include "ccf/js/core/context.h"
#include "ccf/pal/attestation.h"
#include "ccf/version.h"
#include "js/checks.h"
#include "node/uvm_endorsements.h"

#include <algorithm>
#include <quickjs/quickjs.h>
#include <regex>
#include <vector>

namespace ccf::js::extensions
{
#pragma clang diagnostic push
  static JSValue make_js_tcb_version(
    js::core::Context& jsctx, pal::snp::TcbVersion tcb)
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
    if (argc < 2 || argc > 4)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected between 2 and 4", argc);
    }
    js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

    size_t evidence_size;
    uint8_t* evidence = JS_GetArrayBuffer(ctx, &evidence_size, argv[0]);
    if (!evidence)
    {
      return ccf::js::core::constants::Exception;
    }

    size_t endorsements_size;
    uint8_t* endorsements = JS_GetArrayBuffer(ctx, &endorsements_size, argv[1]);
    if (!endorsements)
    {
      return ccf::js::core::constants::Exception;
    }

    std::optional<std::vector<uint8_t>> uvm_endorsements;
    if (!JS_IsUndefined(argv[2]))
    {
      size_t uvm_endorsements_size;
      uint8_t* uvm_endorsements_array =
        JS_GetArrayBuffer(ctx, &uvm_endorsements_size, argv[2]);
      if (!uvm_endorsements_array)
      {
        return ccf::js::core::constants::Exception;
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
        return ccf::js::core::constants::Exception;
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
    std::optional<pal::UVMEndorsements> parsed_uvm_endorsements;

    try
    {
      pal::verify_snp_attestation_report(quote_info, measurement, report_data);
      if (uvm_endorsements.has_value())
      {
        parsed_uvm_endorsements =
          verify_uvm_endorsements_against_roots_of_trust(
            uvm_endorsements.value(), measurement, default_uvm_roots_of_trust);
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
    JS_CHECK_SET(
      policy.set_uint32("migrate_ma", attestation.policy.migrate_ma));
    JS_CHECK_SET(policy.set_uint32("debug", attestation.policy.debug));
    JS_CHECK_SET(
      policy.set_uint32("single_socket", attestation.policy.single_socket));

    JS_CHECK_SET(a.set("policy", std::move(policy)));

    auto family_id = jsctx.new_array_buffer_copy(attestation.family_id);
    JS_CHECK_EXC(family_id);
    JS_CHECK_SET(a.set("family_id", std::move(family_id)));

    auto image_id = jsctx.new_array_buffer_copy(attestation.image_id);
    JS_CHECK_EXC(image_id);
    JS_CHECK_SET(a.set("image_id", std::move(image_id)));

    JS_CHECK_SET(a.set_uint32("vmpl", attestation.vmpl));
    JS_CHECK_SET(a.set_uint32(
      "signature_algo", static_cast<uint32_t>(attestation.signature_algo)));

    auto platform_version =
      jsctx.wrap(make_js_tcb_version(jsctx, attestation.platform_version));
    JS_CHECK_EXC(platform_version);
    JS_CHECK_SET(a.set("platform_version", std::move(platform_version)));

    auto platform_info = jsctx.new_obj();
    JS_CHECK_EXC(platform_info);
    JS_CHECK_SET(
      platform_info.set_uint32("smt_en", attestation.platform_info.smt_en));
    JS_CHECK_SET(
      platform_info.set_uint32("tsme_en", attestation.platform_info.tsme_en));
    JS_CHECK_SET(a.set("plaform_info", std::move(platform_info)));

    auto flags = jsctx.new_obj();
    JS_CHECK_EXC(flags);
    JS_CHECK_SET(
      flags.set_uint32("author_key_en", attestation.flags.author_key_en));
    JS_CHECK_SET(
      flags.set_uint32("mask_chip_key", attestation.flags.mask_chip_key));
    JS_CHECK_SET(
      flags.set_uint32("signing_key", attestation.flags.signing_key));
    JS_CHECK_SET(a.set("flags", std::move(flags)));

    auto attestation_report_data =
      jsctx.new_array_buffer_copy(attestation.report_data);
    JS_CHECK_EXC(attestation_report_data);
    JS_CHECK_SET(a.set("report_data", std::move(attestation_report_data)));

    auto attestation_measurement =
      jsctx.new_array_buffer_copy(attestation.measurement);
    JS_CHECK_EXC(attestation_measurement);
    JS_CHECK_SET(a.set("measurement", std::move(attestation_measurement)));

    auto attestation_host_data =
      jsctx.new_array_buffer_copy(attestation.host_data);
    JS_CHECK_EXC(attestation_host_data);
    JS_CHECK_SET(a.set("host_data", std::move(attestation_host_data)));

    auto attestation_id_key_digest =
      jsctx.new_array_buffer_copy(attestation.id_key_digest);
    JS_CHECK_EXC(attestation_id_key_digest);
    JS_CHECK_SET(a.set("id_key_digest", std::move(attestation_id_key_digest)));

    auto attestation_author_key_digest =
      jsctx.new_array_buffer_copy(attestation.author_key_digest);
    JS_CHECK_EXC(attestation_author_key_digest);
    JS_CHECK_SET(
      a.set("author_key_digest", std::move(attestation_id_key_digest)));

    auto attestation_report_id =
      jsctx.new_array_buffer_copy(attestation.report_id);
    JS_CHECK_EXC(attestation_report_id);
    JS_CHECK_SET(a.set("report_id", std::move(attestation_id_key_digest)));

    auto attestation_report_id_ma =
      jsctx.new_array_buffer_copy(attestation.report_id_ma);
    JS_CHECK_EXC(attestation_report_id_ma);
    JS_CHECK_SET(a.set("report_id_ma", std::move(attestation_report_id_ma)));

    auto reported_tcb =
      jsctx.wrap(make_js_tcb_version(jsctx, attestation.reported_tcb));
    JS_CHECK_EXC(reported_tcb);
    JS_CHECK_SET(a.set("reported_tcb", std::move(reported_tcb)));

    JS_CHECK_SET(a.set_uint32("cpuid_fam_id", attestation.cpuid_fam_id));
    JS_CHECK_SET(a.set_uint32("cpuid_mod_id", attestation.cpuid_mod_id));
    JS_CHECK_SET(a.set_uint32("cpuid_step", attestation.cpuid_step));

    auto attestation_chip_id = jsctx.new_array_buffer_copy(attestation.chip_id);
    JS_CHECK_EXC(attestation_chip_id);
    JS_CHECK_SET(a.set("chip_id", std::move(attestation_chip_id)));

    auto committed_tcb =
      jsctx.wrap(make_js_tcb_version(jsctx, attestation.committed_tcb));
    JS_CHECK_EXC(committed_tcb);
    JS_CHECK_SET(a.set("committed_tcb", std::move(committed_tcb)));

    JS_CHECK_SET(a.set_uint32("current_minor", attestation.current_minor));
    JS_CHECK_SET(a.set_uint32("current_build", attestation.current_build));
    JS_CHECK_SET(a.set_uint32("current_major", attestation.current_major));
    JS_CHECK_SET(a.set_uint32("committed_build", attestation.committed_build));
    JS_CHECK_SET(a.set_uint32("committed_minor", attestation.committed_minor));
    JS_CHECK_SET(a.set_uint32("committed_major", attestation.committed_major));

    auto launch_tcb =
      jsctx.wrap(make_js_tcb_version(jsctx, attestation.launch_tcb));
    JS_CHECK_EXC(launch_tcb);
    JS_CHECK_SET(a.set("launch_tcb", std::move(launch_tcb)));

    auto signature = jsctx.new_obj();
    JS_CHECK_EXC(signature);

    auto signature_r = jsctx.new_array_buffer_copy(attestation.signature.r);
    JS_CHECK_EXC(signature_r);
    JS_CHECK_SET(signature.set("r", std::move(signature_r)));

    auto signature_s = jsctx.new_array_buffer_copy(attestation.signature.s);
    JS_CHECK_EXC(signature_s);
    JS_CHECK_SET(signature.set("s", std::move(signature_s)));

    JS_CHECK_SET(a.set("signature", std::move(signature)));
    JS_CHECK_SET(r.set("attestation", std::move(a)));

    if (parsed_uvm_endorsements.has_value())
    {
      auto u = jsctx.new_obj();
      JS_CHECK_EXC(u);

      auto did = jsctx.new_string(parsed_uvm_endorsements.value().did.c_str());
      JS_CHECK_EXC(did);
      JS_CHECK_SET(u.set("did", std::move(did)));

      auto feed =
        jsctx.new_string(parsed_uvm_endorsements.value().feed.c_str());
      JS_CHECK_EXC(feed);
      JS_CHECK_SET(u.set("feed", std::move(feed)));

      auto svn = jsctx.new_string(parsed_uvm_endorsements.value().svn.c_str());
      JS_CHECK_EXC(svn);
      JS_CHECK_SET(u.set("svn", std::move(svn)));
      JS_CHECK_SET(r.set("uvm_endorsements", std::move(u)));
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

  void SnpAttestationExtension::install(js::core::Context& ctx)
  {
    auto global_obj = ctx.get_global_obj();
    global_obj.set("snp_attestation", create_snp_attestation_obj(ctx));
  }
}