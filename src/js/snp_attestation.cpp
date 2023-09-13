// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js_plugin.h"
#include "ccf/js_snp_attestation_plugin.h"
#include "ccf/pal/attestation.h"
#include "ccf/version.h"
#include "js/wrap.h"

#include <algorithm>
#include <quickjs/quickjs.h>
#include <regex>
#include <vector>

namespace ccf::js
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  static JSValue js_verify_snp_attestation(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 2 && argc != 3)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 2 or 3", argc);
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    size_t evidence_size;
    uint8_t* evidence = JS_GetArrayBuffer(ctx, &evidence_size, argv[0]);
    if (!evidence)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    size_t endorsements_size;
    uint8_t* endorsements = JS_GetArrayBuffer(ctx, &endorsements_size, argv[1]);
    if (!endorsements)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    QuoteInfo quote_info = {};
    quote_info.format = QuoteFormat::amd_sev_snp_v1;
    quote_info.quote = std::vector<uint8_t>(evidence, evidence + evidence_size);
    quote_info.endorsements =
      std::vector<uint8_t>(endorsements, endorsements + endorsements_size);
    if (argc == 3)
    {
      quote_info.endorsed_tcb = jsctx.to_str(argv[2]);
    }

    pal::PlatformAttestationMeasurement measurement = {};
    pal::PlatformAttestationReportData report_data = {};

    try
    {
      pal::verify_snp_attestation_report(quote_info, measurement, report_data);
    }
    catch (const std::exception& e)
    {
      auto e_ = JS_ThrowRangeError(ctx, "%s", e.what());
      js::js_dump_error(ctx);
      return e_;
    }

    auto r = JS_NewObject(ctx);

    auto js_measurement = JS_NewString(ctx, measurement.hex_str().c_str());
    JS_SetPropertyStr(ctx, r, "measurement", js_measurement);

    auto js_report_data = JS_NewString(ctx, report_data.hex_str().c_str());
    JS_SetPropertyStr(ctx, r, "report_data", js_report_data);

    return r;
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
        ctx, js_verify_snp_attestation, "verifySnpAttestation", 3));

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