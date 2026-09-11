// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/snp_attestation.h"

#include "ccf/js/core/context.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"
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
  namespace
  {

    JSValue make_js_tcb_version(
      js::core::Context& jsctx, std::span<const uint8_t> tcb)
    {
      auto data_hex =
        jsctx.new_string(pal::snp::TcbVersionRaw::from_span(tcb).to_hex());
      JS_CHECK_EXC(data_hex);
      return data_hex.take();
    }

    JSValue JS_NewArrayBuffer2(JSContext* ctx, std::span<const uint8_t> data)
    {
      return JS_NewArrayBufferCopy(ctx, data.data(), data.size());
    }

    JSValue js_verify_snp_attestation(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      if (argc < 2 || argc > 4)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected between 2 and 4", argc);
      }
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      // Copy the ArrayBuffer arguments up-front before any call that can
      // re-enter JavaScript. Since QuickJS 2026-06-04, ArrayBuffer.prototype
      // .transfer() and .resize() let script free or reallocate the backing
      // store; converting argv[3] to a string below via to_str() can invoke
      // a user-defined toString / Symbol.toPrimitive that transfers or
      // shrinks the evidence, endorsements or UVM buffers.
      auto evidence_opt = jsctx.copy_array_buffer(argv[0]);
      if (!evidence_opt.has_value())
      {
        return ccf::js::core::constants::Exception;
      }
      auto endorsements_opt = jsctx.copy_array_buffer(argv[1]);
      if (!endorsements_opt.has_value())
      {
        return ccf::js::core::constants::Exception;
      }

      std::optional<std::vector<uint8_t>> uvm_endorsements;
      if (argc >= 3 && JS_IsUndefined(argv[2]) == 0)
      {
        uvm_endorsements = jsctx.copy_array_buffer(argv[2]);
        if (!uvm_endorsements.has_value())
        {
          return ccf::js::core::constants::Exception;
        }
      }

      std::optional<std::string> endorsed_tcb;
      if (argc >= 4 && JS_IsUndefined(argv[3]) == 0)
      {
        endorsed_tcb = jsctx.to_str(argv[3]);
        if (!endorsed_tcb)
        {
          return ccf::js::core::constants::Exception;
        }
      }

      QuoteInfo quote_info = {};
      quote_info.format = QuoteFormat::amd_sev_snp_v1;
      quote_info.quote = std::move(*evidence_opt);
      quote_info.endorsements = std::move(*endorsements_opt);
      if (endorsed_tcb.has_value())
      {
        quote_info.endorsed_tcb = endorsed_tcb.value();
      }

      pal::PlatformAttestationMeasurement measurement = {};
      pal::PlatformAttestationReportData report_data = {};
      std::optional<pal::UVMEndorsements> parsed_uvm_endorsements;
      try
      {
        const auto attestation = pal::verify_snp_attestation_report_and_get(
          quote_info, measurement, report_data);
        if (uvm_endorsements.has_value())
        {
          parsed_uvm_endorsements =
            verify_uvm_endorsements_against_roots_of_trust(
              uvm_endorsements.value(),
              measurement,
              default_uvm_roots_of_trust);
        }
        auto r = jsctx.new_obj();
        JS_CHECK_EXC(r);

        auto a = jsctx.new_obj();
        JS_CHECK_EXC(a);

        JS_CHECK_SET(a.set_uint32(
          "version", tav_snp_attestation_report_version(attestation.get())));
        JS_CHECK_SET(a.set_uint32(
          "guest_svn",
          tav_snp_attestation_report_guest_svn(attestation.get())));

        auto policy = jsctx.new_obj();
        JS_CHECK_EXC(policy);

        JS_CHECK_SET(policy.set_uint32(
          "abi_minor",
          tav_snp_attestation_report_policy_abi_minor(attestation.get())));
        JS_CHECK_SET(policy.set_uint32(
          "abi_major",
          tav_snp_attestation_report_policy_abi_major(attestation.get())));
        JS_CHECK_SET(policy.set_uint32(
          "smt", tav_snp_attestation_report_policy_smt(attestation.get())));
        JS_CHECK_SET(policy.set_uint32(
          "migrate_ma",
          tav_snp_attestation_report_policy_migrate_ma(attestation.get())));
        JS_CHECK_SET(policy.set_uint32(
          "debug", tav_snp_attestation_report_policy_debug(attestation.get())));
        JS_CHECK_SET(policy.set_uint32(
          "single_socket",
          tav_snp_attestation_report_policy_single_socket(attestation.get())));

        JS_CHECK_SET(a.set("policy", std::move(policy)));

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_family_id(attestation.get(), &data, &size);
          auto family_id =
            jsctx.new_array_buffer_copy(std::span<const uint8_t>{data, size});
          JS_CHECK_EXC(family_id);
          JS_CHECK_SET(a.set("family_id", std::move(family_id)));
        }

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_image_id(attestation.get(), &data, &size);
          auto image_id =
            jsctx.new_array_buffer_copy(std::span<const uint8_t>{data, size});
          JS_CHECK_EXC(image_id);
          JS_CHECK_SET(a.set("image_id", std::move(image_id)));
        }

        JS_CHECK_SET(a.set_uint32(
          "vmpl", tav_snp_attestation_report_vmpl(attestation.get())));
        JS_CHECK_SET(a.set_uint32(
          "signature_algo",
          static_cast<uint32_t>(
            tav_snp_attestation_report_signature_algo(attestation.get()))));

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_platform_version(
            attestation.get(), &data, &size);
          auto platform_version = jsctx.wrap(
            make_js_tcb_version(jsctx, std::span<const uint8_t>{data, size}));
          JS_CHECK_EXC(platform_version);
          JS_CHECK_SET(a.set("platform_version", std::move(platform_version)));
        }

        {
          auto platform_info = jsctx.new_obj();
          JS_CHECK_EXC(platform_info);
          const auto raw_platform_info =
            tav_snp_attestation_report_platform_info(attestation.get());
          JS_CHECK_SET(
            platform_info.set_uint32("smt_en", raw_platform_info & 1));
          JS_CHECK_SET(
            platform_info.set_uint32("tsme_en", (raw_platform_info >> 1) & 1));
          JS_CHECK_SET(a.set("plaform_info", std::move(platform_info)));
        }

        {
          auto flags = jsctx.new_obj();
          JS_CHECK_EXC(flags);
          JS_CHECK_SET(flags.set_uint32(
            "author_key_en",
            tav_snp_attestation_report_flags_author_key_en(attestation.get())));
          JS_CHECK_SET(flags.set_uint32(
            "mask_chip_key",
            tav_snp_attestation_report_flags_mask_chip_key(attestation.get())));
          JS_CHECK_SET(flags.set_uint32(
            "signing_key",
            tav_snp_attestation_report_flags_signing_key(attestation.get())));
          JS_CHECK_SET(a.set("flags", std::move(flags)));
        }

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_report_data(
            attestation.get(), &data, &size);
          auto attestation_report_data =
            jsctx.new_array_buffer_copy(std::span<const uint8_t>{data, size});
          JS_CHECK_EXC(attestation_report_data);
          JS_CHECK_SET(
            a.set("report_data", std::move(attestation_report_data)));
        }

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_measurement(
            attestation.get(), &data, &size);
          auto attestation_measurement =
            jsctx.new_array_buffer_copy(std::span<const uint8_t>{data, size});
          JS_CHECK_EXC(attestation_measurement);
          JS_CHECK_SET(
            a.set("measurement", std::move(attestation_measurement)));
        }

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_host_data(attestation.get(), &data, &size);
          auto attestation_host_data =
            jsctx.new_array_buffer_copy(std::span<const uint8_t>{data, size});
          JS_CHECK_EXC(attestation_host_data);
          JS_CHECK_SET(a.set("host_data", std::move(attestation_host_data)));
        }

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_id_key_digest(
            attestation.get(), &data, &size);
          auto attestation_id_key_digest =
            jsctx.new_array_buffer_copy(std::span<const uint8_t>{data, size});
          JS_CHECK_EXC(attestation_id_key_digest);
          JS_CHECK_SET(
            a.set("id_key_digest", std::move(attestation_id_key_digest)));
        }

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_author_key_digest(
            attestation.get(), &data, &size);
          auto attestation_author_key_digest =
            jsctx.new_array_buffer_copy(std::span<const uint8_t>{data, size});
          JS_CHECK_EXC(attestation_author_key_digest);
          JS_CHECK_SET(a.set(
            "author_key_digest", std::move(attestation_author_key_digest)));
        }

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_report_id(attestation.get(), &data, &size);
          auto attestation_report_id =
            jsctx.new_array_buffer_copy(std::span<const uint8_t>{data, size});
          JS_CHECK_EXC(attestation_report_id);
          JS_CHECK_SET(a.set("report_id", std::move(attestation_report_id)));
        }

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_report_id_ma(
            attestation.get(), &data, &size);
          auto attestation_report_id_ma =
            jsctx.new_array_buffer_copy(std::span<const uint8_t>{data, size});
          JS_CHECK_EXC(attestation_report_id_ma);
          JS_CHECK_SET(
            a.set("report_id_ma", std::move(attestation_report_id_ma)));
        }

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_reported_tcb(
            attestation.get(), &data, &size);
          auto reported_tcb = jsctx.wrap(
            make_js_tcb_version(jsctx, std::span<const uint8_t>{data, size}));
          JS_CHECK_EXC(reported_tcb);
          JS_CHECK_SET(a.set("reported_tcb", std::move(reported_tcb)));
        }

        JS_CHECK_SET(a.set_uint32(
          "cpuid_fam_id",
          tav_snp_attestation_report_cpuid_fam_id(attestation.get())));
        JS_CHECK_SET(a.set_uint32(
          "cpuid_mod_id",
          tav_snp_attestation_report_cpuid_mod_id(attestation.get())));
        JS_CHECK_SET(a.set_uint32(
          "cpuid_step",
          tav_snp_attestation_report_cpuid_step(attestation.get())));

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_chip_id(attestation.get(), &data, &size);
          auto attestation_chip_id =
            jsctx.new_array_buffer_copy(std::span<const uint8_t>{data, size});
          JS_CHECK_EXC(attestation_chip_id);
          JS_CHECK_SET(a.set("chip_id", std::move(attestation_chip_id)));
        }

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_committed_tcb(
            attestation.get(), &data, &size);
          auto committed_tcb = jsctx.wrap(
            make_js_tcb_version(jsctx, std::span<const uint8_t>{data, size}));
          JS_CHECK_EXC(committed_tcb);
          JS_CHECK_SET(a.set("committed_tcb", std::move(committed_tcb)));
        }

        JS_CHECK_SET(a.set_uint32(
          "current_minor",
          tav_snp_attestation_report_current_minor(attestation.get())));
        JS_CHECK_SET(a.set_uint32(
          "current_build",
          tav_snp_attestation_report_current_build(attestation.get())));
        JS_CHECK_SET(a.set_uint32(
          "current_major",
          tav_snp_attestation_report_current_major(attestation.get())));
        JS_CHECK_SET(a.set_uint32(
          "committed_build",
          tav_snp_attestation_report_committed_build(attestation.get())));
        JS_CHECK_SET(a.set_uint32(
          "committed_minor",
          tav_snp_attestation_report_committed_minor(attestation.get())));
        JS_CHECK_SET(a.set_uint32(
          "committed_major",
          tav_snp_attestation_report_committed_major(attestation.get())));

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_launch_tcb(
            attestation.get(), &data, &size);
          auto launch_tcb = jsctx.wrap(
            make_js_tcb_version(jsctx, std::span<const uint8_t>{data, size}));
          JS_CHECK_EXC(launch_tcb);
          JS_CHECK_SET(a.set("launch_tcb", std::move(launch_tcb)));
        }

        auto signature = jsctx.new_obj();
        JS_CHECK_EXC(signature);

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_signature_r(
            attestation.get(), &data, &size);
          auto signature_r =
            jsctx.new_array_buffer_copy(std::span<const uint8_t>{data, size});
          JS_CHECK_EXC(signature_r);
          JS_CHECK_SET(signature.set("r", std::move(signature_r)));
        }

        {
          const uint8_t* data = nullptr;
          size_t size = 0;
          tav_snp_attestation_report_signature_s(
            attestation.get(), &data, &size);
          auto signature_s =
            jsctx.new_array_buffer_copy(std::span<const uint8_t>{data, size});
          JS_CHECK_EXC(signature_s);
          JS_CHECK_SET(signature.set("s", std::move(signature_s)));
        }

        JS_CHECK_SET(a.set("signature", std::move(signature)));
        JS_CHECK_SET(r.set("attestation", std::move(a)));

        if (parsed_uvm_endorsements.has_value())
        {
          auto u = jsctx.new_obj();
          JS_CHECK_EXC(u);

          {
            auto did = jsctx.new_string(parsed_uvm_endorsements.value().did);
            JS_CHECK_EXC(did);
            JS_CHECK_SET(u.set("did", std::move(did)));
          }

          {
            auto feed = jsctx.new_string(parsed_uvm_endorsements.value().feed);
            JS_CHECK_EXC(feed);
            JS_CHECK_SET(u.set("feed", std::move(feed)));
          }

          {
            auto svn = jsctx.new_string(parsed_uvm_endorsements.value().svn);
            JS_CHECK_EXC(svn);
            JS_CHECK_SET(u.set("svn", std::move(svn)));
            JS_CHECK_SET(r.set("uvm_endorsements", std::move(u)));
          }
        }

        return r.take();
      }
      catch (const std::exception& e)
      {
        return JS_ThrowRangeError(ctx, "%s", e.what());
      }
    }

#pragma clang diagnostic pop

  }

  void SnpAttestationExtension::install(js::core::Context& ctx)
  {
    auto snp_attestation = ctx.new_obj();

    JS_CHECK_OR_THROW(snp_attestation.set(
      "verifySnpAttestation",
      ctx.new_c_function(
        js_verify_snp_attestation, "verifySnpAttestation", 4)));

    auto global_obj = ctx.get_global_obj();
    JS_CHECK_OR_THROW(
      global_obj.set("snp_attestation", std::move(snp_attestation)));
  }
}