// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <algorithm>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/verifier.h>
#include <quickjs/quickjs.h>
#include <regex>
#include <unordered_map>
#include <vector>
#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/enclave.h>
#else
#  include <openenclave/host_verify.h>
#endif
#include "ccf/js_openenclave_plugin.h"
#include "ccf/js_plugin.h"
#include "ccf/version.h"
#include "js/wrap.h"

namespace ccf::js
{
  struct Claims
  {
    oe_claim_t* data = nullptr;
    size_t length = 0;

    ~Claims()
    {
      oe_free_claims(data, length);
    }
  };

  struct CustomClaims
  {
    oe_claim_t* data = nullptr;
    size_t length = 0;

    ~CustomClaims()
    {
      oe_free_custom_claims(data, length);
    }
  };

  static JSValue js_verify_open_enclave_evidence(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 2 && argc != 3)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 2 or 3", argc);

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    oe_uuid_t format_;
    oe_uuid_t* format = nullptr;
    if (!JS_IsUndefined(argv[0]))
    {
      auto format_str = jsctx.to_str(argv[0]);
      if (!format_str)
      {
        return ccf::js::constants::Exception;
      }
      format_str = std::regex_replace(*format_str, std::regex("-"), "");
      if (format_str->size() != 32)
      {
        auto e = JS_ThrowRangeError(
          ctx, "format contains an invalid number of hex characters");
        return e;
      }

      std::vector<uint8_t> format_v;
      try
      {
        format_v = ds::from_hex(*format_str);
      }
      catch (std::exception& exc)
      {
        auto e = JS_ThrowRangeError(
          ctx, "format could not be parsed as hex: %s", exc.what());
        return e;
      }

      std::memcpy(format_.b, format_v.data(), format_v.size());
      format = &format_;
    }

    size_t evidence_size;
    uint8_t* evidence = JS_GetArrayBuffer(ctx, &evidence_size, argv[1]);
    if (!evidence)
    {
      return ccf::js::constants::Exception;
    }

    size_t endorsements_size = 0;
    uint8_t* endorsements = JS_GetArrayBuffer(ctx, &endorsements_size, argv[2]);

    Claims claims;
    auto rc = oe_verify_evidence(
      format,
      evidence,
      evidence_size,
      endorsements,
      endorsements_size,
      nullptr,
      0,
      &claims.data,
      &claims.length);
    if (rc != OE_OK)
    {
      auto e = JS_ThrowRangeError(
        ctx, "Failed to verify evidence: %s", oe_result_str(rc));
      return e;
    }

    std::unordered_map<std::string, std::vector<uint8_t>> out_claims,
      out_custom_claims;

    for (size_t i = 0; i < claims.length; i++)
    {
      auto& claim = claims.data[i];
      std::string claim_name{claim.name};

      if (claim_name == OE_CLAIM_CUSTOM_CLAIMS_BUFFER)
      {
        CustomClaims custom_claims;
        rc = oe_deserialize_custom_claims(
          claim.value,
          claim.value_size,
          &custom_claims.data,
          &custom_claims.length);
        if (rc != OE_OK)
        {
          auto e = JS_ThrowRangeError(
            ctx, "Failed to deserialise custom claims: %s", oe_result_str(rc));
          return e;
        }

        for (size_t j = 0; j < custom_claims.length; j++)
        {
          auto& custom_claim = custom_claims.data[j];
          std::string custom_claim_name{custom_claim.name};
          std::vector<uint8_t> custom_claim_value{
            custom_claim.value, custom_claim.value + custom_claim.value_size};
          out_custom_claims.emplace(
            std::move(custom_claim_name), std::move(custom_claim_value));
        }
      }
      else
      {
        std::vector<uint8_t> claim_value{
          claim.value, claim.value + claim.value_size};
        out_claims.emplace(std::move(claim_name), std::move(claim_value));
      }
    }

    auto js_claims = JS_NewObject(ctx);
    if (JS_IsException(js_claims))
    {
      return ccf::js::constants::Exception;
    }

    for (auto& [name, val] : out_claims)
    {
      auto buf = JS_NewArrayBufferCopy(ctx, val.data(), val.size());
      if (JS_IsException(buf))
      {
        JS_FreeValue(ctx, js_claims);
        return ccf::js::constants::Exception;
      }
      auto rc = JS_SetPropertyStr(ctx, js_claims, name.c_str(), buf);
      if (rc < 0)
      {
        JS_FreeValue(ctx, buf);
        JS_FreeValue(ctx, js_claims);
        return ccf::js::constants::Exception;
      }
    }

    auto js_custom_claims = JS_NewObject(ctx);
    if (JS_IsException(js_custom_claims))
    {
      JS_FreeValue(ctx, js_claims);
      return ccf::js::constants::Exception;
    }
    for (auto& [name, val] : out_custom_claims)
    {
      auto buf = JS_NewArrayBufferCopy(ctx, val.data(), val.size());
      if (JS_IsException(buf))
      {
        JS_FreeValue(ctx, js_claims);
        JS_FreeValue(ctx, js_custom_claims);
        return ccf::js::constants::Exception;
      }
      auto rc = JS_SetPropertyStr(ctx, js_custom_claims, name.c_str(), buf);
      if (rc < 0)
      {
        JS_FreeValue(ctx, buf);
        JS_FreeValue(ctx, js_claims);
        JS_FreeValue(ctx, js_custom_claims);
        return ccf::js::constants::Exception;
      }
    }

    auto r = JS_NewObject(ctx);
    if (JS_IsException(r))
    {
      JS_FreeValue(ctx, js_claims);
      JS_FreeValue(ctx, js_custom_claims);
      return ccf::js::constants::Exception;
    }
    auto rc0 = JS_SetPropertyStr(ctx, r, "claims", js_claims);
    if (rc0 < 0)
    {
      JS_FreeValue(ctx, js_claims);
      JS_FreeValue(ctx, js_custom_claims);
      JS_FreeValue(ctx, r);
      return ccf::js::constants::Exception;
    }
    auto rc1 = JS_SetPropertyStr(ctx, r, "customClaims", js_custom_claims);
    if (rc1 < 0)
    {
      JS_FreeValue(ctx, js_custom_claims);
      JS_FreeValue(ctx, r);
      return ccf::js::constants::Exception;
    }

    return r;
  }

  static JSValue create_openenclave_obj(JSContext* ctx)
  {
    auto openenclave = JS_NewObject(ctx);

    JS_SetPropertyStr(
      ctx,
      openenclave,
      "verifyOpenEnclaveEvidence",
      JS_NewCFunction(
        ctx, js_verify_open_enclave_evidence, "verifyOpenEnclaveEvidence", 3));

    return openenclave;
  }

  static void populate_global_openenclave(Context& ctx)
  {
    auto global_obj = ctx.get_global_obj();
    global_obj.set("openenclave", create_openenclave_obj(ctx));
  }

  FFIPlugin openenclave_plugin = {
    .name = "Open Enclave",
    .ccf_version = ccf::ccf_version,
    .extend = populate_global_openenclave};
}