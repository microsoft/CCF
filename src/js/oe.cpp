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

namespace js
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  struct Claims
  {
    oe_claim_t* data = nullptr;
    size_t length = 0;

    ~Claims()
    {
      oe_free_claims(data, length);
    }
  };

  static JSValue js_verify_open_enclave_evidence(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 2 && argc != 3)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 2 or 3", argc);

    void* auto_free_ptr = JS_GetContextOpaque(ctx);
    js::Context& auto_free = *(js::Context*)auto_free_ptr;

    oe_uuid_t format_;
    oe_uuid_t* format = nullptr;
    if (!JS_IsUndefined(argv[0]))
    {
      auto format_cstr = auto_free(JS_ToCString(ctx, argv[0]));
      if (!format_cstr)
      {
        js::js_dump_error(ctx);
        return JS_EXCEPTION;
      }
      std::string format_str(format_cstr);
      format_str = std::regex_replace(format_str, std::regex("-"), "");
      if (format_str.size() != 32)
      {
        JS_ThrowRangeError(
          ctx, "format contains an invalid number of hex characters");
        js::js_dump_error(ctx);
        return JS_EXCEPTION;
      }

      std::vector<uint8_t> format_v;
      try
      {
        format_v = ds::from_hex(format_str);
      }
      catch (std::exception& exc)
      {
        JS_ThrowRangeError(
          ctx, "format could not be parsed as hex: %s", exc.what());
        js::js_dump_error(ctx);
        return JS_EXCEPTION;
      }

      std::memcpy(format_.b, format_v.data(), format_v.size());
      format = &format_;
    }

    size_t evidence_size;
    uint8_t* evidence = JS_GetArrayBuffer(ctx, &evidence_size, argv[1]);
    if (!evidence)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
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
      JS_ThrowRangeError(
        ctx, "Failed to verify evidence: %s", oe_result_str(rc));
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    std::unordered_map<std::string, std::vector<uint8_t>> out_claims,
      out_custom_claims;

    for (size_t i = 0; i < claims.length; i++)
    {
      auto& claim = claims.data[i];
      std::string claim_name{claim.name};

      if (claim_name == OE_CLAIM_CUSTOM_CLAIMS_BUFFER)
      {
        Claims custom_claims;
        rc = oe_deserialize_custom_claims(
          claim.value,
          claim.value_size,
          &custom_claims.data,
          &custom_claims.length);
        if (rc != OE_OK)
        {
          JS_ThrowRangeError(
            ctx, "Failed to deserialise custom claims: %s", oe_result_str(rc));
          js::js_dump_error(ctx);
          return JS_EXCEPTION;
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
    for (auto& [name, val] : out_claims)
    {
      auto buf = JS_NewArrayBufferCopy(ctx, val.data(), val.size());
      JS_SetPropertyStr(ctx, js_claims, name.c_str(), buf);
    }

    auto js_custom_claims = JS_NewObject(ctx);
    for (auto& [name, val] : out_custom_claims)
    {
      auto buf = JS_NewArrayBufferCopy(ctx, val.data(), val.size());
      JS_SetPropertyStr(ctx, js_custom_claims, name.c_str(), buf);
    }

    auto r = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, r, "claims", js_claims);
    JS_SetPropertyStr(ctx, r, "customClaims", js_custom_claims);

    return r;
  }

#pragma clang diagnostic pop

}