// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "js/extensions/ccf/network.h"

#include "ccf/js/core/context.h"
#include "node/network_state.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    JSValue js_network_latest_ledger_secret_seqno(
      JSContext* ctx,
      JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      (void)this_val;
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      if (argc != 0)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected none", argc);
      }

      auto* extension = jsctx.get_extension<NetworkExtension>();

      auto* network = extension->network_state;
      if (network == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Network state is not set");
      }

      auto* tx_ptr = extension->tx;

      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "No transaction available to fetch latest ledger secret seqno");
      }

      int64_t latest_ledger_secret_seqno = 0;

      try
      {
        latest_ledger_secret_seqno =
          network->ledger_secrets->get_latest(*tx_ptr).first;
      }
      catch (const std::exception& e)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to fetch latest ledger secret seqno: %s", e.what());
      }

      return JS_NewInt64(ctx, latest_ledger_secret_seqno);
    }

    JSValue js_network_generate_endorsed_certificate(
      JSContext* ctx,
      JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      (void)this_val;
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      if (argc != 3)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected 3", argc);
      }

      auto* extension = jsctx.get_extension<NetworkExtension>();

      auto* network = extension->network_state;
      if (network == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Network state is not set");
      }

      auto csr_cstr = jsctx.to_str(argv[0]);
      if (!csr_cstr)
      {
        return ccf::js::core::constants::Exception;
      }
      ccf::crypto::Pem csr;
      try
      {
        csr = ccf::crypto::Pem(*csr_cstr);
      }
      catch (const std::exception& e)
      {
        return JS_ThrowInternalError(ctx, "CSR is not valid PEM: %s", e.what());
      }

      auto valid_from_str = jsctx.to_str(argv[1]);
      if (!valid_from_str)
      {
        return ccf::js::core::constants::Exception;
      }
      auto valid_from = *valid_from_str;

      size_t validity_period_days = 0;
      if (JS_ToIndex(ctx, &validity_period_days, argv[2]) < 0)
      {
        return ccf::js::core::constants::Exception;
      }

      try
      {
        auto endorsed_cert = create_endorsed_cert(
          csr,
          valid_from,
          validity_period_days,
          network->identity->priv_key,
          network->identity->cert);

        return JS_NewString(ctx, endorsed_cert.str().c_str());
      }
      catch (const std::exception& e)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to create endorsed cert: %s", e.what());
      }
    }

    JSValue js_network_generate_certificate(
      JSContext* ctx,
      JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      (void)this_val;
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      if (argc != 2)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected 2", argc);
      }

      auto* extension = jsctx.get_extension<NetworkExtension>();

      auto* network = extension->network_state;
      if (network == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Network state is not set");
      }

      auto valid_from_str = jsctx.to_str(argv[0]);
      if (!valid_from_str)
      {
        return ccf::js::core::constants::Exception;
      }
      auto valid_from = *valid_from_str;

      size_t validity_period_days = 0;
      if (JS_ToIndex(ctx, &validity_period_days, argv[1]) < 0)
      {
        return ccf::js::core::constants::Exception;
      }

      try
      {
        auto renewed_cert = network->identity->renew_certificate(
          valid_from, validity_period_days);

        return JS_NewString(ctx, renewed_cert.str().c_str());
      }
      catch (std::exception& exc)
      {
        return JS_ThrowInternalError(ctx, "Error: %s", exc.what());
      }
    }
  }

  void NetworkExtension::install(js::core::Context& ctx)
  {
    auto network = JS_NewObject(ctx);

    JS_SetPropertyStr(
      ctx,
      network,
      "getLatestLedgerSecretSeqno",
      JS_NewCFunction(
        ctx,
        js_network_latest_ledger_secret_seqno,
        "getLatestLedgerSecretSeqno",
        0));
    JS_SetPropertyStr(
      ctx,
      network,
      "generateEndorsedCertificate",
      JS_NewCFunction(
        ctx,
        js_network_generate_endorsed_certificate,
        "generateEndorsedCertificate",
        0));
    JS_SetPropertyStr(
      ctx,
      network,
      "generateNetworkCertificate",
      JS_NewCFunction(
        ctx, js_network_generate_certificate, "generateNetworkCertificate", 0));

    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());
    // NOLINTBEGIN(performance-move-const-arg)
    ccf.set("network", std::move(network));
    // NOLINTEND(performance-move-const-arg)
  }
}
