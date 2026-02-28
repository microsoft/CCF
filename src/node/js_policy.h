// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "ccf/js/core/context.h"
#include "ccf/service/tables/jsengine.h"
#include "js/checks.h"
#include "node/cose_common.h"

#include <fmt/format.h>
#include <optional>
#include <string>

namespace ccf::policy
{
  static ccf::js::core::JSWrappedValue protected_header_to_js_val(
    ccf::js::core::Context& ctx, const cose::Sign1ProtectedHeader& phdr)
  {
    auto obj = ctx.new_obj();

    JS_CHECK_OR_THROW(obj.set_int64("alg", phdr.alg));

    if (phdr.cty.has_value())
    {
      if (std::holds_alternative<int64_t>(phdr.cty.value()))
      {
        JS_CHECK_OR_THROW(
          obj.set_int64("cty", std::get<int64_t>(phdr.cty.value())));
      }
      else if (std::holds_alternative<std::string>(phdr.cty.value()))
      {
        JS_CHECK_OR_THROW(obj.set(
          "cty", ctx.new_string(std::get<std::string>(phdr.cty.value()))));
      }
    }

    auto x5_array = ctx.new_array();
    size_t i = 0;
    for (const auto& der_cert : phdr.x5chain)
    {
      auto pem = ccf::crypto::cert_der_to_pem(der_cert);
      JS_CHECK_OR_THROW(x5_array.set_at_index(i++, ctx.new_string(pem.str())));
    }
    JS_CHECK_OR_THROW(obj.set("x5chain", std::move(x5_array)));

    auto cwt = ctx.new_obj();
    if (!phdr.cwt.iss.empty())
    {
      JS_CHECK_OR_THROW(cwt.set("iss", ctx.new_string(phdr.cwt.iss)));
    }
    if (!phdr.cwt.sub.empty())
    {
      JS_CHECK_OR_THROW(cwt.set("sub", ctx.new_string(phdr.cwt.sub)));
    }
    if (phdr.cwt.iat.has_value())
    {
      JS_CHECK_OR_THROW(cwt.set_int64("iat", phdr.cwt.iat.value()));
    }
    if (phdr.cwt.svn.has_value())
    {
      JS_CHECK_OR_THROW(cwt.set_int64("svn", phdr.cwt.svn.value()));
    }
    JS_CHECK_OR_THROW(obj.set("cwt", std::move(cwt)));

    return obj;
  }

  struct ReceiptPolicyInput
  {
    cose::CcfCoseReceiptPhdr phdr;
    std::vector<cose::Leaf> leaves;
  };

  static ccf::js::core::JSWrappedValue receipt_to_js_val(
    ccf::js::core::Context& ctx, const ReceiptPolicyInput& receipt)
  {
    auto obj = ctx.new_obj();

    JS_CHECK_OR_THROW(obj.set_int64("alg", receipt.phdr.alg));
    JS_CHECK_OR_THROW(obj.set_int64("vds", receipt.phdr.vds));

    if (!receipt.phdr.kid.empty())
    {
      auto kid_str =
        std::string(receipt.phdr.kid.begin(), receipt.phdr.kid.end());
      JS_CHECK_OR_THROW(obj.set("kid", ctx.new_string(kid_str)));
    }

    auto cwt = ctx.new_obj();
    if (!receipt.phdr.cwt.iss.empty())
    {
      JS_CHECK_OR_THROW(cwt.set("iss", ctx.new_string(receipt.phdr.cwt.iss)));
    }
    if (!receipt.phdr.cwt.sub.empty())
    {
      JS_CHECK_OR_THROW(cwt.set("sub", ctx.new_string(receipt.phdr.cwt.sub)));
    }
    if (receipt.phdr.cwt.iat.has_value())
    {
      JS_CHECK_OR_THROW(cwt.set_int64("iat", receipt.phdr.cwt.iat.value()));
    }
    JS_CHECK_OR_THROW(obj.set("cwt", std::move(cwt)));

    auto ccf_obj = ctx.new_obj();
    if (!receipt.phdr.ccf.txid.empty())
    {
      JS_CHECK_OR_THROW(
        ccf_obj.set("txid", ctx.new_string(receipt.phdr.ccf.txid)));
    }
    JS_CHECK_OR_THROW(obj.set("ccf", std::move(ccf_obj)));

    // Leaves: one per Merkle inclusion proof
    auto leaves_arr = ctx.new_array();
    for (size_t k = 0; k < receipt.leaves.size(); ++k)
    {
      const auto& leaf = receipt.leaves[k];
      auto leaf_obj = ctx.new_obj();
      if (!leaf.claims_digest.empty())
      {
        auto hex = ccf::ds::to_hex(leaf.claims_digest);
        JS_CHECK_OR_THROW(leaf_obj.set("claims_digest", ctx.new_string(hex)));
      }
      if (!leaf.commit_evidence.empty())
      {
        JS_CHECK_OR_THROW(leaf_obj.set(
          "commit_evidence", ctx.new_string(leaf.commit_evidence)));
      }
      if (!leaf.write_set_digest.empty())
      {
        auto hex = ccf::ds::to_hex(leaf.write_set_digest);
        JS_CHECK_OR_THROW(
          leaf_obj.set("write_set_digest", ctx.new_string(hex)));
      }
      JS_CHECK_OR_THROW(leaves_arr.set_at_index(k, std::move(leaf_obj)));
    }
    JS_CHECK_OR_THROW(obj.set("leaves", std::move(leaves_arr)));

    return obj;
  }

  struct TransparentStatementPolicyInput
  {
    cose::Sign1ProtectedHeader phdr;
    std::vector<ReceiptPolicyInput> receipts;
  };

  static std::optional<std::string> apply_node_join_policy(
    const std::string& policy_script,
    const std::vector<TransparentStatementPolicyInput>& statements)
  {
    ccf::js::core::Context interpreter(ccf::js::TxAccess::GOV_RO);

    ccf::js::core::JSWrappedValue apply_func;
    try
    {
      apply_func = interpreter.get_exported_function(
        policy_script, "apply", "node_join_policy");
    }
    catch (const std::exception& e)
    {
      return fmt::format("Invalid code update policy module: {}", e.what());
    }

    // Build JS array of transparent statements, each with phdr + receipts
    auto ts_array = interpreter.new_array();
    for (size_t i = 0; i < statements.size(); ++i)
    {
      auto ts_obj = interpreter.new_obj();

      auto phdr_val =
        protected_header_to_js_val(interpreter, statements[i].phdr);
      JS_CHECK_OR_THROW(ts_obj.set("phdr", std::move(phdr_val)));

      auto receipts_arr = interpreter.new_array();
      for (size_t j = 0; j < statements[i].receipts.size(); ++j)
      {
        auto receipt_val =
          receipt_to_js_val(interpreter, statements[i].receipts[j]);
        JS_CHECK_OR_THROW(receipts_arr.set_at_index(j, std::move(receipt_val)));
      }
      JS_CHECK_OR_THROW(ts_obj.set("receipts", std::move(receipts_arr)));

      JS_CHECK_OR_THROW(ts_array.set_at_index(i, std::move(ts_obj)));
    }

    const auto result = interpreter.call_with_rt_options(
      apply_func,
      {ts_array},
      ccf::JSRuntimeOptions{},
      ccf::js::core::RuntimeLimitsPolicy::NONE);

    if (result.is_exception())
    {
      auto [reason, trace] = interpreter.error_message();
      return fmt::format(
        "Code update policy threw: {}\n{}",
        reason,
        trace.value_or("<no trace>"));
    }

    if (result.is_str())
    {
      // Policy returned a string => reject
      return interpreter.to_str(result);
    }

    if (JS_IsBool(result.val) != 0 && result.is_true())
    {
      // Policy returned boolean true => accepted
      return std::nullopt;
    }

    return fmt::format(
      "Unexpected return value from code update policy: {}",
      interpreter.to_str(result).value_or("<unknown>"));
  }
}
