// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/crypto/verifier.h"
#include "ccf/js/common_context.h"
#include "ccf/service/tables/jsengine.h"
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

    std::ignore = obj.set_int64("alg", phdr.alg);

    if (phdr.cty.has_value())
    {
      if (std::holds_alternative<int64_t>(phdr.cty.value()))
      {
        std::ignore = obj.set_int64("cty", std::get<int64_t>(phdr.cty.value()));
      }
      else if (std::holds_alternative<std::string>(phdr.cty.value()))
      {
        std::ignore = obj.set(
          "cty", ctx.new_string(std::get<std::string>(phdr.cty.value())));
      }
    }

    auto x5_array = ctx.new_array();
    size_t i = 0;
    for (const auto& der_cert : phdr.x5chain)
    {
      auto pem = ccf::crypto::cert_der_to_pem(der_cert);
      std::ignore = x5_array.set_at_index(i++, ctx.new_string(pem.str()));
    }
    std::ignore = obj.set("x5chain", std::move(x5_array));

    auto cwt = ctx.new_obj();
    if (!phdr.cwt.iss.empty())
    {
      std::ignore = cwt.set("iss", ctx.new_string(phdr.cwt.iss));
    }
    if (!phdr.cwt.sub.empty())
    {
      std::ignore = cwt.set("sub", ctx.new_string(phdr.cwt.sub));
    }
    if (phdr.cwt.iat.has_value())
    {
      std::ignore = cwt.set_int64("iat", phdr.cwt.iat.value());
    }
    if (phdr.cwt.svn.has_value())
    {
      std::ignore = cwt.set_int64("svn", phdr.cwt.svn.value());
    }
    std::ignore = obj.set("cwt", std::move(cwt));

    return obj;
  }

  static std::optional<std::string> apply_node_join_policy(
    const std::string& policy_script, const cose::Sign1ProtectedHeader& phdr)
  {
    ccf::js::CommonContext interpreter(ccf::js::TxAccess::GOV_RO);

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

    auto phdr_val = protected_header_to_js_val(interpreter, phdr);

    const auto result = interpreter.call_with_rt_options(
      apply_func,
      {phdr_val},
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

    if (result.is_true())
    {
      // Policy returned true => accepted
      return std::nullopt;
    }

    return fmt::format(
      "Unexpected return value from code update policy: {}",
      interpreter.to_str(result).value_or("<unknown>"));
  }
}
