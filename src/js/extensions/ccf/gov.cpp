// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/ccf/gov.h"

#include "ccf/js/core/context.h"
#include "js/checks.h"

#include <iostream>
#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    JSValue js_validate_constitution(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      JSValueConst* argv)
    {
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);
      }

      auto arg = jsctx.wrap(argv[0]);
      if (!arg.is_str())
      {
        return JS_ThrowTypeError(ctx, "constitution is not a string");
      }

      auto constitution = jsctx.to_str(arg);
      if (!constitution.has_value())
      {
        return JS_ThrowTypeError(ctx, "constitution is not a string");
      }

      if (constitution->empty())
      {
        return JS_ThrowTypeError(ctx, "constitution is empty");
      }

      const std::string path("proposed constitution");

      struct ArgsSpec
      {
        std::vector<std::string> required_args;
        std::vector<std::string> optional_args;
      };

      std::map<std::string, ArgsSpec> funcs_to_args;
      funcs_to_args["validate"] = {{"input"}, {}};
      funcs_to_args["resolve"] = {
        {"proposal", "proposerId", "votes"}, {"proposalId"}};
      funcs_to_args["apply"] = {{"proposal", "proposerId"}, {}};
      for (const auto& [fn_name, args_spec] : funcs_to_args)
      {
        try
        {
          // Create a new context to lookup this function, since doing so
          // requires evaluating the module, and that must have no side effects
          // or write to the parent's global environment.
          ccf::js::core::Context sub_context(ccf::js::TxAccess::GOV_RO);
          auto func = sub_context.get_exported_function(
            constitution.value(), fn_name, path);

          auto length_val = sub_context.get_property(func.val, "length");
          uint32_t length = 0;
          if (JS_ToUint32(ctx, &length, length_val.val) < 0)
          {
            return ccf::js::core::constants::Exception;
          }

          auto plural_arg = [](size_t n) { return n == 1 ? "arg" : "args"; };

          const auto actual = fmt::format(
            "{} exports function {} with {} {}",
            path,
            fn_name,
            length,
            plural_arg(length));

          if (args_spec.optional_args.empty())
          {
            const auto required_size = args_spec.required_args.size();
            if (length != required_size)
            {
              auto err = fmt::format(
                "{}, expected {} {} ({})",
                actual,
                required_size,
                plural_arg(required_size),
                fmt::join(args_spec.required_args, ", "));
              return JS_ThrowTypeError(ctx, "%s", err.c_str());
            }
          }
          else
          {
            const auto min_size = args_spec.required_args.size();
            const auto max_size = min_size + args_spec.optional_args.size();

            if (length < min_size || length > max_size)
            {
              auto err = fmt::format(
                "{}, expected between {} and {} args ({}[, {}])",
                actual,
                min_size,
                max_size,
                fmt::join(args_spec.required_args, ", "),
                fmt::join(args_spec.optional_args, ", "));
              return JS_ThrowTypeError(ctx, "%s", err.c_str());
            }
          }
        }
        catch (const std::exception& e)
        {
          return JS_ThrowTypeError(
            ctx,
            "%s does not export a function named %s: %s",
            path.c_str(),
            fn_name.c_str(),
            e.what());
        }
      }

      return ccf::js::core::constants::True;
    }
  }

  void GovExtension::install(js::core::Context& ctx)
  {
    auto gov = ctx.new_obj();

    JS_CHECK_OR_THROW(gov.set(
      "validateConstitution",
      ctx.new_c_function(js_validate_constitution, "validateConstitution", 1)));

    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());
    JS_CHECK_OR_THROW(ccf.set("gov", std::move(gov)));
  }
}
