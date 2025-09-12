// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/js/core/wrapped_value.h"
#include "ccf/js/extensions/ccf/gov.h"
#include "js/global_class_ids.h"
#include "js/permissions_checks.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#include <random>

using namespace ccf::js;

TEST_CASE("Check KV Map access")
{
  constexpr auto public_internal_table_name = "public:ccf.internal.table";
  constexpr auto private_internal_table_name = "ccf.internal.table";

  constexpr auto public_gov_table_name = "public:ccf.gov.table";
  constexpr auto private_gov_table_name = "ccf.gov.table";

  constexpr auto public_app_table_name = "public:table";
  constexpr auto private_app_table_name = "table";
  {
    INFO("In application context");
    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, public_internal_table_name) ==
        KVAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, private_internal_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Governance tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, public_gov_table_name) ==
        KVAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, private_gov_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Public application tables are read-write");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, public_app_table_name) ==
        KVAccessPermissions::READ_WRITE);

      {
        INFO(
          "Unless the operation is read-only, in which case they're read-only");
        REQUIRE(
          check_kv_map_access(TxAccess::APP_RO, public_app_table_name) ==
          KVAccessPermissions::READ_ONLY);
      }
    }

    {
      INFO("Private application tables are read-write");
      REQUIRE(
        check_kv_map_access(TxAccess::APP_RW, private_app_table_name) ==
        KVAccessPermissions::READ_WRITE);

      {
        INFO(
          "Unless the operation is read-only, in which case they're read-only");
        REQUIRE(
          check_kv_map_access(TxAccess::APP_RO, private_app_table_name) ==
          KVAccessPermissions::READ_ONLY);
      }
    }
  }

  {
    INFO("In read-only governance context (ballot, validate, resolve)");
    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, public_internal_table_name) ==
        KVAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, private_internal_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Governance tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, public_gov_table_name) ==
        KVAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, private_gov_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Public application cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, public_app_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Private application cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RO, private_app_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }
  }

  {
    INFO("In read-write governance context (apply)");

    {
      INFO("Public internal tables are read-only");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, public_internal_table_name) ==
        KVAccessPermissions::READ_ONLY);
    }

    {
      INFO("Private tables in internal namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, private_internal_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Governance tables are read-write");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, public_gov_table_name) ==
        KVAccessPermissions::READ_WRITE);
    }

    {
      INFO("Private tables in governance namespace cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, private_gov_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }

    {
      INFO("Public applications tables cannot be read, but can be written to");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, public_app_table_name) ==
        KVAccessPermissions::WRITE_ONLY);
    }

    {
      INFO("Private applications tables cannot even be read");
      REQUIRE(
        check_kv_map_access(TxAccess::GOV_RW, private_app_table_name) ==
        KVAccessPermissions::ILLEGAL);
    }
  }
}

bool str_contains(const std::string& s, std::string_view sv)
{
  const auto b = s.find(sv) != std::string::npos;
  if (!b)
  {
    fmt::print("Didn't find\n {}\nin\n {}\n", sv, s);
  }
  return b;
}

bool str_contains(const std::optional<std::string>& s, std::string_view sv)
{
  return str_contains(s.value_or(""), sv);
}

// Returns error string, or nullopt if validation succeeded
std::optional<std::string> call_validate_constitution(
  const std::string& constitution,
  ccf::js::extensions::ExtensionPtr extra_extension = nullptr,
  const std::string& module_suffix = "")
{
  ccf::js::core::Context ctx(TxAccess::GOV_RO);

  ctx.add_extension(std::make_shared<ccf::js::extensions::GovExtension>());

  if (extra_extension != nullptr)
  {
    ctx.add_extension(extra_extension);
  }

  const auto path = "/path/to/constitution";

  auto module = fmt::format(
                  "export function call_validate () {{\n"
                  "  let constitution = {};\n"
                  "  return ccf.gov.validateConstitution(constitution);\n"
                  "}}",
                  constitution) +
    module_suffix;

  auto func = ctx.get_exported_function(module, "call_validate", path);

  const auto result = ctx.call_with_rt_options(
    func, {}, std::nullopt, ccf::js::core::RuntimeLimitsPolicy::NONE);
  if (result.is_true())
  {
    return std::nullopt;
  }

  auto [reason, trace] = ctx.error_message();
  return reason;
}

int64_t global_side_effect_value = 0;

JSValue js_side_effect(
  [[maybe_unused]] JSContext* ctx,
  [[maybe_unused]] JSValueConst this_val,
  [[maybe_unused]] int argc,
  [[maybe_unused]] JSValueConst* argv)
{
  if (argc != 1)
  {
    return JS_ThrowTypeError(ctx, "Passed %d arguments, but expected 1", argc);
  }

  if (JS_ToInt64(ctx, &global_side_effect_value, argv[0]) < 0)
  {
    return ccf::js::core::constants::Exception;
  }

  return ccf::js::core::constants::Undefined;
}

class SideEffectExtension : public ccf::js::extensions::ExtensionInterface
{
public:
  size_t n = 0;

  SideEffectExtension() = default;

  void install(ccf::js::core::Context& ctx) override
  {
    auto side_effect_func = ctx.new_c_function(js_side_effect, "setGlobal", 1);
    ctx.get_or_create_global_property("setGlobal", std::move(side_effect_func));
  }
};

TEST_CASE("Constitution validation")
{
  {
    INFO("not a string");
    for (const auto& c : {"1", "1 + 2", "{}", "true", "null"})
    {
      const auto error = call_validate_constitution(c);
      REQUIRE(error.has_value());
      REQUIRE(str_contains(error, "not a string"));
    }
  }

  {
    INFO("empty");
    for (const auto& c : {"``", "\"\""})
    {
      const auto error = call_validate_constitution(c);
      REQUIRE(error.has_value());
      REQUIRE(str_contains(error, "empty"));
    }
  }

  {
    INFO("does not compile");
    for (const auto& c : {"`this is not syntactically valid JavaScript`"})
    {
      const auto error = call_validate_constitution(c);
      REQUIRE(error.has_value());
      REQUIRE(str_contains(error, "Failed to compile"));
    }
  }

  {
    INFO("missing validate");
    for (const auto& c : {R"!!!(`
export function resolve(proposal, proposerId, votes) {}
export function apply(proposal, proposerId) {}
`)!!!"})
    {
      const auto error = call_validate_constitution(c);
      REQUIRE(error.has_value());
      REQUIRE(str_contains(error, "Failed to find export 'validate'"));
    }
  }

  {
    INFO("missing resolve");
    for (const auto& c : {R"!!!(`
export function validate(input) {}
export function apply(proposal, proposerId) {}
`)!!!"})
    {
      const auto error = call_validate_constitution(c);
      REQUIRE(error.has_value());
      REQUIRE(str_contains(error, "Failed to find export 'resolve'"));
    }
  }

  {
    INFO("missing apply");
    for (const auto& c : {R"!!!(`
export function validate(input) {}
export function resolve(proposal, proposerId, votes) {}
`)!!!"})
    {
      const auto error = call_validate_constitution(c);
      REQUIRE(error.has_value());
      REQUIRE(str_contains(error, "Failed to find export 'apply'"));
    }
  }

  {
    INFO("valid");

    for (const auto& c :
         {R"!!!(`
export function validate(input) {}
export function resolve(proposal, proposerId, votes) {}
export function apply(proposal, proposerId) {}
`)!!!",
          // Alternate signature for resolve, taking additional proposalId arg
          R"!!!(`
export function validate(input) {}
export function resolve(proposal, proposerId, votes, proposalId) {}
export function apply(proposal, proposerId) {}
`)!!!"})
    {
      const auto error = call_validate_constitution(c);
      REQUIRE(!error.has_value());
    }
  }

  {
    INFO("sandboxing");

    {
      INFO(
        "code in outer module (existing constitution) may have side effects");
      const auto constitution = R"!!!(`
export function validate(input) {}
export function resolve(proposal, proposerId, votes) {}
export function apply(proposal, proposerId) {}
`)!!!";

      auto side_effect_extension = std::make_shared<SideEffectExtension>();
      REQUIRE(global_side_effect_value == 0);
      const auto error = call_validate_constitution(
        constitution, {side_effect_extension}, "\nsetGlobal(42);");
      REQUIRE(!error.has_value());
      REQUIRE(global_side_effect_value == 42);
    }

    {
      INFO("code inside proposed constitution has no side effects");
      const auto constitution = R"!!!(`
export function validate(input) {}
export function resolve(proposal, proposerId, votes) {}
export function apply(proposal, proposerId) {}
setGlobal(100)
`)!!!";

      auto side_effect_extension = std::make_shared<SideEffectExtension>();
      REQUIRE(global_side_effect_value == 42);
      auto error =
        call_validate_constitution(constitution, {side_effect_extension});
      REQUIRE(!error.has_value());
      REQUIRE(global_side_effect_value == 42); // No change
    }
  }

  {
    INFO("error detectability");

    {
      INFO("global throws");
      const auto constitution = R"!!!(`
export function validate(input) {}
export function resolve(proposal, proposerId, votes) {}
export function apply(proposal, proposerId) {}

throw new Error(`I'm not happy`);
`)!!!";

      REQUIRE_THROWS(call_validate_constitution(constitution));
    }

    {
      INFO("incorrect signatures");

      {
        INFO("arg count is checked");

        {
          INFO("validate low");
          const auto constitution = R"!!!(`
export function validate() {}
export function resolve(proposal, proposerId, votes) {}
export function apply(proposal, proposerId) {}
`)!!!";

          auto error = call_validate_constitution(constitution);
          REQUIRE(error.has_value());
          REQUIRE(str_contains(
            error,
            "exports function validate with 0 args, expected 1 arg (input)"));
        }

        {
          INFO("validate high");
          const auto constitution = R"!!!(`
export function validate(a, b) {}
export function resolve(proposal, proposerId, votes) {}
export function apply(proposal, proposerId) {}
`)!!!";

          auto error = call_validate_constitution(constitution);
          REQUIRE(error.has_value());
          REQUIRE(str_contains(
            error,
            "exports function validate with 2 args, expected 1 arg (input)"));
        }

        {
          INFO("resolve low");
          const auto constitution = R"!!!(`
export function validate(input) {}
export function resolve(a, b) {}
export function apply(proposal, proposerId) {}
`)!!!";

          auto error = call_validate_constitution(constitution);
          REQUIRE(error.has_value());
          REQUIRE(str_contains(
            error,
            "exports function resolve with 2 args, expected between 3 and 4 "
            "args (proposal, proposerId, votes[, proposalId])"));
        }

        {
          INFO("resolve high");
          const auto constitution = R"!!!(`
export function validate(input) {}
export function resolve(a, b, c, d, e) {}
export function apply(proposal, proposerId) {}
`)!!!";

          auto error = call_validate_constitution(constitution);
          REQUIRE(error.has_value());
          REQUIRE(str_contains(
            error,
            "exports function resolve with 5 args, expected between 3 and 4 "
            "args (proposal, proposerId, votes[, proposalId])"));
        }

        {
          INFO("apply low");
          const auto constitution = R"!!!(`
export function validate(input) {}
export function resolve(proposal, proposerId, votes) {}
export function apply(a) {}
`)!!!";

          auto error = call_validate_constitution(constitution);
          REQUIRE(error.has_value());
          REQUIRE(str_contains(
            error,
            "exports function apply with 1 arg, expected 2 args (proposal, "
            "proposerId)"));
        }

        {
          INFO("apply high");
          const auto constitution = R"!!!(`
export function validate(input) {}
export function resolve(proposal, proposerId, votes) {}
export function apply(a, b, c) {}
`)!!!";

          auto error = call_validate_constitution(constitution);
          REQUIRE(error.has_value());
          REQUIRE(str_contains(
            error,
            "exports function apply with 3 args, expected 2 args (proposal, "
            "proposerId)"));
        }
      }

      {
        INFO("arg names are not checked");
        const auto constitution = R"!!!(`
export function validate(a) {}
export function resolve(a, b, c) {}
export function apply(a, b) {}
`)!!!";

        auto error = call_validate_constitution(constitution);
        REQUIRE_FALSE(error.has_value());
      }
    }

    {
      INFO("null accesses can't be checked");
      const auto constitution = R"!!!(`
export function validate(input) {}
export function resolve(proposal, proposerId, votes) {}
export function apply(proposal, proposerId) {}

foo.bar.baz;
`)!!!";

      auto error = call_validate_constitution(constitution);
      REQUIRE_FALSE(error.has_value());
    }
  }
}

int main(int argc, char** argv)
{
  ccf::js::register_class_ids();

  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}