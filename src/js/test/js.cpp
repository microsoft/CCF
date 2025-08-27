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
  return s.find(sv) != std::string::npos;
}

bool str_contains(const std::optional<std::string>& s, std::string_view sv)
{
  return str_contains(s.value_or(""), sv);
}

// Returns error string, or nullopt if validation succeeded
std::optional<std::string> call_validate_constitution(
  const std::string& constitution)
{
  ccf::js::core::Context ctx(TxAccess::GOV_RO);

  ctx.add_extension(std::make_shared<ccf::js::extensions::GovExtension>());

  const auto path = "/path/to/constitution";

  auto module = fmt::format(
    "export function call_validate () {{\n"
    "  let constitution = {};\n"
    "  return ccf.gov.validateConstitution(constitution);\n"
    "}}",
    constitution);

  auto func = ctx.get_exported_function(module, "call_validate", path);

  const auto result = ctx.inner_call(func, {});
  if (result.is_true())
  {
    return std::nullopt;
  }

  auto [reason, trace] = ctx.error_message();
  return reason;
}

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
export function apply() {}
export function resolve() {}
`)!!!"})
    {
      const auto error = call_validate_constitution(c);
      REQUIRE(error.has_value());
      REQUIRE(str_contains(error, "not find function validate"));
    }
  }

  {
    INFO("missing apply");
    for (const auto& c : {R"!!!(`
export function validate() {}
export function resolve() {}
`)!!!"})
    {
      const auto error = call_validate_constitution(c);
      REQUIRE(error.has_value());
      REQUIRE(str_contains(error, "not find function apply"));
    }
  }

  {
    INFO("missing resolve");
    for (const auto& c : {R"!!!(`
export function validate() {}
export function apply() {}
`)!!!"})
    {
      const auto error = call_validate_constitution(c);
      REQUIRE(error.has_value());
      REQUIRE(str_contains(error, "not find function resolve"));
    }
  }

  {
    INFO("good");
    for (const auto& c : {R"!!!(`
export function validate() {}
export function apply() {}
export function resolve() {}
`)!!!"})
    {
      const auto error = call_validate_constitution(c);
      REQUIRE(!error.has_value());
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