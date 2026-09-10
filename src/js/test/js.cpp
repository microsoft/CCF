// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/js/core/wrapped_value.h"
#include "ccf/js/extensions/ccf/gov.h"
#include "ccf/js/extensions/ccf/historical.h"
#include "ccf/js/extensions/ccf/kv.h"
#include "js/global_class_ids.h"
#include "js/permissions_checks.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/untyped_map.h"
#include "node/tx_receipt_impl.h"

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

  {
    INFO("Every permission is described accurately");
    REQUIRE(
      explain_kv_map_access(KVAccessPermissions::READ_WRITE, TxAccess::APP_RW)
        .contains("read-write"));
    REQUIRE(
      explain_kv_map_access(KVAccessPermissions::READ_ONLY, TxAccess::APP_RW)
        .contains("read-only"));
    REQUIRE(
      explain_kv_map_access(KVAccessPermissions::WRITE_ONLY, TxAccess::GOV_RW)
        .contains("write-only"));
    REQUIRE(
      explain_kv_map_access(KVAccessPermissions::ILLEGAL, TxAccess::APP_RW)
        .contains("inaccessible"));

    {
      INFO("A permitted table is never described as inaccessible");
      REQUIRE(!explain_kv_map_access(
                 KVAccessPermissions::READ_WRITE, TxAccess::APP_RW)
                 .contains("inaccessible"));
    }

    for (const auto permission_value : {4, 5, 255})
    {
      INFO("Unexpected permission bits are rejected");
      CAPTURE(permission_value);
      REQUIRE_THROWS_WITH_AS(
        explain_kv_map_access(
          static_cast<KVAccessPermissions>(permission_value), TxAccess::APP_RW),
        fmt::format("Unexpected KV access permission: {}", permission_value),
        std::logic_error);
    }
  }
}

bool str_contains(const std::string& s, std::string_view sv)
{
  const auto b = s.contains(sv);
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

using KVMap = ccf::kv::untyped::Map;

// Returns an error message if the JS script throws.
std::optional<std::string> run_kv_script(
  ccf::kv::Tx& tx, TxAccess access, const std::string& body)
{
  ccf::js::core::Context ctx(access);
  ctx.add_extension(std::make_shared<ccf::js::extensions::KvExtension>(&tx));

  const auto module = fmt::format("export function run() {{\n{}\n}}", body);
  auto func = ctx.get_exported_function(module, "run", "/test/kv_script");

  const auto result = ctx.call_with_rt_options(
    func, {}, std::nullopt, ccf::js::core::RuntimeLimitsPolicy::NONE);
  if (!result.is_exception())
  {
    return std::nullopt;
  }

  auto [reason, trace] = ctx.error_message();
  return reason;
}

bool table_contains(ccf::kv::Tx& tx, const std::string& table_name)
{
  auto* handle = tx.ro<KVMap>(table_name);
  return handle->has({'k'});
}

// Access is resolved once, when a handle is created. These cases confirm that
// decision cannot then be bypassed by re-targeting a method at another
// receiver, or by mutating the handle from JS.
TEST_CASE("KV handle permissions")
{
  constexpr auto app_table = "public:my_app_table";
  constexpr auto gov_table = "public:ccf.gov.my_custom_table";
  constexpr auto private_app_table = "my_app_table";

  // Every script below operates on a single key, and refers to tables by these
  // names rather than repeating the string literals
  const auto js_prelude = fmt::format(
    R"JS(
const key = new Uint8Array([107]).buffer;
const value = new Uint8Array([118]).buffer;
const appTable = "{}";
const govTable = "{}";
const privateAppTable = "{}";
)JS",
    app_table,
    gov_table,
    private_app_table);

  auto make_store = []() {
    auto store = std::make_unique<ccf::kv::Store>();
    store->set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
    return store;
  };

  {
    INFO("Permitted operations on a handle still work");

    auto store = make_store();
    auto tx = store->create_tx();

    const auto err = run_kv_script(tx, TxAccess::APP_RW, js_prelude + R"JS(
const t = ccf.kv[appTable];
t.set(key, value);
if (!t.has(key)) { throw new Error("has"); }
if (new Uint8Array(t.get(key))[0] !== 118) { throw new Error("get"); }
if (t.size !== 1) { throw new Error("size"); }
let seen = 0;
t.forEach(() => { seen++; });
if (seen !== 1) { throw new Error("forEach"); }
t.delete(key);
if (t.has(key)) { throw new Error("delete"); }
)JS");
    REQUIRE(!err.has_value());
  }

  {
    INFO("Restrictions are enforced on a directly-used handle");

    auto store = make_store();
    auto tx = store->create_tx();

    const auto err = run_kv_script(tx, TxAccess::APP_RW, js_prelude + R"JS(
ccf.kv[govTable].set(key, value);
)JS");
    REQUIRE(!table_contains(tx, gov_table));
    REQUIRE(str_contains(err, "Cannot call \"set\" on table named"));
    REQUIRE(str_contains(err, gov_table));
  }

  {
    INFO("A permitted method cannot be re-targeted at a forged receiver");

    auto store = make_store();
    auto tx = store->create_tx();

    const auto err = run_kv_script(tx, TxAccess::APP_RW, js_prelude + R"JS(
ccf.kv[appTable].set.call({ _map_name: govTable }, key, value);
)JS");
    REQUIRE(!table_contains(tx, gov_table));
    REQUIRE(str_contains(err, "KV Map Handle object expected"));
  }

  {
    INFO("A permitted method cannot be re-targeted at a restricted handle");

    auto store = make_store();
    auto tx = store->create_tx();

    const auto err = run_kv_script(tx, TxAccess::APP_RW, js_prelude + R"JS(
ccf.kv[appTable].set.call(ccf.kv[govTable], key, value);
)JS");
    REQUIRE(!table_contains(tx, gov_table));
    REQUIRE(str_contains(err, "Cannot perform this operation on table named"));
    REQUIRE(str_contains(err, gov_table));
  }

  {
    INFO("A handle method cannot be invoked via a derived object");

    auto store = make_store();
    auto tx = store->create_tx();

    const auto err = run_kv_script(tx, TxAccess::APP_RW, js_prelude + R"JS(
Object.create(ccf.kv[appTable]).set(key, value);
)JS");
    REQUIRE(!table_contains(tx, app_table));
    REQUIRE(str_contains(err, "KV Map Handle object expected"));
  }

  {
    INFO("A handle method cannot be invoked via a Proxy");

    auto store = make_store();
    auto tx = store->create_tx();

    const auto err = run_kv_script(tx, TxAccess::APP_RW, js_prelude + R"JS(
const p = new Proxy(ccf.kv[appTable], {
  get(target, prop) {
    return prop === "_map_name" ? govTable : Reflect.get(target, prop);
  }
});
p.set(key, value);
)JS");
    REQUIRE(!table_contains(tx, gov_table));
    REQUIRE(str_contains(err, "KV Map Handle object expected"));
  }

  {
    INFO("Copying a handle's properties does not copy its identity");

    auto store = make_store();
    auto tx = store->create_tx();

    // Spreading a handle onto a plain object was the original forgery
    // primitive, when the table name was a JS property
    const auto err = run_kv_script(tx, TxAccess::APP_RW, js_prelude + R"JS(
const copy = { ...ccf.kv[appTable], _map_name: govTable };
copy.set(key, value);
)JS");
    REQUIRE(!table_contains(tx, gov_table));
    REQUIRE(str_contains(err, "KV Map Handle object expected"));
  }

  {
    INFO("A handle method cannot be bound to a forged receiver");

    auto store = make_store();
    auto tx = store->create_tx();

    const auto err = run_kv_script(tx, TxAccess::APP_RW, js_prelude + R"JS(
ccf.kv[appTable].set.bind({ _map_name: govTable })(key, value);
)JS");
    REQUIRE(!table_contains(tx, gov_table));
    REQUIRE(str_contains(err, "KV Map Handle object expected"));
  }

  {
    INFO("A denied method does not describe an unrelated permitted table");

    auto store = make_store();
    auto tx = store->create_tx();

    // The denied stub reports the table of whatever receiver it is given, so
    // that description must remain true when the receiver is permitted
    const auto err = run_kv_script(tx, TxAccess::APP_RW, js_prelude + R"JS(
ccf.kv[govTable].set.call(ccf.kv[appTable], key, value);
)JS");
    REQUIRE(!table_contains(tx, gov_table));
    REQUIRE(str_contains(err, app_table));
    REQUIRE(str_contains(err, "read-write"));
    REQUIRE(!err.value().contains("inaccessible"));
  }

  {
    INFO("Setting _map_name on a permitted handle does not redirect it");

    auto store = make_store();
    auto tx = store->create_tx();

    const auto err = run_kv_script(tx, TxAccess::APP_RW, js_prelude + R"JS(
const t = ccf.kv[appTable];
t._map_name = govTable;
t.set(key, value);
)JS");
    REQUIRE(!err.has_value());
    REQUIRE(!table_contains(tx, gov_table));
    REQUIRE(table_contains(tx, app_table));
  }

  {
    INFO("Governance ballots cannot read private application tables");

    auto store = make_store();

    {
      auto tx = store->create_tx();
      tx.rw<KVMap>(private_app_table)->put({'k'}, {'v'});
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    auto tx = store->create_tx();
    const auto err = run_kv_script(tx, TxAccess::GOV_RO, js_prelude + R"JS(
const gov = ccf.kv["public:ccf.gov.proposals_info"];
const leaked = gov.get.call({ _map_name: privateAppTable }, key);
if (leaked !== undefined) {
  throw new Error("Leaked " + new Uint8Array(leaked));
}
)JS");
    REQUIRE(err.has_value());
    REQUIRE(!err.value().contains("Leaked"));
    REQUIRE(str_contains(err, "KV Map Handle object expected"));
  }
}

// Handle state is owned by C++ and released by a class finalizer, so it is only
// freed if QuickJS destroys every handle. These cases are the ones plain
// reference counting would not cover. Leaks are detected by the ASAN build.
TEST_CASE("KV handle lifetime")
{
  constexpr auto js_prelude = R"JS(
const key = new Uint8Array([107]).buffer;
const value = new Uint8Array([118]).buffer;
)JS";

  auto run = [&](const std::string& body) {
    ccf::kv::Store store;
    store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
    auto tx = store.create_tx();
    return run_kv_script(tx, TxAccess::APP_RW, js_prelude + body);
  };

  {
    INFO("Handle in a reference cycle, which only the cycle collector breaks");
    REQUIRE(!run(R"JS(
const t = ccf.kv["tbl"];
t.self = t;
t.indirect = { back: t };
t.set(key, value);
)JS")
               .has_value());
  }

  {
    INFO("Handle still reachable when the interpreter is destroyed");
    REQUIRE(!run(R"JS(
globalThis.escaped = ccf.kv["tbl"];
globalThis.escaped.set(key, value);
)JS")
               .has_value());
  }

  {
    INFO("Handle live while an exception unwinds");
    REQUIRE(run(R"JS(
globalThis.escaped = ccf.kv["tbl"];
throw new Error("boom");
)JS")
              .has_value());
  }

  {
    INFO("Handle whose methods were all replaced by denied stubs");
    REQUIRE(run(R"JS(
ccf.kv["public:ccf.gov.tbl"].set(key, value);
)JS")
              .has_value());
  }
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

static int get_ref_count(JSValue v)
{
  REQUIRE(JS_VALUE_HAS_REF_COUNT(v));
  auto* p = (JSRefCountHeader*)JS_VALUE_GET_PTR(v);
  return p->ref_count;
}

TEST_CASE("JSWrappedValue copy assignment frees old value")
{
  JSRuntime* rt = JS_NewRuntime();
  REQUIRE(rt != nullptr);
  JSContext* ctx = JS_NewContext(rt);
  REQUIRE(ctx != nullptr);

  // Create two distinct JS objects (heap-allocated, so ref-counted)
  JSValue obj_a = JS_NewObject(ctx); // ref_count == 1
  JSValue obj_b = JS_NewObject(ctx); // ref_count == 1

  // Keep raw copies so we can inspect ref counts after wrapping
  JSValue raw_a = JS_DupValue(ctx, obj_a); // ref_count(a) == 2
  JSValue raw_b = JS_DupValue(ctx, obj_b); // ref_count(b) == 2

  {
    // Wrap both via the rvalue constructor (takes ownership, no dup)
    ccf::js::core::JSWrappedValue wa(ctx, std::move(obj_a));
    ccf::js::core::JSWrappedValue wb(ctx, std::move(obj_b));

    // raw_a has ref 2 (raw_a + wa), raw_b has ref 2 (raw_b + wb)
    REQUIRE(get_ref_count(raw_a) == 2);
    REQUIRE(get_ref_count(raw_b) == 2);

    // Copy-assign: wa = wb.  This should free the old obj_a held by wa
    wa = wb;

    // obj_a should have been freed by the assignment, leaving only raw_a
    REQUIRE(get_ref_count(raw_a) == 1);
    // obj_b should now be referenced by wa, wb, and raw_b
    REQUIRE(get_ref_count(raw_b) == 3);
  }
  // After both wrappers are destroyed, only our raw refs should remain
  REQUIRE(get_ref_count(raw_a) == 1);
  REQUIRE(get_ref_count(raw_b) == 1);

  JS_FreeValue(ctx, raw_a);
  JS_FreeValue(ctx, raw_b);
  JS_FreeContext(ctx);
  JS_FreeRuntime(rt);
}

TEST_CASE("Context::to_str preserves embedded NUL bytes")
{
  ccf::js::core::Context ctx(TxAccess::APP_RW);

  // JS strings are not NUL-terminated internally, and may contain arbitrary
  // embedded NUL bytes. Constructing a std::string from the NUL-terminated
  // buffer returned by JS_ToCString (rather than from the buffer and its
  // real length, as returned by JS_ToCStringLen) would silently truncate at
  // the first embedded NUL. Regression test for that.
  const std::string input("abc\0def", 7);
  REQUIRE(input.size() == 7);

  auto js_str = ctx.new_string_len(input.data(), input.size());
  REQUIRE(js_str.is_str());

  {
    INFO("to_str(const JSWrappedValue&)");
    auto result = ctx.to_str(js_str);
    REQUIRE(result.has_value());
    REQUIRE(*result == input);
  }

  {
    INFO("to_str(const JSValue&)");
    auto result = ctx.to_str(js_str.val);
    REQUIRE(result.has_value());
    REQUIRE(*result == input);
  }

  {
    INFO("to_str(const JSValue&, size_t&)");
    size_t len = 0;
    auto result = ctx.to_str(js_str.val, len);
    REQUIRE(result.has_value());
    REQUIRE(len == input.size());
    REQUIRE(*result == input);
  }

  {
    INFO("to_str(const JSAtom&)");
    JSAtom atom = JS_NewAtomLen(ctx, input.data(), input.size());
    auto result = ctx.to_str(atom);
    JS_FreeAtom(ctx, atom);
    REQUIRE(result.has_value());
    REQUIRE(*result == input);
  }
}

TEST_CASE("Historical state")
{
  class CountingStore : public ccf::kv::Store
  {
  public:
    size_t tx_creations = 0;

    std::unique_ptr<ccf::kv::ReadOnlyTx> create_read_only_tx_ptr() override
    {
      ++tx_creations;
      return ccf::kv::Store::create_read_only_tx_ptr();
    }
  };

  auto store = std::make_shared<CountingStore>();
  auto receipt = std::make_shared<ccf::TxReceiptImpl>(
    std::vector<uint8_t>{1, 2, 3},
    std::nullopt,
    ccf::HistoryTree::Hash{},
    nullptr,
    ccf::NodeId("test-node"),
    std::nullopt);
  auto state =
    std::make_shared<ccf::historical::State>(store, receipt, ccf::TxID{1, 1});
  std::weak_ptr<ccf::historical::State> original_state = state;

  {
    ccf::js::core::Context ctx(TxAccess::APP_RO);
    auto extension =
      std::make_shared<ccf::js::extensions::HistoricalExtension>(nullptr);
    ctx.add_extension(extension);

    auto first = extension->create_historical_state_object(ctx, state);
    REQUIRE_FALSE(first.is_exception());
    REQUIRE(store->tx_creations == 1);
    auto map = first["kv"]["public:records"];
    REQUIRE_FALSE(map.is_exception());
    REQUIRE(ctx.to_str(map["size"]) == "0");

    SUBCASE("Repeated access to the same state")
    {
      auto second = extension->create_historical_state_object(ctx, state);
      REQUIRE_FALSE(second.is_exception());
      REQUIRE(store->tx_creations == 1);
    }

    SUBCASE("A newly retrieved state for the same sequence number")
    {
      auto duplicate = std::make_shared<ccf::historical::State>(*state);
      state.reset();
      auto second = extension->create_historical_state_object(ctx, duplicate);
      REQUIRE_FALSE(second.is_exception());
      REQUIRE_FALSE(original_state.expired());
      REQUIRE(store->tx_creations == 1);
    }

    auto next_state =
      std::make_shared<ccf::historical::State>(store, receipt, ccf::TxID{1, 2});
    auto next = extension->create_historical_state_object(ctx, next_state);
    REQUIRE_FALSE(next.is_exception());
    REQUIRE(ctx.to_str(next["transactionId"]) == "1.2");
    REQUIRE(store->tx_creations == 2);
    REQUIRE(ctx.to_str(map["size"]) == "0");

    state.reset();
    REQUIRE_FALSE(original_state.expired());
  }

  REQUIRE(original_state.expired());
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