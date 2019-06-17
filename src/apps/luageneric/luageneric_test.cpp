// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"
#include "ds/files.h"
#include "ds/logger.h"
#include "enclave/appinterface.h"
#include "genesisgen/genesisgen.h"
#include "luainterp/luainterp.h"
#include "node/rpc/jsonrpc.h"
#include "node/rpc/test/node_stub.h"
#include "runtime_config/default_whitelists.h"

#include <iostream>
#include <map>
#include <set>
#include <string>

using namespace ccfapp;
using namespace ccf;
using namespace std;
using namespace jsonrpc;
using namespace nlohmann;

namespace ccf
{
  bool operator==(const MemberInfo& mi0, const MemberInfo& mi1)
  {
    return mi0.status == mi1.status && mi0.keyshare == mi1.keyshare;
  }
}

void check_error(const vector<uint8_t> v, const int expected)
{
  const auto j_error = json::from_msgpack(v);
  CHECK(j_error[ERR][CODE] == expected);
}

template <typename T>
void check_success(const vector<uint8_t> v, const T& expected)
{
  const Response<json> r = json::from_msgpack(v);
  CHECK(T(r.result) == expected);
}

void set_whitelists(GenesisGenerator& network)
{
  for (const auto& wl : default_whitelists)
    network.set_whitelist(wl.first, wl.second);
}

auto init_frontend(
  GenesisGenerator& network,
  StubNotifier& notifier,
  const int n_users,
  const int n_members)
{
  // create users with fake certs (no crypto here)
  for (uint8_t i = 0; i < n_users; i++)
    network.add_user({i});

  for (uint8_t i = 0; i < n_members; i++)
    network.add_member({i});

  set_whitelists(network);

  const auto env_script = R"xxx(
  return {
  __environment = [[
    env = {
      error_codes = {
        PARSE_ERROR = -32700,
        INVALID_REQUEST = -32600,
        METHOD_NOT_FOUND = -32601,
        INVALID_PARAMS = -32602,
        INTERNAL_ERROR = -32603,
        INVALID_CLIENT_SIGNATURE = -32605,
        INVALID_CALLER_ID = -32606,

        INSUFFICIENT_RIGHTS = -32006,
        DENIED = -32007
      }
    }
    function env.jsucc (result)
      return {result = result}
    end

    function env.jerr (code, message)
      return {error = {code = code, message = message}}
    end
  ]]})xxx";

  network.set_app_scripts(
    lua::Interpreter().invoke<nlohmann::json>(env_script));
  network.finalize_raw();
  return get_rpc_handler(network, notifier);
}

void set_default_handler(GenesisGenerator& network, Script dh)
{
  Store::Tx tx;
  tx.get_view(network.app_scripts)->put(UserScriptIds::DEFAULT_HANDLER, dh);
  REQUIRE(tx.commit() == kv::CommitSuccess::OK);
}

using Params = map<string, json>;

auto make_pc(string method, Params params)
{
  return json::to_msgpack(ProcedureCall<Params>{method, 0, params});
}

template <typename F, typename K, typename V>
void check_store_load(F frontend, K k, V v)
{
  const Cert u0 = {0};
  enclave::RPCContext rpc_ctx(0, u0);

  // store
  const auto pc0 = make_pc("store", {{"k", k}, {"v", v}});
  check_success(frontend->process(rpc_ctx, pc0), true);

  // load and check that we get the right result
  const auto pc1 = make_pc("load", {{"k", k}});
  check_success(frontend->process(rpc_ctx, pc1), v);
}

TEST_CASE("simple lua apps")
{
  GenesisGenerator network;
  StubNotifier notifier;
  // create network with 1 user and 3 active members
  auto frontend = init_frontend(network, notifier, 1, 3);
  const Cert u0 = {0};
  enclave::RPCContext rpc_ctx(0, u0);

  SUBCASE("echo")
  {
    constexpr auto app = R"xxx(
    tables, gov_tables, caller_id, method, params = ...

    -- define handlers
    handlers = {}
    function handlers.echo()
      return env.jsucc(params.verb)
    end
    -- call handler
    return handlers[method]()
    )xxx";
    set_default_handler(network, {app});

    // call "echo" function with "hello"
    const string verb = "hello";
    const auto pc = make_pc("echo", {{"verb", verb}});
    check_success(frontend->process(rpc_ctx, pc), verb);
  }

  SUBCASE("store/load different types in generic table")
  {
    constexpr auto app = R"xxx(
    tables, gov_tables, caller_id, method, params = ...

    handlers = {}
    function handlers.store()
      local r = tables.priv0:put(params.k, params.v)
      return env.jsucc(r)
    end

    function handlers.load()
      local v = tables.priv0:get(params.k)
      if not v then
        return env.jerr(env.error_codes.INVALID_PARAMS, "key does not exist")
      end
      return env.jsucc(v)
    end

    return handlers[method]()
    )xxx";
    set_default_handler(network, {app});

    // (1) store/load vector -> vector
    check_store_load(
      frontend,
      vector<string>{"abc", "ddeeeee"}, // key
      vector<int>(100, 99) // value
    );

    // (2) store/load string -> map
    check_store_load(
      frontend,
      string("abc"), // key
      map<string, int>{{"def", 1}, {"ghij", 2}} // value
    );

    // (3) attempt to read non-existing key (set of integers)
    const auto pc = make_pc("load", {{"k", set{5, 6, 7}}});
    check_error(frontend->process(rpc_ctx, pc), ErrorCodes::INVALID_PARAMS);
  }

  SUBCASE("access gov tables")
  {
    constexpr auto app = R"xxx(
    tables, gov_tables, caller_id, method, params = ...

    handlers = {}
    -- allowed
    function handlers.get_members()
      local members = {}
      gov_tables.members:foreach(
        function(k, v) members[tostring(k)] = v end )
      return env.jsucc(members)
    end

    -- not allowed
    function handlers.put_member()
      return env.jsucc(gov_tables.members:put(params.k, params.v))
    end

    return handlers[method]()
    )xxx";
    set_default_handler(network, {app});

    // (1) read out members table
    const auto pc = make_pc("get_members", {});
    // expect to see 3 members in state active
    map<string, MemberInfo> expected = {{"0", {MemberStatus::ACTIVE}},
                                        {"1", {MemberStatus::ACTIVE}},
                                        {"2", {MemberStatus::ACTIVE}}};
    check_success(frontend->process(rpc_ctx, pc), expected);

    // (2) try to write to members table
    const auto pc1 = make_pc(
      "put_member", {{"k", 99}, {"v", MemberInfo{MemberStatus::ACTIVE}}});
    check_error(frontend->process(rpc_ctx, pc1), ErrorCodes::SCRIPT_ERROR);
  }
}

TEST_CASE("simple bank")
{
  GenesisGenerator network;
  StubNotifier notifier;
  // create network with 1 user and 3 active members
  auto frontend = init_frontend(network, notifier, 1, 3);
  const Cert u0 = {0};
  enclave::RPCContext rpc_ctx(0, u0);

  constexpr auto app = R"xxx(
  tables, gov_tables, caller_id, method, params = ...
  handlers = {}
  function handlers.SB_create()
      local dst = params.dst
      if tables.priv0:get(dst) then
        return env.jerr(env.error_codes.INVALID_PARAMS, "account already exists")
      end

      tables.priv0:put(dst, params.amt)
      return env.jsucc(true)
  end

  function handlers.SB_read()
      local acc = params.account
      local amt = tables.priv0:get(acc)
      if not amt then
        return env.jerr(env.error_codes.INVALID_PARAMS, "account " .. acc .. " does not exist")
      end

      return env.jsucc(amt)
  end

  function handlers.SB_transfer()
      local src = params.src
      local dst = params.dst
      local src_n = tables.priv0:get(src)
      if not src_n then
        return env.jerr(env.error_codes.INVALID_PARAMS, "source account does not exist")
      end

      local dst_n = tables.priv0:get(dst)
      if not dst_n then
        return env.jerr(env.error_codes.INVALID_PARAMS, "destination account does not exist")
      end

      local amt = params.amt
      if src_n < amt then
        return env.jerr(env.error_codes.INVALID_PARAMS, "insufficient funds")
      end

      tables.priv0:put(src, src_n - amt)
      tables.priv0:put(dst, dst_n + amt)

      return env.jsucc(true)
  end

  return handlers[method]()
  )xxx";
  set_default_handler(network, {app});

  {
    const auto pc = make_pc("SB_create", {{"dst", 1}, {"amt", 123}});
    check_success<bool>(frontend->process(rpc_ctx, pc), true);

    const auto pc1 = make_pc("SB_read", {{"account", 1}});
    check_success(frontend->process(rpc_ctx, pc1), 123);
  }

  {
    const auto pc = make_pc("SB_create", {{"dst", 2}, {"amt", 999}});
    check_success<bool>(frontend->process(rpc_ctx, pc), true);

    const auto pc1 = make_pc("SB_read", {{"account", 2}});
    check_success(frontend->process(rpc_ctx, pc1), 999);
  }

  {
    const auto pc = make_pc("SB_read", {{"account", 3}});
    check_error(frontend->process(rpc_ctx, pc), ErrorCodes::INVALID_PARAMS);
  }

  {
    const auto pc =
      make_pc("SB_transfer", {{"src", 1}, {"dst", 2}, {"amt", 5}});
    check_success<bool>(frontend->process(rpc_ctx, pc), true);

    const auto pc1 = make_pc("SB_read", {{"account", 1}});
    check_success(frontend->process(rpc_ctx, pc1), 123 - 5);

    const auto pc2 = make_pc("SB_read", {{"account", 2}});
    check_success(frontend->process(rpc_ctx, pc2), 999 + 5);
  }
}