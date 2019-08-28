// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"
#include "ds/files.h"
#include "ds/logger.h"
#include "enclave/appinterface.h"
#include "luainterp/luainterp.h"
#include "node/genesisgen.h"
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

template <typename E>
nlohmann::json check_error(const vector<uint8_t>& v, const E expected)
{
  const auto j_error = json::from_msgpack(v);
  CHECK(
    j_error[ERR][CODE].get<jsonrpc::ErrorBaseType>() ==
    static_cast<jsonrpc::ErrorBaseType>(expected));
  return j_error;
}

template <typename T>
void check_success(const vector<uint8_t>& v, const T& expected)
{
  const Response<json> r = json::from_msgpack(v);
  CHECK(T(r.result) == expected);
}

void set_whitelists(GenesisGenerator& gen)
{
  for (const auto& wl : default_whitelists)
    gen.set_whitelist(wl.first, wl.second);
}

auto init_frontend(
  NetworkTables& network,
  GenesisGenerator& gen,
  StubNotifier& notifier,
  const int n_users,
  const int n_members)
{
  // create users with fake certs (no crypto here)
  for (uint8_t i = 0; i < n_users; i++)
    gen.add_user({i});

  for (uint8_t i = 0; i < n_members; i++)
    gen.add_member({i});

  set_whitelists(gen);

  const auto env_script = R"xxx(
    return {
      __environment = [[
        function env.jsucc (result)
          return {result = result}
        end

        function env.jerr (code, message)
          return {error = {code = code, message = message}}
        end
      ]]
    }
  )xxx";

  gen.set_app_scripts(lua::Interpreter().invoke<nlohmann::json>(env_script));
  gen.finalize();
  return get_rpc_handler(network, notifier);
}

void set_handler(NetworkTables& network, const string& method, const Script& h)
{
  Store::Tx tx;
  tx.get_view(network.app_scripts)->put(method, h);
  REQUIRE(tx.commit() == kv::CommitSuccess::OK);
}

using Params = map<string, json>;

auto make_pc(const string& method, const Params& params)
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
  NetworkTables network;
  GenesisGenerator gen(network);
  gen.init_values();
  StubNotifier notifier;
  // create network with 1 user and 3 active members
  auto frontend = init_frontend(network, gen, notifier, 1, 3);
  const Cert u0 = {0};
  enclave::RPCContext rpc_ctx(0, u0);

  SUBCASE("missing lua arg")
  {
    constexpr auto missing = R"xxx(
      tables, gov_tables, args = ...

      -- access all expected keys
      x = args.caller_id
      x = args.method
      x = args.params

      -- try to access missing key
      x = args.THIS_KEY_DOESNT_EXIST
    )xxx";
    set_handler(network, "missing", {missing});

    // call "missing"
    const auto pc = make_pc("missing", {});
    const auto response =
      check_error(frontend->process(rpc_ctx, pc), CCFErrorCodes::SCRIPT_ERROR);
    const auto error_msg = response[ERR][MESSAGE].get<string>();
    CHECK(error_msg.find("THIS_KEY_DOESNT_EXIST") != string::npos);
  }

  SUBCASE("echo")
  {
    constexpr auto app = R"xxx(
      tables, gov_tables, args = ...
      return env.jsucc(args.params.verb)
    )xxx";
    set_handler(network, "echo", {app});

    // call "echo" function with "hello"
    const string verb = "hello";
    const auto pc = make_pc("echo", {{"verb", verb}});
    check_success(frontend->process(rpc_ctx, pc), verb);
  }

  SUBCASE("store/load different types in generic table")
  {
    constexpr auto store = R"xxx(
      tables, gov_tables, args = ...
      local r = tables.priv0:put(args.params.k, args.params.v)
      return env.jsucc(r)
    )xxx";
    set_handler(network, "store", {store});

    constexpr auto load = R"xxx(
      tables, gov_tables, args = ...
      local v = tables.priv0:get(args.params.k)
      if not v then
        return env.jerr(env.error_codes.INVALID_PARAMS, "key does not exist")
      end
      return env.jsucc(v)
    )xxx";
    set_handler(network, "load", {load});

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
    check_error(
      frontend->process(rpc_ctx, pc), StandardErrorCodes::INVALID_PARAMS);
  }

  SUBCASE("access gov tables")
  {
    constexpr auto get_members = R"xxx(
      tables, gov_tables, args = ...
      local members = {}
      gov_tables.members:foreach(
        function(k, v) members[tostring(k)] = v end
      )
      return env.jsucc(members)
    )xxx";
    set_handler(network, "get_members", {get_members});

    // Not allowed to call put() on read-only gov_tables
    constexpr auto put_member = R"xxx(
      tables, gov_tables, args = ...
      return env.jsucc(gov_tables.members:put(args.params.k, args.params.v))
    )xxx";
    set_handler(network, "put_member", {put_member});

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
    check_error(frontend->process(rpc_ctx, pc1), CCFErrorCodes::SCRIPT_ERROR);
  }
}

TEST_CASE("simple bank")
{
  NetworkTables network;
  GenesisGenerator gen(network);
  gen.init_values();
  StubNotifier notifier;
  // create network with 1 user and 3 active members
  auto frontend = init_frontend(network, gen, notifier, 1, 3);
  const Cert u0 = {0};
  enclave::RPCContext rpc_ctx(0, u0);

  constexpr auto create_method = "SB_create";
  constexpr auto create = R"xxx(
    tables, gov_tables, args = ...
    local dst = args.params.dst
    if tables.priv0:get(dst) then
      return env.jerr(env.error_codes.INVALID_PARAMS, "account already exists")
    end

    tables.priv0:put(dst, args.params.amt)
    return env.jsucc(true)
  )xxx";
  set_handler(network, create_method, {create});

  constexpr auto read_method = "SB_read";
  constexpr auto read = R"xxx(
    tables, gov_tables, args = ...
    local acc = args.params.account
    local amt = tables.priv0:get(acc)
    if not amt then
      return env.jerr(
        env.error_codes.INVALID_PARAMS, "account " .. acc .. " does not exist")
    end

    return env.jsucc(amt)
  )xxx";
  set_handler(network, read_method, {read});

  constexpr auto transfer_method = "SB_transfer";
  constexpr auto transfer = R"xxx(
    tables, gov_tables, args = ...
    local src = args.params.src
    local dst = args.params.dst
    local src_n = tables.priv0:get(src)
    if not src_n then
      return env.jerr(
        env.error_codes.INVALID_PARAMS, "source account does not exist")
    end

    local dst_n = tables.priv0:get(dst)
    if not dst_n then
      return env.jerr(
        env.error_codes.INVALID_PARAMS, "destination account does not exist")
    end

    local amt = args.params.amt
    if src_n < amt then
      return env.jerr(env.error_codes.INVALID_PARAMS, "insufficient funds")
    end

    tables.priv0:put(src, src_n - amt)
    tables.priv0:put(dst, dst_n + amt)

    return env.jsucc(true)
  )xxx";
  set_handler(network, transfer_method, {transfer});

  {
    const auto pc = make_pc(create_method, {{"dst", 1}, {"amt", 123}});
    check_success<bool>(frontend->process(rpc_ctx, pc), true);

    const auto pc1 = make_pc(read_method, {{"account", 1}});
    check_success(frontend->process(rpc_ctx, pc1), 123);
  }

  {
    const auto pc = make_pc(create_method, {{"dst", 2}, {"amt", 999}});
    check_success<bool>(frontend->process(rpc_ctx, pc), true);

    const auto pc1 = make_pc(read_method, {{"account", 2}});
    check_success(frontend->process(rpc_ctx, pc1), 999);
  }

  {
    const auto pc = make_pc(read_method, {{"account", 3}});
    check_error(
      frontend->process(rpc_ctx, pc), StandardErrorCodes::INVALID_PARAMS);
  }

  {
    const auto pc =
      make_pc(transfer_method, {{"src", 1}, {"dst", 2}, {"amt", 5}});
    check_success<bool>(frontend->process(rpc_ctx, pc), true);

    const auto pc1 = make_pc(read_method, {{"account", 1}});
    check_success(frontend->process(rpc_ctx, pc1), 123 - 5);

    const auto pc2 = make_pc(read_method, {{"account", 2}});
    check_success(frontend->process(rpc_ctx, pc2), 999 + 5);
  }
}

TEST_CASE("pre-populated environment")
{
  NetworkTables network;
  GenesisGenerator gen(network);
  gen.init_values();
  StubNotifier notifier;
  // create network with 1 user and 3 active members
  auto frontend = init_frontend(network, gen, notifier, 1, 3);
  const Cert u0 = {0};
  enclave::RPCContext rpc_ctx(0, u0);

  {
    constexpr auto log_trace_method = "log_trace";
    constexpr auto log_trace = R"xxx(
      LOG_TRACE("Logging trace message from Lua")
      LOG_TRACE("Concatenating ", 3, " args")
      return env.jsucc(true)
    )xxx";
    set_handler(network, log_trace_method, {log_trace});

    {
      const auto pc = make_pc(log_trace_method, {});
      check_success(frontend->process(rpc_ctx, pc), true);
    }

    constexpr auto log_debug_method = "log_debug";
    constexpr auto log_debug = R"xxx(
      LOG_DEBUG("Logging debug message from Lua")
      LOG_DEBUG("Concatenating ", 3, " args")
      return env.jsucc(true)
    )xxx";
    set_handler(network, log_debug_method, {log_debug});

    {
      const auto pc = make_pc(log_debug_method, {});
      check_success(frontend->process(rpc_ctx, pc), true);
    }

    constexpr auto log_info_method = "log_info";
    constexpr auto log_info = R"xxx(
      LOG_INFO("Logging state message from Lua")
      LOG_INFO("Concatenating ", 3, " args")
      return env.jsucc(true)
    )xxx";
    set_handler(network, log_info_method, {log_info});

    {
      const auto pc = make_pc(log_info_method, {});
      check_success(frontend->process(rpc_ctx, pc), true);
    }

    constexpr auto log_fail_method = "log_fail";
    constexpr auto log_fail = R"xxx(
      LOG_FAIL("Logging failures from Lua")
      LOG_FAIL("Concatenating ", 3, " args")
      return env.jsucc(true)
    )xxx";
    set_handler(network, log_fail_method, {log_fail});

    {
      const auto pc = make_pc(log_fail_method, {});
      check_success(frontend->process(rpc_ctx, pc), true);
    }

    constexpr auto log_fatal_method = "log_fatal";
    constexpr auto log_fatal = R"xxx(
      LOG_FATAL("Logging a fatal error, raising an error")
      return env.jsucc(true)
    )xxx";
    set_handler(network, log_fatal_method, {log_fatal});

    {
      const auto pc = make_pc(log_fatal_method, {});
      check_error(
        frontend->process(rpc_ctx, pc),
        jsonrpc::StandardErrorCodes::INTERNAL_ERROR);
    }
  }

  {
    // Test Lua sees the correct error codes by returning them from RPC
    constexpr auto invalid_params_method = "invalid_params";
    constexpr auto invalid_params = R"xxx(
      return env.jsucc(
        {
          env.error_codes.PARSE_ERROR,
          env.error_codes.INVALID_REQUEST,
          env.error_codes.METHOD_NOT_FOUND,
          env.error_codes.INVALID_PARAMS,
          env.error_codes.INTERNAL_ERROR,
          env.error_codes.METHOD_NOT_FOUND,

          env.error_codes.TX_NOT_PRIMARY,
          env.error_codes.TX_FAILED_TO_REPLICATE,
          env.error_codes.SCRIPT_ERROR,
          env.error_codes.INSUFFICIENT_RIGHTS,
          env.error_codes.TX_PRIMARY_UNKNOWN,
          env.error_codes.RPC_NOT_SIGNED,
          env.error_codes.INVALID_CLIENT_SIGNATURE,
          env.error_codes.INVALID_CALLER_ID,
          env.error_codes.CODE_ID_NOT_FOUND,
          env.error_codes.CODE_ID_RETIRED,
          env.error_codes.RPC_NOT_FORWARDED,
          env.error_codes.QUOTE_NOT_VERIFIED
        }
      )
    )xxx";
    set_handler(network, invalid_params_method, {invalid_params});

    {
      using EBT = jsonrpc::ErrorBaseType;
      using StdEC = jsonrpc::StandardErrorCodes;
      using CCFEC = jsonrpc::CCFErrorCodes;
      const auto pc = make_pc(invalid_params_method, {});
      const Response<std::vector<EBT>> r =
        json::from_msgpack(frontend->process(rpc_ctx, pc));

      std::vector<EBT> expected;
      expected.push_back(EBT(StdEC::PARSE_ERROR));
      expected.push_back(EBT(StdEC::INVALID_REQUEST));
      expected.push_back(EBT(StdEC::METHOD_NOT_FOUND));
      expected.push_back(EBT(StdEC::INVALID_PARAMS));
      expected.push_back(EBT(StdEC::INTERNAL_ERROR));
      expected.push_back(EBT(StdEC::METHOD_NOT_FOUND));

      expected.push_back(EBT(CCFEC::TX_NOT_PRIMARY));
      expected.push_back(EBT(CCFEC::TX_FAILED_TO_REPLICATE));
      expected.push_back(EBT(CCFEC::SCRIPT_ERROR));
      expected.push_back(EBT(CCFEC::INSUFFICIENT_RIGHTS));
      expected.push_back(EBT(CCFEC::TX_PRIMARY_UNKNOWN));
      expected.push_back(EBT(CCFEC::RPC_NOT_SIGNED));
      expected.push_back(EBT(CCFEC::INVALID_CLIENT_SIGNATURE));
      expected.push_back(EBT(CCFEC::INVALID_CALLER_ID));
      expected.push_back(EBT(CCFEC::CODE_ID_NOT_FOUND));
      expected.push_back(EBT(CCFEC::CODE_ID_RETIRED));
      expected.push_back(EBT(CCFEC::RPC_NOT_FORWARDED));
      expected.push_back(EBT(CCFEC::QUOTE_NOT_VERIFIED));

      CHECK(r.result == expected);
    }
  }
}
