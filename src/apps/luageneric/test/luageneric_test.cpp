// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"
#include "ds/files.h"
#include "ds/logger.h"
#include "enclave/appinterface.h"
#include "http/http_rpc_context.h"
#include "luainterp/luainterp.h"
#include "node/encryptor.h"
#include "node/genesisgen.h"
#include "node/rpc/jsonrpc.h"
#include "node/rpc/test/node_stub.h"
#include "runtime_config/default_whitelists.h"
#include "tls/keypair.h"

#include <iostream>
#include <map>
#include <set>
#include <string>

using namespace ccfapp;
using namespace ccf;
using namespace std;
using namespace jsonrpc;
using namespace nlohmann;

auto kp = tls::make_key_pair();

namespace ccf
{
  bool operator==(const MemberInfo& mi0, const MemberInfo& mi1)
  {
    return mi0.status == mi1.status && mi0.keyshare == mi1.keyshare;
  }
}

constexpr auto default_format = jsonrpc::Pack::MsgPack;
constexpr auto content_type = default_format == jsonrpc::Pack::Text ?
  http::headervalues::contenttype::JSON :
  (default_format == jsonrpc::Pack::MsgPack ?
     http::headervalues::contenttype::MSGPACK :
     "unknown");

nlohmann::json parse_response(const vector<uint8_t>& v)
{
  http::SimpleMsgProcessor processor;
  http::Parser parser(HTTP_RESPONSE, processor);

  const auto parsed_count = parser.execute(v.data(), v.size());
  REQUIRE(parsed_count == v.size());
  REQUIRE(processor.received.size() == 1);

  return jsonrpc::unpack(processor.received.front().body, default_format);
}

template <typename E>
nlohmann::json check_error(const vector<uint8_t>& v, const E expected)
{
  const auto j_error = parse_response(v);
  CHECK(
    j_error[ERR][CODE].get<jsonrpc::ErrorBaseType>() ==
    static_cast<jsonrpc::ErrorBaseType>(expected));
  return j_error;
}

template <typename T>
void check_success(const vector<uint8_t>& v, const T& expected)
{
  const Response<json> r = parse_response(v);
  CHECK(T(r.result) == expected);
}

void set_whitelists(GenesisGenerator& gen)
{
  for (const auto& wl : default_whitelists)
    gen.set_whitelist(wl.first, wl.second);
}

class LuaLogger : public logger::JsonLogger
{
public:
  LuaLogger() : JsonLogger("") {}

  void write(const std::string& log_line) override
  {
    auto j = nlohmann::json::parse(log_line);
    REQUIRE(j.find("h_ts") != j.end());
    REQUIRE(j.find("msg") != j.end());
    REQUIRE(j.find("file") != j.end());
    REQUIRE(j.find("number") != j.end());
    REQUIRE(j.find("level") != j.end());
  }
};

void set_lua_logger()
{
  logger::config::loggers().emplace_back(std::make_unique<LuaLogger>());
}

auto user_caller = kp -> self_sign("CN=name");
auto user_caller_der = tls::make_verifier(user_caller) -> der_cert_data();
std::vector<uint8_t> dummy_key_share = {1, 2, 3};

auto init_frontend(
  NetworkTables& network,
  GenesisGenerator& gen,
  StubNotifier& notifier,
  const int n_users,
  const int n_members)
{
  for (uint8_t i = 0; i < n_users; i++)
    gen.add_user(user_caller);

  for (uint8_t i = 0; i < n_members; i++)
    gen.add_member(kp->self_sign("CN=name_member"), dummy_key_share);

  set_whitelists(gen);

  const auto env_script = R"xxx(
    return {
      __environment = [[
        function env.succ (result)
          return {result = result}
        end

        function env.err (code, message)
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

std::vector<uint8_t> make_pc(const string& method, const Params& params)
{
  auto request = http::Request(method);
  request.set_header(http::headers::CONTENT_TYPE, content_type);
  const auto body = jsonrpc::pack(params, default_format);
  request.set_body(&body);
  return request.build_request();
}

template <typename F, typename K, typename V>
void check_store_load(F frontend, K k, V v)
{
  const enclave::SessionContext user_session(
    enclave::InvalidSessionId, user_caller_der);

  // store
  const auto store_packed = make_pc("store", {{"k", k}, {"v", v}});
  auto store_ctx = enclave::make_rpc_context(user_session, store_packed);
  check_success(frontend->process(store_ctx).value(), true);

  // load and check that we get the right result
  const auto load_packed = make_pc("load", {{"k", k}});
  auto load_ctx = enclave::make_rpc_context(user_session, load_packed);
  check_success(frontend->process(load_ctx).value(), v);
}

TEST_CASE("simple lua apps")
{
  NetworkTables network;
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  StubNotifier notifier;
  // create network with 1 user and 3 active members
  auto frontend = init_frontend(network, gen, notifier, 1, 3);
  set_lua_logger();
  const enclave::SessionContext user_session(
    enclave::InvalidSessionId, user_caller_der);

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
    const auto packed = make_pc("missing", {});
    auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
    const auto response = check_error(
      frontend->process(rpc_ctx).value(), CCFErrorCodes::SCRIPT_ERROR);
    const auto error_msg = response[ERR][MESSAGE].get<string>();
    CHECK(error_msg.find("THIS_KEY_DOESNT_EXIST") != string::npos);
  }

  SUBCASE("echo")
  {
    constexpr auto app = R"xxx(
      tables, gov_tables, args = ...
      return env.succ(args.params.verb)
    )xxx";
    set_handler(network, "echo", {app});

    // call "echo" function with "hello"
    const string verb = "hello";
    const auto packed = make_pc("echo", {{"verb", verb}});
    auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
    check_success(frontend->process(rpc_ctx).value(), verb);
  }

  SUBCASE("store/load different types in generic table")
  {
    constexpr auto store = R"xxx(
      tables, gov_tables, args = ...
      local r = tables.priv0:put(args.params.k, args.params.v)
      return env.succ(r)
    )xxx";
    set_handler(network, "store", {store});

    constexpr auto load = R"xxx(
      tables, gov_tables, args = ...
      local v = tables.priv0:get(args.params.k)
      if not v then
        return env.err(env.error_codes.INVALID_PARAMS, "key does not exist")
      end
      return env.succ(v)
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
    const auto packed = make_pc("load", {{"k", set{5, 6, 7}}});
    auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
    check_error(
      frontend->process(rpc_ctx).value(), StandardErrorCodes::INVALID_PARAMS);
  }

  SUBCASE("access gov tables")
  {
    constexpr auto get_members = R"xxx(
      tables, gov_tables, args = ...
      local members = {}
      gov_tables["ccf.members"]:foreach(
        function(k, v) members[tostring(k)] = v end
      )
      return env.succ(members)
    )xxx";
    set_handler(network, "get_members", {get_members});

    // Not allowed to call put() on read-only gov_tables
    constexpr auto put_member = R"xxx(
      tables, gov_tables, args = ...
      return env.succ(gov_tables["ccf.members"]:put(args.params.k,
      args.params.v))
    )xxx";
    set_handler(network, "put_member", {put_member});

    // (1) read out members table
    const auto packed = make_pc("get_members", {});
    auto get_ctx = enclave::make_rpc_context(user_session, packed);
    // expect to see 3 members in state active
    map<string, MemberInfo> expected = {
      {"0", {{}, dummy_key_share, MemberStatus::ACTIVE}},
      {"1", {{}, dummy_key_share, MemberStatus::ACTIVE}},
      {"2", {{}, dummy_key_share, MemberStatus::ACTIVE}}};
    check_success(frontend->process(get_ctx).value(), expected);

    // (2) try to write to members table
    const auto put_packed = make_pc(
      "put_member",
      {{"k", 99}, {"v", MemberInfo{{}, {}, MemberStatus::ACTIVE}}});
    auto put_ctx = enclave::make_rpc_context(user_session, put_packed);
    check_error(
      frontend->process(put_ctx).value(), CCFErrorCodes::SCRIPT_ERROR);
  }
}

TEST_CASE("simple bank")
{
  NetworkTables network;
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  StubNotifier notifier;
  // create network with 1 user and 3 active members
  auto frontend = init_frontend(network, gen, notifier, 1, 3);
  set_lua_logger();
  const enclave::SessionContext user_session(
    enclave::InvalidSessionId, user_caller_der);

  constexpr auto create_method = "SB_create";
  constexpr auto create = R"xxx(
    tables, gov_tables, args = ...
    local dst = args.params.dst
    if tables.priv0:get(dst) then
      return env.err(env.error_codes.INVALID_PARAMS, "account already exists")
    end

    tables.priv0:put(dst, args.params.amt)
    return env.succ(true)
  )xxx";
  set_handler(network, create_method, {create});

  constexpr auto read_method = "SB_read";
  constexpr auto read = R"xxx(
    tables, gov_tables, args = ...
    local acc = args.params.account
    local amt = tables.priv0:get(acc)
    if not amt then
      return env.err(
        env.error_codes.INVALID_PARAMS, "account " .. acc .. " does not exist")
    end

    return env.succ(amt)
  )xxx";
  set_handler(network, read_method, {read});

  constexpr auto transfer_method = "SB_transfer";
  constexpr auto transfer = R"xxx(
    tables, gov_tables, args = ...
    local src = args.params.src
    local dst = args.params.dst
    local src_n = tables.priv0:get(src)
    if not src_n then
      return env.err(
        env.error_codes.INVALID_PARAMS, "source account does not exist")
    end

    local dst_n = tables.priv0:get(dst)
    if not dst_n then
      return env.err(
        env.error_codes.INVALID_PARAMS, "destination account does not exist")
    end

    local amt = args.params.amt
    if src_n < amt then
      return env.err(env.error_codes.INVALID_PARAMS, "insufficient funds")
    end

    tables.priv0:put(src, src_n - amt)
    tables.priv0:put(dst, dst_n + amt)

    return env.succ(true)
  )xxx";
  set_handler(network, transfer_method, {transfer});

  {
    const auto create_packed =
      make_pc(create_method, {{"dst", 1}, {"amt", 123}});
    auto create_ctx = enclave::make_rpc_context(user_session, create_packed);
    check_success<bool>(frontend->process(create_ctx).value(), true);

    const auto read_packed = make_pc(read_method, {{"account", 1}});
    auto read_ctx = enclave::make_rpc_context(user_session, read_packed);
    check_success(frontend->process(read_ctx).value(), 123);
  }

  {
    const auto create_packed =
      make_pc(create_method, {{"dst", 2}, {"amt", 999}});
    auto create_ctx = enclave::make_rpc_context(user_session, create_packed);
    check_success<bool>(frontend->process(create_ctx).value(), true);

    const auto read_packed = make_pc(read_method, {{"account", 2}});
    auto read_ctx = enclave::make_rpc_context(user_session, read_packed);
    check_success(frontend->process(read_ctx).value(), 999);
  }

  {
    const auto read_packed = make_pc(read_method, {{"account", 3}});
    auto read_ctx = enclave::make_rpc_context(user_session, read_packed);
    check_error(
      frontend->process(read_ctx).value(), StandardErrorCodes::INVALID_PARAMS);
  }

  {
    const auto transfer_packed =
      make_pc(transfer_method, {{"src", 1}, {"dst", 2}, {"amt", 5}});
    auto transfer_ctx =
      enclave::make_rpc_context(user_session, transfer_packed);
    check_success<bool>(frontend->process(transfer_ctx).value(), true);

    const auto read1_packed = make_pc(read_method, {{"account", 1}});
    auto read1_ctx = enclave::make_rpc_context(user_session, read1_packed);
    check_success(frontend->process(read1_ctx).value(), 123 - 5);

    const auto read2_packed = make_pc(read_method, {{"account", 2}});
    auto read2_ctx = enclave::make_rpc_context(user_session, read2_packed);
    check_success(frontend->process(read2_ctx).value(), 999 + 5);
  }
}

TEST_CASE("pre-populated environment")
{
  NetworkTables network;
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  StubNotifier notifier;
  // create network with 1 user and 3 active members
  auto frontend = init_frontend(network, gen, notifier, 1, 3);
  set_lua_logger();
  const enclave::SessionContext user_session(
    enclave::InvalidSessionId, user_caller_der);

  {
    constexpr auto log_trace_method = "log_trace";
    constexpr auto log_trace = R"xxx(
      LOG_TRACE("Logging trace message from Lua")
      LOG_TRACE("Concatenating ", 3, " args")
      return env.succ(true)
    )xxx";
    set_handler(network, log_trace_method, {log_trace});

    {
      const auto packed = make_pc(log_trace_method, {});
      auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
      check_success(frontend->process(rpc_ctx).value(), true);
    }

    constexpr auto log_debug_method = "log_debug";
    constexpr auto log_debug = R"xxx(
      LOG_DEBUG("Logging debug message from Lua")
      LOG_DEBUG("Concatenating ", 3, " args")
      return env.succ(true)
    )xxx";
    set_handler(network, log_debug_method, {log_debug});

    {
      const auto packed = make_pc(log_debug_method, {});
      auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
      check_success(frontend->process(rpc_ctx).value(), true);
    }

    constexpr auto log_info_method = "log_info";
    constexpr auto log_info = R"xxx(
      LOG_INFO("Logging state message from Lua")
      LOG_INFO("Concatenating ", 3, " args")
      return env.succ(true)
    )xxx";
    set_handler(network, log_info_method, {log_info});

    {
      const auto packed = make_pc(log_info_method, {});
      auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
      check_success(frontend->process(rpc_ctx).value(), true);
    }

    constexpr auto log_fail_method = "log_fail";
    constexpr auto log_fail = R"xxx(
      LOG_FAIL("Logging failures from Lua")
      LOG_FAIL("Concatenating ", 3, " args")
      return env.succ(true)
    )xxx";
    set_handler(network, log_fail_method, {log_fail});

    {
      const auto packed = make_pc(log_fail_method, {});
      auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
      check_success(frontend->process(rpc_ctx).value(), true);
    }

    constexpr auto log_fatal_method = "log_fatal";
    constexpr auto log_fatal = R"xxx(
      LOG_FATAL("Logging a fatal error, raising an error")
      return env.succ(true)
    )xxx";
    set_handler(network, log_fatal_method, {log_fatal});

    {
      const auto packed = make_pc(log_fatal_method, {});
      auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
      check_error(
        frontend->process(rpc_ctx).value(),
        jsonrpc::StandardErrorCodes::INTERNAL_ERROR);
    }

    constexpr auto log_throws_nil_method = "log_throws_nil";
    constexpr auto log_throws_nil = "LOG_INFO(nil)";
    set_handler(network, log_throws_nil_method, {log_throws_nil});
    {
      const auto packed = make_pc(log_throws_nil_method, {});
      auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
      check_error(
        frontend->process(rpc_ctx).value(),
        jsonrpc::StandardErrorCodes::INTERNAL_ERROR);
    }

    constexpr auto log_throws_bool_method = "log_throws_bool";
    constexpr auto log_throws_bool = "LOG_INFO(true)";
    set_handler(network, log_throws_bool_method, {log_throws_bool});

    {
      const auto packed = make_pc(log_throws_bool_method, {});
      auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
      check_error(
        frontend->process(rpc_ctx).value(),
        jsonrpc::StandardErrorCodes::INTERNAL_ERROR);
    }

    constexpr auto log_no_throw_method = "log_no_throw";
    constexpr auto log_no_throw =
      "LOG_INFO(tostring(nil), tostring(true)); return env.succ(true)";
    set_handler(network, log_no_throw_method, {log_no_throw});

    {
      const auto packed = make_pc(log_no_throw_method, {});
      auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
      check_success(frontend->process(rpc_ctx).value(), true);
    }
  }

  {
    // Test Lua sees the correct error codes by returning them from RPC
    constexpr auto invalid_params_method = "invalid_params";
    constexpr auto invalid_params = R"xxx(
      return env.succ(
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
      const auto packed = make_pc(invalid_params_method, {});
      auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
      const Response<std::vector<EBT>> r =
        parse_response(frontend->process(rpc_ctx).value());

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
