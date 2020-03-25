// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ds/files.h"
#include "ds/logger.h"
#include "enclave/app_interface.h"
#include "http/http_rpc_context.h"
#include "lua_interp/lua_interp.h"
#include "node/encryptor.h"
#include "node/genesis_gen.h"
#include "node/rpc/json_handler.h"
#include "node/rpc/json_rpc.h"
#include "node/rpc/test/node_stub.h"
#include "runtime_config/default_whitelists.h"
#include "tls/key_pair.h"

#include <doctest/doctest.h>
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
constexpr auto content_type = details::pack_to_content_type(default_format);

using TResponse = http::SimpleResponseProcessor::Response;

TResponse parse_response(const vector<uint8_t>& v)
{
  http::SimpleResponseProcessor processor;
  http::ResponseParser parser(processor);

  const auto parsed_count = parser.execute(v.data(), v.size());
  REQUIRE(parsed_count == v.size());
  REQUIRE(processor.received.size() == 1);

  return processor.received.front();
}

TResponse check_error(const vector<uint8_t>& v, http_status expected)
{
  const auto response = parse_response(v);
  CHECK(response.status == expected);
  return response;
}

template <typename T>
T parse_response_body(const TResponse& r)
{
  const auto body_j = jsonrpc::unpack(r.body, default_format);
  return body_j.get<T>();
}

template <typename T>
void check_success(const vector<uint8_t>& v, const T& expected)
{
  const auto actual = parse_response_body<T>(parse_response(v));
  CHECK(actual == expected);
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
  auto user_session = std::make_shared<enclave::SessionContext>(
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
  auto user_session = std::make_shared<enclave::SessionContext>(
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
    auto response = check_error(
      frontend->process(rpc_ctx).value(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    CHECK(
      response.headers[http::headers::CONTENT_TYPE] ==
      http::headervalues::contenttype::TEXT);
    const std::string error_msg(response.body.begin(), response.body.end());
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
        return env.err(env.error_codes.BAD_REQUEST, "key does not exist")
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
    check_error(frontend->process(rpc_ctx).value(), HTTP_STATUS_BAD_REQUEST);
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
      frontend->process(put_ctx).value(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
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
  auto user_session = std::make_shared<enclave::SessionContext>(
    enclave::InvalidSessionId, user_caller_der);

  constexpr auto create_method = "SB_create";
  constexpr auto create = R"xxx(
    tables, gov_tables, args = ...
    local dst = args.params.dst
    if tables.priv0:get(dst) then
      return env.err(env.error_codes.BAD_REQUEST, "account already exists")
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
        env.error_codes.BAD_REQUEST, "account " .. acc .. " does not exist")
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
        env.error_codes.BAD_REQUEST, "source account does not exist")
    end

    local dst_n = tables.priv0:get(dst)
    if not dst_n then
      return env.err(
        env.error_codes.BAD_REQUEST, "destination account does not exist")
    end

    local amt = args.params.amt
    if src_n < amt then
      return env.err(env.error_codes.BAD_REQUEST, "insufficient funds")
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
    check_error(frontend->process(read_ctx).value(), HTTP_STATUS_BAD_REQUEST);
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
  auto user_session = std::make_shared<enclave::SessionContext>(
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
        frontend->process(rpc_ctx).value(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    }

    constexpr auto log_throws_nil_method = "log_throws_nil";
    constexpr auto log_throws_nil = "LOG_INFO(nil)";
    set_handler(network, log_throws_nil_method, {log_throws_nil});
    {
      const auto packed = make_pc(log_throws_nil_method, {});
      auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
      check_error(
        frontend->process(rpc_ctx).value(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    }

    constexpr auto log_throws_bool_method = "log_throws_bool";
    constexpr auto log_throws_bool = "LOG_INFO(true)";
    set_handler(network, log_throws_bool_method, {log_throws_bool});

    {
      const auto packed = make_pc(log_throws_bool_method, {});
      auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
      check_error(
        frontend->process(rpc_ctx).value(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
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
          env.error_codes.CONTINUE,
          env.error_codes.OK,
          env.error_codes.NO_CONTENT,
          env.error_codes.MOVED_PERMANENTLY,
          env.error_codes.TEMPORARY_REDIRECT,
          env.error_codes.BAD_REQUEST,
          env.error_codes.UNAUTHORIZED,
          env.error_codes.FORBIDDEN,
          env.error_codes.NOT_FOUND,
          env.error_codes.INTERNAL_SERVER_ERROR,
          env.error_codes.NOT_IMPLEMENTED,
        }
      )
    )xxx";
    set_handler(network, invalid_params_method, {invalid_params});

    {
      const auto packed = make_pc(invalid_params_method, {});
      auto rpc_ctx = enclave::make_rpc_context(user_session, packed);
      const auto r = parse_response_body<std::vector<http_status>>(
        parse_response(frontend->process(rpc_ctx).value()));

      std::vector<http_status> expected;
      expected.push_back(HTTP_STATUS_CONTINUE);
      expected.push_back(HTTP_STATUS_OK);
      expected.push_back(HTTP_STATUS_NO_CONTENT);
      expected.push_back(HTTP_STATUS_MOVED_PERMANENTLY);
      expected.push_back(HTTP_STATUS_TEMPORARY_REDIRECT);
      expected.push_back(HTTP_STATUS_BAD_REQUEST);
      expected.push_back(HTTP_STATUS_UNAUTHORIZED);
      expected.push_back(HTTP_STATUS_FORBIDDEN);
      expected.push_back(HTTP_STATUS_NOT_FOUND);
      expected.push_back(HTTP_STATUS_INTERNAL_SERVER_ERROR);
      expected.push_back(HTTP_STATUS_NOT_IMPLEMENTED);

      CHECK(r == expected);
    }
  }
}
