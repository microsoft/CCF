// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../lua_kv.h"

#include "../lua_interp.h"
#include "ds/hash.h"
#include "ds/logger.h"
#include "enclave/app_interface.h"
#include "kv/kv_serialiser.h"

#include <doctest/doctest.h>

using namespace ccf;
using namespace ccf::lua;
using namespace ccfapp;
using namespace std;
using namespace nlohmann;

namespace ccf
{
  using TableII = Store::Map<int, int>;
  using TxII = TableII::TxView;

  using TableIS = Store::Map<int, std::string>;
  using TxIS = TableIS::TxView;

  using TableSB = Store::Map<std::string, bool>;
  using TxSB = TableSB::TxView;

  using TableVI = Store::Map<vector<uint8_t>, int>;
  using TxVI = TableVI::TxView;

  TEST_CASE("lua tx")
  {
    Store tables;
    auto& table = tables.create<TableIS>("test", kv::SecurityDomain::PUBLIC);

    Store::Tx txs;

    const auto a = "Alice";
    const auto b = "Bob";

    auto tx = txs.get_view(table);
    tx->put(0, a);

    auto li = Interpreter();
    li.register_metatable<TxIS>(kv_methods<TxIS>);

    SUBCASE("basic")
    {
      constexpr auto code(
        "local tx, a, b = ...;"
        "if tx:get(0) ~= a then return 'tx get failed' end;"

        "if tx:get(1) ~= nil then return 'index 1 already populated' end;"
        "tx:put(1, '');"
        "if tx:get(1) ~= '' then return 'tx put failed' end;"

        "tx:put(1, b);"
        "if tx:get(1) ~= b then return 'tx overwrite failed' end;");

      li.invoke<nullptr_t>(code, tx, a, b);

      const auto res0 = tx->get(0);
      REQUIRE(res0.has_value());
      REQUIRE(res0.value() == a);

      const auto res1 = tx->get(1);
      REQUIRE(res1.has_value());
      REQUIRE(res1.value() == b);

      REQUIRE(txs.commit() == kv::CommitSuccess::OK);
    }

    SUBCASE("all methods")
    {
      constexpr auto count_keys(
        "local tx = ...;"
        "local n = 0;"
        "tx:foreach( function(k, v) n = n + 1 end );"
        "return n");
      constexpr auto put(
        "local tx, k, v = ...;"
        "return tx:put(k, v)");
      constexpr auto get(
        "local tx, k = ...;"
        "return tx:get(k)");
      constexpr auto get_globally_committed(
        "local tx, k = ...;"
        "return tx:get_globally_committed(k)");
      constexpr auto remove(
        "local tx, n = ...;"
        "return tx:remove(n)");
      constexpr auto start_order(
        "local tx = ...;"
        "return tx:start_order()");
      constexpr auto end_order(
        "local tx = ...;"
        "return tx:end_order()");
      constexpr auto k = 0;
      constexpr auto s0 = "Something";
      constexpr auto s1 = "Something else";

      INFO("1 key initially");
      {
        REQUIRE(li.invoke<int>(count_keys, tx) == 1);
      }

      INFO("Added key is counted");
      {
        REQUIRE(li.invoke<bool>(put, tx, 1, b));
        REQUIRE(li.invoke<int>(count_keys, tx) == 2);
      }

      INFO("Same key is not counted twice");
      {
        REQUIRE(li.invoke<bool>(put, tx, 1, b));
        REQUIRE(li.invoke<int>(count_keys, tx) == 2);
      }

      INFO("Removed key is not counted");
      {
        REQUIRE(li.invoke<bool>(remove, tx, 1));
        REQUIRE(li.invoke<int>(count_keys, tx) == 1);
      }

      INFO("Pre-commit orders can be read from lua");
      {
        REQUIRE(tx->put(k, s0));

        REQUIRE(li.invoke<int>(start_order, tx) == tx->start_order());
        REQUIRE(li.invoke<nullptr_t>(end_order, tx) == nullptr);
      }

      INFO("Post-commit orders can be read from lua");
      {
        REQUIRE(txs.commit() == kv::CommitSuccess::OK);

        REQUIRE(li.invoke<int>(start_order, tx) == tx->start_order());
        REQUIRE(li.invoke<int>(end_order, tx) == tx->end_order());
      }

      INFO("get_commit from lua");
      {
        tables.compact(tx->end_order());

        Store::Tx next_txs;
        auto next_tx = next_txs.get_view(table);

        REQUIRE(next_tx->put(k, s1));

        INFO("get and get_globally_committed may return different values");
        {
          REQUIRE(li.invoke<string>(get_globally_committed, next_tx, k) == s0);
          REQUIRE(li.invoke<string>(get, next_tx, k) == s1);
        }

        INFO("get_globally_committed for a new key returns nil");
        {
          const auto next_k = k + 1;
          REQUIRE(next_tx->put(next_k, s1));
          REQUIRE(
            li.invoke<nullptr_t>(get_globally_committed, next_tx, next_k) ==
            nullptr);
        }

        REQUIRE(next_txs.commit() == kv::CommitSuccess::OK);
      }
    }
  }

  TEST_CASE("multiple tables")
  {
    Store tables;
    auto& ii = tables.create<TableII>("test_ii", kv::SecurityDomain::PUBLIC);
    auto& is = tables.create<TableIS>("test_is", kv::SecurityDomain::PUBLIC);
    auto& sb = tables.create<TableSB>("test_sb", kv::SecurityDomain::PUBLIC);

    Store::Tx txs;
    auto tx = txs.get_view(ii, is, sb);
    auto tx_ii = get<0>(tx);
    auto tx_is = get<1>(tx);
    auto tx_sb = get<2>(tx);

    auto li = Interpreter();
    li.register_metatable<TxII>(kv_methods<TxII>);
    li.register_metatable<TxIS>(kv_methods<TxIS>);
    li.register_metatable<TxSB>(kv_methods<TxSB>);

    constexpr auto code(
      "local i_to_i, i_to_s, s_to_b = ...;"

      "local l = {1, 2, 3, 4, 5, 6, 7};"

      "for _, n in ipairs(l) do"
      "  assert(i_to_i:put(n, math.tointeger(n^n)));"
      "end;"

      "for _, n in ipairs(l) do"
      "  local pow = i_to_i:get(n);"
      "  assert(i_to_s:put(pow, tostring(pow)));"
      "end;"

      "for _, n in ipairs(l) do"
      "  local pow = i_to_i:get(n);"
      "  local s = i_to_s:get(pow);"
      "  local contains_n = s:find(tostring(n)) ~= nil;"
      "  assert(s_to_b:put(s, contains_n));"
      "end;");

    li.invoke<nullptr_t>(code, tx_ii, tx_is, tx_sb);

    // Does string(n**n) contain string(n)?
    auto expect_result = [tx_ii, tx_is, tx_sb](int n, auto s, bool b) {
      auto r_ii = tx_ii->get(n);
      REQUIRE(r_ii.has_value());
      REQUIRE(r_ii.value() == pow(n, n));

      auto r_is = tx_is->get(r_ii.value());
      REQUIRE(r_is.has_value());
      REQUIRE(r_is.value() == s);

      auto r_sb = tx_sb->get(r_is.value());
      REQUIRE(r_sb.has_value());
      REQUIRE(r_sb.value() == b);
    };

    expect_result(1, "1", true);
    expect_result(2, "4", false);
    expect_result(3, "27", false);
    expect_result(4, "256", false);
    expect_result(5, "3125", true);
    expect_result(6, "46656", true);
    expect_result(7, "823543", false);

    REQUIRE(txs.commit() == kv::CommitSuccess::OK);
  }

  TEST_CASE("vector as index")
  {
    Interpreter li;
    li.register_metatable<TxVI>(kv_methods<TxVI>);

    Store tables;
    auto& table = tables.create<TableVI>("v");
    Store::Tx txs;
    auto tx = txs.get_view(table);
    tx->put(vector<uint8_t>(100, 1), 123);

    SUBCASE("read 1")
    {
      constexpr auto code(
        "local tx = ...;"
        "a = {}"
        "for i=1, 100 do a[i] = 1 end;"
        "return tx:get(a) == 123;");

      REQUIRE(li.invoke<bool>(code, tx));
    }

    SUBCASE("write 1")
    {
      constexpr auto code(
        "local tx = ...;"
        "a = {}"
        "for i=1, 100 do a[i] = i end;"
        "tx:put(a, 321)");

      li.invoke<nullptr_t>(code, tx);
      vector<uint8_t> v(100);
      std::iota(v.begin(), v.end(), 1);
      REQUIRE(tx->get(v) == 321);
    }

    SUBCASE("write many")
    {
      constexpr auto code(
        "local tx = ...;"
        "for i=1, 100 do tx:put({i,i}, i) end;");

      li.invoke<nullptr_t>(code, tx);
      for (uint8_t i = 1; i <= 100; i++)
        REQUIRE(tx->get({i, i}) == i);
    }
  }

  TEST_CASE("simple bank")
  {
    static constexpr auto code = R"xxx(
  tx, caller, id, method, params = ...

  function jsucc(id, result)
    return {jsonrpc = "2.0", id = id, result = result}
  end

  function jerr(id, code, message)
    return {jsonrpc = "2.0", id = id, error = {code = code, message = message}}
  end

  handlers = {}
  function handlers.SB_create()
    local dst = params.dst
    if tx:get(dst) ~= nil then
      return jerr(id, -32602, "account already exists")
    end

    tx:put(dst, params.amt)
    return jsucc(id, 1)
  end

  function handlers.SB_read()
    local acc = params.account
    local amt = tx:get(acc)
    if amt == nil then
      return jerr(id, -32602, "account " .. acc .. " does not exist")
    end

    return jsucc(id, amt)
  end

  function handlers.SB_transfer()
    local src = params.src
    local dst = params.dst
    local src_n = tx:get(src)
    if src_n == nil then
      return jerr(id, -32602, "source account does not exist")
    end

    local dst_n = tx:get(dst)
    if dst_n == nil then
      return jerr(id, -32602, "destination account does not exist")
    end

    local amt = params.amt
    if src_n < amt then
      return jerr(id, -32602, "insufficient funds")
    end

    tx:put(src, src_n - amt)
    tx:put(dst, dst_n + amt)

    return jsucc(id, 1)
  end

  return handlers[method]()
  )xxx";

    Store tables;
    auto& table = tables.create<TableII>("t", kv::SecurityDomain::PUBLIC);
    Store::Tx txs;
    auto tx = txs.get_view(table);

    auto create = [tx](int dst, int amt) {
      json params;
      params["dst"] = dst;
      params["amt"] = amt;
      Interpreter li;
      li.register_metatable<TxII>(kv_methods<TxII>);
      const auto r = li.invoke<json>(code, tx, 1, 1, "SB_create", params);
      REQUIRE(r.find("error") == r.end());
      REQUIRE(tx->get(dst) == amt);
    };

    auto read = [tx](int acc, int expected) {
      json params;
      params["account"] = acc;
      Interpreter li;
      li.register_metatable<TxII>(kv_methods<TxII>);
      const auto r = li.invoke<json>(code, tx, 1, 1, "SB_read", params);
      REQUIRE(int(r["result"]) == expected);
    };

    auto transfer = [tx](int src, int dst, int amt) {
      json params;
      params["src"] = src;
      params["dst"] = dst;
      params["amt"] = amt;
      const auto dst_before = tx->get(dst);
      const auto src_before = tx->get(src);

      Interpreter li;
      li.register_metatable<TxII>(kv_methods<TxII>);
      const auto r = li.invoke<json>(code, tx, 1, 1, "SB_transfer", params);
      REQUIRE(r.find("error") == r.end());
      REQUIRE(*tx->get(dst) == *dst_before + amt);
      REQUIRE(*tx->get(src) == *src_before - amt);
    };

    create(1, 234);
    read(1, 234);

    create(5, 678);
    read(5, 678);

    transfer(1, 5, 7);
    read(5, 685);
  }

  TEST_CASE("read-only")
  {
    constexpr auto put(
      "local tx, k, v = ...;"
      "return tx:put(k, v)");
    constexpr auto get(
      "local tx, k = ...;"
      "return tx:get(k)");

    Store tables;
    auto& table = tables.create<TableII>("t", kv::SecurityDomain::PUBLIC);
    Store::Tx txs;
    auto tx = txs.get_view(table);

    Interpreter li;
    li.register_metatable<TxII>(kv_methods_read_only<TxII>);
    tx->put(1, 2);

    // read works
    REQUIRE(li.invoke<int>(get, tx, 1) == 2);
    // write doesn't
    REQUIRE_THROWS_AS(li.invoke<bool>(put, tx, 1, 3), lua::ex);
  }
}
