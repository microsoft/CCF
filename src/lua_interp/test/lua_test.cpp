// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../lua_interp.h"
#include "../lua_json.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <map>
#include <string>
#include <vector>

using namespace ccf;
using namespace ccf::lua;
using namespace std;

static constexpr auto retnil = "return nil";
static constexpr auto ret5 = "return 5";
static constexpr auto mulab = "local a, b = ...; return a*b";

TEST_CASE("return constant")
{
  REQUIRE(Interpreter().invoke<int>(ret5) == 5);
}

TEST_CASE("wrong return type")
{
  REQUIRE_THROWS_AS(Interpreter().invoke<bool>(ret5), lua::ex);
}

TEST_CASE("return nil")
{
  REQUIRE(Interpreter().invoke<std::nullptr_t>(retnil) == nullptr);
}

TEST_CASE("pass nil")
{
  REQUIRE(Interpreter().invoke<bool>("return ... == nil", nullptr));
}

TEST_CASE("basic number multiplication")
{
  constexpr auto a = 5;
  constexpr auto b = 4;
  REQUIRE(Interpreter().invoke<int>(mulab, a, b) == a * b);

  // Extra arguments are ignored
  REQUIRE(Interpreter().invoke<int>(mulab, a, b, a) == a * b);
  REQUIRE(Interpreter().invoke<int>(mulab, a, b, b) == a * b);
  REQUIRE(Interpreter().invoke<int>(mulab, a, b, nullptr, nullptr) == a * b);
  REQUIRE(
    Interpreter().invoke<int>(mulab, a, b, "Extra nonsense", nullptr, a) ==
    a * b);
}

TEST_CASE("compile bytecode")
{
  constexpr auto a = 5;
  constexpr auto b = 4;
  const auto code = compile(mulab);

  REQUIRE(
    Interpreter().invoke<int>(code, b, a) ==
    Interpreter().invoke<int>(mulab, b, a));
}

TEST_CASE("compare doubles")
{
  constexpr auto a = 1.1;
  constexpr auto b = 1.2;
  REQUIRE(
    Interpreter().invoke<bool>("local a,b = ...; return a >= b", a, b) ==
    false);
  REQUIRE(
    Interpreter().invoke<bool>("local a,b = ...; return b > a", a, b) == true);
}

TEST_CASE("multiple invokes")
{
  auto a = 1;
  auto b = 2;
  constexpr auto return_arg("local n = ...; return n");

  constexpr auto set_global("g = ...; return g");
  constexpr auto get_global("return g");

  auto li = Interpreter();

  REQUIRE(li.invoke<int>(ret5) == 5);
  REQUIRE(li.invoke<int>(ret5) == 5);

  REQUIRE(li.invoke<int>(return_arg, a) == a);
  REQUIRE(li.invoke<int>(return_arg, b) == b);

  REQUIRE(li.invoke<int>(set_global, a) == a);
  REQUIRE(li.invoke<int>(get_global) == a);
  REQUIRE(li.invoke<int>(return_arg, b) == b);
  REQUIRE(li.invoke<int>(get_global) == a);
}

TEST_CASE("build and modify table")
{
  constexpr auto a = 5;
  constexpr auto b = 4;
  constexpr auto code(
    "local a,b = ...;"
    "local t = {};"
    "t.x = a;"
    "t.y = b;"
    "t.result = a * b;"
    "return t.result");

  REQUIRE(Interpreter().invoke<int>(code, a, b) == a * b);
}

TEST_CASE("access modules")
{
  REQUIRE(Interpreter().invoke<bool>("return nil ~= math"));
  REQUIRE(
    Interpreter().invoke<int>("return math.maxinteger") == (int)LUA_MAXINTEGER);

  REQUIRE(Interpreter().invoke<bool>("return nil ~= string.reverse"));
  REQUIRE(
    Interpreter().invoke<std::string>(
      "return string.reverse(...)", "reverse") == "esrever");

  REQUIRE(Interpreter().invoke<bool>("return nil ~= table.sort"));
  REQUIRE(
    Interpreter().invoke<std::string>(
      "local t = {'d', 'a', 'c', 'b'}; table.sort(t); return t[2]") == "b");
}

namespace moduletest
{
  static int foo(lua_State* l)
  {
    auto a = lua_tointeger(l, 1);
    auto b = lua_tointeger(l, 2);
    auto c = lua_tointeger(l, 3);

    lua_pushinteger(l, a + b + c);
    return 1;
  }

  static constexpr auto initial_bar = 3;
  static constexpr auto NAME = "test";
  static constexpr auto BAR = "bar";

  static constexpr luaL_Reg lib[] = {
    {"foo", foo}, {BAR, nullptr}, {nullptr, nullptr}};

  LUAMOD_API int open(lua_State* l)
  {
    luaL_newlib(l, lib);
    lua_pushnumber(l, initial_bar);
    lua_setfield(l, -2, BAR);
    return 1;
  }
}

TEST_CASE("user module")
{
  constexpr auto n = 2;
  constexpr auto code(
    "local n = ...; local b = test.bar; test.bar = 7;"
    "return test.foo(n, b, test.bar)");

  auto li = Interpreter();
  li.load_module(moduletest::NAME, moduletest::open);
  REQUIRE(li.invoke<int>(code, n) == n + moduletest::initial_bar + 7);
}

namespace ccf
{
  struct Point
  {
    int x = 2;
    int y = 3;
  };

  using PointUD = UserData<Point>;

  static int get_x(lua_State* l)
  {
    const auto p = PointUD::unbox(l);
    lua_pushinteger(l, p->x);
    return 1;
  }

  static int get_y(lua_State* l)
  {
    const auto p = PointUD::unbox(l);
    lua_pushinteger(l, p->y);
    return 1;
  }

  static int set_x(lua_State* l)
  {
    auto p = PointUD::unbox(l);
    auto n = luaL_checkinteger(l, 2);
    p->x = n;
    return 0;
  }

  static int set_y(lua_State* l)
  {
    auto p = PointUD::unbox(l);
    auto n = luaL_checkinteger(l, 2);
    p->y = n;
    return 0;
  }

  constexpr luaL_Reg point_metatable_methods[] = {{"getX", get_x},
                                                  {"getY", get_y},
                                                  {"setX", set_x},
                                                  {"setY", set_y},
                                                  {nullptr, nullptr}};
}

TEST_CASE("boxed user data")
{
  Point p;

  auto li = Interpreter();
  li.register_metatable<Point>(point_metatable_methods);

  constexpr auto getsum(
    "local p = ...;"
    "return p:getX() + p:getY()");

  SUBCASE("access")
  {
    REQUIRE(li.invoke<int>(getsum, &p) == p.x + p.y);
  }

  SUBCASE("modify")
  {
    Point orig = p;

    constexpr auto doubler(
      "local p = ...;"
      "p:setX(p:getX() * 2);"
      "p:setY(p:getY() * 2)");

    li.invoke<std::nullptr_t>(doubler, &p);
    REQUIRE(p.x == orig.x * 2);
    REQUIRE(p.y == orig.y * 2);
    REQUIRE(li.invoke<int>(getsum, &p) == p.x + p.y);
  }
}

TEST_CASE("json")
{
  SUBCASE("null")
  {
    const nlohmann::json j;
    REQUIRE(Interpreter().invoke<bool>("return nil == ...", j));
  }

  SUBCASE("int")
  {
    constexpr int n = 666;
    const nlohmann::json j = n;
    REQUIRE(Interpreter().invoke<int>("return ...", n) == n);
  }

  SUBCASE("string")
  {
    constexpr auto s = "Round trip me";
    const nlohmann::json j = s;
    REQUIRE(Interpreter().invoke<std::string>("return ...", s) == s);
  }

  SUBCASE("table")
  {
    const nlohmann::json j = {
      {"pi", 3.141},
      {"happy", true},
      {"name", "Niels"},
      {"nothing", nullptr},
      {"answer", {{"everything", 42}}},
      {"list", {1, 0, 2}},
      {"object", {{"currency", "USD"}, {"value", 42.99}}}};

    constexpr auto code(
      "local j, s = ...;"
      "if not j.happy then return 'unhappy' end;"
      "if j.name ~= s then return 'badly named' end;"
      "return j.pi + j.answer.everything");

    auto expected = (double)j["pi"] + (double)j["answer"]["everything"];
    auto actual = Interpreter().invoke<double>(code, j, j["name"]);
    REQUIRE(actual == expected);
  }

  SUBCASE("empty table")
  {
    constexpr auto code("return {}");
    const auto j = Interpreter().invoke<nlohmann::json>(code);
    // an empty table is supposed to be translated into an empty array
    REQUIRE(j.type() == nlohmann::json::value_t::array);
    REQUIRE(!j.size());
    // can we unserialize to map and vector?
    map<int, int> m = j;
    REQUIRE(!m.size());
    vector<string> v = j;
    REQUIRE(!v.size());
  }
}

TEST_CASE("push table and attempt to print")
{
  static constexpr auto script = R"xxx(
  t = ...
  return (t['a'] * t['b']) == 10 and t['d']
  )xxx";

  Interpreter interp;
  interp.push_code(script);
  interp.push_table("a", 5, "b", 2, "c", "x", "d", true);

  // write the stack to a stringstream
  stringstream ss;
  interp.print_stack(ss);
  REQUIRE(ss.str().length());
  REQUIRE(interp.invoke_raw<bool>(1) == true);
}

TEST_CASE("table parsing")
{
  // this should be translated to an array (since there are consecutive indexes)
  constexpr auto valid = "return {1, 2}";
  vector<int> a = Interpreter().invoke<nlohmann::json>(valid);
  REQUIRE(a == vector<int>{1, 2});

  // this should throw, because it can neither be translated to an array, nor to
  // a map (because Json does not support integer keys) However, if we should
  // ever move away from json, this could work.
  constexpr auto invalid = "return {[1] = 1, [3] = 2}";
  REQUIRE_THROWS_AS(Interpreter().invoke<nlohmann::json>(invalid), lua::ex);
}

TEST_CASE("infinite loop prevention")
{
  REQUIRE_THROWS_AS(Interpreter().invoke("while true do end"), lua::ex);

  {
    INFO("Callstack in error message");

    bool threw = false;
    try
    {
      Interpreter().invoke(R"xxx(
        function foo()
          local function baz()
            while true do end
          end

          t = {}
          function t:bar()
            while true do
              baz()
            end
          end

          while true do
            t.bar()
          end
        end

        foo()
      )xxx");
    }
    catch (const lua::ex& e)
    {
      threw = true;
      const std::string msg = e.what();
      REQUIRE(msg.find("baz") != std::string::npos);
      REQUIRE(msg.find("bar") != std::string::npos);
      REQUIRE(msg.find("foo") != std::string::npos);
    }
    REQUIRE(threw);
  }

  {
    constexpr auto script = R"xxx(
      n = 1
      for i = 1, 10 do
        n = n * 2
      end
    )xxx";

    Interpreter interp;
    REQUIRE_NOTHROW(interp.invoke(script));

    INFO("Execution limit can be adjusted");
    interp.set_execution_limit(10);
    REQUIRE_THROWS_AS(interp.invoke(script), lua::ex);

    INFO("Execution limit can be removed entirely");
    interp.remove_execution_limit();
    REQUIRE_NOTHROW(interp.invoke(script));
  }
}
