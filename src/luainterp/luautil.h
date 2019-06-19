// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>
extern "C"
{
#include "../../3rdparty/lua/lauxlib.h"
#include "../../3rdparty/lua/lua.h"
}

namespace ccf
{
  namespace lua
  {
    /** Lua exception
     */
    class ex : public std::logic_error
    {
      using logic_error::logic_error;
    };

    /**
     * @brief Sanitize a possibly relative stack index
     *
     * @param l Lua context
     * @param idx stack index
     * @return int if the stack index is negative/relative, the absolute index
     * is returned.
     */
    inline int sanitize_stack_idx(lua_State* l, int idx)
    {
      const auto stack_size = lua_gettop(l);
      if (stack_size < abs(idx))
        throw ex("Index exceeds stack size.");

      // if arg is a negative relative index, make it absolute
      return idx < 0 ? stack_size + 1 + idx : idx;
    }

    /**
     * @brief Get the absolute stack index from a negative/relative one.
     *
     * @param l Lua context
     * @param idx stack index
     * @return int the absolute index
     */
    inline int absolute_stack_idx(lua_State* l, int idx)
    {
      const auto stack_size = lua_gettop(l);
      return idx < 0 ? stack_size + 1 + idx : idx;
    }

    inline void push_raw(lua_State* l, const char* s)
    {
      lua_pushstring(l, s);
    }

    inline void push_raw(lua_State* l, int i)
    {
      lua_pushinteger(l, i);
    }

    inline void push_raw(lua_State* l, uint64_t i)
    {
      lua_pushinteger(l, (lua_Integer)i);
    }

    inline void push_raw(lua_State* l, double d)
    {
      lua_pushnumber(l, d);
    }

    inline void push_raw(lua_State* l, bool b)
    {
      lua_pushboolean(l, b);
    }

    inline void push_raw(lua_State* l, std::nullptr_t)
    {
      lua_pushnil(l);
    }

    /** The base push case. Specialize this to push other types onto the lua
     * stack.
     */
    template <typename T>
    void push_raw(lua_State* l, const T& o)
    {
      static_assert(
        std::is_empty<T>::value,
        "Unsupported type for Lua stack object (push).");
    }

    template <>
    inline void push_raw(lua_State* l, const std::string& s)
    {
      lua_pushstring(l, s.c_str());
    }

    template <typename F0, typename F1>
    auto check_and_convert(lua_State* l, int arg, F0 check, F1 convert)
    {
      sanitize_stack_idx(l, arg);
      if (!check(l, arg)) // e.g., lua_isnumber()
        throw ex("Lua stack object has wrong type.");

      return convert(l, arg, nullptr); // e.g., lua_tonumberx()
    }

    template <typename F0, typename F1>
    auto top_of_stack(lua_State* l, F0 check, F1 convert)
    {
      return check_and_convert(l, -1, check, convert);
    }

    template <typename T>
    inline T check_get(lua_State* l, int arg)
    {
      static_assert(
        std::is_empty<T>::value,
        "Unsupported type for Lua stack object (check_get).");
      return {};
    }

    template <>
    inline int check_get(lua_State* l, int arg)
    {
      return check_and_convert(l, arg, lua_isinteger, lua_tointegerx);
    }

    template <>
    inline uint64_t check_get(lua_State* l, int arg)
    {
      return (uint64_t)check_get<int>(l, arg);
    }

    template <>
    inline double check_get(lua_State* l, int arg)
    {
      return check_and_convert(l, arg, lua_isnumber, lua_tonumberx);
    }

    template <>
    inline std::string check_get(lua_State* l, int arg)
    {
      return std::string(
        check_and_convert(l, arg, lua_isstring, lua_tolstring));
    }

    template <>
    inline bool check_get(lua_State* l, int arg)
    {
      return check_and_convert(
        l,
        arg,
        [](lua_State* L, int n) { return lua_isboolean(L, n); },
        [](lua_State* L, int n, void*) { return lua_toboolean(L, n) != 0; });
    }

    template <>
    inline std::nullptr_t check_get(lua_State* l, int arg)
    {
      return check_and_convert(
        l,
        arg,
        [](lua_State* L, int n) { return lua_isnil(L, n); },
        [](lua_State*, int, void*) { return nullptr; });
    }

    template <typename T>
    inline T get_top(lua_State* l)
    {
      return check_get<T>(l, -1);
    }

    /**
     * @brief Compile Lua script to bytecode.
     *
     * @param script the Lua script
     * @return std::vector<uint8_t> the compiled bytecode
     */
    inline std::vector<uint8_t> compile(const std::string& script)
    {
      auto l = luaL_newstate();
      if (luaL_loadbuffer(l, script.c_str(), script.size(), nullptr))
        throw lua::ex("Failed to load Lua code (compile)");

      std::vector<uint8_t> b;
      lua_dump(
        l,
        [](lua_State*, const void* p, size_t sz, void* v) {
          auto const _v = reinterpret_cast<std::vector<uint8_t>*>(v);
          auto const _p = reinterpret_cast<const uint8_t*>(p);
          _v->insert(_v->end(), _p, _p + sz);
          return 0;
        },
        &b,
        1); // strip debug symbols
      lua_close(l);
      return b;
    }

  } // namespace lua
} // namespace ccf
