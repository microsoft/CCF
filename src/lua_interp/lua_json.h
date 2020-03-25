// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "lua_user_data.h"

#include <nlohmann/json.hpp>

/**
 * @file lua_json.h
 * @brief Convert between nlohmann::json and lua
 */
namespace ccf
{
  namespace lua
  {
    /**
     * Push a json value onto the lua stack
     *
     * Leaves a single new value, but may use additional stack space. Objects
     * and arrays in json become tables in lua, with string and integer indexes
     * (starting from 1) respectively.
     */
    template <>
    inline void push_raw(lua_State* l, const nlohmann::json& j)
    {
      switch (j.type())
      {
        case nlohmann::json::value_t::null:
        {
          lua_pushnil(l);
          break;
        }
        case nlohmann::json::value_t::object:
        {
          lua_newtable(l);
          for (auto it = j.begin(); it != j.end(); ++it)
          {
            push_raw(l, it.value());
            lua_setfield(l, -2, it.key().c_str());
          }
          break;
        }
        case nlohmann::json::value_t::array:
        {
          lua_newtable(l);
          size_t i = 0;
          for (const auto& v : j)
          {
            push_raw(l, v);
            lua_seti(
              l, -2, ++i); // lua 'arrays' are 1-indexed, so pre-increment
          }
          break;
        }
        case nlohmann::json::value_t::string:
        {
          const std::string s = j;
          lua_pushstring(l, s.c_str());
          break;
        }
        case nlohmann::json::value_t::boolean:
        {
          const bool b = j;
          lua_pushboolean(l, b);
          break;
        }
        case nlohmann::json::value_t::number_integer:
        case nlohmann::json::value_t::number_unsigned:
        {
          const lua_Integer i = j;
          lua_pushinteger(l, i);
          break;
        }
        case nlohmann::json::value_t::number_float:
        {
          const lua_Number n = j;
          lua_pushnumber(l, n);
          break;
        }
        default:
        {
          throw ex("Unhandled json type, unable to push onto lua stack");
        }
      }
    }

    template <>
    inline nlohmann::json check_get(lua_State* l, int arg)
    {
      arg = sanitize_stack_idx(l, arg);

      nlohmann::json j;
      switch (lua_type(l, arg))
      {
        case LUA_TNIL:
        {
          j = nullptr;
          break;
        }
        case LUA_TNUMBER:
        {
          if (lua_isinteger(l, arg))
            j = lua_tointegerx(l, arg, nullptr);
          else
            j = lua_tonumberx(l, arg, nullptr);
          break;
        }
        case LUA_TBOOLEAN:
        {
          j = bool(lua_toboolean(l, arg));
          break;
        }
        case LUA_TSTRING:
        {
          j = lua_tolstring(l, arg, nullptr);
          break;
        }
        case LUA_TTABLE:
        {
          constexpr auto ikey = -2;
          constexpr auto ivalue = -1;

          // to parse a table, we need two additional stack slots
          if (!lua_checkstack(l, 2))
            throw ex("Not enough stack left for iterating over table.");

          // (1) attempt to create a json array
          // there must a sequence of integer keys starting from 1
          auto a = nlohmann::json::array();
          bool is_array = true;
          bool saw_integer_key = false;
          int prev_key = 0;
          lua_pushnil(l); // first key
          while (lua_next(l, arg) != 0)
          {
            is_array = false;
            // is the key an integer
            if (!lua_isinteger(l, ikey))
              break;
            saw_integer_key = true;

            // does the key come directly after the previous one?
            if (const auto key = lua_tointegerx(l, ikey, nullptr);
                key != ++prev_key)
              break;

            is_array = true;
            a.push_back(check_get<nlohmann::json>(l, ivalue));
            // remove value and keep key for next iteration
            lua_pop(l, 1);
          }
          if (is_array)
          {
            j = std::move(a);
            break;
          }

          const auto non_string_key = []() {
            throw ex("Cannot create Json table with integer key.");
          };
          if (saw_integer_key)
            non_string_key();

          // failed to create array; pop the remaining k-v pair from the stack
          lua_pop(l, 2);

          // (2) parse the table as dictionary instead
          // since json only supports strings as keys, we throw for anything
          // else
          lua_pushnil(l); // first key
          while (lua_next(l, arg) != 0)
          {
            // need an extra check here, because Lua will report ints to be
            // strings
            if (lua_isinteger(l, ikey))
              non_string_key();

            const auto key = check_get<std::string>(l, ikey);
            j[key] = check_get<nlohmann::json>(l, ivalue);
            // pop value and keep original key for next iteration
            lua_pop(l, 1);
          }
          break;
        }
        case LUA_TUSERDATA:
        case LUA_TFUNCTION:
          // do nothing
          break;

        default:
          throw ex(
            "Encountered unexpected lua type while constructing json object.");
      }
      return j;
    }
  } // namespace lua
} // namespace ccf