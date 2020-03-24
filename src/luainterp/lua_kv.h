// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "lua_json.h"

#include <kv/kv.h>

/**
 * @file luajsonKvTable.h
 * @brief Wrap KvTable structures so they can be used in lua. Types are
 * translated using nlohmann::json.
 */
namespace ccf
{
  namespace lua
  {
    /**
     * Static functions to interact with a kv::Map<K, V>::TxView from lua.
     *
     * Each of the Txs public methods have an equivalent lua function. Where the
     * C++ api throws exceptions or returns empty options, the lua version will
     * return nil.
     *
     * nlohmann::json is used to transfer types between C++/the KvTable and lua.
     * Thus, all types that nlohmann::json can serialize/unserialize can be
     * passed.
     */
    template <typename TxView, typename X = TxView>
    struct KvTable
    {
      using UD = UserData<TxView, X>;
      using K = typename TxView::KeyType;
      using V = typename TxView::ValueType;

      /**
       * @brief Callable from lua.
       * Expects the following arguments from lua.
       * #1 (-2): self/table
       * #2 (-1): key
       *
       * @param l
       * @return int
       */
      static int get(lua_State* l)
      {
        constexpr int n_args = 2;
        sanitize_stack_idx(l, n_args);

        auto tx = UD::unbox(l, -2);
        const K key = lua::check_get<nlohmann::json>(l, -1);
        const auto search = tx->get(key);
        if (!search)
        {
          lua_pushnil(l);
          return 1;
        }
        lua::push_raw<nlohmann::json>(l, *search);
        return 1;
      }

      /**
       * @brief Callable from lua.
       * Expects the following arguments from lua.
       * #1 (-2): self/table
       * #2 (-1): key
       * @param l
       * @return int
       */
      static int get_globally_committed(lua_State* l)
      {
        constexpr int n_args = 2;
        sanitize_stack_idx(l, n_args);

        auto tx = UD::unbox(l, -2);
        const K key = lua::check_get<nlohmann::json>(l, -1);
        const auto search = tx->get_globally_committed(key);
        if (!search)
        {
          lua_pushnil(l);
          return 1;
        }
        lua::push_raw<nlohmann::json>(l, *search);
        return 1;
      }

      /**
       * @brief Callable from lua.
       * Expects the following arguments from lua.
       * #1 (-3): self/table
       * #2 (-2): key
       * #3 (-1): value
       *
       * @param l
       * @return int
       */
      static int put(lua_State* l)
      {
        constexpr int n_args = 3;
        sanitize_stack_idx(l, n_args);

        auto tx = UD::unbox(l, -3);
        const K key = lua::check_get<nlohmann::json>(l, -2);
        const V value = lua::check_get<nlohmann::json>(l, -1);
        const auto b = tx->put(key, value);
        lua_pushboolean(l, b);
        return 1;
      }

      static int remove(lua_State* l)
      {
        constexpr int n_args = 2;
        sanitize_stack_idx(l, n_args);

        auto tx = UD::unbox(l, -2);
        const K key = lua::check_get<nlohmann::json>(l, -1);
        const auto b = tx->remove(key);
        lua_pushboolean(l, b);
        return 1;
      }

      static int foreach(lua_State* l)
      {
        constexpr int n_args = 2;
        sanitize_stack_idx(l, n_args);

        const auto ifunc = absolute_stack_idx(l, -1);
        if (!lua_isfunction(l, ifunc))
        {
          lua_pushnil(l);
          return 1;
        }

        UD::unbox(l, -2)->foreach([l, ifunc](const K& k, const V& v) {
          // Dup the lua functor on the top of the stack
          lua_pushvalue(l, ifunc);

          // Translate the arguments using nlohmann::json and push them to the
          // stack
          lua::push_raw<nlohmann::json>(l, k);
          lua::push_raw<nlohmann::json>(l, v);

          // Call the lua functor. This pops the args and functor-copy
          lua_pcall(l, ifunc, 0, 0);
          return true;
        });

        return 0;
      }

      static int start_order(lua_State* l)
      {
        constexpr int n_args = 1;
        sanitize_stack_idx(l, n_args);
        const auto v = UD::unbox(l, -1)->start_order();
        lua_pushinteger(l, v);
        return 1;
      }

      static int end_order(lua_State* l)
      {
        constexpr int n_args = 1;
        sanitize_stack_idx(l, n_args);
        auto tx = UD::unbox(l);
        try
        {
          const auto v = tx->end_order();
          lua_pushinteger(l, v);
          return 1;
        }
        catch (const std::logic_error& e)
        {
          lua_pushnil(l);
          return 1;
        }
      }
    };

    template <typename T, typename X = T>
    const luaL_Reg kv_methods[] = {
      {"get", KvTable<T, X>::get},
      {"get_globally_committed", KvTable<T, X>::get_globally_committed},
      {"remove", KvTable<T, X>::remove},
      {"foreach", KvTable<T, X>::foreach},
      {"start_order", KvTable<T, X>::start_order},
      {"end_order", KvTable<T, X>::end_order},
      {"put", KvTable<T, X>::put},
      {nullptr, nullptr}};

    template <typename T, typename X = T>
    const luaL_Reg kv_methods_read_only[] = {
      {"get", KvTable<T, X>::get},
      {"get_globally_committed", KvTable<T, X>::get_globally_committed},
      {"foreach", KvTable<T, X>::foreach},
      {"start_order", KvTable<T, X>::start_order},
      {"end_order", KvTable<T, X>::end_order},
      {nullptr, nullptr}};

  } // namespace lua
} // namespace ccf