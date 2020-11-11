// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "lua_json.h"

/**
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
        const K key = get_internal<K>(l, -1);
        const auto search = tx->get(key);
        if (!search)
        {
          lua_pushnil(l);
          return 1;
        }
        push_internal(l, *search);
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
        const K key = get_internal<K>(l, -1);
        const auto search = tx->get_globally_committed(key);
        if (!search)
        {
          lua_pushnil(l);
          return 1;
        }
        push_internal(l, *search);
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
        const K key = get_internal<K>(l, -2);
        const V value = get_internal<V>(l, -1);
        const auto b = tx->put(key, value);
        lua_pushboolean(l, b);
        return 1;
      }

      static int remove(lua_State* l)
      {
        constexpr int n_args = 2;
        sanitize_stack_idx(l, n_args);

        auto tx = UD::unbox(l, -2);
        const K key = get_internal<K>(l, -1);
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
          push_internal(l, k);
          push_internal(l, v);

          // Call the lua functor. This pops the args and functor-copy
          const auto ret = lua_pcall(l, 2, 0, 0);

          if (ret != 0)
          {
            const auto err = get_internal<std::string>(l, -1);
            throw lua::ex(err);
          }

          return true;
        });

        return 0;
      }

    private:
      // Bodge: Special-case byte-vector. Via JSON we would produce a base64
      // string, but instead we build a Lua list directly
      template <typename T>
      static T get_internal(lua_State* l, int idx)
      {
        if constexpr (std::is_same_v<T, std::vector<uint8_t>>)
        {
          return lua::check_get<T>(l, idx);
        }
        else
        {
          return lua::check_get<nlohmann::json>(l, idx);
        }
      }

      template <typename T>
      static void push_internal(lua_State* l, const T& t)
      {
        if constexpr (std::is_same_v<T, std::vector<uint8_t>>)
        {
          lua::push_raw<T>(l, t);
        }
        else
        {
          lua::push_raw<nlohmann::json>(l, t);
        }
      }
    };

    template <typename T, typename X = T>
    const luaL_Reg kv_methods[] = {
      {"get", KvTable<T, X>::get},
      {"get_globally_committed", KvTable<T, X>::get_globally_committed},
      {"remove", KvTable<T, X>::remove},
      {"foreach", KvTable<T, X>::foreach},
      {"put", KvTable<T, X>::put},
      {nullptr, nullptr}};

    template <typename T, typename X = T>
    const luaL_Reg kv_methods_read_only[] = {
      {"get", KvTable<T, X>::get},
      {"get_globally_committed", KvTable<T, X>::get_globally_committed},
      {"foreach", KvTable<T, X>::foreach},
      {nullptr, nullptr}};

  } // namespace lua
} // namespace ccf