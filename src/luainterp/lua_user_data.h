// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "lua_util.h"

#include <typeinfo>

/**
 * @file lua_user_data.h
 * @brief Helper to hide common lua boilerplate
 *
 * To pass data from C++ to lua, we push userdata onto the stack. This
 * userdata is a simple box containing a pointer to the real data, with an
 * associated metatable containing the methods which can be called on it. The
 * real data is owned and managed in C++, only the box is garbage collected by
 * Lua. The metatable is identified and looked up by a string name, and the same
 * boxing boilerplate is needed for every type. This aims to cut down that
 * boilerplate, providing templated functions and removing any knowledge of
 * magic strings or the boxing process.
 *
 * For example, to wrap a simple Point struct:
 *
 * @code
 *    // The type we want to wrap
 *    struct Point
 *    {
 *      int x;
 *      int y;
 *    };
 *
 *    using PointUD = UserData<Point>;
 *
 *    // Define some lua C functions, using unbox
 *    static int get_x(lua_State* l)
 *    {
 *      const auto p = PointUD::unbox(l);
 *      lua_pushinteger(l, p->x);
 *      return 1;
 *    }
 *
 *    static int set_x(lua_State* l)
 *    {
 *      auto p = PointUD::unbox(l);
 *      auto n = luaL_checkinteger(l, 2);
 *      p->x = n;
 *      return 0;
 *    }
 *
 *    ...
 *
 *    // Associate functions with the names they'll be called from in lua
 *    constexpr luaL_Reg point_metatable_methods[] = {{"getx", get_x},
 *      {"setx", set_x}, ... {nullptr, nullptr}};
 * @endcode
 *
 * Then you can pass a Point to Interpreter:
 *
 * @code
 *    auto li = Interpreter();
 *    li.register_metatable<Point>(point_metatable_methods);
 *
 *    Point p;
 *    li.invoke<...>(..., &p);
 * @endcode
 *
 * And access it from lua:
 *
 * @code
 *    local p = ...
 *    local n = p:getx();
 *    p:setx(n + 5);
 *    ...
 * @endcode
 *
 */
namespace ccf
{
  namespace lua
  {
    template <typename T, typename X = T>
    struct UserData
    {
      /**
       * Returns a name for looking up the type's metatable
       *
       * The metatable for this type is looked up and registered by string, but
       * that is entirely an internal implementation detail. We could require
       * users to declare a static string themselves but this is an ugly bit of
       * boilerplate, with no guarantee of uniqueness. Instead we rely on
       * typeid, which may be mangled but should give us the uniqueness we're
       * looking for.
       */
      static const char* metatable_name()
      {
        return typeid(X).name();
      }

      /**
       * Pushes userdata onto the lua stack which wraps the given data.
       *
       * A metatable for T must have set in l, else an exception will be thrown.
       * The caller is responsible for ensuring that d remains valid.
       */
      static void push_boxed(lua_State* l, T* d)
      {
        auto p = reinterpret_cast<T**>(lua_newuserdata(l, sizeof(d)));
        auto name = metatable_name();
        if (luaL_getmetatable(l, name) == LUA_TNIL)
          throw ex("Metatable not registered");

        lua_setmetatable(l, -2);
        *p = d;
      }

      /**
       * Checks the item on the lua stack at the given position is of the
       * correct type, and returns a raw pointer to the wrapped data.
       *
       * CAUTION: arg here means the n-th (1-based) arg to the function.
       *  Lua-style negative indexing does not work.
       */
      static T* unbox(lua_State* l, int arg = 1)
      {
        return *reinterpret_cast<T**>(
          luaL_checkudata(l, arg, metatable_name()));
      }
    };

    /**
     * @brief specialization of push_raw() that 'boxes' pointers.
     * Disabled for const char* as we want to treat those as strings (see
     * lua_util.h).
     *
     * @tparam T object type of the pointer
     * @param l Lua context
     * @param p the pointer
     */
    template <
      typename T,
      /* exclude const char* */
      typename = std::enable_if_t<!std::is_same_v<T, const char>>>
    void push_raw(lua_State* l, T* p)
    {
      UserData<T>::push_boxed(l, p);
    }

    /**
     * @brief Wrapper class for specifying "extended types" for metatable
     * registration. This addresses the problem of registering different
     * metatables for a single C++ type. (With the basic UserData only a single
     * metatable can be registered per type.)
     *
     * @tparam T the actual type of the pointer that is to be pushd to Lua
     * @tparam X an arbitrary type "modifier"; likely s.th. likely an empty type
     * like struct M {};
     */
    template <typename T, typename X>
    struct UserDataExt
    {
      T* p;
    };

    template <typename T, typename X>
    void push_raw(lua_State* l, const UserDataExt<T, X>& udx)
    {
      UserData<T, UserDataExt<T, X>>::push_boxed(l, udx.p);
    }

  } // namespace lua
} // namespace ccf