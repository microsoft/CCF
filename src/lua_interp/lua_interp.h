// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <optional>
#include <ostream>
#include <sstream>
#include <stdint.h>
#include <string>
#include <vector>
extern "C"
{
#include "../../3rdparty/lua/lualib.h"
}
#include "lua_json.h"

/**
 * @file lua_interp.h
 * @brief Lua interpreter and associated helpers
 */
namespace ccf
{
  namespace lua
  {
    /**
     * Hook called if lua instruction count gets too high - assume this is an
     * unwanted infinite loop and abandon by throwing an exception
     */
    inline void instruction_limit_hook(lua_State* l, lua_Debug* dbg)
    {
      std::stringstream ss;

      lua_getinfo(l, "S", dbg);
      ss << "Lua instruction limit reached while executing " << dbg->short_src
         << std::endl;

      int level = 0;
      ss << "Callstack:" << std::endl;
      while (lua_getstack(l, level, dbg) == 1)
      {
        lua_getinfo(l, "nSl", dbg);

        ss << " [" << level << "] Line " << dbg->currentline << " in ";
        if (dbg->name != nullptr)
        {
          if (strlen(dbg->namewhat) > 0)
          {
            ss << dbg->namewhat << " ";
          }
          ss << dbg->name;
        }
        else
        {
          ss << "<unknown>";
        }

        ss << " : " << dbg->short_src << std::endl;

        ++level;
      }

      throw ex(ss.str());
    }

    /**
     * @brief C++ frontend for the Lua interpreter
     */
    class Interpreter
    {
    private:
      lua_State* l;

      std::optional<size_t> execution_limit;

      /**
       * @brief Check that the stack has enough space to push an element of the
       * templated type
       *
       */
      void prepare_push(unsigned int slots = 1)
      {
        if (!lua_checkstack(l, slots))
          throw lua::ex("Lua stack size exceeded.");
      }

      /* required for cases where invoke() is called without args.
        Could be avoided in C++17 with if constexpr (sizeof...(T)) */
      void push_n() {}

      static int panic(lua_State* l)
      {
        throw lua::ex("Lua panicked.");
        return 0;
      }

      template <typename T, typename... Args>
      void _push_table(const char* k, T&& v, Args&&... args)
      {
        push(v);
        lua_setfield(l, -2, k);
        _push_table(std::forward<Args>(args)...);
      }

      void _push_table() {}

    public:
      Interpreter() : execution_limit(1 << 22)
      {
        l = luaL_newstate();
        lua_atpanic(l, panic);

        // Modules that are exposed, to expose a new module
        // add it to this list
        static const luaL_Reg libs[] = {{LUA_GNAME, luaopen_base},
                                        {LUA_TABLIBNAME, luaopen_table},
                                        {LUA_STRLIBNAME, luaopen_string},
                                        {LUA_MATHLIBNAME, luaopen_math},
                                        {nullptr, nullptr}};

        // load these into the global table (same as luaL_openlibs, but with a
        // custom module list)
        const luaL_Reg* lib;
        for (lib = libs; lib->func; lib++)
        {
          luaL_requiref(l, lib->name, lib->func, 1);
          lua_pop(l, 1); /* remove lib */
        }

        // lua's garbage collector is left in its default state. As long as
        // instances of this Interpreter remain reasonably short-lived their
        // memory use is unlikely to be a problem - either they are destroyed
        // before the garbage collector ever runs, or they kept in check by
        // occasional
        //  mark-and-sweep passes.
        // If we trust that all scripts will avoid long-term growth and want to
        // remove the GC interruptions we could disable GC entirely:
        // lua_gc(l, LUA_GCSTOP);
      }

      ~Interpreter()
      {
        lua_close(l);
      }

      /**
       * @brief Push item to stack.
       *
       * @tparam T type of item
       * @param o the item
       */
      template <typename T>
      void push(T&& o)
      {
        prepare_push();
        lua::push_raw(l, std::forward<T>(o));
      }

      /**
       * @brief Push sequence of items to stack.
       */
      template <typename T, typename... Args>
      void push_n(T&& first, Args&&... args)
      {
        push(first);
        push_n(std::forward<Args>(args)...);
      }

      /**
       * @brief Pop item from stack.
       * @return T the type of the item
       */
      template <typename T>
      T pop()
      {
        const auto r = lua::get_top<T>(l);
        lua_pop(l, 1);
        return r;
      }

      /**
       * @brief Push a table with strings as keys and variying types as values.
       * For example:
       * interp.push_table(
       *   "a", 5, // 1st entry
       *   "b", 2, // 2nd entry
       *   "c", "x", // 3rd entry
       *   "d", true); // 4th entry
       *
       * @param k the first key
       * @param v the first value
       * @param args the remaining entries
       */
      template <typename T, typename... Args>
      void push_table(const char* k, T&& v, Args&&... args)
      {
        lua_newtable(l);
        _push_table(k, v, std::forward<Args>(args)...);
      }

      /**
       * @brief Invoke Lua script on sequence of arguments.
       *
       * Within the Lua code, the arguments can be accessed through "...".
       * For example, to add two numbers:
       * local a, b = ...
       * return a + b
       *
       * @param script the Lua script
       * @param args the arguments
       * @return T the result of invoking the Lua code on the arguments
       */
      template <typename T, typename... Args>
      T invoke(const std::string& script, Args&&... args)
      {
        push_code(script);
        return invoke_raw<T>(0, std::forward<Args>(args)...);
      }

      /**
       * @brief Invoke pre-compiled Lua bytecode on sequence of arguments.
       *
       * Within the Lua code, the arguments can be accessed through "...".
       * For example, to add two numbers:
       * local a, b = ...
       * return a + b
       *
       * @param bc the Lua bytecode
       * @param args the arguments
       * @return T the result of invoking the Lua bytecode on the arguments
       */
      template <typename T, typename... Args>
      T invoke(const std::vector<uint8_t>& bc, Args&&... args)
      {
        push_code(bc);
        return invoke_raw<T>(0, std::forward<Args>(args)...);
      }

      template <typename... Args>
      void invoke(const std::vector<uint8_t>& bc, Args&&... args)
      {
        push_code(bc);
        invoke_raw(0, std::forward<Args>(args)...);
      }

      template <typename... Args>
      void invoke(const std::string& s, Args&&... args)
      {
        push_code(s);
        invoke_raw(0, std::forward<Args>(args)...);
      }

      /**
       * @brief Invoke script that was previously pushed
       *
       * @param n_args_on_stack number of arguments that are already on the
       * stack; if n_args_on_stack=0, consider using invoke() instead.
       * @param args additional arguments to be pushed
       * @return T the result of invoking the Lua bytecode on the arguments
       */
      template <typename T, typename... Args>
      T invoke_raw(unsigned int n_args_on_stack, Args&&... args)
      {
        invoke_raw(n_args_on_stack, std::forward<Args>(args)...);
        return pop<T>();
      }

      template <typename... Args>
      void invoke_raw(unsigned int n_args_on_stack, Args&&... args)
      {
        push_n(std::forward<Args>(args)...);

        if (execution_limit.has_value())
        {
          lua_sethook(
            l, instruction_limit_hook, LUA_MASKCOUNT, execution_limit.value());
        }

        if (lua_pcall(l, sizeof...(Args) + n_args_on_stack, 1, 0))
        {
          const auto err = pop<std::string>();
          std::stringstream ss;
          ss << "Failed to run Lua code: " << err;
          throw lua::ex(ss.str());
        }
      }

      /** Push bytecode
       * @param bc the bytecode
       */
      void push_code(const std::vector<uint8_t>& bc)
      {
        push_code(reinterpret_cast<const char*>(bc.data()), bc.size());
      }

      /** Push script
       * @param s the script
       */
      void push_code(const std::string& s)
      {
        push_code(s.data(), s.size());
      }

      /** Push script
       * @param c the script
       * @param s the length of the string
       */
      void push_code(const char* c, const size_t s)
      {
        prepare_push();
        if (luaL_loadbufferx(l, c, s, nullptr, nullptr))
        {
          const auto err = pop<std::string>();
          std::stringstream ss;
          ss << "Failed to load Lua code: " << err;
          throw lua::ex(ss.str());
        }
      }

      /**
       * @brief Load a named module into the global table
       *
       * @param name the name which should be used to access the module from lua
       * @param open function which pushes this module onto the top of the
       * stack, eg luaopen_math
       */
      template <typename FOpen>
      void load_module(const char* name, FOpen open)
      {
        luaL_requiref(l, name, open, 1);
        lua_pop(l, 1); /* remove copy of module table from stack */
      }

      /**
       * @brief Register a named metatable, which can later be retrieved through
       * luaL_getmetatable
       *
       * @param name the metatable's identifier
       * @param funcs C-array of luaL_Reg entries giving the metatable's named
       * functions, terminated by a nullptr pair
       * @param skip_existing skip if metatable already exists. Otherwise,
       * merge.
       */
      void register_metatable(
        const char* name, const luaL_Reg* funcs, bool skip_existing)
      {
        constexpr auto metatable = -1;
        constexpr auto field = -2;
        prepare_push(2);
        const auto exists = !luaL_newmetatable(l, name);
        if (exists && skip_existing)
        {
          lua_pop(l, 1); // remove metatable from stack
          return;
        }

        for (const luaL_Reg* method = funcs; method->func; method++)
        {
          lua_pushcfunction(l, method->func);
          lua_setfield(l, field, method->name);
        }

        lua_pushvalue(l, metatable); // dup metatable
        lua_setfield(l, field, "__index"); // metatable.__index = metatable

        lua_pop(l, 1); // remove metatable from stack
      }

      //! Register a metatable for a certain UserData type.
      template <typename T, typename X = T>
      void register_metatable(const luaL_Reg* funcs, bool skip_existing = true)
      {
        register_metatable(
          UserData<T, X>::metatable_name(), funcs, skip_existing);
      }

      /** Get the raw state object */
      auto get_state()
      {
        return l;
      }

      /**
       * @brief Print the stack
       *
       * @param os the ostream to print to
       */
      void print_stack(std::ostream& os)
      {
        const auto stack_size = lua_gettop(l);
        for (int i = 1; i <= stack_size; i++)
        {
          const auto j = check_get<nlohmann::json>(l, i);
          os << i << " (" << lua_typename(l, lua_type(l, i)) << ")\n"
             << j.dump() << std::endl;
        }
      }

      /** Set maximum number of instructions which may be executed in a single
       * call to invoke */
      void set_execution_limit(size_t n)
      {
        execution_limit = {n};
      }

      void remove_execution_limit()
      {
        execution_limit = std::nullopt;
      }
    };
  } // namespace lua
} // namespace ccf