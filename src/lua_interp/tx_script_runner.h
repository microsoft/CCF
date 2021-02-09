// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "lua_interp/lua_interp.h"
#include "lua_interp/lua_kv.h"
#include "node/network_tables.h"
#include "node/rpc/rpc_exception.h"

#include <sstream>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace ccf
{
  namespace lua
  {
    //! Describes a script to be run within a transaction
    struct TxScript
    {
      //! the script to run
      const Script script;
      //! [optional] the id of the write whitelist to apply
      std::optional<WlId> whitelist_write;
      //! [optional] the id of the read whitelist to apply
      std::optional<WlId> whitelist_read;
      //! [optional] script to setup the environment for the actual script
      std::optional<Script> env_script;
    };

    class TxScriptRunner
    {
    protected:
      static constexpr auto env_table_name = "env";

      /** Dummy type to distinguish writable from read-only tables at compile
       * time. Used to instantiate lua::UserDataExt for writable tables.
       */
      struct _W
      {};

      template <bool READ_ONLY>
      class TableCreator
      {
      private:
        template <typename T>
        using WT = lua::UserDataExt<T, _W>;

        template <typename T>
        static void register_meta(lua::Interpreter& li)
        {
          using TT = typename T::Handle;
          if constexpr (READ_ONLY)
            li.register_metatable<TT>(lua::kv_methods_read_only<TT>);
          else
            li.register_metatable<TT, WT<TT>>(lua::kv_methods<TT, WT<TT>>);
        }

        template <typename T>
        static void add_table(lua::Interpreter& li, kv::Tx& tx, T& table)
        {
          decltype(auto) name = table.get_name();

          using TT = typename T::Handle;
          auto h = tx.rw(table);
          if constexpr (READ_ONLY)
            li.push(h);
          else
            li.push(WT<TT>{h});
          lua_setfield(li.get_state(), -2, name.c_str());
        }

        template <typename T, typename... Tables>
        static void process_tables(
          lua::Interpreter& li,
          kv::Tx& tx,
          const Whitelist& wl,
          T& table,
          Tables&... tables)
        {
          decltype(auto) name = table.get_name();
          if (wl.find(name) != wl.end())
          {
            register_meta<T>(li);
            add_table(li, tx, table);
          }
          process_tables(li, tx, wl, tables...);
        }
        static void process_tables(lua::Interpreter&, kv::Tx&, const Whitelist&)
        {}

        // helper method to expand parameters in the table tuple
        template <typename... T, std::size_t... Is>
        static void call_process_tables(
          lua::Interpreter& li,
          kv::Tx& tx,
          const Whitelist& wl,
          const std::tuple<T&...>& tables,
          std::index_sequence<Is...>)
        {
          process_tables(li, tx, wl, std::get<Is>(tables)...);
        }

      public:
        template <typename T>
        static void create(
          lua::Interpreter& li, kv::Tx& tx, const std::vector<T>& tables)
        {
          register_meta<T>(li);
          lua_newtable(li.get_state());
          for (decltype(auto) table : tables)
            add_table(li, tx, table);
        }

        template <typename... T>
        static void create(
          lua::Interpreter& li,
          kv::Tx& tx,
          const Whitelist& wl,
          const std::tuple<T&...>& tables)
        {
          lua_newtable(li.get_state());
          call_process_tables(
            li, tx, wl, tables, std::index_sequence_for<T...>());
        }
      };

      const NetworkTables& network_tables;

      static void load(lua::Interpreter& li, Script s)
      {
        if (s.bytecode)
          li.push_code(*s.bytecode);
        else if (s.text)
          li.push_code(*s.text);
        else
          throw std::logic_error("no bytecode or string to load as script");
      }

      Whitelist get_whitelist(kv::Tx& tx, WlId id) const
      {
        const auto wl = tx.rw(network_tables.whitelists)->get(id);
        if (!wl)
          throw std::logic_error(
            "Whitelist with id: " + std::to_string(id) + " does not exist");
        return *wl;
      }

      [[noreturn]] static void lua_fail(const lua::ex& e)
      {
        std::stringstream ss;
        ss << "Script failed: " << e.what();
        throw RpcException(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          ss.str());
      }

      static std::string get_var_string_from_args(lua_State* l)
      {
        size_t args = lua_gettop(l);
        std::stringstream ss;
        for (size_t i = 1; i <= args; ++i)
        {
          const int type = lua_type(l, i);
          if (type != LUA_TNUMBER && type != LUA_TSTRING)
          {
            throw std::runtime_error(fmt::format(
              "Can only format lua args which are numbers or strings - got {}. "
              "Call tostring from within Lua",
              lua_typename(l, type)));
          }
          ss << lua_tostring(l, i);
        }
        return ss.str();
      }

      static int lua_log_trace(lua_State* l)
      {
        LOG_TRACE_FMT("{}", get_var_string_from_args(l));
        return 0;
      }

      static int lua_log_debug(lua_State* l)
      {
        LOG_DEBUG_FMT("{}", get_var_string_from_args(l));
        return 0;
      }

      static int lua_log_info(lua_State* l)
      {
        LOG_INFO_FMT("{}", get_var_string_from_args(l));
        return 0;
      }

      static int lua_log_fail(lua_State* l)
      {
        LOG_FAIL_FMT("{}", get_var_string_from_args(l));
        return 0;
      }

      static int lua_log_fatal(lua_State* l)
      {
        throw std::logic_error(get_var_string_from_args(l));
        return 0;
      }

      virtual void setup_environment(
        lua::Interpreter& li, const std::optional<Script>& env_script) const
      {
        auto l = li.get_state();

        // Register global logging functions
        lua_register(l, "LOG_TRACE", lua_log_trace);
        lua_register(l, "LOG_DEBUG", lua_log_debug);
        lua_register(l, "LOG_INFO", lua_log_info);
        lua_register(l, "LOG_FAIL", lua_log_fail);
        lua_register(l, "LOG_FATAL", lua_log_fatal);

        if (env_script)
        {
          load(li, *env_script);
          li.invoke_raw(0);
        }
      }

      virtual void add_custom_tables(lua::Interpreter&, kv::Tx&, int&) const {}

    public:
      /** Run a script transactionally in a given environment.
       *
       * For each given whitelist id (read or write, in TxScript), a table of
       * corresponding table objects is passed to the script as arguments. The
       * script can use those table objects to access the key-value store. For
       * example, if both a read and a write whitelist are specified, a script
       * with three arguments a,b,c would start as follows:
       *
       * tables_writable, tables_readable, a, b, c = ...
       * -- read members table
       * local member_0 = tables_readable["public:ccf.gov.members.info"]:get(0)
       *
       * Further, subclasses of this class may add custom tables by overriding
       * the add_custom_tables() method.
       *
       * @tparam T the return type of the script
       * @tparam Args the types of the arguments to the script
       * @param tx the transaction to run the script in
       * @param txs the script to run and corresponding parameters (i.e.,
       * read/write whitelists and environment script).
       * @param args the arguments to the script
       * @return T the result of the script
       */
      template <typename T, typename... Args>
      T run(kv::Tx& tx, const TxScript& txs, Args&&... args) const
      {
        lua::Interpreter li;

        // run an optional environment script
        setup_environment(li, txs.env_script);

        load(li, txs.script);

        // register writable and read-only tables with respect to the given
        // whitelists the table of writable tables will be pushed on the stack
        // first. the table of readable tables second
        int n_registered_tables = 0;
        add_custom_tables(li, tx, n_registered_tables);

        if (txs.whitelist_write || txs.whitelist_read)
        {
          auto tables = network_tables.get_scriptable_tables();
          if (txs.whitelist_write)
          {
            TableCreator<false>::create(
              li, tx, get_whitelist(tx, *txs.whitelist_write), tables);
            n_registered_tables++;
          }

          if (txs.whitelist_read)
          {
            TableCreator<true>::create(
              li, tx, get_whitelist(tx, *txs.whitelist_read), tables);
            n_registered_tables++;
          }
        }
        try
        {
          // no return if T == void
          if constexpr (std::is_same_v<T, void>)
            li.invoke_raw(n_registered_tables, std::forward<Args>(args)...);
          else
            return li.template invoke_raw<T>(
              n_registered_tables, std::forward<Args>(args)...);
        }
        catch (const lua::ex& e)
        {
          lua_fail(e);
        }
      }

      TxScriptRunner(NetworkTables& network_tables) :
        network_tables(network_tables)
      {}

      virtual ~TxScriptRunner(){};
    };
  }
}