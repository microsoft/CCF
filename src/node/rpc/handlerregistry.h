// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json_schema.h"
#include "enclave/rpccontext.h"
#include "node/certs.h"
#include "serialization.h"

#include <functional>
#include <nlohmann/json.hpp>

namespace ccf
{
  struct RequestArgs
  {
    std::shared_ptr<enclave::RpcContext> rpc_ctx;
    Store::Tx& tx;
    CallerId caller_id;
    const std::string& method;
    const nlohmann::json& params;
  };

  using HandleFunction = std::function<void(RequestArgs& args)>;

  static enclave::RpcResponse make_success(nlohmann::json&& result_payload)
  {
    return enclave::RpcResponse{std::move(result_payload)};
  }

  static enclave::RpcResponse make_success(const nlohmann::json& result_payload)
  {
    return enclave::RpcResponse{result_payload};
  }

  template <typename ErrorCode>
  static enclave::RpcResponse make_error(
    ErrorCode code, const std::string& msg = "")
  {
    return enclave::RpcResponse{enclave::ErrorDetails{(int)code, msg}};
  }

  class HandlerRegistry
  {
  public:
    enum ReadWrite
    {
      Read,
      Write,
      MayWrite
    };

    enum class Forwardable
    {
      CanForward,
      DoNotForward
    };

    struct Handler
    {
      HandleFunction func;
      ReadWrite rw;
      nlohmann::json params_schema;
      nlohmann::json result_schema;
      Forwardable forwardable;
      bool execute_locally = false;
    };

  protected:
    std::optional<Handler> default_handler;
    std::unordered_map<std::string, Handler> handlers;

    kv::Consensus* consensus = nullptr;
    kv::TxHistory* history = nullptr;

    Certs* certs = nullptr;

  public:
    HandlerRegistry(Store& tables, const std::string& certs_table_name = "")
    {
      if (!certs_table_name.empty())
      {
        certs = tables.get<Certs>(certs_table_name);
      }
    }

    virtual ~HandlerRegistry() {}

    /** Install HandleFunction for method name
     *
     * If an implementation is already installed for that method, it will be
     * replaced.
     *
     * @param method Method name
     * @param f Method implementation
     * @param rw Flag if method will Read, Write, MayWrite
     * @param params_schema JSON schema for params object in requests
     * @param result_schema JSON schema for result object in responses
     * @param forwardable Allow method to be forwarded to primary
     */
    void install(
      const std::string& method,
      HandleFunction f,
      ReadWrite rw,
      const nlohmann::json& params_schema = nlohmann::json::object(),
      const nlohmann::json& result_schema = nlohmann::json::object(),
      Forwardable forwardable = Forwardable::CanForward,
      bool execute_locally = false)
    {
      handlers[method] = {
        f, rw, params_schema, result_schema, forwardable, execute_locally};
    }

    void install(
      const std::string& method,
      HandleFunction f,
      ReadWrite rw,
      Forwardable forwardable)
    {
      install(
        method,
        f,
        rw,
        nlohmann::json::object(),
        nlohmann::json::object(),
        forwardable);
    }

    template <typename In, typename Out, typename F>
    void install_with_auto_schema(
      const std::string& method,
      F&& f,
      ReadWrite rw,
      Forwardable forwardable = Forwardable::CanForward,
      bool execute_locally = false)
    {
      auto params_schema = nlohmann::json::object();
      if constexpr (!std::is_same_v<In, void>)
      {
        params_schema = ds::json::build_schema<In>(method + "/params");
      }

      auto result_schema = nlohmann::json::object();
      if constexpr (!std::is_same_v<Out, void>)
      {
        result_schema = ds::json::build_schema<Out>(method + "/result");
      }

      install(
        method,
        std::forward<F>(f),
        rw,
        params_schema,
        result_schema,
        forwardable,
        execute_locally);
    }

    template <typename T, typename... Ts>
    void install_with_auto_schema(const std::string& method, Ts&&... ts)
    {
      install_with_auto_schema<typename T::In, typename T::Out>(
        method, std::forward<Ts>(ts)...);
    }

    /** Set a default HandleFunction
     *
     * The default HandleFunction is only invoked if no specific HandleFunction
     * was found.
     *
     * @param f Method implementation
     * @param rw Flag if method will Read, Write, MayWrite
     */
    void set_default(HandleFunction f, ReadWrite rw)
    {
      default_handler = {f, rw};
    }

    /** Populate out with all supported methods
     *
     * This is virtual since the default handler may do its own dispatch
     * internally, so derived implementations must be able to populate the list
     * with the supported methods however it constructs them.
     */
    virtual void list_methods(Store::Tx& tx, ListMethods::Out& out)
    {
      for (const auto& handler : handlers)
      {
        out.methods.push_back(handler.first);
      }
    }

    virtual void init_handlers(Store& tables) {}

    virtual Handler* find_handler(const std::string& method)
    {
      auto search = handlers.find(method);
      if (search != handlers.end())
      {
        return &search->second;
      }
      else if (default_handler)
      {
        return &default_handler.value();
      }

      return nullptr;
    }

    virtual void tick(std::chrono::milliseconds elapsed, size_t tx_count) {}

    virtual std::optional<CallerId> valid_caller(
      Store::Tx& tx, const std::vector<uint8_t>& caller)
    {
      if (certs == nullptr)
      {
        return INVALID_ID;
      }

      if (caller.empty())
      {
        return {};
      }

      auto certs_view = tx.get_view(*certs);
      auto caller_id = certs_view->get(caller);

      return caller_id;
    }

    void set_consensus(kv::Consensus* c)
    {
      consensus = c;
    }

    void set_history(kv::TxHistory* h)
    {
      history = h;
    }
  };
}