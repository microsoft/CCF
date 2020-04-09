// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json_schema.h"
#include "enclave/rpc_context.h"
#include "http/http_consts.h"
#include "node/certs.h"
#include "serialization.h"

#include <functional>
#include <http-parser/http_parser.h>
#include <nlohmann/json.hpp>
#include <set>

namespace ccf
{
  struct RequestArgs
  {
    std::shared_ptr<enclave::RpcContext> rpc_ctx;
    Store::Tx& tx;
    CallerId caller_id;
  };

  static uint64_t verb_to_mask(size_t verb)
  {
    return 1ul << verb;
  }

  using HandleFunction = std::function<void(RequestArgs& args)>;

  class HandlerRegistry
  {
  public:
    enum ReadWrite
    {
      Read,
      Write,
      MayWrite
    };

    struct Handler
    {
      std::string method;
      HandleFunction func;
      ReadWrite read_write = Write;
      HandlerRegistry* registry;

      nlohmann::json params_schema = nullptr;

      Handler& set_params_schema(const nlohmann::json& j)
      {
        params_schema = j;
        return *this;
      }

      nlohmann::json result_schema = nullptr;

      Handler& set_result_schema(const nlohmann::json& j)
      {
        result_schema = j;
        return *this;
      }

      template <typename In, typename Out>
      Handler& set_auto_schema()
      {
        if constexpr (!std::is_same_v<In, void>)
        {
          params_schema = ds::json::build_schema<In>(method + "/params");
        }
        else
        {
          params_schema = nullptr;
        }

        if constexpr (!std::is_same_v<Out, void>)
        {
          result_schema = ds::json::build_schema<Out>(method + "/result");
        }
        else
        {
          result_schema = nullptr;
        }

        return *this;
      }

      template <typename T>
      Handler& set_auto_schema()
      {
        return set_auto_schema<typename T::In, typename T::Out>();
      }

      // If true, client request must be signed
      bool require_client_signature = false;

      Handler& set_require_client_signature(bool v)
      {
        require_client_signature = v;
        return *this;
      }

      // If true, client must be known in certs table
      bool require_client_identity = true;

      Handler& set_require_client_identity(bool v)
      {
        if (!v && registry != nullptr && !registry->has_certs())
        {
          LOG_INFO_FMT(
            "Disabling client identity requirement on {} handler has no effect "
            "since its registry does not have certificates table",
            method);
          return *this;
        }

        require_client_identity = v;
        return *this;
      }

      // If true, request is executed without consensus (PBFT only)
      bool execute_locally = false;

      Handler& set_execute_locally(bool v)
      {
        execute_locally = v;
        return *this;
      }

      // Bit mask. Bit i is 1 iff the http_method with value i is allowed.
      // Default is that all verbs are allowed
      uint64_t allowed_verbs_mask = ~0;

      Handler& set_allowed_verbs(std::set<http_method>&& allowed_verbs)
      {
        // Reset mask to disallow everything
        allowed_verbs_mask = 0;

        // Set bit for each allowed verb
        for (const auto& verb : allowed_verbs)
        {
          allowed_verbs_mask |= verb_to_mask(verb);
        }

        return *this;
      }

      Handler& set_http_get_only()
      {
        return set_allowed_verbs({HTTP_GET});
      }

      Handler& set_http_post_only()
      {
        return set_allowed_verbs({HTTP_POST});
      }
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
     * @param read_write Flag if method will Read, Write, MayWrite
     * @return Returns the installed Handler for further modification
     */
    Handler& install(
      const std::string& method, HandleFunction f, ReadWrite read_write)
    {
      auto& handler = handlers[method];
      handler.method = method;
      handler.func = f;
      handler.read_write = read_write;
      handler.registry = this;
      return handler;
    }

    /** Set a default HandleFunction
     *
     * The default HandleFunction is only invoked if no specific HandleFunction
     * was found.
     *
     * @param f Method implementation
     * @param read_write Flag if method will Read, Write, MayWrite
     * @return Returns the installed Handler for further modification
     */
    Handler& set_default(HandleFunction f, ReadWrite read_write)
    {
      default_handler = {"", f, read_write, this};
      return default_handler.value();
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

    virtual void tick(
      std::chrono::milliseconds elapsed, kv::Consensus::Statistics stats)
    {}

    bool has_certs()
    {
      return certs != nullptr;
    }

    virtual CallerId get_caller_id(
      Store::Tx& tx, const std::vector<uint8_t>& caller)
    {
      if (certs == nullptr || caller.empty())
      {
        return INVALID_ID;
      }

      auto certs_view = tx.get_view(*certs);
      auto caller_id = certs_view->get(caller);

      if (!caller_id.has_value())
      {
        return INVALID_ID;
      }

      return caller_id.value();
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