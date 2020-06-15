// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json_schema.h"
#include "enclave/rpc_context.h"
#include "http/http_consts.h"
#include "kv/store.h"
#include "kv/tx.h"
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
    kv::Tx& tx;
    CallerId caller_id;
  };

  using HandleFunction = std::function<void(RequestArgs& args)>;

  /** The HandlerRegistry records the user-defined Handlers for a given
   * CCF application.
   */
  class HandlerRegistry
  {
  public:
    enum ReadWrite
    {
      Read,
      Write,
      MayWrite
    };

    /** A Handler represents a user-defined endpoint that can be invoked by
    * authorised users via HTTP requests, over TLS. A Handler is accessible at a
    * specific verb and URI, e.g. POST /app/accounts or GET /app/records.
    *
    * Handlers can read from and mutate the state of the replicated key-value
    store.
    *
    * A CCF application is a collection of Handlers recorded in the
    application's HandlerRegistry.
    */
    struct Handler
    {
      std::string method;
      HandleFunction func;
      ReadWrite read_write = Write;
      HandlerRegistry* registry;

      nlohmann::json params_schema = nullptr;

      /** Sets the JSON schema that the request parameters must comply with.
       *
       * @param j Request parameters JSON schema
       * @return The installed Handler for further modification
       */
      Handler& set_params_schema(const nlohmann::json& j)
      {
        params_schema = j;
        return *this;
      }

      nlohmann::json result_schema = nullptr;

      /** Sets the JSON schema that the request response must comply with.
       *
       * @param j Request response JSON schema
       * @return The installed Handler for further modification
       */
      Handler& set_result_schema(const nlohmann::json& j)
      {
        result_schema = j;
        return *this;
      }

      /** Sets the schema that the request parameters and response must comply
       * with based on JSON-serialisable data structures.
       *
       * \verbatim embed:rst:leading-asterisk
       * .. note::
       *  See ``DECLARE_JSON_`` serialisation macros for serialising
       *  user-defined data structures.
       * \endverbatim
       *
       * @tparam In Request parameters JSON-serialisable data structure
       * @tparam Out Request response JSON-serialisable data structure
       * @return The installed Handler for further modification
       */
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

      /** Sets the schema that the request parameters and response must comply
       * with, based on a single JSON-serialisable data structure.
       *
       * \verbatim embed:rst:leading-asterisk
       * .. note::
       *   ``T`` data structure should contain two nested ``In`` and ``Out``
       *   structures for request parameters and response format, respectively.
       * \endverbatim
       *
       * @tparam T Request parameters and response JSON-serialisable data
       * structure
       * @return The installed Handler for further modification
       */
      template <typename T>
      Handler& set_auto_schema()
      {
        return set_auto_schema<typename T::In, typename T::Out>();
      }

      bool require_client_signature = false;

      /** Requires that the HTTP request is cryptographically signed by
       * the calling user.
       *
       * By default, client signatures are not required.
       *
       * @param v Boolean indicating whether the request must be signed
       * @return The installed Handler for further modification
       */
      Handler& set_require_client_signature(bool v)
      {
        require_client_signature = v;
        return *this;
      }

      bool require_client_identity = true;

      /** Requires that the HTTPS request is emitted by a user whose public
       * identity has been registered in advance by consortium members.
       *
       * By default, a known client identity is required.
       *
       * \verbatim embed:rst:leading-asterisk
       * .. warning::
       *  If set to false, it is left to the application developer to implement
       *  the authentication and authorisation mechanisms for the handler.
       * \endverbatim
       *
       * @param v Boolean indicating whether the user identity must be known
       * @return The installed Handler for further modification
       */
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

      bool execute_locally = false;

      /** Indicates that the execution of the handler does not require consensus
       * from other nodes in the network.
       *
       * By default, handlers are not executed locally.
       *
       * \verbatim embed:rst:leading-asterisk
       * .. warning::
       *  Use with caution. This should only be used for non-critical handlers
       *  that do not read or mutate the state of the key-value store.
       * \endverbatim
       *
       * @param v Boolean indicating whether the handler is executed locally, on
       * the node receiving the request
       * @return The installed Handler for further modification
       */
      Handler& set_execute_locally(bool v)
      {
        execute_locally = v;
        return *this;
      }

      http_method verb = HTTP_POST;

      /** Indicates which HTTP verb the handler should respond to.
       *
       * @return The installed Handler for further modification
       */
      [[deprecated("HTTP Verb should not be changed after installation: pass verb to install()")]] Handler&
      set_allowed_verb(http_method v)
      {
        verb = v;
        return *this;
      }

      /** Indicates that the handler is only accessible via the GET HTTP verb.
       *
       * @return The installed Handler for further modification
       */
      [[deprecated("HTTP Verb should not be changed after installation: use install_get()")]] Handler&
      set_http_get_only()
      {
        return set_allowed_verb(HTTP_GET);
      }

      /** Indicates that the handler is only accessible via the POST HTTP verb.
       *
       * @return The installed Handler for further modification
       */
      [[deprecated("HTTP Verb should not be changed after installation: use install_post()")]] Handler&
      set_http_post_only()
      {
        return set_allowed_verb(HTTP_POST);
      }
    };

  protected:
    std::optional<Handler> default_handler;
    // Handler lookup uses method and HTTP verb. We assume there is usually a
    // single verb-per-method, so this map looks up only by method and then we
    // iterate.
    std::unordered_map<std::string, std::vector<Handler>> handlers;

    kv::Consensus* consensus = nullptr;
    kv::TxHistory* history = nullptr;

    Certs* certs = nullptr;

  public:
    HandlerRegistry(kv::Store& tables, const std::string& certs_table_name = "")
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
     * @param verb The HTTP verb which this handler will respond to
     * @return The installed Handler for further modification
     */
    Handler& install(
      const std::string& method,
      const HandleFunction& f,
      ReadWrite read_write,
      http_method verb = HTTP_POST)
    {
      auto& method_handlers = handlers[method];
      for (const auto& other : method_handlers)
      {
        if (other.verb == verb)
        {
          throw std::logic_error(fmt::format(
            "Already have an installed handler for {} on {}",
            http_method_str(verb),
            method));
        }
      }
      auto& handler = method_handlers.emplace_back();
      handler.method = method;
      handler.func = f;
      handler.read_write = read_write;
      handler.verb = verb;
      handler.registry = this;
      return handler;
    }

    Handler& install_post(
      const std::string& method, HandleFunction f, ReadWrite read_write)
    {
      return install(method, f, read_write, HTTP_POST);
    }

    Handler& install_get(
      const std::string& method, HandleFunction f, ReadWrite read_write)
    {
      return install(method, f, read_write, HTTP_GET);
    }

    /** Set a default HandleFunction
     *
     * The default HandleFunction is only invoked if no specific HandleFunction
     * was found.
     *
     * @param f Method implementation
     * @param read_write Flag if method will Read, Write, MayWrite
     * @return The installed Handler for further modification
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
    virtual void list_methods(kv::Tx& tx, ListMethods::Out& out)
    {
      for (const auto& handler : handlers)
      {
        out.methods.push_back(handler.first);
      }
    }

    virtual void init_handlers(kv::Store& tables) {}

    virtual Handler* find_handler(const std::string& method, http_method verb)
    {
      auto search = handlers.find(method);
      if (search != handlers.end())
      {
        for (auto& handler : search->second)
        {
          if (handler.verb == verb)
          {
            return &handler;
          }
        }
      }

      if (default_handler)
      {
        return &default_handler.value();
      }

      return nullptr;
    }

    virtual std::vector<http_method> get_allowed_verbs(
      const std::string& method)
    {
      std::vector<http_method> verbs;
      auto search = handlers.find(method);
      if (search != handlers.end())
      {
        for (auto& handler : search->second)
        {
          verbs.push_back(handler.verb);
        }
      }

      return verbs;
    }

    virtual void tick(
      std::chrono::milliseconds elapsed, kv::Consensus::Statistics stats)
    {}

    bool has_certs()
    {
      return certs != nullptr;
    }

    virtual CallerId get_caller_id(
      kv::Tx& tx, const std::vector<uint8_t>& caller)
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