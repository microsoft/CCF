// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/appinterface.h"
#include "node/rpc/userfrontend.h"
#include "quickjs.h"

#include <memory>
#include <vector>

namespace ccfapp
{
  using namespace std;
  using namespace kv;
  using namespace ccf;

  using GenericTable = ccf::Store::Map<nlohmann::json, nlohmann::json>;

  class JS : public ccf::UserRpcFrontend
  {
  private:
    NetworkTables& network;

  public:
    JS(NetworkTables& network, const uint16_t n_tables = 8) :
      UserRpcFrontend(*network.tables),
      network(network)
    {
      // create public and private app tables (2x n_tables in total)
      std::vector<GenericTable*> app_tables(n_tables * 2);
      for (uint16_t i = 0; i < n_tables; i++)
      {
        const auto suffix = std::to_string(i);
        app_tables[i] = &tables.create<GenericTable>("priv" + suffix);
        app_tables[i + n_tables] = &tables.create<GenericTable>("pub" + suffix);
      }

      auto default_handler = [this](RequestArgs& args) {
        const auto scripts = args.tx.get_view(this->network.app_scripts);

        // try find script for method
        auto handler_script = scripts->get(args.method);
        if (!handler_script)
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::METHOD_NOT_FOUND,
            "No handler script found for method '" + args.method + "'");

        JSRuntime* rt = JS_NewRuntime();
        if (rt == nullptr)
        {
          throw std::runtime_error("Failed to initialise QuickJS runtime");
        }
        // TODO: share runtime across handlers
        // TODO: set memory limit with JS_SetMemoryLimit

        JSContext* ctx = JS_NewContext(rt);
        if (ctx == nullptr)
        {
          JS_FreeRuntime(rt);
          throw std::runtime_error("Failed to initialise QuickJS context");
        }
        // TODO: load modules from module table here?

        const nlohmann::json response = {};

        if (!handler_script.value().text.has_value())
        {
          throw std::runtime_error("Could not find script text");
        }

        // TODO: support pre-compiled byte-code
        std::string code = handler_script.value().text.value();
        LOG_INFO_FMT("About to run {}", code);
        JSValue val = JS_Eval(ctx, code.data(), code.size(), "table_name::key", JS_EVAL_TYPE_GLOBAL);

        // TODO: handle exceptions
        if (JS_VALUE_GET_TAG(val) == JS_TAG_STRING)
          LOG_INFO_FMT("Ran, returned a string"); // ODO: print and maybe free?
        else
          LOG_INFO_FMT("Ran, but returned not a string");

        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);

        const auto err_it = response.find(jsonrpc::ERR);
        if (err_it == response.end())
        {
          const auto result_it = response.find(jsonrpc::RESULT);
          if (result_it == response.end())
          {
            // Response contains neither RESULT nor ERR. It may not even be an
            // object. We assume the entire response is a successful result.
            return make_pair(true, response);
          }
          else
          {
            return make_pair(true, *result_it);
          }
        }
        else
        {
          return make_pair(false, *err_it);
        }
      };

      // TODO: https://github.com/microsoft/CCF/issues/409
      set_default(default_handler, Write);
    }
  };

  std::shared_ptr<enclave::RpcHandler> get_rpc_handler(
    NetworkTables& network, AbstractNotifier& notifier)
  {
    return make_shared<JS>(network);
  }
} // namespace ccfapp
