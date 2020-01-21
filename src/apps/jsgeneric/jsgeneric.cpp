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

  class JSHandlers : public UserHandlerRegistry
  {
  private:
    NetworkTables& network;

  public:
    JSHandlers(NetworkTables& network, const uint16_t n_tables = 8) :
      UserHandlerRegistry(network),
      network(network)
    {
      auto& tables = *network.tables;

      // create public and private app tables (2x n_tables in total)
      std::vector<GenericTable*> app_tables(n_tables * 2);
      for (uint16_t i = 0; i < n_tables; i++)
      {
        const auto suffix = std::to_string(i);
        app_tables[i] = &tables.create<GenericTable>("priv" + suffix);
        app_tables[i + n_tables] = &tables.create<GenericTable>("pub" + suffix);
      }

      auto default_handler = [this](RequestArgs& args) {
        JSRuntime* rt = JS_NewRuntime();
        JSContext* ctx = JS_NewContext(rt);

        if (args.method == UserScriptIds::ENV_HANDLER)
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::StandardErrorCodes::METHOD_NOT_FOUND,
            fmt::format("Cannot call environment script ('{}')", args.method));
          return;
        }

        const auto scripts = args.tx.get_view(this->network.app_scripts);

        // try find script for method
        auto handler_script = scripts->get(args.method);
        if (!handler_script)
        {
          args.rpc_ctx->set_response_error(
            jsonrpc::StandardErrorCodes::METHOD_NOT_FOUND,
            fmt::format(
              "No handler script found for method '{}'", args.method));
          return;
        }

        nlohmann::json response = {};
        /*
        const auto response = tsr->run<nlohmann::json>(
          args.tx,
          {*handler_script,
           {},
           WlIds::USER_APP_CAN_READ_ONLY,
           scripts->get(UserScriptIds::ENV_HANDLER)},
          // vvv arguments to the script vvv
          args);
        */

        auto err_it = response.find("error");
        if (err_it == response.end())
        {
          auto result_it = response.find("result");
          if (result_it == response.end())
          {
            // Response contains neither result nor error. It may not even be an
            // object. We assume the entire response is a successful result.
            args.rpc_ctx->set_response_result(std::move(response));
            return;
          }
          else
          {
            args.rpc_ctx->set_response_result(std::move(*result_it));
            return;
          }
        }
        else
        {
          int err_code = jsonrpc::CCFErrorCodes::SCRIPT_ERROR;
          std::string msg = "";

          if (err_it->is_object())
          {
            auto err_code_it = err_it->find("code");
            if (err_code_it != err_it->end())
            {
              err_code = *err_code_it;
            }

            auto err_message_it = err_it->find("message");
            if (err_message_it != err_it->end())
            {
              msg = *err_message_it;
            }
          }

          args.rpc_ctx->set_response_error(err_code, msg);
          return;
        }
      };

      // TODO: https://github.com/microsoft/CCF/issues/409
      set_default(default_handler, Write);
    }
  };

  class JS : public ccf::UserRpcFrontend
  {
  private:
    JSHandlers js_handlers;

  public:
    JS(NetworkTables& network) :
      ccf::UserRpcFrontend(*network.tables, js_handlers),
      js_handlers(network)
    {}
  };

  std::shared_ptr<enclave::RpcHandler> get_rpc_handler(
    NetworkTables& network, AbstractNotifier& notifier)
  {
    return make_shared<JS>(network);
  }
} // namespace ccfapp
