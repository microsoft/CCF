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

  static JSValue js_print(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv)
  {
      int i;
      const char *str;
      auto level = logger::INFO;

      if (logger::config::ok(level))
      {
        auto os = logger::LogLine(level, __FILE__, __LINE__);
        for(i = 0; i < argc; i++) {
          if (i != 0)
            os << ' ';    
            str = JS_ToCString(ctx, argv[i]);
            if (!str)
                return JS_EXCEPTION;
            os << str;
            JS_FreeCString(ctx, str);
        }
        os << std::endl;
        auto _ = logger::Out() == os;
      }
      return JS_UNDEFINED;
  }

  void js_dump_error(JSContext *ctx)
  {
      JSValue exception_val = JS_GetException(ctx);

    JSValue val;
    const char *stack;
    bool is_error;
    
    is_error = JS_IsError(ctx, exception_val);
    if (!is_error)
      LOG_INFO_FMT("Throw: ");
    js_print(ctx, JS_NULL, 1, (JSValueConst *)&exception_val);
    if (is_error) {
        val = JS_GetPropertyStr(ctx, exception_val, "stack");
        if (!JS_IsUndefined(val)) {
            stack = JS_ToCString(ctx, val);
            LOG_INFO_FMT("{}", stack);

            JS_FreeCString(ctx, stack);
        }
        JS_FreeValue(ctx, val);
    }

      JS_FreeValue(ctx, exception_val);
  }

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
        // TODO: share runtime across handlers?
        // TODO: set memory limit with JS_SetMemoryLimit

        JSContext* ctx = JS_NewContext(rt);
        if (ctx == nullptr)
        {
          JS_FreeRuntime(rt);
          throw std::runtime_error("Failed to initialise QuickJS context");
        }
        // TODO: load modules from module table here?

        auto global_obj = JS_GetGlobalObject(ctx);
        auto console = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, console, "log", JS_NewCFunction(ctx, ccfapp::js_print, "log", 1));
        JS_SetPropertyStr(ctx, global_obj, "console", console);
        // TODO: avoid parsing argument for JS frontend
        auto args_str = JS_NewStringLen(ctx, (const char *) args.rpc_ctx.raw.data(), args.rpc_ctx.raw.size());
        JS_SetPropertyStr(ctx, global_obj, "args", args_str);
        JS_FreeValue(ctx, global_obj);

        if (!handler_script.value().text.has_value())
        {
          throw std::runtime_error("Could not find script text");
        }

        // TODO: support pre-compiled byte-code
        std::string code = handler_script.value().text.value();
        auto path = fmt::format("app_scripts::{}", args.method);
        JSValue val = JS_Eval(ctx, code.c_str(), code.size(), path.c_str(), JS_EVAL_TYPE_GLOBAL);

        auto status = true;

        if (JS_IsException(val)) {
          js_dump_error(ctx);
          status = false;
        }

        if (JS_IsBool(val) && !JS_VALUE_GET_BOOL(val))
          status = false;

        JSValue rval = JS_JSONStringify(ctx, val, JS_NULL, JS_NULL);
        auto cstr = JS_ToCString(ctx, rval);
        auto response = nlohmann::json::parse(cstr);

        JS_FreeCString(ctx, cstr);
        JS_FreeValue(ctx, val);

        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);

        return make_pair(status, response);
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
