// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/app_interface.h"
#include "kv/untyped_map.h"
#include "node/rpc/user_frontend.h"
#include "quickjs.h"

#include <memory>
#include <vector>

namespace ccfapp
{
  using namespace std;
  using namespace kv;
  using namespace ccf;

  using Table = kv::Map<std::vector<uint8_t>, std::vector<uint8_t>>;

  static JSValue js_print(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    int i;
    const char* str;
    std::stringstream ss;

    for (i = 0; i < argc; i++)
    {
      if (i != 0)
        ss << ' ';
      str = JS_ToCString(ctx, argv[i]);
      if (!str)
        return JS_EXCEPTION;
      ss << str;
      JS_FreeCString(ctx, str);
    }
    LOG_INFO_FMT(ss.str());
    return JS_UNDEFINED;
  }

  void js_dump_error(JSContext* ctx)
  {
    JSValue exception_val = JS_GetException(ctx);

    JSValue val;
    const char* stack;
    bool is_error;

    is_error = JS_IsError(ctx, exception_val);
    if (!is_error)
      LOG_INFO_FMT("Throw: ");
    js_print(ctx, JS_NULL, 1, (JSValueConst*)&exception_val);
    if (is_error)
    {
      val = JS_GetPropertyStr(ctx, exception_val, "stack");
      if (!JS_IsUndefined(val))
      {
        stack = JS_ToCString(ctx, val);
        LOG_INFO_FMT("{}", stack);

        JS_FreeCString(ctx, stack);
      }
      JS_FreeValue(ctx, val);
    }

    JS_FreeValue(ctx, exception_val);
  }

  static JSValue js_get(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto table_view = (Table::TxView*)JS_GetContextOpaque(ctx);
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    if (!JS_IsString(argv[0]))
      return JS_ThrowTypeError(ctx, "Argument must be a string");

    size_t sz = 0;
    auto k = JS_ToCStringLen(ctx, &sz, argv[0]);
    auto v = table_view->get({k, k + sz});
    JS_FreeCString(ctx, k);

    if (v.has_value())
      return JS_NewStringLen(
        ctx, (const char*)v.value().data(), v.value().size());
    else
      return JS_ThrowRangeError(ctx, "No such key");
  }

  static JSValue js_remove(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto table_view = (Table::TxView*)JS_GetContextOpaque(ctx);
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    if (!JS_IsString(argv[0]))
      return JS_ThrowTypeError(ctx, "Argument must be a string");

    size_t sz = 0;
    auto k = JS_ToCStringLen(ctx, &sz, argv[0]);
    auto v = table_view->remove({k, k + sz});
    JS_FreeCString(ctx, k);

    if (v)
      return JS_NULL;
    else
      return JS_ThrowRangeError(ctx, "Failed to remove at key");
  }

  static JSValue js_put(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto table_view = (Table::TxView*)JS_GetContextOpaque(ctx);
    if (argc != 2)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 2", argc);

    if (!(JS_IsString(argv[0]) && JS_IsString(argv[0])))
      return JS_ThrowTypeError(ctx, "Arguments must be strings");

    auto r = JS_NULL;

    size_t k_sz = 0;
    auto k = JS_ToCStringLen(ctx, &k_sz, argv[0]);

    size_t v_sz = 0;
    auto v = JS_ToCStringLen(ctx, &v_sz, argv[1]);

    if (!table_view->put({k, k + k_sz}, {v, v + v_sz}))
    {
      r = JS_ThrowRangeError(ctx, "Could not insert at key");
    }

    JS_FreeCString(ctx, k);
    JS_FreeCString(ctx, v);
    return r;
  }

  class JSHandlers : public UserHandlerRegistry
  {
  private:
    NetworkTables& network;
    Table& table;

  public:
    JSHandlers(NetworkTables& network) :
      UserHandlerRegistry(network),
      network(network),
      table(network.tables->create<Table>("data"))
    {
      auto& tables = *network.tables;

      auto default_handler = [this](HandlerArgs& args) {
        const auto method = args.rpc_ctx->get_method();
        const auto local_method = method.substr(method.find_first_not_of('/'));
        if (local_method == UserScriptIds::ENV_HANDLER)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_NOT_FOUND);
          args.rpc_ctx->set_response_body(
            fmt::format("Cannot call environment script ('{}')", local_method));
          return;
        }

        const auto scripts = args.tx.get_view(this->network.app_scripts);

        auto handler_script = scripts->get(local_method);
        if (!handler_script)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_NOT_FOUND);
          args.rpc_ctx->set_response_body(fmt::format(
            "No handler script found for method '{}'", local_method));
          return;
        }

        JSRuntime* rt = JS_NewRuntime();
        if (rt == nullptr)
        {
          throw std::runtime_error("Failed to initialise QuickJS runtime");
        }

        JSContext* ctx = JS_NewContext(rt);
        if (ctx == nullptr)
        {
          JS_FreeRuntime(rt);
          throw std::runtime_error("Failed to initialise QuickJS context");
        }

        auto ltv = args.tx.get_view(table);
        JS_SetContextOpaque(ctx, (void*)ltv);

        auto global_obj = JS_GetGlobalObject(ctx);

        auto console = JS_NewObject(ctx);
        JS_SetPropertyStr(
          ctx,
          console,
          "log",
          JS_NewCFunction(ctx, ccfapp::js_print, "log", 1));
        JS_SetPropertyStr(ctx, global_obj, "console", console);

        auto data = JS_NewObject(ctx);
        JS_SetPropertyStr(
          ctx, data, "get", JS_NewCFunction(ctx, ccfapp::js_get, "get", 1));
        JS_SetPropertyStr(
          ctx, data, "put", JS_NewCFunction(ctx, ccfapp::js_put, "put", 2));
        JS_SetPropertyStr(
          ctx,
          data,
          "remove",
          JS_NewCFunction(ctx, ccfapp::js_remove, "remove", 1));
        auto tables_ = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, tables_, "data", data);
        JS_SetPropertyStr(ctx, global_obj, "tables", tables_);

        const auto& request_query = args.rpc_ctx->get_request_query();
        auto query_str =
          JS_NewStringLen(ctx, request_query.c_str(), request_query.size());
        JS_SetPropertyStr(ctx, global_obj, "query", query_str);

        const auto& request_body = args.rpc_ctx->get_request_body();
        auto body_str = JS_NewStringLen(
          ctx, (const char*)request_body.data(), request_body.size());
        JS_SetPropertyStr(ctx, global_obj, "body", body_str);

        JS_FreeValue(ctx, global_obj);

        if (!handler_script.value().text.has_value())
        {
          throw std::runtime_error("Could not find script text");
        }

        std::string code = handler_script.value().text.value();
        auto path = fmt::format("app_scripts::{}", local_method);
        JSValue val = JS_Eval(
          ctx, code.c_str(), code.size(), path.c_str(), JS_EVAL_TYPE_GLOBAL);

        auto status = true;

        if (JS_IsException(val))
        {
          js_dump_error(ctx);
          args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          args.rpc_ctx->set_response_body("Exception thrown while executing");
          return;
        }

        if (JS_IsBool(val) && !JS_VALUE_GET_BOOL(val))
          status = false;

        JSValue rval = JS_JSONStringify(ctx, val, JS_NULL, JS_NULL);
        auto cstr = JS_ToCString(ctx, rval);
        auto response = nlohmann::json::parse(cstr);

        JS_FreeValue(ctx, rval);
        JS_FreeCString(ctx, cstr);
        JS_FreeValue(ctx, val);

        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_body(
          jsonrpc::pack(response, jsonrpc::Pack::Text));
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        return;
      };

      set_default(default_handler);
    }

    // Since we do our own dispatch within the default handler, report the
    // supported methods here
    void list_methods(kv::Tx& tx, ListMethods::Out& out) override
    {
      UserHandlerRegistry::list_methods(tx, out);

      auto scripts = tx.get_view(this->network.app_scripts);
      scripts->foreach([&out](const auto& key, const auto&) {
        out.methods.push_back(key);
        return true;
      });
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

  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    NetworkTables& network, ccfapp::AbstractNodeContext& context)
  {
    return make_shared<JS>(network);
  }
} // namespace ccfapp
