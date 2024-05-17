// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "js/extensions/console.h"

#include "js/core/context.h"
#include "node/rpc/gov_logging.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    std::optional<std::stringstream> stringify_args(
      JSContext* ctx, int argc, JSValueConst* argv)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

      int i;
      std::optional<std::string> str;
      std::stringstream ss;

      for (i = 0; i < argc; i++)
      {
        if (i != 0)
        {
          ss << ' ';
        }
        if (!JS_IsError(ctx, argv[i]) && JS_IsObject(argv[i]))
        {
          auto rval = jsctx.json_stringify(jsctx.wrap(argv[i]));
          str = jsctx.to_str(rval);
        }
        else
        {
          str = jsctx.to_str(argv[i]);
        }
        if (!str)
        {
          return std::nullopt;
        }
        ss << *str;
      }
      return ss;
    }

    JSValue js_info(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      const auto ss = stringify_args(ctx, argc, argv);
      if (!ss.has_value())
      {
        return ccf::js::core::constants::Exception;
      }

      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);
      ConsoleExtension::log_info_with_tag(jsctx.access, ss->str());
      return ccf::js::core::constants::Undefined;
    }

    JSValue js_fail(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      const auto ss = stringify_args(ctx, argc, argv);
      if (!ss.has_value())
      {
        return ccf::js::core::constants::Exception;
      }

      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);
      switch (jsctx.access)
      {
        case (js::TxAccess::APP_RO):
        case (js::TxAccess::APP_RW):
        {
          CCF_APP_FAIL("{}", ss->str());
          break;
        }

        case (js::TxAccess::GOV_RO):
        case (js::TxAccess::GOV_RW):
        {
          GOV_FAIL_FMT("{}", ss->str());
          break;
        }

        default:
        {
          LOG_FAIL_FMT("{}", ss->str());
          break;
        }
      }
      return ccf::js::core::constants::Undefined;
    }

    JSValue js_fatal(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      const auto ss = stringify_args(ctx, argc, argv);
      if (!ss.has_value())
      {
        return ccf::js::core::constants::Exception;
      }

      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);
      switch (jsctx.access)
      {
        case (js::TxAccess::APP_RO):
        case (js::TxAccess::APP_RW):
        {
          CCF_APP_FATAL("{}", ss->str());
          break;
        }

        case (js::TxAccess::GOV_RO):
        case (js::TxAccess::GOV_RW):
        {
          GOV_FATAL_FMT("{}", ss->str());
          break;
        }

        default:
        {
          LOG_FATAL_FMT("{}", ss->str());
          break;
        }
      }
      return ccf::js::core::constants::Undefined;
    }

    static js::core::JSWrappedValue create_console_obj(js::core::Context& jsctx)
    {
      auto console = jsctx.new_obj();

      console.set("log", jsctx.new_c_function(js_info, "log", 1));
      console.set("info", jsctx.new_c_function(js_info, "info", 1));
      console.set("warn", jsctx.new_c_function(js_fail, "warn", 1));
      console.set("error", jsctx.new_c_function(js_fatal, "error", 1));

      return console;
    }
  }

  void ConsoleExtension::install(js::core::Context& ctx)
  {
    auto global_obj = ctx.get_global_obj();
    global_obj.set("console", create_console_obj(ctx));
  }

  void ConsoleExtension::log_info_with_tag(
    const ccf::js::TxAccess access, std::string_view s)
  {
    switch (access)
    {
      case (js::TxAccess::APP_RO):
      case (js::TxAccess::APP_RW):
      {
        CCF_APP_INFO("{}", s);
        break;
      }

      case (js::TxAccess::GOV_RO):
      case (js::TxAccess::GOV_RW):
      {
        GOV_INFO_FMT("{}", s);
        break;
      }

      default:
      {
        LOG_INFO_FMT("{}", s);
        break;
      }
    }
  }
}