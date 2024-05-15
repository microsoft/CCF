// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "js/extensions/ccf/kv.h"

#include "js/checks.h"
#include "js/core/context.h"
#include "js/extensions/ccf/kv_helpers.h"
#include "js/global_class_ids.h"
#include "js/map_access_permissions.h"

#include <map>
#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  struct CcfKvExtension::Impl
  {
    kv::Tx* tx;
    std::unordered_map<std::string, kv::untyped::Map::Handle*> kv_handles = {};

    struct HistoricalHandle
    {
      ccf::historical::StatePtr state;
      std::unique_ptr<kv::ReadOnlyTx> tx;
      std::unordered_map<std::string, kv::untyped::Map::ReadOnlyHandle*>
        kv_handles = {};
    };
    std::unordered_map<ccf::SeqNo, HistoricalHandle> historical_handles;

    Impl(kv::Tx* t) : tx(t){};
  };

  namespace
  {
    static kvhelpers::KVMap::Handle* get_map_handle(
      js::core::Context& jsctx, JSValueConst _this_val)
    {
      auto this_val = jsctx.duplicate_value(_this_val);
      auto map_name_val = this_val["_map_name"];
      auto map_name = jsctx.to_str(map_name_val);

      if (!map_name.has_value())
      {
        LOG_FAIL_FMT("No map name stored on handle");
        return nullptr;
      }

      auto extension = jsctx.get_extension<CcfKvExtension>();
      if (extension == nullptr)
      {
        LOG_FAIL_FMT("No KV extension available");
        return nullptr;
      }

      auto& handles = extension->impl->kv_handles;
      auto it = handles.find(map_name.value());
      if (it == handles.end())
      {
        it = handles.emplace_hint(it, map_name.value(), nullptr);
      }

      if (it->second == nullptr)
      {
        kv::Tx* tx = extension->impl->tx;
        if (tx == nullptr)
        {
          LOG_FAIL_FMT("Can't rehydrate MapHandle - no transaction context");
          return nullptr;
        }
        it->second = tx->rw<kvhelpers::KVMap>(map_name.value());
      }

      return it->second;
    }

    static kvhelpers::KVMap::ReadOnlyHandle* get_ro_map_handle(
      js::core::Context& jsctx, JSValueConst this_val)
    {
      // NB: This creates (and stores) a writeable handle internally, but
      // converts to the (subtype) ReadOnlyHandle* in return here. This means
      // that if we call has() and then put(), we'll correctly have a writeable
      // handle for the put() despite reading initially.
      return get_map_handle(jsctx, this_val);
    }

    static int js_kv_lookup(
      JSContext* ctx,
      JSPropertyDescriptor* desc,
      JSValueConst this_val,
      JSAtom property)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);
      const auto map_name = jsctx.to_str(property).value_or("");
      LOG_TRACE_FMT("Looking for kv map '{}'", map_name);

      const auto access_permission =
        ccf::js::check_kv_map_access(jsctx.access, map_name);
      auto handle_val =
        kvhelpers::create_kv_map_handle<get_ro_map_handle, get_map_handle>(
          jsctx, map_name, access_permission);
      if (JS_IsException(handle_val))
      {
        return -1;
      }

      desc->flags = 0;
      desc->value = handle_val;

      return true;
    }
  }

  CcfKvExtension::CcfKvExtension(kv::Tx* t)
  {
    impl = std::make_unique<CcfKvExtension::Impl>(t);
  }

  CcfKvExtension::~CcfKvExtension() = default;

  void CcfKvExtension::install(js::core::Context& ctx)
  {
    auto kv = ctx.new_obj_class(kv_class_id);

    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());
    ccf.set("kv", std::move(kv));
  }
}

namespace ccf::js
{
  JSClassExoticMethods kv_exotic_methods = {
    .get_own_property = extensions::js_kv_lookup};
  JSClassDef kv_class_def = {
    .class_name = "KV Tables", .exotic = &kv_exotic_methods};
}
