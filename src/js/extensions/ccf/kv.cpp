// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/ccf/kv.h"

#include "ccf/js/core/context.h"
#include "ccf/tx.h"
#include "js/checks.h"
#include "js/extensions/ccf/kv_helpers.h"
#include "js/global_class_ids.h"
#include "js/permissions_checks.h"
#include "kv/compacted_version_conflict.h"

#include <map>
#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  struct KvExtension::Impl
  {
    ccf::kv::Tx* tx;
    std::unordered_map<std::string, ccf::kv::untyped::Map::Handle*> kv_handles =
      {};

    std::optional<ccf::kv::CompactedVersionConflict>
      compacted_version_conflict = std::nullopt;

    Impl(ccf::kv::Tx* t) : tx(t) {};
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

      auto extension = jsctx.get_extension<KvExtension>();
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
        ccf::kv::Tx* tx = extension->impl->tx;
        if (tx == nullptr)
        {
          LOG_FAIL_FMT("Can't rehydrate MapHandle - no transaction context");
          return nullptr;
        }

        try
        {
          it->second = tx->rw<kvhelpers::KVMap>(map_name.value());
        }
        catch (const ccf::kv::CompactedVersionConflict& e)
        {
          LOG_DEBUG_FMT(
            "Caught CompactedVersionConflict in JS callback - storing to be "
            "rethrown later");
          extension->impl->compacted_version_conflict = e;
        }
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

      auto extension = jsctx.get_extension<KvExtension>();
      if (extension == nullptr)
      {
        LOG_FAIL_FMT("No KV extension available");
        return -1;
      }

      auto access_permission =
        ccf::js::check_kv_map_access(jsctx.access, map_name);
      std::string explanation =
        ccf::js::explain_kv_map_access(access_permission, jsctx.access);

      if (extension->namespace_restriction != nullptr)
      {
        std::string proposed_explanation;
        const auto proposed_permission =
          extension->namespace_restriction(map_name, proposed_explanation);

        // Name-based policy cannot grant more access (eg - cannot change
        // Read-Only to Read-Write), can only make it more restricted
        const auto combined_permission = ccf::js::intersect_access_permissions(
          proposed_permission, access_permission);
        if (combined_permission != access_permission)
        {
          access_permission = combined_permission;
          explanation = proposed_explanation;
        }
      }

      auto handle_val =
        kvhelpers::create_kv_map_handle<get_ro_map_handle, get_map_handle>(
          jsctx, map_name, access_permission, explanation);

      if (JS_IsException(handle_val))
      {
        return -1;
      }

      desc->flags = 0;
      desc->value = handle_val;

      return true;
    }
  }

  KvExtension::KvExtension(
    ccf::kv::Tx* t, const ccf::js::NamespaceRestriction& nr) :
    namespace_restriction(nr)
  {
    impl = std::make_unique<KvExtension::Impl>(t);
  }

  KvExtension::~KvExtension() = default;

  void KvExtension::install(js::core::Context& ctx)
  {
    auto kv = ctx.new_obj_class(kv_class_id);

    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());
    ccf.set("kv", std::move(kv));
  }

  void KvExtension::rethrow_trapped_exceptions() const
  {
    auto& exception = impl->compacted_version_conflict;
    if (exception.has_value())
    {
      throw std::move(exception.value());
    }
  }
}

namespace ccf::js
{
  JSClassExoticMethods kv_exotic_methods = {
    .get_own_property = extensions::js_kv_lookup,
    .get_own_property_names = {},
    .delete_property = {},
    .define_own_property = {},
    .has_property = {},
    .get_property = {},
    .set_property = {}};
  JSClassDef kv_class_def = {
    .class_name = "KV Tables",
    .finalizer = {},
    .gc_mark = {},
    .call = {},
    .exotic = &kv_exotic_methods};
}
