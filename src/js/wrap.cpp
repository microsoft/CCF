// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "js/wrap.h"

#include "ccf/ds/logger.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/tx_id.h"
#include "ccf/version.h"
#include "crypto/certs.h"
#include "crypto/openssl/x509_time.h"
#include "js/consensus.cpp"
#include "js/conv.cpp"
#include "js/crypto.cpp"
#include "js/historical.cpp"
#include "js/no_plugins.cpp"
#include "kv/untyped_map.h"
#include "node/rpc/call_types.h"
#include "node/rpc/gov_effects_interface.h"
#include "node/rpc/jwt_management.h"
#include "node/rpc/node_interface.h"

#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>
#include <span>

namespace ccf::js
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  using KVMap = kv::untyped::Map;

  JSClassID kv_class_id = 0;
  JSClassID kv_map_handle_class_id = 0;
  JSClassID body_class_id = 0;
  JSClassID node_class_id = 0;
  JSClassID network_class_id = 0;
  JSClassID rpc_class_id = 0;
  JSClassID host_class_id = 0;
  JSClassID consensus_class_id = 0;
  JSClassID historical_class_id = 0;
  JSClassID historical_state_class_id = 0;

  JSClassDef kv_class_def = {};
  JSClassExoticMethods kv_exotic_methods = {};
  JSClassDef kv_map_handle_class_def = {};
  JSClassDef body_class_def = {};
  JSClassDef node_class_def = {};
  JSClassDef network_class_def = {};
  JSClassDef rpc_class_def = {};
  JSClassDef host_class_def = {};
  JSClassDef consensus_class_def = {};
  JSClassDef historical_class_def = {};
  JSClassDef historical_state_class_def = {};

  std::vector<FFIPlugin> ffi_plugins;

  static void register_ffi_plugin(const FFIPlugin& plugin)
  {
    if (plugin.ccf_version != std::string(ccf::ccf_version))
    {
      throw std::runtime_error(fmt::format(
        "CCF version mismatch in JS FFI plugin '{}': expected={} != actual={}",
        plugin.name,
        plugin.ccf_version,
        ccf::ccf_version));
    }
    LOG_DEBUG_FMT("JS FFI plugin registered: {}", plugin.name);
    ffi_plugins.push_back(plugin);
  }

  void register_ffi_plugins(const std::vector<FFIPlugin>& plugins)
  {
    for (const auto& plugin : plugins)
    {
      register_ffi_plugin(plugin);
    }
  }

  static JSValue js_kv_map_has(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));

    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
    {
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
    }

    auto has = handle->has({key, key + key_size});

    return JS_NewBool(ctx, has);
  }

  static JSValue js_kv_map_get(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));

    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
    {
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
    }

    auto val = handle->get({key, key + key_size});

    if (!val.has_value())
    {
      return JS_UNDEFINED;
    }

    JSValue buf =
      JS_NewArrayBufferCopy(ctx, val.value().data(), val.value().size());

    if (JS_IsException(buf))
      js_dump_error(ctx);

    return buf;
  }

  static JSValue js_kv_get_version_of_previous_write(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));

    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
    {
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
    }

    auto val = handle->get_version_of_previous_write({key, key + key_size});

    if (!val.has_value())
    {
      return JS_UNDEFINED;
    }

    return JS_NewInt64(ctx, val.value());
  }

  static JSValue js_kv_map_size_getter(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst*)
  {
    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));
    const uint64_t size = handle->size();
    if (size > INT64_MAX)
    {
      return JS_ThrowInternalError(
        ctx, "Map size (%lu) is too large to represent in int64", size);
    }
    return JS_NewInt64(ctx, (int64_t)size);
  }

  static JSValue js_kv_map_delete(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));

    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
    {
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
    }

    auto val = handle->remove({key, key + key_size});

    return JS_NewBool(ctx, val);
  }

  static JSValue js_kv_map_delete_read_only(
    JSContext* ctx, JSValueConst, int, JSValueConst*)
  {
    return JS_ThrowTypeError(ctx, "Cannot call delete on read-only map");
  }

  static JSValue js_kv_map_set(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));

    if (argc != 2)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 2", argc);
    }

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    size_t val_size;
    uint8_t* val = JS_GetArrayBuffer(ctx, &val_size, argv[1]);

    if (!key || !val)
    {
      return JS_ThrowTypeError(ctx, "Arguments must be ArrayBuffers");
    }

    handle->put({key, key + key_size}, {val, val + val_size});

    return JS_DupValue(ctx, this_val);
  }

  static JSValue js_kv_map_set_read_only(
    JSContext* ctx, JSValueConst, int, JSValueConst*)
  {
    return JS_ThrowTypeError(ctx, "Cannot call set on read-only map");
  }

  static JSValue js_kv_map_clear(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));

    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 0", argc);
    }

    handle->clear();

    return JS_UNDEFINED;
  }

  static JSValue js_kv_map_clear_read_only(
    JSContext* ctx, JSValueConst, int, JSValueConst*)
  {
    return JS_ThrowTypeError(ctx, "Cannot call clear on read-only map");
  }

  static JSValue js_kv_map_foreach(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));

    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    JSWrappedValue func(ctx, argv[0]);
    JSWrappedValue obj(ctx, this_val);

    if (!JS_IsFunction(ctx, func))
    {
      return JS_ThrowTypeError(ctx, "Argument must be a function");
    }

    bool failed = false;
    handle->foreach(
      [&jsctx, &obj, &func, &failed](const auto& k, const auto& v) {
        std::vector<JSWrappedValue> args = {
          // JS forEach expects (v, k, map) rather than (k, v)
          jsctx.new_array_buffer_copy(v.data(), v.size()),
          jsctx.new_array_buffer_copy(k.data(), k.size()),
          obj};

        auto val = jsctx.call(func, args);

        if (JS_IsException(val))
        {
          js_dump_error(jsctx);
          failed = true;
          return false;
        }

        return true;
      });

    if (failed)
    {
      return JS_EXCEPTION;
    }

    return JS_UNDEFINED;
  }

  static int js_kv_lookup(
    JSContext* ctx,
    JSPropertyDescriptor* desc,
    JSValueConst this_val,
    JSAtom property)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    const auto property_name = jsctx.to_str(property).value_or("");
    LOG_TRACE_FMT("Looking for kv map '{}'", property_name);

    const auto [security_domain, access_category] =
      kv::parse_map_name(property_name);

    auto tx_ctx_ptr =
      static_cast<TxContext*>(JS_GetOpaque(this_val, kv_class_id));

    auto read_only = false;
    switch (access_category)
    {
      case kv::AccessCategory::INTERNAL:
      {
        if (security_domain == kv::SecurityDomain::PUBLIC)
        {
          read_only = true;
        }
        else
        {
          throw std::runtime_error(fmt::format(
            "JS application cannot access private internal CCF table '{}'",
            property_name));
        }
        break;
      }
      case kv::AccessCategory::GOVERNANCE:
      {
        read_only = tx_ctx_ptr->access != TxAccess::GOV_RW;
        break;
      }
      case kv::AccessCategory::APPLICATION:
      {
        read_only = tx_ctx_ptr->access != TxAccess::APP;
        break;
      }
      default:
      {
        throw std::logic_error(fmt::format(
          "Unhandled AccessCategory for table '{}'", property_name));
      }
    }

    auto handle = tx_ctx_ptr->tx->rw<KVMap>(property_name);

    // This follows the interface of Map:
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map
    // Keys and values are ArrayBuffers. Keys are matched based on their
    // contents.
    auto view_val = JS_NewObjectClass(ctx, kv_map_handle_class_id);
    JS_SetOpaque(view_val, handle);

    JS_SetPropertyStr(
      ctx, view_val, "has", JS_NewCFunction(ctx, js_kv_map_has, "has", 1));

    JS_SetPropertyStr(
      ctx, view_val, "get", JS_NewCFunction(ctx, js_kv_map_get, "get", 1));

    auto size_atom = JS_NewAtom(ctx, "size");
    JS_DefinePropertyGetSet(
      ctx,
      view_val,
      size_atom,
      JS_NewCFunction2(
        ctx,
        js_kv_map_size_getter,
        "size",
        0,
        JS_CFUNC_getter,
        JS_CFUNC_getter_magic),
      JS_UNDEFINED,
      0);
    JS_FreeAtom(ctx, size_atom);

    auto setter = js_kv_map_set;
    auto deleter = js_kv_map_delete;
    auto clearer = js_kv_map_clear;

    if (read_only)
    {
      setter = js_kv_map_set_read_only;
      deleter = js_kv_map_delete_read_only;
      clearer = js_kv_map_clear_read_only;
    }

    JS_SetPropertyStr(
      ctx, view_val, "set", JS_NewCFunction(ctx, setter, "set", 2));
    JS_SetPropertyStr(
      ctx, view_val, "delete", JS_NewCFunction(ctx, deleter, "delete", 1));
    JS_SetPropertyStr(
      ctx, view_val, "clear", JS_NewCFunction(ctx, clearer, "clear", 0));

    JS_SetPropertyStr(
      ctx,
      view_val,
      "forEach",
      JS_NewCFunction(ctx, js_kv_map_foreach, "forEach", 1));

    JS_SetPropertyStr(
      ctx,
      view_val,
      "getVersionOfPreviousWrite",
      JS_NewCFunction(
        ctx,
        js_kv_get_version_of_previous_write,
        "getVersionOfPreviousWrite",
        1));

    desc->flags = 0;
    desc->value = view_val;

    return true;
  }

  JSValue js_body_text(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    if (argc != 0)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected none", argc);

    auto body = static_cast<const std::vector<uint8_t>*>(
      JS_GetOpaque(this_val, body_class_id));
    auto body_ = JS_NewStringLen(ctx, (const char*)body->data(), body->size());
    return body_;
  }

  JSValue js_body_json(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    if (argc != 0)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected none", argc);

    auto body = static_cast<const std::vector<uint8_t>*>(
      JS_GetOpaque(this_val, body_class_id));
    std::string body_str(body->begin(), body->end());
    auto body_ = JS_ParseJSON(ctx, body_str.c_str(), body->size(), "<body>");
    return body_;
  }

  JSValue js_body_array_buffer(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    if (argc != 0)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected none", argc);

    auto body = static_cast<const std::vector<uint8_t>*>(
      JS_GetOpaque(this_val, body_class_id));
    auto body_ = JS_NewArrayBufferCopy(ctx, body->data(), body->size());
    return body_;
  }

  JSValue js_node_trigger_ledger_rekey(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected none", argc);
    }

    auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
      JS_GetOpaque(this_val, node_class_id));

    auto global_obj = jsctx.get_global_obj();
    auto ccf = global_obj["ccf"];
    auto kv = ccf["kv"];

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(
        ctx, "No transaction available to rekey ledger");
    }

    bool result = gov_effects->rekey_ledger(*tx_ctx_ptr->tx);

    if (!result)
    {
      return JS_ThrowInternalError(ctx, "Could not rekey ledger");
    }

    return JS_UNDEFINED;
  }

  JSValue js_node_transition_service_to_open(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 2)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected two", argc);
    }

    auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
      JS_GetOpaque(this_val, node_class_id));

    if (gov_effects == nullptr)
    {
      return JS_ThrowInternalError(ctx, "Node state is not set");
    }

    auto global_obj = jsctx.get_global_obj();
    auto ccf = global_obj["ccf"];
    auto kv = ccf["kv"];

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(
        ctx, "No transaction available to open service");
    }

    try
    {
      AbstractGovernanceEffects::ServiceIdentities identities;

      size_t prev_bytes_sz = 0;
      uint8_t* prev_bytes = nullptr;
      if (!JS_IsUndefined(argv[0]))
      {
        prev_bytes = JS_GetArrayBuffer(ctx, &prev_bytes_sz, argv[0]);
        if (!prev_bytes)
        {
          return JS_ThrowTypeError(
            ctx, "Previous service identity argument is not an array buffer");
        }
        identities.previous =
          std::vector<uint8_t>{prev_bytes, prev_bytes + prev_bytes_sz};
        LOG_DEBUG_FMT(
          "previous service identity: {}", ds::to_hex(*identities.previous));
      }

      if (JS_IsUndefined(argv[1]))
      {
        return JS_ThrowInternalError(
          ctx, "Proposal requires a service identity");
      }

      size_t next_bytes_sz = 0;
      uint8_t* next_bytes = JS_GetArrayBuffer(ctx, &next_bytes_sz, argv[1]);

      if (!next_bytes)
      {
        return JS_ThrowTypeError(
          ctx, "Next service identity argument is not an array buffer");
      }

      identities.next =
        std::vector<uint8_t>{next_bytes, next_bytes + next_bytes_sz};
      LOG_DEBUG_FMT("next service identity: {}", ds::to_hex(identities.next));

      gov_effects->transition_service_to_open(*tx_ctx_ptr->tx, identities);
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Unable to open service: {}", e.what());
    }

    return JS_UNDEFINED;
  }

  JSValue js_network_generate_endorsed_certificate(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 3)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 3", argc);
    }

    auto network =
      static_cast<ccf::NetworkState*>(JS_GetOpaque(this_val, network_class_id));
    if (network == nullptr)
    {
      return JS_ThrowInternalError(ctx, "Network state is not set");
    }

    auto csr_cstr = jsctx.to_str(argv[0]);
    if (!csr_cstr)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }
    auto csr = crypto::Pem(*csr_cstr);

    auto valid_from_str = jsctx.to_str(argv[1]);
    if (!valid_from_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }
    auto valid_from = *valid_from_str;

    size_t validity_period_days = 0;
    if (JS_ToIndex(ctx, &validity_period_days, argv[2]) < 0)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    auto endorsed_cert = create_endorsed_cert(
      csr,
      valid_from,
      validity_period_days,
      network->identity->priv_key,
      network->identity->cert);

    return JS_NewString(ctx, endorsed_cert.str().c_str());
  }

  JSValue js_network_generate_certificate(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 2)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 2", argc);
    }

    auto network =
      static_cast<ccf::NetworkState*>(JS_GetOpaque(this_val, network_class_id));
    if (network == nullptr)
    {
      return JS_ThrowInternalError(ctx, "Network state is not set");
    }

    auto valid_from_str = jsctx.to_str(argv[0]);
    if (!valid_from_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }
    auto valid_from = *valid_from_str;

    size_t validity_period_days = 0;
    if (JS_ToIndex(ctx, &validity_period_days, argv[1]) < 0)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    auto renewed_cert =
      network->identity->issue_certificate(valid_from, validity_period_days);

    return JS_NewString(ctx, renewed_cert.str().c_str());
  }

  JSValue js_network_latest_ledger_secret_seqno(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected none", argc);
    }

    auto network =
      static_cast<ccf::NetworkState*>(JS_GetOpaque(this_val, network_class_id));

    if (network == nullptr)
    {
      return JS_ThrowInternalError(ctx, "Network state is not set");
    }

    auto global_obj = jsctx.get_global_obj();
    auto ccf = global_obj["ccf"];
    auto kv = ccf["kv"];

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(
        ctx, "No transaction available to fetch latest ledger secret seqno");
    }

    return JS_NewInt64(
      ctx, network->ledger_secrets->get_latest(*tx_ctx_ptr->tx).first);
  }

  JSValue js_rpc_set_apply_writes(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 1", argc);
    }

    auto rpc_ctx =
      static_cast<ccf::RpcContext*>(JS_GetOpaque(this_val, rpc_class_id));

    if (rpc_ctx == nullptr)
    {
      return JS_ThrowInternalError(ctx, "RPC context is not set");
    }

    int val = JS_ToBool(ctx, argv[0]);
    if (val == -1)
    {
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    rpc_ctx->set_apply_writes(val);
    return JS_UNDEFINED;
  }

  JSValue js_rpc_set_claims_digest(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    if (argc != 1)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 1", argc);
    }

    auto rpc_ctx =
      static_cast<ccf::RpcContext*>(JS_GetOpaque(this_val, rpc_class_id));

    if (rpc_ctx == nullptr)
    {
      return JS_ThrowInternalError(ctx, "RPC context is not set");
    }

    size_t digest_size;
    uint8_t* digest = JS_GetArrayBuffer(ctx, &digest_size, argv[0]);

    if (!digest)
    {
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
    }

    if (digest_size != ccf::ClaimsDigest::Digest::SIZE)
    {
      return JS_ThrowTypeError(
        ctx, "Argument must be an ArrayBuffer of the right size");
    }

    std::span<uint8_t, ccf::ClaimsDigest::Digest::SIZE> digest_bytes(
      digest, ccf::ClaimsDigest::Digest::SIZE);
    rpc_ctx->set_claims_digest(
      ccf::ClaimsDigest::Digest::from_span(digest_bytes));

    return JS_UNDEFINED;
  }

  JSValue js_gov_set_jwt_public_signing_keys(
    JSContext* ctx,
    [[maybe_unused]] JSValueConst this_val,
    int argc,
    JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 3)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 3", argc);
    }

    // yikes
    auto global_obj = jsctx.get_global_obj();
    auto ccf = global_obj["ccf"];
    auto kv = ccf["kv"];

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    auto& tx = *tx_ctx_ptr->tx;

    auto issuer = jsctx.to_str(argv[0]);
    if (!issuer)
    {
      return JS_ThrowTypeError(ctx, "issuer argument is not a string");
    }

    JSValue metadata_val = JS_JSONStringify(ctx, argv[1], JS_NULL, JS_NULL);
    if (JS_IsException(metadata_val))
    {
      return JS_ThrowTypeError(ctx, "metadata argument is not a JSON object");
    }
    auto metadata_json = jsctx.to_str(metadata_val);

    JSValue jwks_val = JS_JSONStringify(ctx, argv[2], JS_NULL, JS_NULL);
    if (JS_IsException(jwks_val))
    {
      return JS_ThrowTypeError(ctx, "jwks argument is not a JSON object");
    }
    auto jwks_json = jsctx.to_str(jwks_val);

    try
    {
      auto metadata =
        nlohmann::json::parse(*metadata_json).get<ccf::JwtIssuerMetadata>();
      auto jwks = nlohmann::json::parse(*jwks_json).get<ccf::JsonWebKeySet>();
      auto success =
        ccf::set_jwt_public_signing_keys(tx, "<js>", *issuer, metadata, jwks);
      if (!success)
      {
        return JS_ThrowInternalError(
          ctx, "set_jwt_public_signing_keys() failed");
      }
    }
    catch (std::exception& exc)
    {
      return JS_ThrowInternalError(ctx, "Error: %s", exc.what());
    }
    return JS_UNDEFINED;
  }

  JSValue js_gov_remove_jwt_public_signing_keys(
    JSContext* ctx,
    [[maybe_unused]] JSValueConst this_val,
    int argc,
    JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 1", argc);
    }

    // yikes
    auto global_obj = jsctx.get_global_obj();
    auto ccf = global_obj["ccf"];
    auto kv = ccf["kv"];

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    auto issuer = jsctx.to_str(argv[0]);
    if (!issuer)
    {
      return JS_ThrowTypeError(ctx, "issuer argument is not a string");
    }

    try
    {
      auto& tx = *tx_ctx_ptr->tx;
      ccf::remove_jwt_public_signing_keys(tx, *issuer);
    }
    catch (std::exception& exc)
    {
      return JS_ThrowInternalError(ctx, "Error: %s", exc.what());
    }
    return JS_UNDEFINED;
  }

  JSValue js_node_trigger_recovery_shares_refresh(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected none", argc);
    }

    auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
      JS_GetOpaque(this_val, node_class_id));
    auto global_obj = jsctx.get_global_obj();
    auto ccf = global_obj["ccf"];
    auto kv = ccf["kv"];

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(
        ctx, "No transaction available to open service");
    }

    gov_effects->trigger_recovery_shares_refresh(*tx_ctx_ptr->tx);

    return JS_UNDEFINED;
  }

  JSValue js_trigger_ledger_chunk(
    JSContext* ctx,
    JSValueConst this_val,
    [[maybe_unused]] int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
      JS_GetOpaque(this_val, node_class_id));
    auto global_obj = jsctx.get_global_obj();
    auto ccf = global_obj["ccf"];
    auto kv = ccf["kv"];

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    try
    {
      gov_effects->trigger_ledger_chunk(*tx_ctx_ptr->tx);
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Unable to force ledger chunk: {}", e.what());
    }

    return JS_UNDEFINED;
  }

  JSValue js_trigger_snapshot(
    JSContext* ctx,
    JSValueConst this_val,
    [[maybe_unused]] int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
      JS_GetOpaque(this_val, node_class_id));
    auto global_obj = jsctx.get_global_obj();
    auto ccf = global_obj["ccf"];
    auto kv = ccf["kv"];

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    try
    {
      gov_effects->trigger_snapshot(*tx_ctx_ptr->tx);
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Unable to request snapshot: {}", e.what());
    }

    return JS_UNDEFINED;
  }

  JSValue js_node_trigger_host_process_launch(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 1", argc);
    }

    auto args = JSWrappedValue(ctx, argv[0]);

    if (!JS_IsArray(ctx, args))
    {
      return JS_ThrowTypeError(ctx, "First argument must be an array");
    }

    std::vector<std::string> process_args;

    auto len_atom = JS_NewAtom(ctx, "length");
    auto len_val = args.get_property(len_atom);
    JS_FreeAtom(ctx, len_atom);
    uint32_t len = 0;
    JS_ToUint32(ctx, &len, len_val);

    if (len == 0)
    {
      return JS_ThrowRangeError(
        ctx, "First argument must be a non-empty array");
    }

    for (uint32_t i = 0; i < len; i++)
    {
      auto arg_val = args[i];
      if (!JS_IsString(arg_val))
      {
        return JS_ThrowTypeError(
          ctx, "First argument must be an array of strings, found non-string");
      }
      auto arg = jsctx.to_str(arg_val);
      process_args.push_back(*arg);
    }

    auto host_processes = static_cast<ccf::AbstractHostProcesses*>(
      JS_GetOpaque(this_val, host_class_id));

    host_processes->trigger_host_process_launch(process_args);

    return JS_UNDEFINED;
  }

  JSWrappedValue load_app_module(
    JSContext* ctx, const char* module_name, kv::Tx* tx)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    std::string module_name_kv(module_name);
    if (module_name_kv[0] != '/')
    {
      module_name_kv.insert(0, "/");
    }
    // conforms to quickjs' default module filename normalizer
    auto module_name_quickjs = module_name_kv.c_str() + 1;

    const auto modules = tx->ro<ccf::Modules>(ccf::Tables::MODULES);

    std::optional<std::vector<uint8_t>> bytecode;
    const auto modules_quickjs_bytecode = tx->ro<ccf::ModulesQuickJsBytecode>(
      ccf::Tables::MODULES_QUICKJS_BYTECODE);
    bytecode = modules_quickjs_bytecode->get(module_name_kv);
    if (bytecode)
    {
      auto modules_quickjs_version = tx->ro<ccf::ModulesQuickJsVersion>(
        ccf::Tables::MODULES_QUICKJS_VERSION);
      if (modules_quickjs_version->get() != std::string(ccf::quickjs_version))
        bytecode = std::nullopt;
    }

    JSWrappedValue module_val;

    if (!bytecode)
    {
      LOG_TRACE_FMT("Loading module '{}'", module_name_kv);

      auto module = modules->get(module_name_kv);
      auto& js = module.value();

      const char* buf = js.c_str();
      size_t buf_len = js.size();
      module_val = jsctx.eval(
        buf,
        buf_len,
        module_name_quickjs,
        JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
      if (JS_IsException(module_val))
      {
        js::js_dump_error(ctx);
        throw std::runtime_error(
          fmt::format("Failed to compile module '{}'", module_name));
      }
    }
    else
    {
      LOG_TRACE_FMT("Loading module from cache '{}'", module_name_kv);

      module_val = jsctx.read_object(
        bytecode->data(), bytecode->size(), JS_READ_OBJ_BYTECODE);
      if (JS_IsException(module_val))
      {
        js::js_dump_error(ctx);
        throw std::runtime_error(fmt::format(
          "Failed to deserialize bytecode for module '{}'", module_name));
      }
      if (JS_ResolveModule(ctx, module_val) < 0)
      {
        js::js_dump_error(ctx);
        throw std::runtime_error(fmt::format(
          "Failed to resolve dependencies for module '{}'", module_name));
      }
    }

    return module_val;
  }

  JSModuleDef* js_app_module_loader(
    JSContext* ctx, const char* module_name, void* opaque)
  {
    auto tx = (kv::Tx*)opaque;

    try
    {
      auto module_val = load_app_module(ctx, module_name, tx);
      return (JSModuleDef*)JS_VALUE_GET_PTR(module_val.val);
    }
    catch (const std::exception& exc)
    {
      JS_ThrowReferenceError(ctx, "%s", exc.what());
      js::js_dump_error(ctx);
      return nullptr;
    }
  }

  JSValue js_refresh_app_bytecode_cache(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected none", argc);
    }

    auto global_obj = jsctx.get_global_obj();
    auto ccf = global_obj["ccf"];
    auto kv = ccf["kv"];

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    auto& tx = *tx_ctx_ptr->tx;

    js::Runtime rt;
    JS_SetModuleLoaderFunc(rt, nullptr, js::js_app_module_loader, &tx);
    js::Context ctx2(rt);

    auto modules = tx.ro<ccf::Modules>(ccf::Tables::MODULES);
    auto quickjs_version =
      tx.wo<ccf::ModulesQuickJsVersion>(ccf::Tables::MODULES_QUICKJS_VERSION);
    auto quickjs_bytecode =
      tx.wo<ccf::ModulesQuickJsBytecode>(ccf::Tables::MODULES_QUICKJS_BYTECODE);

    quickjs_version->put(ccf::quickjs_version);
    quickjs_bytecode->clear();

    try
    {
      modules->foreach([&](const auto& name, const auto& src) {
        JSValue module_val = load_app_module(ctx2, name.c_str(), &tx);

        uint8_t* out_buf;
        size_t out_buf_len;
        int flags = JS_WRITE_OBJ_BYTECODE;
        out_buf = JS_WriteObject(ctx2, &out_buf_len, module_val, flags);
        if (!out_buf)
        {
          js_dump_error(ctx);
          throw std::runtime_error(fmt::format(
            "Unable to serialize bytecode for JS module '{}'", name));
        }

        quickjs_bytecode->put(name, {out_buf, out_buf + out_buf_len});

        js_free(ctx2, out_buf);

        return true;
      });
    }
    catch (std::runtime_error& exc)
    {
      return JS_ThrowInternalError(ctx, "%s", exc.what());
    }

    return JS_UNDEFINED;
  }

  // Partially replicates https://developer.mozilla.org/en-US/docs/Web/API/Body
  // with a synchronous interface.
  static const JSCFunctionListEntry js_body_proto_funcs[] = {
    JS_CFUNC_DEF("text", 0, js_body_text),
    JS_CFUNC_DEF("json", 0, js_body_json),
    JS_CFUNC_DEF("arrayBuffer", 0, js_body_array_buffer),
  };

  // Not thread-safe, must happen exactly once
  void register_class_ids()
  {
    JS_NewClassID(&kv_class_id);
    kv_exotic_methods.get_own_property = js_kv_lookup;
    kv_class_def.class_name = "KV Tables";
    kv_class_def.exotic = &kv_exotic_methods;

    JS_NewClassID(&kv_map_handle_class_id);
    kv_map_handle_class_def.class_name = "KV Map Handle";

    JS_NewClassID(&body_class_id);
    body_class_def.class_name = "Body";

    JS_NewClassID(&node_class_id);
    node_class_def.class_name = "Node";

    JS_NewClassID(&network_class_id);
    network_class_def.class_name = "Network";

    JS_NewClassID(&rpc_class_id);
    rpc_class_def.class_name = "RPC";

    JS_NewClassID(&host_class_id);
    host_class_def.class_name = "Host";

    JS_NewClassID(&consensus_class_id);
    consensus_class_def.class_name = "Consensus";

    JS_NewClassID(&historical_class_id);
    historical_class_def.class_name = "Historical";

    JS_NewClassID(&historical_state_class_id);
    historical_state_class_def.class_name = "HistoricalState";
    historical_state_class_def.finalizer = js_historical_state_finalizer;
  }

  JSValue js_print(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    int i;
    std::optional<std::string> str;
    std::stringstream ss;

    for (i = 0; i < argc; i++)
    {
      if (i != 0)
        ss << ' ';
      if (!JS_IsError(ctx, argv[i]) && JS_IsObject(argv[i]))
      {
        auto rval = jsctx.json_stringify(JSWrappedValue(ctx, argv[i]));
        str = jsctx.to_str(rval);
      }
      else
        str = jsctx.to_str(argv[i]);
      if (!str)
        return JS_EXCEPTION;
      ss << *str;
    }
    LOG_INFO << ss.str() << std::endl;
    return JS_UNDEFINED;
  }

  void js_dump_error(JSContext* ctx)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto exception_val = jsctx.get_exception();

    bool is_error = JS_IsError(ctx, exception_val);
    if (!is_error)
      LOG_INFO_FMT("Throw: ");
    js_print(ctx, JS_NULL, 1, (JSValueConst*)&exception_val);
    if (is_error)
    {
      auto val = exception_val["stack"];
      if (!JS_IsUndefined(val))
      {
        LOG_INFO_FMT("{}", jsctx.to_str(val).value_or(""));
      }
    }

    JS_Throw(ctx, exception_val.take());
  }

  std::pair<std::string, std::optional<std::string>> js_error_message(
    Context& ctx)
  {
    auto exception_val = ctx.get_exception();
    std::optional<std::string> message;
    bool is_error = JS_IsError(ctx, exception_val);
    if (!is_error && JS_IsObject(exception_val))
    {
      auto rval = ctx.json_stringify(exception_val);
      message = ctx.to_str(rval);
    }
    else
    {
      message = ctx.to_str(exception_val);
    }

    std::optional<std::string> trace = std::nullopt;
    if (is_error)
    {
      auto val = exception_val["stack"];
      if (!JS_IsUndefined(val))
      {
        trace = ctx.to_str(val);
      }
    }
    return {message.value_or(""), trace};
  }

  JSWrappedValue Context::default_function(
    const std::string& code, const std::string& path)

  {
    return function(code, "default", path);
  }

  JSWrappedValue Context::function(
    const std::string& code, const std::string& func, const std::string& path)
  {
    auto module = eval(
      code.c_str(),
      code.size(),
      path.c_str(),
      JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);

    if (JS_IsException(module))
    {
      js_dump_error(ctx);
      throw std::runtime_error(fmt::format("Failed to compile {}", path));
    }

    return function(module, func, path);
  }

  JSWrappedValue Context::function(
    const JSWrappedValue& module,
    const std::string& func,
    const std::string& path)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto eval_val = eval_function(module);

    if (JS_IsException(eval_val))
    {
      js_dump_error(ctx);
      throw std::runtime_error(fmt::format("Failed to execute {}", path));
    }

    // Get exported function from module
    assert(JS_VALUE_GET_TAG(module.val) == JS_TAG_MODULE);
    auto module_def = (JSModuleDef*)JS_VALUE_GET_PTR(module.val);
    auto export_count = JS_GetModuleExportEntriesCount(module_def);
    for (auto i = 0; i < export_count; i++)
    {
      auto export_name_atom = JS_GetModuleExportEntryName(ctx, module_def, i);
      auto export_name = jsctx.to_str(export_name_atom);
      JS_FreeAtom(ctx, export_name_atom);
      if (export_name.value_or("") == func)
      {
        auto export_func = get_module_export_entry(module_def, i);
        if (!JS_IsFunction(ctx, export_func))
        {
          throw std::runtime_error(fmt::format(
            "Export '{}' of module '{}' is not a function", func, path));
        }
        return export_func;
      }
    }

    throw std::runtime_error(
      fmt::format("Failed to find export '{}' in module '{}'", func, path));
  }

  void register_request_body_class(JSContext* ctx)
  {
    // Set prototype for request body class
    JSValue body_proto = JS_NewObject(ctx);
    size_t func_count =
      sizeof(js_body_proto_funcs) / sizeof(js_body_proto_funcs[0]);
    JS_SetPropertyFunctionList(
      ctx, body_proto, js_body_proto_funcs, func_count);
    JS_SetClassProto(ctx, body_class_id, body_proto);
  }

  static JSWrappedValue create_console_obj(JSContext* ctx)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto console = jsctx.new_obj();

    JS_SetPropertyStr(
      ctx, console, "log", JS_NewCFunction(ctx, js_print, "log", 1));

    return console;
  }

  void populate_global_console(Context& ctx)
  {
    auto global_obj = ctx.get_global_obj();
    global_obj.set("console", create_console_obj(ctx));
  }

  JSValue create_ccf_obj(
    TxContext* txctx,
    TxContext* historical_txctx,
    ccf::RpcContext* rpc_ctx,
    const std::optional<ccf::TxID>& transaction_id,
    ccf::TxReceiptPtr receipt,
    ccf::AbstractGovernanceEffects* gov_effects,
    ccf::AbstractHostProcesses* host_processes,
    ccf::NetworkState* network_state,
    ccf::historical::AbstractStateCache* historical_state,
    ccf::BaseEndpointRegistry* endpoint_registry,
    js::Context& ctx)
  {
    auto ccf = JS_NewObject(ctx);

    JS_SetPropertyStr(
      ctx, ccf, "strToBuf", JS_NewCFunction(ctx, js_str_to_buf, "strToBuf", 1));
    JS_SetPropertyStr(
      ctx, ccf, "bufToStr", JS_NewCFunction(ctx, js_buf_to_str, "bufToStr", 1));
    JS_SetPropertyStr(
      ctx,
      ccf,
      "jsonCompatibleToBuf",
      JS_NewCFunction(
        ctx, js_json_compatible_to_buf, "jsonCompatibleToBuf", 1));
    JS_SetPropertyStr(
      ctx,
      ccf,
      "bufToJsonCompatible",
      JS_NewCFunction(
        ctx, js_buf_to_json_compatible, "bufToJsonCompatible", 1));
    JS_SetPropertyStr(
      ctx,
      ccf,
      "generateAesKey",
      JS_NewCFunction(ctx, js_generate_aes_key, "generateAesKey", 1));
    JS_SetPropertyStr(
      ctx,
      ccf,
      "generateRsaKeyPair",
      JS_NewCFunction(ctx, js_generate_rsa_key_pair, "generateRsaKeyPair", 1));
    JS_SetPropertyStr(
      ctx, ccf, "wrapKey", JS_NewCFunction(ctx, js_wrap_key, "wrapKey", 3));
    JS_SetPropertyStr(
      ctx, ccf, "digest", JS_NewCFunction(ctx, js_digest, "digest", 2));
    JS_SetPropertyStr(
      ctx,
      ccf,
      "isValidX509CertBundle",
      JS_NewCFunction(
        ctx, js_is_valid_x509_cert_bundle, "isValidX509CertBundle", 1));
    JS_SetPropertyStr(
      ctx,
      ccf,
      "isValidX509CertChain",
      JS_NewCFunction(
        ctx, js_is_valid_x509_cert_chain, "isValidX509CertChain", 2));
    JS_SetPropertyStr(
      ctx, ccf, "pemToId", JS_NewCFunction(ctx, js_pem_to_id, "pemToId", 1));
    JS_SetPropertyStr(
      ctx,
      ccf,
      "refreshAppBytecodeCache",
      JS_NewCFunction(
        ctx, js_refresh_app_bytecode_cache, "refreshAppBytecodeCache", 0));

    auto crypto = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, ccf, "crypto", crypto);

    JS_SetPropertyStr(
      ctx,
      crypto,
      "verifySignature",
      JS_NewCFunction(ctx, js_verify_signature, "verifySignature", 4));

    if (txctx != nullptr)
    {
      auto kv = JS_NewObjectClass(ctx, kv_class_id);
      JS_SetOpaque(kv, txctx);
      JS_SetPropertyStr(ctx, ccf, "kv", kv);

      JS_SetPropertyStr(
        ctx,
        ccf,
        "setJwtPublicSigningKeys",
        JS_NewCFunction(
          ctx,
          js_gov_set_jwt_public_signing_keys,
          "setJwtPublicSigningKeys",
          3));
      JS_SetPropertyStr(
        ctx,
        ccf,
        "removeJwtPublicSigningKeys",
        JS_NewCFunction(
          ctx,
          js_gov_remove_jwt_public_signing_keys,
          "removeJwtPublicSigningKeys",
          1));
    }

    // Historical queries
    if (receipt != nullptr)
    {
      CCF_ASSERT(
        transaction_id.has_value(),
        "Expected receipt and transaction_id to both be passed");

      auto state = JS_NewObject(ctx);

      JS_SetPropertyStr(
        ctx,
        state,
        "transactionId",
        JS_NewString(ctx, transaction_id->to_str().c_str()));
      auto js_receipt = ccf_receipt_to_js(ctx, receipt);
      JS_SetPropertyStr(ctx, state, "receipt", js_receipt);
      auto kv = JS_NewObjectClass(ctx, kv_class_id);
      JS_SetOpaque(kv, historical_txctx);
      JS_SetPropertyStr(ctx, state, "kv", kv);
      JS_SetPropertyStr(ctx, ccf, "historicalState", state);
    }

    // Gov effects
    if (gov_effects != nullptr)
    {
      if (txctx == nullptr)
      {
        throw std::logic_error("Tx should be set to set node context");
      }

      auto node = JS_NewObjectClass(ctx, node_class_id);
      JS_SetOpaque(node, gov_effects);
      JS_SetPropertyStr(ctx, ccf, "node", node);
      JS_SetPropertyStr(
        ctx,
        node,
        "triggerLedgerRekey",
        JS_NewCFunction(
          ctx, js_node_trigger_ledger_rekey, "triggerLedgerRekey", 0));
      JS_SetPropertyStr(
        ctx,
        node,
        "transitionServiceToOpen",
        JS_NewCFunction(
          ctx,
          js_node_transition_service_to_open,
          "transitionServiceToOpen",
          2));
      JS_SetPropertyStr(
        ctx,
        node,
        "triggerRecoverySharesRefresh",
        JS_NewCFunction(
          ctx,
          js_node_trigger_recovery_shares_refresh,
          "triggerRecoverySharesRefresh",
          0));
      JS_SetPropertyStr(
        ctx,
        node,
        "triggerLedgerChunk",
        JS_NewCFunction(ctx, js_trigger_ledger_chunk, "triggerLedgerChunk", 0));
      JS_SetPropertyStr(
        ctx,
        node,
        "triggerSnapshot",
        JS_NewCFunction(ctx, js_trigger_snapshot, "triggerSnapshot", 0));
    }

    if (host_processes != nullptr)
    {
      auto host = JS_NewObjectClass(ctx, host_class_id);
      JS_SetOpaque(host, host_processes);
      JS_SetPropertyStr(ctx, ccf, "host", host);

      JS_SetPropertyStr(
        ctx,
        host,
        "triggerSubprocess",
        JS_NewCFunction(
          ctx, js_node_trigger_host_process_launch, "triggerSubprocess", 1));
    }

    if (network_state != nullptr)
    {
      if (txctx == nullptr)
      {
        throw std::logic_error("Tx should be set to set network context");
      }

      auto network = JS_NewObjectClass(ctx, network_class_id);
      JS_SetOpaque(network, network_state);
      JS_SetPropertyStr(ctx, ccf, "network", network);
      JS_SetPropertyStr(
        ctx,
        network,
        "getLatestLedgerSecretSeqno",
        JS_NewCFunction(
          ctx,
          js_network_latest_ledger_secret_seqno,
          "getLatestLedgerSecretSeqno",
          0));
      JS_SetPropertyStr(
        ctx,
        network,
        "generateEndorsedCertificate",
        JS_NewCFunction(
          ctx,
          js_network_generate_endorsed_certificate,
          "generateEndorsedCertificate",
          0));
      JS_SetPropertyStr(
        ctx,
        network,
        "generateNetworkCertificate",
        JS_NewCFunction(
          ctx,
          js_network_generate_certificate,
          "generateNetworkCertificate",
          0));
    }

    if (rpc_ctx != nullptr)
    {
      auto rpc = JS_NewObjectClass(ctx, rpc_class_id);
      JS_SetOpaque(rpc, rpc_ctx);
      JS_SetPropertyStr(ctx, ccf, "rpc", rpc);
      JS_SetPropertyStr(
        ctx,
        rpc,
        "setApplyWrites",
        JS_NewCFunction(ctx, js_rpc_set_apply_writes, "setApplyWrites", 1));
      JS_SetPropertyStr(
        ctx,
        rpc,
        "setClaimsDigest",
        JS_NewCFunction(ctx, js_rpc_set_claims_digest, "setClaimsDigest", 1));
    }

    // All high-level public helper functions are exposed through
    // ccf::BaseEndpointRegistry. Ideally, they should be
    // exposed separately.
    if (endpoint_registry != nullptr)
    {
      auto consensus = JS_NewObjectClass(ctx, consensus_class_id);
      JS_SetOpaque(consensus, endpoint_registry);
      JS_SetPropertyStr(ctx, ccf, "consensus", consensus);
      JS_SetPropertyStr(
        ctx,
        consensus,
        "getLastCommittedTxId",
        JS_NewCFunction(
          ctx,
          js_consensus_get_last_committed_txid,
          "getLastCommittedTxId",
          0));
      JS_SetPropertyStr(
        ctx,
        consensus,
        "getStatusForTxId",
        JS_NewCFunction(
          ctx, js_consensus_get_status_for_txid, "getStatusForTxId", 2));
      JS_SetPropertyStr(
        ctx,
        consensus,
        "getViewForSeqno",
        JS_NewCFunction(
          ctx, js_consensus_get_view_for_seqno, "getViewForSeqno", 1));
    }

    if (historical_state != nullptr)
    {
      auto historical = JS_NewObjectClass(ctx, historical_class_id);
      JS_SetOpaque(historical, historical_state);
      JS_SetPropertyStr(ctx, ccf, "historical", historical);
      JS_SetPropertyStr(
        ctx,
        historical,
        "getStateRange",
        JS_NewCFunction(
          ctx, js_historical_get_state_range, "getStateRange", 4));
      JS_SetPropertyStr(
        ctx,
        historical,
        "dropCachedStates",
        JS_NewCFunction(
          ctx, js_historical_drop_cached_states, "dropCachedStates", 1));
    }

    return ccf;
  }

  void populate_global_ccf(
    TxContext* txctx,
    TxContext* historical_txctx,
    ccf::RpcContext* rpc_ctx,
    const std::optional<ccf::TxID>& transaction_id,
    ccf::TxReceiptPtr receipt,
    ccf::AbstractGovernanceEffects* gov_effects,
    ccf::AbstractHostProcesses* host_processes,
    ccf::NetworkState* network_state,
    ccf::historical::AbstractStateCache* historical_state,
    ccf::BaseEndpointRegistry* endpoint_registry,
    js::Context& ctx)
  {
    auto global_obj = ctx.get_global_obj();

    JS_SetPropertyStr(
      ctx,
      global_obj,
      "ccf",
      create_ccf_obj(
        txctx,
        historical_txctx,
        rpc_ctx,
        transaction_id,
        receipt,
        gov_effects,
        host_processes,
        network_state,
        historical_state,
        endpoint_registry,
        ctx));
  }

  void populate_global(
    TxContext* txctx,
    TxContext* historical_txctx,
    ccf::RpcContext* rpc_ctx,
    const std::optional<ccf::TxID>& transaction_id,
    ccf::TxReceiptPtr receipt,
    ccf::AbstractGovernanceEffects* gov_effects,
    ccf::AbstractHostProcesses* host_processes,
    ccf::NetworkState* network_state,
    ccf::historical::AbstractStateCache* historical_state,
    ccf::BaseEndpointRegistry* endpoint_registry,
    js::Context& ctx)
  {
    populate_global_console(ctx);
    populate_global_ccf(
      txctx,
      historical_txctx,
      rpc_ctx,
      transaction_id,
      receipt,
      gov_effects,
      host_processes,
      network_state,
      historical_state,
      endpoint_registry,
      ctx);

    for (auto& plugin : ffi_plugins)
    {
      plugin.extend(ctx);
    }
  }

  void Runtime::add_ccf_classdefs()
  {
    std::vector<std::pair<JSClassID, JSClassDef*>> classes{
      {kv_class_id, &kv_class_def},
      {kv_map_handle_class_id, &kv_map_handle_class_def},
      {body_class_id, &body_class_def},
      {node_class_id, &node_class_def},
      {network_class_id, &network_class_def},
      {rpc_class_id, &rpc_class_def},
      {host_class_id, &host_class_def},
      {consensus_class_id, &consensus_class_def},
      {historical_class_id, &historical_class_def},
      {historical_state_class_id, &historical_state_class_def}};
    for (auto [class_id, class_def] : classes)
    {
      auto ret = JS_NewClass(rt, class_id, class_def);
      if (ret != 0)
        throw std::logic_error(fmt::format(
          "Failed to register JS class definition {}", class_def->class_name));
    }
  }

#pragma clang diagnostic pop
}
