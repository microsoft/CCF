// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/pal/locking.h"
#include "enclave/enclave_time.h"
#include "js/core/runtime.h"
#include "js/core/wrapped_value.h"
#include "js/globals/ccf/consensus.h"
#include "js/globals/ccf/historical.h"
#include "js/globals/ccf/host.h"
#include "js/globals/ccf/network.h"
#include "js/globals/ccf/node.h"
#include "js/globals/ccf/rpc.h"
#include "js/globals/init.h"
#include "js/tx_access.h"

#include <chrono>
#include <quickjs/quickjs.h>

namespace ccf::js::core
{
  Context::Context(TxAccess acc) : access(acc)
  {
    ctx = JS_NewContext(rt);
    if (ctx == nullptr)
    {
      throw std::runtime_error("Failed to initialise QuickJS context");
    }
    JS_SetContextOpaque(ctx, this);

    globals::init_globals(*this);
  }

  Context::~Context()
  {
    JS_SetInterruptHandler(JS_GetRuntime(ctx), NULL, NULL);
    JS_FreeContext(ctx);
  }

  std::optional<JSWrappedValue> Context::get_module_from_cache(
    const std::string& module_name)
  {
    auto module = loaded_modules_cache.find(module_name);
    if (module == loaded_modules_cache.end())
    {
      return std::nullopt;
    }

    return module->second;
  }

  void Context::load_module_to_cache(
    const std::string& module_name, const JSWrappedValue& module)
  {
    if (get_module_from_cache(module_name).has_value())
    {
      throw std::logic_error(fmt::format(
        "Module '{}' is already loaded in interpreter cache", module_name));
    }
    loaded_modules_cache[module_name] = module;
  }

  JSWrappedValue Context::wrap(JSValue&& val) const
  {
    return JSWrappedValue(ctx, std::move(val));
  };

  JSWrappedValue Context::wrap(const JSValue& val) const
  {
    return JSWrappedValue(ctx, val);
  };

  JSWrappedValue Context::get_property(
    JSValue object, char const* property_name) const
  {
    return wrap(JS_GetPropertyStr(ctx, object, property_name));
  }

  JSWrappedValue Context::new_obj() const
  {
    return wrap(JS_NewObject(ctx));
  }

  JSWrappedValue Context::new_obj_class(JSClassID class_id) const
  {
    return wrap(JS_NewObjectClass(ctx, class_id));
  }

  JSWrappedValue Context::get_global_obj() const
  {
    return wrap(JS_GetGlobalObject(ctx));
  }

  JSWrappedValue Context::get_global_property(const char* s) const
  {
    auto g = Context::get_global_obj();
    return wrap(JS_GetPropertyStr(ctx, g.val, s));
  }

  JSValue Context::get_string_array(
    JSValueConst& argv, std::vector<std::string>& out)
  {
    auto args = wrap(argv);

    if (!JS_IsArray(ctx, argv))
    {
      return JS_ThrowTypeError(ctx, "First argument must be an array");
    }

    auto len_val = args["length"];
    uint32_t len = 0;
    if (JS_ToUint32(ctx, &len, len_val.val))
    {
      return ccf::js::core::constants::Exception;
    }

    if (len == 0)
    {
      return JS_ThrowRangeError(
        ctx, "First argument must be a non-empty array");
    }

    for (uint32_t i = 0; i < len; i++)
    {
      auto arg_val = args[i];
      if (!arg_val.is_str())
      {
        return JS_ThrowTypeError(
          ctx, "First argument must be an array of strings, found non-string");
      }
      auto s = to_str(arg_val);
      if (!s)
      {
        return JS_ThrowTypeError(
          ctx, "Failed to extract C string from JS string at position %d", i);
      }
      out.push_back(*s);
    }

    return ccf::js::core::constants::Undefined;
  }

  JSWrappedValue Context::json_stringify(const JSWrappedValue& obj) const
  {
    return wrap(JS_JSONStringify(
      ctx,
      obj.val,
      ccf::js::core::constants::Null,
      ccf::js::core::constants::Null));
  }

  JSWrappedValue Context::new_array() const
  {
    return wrap(JS_NewArray(ctx));
  }

  JSWrappedValue Context::new_array_buffer(
    uint8_t* buf,
    size_t len,
    JSFreeArrayBufferDataFunc* free_func,
    void* opaque,
    bool is_shared) const
  {
    return JSWrappedValue(
      ctx,
      JS_NewArrayBuffer(ctx, (uint8_t*)buf, len, free_func, opaque, is_shared));
  }

  JSWrappedValue Context::new_array_buffer_copy(
    const uint8_t* buf, size_t buf_len) const
  {
    return wrap(JS_NewArrayBufferCopy(ctx, buf, buf_len));
  }

  JSWrappedValue Context::new_array_buffer_copy(
    const char* buf, size_t buf_len) const
  {
    return JSWrappedValue(
      ctx, JS_NewArrayBufferCopy(ctx, (uint8_t*)buf, buf_len));
  }

  JSWrappedValue Context::new_array_buffer_copy(
    std::span<const uint8_t> data) const
  {
    return JSWrappedValue(
      ctx, JS_NewArrayBufferCopy(ctx, data.data(), data.size()));
  }

  JSWrappedValue Context::new_string(const std::string& str) const
  {
    return wrap(JS_NewStringLen(ctx, str.data(), str.size()));
  }

  JSWrappedValue Context::new_string(const char* str) const
  {
    return wrap(JS_NewString(ctx, str));
  }

  JSWrappedValue Context::new_string_len(const char* buf, size_t buf_len) const
  {
    return wrap(JS_NewStringLen(ctx, buf, buf_len));
  }

  JSWrappedValue Context::new_type_error(const char* fmt, ...) const
  {
    va_list ap;
    va_start(ap, fmt);
    auto r = wrap(JS_ThrowTypeError(ctx, fmt, ap));
    va_end(ap);
    return r;
  }

  JSValue Context::new_internal_error(const char* fmt, ...) const
  {
    va_list ap;
    va_start(ap, fmt);
    auto r = JS_ThrowInternalError(ctx, fmt, ap);
    va_end(ap);
    return r;
  }

  JSWrappedValue Context::new_tag_value(int tag, int32_t val) const
  {
// "compound literals are a C99-specific feature"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
    return wrap((JSValue){(JSValueUnion){.int32 = val}, tag});
#pragma clang diagnostic pop
  }

  JSWrappedValue Context::duplicate_value(JSValueConst original) const
  {
    return wrap(JS_DupValue(ctx, original));
  }

  JSWrappedValue Context::null() const
  {
    return wrap(ccf::js::core::constants::Null);
  }

  JSWrappedValue Context::undefined() const
  {
    return wrap(ccf::js::core::constants::Undefined);
  }

  JSWrappedValue Context::new_c_function(
    JSCFunction* func, const char* name, int length) const
  {
    return wrap(JS_NewCFunction(ctx, func, name, length));
  }

  JSWrappedValue Context::new_getter_c_function(
    JSCFunction* func, const char* name) const
  {
    return wrap(JS_NewCFunction2(
      ctx, func, name, 0, JS_CFUNC_getter, JS_CFUNC_getter_magic));
  }

  JSWrappedValue Context::eval(
    const char* input,
    size_t input_len,
    const char* filename,
    int eval_flags) const
  {
    return wrap(JS_Eval(ctx, input, input_len, filename, eval_flags));
  }

  JSWrappedValue Context::eval_function(const JSWrappedValue& module) const
  {
    return wrap(JS_EvalFunction(ctx, module.val));
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

    if (module.is_exception())
    {
      throw std::runtime_error(fmt::format("Failed to compile {}", path));
    }

    return function(module, func, path);
  }

  JSWrappedValue Context::function(
    const JSWrappedValue& module,
    const std::string& func,
    const std::string& path)
  {
    auto eval_val = eval_function(module);

    if (eval_val.is_exception())
    {
      auto [reason, trace] = error_message();

      if (rt.log_exception_details)
      {
        CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
      }
      throw std::runtime_error(
        fmt::format("Failed to execute {}: {}", path, reason));
    }

    // Get exported function from module
    assert(JS_VALUE_GET_TAG(module.val) == JS_TAG_MODULE);
    auto module_def = (JSModuleDef*)JS_VALUE_GET_PTR(module.val);
    auto export_count = JS_GetModuleExportEntriesCount(module_def);
    for (auto i = 0; i < export_count; i++)
    {
      auto export_name_atom = JS_GetModuleExportEntryName(ctx, module_def, i);
      auto export_name = to_str(export_name_atom);
      JS_FreeAtom(ctx, export_name_atom);
      if (export_name.value_or("") == func)
      {
        auto export_func = get_module_export_entry(module_def, i);
        if (!JS_IsFunction(ctx, export_func.val))
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

  JSWrappedValue Context::inner_call(
    const JSWrappedValue& f, const std::vector<JSWrappedValue>& argv)
  {
    std::vector<JSValue> argvn;
    argvn.reserve(argv.size());
    for (auto& a : argv)
    {
      argvn.push_back(a.val);
    }

    return wrap(JS_Call(
      ctx,
      f.val,
      ccf::js::core::constants::Undefined,
      argv.size(),
      argvn.data()));
  }

  JSWrappedValue Context::get_module_export_entry(JSModuleDef* m, int idx) const
  {
    return wrap(JS_GetModuleExportEntry(ctx, m, idx));
  }

  JSWrappedValue Context::read_object(
    const uint8_t* buf, size_t buf_len, int flags) const
  {
    return wrap(JS_ReadObject(ctx, buf, buf_len, flags));
  }

  JSWrappedValue Context::get_exception() const
  {
    return wrap(JS_GetException(ctx));
  }

  JSWrappedValue Context::parse_json(const nlohmann::json& j) const
  {
    const auto buf = j.dump();
    return wrap(JS_ParseJSON(ctx, buf.data(), buf.size(), "<json>"));
  }

  JSWrappedValue Context::parse_json(
    const char* buf, size_t buf_len, const char* filename) const
  {
    return wrap(JS_ParseJSON(ctx, buf, buf_len, filename));
  }

  JSWrappedValue Context::get_typed_array_buffer(
    const JSWrappedValue& obj,
    size_t* pbyte_offset,
    size_t* pbyte_length,
    size_t* pbytes_per_element) const
  {
    return wrap(JS_GetTypedArrayBuffer(
      ctx, obj.val, pbyte_offset, pbyte_length, pbytes_per_element));
  }

  std::optional<std::string> Context::to_str(const JSWrappedValue& x) const
  {
    auto val = JS_ToCString(ctx, x.val);
    if (!val)
    {
      new_type_error("value is not a string");
      return std::nullopt;
    }
    std::string r(val);
    JS_FreeCString(ctx, val);
    return r;
  }

  std::optional<std::string> Context::to_str(const JSValue& x) const
  {
    auto val = JS_ToCString(ctx, x);
    if (!val)
    {
      new_type_error("value is not a string");
      return std::nullopt;
    }
    std::string r(val);
    JS_FreeCString(ctx, val);
    return r;
  }

  std::optional<std::string> Context::to_str(
    const JSValue& x, size_t& len) const
  {
    auto val = JS_ToCStringLen(ctx, &len, x);
    if (!val)
    {
      new_type_error("value is not a string");
      return std::nullopt;
    }
    std::string r(val);
    JS_FreeCString(ctx, val);
    return r;
  }

  std::optional<std::string> Context::to_str(const JSAtom& atom) const
  {
    auto val = JS_AtomToCString(ctx, atom);
    if (!val)
    {
      new_type_error("atom is not a string");
      return std::nullopt;
    }
    std::string r(val);
    JS_FreeCString(ctx, val);
    return r;
  }

  static int js_custom_interrupt_handler(JSRuntime* rt, void* opaque)
  {
    InterruptData* inter = reinterpret_cast<InterruptData*>(opaque);
    auto now = ccf::get_enclave_time();
    auto elapsed_time = now - inter->start_time;
    auto elapsed_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_time);
    if (elapsed_ms.count() >= inter->max_execution_time.count())
    {
      globals::log_info_with_tag(
        inter->access,
        fmt::format(
          "JS execution has timed out after {}ms (max is {}ms)",
          elapsed_ms.count(),
          inter->max_execution_time.count()));
      inter->request_timed_out = true;
      return 1;
    }
    else
    {
      return 0;
    }
  }

  JSWrappedValue Context::call_with_rt_options(
    const JSWrappedValue& f,
    const std::vector<JSWrappedValue>& argv,
    kv::Tx* tx,
    RuntimeLimitsPolicy policy)
  {
    rt.set_runtime_options(tx, policy);
    const auto curr_time = ccf::get_enclave_time();
    interrupt_data.start_time = curr_time;
    interrupt_data.max_execution_time = rt.get_max_exec_time();
    JS_SetInterruptHandler(rt, js_custom_interrupt_handler, &interrupt_data);

    auto rv = inner_call(f, argv);

    rt.reset_runtime_options();

    return rv;
  }

  void Context::invalidate_globals()
  {
    globals.tx = nullptr;

    // Any KV handles which have been created with reference to this tx should
    // no longer be accessed. Any future calls on these JSValues will
    // re-populate this map with fresh KVMap::Handle*s
    globals.kv_handles.clear();

    globals.historical_handles.clear();

    globals.rpc_ctx = nullptr;
  }

  void Context::populate_global_ccf_kv(kv::Tx& tx)
  {
    auto kv = new_obj_class(kv_class_id);
    globals.tx = &tx;

    auto ccf = get_global_property("ccf");
    ccf.set("kv", std::move(kv));
  }

  void Context::populate_global_ccf_node(
    ccf::AbstractGovernanceEffects* gov_effects)
  {
    auto node = create_global_node_object(gov_effects, ctx);
    auto ccf = get_global_property("ccf");
    ccf.set("node", std::move(node));
  }

  void Context::populate_global_ccf_host(
    ccf::AbstractHostProcesses* host_processes)
  {
    auto host = create_global_host_object(host_processes, ctx);
    auto ccf = get_global_property("ccf");
    ccf.set("host", std::move(host));
  }

  void Context::populate_global_ccf_network(ccf::NetworkState* network_state)
  {
    auto network = create_global_network_object(network_state, ctx);
    auto ccf = get_global_property("ccf");
    ccf.set("network", std::move(network));
  }

  void Context::populate_global_ccf_rpc(ccf::RpcContext* rpc_ctx)
  {
    auto rpc = create_global_rpc_object(rpc_ctx, ctx);
    globals.rpc_ctx = rpc_ctx;
    auto ccf = get_global_property("ccf");
    ccf.set("rpc", std::move(rpc));
  }

  void Context::populate_global_ccf_consensus(
    ccf::BaseEndpointRegistry* endpoint_registry)
  {
    auto consensus = create_global_consensus_object(endpoint_registry, ctx);
    auto ccf = get_global_property("ccf");
    ccf.set("consensus", std::move(consensus));
  }

  void Context::populate_global_ccf_historical(
    ccf::historical::AbstractStateCache* historical_state)
  {
    auto historical = create_global_historical_object(historical_state, ctx);
    auto ccf = get_global_property("ccf");
    ccf.set("historical", std::move(historical));
  }

  void Context::populate_global_ccf_gov_actions()
  {
    globals::extend_ccf_object_with_gov_actions(*this);
  }

  static JSValue ccf_receipt_to_js(Context& jsctx, TxReceiptImplPtr receipt)
  {
    ccf::ReceiptPtr receipt_out_p = ccf::describe_receipt_v2(*receipt);
    auto& receipt_out = *receipt_out_p;
    auto js_receipt = jsctx.new_obj();
    JS_CHECK_EXC(js_receipt);

    std::string sig_b64;
    try
    {
      sig_b64 = crypto::b64_from_raw(receipt_out.signature);
    }
    catch (const std::exception& e)
    {
      return jsctx.new_internal_error(
        "Failed to convert signature to base64: %s", e.what());
    }
    auto sig_string = jsctx.new_string(sig_b64.c_str());
    JS_CHECK_EXC(sig_string);
    JS_CHECK_SET(js_receipt.set("signature", std::move(sig_string)));

    auto js_cert = jsctx.new_string(receipt_out.cert.str().c_str());
    JS_CHECK_EXC(js_cert);
    JS_CHECK_SET(js_receipt.set("cert", std::move(js_cert)));

    auto js_node_id = jsctx.new_string(receipt_out.node_id.value().c_str());
    JS_CHECK_EXC(js_node_id);
    JS_CHECK_SET(js_receipt.set("node_id", std::move(js_node_id)));
    bool is_signature_transaction = receipt_out.is_signature_transaction();
    JS_CHECK_SET(js_receipt.set_bool(
      "is_signature_transaction", is_signature_transaction));

    if (!is_signature_transaction)
    {
      auto p_receipt =
        std::dynamic_pointer_cast<ccf::ProofReceipt>(receipt_out_p);
      auto leaf_components = jsctx.new_obj();
      JS_CHECK_EXC(leaf_components);

      const auto wsd_hex =
        ds::to_hex(p_receipt->leaf_components.write_set_digest.h);

      auto js_wsd = jsctx.new_string(wsd_hex.c_str());
      JS_CHECK_EXC(js_wsd);
      JS_CHECK_SET(leaf_components.set("write_set_digest", std::move(js_wsd)));

      auto js_commit_evidence =
        jsctx.new_string(p_receipt->leaf_components.commit_evidence.c_str());
      JS_CHECK_EXC(js_commit_evidence);
      JS_CHECK_SET(
        leaf_components.set("commit_evidence", std::move(js_commit_evidence)));

      if (!p_receipt->leaf_components.claims_digest.empty())
      {
        const auto cd_hex =
          ds::to_hex(p_receipt->leaf_components.claims_digest.value().h);

        auto js_cd = jsctx.new_string(cd_hex.c_str());
        JS_CHECK_EXC(js_cd);
        JS_CHECK_SET(leaf_components.set("claims_digest", std::move(js_cd)));
      }
      JS_CHECK_SET(
        js_receipt.set("leaf_components", std::move(leaf_components)));

      auto proof = jsctx.new_array();
      JS_CHECK_EXC(proof);

      uint32_t i = 0;
      for (auto& element : p_receipt->proof)
      {
        auto js_element = jsctx.new_obj();
        JS_CHECK_EXC(js_element);

        auto is_left = element.direction == ccf::ProofReceipt::ProofStep::Left;
        const auto hash_hex = ds::to_hex(element.hash.h);

        auto js_hash = jsctx.new_string(hash_hex.c_str());
        JS_CHECK_EXC(js_hash);
        JS_CHECK_SET(
          js_element.set(is_left ? "left" : "right", std::move(js_hash)));
        JS_CHECK_SET(proof.set_at_index(i++, std::move(js_element)));
      }
      JS_CHECK_SET(js_receipt.set("proof", std::move(proof)));
    }
    else
    {
      auto sig_receipt =
        std::dynamic_pointer_cast<ccf::SignatureReceipt>(receipt_out_p);
      const auto signed_root = sig_receipt->signed_root;
      const auto root_hex = ds::to_hex(signed_root.h);
      auto js_root_hex = jsctx.new_string(root_hex.c_str());
      JS_CHECK_EXC(js_root_hex);
      JS_CHECK_SET(js_receipt.set("root_hex", std::move(js_root_hex)));
    }

    return js_receipt.take();
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

    Context& jsctx = *(Context*)JS_GetContextOpaque(ctx);
    auto body = jsctx.globals.current_request_body;
    if (body == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No request body set");
    }

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

    Context& jsctx = *(Context*)JS_GetContextOpaque(ctx);
    auto body = jsctx.globals.current_request_body;
    if (body == nullptr)
    {
      return JS_ThrowTypeError(ctx, "No request body set");
    }

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

    Context& jsctx = *(Context*)JS_GetContextOpaque(ctx);
    auto body = jsctx.globals.current_request_body;
    if (body == nullptr)
    {
      return JS_ThrowTypeError(ctx, "No request body set");
    }

    auto body_ = JS_NewArrayBufferCopy(ctx, body->data(), body->size());
    return body_;
  }

// "mixture of designated and non-designated initializers in the same
// initializer list is a C99 extension"
// Used heavily by QuickJS, including in macros (such as JS_CFUNC_DEF) repeated
// here
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
  // Partially replicates https://developer.mozilla.org/en-US/docs/Web/API/Body
  // with a synchronous interface.
  static const JSCFunctionListEntry js_body_proto_funcs[] = {
    JS_CFUNC_DEF("text", 0, js_body_text),
    JS_CFUNC_DEF("json", 0, js_body_json),
    JS_CFUNC_DEF("arrayBuffer", 0, js_body_array_buffer),
  };
#pragma clang diagnostic pop

  void Context::register_request_body_class()
  {
    // Set prototype for request body class
    JSValue body_proto = JS_NewObject(ctx);
    size_t func_count =
      sizeof(js_body_proto_funcs) / sizeof(js_body_proto_funcs[0]);
    JS_SetPropertyFunctionList(
      ctx, body_proto, js_body_proto_funcs, func_count);
    JS_SetClassProto(ctx, body_class_id, body_proto);
  }

  JSValue Context::create_historical_state_object(
    ccf::historical::StatePtr state)
  {
    auto js_state = new_obj_class(historical_state_class_id);
    JS_CHECK_EXC(js_state);

    const auto transaction_id = state->transaction_id;
    auto transaction_id_s = new_string(transaction_id.to_str());
    JS_CHECK_EXC(transaction_id_s);
    JS_CHECK_SET(js_state.set("transactionId", std::move(transaction_id_s)));

    // NB: ccf_receipt_to_js returns a JSValue (unwrapped), due to its use of
    // macros. So we must rewrap it here, immediately after returning
    auto js_receipt = wrap(ccf_receipt_to_js(*this, state->receipt));
    JS_CHECK_EXC(js_receipt);
    JS_CHECK_SET(js_state.set("receipt", std::move(js_receipt)));

    auto kv = new_obj_class(kv_historical_class_id);
    JS_CHECK_EXC(kv);
    JS_SetOpaque(kv.val, reinterpret_cast<void*>(transaction_id.seqno));
    JS_CHECK_SET(js_state.set("kv", std::move(kv)));

    try
    {
      // Create a tx which will be used to access this state
      auto tx = state->store->create_read_only_tx_ptr();
      // Extend lifetime of state and tx, by storing on the ctx
      globals.historical_handles[transaction_id.seqno] = {state, std::move(tx)};
    }
    catch (const std::exception& e)
    {
      return new_internal_error(
        "Failed to create read-only historical tx: %s", e.what());
    }

    return js_state.take();
  }

  std::pair<std::string, std::optional<std::string>> Context::error_message()
  {
    auto exception_val = get_exception();
    std::optional<std::string> message;
    bool is_error = exception_val.is_error();
    if (!is_error && exception_val.is_obj())
    {
      auto rval = json_stringify(exception_val);
      message = to_str(rval);
    }
    else
    {
      message = to_str(exception_val);
    }

    std::optional<std::string> trace = std::nullopt;
    if (is_error)
    {
      auto val = exception_val["stack"];
      if (!val.is_undefined())
      {
        trace = to_str(val);
      }
    }
    return {message.value_or(""), trace};
  }
}

extern "C"
{
  int qjs_gettimeofday(struct JSContext* ctx, struct timeval* tv, void* tz)
  {
    if (tv != NULL)
    {
      // Opaque may be null, when this is called during Context construction
      const ccf::js::core::Context* jsctx =
        (ccf::js::core::Context*)JS_GetContextOpaque(ctx);
      if (jsctx != nullptr && jsctx->implement_untrusted_time)
      {
        const auto microseconds_since_epoch = ccf::get_enclave_time();
        tv->tv_sec = std::chrono::duration_cast<std::chrono::seconds>(
                       microseconds_since_epoch)
                       .count();
        tv->tv_usec = microseconds_since_epoch.count() % std::micro::den;
      }
      else
      {
        memset(tv, 0, sizeof(struct timeval));
      }
    }
    return 0;
  }
}
