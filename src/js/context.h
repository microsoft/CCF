// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/locking.h"
#include "js/tx_access.h"
#include "runtime.h"
#include "wrapped_value.h"

#include <chrono>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>

// NB: Only required while globals is public
#include "ccf/tx.h"
#include "kv/untyped_map.h"

// Forward declarations
namespace ccf
{
  class AbstractGovernanceEffects;
  class AbstractHostProcesses;
  struct NetworkState;
  class RpcContext;
  class BaseEndpointRegistry;

  namespace historical
  {
    class AbstractStateCache;
    struct State;

    using StatePtr = std::shared_ptr<State>;
  }
}

namespace ccf::js
{
  struct InterruptData
  {
    std::chrono::microseconds start_time;
    std::chrono::milliseconds max_execution_time;
    ccf::js::TxAccess access;
    bool request_timed_out = false;
  };

  class Context
  {
  private:
    JSContext* ctx;
    Runtime rt;

    // The interpreter can cache loaded modules so they do not need to be loaded
    // from the KV for every execution, which is particularly useful when
    // re-using interpreters. A module can only be loaded once per interpreter,
    // and the entire interpreter should be thrown away if _any_ of its modules
    // needs to be refreshed.
    std::map<std::string, JSWrappedValue> loaded_modules_cache;

  public:
    // NB: This should really be hidden as an implementation detail
    // State which may be set by calls to populate_global_ccf_*. Likely
    // references transaction-scoped entries, so should be cleared between
    // calls. Retained handles to these globals must not access the previous
    // values.
    struct
    {
      kv::Tx* tx = nullptr;
      std::unordered_map<std::string, kv::untyped::Map::Handle*> kv_handles;

      struct HistoricalHandle
      {
        ccf::historical::StatePtr state;
        std::unique_ptr<kv::ReadOnlyTx> tx;
        std::unordered_map<std::string, kv::untyped::Map::ReadOnlyHandle*>
          kv_handles = {};
      };
      std::unordered_map<ccf::SeqNo, HistoricalHandle> historical_handles;

      ccf::RpcContext* rpc_ctx = nullptr;

      const std::vector<uint8_t>* current_request_body = nullptr;
    } globals;

    ccf::pal::Mutex lock;

    const TxAccess access;
    InterruptData interrupt_data;
    bool implement_untrusted_time = false;
    bool log_execution_metrics = true;

    Context(TxAccess acc);

    ~Context();

    // Delete copy and assignment operators, since this assumes sole ownership
    // of underlying rt and ctx
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

    Runtime& runtime()
    {
      return rt;
    }

    operator JSContext*() const
    {
      return ctx;
    }

    std::optional<JSWrappedValue> get_module_from_cache(
      const std::string& module_name);
    void load_module_to_cache(
      const std::string& module_name, const JSWrappedValue& module);

    JSWrappedValue wrap(JSValue&& val) const;
    JSWrappedValue wrap(const JSValue& x) const;

    JSWrappedValue get_property(
      JSValue object, char const* property_name) const;

    JSWrappedValue new_obj() const;
    JSWrappedValue new_obj_class(JSClassID class_id) const;
    JSWrappedValue get_global_obj() const;
    JSWrappedValue get_global_property(const char* s) const;
    JSValue get_string_array(JSValueConst& argv, std::vector<std::string>& out);
    JSWrappedValue json_stringify(const JSWrappedValue& obj) const;
    JSWrappedValue new_array() const;
    JSWrappedValue new_array_buffer(
      uint8_t* buf,
      size_t len,
      JSFreeArrayBufferDataFunc* free_func,
      void* opaque,
      bool is_shared) const;
    JSWrappedValue new_array_buffer_copy(
      const uint8_t* buf, size_t buf_len) const;
    JSWrappedValue new_array_buffer_copy(const char* buf, size_t buf_len) const;
    JSWrappedValue new_array_buffer_copy(std::span<const uint8_t> data) const;
    JSWrappedValue new_string(const std::string& str) const;
    JSWrappedValue new_string(const char* str) const;
    JSWrappedValue new_string_len(const char* buf, size_t buf_len) const;
    JSWrappedValue new_type_error(const char* fmt, ...) const;
    JSValue new_internal_error(const char* fmt, ...) const;
    JSWrappedValue new_tag_value(int tag, int32_t val = 0) const;

    JSWrappedValue duplicate_value(JSValueConst original) const;

    JSWrappedValue null() const;
    JSWrappedValue undefined() const;
    JSWrappedValue new_c_function(
      JSCFunction* func, const char* name, int length) const;
    JSWrappedValue new_getter_c_function(
      JSCFunction* func, const char* name) const;
    JSWrappedValue eval(
      const char* input,
      size_t input_len,
      const char* filename,
      int eval_flags) const;
    JSWrappedValue eval_function(const JSWrappedValue& module) const;

    JSWrappedValue default_function(
      const std::string& code, const std::string& path);

    JSWrappedValue function(
      const std::string& code,
      const std::string& func,
      const std::string& path);

    JSWrappedValue function(
      const JSWrappedValue& module,
      const std::string& func,
      const std::string& path);

    JSWrappedValue get_module_export_entry(JSModuleDef* m, int idx) const;
    JSWrappedValue read_object(
      const uint8_t* buf, size_t buf_len, int flags) const;
    JSWrappedValue get_exception() const;

    JSWrappedValue call_with_rt_options(
      const JSWrappedValue& f,
      const std::vector<js::JSWrappedValue>& argv,
      kv::Tx* tx,
      RuntimeLimitsPolicy policy);

    // Call a JS function _without_ any stack, heap or execution time limits.
    // Only to be used, as the name indicates, for calls inside an already
    // invoked JS function, where the caller has already set up the necessary
    // limits.
    JSWrappedValue inner_call(
      const JSWrappedValue& f, const std::vector<js::JSWrappedValue>& argv);

    JSWrappedValue parse_json(const nlohmann::json& j) const;
    JSWrappedValue parse_json(
      const char* buf, size_t buf_len, const char* filename) const;
    JSWrappedValue get_typed_array_buffer(
      const JSWrappedValue& obj,
      size_t* pbyte_offset,
      size_t* pbyte_length,
      size_t* pbytes_per_element) const;
    std::optional<std::string> to_str(const JSWrappedValue& x) const;
    std::optional<std::string> to_str(const JSValue& x) const;
    std::optional<std::string> to_str(const JSValue& x, size_t& len) const;
    std::optional<std::string> to_str(const JSAtom& atom) const;

    // Reset any state that has been stored on the ctx object to implement
    // globals. This should be called at the end of any invocation where the
    // globals may point to locally-scoped memory, and the Context itself (the
    // interpreter) may live longer and be reused for future calls. Those calls
    // must re-populate the globals appropriately, pointing to their own local
    // instances of state as required.
    void invalidate_globals();

    void populate_global_ccf_kv(kv::Tx& tx);
    void populate_global_ccf_node(ccf::AbstractGovernanceEffects* gov_effects);
    void populate_global_ccf_host(ccf::AbstractHostProcesses* host_processes);
    void populate_global_ccf_network(ccf::NetworkState* network_state);
    void populate_global_ccf_rpc(ccf::RpcContext* rpc_ctx);
    void populate_global_ccf_consensus(
      ccf::BaseEndpointRegistry* endpoint_registry);
    void populate_global_ccf_historical(
      ccf::historical::AbstractStateCache* historical_state);
    void populate_global_ccf_gov_actions();

    void register_request_body_class();

    JSValue create_historical_state_object(ccf::historical::StatePtr state);

    std::pair<std::string, std::optional<std::string>> error_message();
  };
}
