// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/locking.h"
#include "js/core/runtime.h"
#include "js/core/wrapped_value.h"
#include "js/extensions/extension_interface.h"
#include "js/tx_access.h"

#include <chrono>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>

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

namespace ccf::js::core
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

    js::extensions::Extensions extensions;

  public:
    ccf::pal::Mutex lock;

    const TxAccess access;
    InterruptData interrupt_data;
    bool implement_untrusted_time = false;
    bool log_execution_metrics = true;

    Context(TxAccess acc);

    virtual ~Context();

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

    // Construct RAII wrapper around raw QuickJS value
    JSWrappedValue wrap(JSValue&& val) const;
    JSWrappedValue wrap(const JSValue& x) const;

    // If the first argument is a string-array, populates the second, and
    // returns undefined. Otherwise returns a JS error value.
    JSValue extract_string_array(
      JSValueConst& argv, std::vector<std::string>& out);

    std::pair<std::string, std::optional<std::string>> error_message();

    // Getters
    JSWrappedValue get_property(
      JSValue object, char const* property_name) const;
    JSWrappedValue get_global_obj() const;
    JSWrappedValue get_global_property(const char* s) const;
    JSWrappedValue get_or_create_global_property(
      const char* s, JSWrappedValue default_value) const;
    JSWrappedValue get_typed_array_buffer(
      const JSWrappedValue& obj,
      size_t* pbyte_offset,
      size_t* pbyte_length,
      size_t* pbytes_per_element) const;
    JSWrappedValue get_exported_function(
      const std::string& code,
      const std::string& func,
      const std::string& path);
    JSWrappedValue get_exported_function(
      const JSWrappedValue& module,
      const std::string& func,
      const std::string& path);

    // Constant values
    JSWrappedValue null() const;
    JSWrappedValue undefined() const;

    // Construct new values
    JSWrappedValue new_obj() const;
    JSWrappedValue new_obj_class(JSClassID class_id) const;
    JSWrappedValue new_array() const;
    JSWrappedValue new_array_buffer_copy(
      const uint8_t* buf, size_t buf_len) const;
    JSWrappedValue new_array_buffer_copy(const char* buf, size_t buf_len) const;
    JSWrappedValue new_array_buffer_copy(std::span<const uint8_t> data) const;
    JSWrappedValue new_string(const std::string_view& str) const;
    JSWrappedValue new_string_len(const char* buf, size_t buf_len) const;
    JSWrappedValue new_string_len(const std::span<const uint8_t> buf) const;
    JSWrappedValue new_type_error(const char* fmt, ...) const;
    JSWrappedValue new_internal_error(const char* fmt, ...) const;
    JSWrappedValue new_tag_value(int tag, int32_t val = 0) const;
    JSWrappedValue new_c_function(
      JSCFunction* func, const char* name, int length) const;
    JSWrappedValue new_getter_c_function(
      JSCFunction* func, const char* name) const;

    JSWrappedValue duplicate_value(JSValueConst original) const;

    JSWrappedValue eval(
      const char* input,
      size_t input_len,
      const char* filename,
      int eval_flags) const;
    JSWrappedValue read_object(
      const uint8_t* buf, size_t buf_len, int flags) const;

    JSWrappedValue call_with_rt_options(
      const JSWrappedValue& f,
      const std::vector<JSWrappedValue>& argv,
      kv::Tx* tx,
      RuntimeLimitsPolicy policy);

    // Call a JS function _without_ any stack, heap or execution time limits.
    // Only to be used, as the name indicates, for calls inside an already
    // invoked JS function, where the caller has already set up the necessary
    // limits.
    JSWrappedValue inner_call(
      const JSWrappedValue& f, const std::vector<JSWrappedValue>& argv);

    // JSON I/O
    JSWrappedValue json_stringify(const JSWrappedValue& obj) const;
    JSWrappedValue parse_json(const nlohmann::json& j) const;
    JSWrappedValue parse_json(
      const char* buf, size_t buf_len, const char* filename) const;

    // Convert objects to string
    std::optional<std::string> to_str(const JSWrappedValue& x) const;
    std::optional<std::string> to_str(const JSValue& x) const;
    std::optional<std::string> to_str(const JSValue& x, size_t& len) const;
    std::optional<std::string> to_str(const JSAtom& atom) const;

    void add_extension(const js::extensions::ExtensionPtr& extension);
    bool remove_extension(const js::extensions::ExtensionPtr& extension);

    template <typename TExtension>
    TExtension* get_extension()
    {
      for (auto& extension : extensions)
      {
        if (TExtension* t = dynamic_cast<TExtension*>(extension.get());
            t != nullptr)
        {
          return t;
        }
      }

      return nullptr;
    }
  };
}
