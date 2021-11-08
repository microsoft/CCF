// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define V8_CC_MSVC 0
#include "v8.h"
#include "libplatform/libplatform.h"

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <optional>

namespace ccf
{
  /**
   * Initialize V8. Must be called exactly once, before
   * creating instances of this class.
   */
  void v8_initialize();

  /**
   * Shutdown V8. Must be called exactly once, after
   * destroying all instances of this class.
   */
  void v8_shutdown();

  /*
   * A V8 isolate, representing a VM instance.
   * An instance cannot be used from multiple threads.
   */
  class V8Isolate
  {
  public:
    V8Isolate();
    ~V8Isolate();
    v8::Isolate* GetIsolate() { return isolate_; }

  private:
    v8::Isolate* isolate_;
  };

  /**
   * A V8 Context, to be used for a single call/request only.
   */
  class V8Context
  {
  public:
    using ModuleLoadCallback =
      std::function<std::optional<std::string>(const std::string&, void*)>;

    V8Context(V8Isolate& isolate);
    ~V8Context();

    /**
     * Return the V8 Context.
     * The context can be used to install additional globals.
     */
    v8::Local<v8::Context> get_context()
    {
      return v8::Local<v8::Context>::New(isolate_, context_);
    }

    /** 
     * Must be called before run().
     */
    void set_module_load_callback(ModuleLoadCallback callback, void* data);

    // TODO allow function arguments to be passed in
    // TODO allow to compile-only for validation purposes
    void run(
      const std::string& module_name,
      const std::string& exported_function_name);
  
  private:
    v8::Isolate* isolate_;
    v8::Global<v8::Context> context_;
    ModuleLoadCallback module_load_cb_;
    void* module_load_cb_data_;

    v8::Local<v8::Value> do_run(
      v8::Local<v8::Context> context,
      const std::string& module_name,
      const std::string& exported_function_name);

    static v8::MaybeLocal<v8::Module> compile_module(
      v8::Local<v8::Context> context,
      v8::Local<v8::String> source_text,
      const std::string& module_name);

    static bool exec_module(
      v8::Local<v8::Context> context,
      v8::Local<v8::Module> module);

    static v8::MaybeLocal<v8::Module> ResolveModuleCallback(
      v8::Local<v8::Context> context,
      v8::Local<v8::String> specifier,
      v8::Local<v8::FixedArray> import_assertions,
      v8::Local<v8::Module> referrer);
        
    static v8::MaybeLocal<v8::Module> FetchModuleTree(
      v8::Local<v8::Module> referrer,
      v8::Local<v8::Context> context,
      const std::string& file_name);
  };
} // namespace ccf