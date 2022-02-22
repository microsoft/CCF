// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <v8.h>
#include <vector>

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
    class TemplateCache
    {
    public:
      explicit TemplateCache(v8::Isolate* isolate);

      // Using strings for keys is not ideal but we need something
      // that is extensible.

      /**
       * Return whether a template with the given name is cached.
       */
      bool has(const std::string& key);

      /**
       * Return the template with the given name from the cache.
       */
      v8::Local<v8::Template> get(const std::string& name);

      /**
       * Add a template to the cache.
       *
       * Once set, a template cannot be changed. This prevents
       * overriding core templates by plugins.
       */
      void set(const std::string& name, v8::Local<v8::Template> value);

    private:
      v8::Isolate* isolate_;
      std::unordered_map<std::string, v8::Global<v8::Template>> templates_;
    };

    // Adapted from v8/src/d8/d8.h::PerIsolateData.
    class Data
    {
    public:
      explicit Data(v8::Isolate* isolate);
      ~Data();

      TemplateCache& get_template_cache()
      {
        return template_cache_;
      }

      static Data* Get(v8::Isolate* isolate);

    private:
      v8::Isolate* isolate_;
      TemplateCache template_cache_;
    };

    V8Isolate();
    ~V8Isolate();

    V8Isolate(const V8Isolate&) = delete;
    V8Isolate& operator=(const V8Isolate&) = delete;
    V8Isolate(V8Isolate&&) = delete;
    V8Isolate& operator=(V8Isolate&&) = delete;

    v8::Isolate* get_isolate()
    {
      return isolate_;
    }
    operator v8::Isolate *()
    {
      return isolate_;
    }

  private:
    v8::Isolate* isolate_;
    std::unique_ptr<Data> data_;
  };

  /**
   * A V8 Context, to be used for a single call/request only.
   */
  class V8Context
  {
  public:
    using ModuleLoadCallback =
      std::function<std::optional<std::string>(const std::string&, void*)>;
    using FinalizerCallback = std::function<void(void*)>;

    class FinalizerScope
    {
    public:
      explicit FinalizerScope(V8Context& context);
      ~FinalizerScope();

      void register_finalizer(FinalizerCallback callback, void* data);

      static FinalizerScope& from_context(v8::Local<v8::Context> context);

    private:
      v8::Local<v8::Context> context_;
      std::vector<std::pair<FinalizerCallback, void*>> finalizers_;
    };

    V8Context(V8Isolate& isolate);
    ~V8Context();

    V8Context(const V8Context&) = delete;
    V8Context& operator=(const V8Context&) = delete;
    V8Context(V8Context&&) = delete;
    V8Context& operator=(V8Context&&) = delete;

    /**
     * Return the V8 Context.
     * The context can be used to install additional globals.
     */
    v8::Local<v8::Context> get_context()
    {
      return v8::Local<v8::Context>::New(isolate_, context_);
    }

    static V8Context& from_context(v8::Local<v8::Context> context);

    void register_finalizer(FinalizerCallback callback, void* data);

    /**
     * Must be called before run().
     */
    void set_module_load_callback(ModuleLoadCallback callback, void* data);

    void install_global(const std::string& name, v8::Local<v8::Value> value);

    v8::Local<v8::Value> run(
      const std::string& module_name,
      const std::string& exported_function_name,
      const std::vector<v8::Local<v8::Value>>& args = {});

  private:
    v8::Isolate* isolate_;
    v8::Global<v8::Context> context_;
    ModuleLoadCallback module_load_cb_;
    void* module_load_cb_data_;

    static v8::MaybeLocal<v8::Module> compile_module(
      v8::Local<v8::Context> context,
      v8::Local<v8::String> source_text,
      const std::string& module_name);

    static bool exec_module(
      v8::Local<v8::Context> context, v8::Local<v8::Module> module);

    static v8::MaybeLocal<v8::Module> ResolveModuleCallback(
      v8::Local<v8::Context> context,
      v8::Local<v8::String> specifier,
      v8::Local<v8::FixedArray> import_assertions,
      v8::Local<v8::Module> referrer);

    static v8::MaybeLocal<v8::Promise> HostImportModuleDynamically(
      v8::Local<v8::Context> context,
      v8::Local<v8::ScriptOrModule> script_or_module,
      v8::Local<v8::String> specifier,
      v8::Local<v8::FixedArray> import_assertions);

    static v8::MaybeLocal<v8::Module> FetchModuleTree(
      v8::Local<v8::Module> referrer,
      v8::Local<v8::Context> context,
      const std::string& file_name);
  };
} // namespace ccf