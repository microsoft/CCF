// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "v8_runner.h"

#include "ccf/ds/logger.h"
#include "libplatform/libplatform.h"
#include "v8_util.h"

#include <map>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

// Reading material:
// Samples:
// - https://gist.github.com/surusek/4c05e4dcac6b82d18a1a28e6742fc23e
// v8 codebase:
// - test/cctest/test-api.cc
// - src/d8/d8.cc

namespace ccf
{
  static std::unique_ptr<v8::Platform> platform = nullptr;

#define CHECK(expr) \
  if (!(expr)) \
  LOG_FATAL_FMT("CHECK failed")

  // Adapted from v8/src/d8/d8.cc.
  static bool IsAbsolutePath(const std::string& path)
  {
    return path[0] == '/';
  }

  // Adapted from v8/d8/d8.cc.
  // Returns the directory part of path, without the trailing '/'.
  static std::string DirName(const std::string& path)
  {
    CHECK(IsAbsolutePath(path));
    size_t last_slash = path.find_last_of('/');
    CHECK(last_slash != std::string::npos);
    return path.substr(0, last_slash);
  }

  // Adapted from v8/d8/d8.cc.
  // Resolves path to an absolute path if necessary, and does some
  // normalization (eliding references to the current directory
  // and replacing backslashes with slashes).
  static std::string NormalizePath(
    const std::string& path, const std::string& dir_name)
  {
    std::string absolute_path;
    if (IsAbsolutePath(path))
    {
      absolute_path = path;
    }
    else
    {
      absolute_path = dir_name + '/' + path;
    }
    std::replace(absolute_path.begin(), absolute_path.end(), '\\', '/');
    std::vector<std::string> segments;
    std::istringstream segment_stream(absolute_path);
    std::string segment;
    while (std::getline(segment_stream, segment, '/'))
    {
      if (segment == "..")
      {
        if (!segments.empty())
          segments.pop_back();
      }
      else if (segment != ".")
      {
        segments.push_back(segment);
      }
    }
    // Join path segments.
    std::ostringstream os;
    if (segments.size() > 1)
    {
      std::copy(
        segments.begin(),
        segments.end() - 1,
        std::ostream_iterator<std::string>(os, "/"));
      os << *segments.rbegin();
    }
    else
    {
      os << "/";
      if (!segments.empty())
        os << segments[0];
    }
    return os.str();
  }

  enum
  {
    kContextEmbedderDataField,
    kModuleEmbedderDataField,
    kFinalizerEmbedderDataField
  };

  // Adapted from v8/src/d8/d8.cc::ModuleEmbedderData.
  // Per-context Module data, allowing sharing of module maps
  // across top-level module loads.
  class ModuleEmbedderData
  {
  private:
    class ModuleGlobalHash
    {
    public:
      explicit ModuleGlobalHash(v8::Isolate* isolate) : isolate_(isolate) {}
      size_t operator()(const v8::Global<v8::Module>& module) const
      {
        return module.Get(isolate_)->GetIdentityHash();
      }

    private:
      v8::Isolate* isolate_;
    };

  public:
    class Scope
    {
    public:
      explicit Scope(
        v8::Local<v8::Context> context,
        V8Context::ModuleLoadCallback module_load_cb,
        void* module_load_cb_data) :
        context_(context)
      {
        context->SetAlignedPointerInEmbedderData(
          kModuleEmbedderDataField,
          new ModuleEmbedderData(
            context->GetIsolate(), module_load_cb, module_load_cb_data));
      }

      ~Scope()
      {
        delete ModuleEmbedderData::GetFromContext(context_);
        context_->SetAlignedPointerInEmbedderData(
          kModuleEmbedderDataField, nullptr);
      }

    private:
      v8::Local<v8::Context> context_;
    };

    explicit ModuleEmbedderData(
      v8::Isolate* isolate,
      V8Context::ModuleLoadCallback load_callback,
      void* load_callback_data) :
      module_load_callback(load_callback),
      module_load_callback_data(load_callback_data),
      module_to_specifier_map(10, ModuleGlobalHash(isolate))
    {}

    static ModuleEmbedderData* GetFromContext(v8::Local<v8::Context> context)
    {
      return static_cast<ModuleEmbedderData*>(
        context->GetAlignedPointerFromEmbedderData(kModuleEmbedderDataField));
    }

    V8Context::ModuleLoadCallback module_load_callback;
    void* module_load_callback_data;

    // Map from normalized module specifier to Module.
    std::map<std::string, v8::Global<v8::Module>> module_map;
    // Map from Module to its URL as defined in the ScriptOrigin
    std::unordered_map<v8::Global<v8::Module>, std::string, ModuleGlobalHash>
      module_to_specifier_map;
  };

  V8Context::FinalizerScope::FinalizerScope(V8Context& context) :
    context_(context.get_context())
  {
    context_->SetAlignedPointerInEmbedderData(
      kFinalizerEmbedderDataField, this);
  }

  V8Context::FinalizerScope::~FinalizerScope()
  {
    for (auto& [fn, data] : finalizers_)
      fn(data);
    context_->SetAlignedPointerInEmbedderData(
      kFinalizerEmbedderDataField, nullptr);
  }

  void V8Context::FinalizerScope::register_finalizer(
    FinalizerCallback callback, void* data)
  {
    finalizers_.push_back({callback, data});
  }

  V8Context::FinalizerScope& V8Context::FinalizerScope::from_context(
    v8::Local<v8::Context> context)
  {
    auto s = static_cast<V8Context::FinalizerScope*>(
      context->GetAlignedPointerFromEmbedderData(kFinalizerEmbedderDataField));
    if (!s)
      throw std::logic_error("No FinalizerScope in context");
    return *s;
  }

  void v8_initialize()
  {
    if (platform)
    {
      throw std::runtime_error("v8_initialize() must only be called once");
    }

    // See https://github.com/v8/v8/blob/master/src/flags/flag-definitions.h
    // for all available flags.

#ifdef VIRTUAL_ENCLAVE
    // By default, strings from the snapshot are rehashed
    // when creating a context to override the baked-in seed.
    // For now, we disable this to avoid the performance hit,
    // but since it is a security feature it needs to be carefully
    // evaluated.
    v8::V8::SetFlagsFromString("--norehash_snapshot");
    platform = v8::platform::NewDefaultPlatform();
#else
    // Disables runtime allocation of executable memory.
    // Uses only the Ignition interpreter.
    v8::V8::SetFlagsFromString(
      "--v8_os_page_size=4 --single-threaded --jitless --norehash_snapshot");
    platform = v8::platform::NewSingleThreadedDefaultPlatform();
#endif

    v8::V8::InitializePlatform(platform.get());
    v8::V8::Initialize();
  }

  void v8_shutdown()
  {
    if (!platform)
    {
      throw std::runtime_error(
        "v8_shutdown must only be called after initialize and exactly "
        "once");
    }
    v8::V8::Dispose();
    v8::V8::ShutdownPlatform();
    platform = nullptr;
  }

  V8Isolate::Data::Data(v8::Isolate* isolate) :
    isolate_(isolate),
    template_cache_(isolate)
  {
    isolate->SetData(0, this);
  }

  V8Isolate::Data::~Data()
  {
    isolate_->SetData(0, nullptr);
  }

  V8Isolate::TemplateCache::TemplateCache(v8::Isolate* isolate) :
    isolate_(isolate)
  {}

  bool V8Isolate::TemplateCache::has(const std::string& name)
  {
    auto it = templates_.find(name);
    return it != templates_.end();
  }

  v8::Local<v8::Template> V8Isolate::TemplateCache::get(const std::string& name)
  {
    auto it = templates_.find(name);
    CHECK(it != templates_.end());
    return it->second.Get(isolate_);
  }

  void V8Isolate::TemplateCache::set(
    const std::string& name, v8::Local<v8::Template> value)
  {
    auto it = templates_.find(name);
    CHECK(it == templates_.end());
    templates_[name].Reset(isolate_, value);
  }

  V8Isolate::Data* V8Isolate::Data::Get(v8::Isolate* isolate)
  {
    return static_cast<V8Isolate::Data*>(isolate->GetData(0));
  }

  static void on_fatal_error(const char* location, const char* message)
  {
    LOG_FATAL_FMT("Fatal error in V8: {}: {}", location, message);
  }

  static size_t on_near_heap_limit(
    void* data, size_t current_heap_limit, size_t initial_heap_limit)
  {
    LOG_INFO_FMT(
      "WARNING: Approaching heap limit in V8 (limit: {})", current_heap_limit);
    return current_heap_limit;
  }

  V8Isolate::V8Isolate()
  {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator =
      v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    isolate_ = v8::Isolate::New(create_params);
    // Note: Out-of-memory also calls the fatal error handler.
    isolate_->SetFatalErrorHandler(on_fatal_error);
    isolate_->AddNearHeapLimitCallback(on_near_heap_limit, nullptr);
    data_ = std::make_unique<V8Isolate::Data>(isolate_);
  }

  V8Isolate::~V8Isolate()
  {
    v8::ArrayBuffer::Allocator* allocator = isolate_->GetArrayBufferAllocator();
    data_ = nullptr;
    isolate_->Dispose();
    delete allocator;
  }

  // Instantiating a V8Context also establishes
  // the scopes for the isolate and the underlying context
  // by manually Enter()'ing them (and Exit()'ing them at destruction)
  // instead of using v8::Isolate::Scope and v8::Context::Scope.
  // This simplifies writing code.
  V8Context::V8Context(V8Isolate& isolate)
  {
    isolate_ = isolate.get_isolate();
    isolate_->Enter();
    v8::HandleScope handle_scope(isolate_);
    v8::Local<v8::Context> context = v8::Context::New(isolate_);
    context->SetAlignedPointerInEmbedderData(kContextEmbedderDataField, this);
    context->SetAlignedPointerInEmbedderData(
      kFinalizerEmbedderDataField, nullptr);
    context->SetAlignedPointerInEmbedderData(kModuleEmbedderDataField, nullptr);
    context->Enter();
    context_.Reset(isolate_, context);
  }

  V8Context::~V8Context()
  {
    {
      v8::HandleScope handle_scope(isolate_);
      v8::Local<v8::Context> context = get_context();
      context->Exit();
    }
    // Dispose the persistent handle.  When no one else has any
    // references to the objects stored in the handles they will be
    // automatically reclaimed.
    context_.Reset();

    isolate_->Exit();
  }

  V8Context& V8Context::from_context(v8::Local<v8::Context> context)
  {
    return *static_cast<V8Context*>(
      context->GetAlignedPointerFromEmbedderData(kContextEmbedderDataField));
  }

  void V8Context::register_finalizer(FinalizerCallback callback, void* data)
  {
    FinalizerScope::from_context(get_context())
      .register_finalizer(callback, data);
  }

  void V8Context::set_module_load_callback(
    ModuleLoadCallback callback, void* data)
  {
    module_load_cb_ = callback;
    module_load_cb_data_ = data;
  }

  void V8Context::install_global(
    const std::string& name, v8::Local<v8::Value> value)
  {
    v8::HandleScope handle_scope(isolate_);
    v8::Local<v8::Context> context = get_context();
    context->Global()
      ->Set(context, v8_util::to_v8_istr(isolate_, name), value)
      .Check();
  }

  v8::Local<v8::Value> V8Context::run(
    const std::string& module_name,
    const std::string& exported_function_name,
    const std::vector<v8::Local<v8::Value>>& args)
  {
    v8::EscapableHandleScope handle_scope(isolate_);
    v8::Local<v8::Context> context = get_context();
    ModuleEmbedderData::Scope embedder_data_scope(
      context, module_load_cb_, module_load_cb_data_);
    isolate_->SetHostImportModuleDynamicallyCallback(
      V8Context::HostImportModuleDynamically);
    v8::Local<v8::Module> module;
    if (!FetchModuleTree(v8::Local<v8::Module>(), context, module_name)
           .ToLocal(&module))
      return v8::Local<v8::Value>();

    if (!exec_module(context, module))
      return v8::Local<v8::Value>();

    v8::Local<v8::Value> ns_val = module->GetModuleNamespace();
    CHECK(ns_val->IsModuleNamespaceObject());
    v8::Local<v8::Object> ns = ns_val.As<v8::Object>();
    v8::Local<v8::Value> exported_val;
    if (!ns->Get(
             context,
             v8_util::to_v8_str(isolate_, exported_function_name.c_str()))
           .ToLocal(&exported_val))
    {
      isolate_->ThrowError("Could not find exported function");
      return v8::Local<v8::Value>();
    }
    if (!exported_val->IsFunction())
    {
      isolate_->ThrowError("Exported value is not a function");
      return v8::Local<v8::Value>();
    }
    v8::Local<v8::Function> exported_function =
      v8::Local<v8::Function>::Cast(exported_val);
    int argc = args.size();
    v8::Local<v8::Value>* argv = const_cast<v8::Local<v8::Value>*>(args.data());
    v8::Local<v8::Value> result;
    if (!exported_function->Call(context, v8::Undefined(isolate_), argc, argv)
           .ToLocal(&result))
      return v8::Local<v8::Value>();

    while (v8::platform::PumpMessageLoop(platform.get(), isolate_))
      continue;

    if (result->IsPromise())
    {
      v8::Local<v8::Promise> promise = result.As<v8::Promise>();
      v8::Local<v8::Value> promise_result = promise->Result();
      if (promise->State() == v8::Promise::kFulfilled)
      {
        result = promise_result;
      }
      else if (promise->State() == v8::Promise::kRejected)
      {
        isolate_->ThrowException(promise_result);
        return v8::Local<v8::Value>();
      }
      else
      {
        CHECK(false);
      }
    }

    return handle_scope.Escape(result);
  }

  // Adapted from v8/src/d8/d8.cc::CompileString.
  v8::MaybeLocal<v8::Module> V8Context::compile_module(
    v8::Local<v8::Context> context,
    v8::Local<v8::String> source_text,
    const std::string& module_name)
  {
    v8::Isolate* isolate = context->GetIsolate();

    v8::ScriptOrigin origin(
      isolate,
      v8::String::NewFromUtf8(isolate, module_name.c_str()).ToLocalChecked(),
      0,
      0,
      false,
      -1,
      v8::Local<v8::Value>(),
      false,
      false,
      true);

    // Note: V8 automatically caches bytecode per Isolate.
    // See https://v8.dev/blog/code-caching-for-devs.
    v8::ScriptCompiler::Source script_source(source_text, origin);
    v8::MaybeLocal<v8::Module> result =
      v8::ScriptCompiler::CompileModule(isolate, &script_source);
    return result;
  }

  bool V8Context::exec_module(
    v8::Local<v8::Context> context, v8::Local<v8::Module> module)
  {
    if (module->InstantiateModule(context, ResolveModuleCallback).IsNothing())
    {
      return false;
    }

    if (module->Evaluate(context).IsEmpty())
    {
      return false;
    }
    return true;
  }

  // Adapted from v8/src/d8/d8.cc::ResolveModuleCallback.
  v8::MaybeLocal<v8::Module> V8Context::ResolveModuleCallback(
    v8::Local<v8::Context> context,
    v8::Local<v8::String> specifier,
    v8::Local<v8::FixedArray> import_assertions,
    v8::Local<v8::Module> referrer)
  {
    v8::Isolate* isolate = context->GetIsolate();
    ModuleEmbedderData* d = ModuleEmbedderData::GetFromContext(context);
    auto specifier_it = d->module_to_specifier_map.find(
      v8::Global<v8::Module>(isolate, referrer));
    CHECK(specifier_it != d->module_to_specifier_map.end());

    std::string absolute_path = NormalizePath(
      v8_util::to_str(isolate, specifier), DirName(specifier_it->second));

    auto module_it = d->module_map.find(absolute_path);
    CHECK(module_it != d->module_map.end());
    return module_it->second.Get(isolate);
  }

  // Adapted from v8/src/d8/d8.cc::HostImportModuleDynamically.
  v8::MaybeLocal<v8::Promise> V8Context::HostImportModuleDynamically(
    v8::Local<v8::Context> context,
    v8::Local<v8::ScriptOrModule> script_or_module,
    v8::Local<v8::String> specifier,
    v8::Local<v8::FixedArray> import_assertions)
  {
    v8::Isolate* isolate = context->GetIsolate();
    ModuleEmbedderData* d = ModuleEmbedderData::GetFromContext(context);

    // Instantiate a Promise
    v8::Local<v8::Promise::Resolver> resolver;
    if (!v8::Promise::Resolver::New(context).ToLocal(&resolver))
      return v8::MaybeLocal<v8::Promise>();
    v8::Local<v8::Promise> promise = resolver->GetPromise();

    // Lookup already-resolved referrer module
    v8::Local<v8::String> referrer_module_name =
      script_or_module->GetResourceName().As<v8::String>();
    std::string referrer_module_name_str =
      v8_util::to_str(isolate, referrer_module_name);
    auto module_it = d->module_map.find(referrer_module_name_str);
    CHECK(module_it != d->module_map.end());
    v8::Local<v8::Module> referrer = module_it->second.Get(isolate);

    // Compute absolute path of module to be resolved
    std::string absolute_path = NormalizePath(
      v8_util::to_str(isolate, specifier), DirName(referrer_module_name_str));

    // Check if module has already been resolved, otherwise resolve it
    v8::TryCatch try_catch(isolate);
    module_it = d->module_map.find(absolute_path);
    v8::Local<v8::Module> module;
    if (module_it != d->module_map.end())
    {
      module = module_it->second.Get(isolate);
    }
    else if (!FetchModuleTree(referrer, context, absolute_path)
                .ToLocal(&module))
    {
      CHECK(try_catch.HasCaught());
      resolver->Reject(context, try_catch.Exception()).ToChecked();
      return promise;
    }

    if (!exec_module(context, module))
    {
      CHECK(try_catch.HasCaught());
      resolver->Reject(context, try_catch.Exception()).ToChecked();
      return promise;
    }

    // Get the module namespace object
    v8::Local<v8::Value> module_namespace = module->GetModuleNamespace();
    CHECK(!try_catch.HasCaught());
    resolver->Resolve(context, module_namespace).ToChecked();
    return promise;
  }

  // Adapted from v8/d8/d8.cc::ReadFile
  static v8::MaybeLocal<v8::String> ReadFile(
    v8::Local<v8::Context> context, const std::string& name)
  {
    v8::Isolate* isolate = context->GetIsolate();
    ModuleEmbedderData* d = ModuleEmbedderData::GetFromContext(context);
    CHECK(d->module_load_callback != nullptr);
    auto source_text =
      d->module_load_callback(name, d->module_load_callback_data);
    if (!source_text)
    {
      return v8::MaybeLocal<v8::String>();
    }
    v8::MaybeLocal<v8::String> result =
      v8::String::NewFromUtf8(isolate, source_text->c_str());
    return result;
  }

  // Adapted from v8/d8/d8.cc::FetchModuleTree
  v8::MaybeLocal<v8::Module> V8Context::FetchModuleTree(
    v8::Local<v8::Module> referrer,
    v8::Local<v8::Context> context,
    const std::string& file_name)
  {
    CHECK(IsAbsolutePath(file_name));
    v8::Isolate* isolate = context->GetIsolate();
    ModuleEmbedderData* d = ModuleEmbedderData::GetFromContext(context);
    v8::Local<v8::String> source_text;
    if (!ReadFile(context, file_name).ToLocal(&source_text))
    {
      std::string msg = "Error reading module from " + file_name;
      if (!referrer.IsEmpty())
      {
        auto specifier_it = d->module_to_specifier_map.find(
          v8::Global<v8::Module>(isolate, referrer));
        CHECK(specifier_it != d->module_to_specifier_map.end());
        msg += "\n    imported by " + specifier_it->second;
      }
      isolate->ThrowError(
        v8::String::NewFromUtf8(isolate, msg.c_str()).ToLocalChecked());
      return v8::MaybeLocal<v8::Module>();
    }

    v8::Local<v8::Module> module;
    if (!compile_module(context, source_text, file_name).ToLocal(&module))
    {
      return v8::MaybeLocal<v8::Module>();
    }

    CHECK(d->module_map
            .insert(std::make_pair(
              file_name, v8::Global<v8::Module>(isolate, module)))
            .second);
    CHECK(d->module_to_specifier_map
            .insert(std::make_pair(
              v8::Global<v8::Module>(isolate, module), file_name))
            .second);

    std::string dir_name = DirName(file_name);

    v8::Local<v8::FixedArray> module_requests = module->GetModuleRequests();
    for (int i = 0, length = module_requests->Length(); i < length; ++i)
    {
      v8::Local<v8::ModuleRequest> module_request =
        module_requests->Get(context, i).As<v8::ModuleRequest>();
      v8::Local<v8::String> name = module_request->GetSpecifier();
      v8::Local<v8::FixedArray> import_assertions =
        module_request->GetImportAssertions();
      std::string absolute_path =
        NormalizePath(v8_util::to_str(isolate, name), dir_name);
      if (d->module_map.count(absolute_path))
      {
        continue;
      }
      if (FetchModuleTree(module, context, absolute_path).IsEmpty())
      {
        return v8::MaybeLocal<v8::Module>();
      }
    }
    return module;
  }

} // namespace ccf