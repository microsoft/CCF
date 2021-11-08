// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "v8_runner.h"
#include "ds/logger.h"

#include <stdexcept>
#include <sstream>
#include <map>
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

  #define CHECK(expr) if (!(expr)) LOG_FATAL_FMT("CHECK failed")

  // Extracts a C string from a V8 Utf8Value.
  // Adapted from v8/samples/shell.cc::ToCString.
  static const char* ToCString(const v8::String::Utf8Value& value) {
    return *value ? *value : "<string conversion failed>";
  }

  // Adapted from v8/src/d8/d8.cc.
  static std::string ToSTLString(v8::Isolate* isolate, v8::Local<v8::String> v8_str) {
    v8::String::Utf8Value utf8(isolate, v8_str);
    // Should not be able to fail since the input is a v8::String.
    CHECK(*utf8);
    return *utf8;
  }

  static inline v8::Local<v8::String> v8_str(v8::Isolate* isolate, const char* x) {
    return v8::String::NewFromUtf8(isolate, x).ToLocalChecked();
  }

  // Adapted from v8/samples/shell.cc::ReportException.
  static void ReportException(v8::Isolate* isolate, v8::TryCatch* try_catch) {
    v8::HandleScope handle_scope(isolate);
    v8::String::Utf8Value exception(isolate, try_catch->Exception());
    const char* exception_string = ToCString(exception);
    v8::Local<v8::Message> message = try_catch->Message();
    if (message.IsEmpty()) {
      // V8 didn't provide any extra information about this error; just
      // print the exception.
      LOG_INFO_FMT("Throw: {}", exception_string);
    } else {
      // Print (filename):(line number): (message).
      v8::String::Utf8Value filename(isolate,
                                    message->GetScriptOrigin().ResourceName());
      v8::Local<v8::Context> context(isolate->GetCurrentContext());
      const char* filename_string = ToCString(filename);
      int linenum = message->GetLineNumber(context).FromJust();
      LOG_INFO_FMT("{}:{}: {}", filename_string, linenum, exception_string);
      // Print line of source code.
      v8::String::Utf8Value sourceline(
          isolate, message->GetSourceLine(context).ToLocalChecked());
      const char* sourceline_string = ToCString(sourceline);
      LOG_INFO_FMT("{}", sourceline_string);
      // Print wavy underline (GetUnderline is deprecated).
      // int start = message->GetStartColumn(context).FromJust();
      // for (int i = 0; i < start; i++) {
      //   LOG_INFO_FMT((stderr, " ");
      // }
      // int end = message->GetEndColumn(context).FromJust();
      // for (int i = start; i < end; i++) {
      //   fprintf(stderr, "^");
      // }
      // fprintf(stderr, "\n");
      v8::Local<v8::Value> stack_trace_string;
      if (try_catch->StackTrace(context).ToLocal(&stack_trace_string) &&
          stack_trace_string->IsString() &&
          stack_trace_string.As<v8::String>()->Length() > 0) {
        v8::String::Utf8Value stack_trace(isolate, stack_trace_string);
        const char* stack_trace_string = ToCString(stack_trace);
        LOG_INFO_FMT("{}", stack_trace_string);
      }
    }
  }

  // Adapted from v8/src/d8/d8.cc.
  static bool IsAbsolutePath(const std::string& path) {
    return path[0] == '/';
  }

  // Adapted from v8/d8/d8.cc.
  // Returns the directory part of path, without the trailing '/'.
  static std::string DirName(const std::string& path) {
    CHECK(IsAbsolutePath(path));
    size_t last_slash = path.find_last_of('/');
    CHECK(last_slash != std::string::npos);
    return path.substr(0, last_slash);
  }

  // Adapted from v8/d8/d8.cc.
  // Resolves path to an absolute path if necessary, and does some
  // normalization (eliding references to the current directory
  // and replacing backslashes with slashes).
  static std::string NormalizePath(const std::string& path,
                            const std::string& dir_name) {
    std::string absolute_path;
    if (IsAbsolutePath(path)) {
      absolute_path = path;
    } else {
      absolute_path = dir_name + '/' + path;
    }
    std::replace(absolute_path.begin(), absolute_path.end(), '\\', '/');
    std::vector<std::string> segments;
    std::istringstream segment_stream(absolute_path);
    std::string segment;
    while (std::getline(segment_stream, segment, '/')) {
      if (segment == "..") {
        if (!segments.empty()) segments.pop_back();
      } else if (segment != ".") {
        segments.push_back(segment);
      }
    }
    // Join path segments.
    std::ostringstream os;
    if (segments.size() > 1) {
      std::copy(segments.begin(), segments.end() - 1,
                std::ostream_iterator<std::string>(os, "/"));
      os << *segments.rbegin();
    } else {
      os << "/";
      if (!segments.empty()) os << segments[0];
    }
    return os.str();
  }

  // Adapted from v8/src/d8/d8.h::PerIsolateData.
  // Not used currently, but may be useful in the future.
  class PerIsolateData {
  public:
    explicit PerIsolateData(v8::Isolate* isolate) : isolate_(isolate)
    {
      isolate->SetData(0, this);
    }

    ~PerIsolateData()
    {
      isolate_->SetData(0, nullptr);
    }

    inline static PerIsolateData* Get(v8::Isolate* isolate) {
      return reinterpret_cast<PerIsolateData*>(isolate->GetData(0));
    }
  private:
    v8::Isolate* isolate_;
  };

  // Adapted from v8/src/d8/d8.cc::ModuleEmbedderData.
  // Per-context Module data, allowing sharing of module maps
  // across top-level module loads.
  class ModuleEmbedderData {
  private:
    class ModuleGlobalHash {
    public:
      explicit ModuleGlobalHash(v8::Isolate* isolate) : isolate_(isolate) {}
      size_t operator()(const v8::Global<v8::Module>& module) const {
        return module.Get(isolate_)->GetIdentityHash();
      }

    private:
      v8::Isolate* isolate_;
    };

  public:
    enum { kModuleEmbedderDataIndex };

    class Scope {
    public:
      explicit Scope(v8::Local<v8::Context> context,
        V8Context::ModuleLoadCallback module_load_cb,
        void* module_load_cb_data)
        : context_(context)
      {
        context->SetAlignedPointerInEmbedderData(
            kModuleEmbedderDataIndex, new ModuleEmbedderData(
              context->GetIsolate(),
              module_load_cb,
              module_load_cb_data));
      }

      ~Scope()
      {
        delete ModuleEmbedderData::GetFromContext(context_);
        context_->SetAlignedPointerInEmbedderData(kModuleEmbedderDataIndex, nullptr);
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
        module_to_specifier_map(10, ModuleGlobalHash(isolate)) {}
    
    static ModuleEmbedderData* GetFromContext(v8::Local<v8::Context> context) {
      return static_cast<ModuleEmbedderData*>(
          context->GetAlignedPointerFromEmbedderData(kModuleEmbedderDataIndex));
    }

    V8Context::ModuleLoadCallback module_load_callback;
    void* module_load_callback_data;

    // Map from normalized module specifier to Module.
    std::map<std::string, v8::Global<v8::Module>> module_map;
    // Map from Module to its URL as defined in the ScriptOrigin
    std::unordered_map<v8::Global<v8::Module>, std::string, ModuleGlobalHash>
        module_to_specifier_map;
  };

  void v8_initialize()
  {
    if (platform)
    {
      throw std::runtime_error("V8Isolate::initialize must only be called once");
    }
    int thread_pool_size = 1;
    platform = v8::platform::NewDefaultPlatform(thread_pool_size);
    v8::V8::InitializePlatform(platform.get());
    v8::V8::Initialize();
  }

  void v8_shutdown()
  {
    if (!platform)
    {
      throw std::runtime_error(
        "V8Isolate::shutdown must only be called after initialize and exactly "
        "once");
    }
    v8::V8::Dispose();
    v8::V8::ShutdownPlatform();
    platform = nullptr;
  }

  V8Isolate::V8Isolate()
  {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator =
      v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    isolate_ = v8::Isolate::New(create_params);
  }

  V8Isolate::~V8Isolate()
  {
    delete isolate_->GetArrayBufferAllocator();
    isolate_->Dispose();
  }

  V8Context::V8Context(V8Isolate& isolate)
  {
    // TODO do we need to Enter the isolate?
    isolate_ = isolate.GetIsolate();
    v8::HandleScope handle_scope(isolate_);
    v8::Local<v8::Context> context = v8::Context::New(isolate_);
    this->context_.Reset(isolate_, context);
  }

  V8Context::~V8Context()
  {
    // Dispose the persistent handles.  When no one else has any
    // references to the objects stored in the handles they will be
    // automatically reclaimed.
    context_.Reset();
  }

  void V8Context::set_module_load_callback(ModuleLoadCallback callback, void* data)
  {
    module_load_cb_ = callback;
    module_load_cb_data_ = data;
  }

  void V8Context::run(
    const std::string& module_name,
    const std::string& exported_function_name)
  {
    v8::Isolate::Scope isolate_scope(isolate_);
    v8::HandleScope handle_scope(isolate_);
    v8::Local<v8::Context> context = get_context();
    v8::Context::Scope context_scope(context);
    ModuleEmbedderData::Scope embedder_data_scope(context, module_load_cb_, module_load_cb_data_);
    
    v8::TryCatch try_catch(isolate_);
    v8::Local<v8::Value> v = do_run(context, module_name, exported_function_name);
    if (v.IsEmpty())
    {
      ReportException(isolate_, &try_catch);
      v8::String::Utf8Value exception(isolate_, try_catch.Exception());
      const char* exception_str = ToCString(exception);
      throw std::runtime_error(exception_str);
    }

    // TODO handle return value
  }

  v8::Local<v8::Value> V8Context::do_run(
    v8::Local<v8::Context> context,
    const std::string& module_name,
    const std::string& exported_function_name)
  {
    v8::EscapableHandleScope handle_scope(isolate_);
    v8::Local<v8::Module> module;
    if (!FetchModuleTree(v8::Local<v8::Module>(), context, module_name).ToLocal(&module))
      return v8::Local<v8::Value>();

    if (!exec_module(context, module))
      return v8::Local<v8::Value>();

    v8::Local<v8::Value> ns_val = module->GetModuleNamespace();
    CHECK(ns_val->IsModuleNamespaceObject());
    v8::Local<v8::Object> ns = ns_val.As<v8::Object>();
    v8::Local<v8::Value> exported_val;
    if (!ns->Get(context, v8_str(isolate_, exported_function_name.c_str())).ToLocal(&exported_val))
    {
      isolate_->ThrowError("Could not find exported function");
      return v8::Local<v8::Value>();
    }
    if (!exported_val->IsFunction())
    {
      isolate_->ThrowError("Exported value is not a function");
      return v8::Local<v8::Value>();
    }
    v8::Local<v8::Function> exported_function = v8::Local<v8::Function>::Cast(exported_val);
    int argc = 0;
    v8::Local<v8::Value> args[1];
    v8::Local<v8::Value> result;
    if (!exported_function->Call(context, v8::Undefined(isolate_), argc, args).ToLocal(&result))
      return v8::Local<v8::Value>();
    
    // TODO when is this needed? for async functions only?
    while (v8::platform::PumpMessageLoop(platform.get(), isolate_))
      continue;
    
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

    // TODO: cache compiled code using KV?
    // V8 caches automatically per Isolate, maybe that's enough?
    // TODO check how Isolate cache works, eviction?
    // see CodeCache test in v8/test/cctest/test-api.cc
    // https://v8.dev/blog/code-caching
    // https://v8.dev/blog/code-caching-for-devs
    v8::ScriptCompiler::CachedData* cached_code = nullptr;
    v8::ScriptCompiler::Source script_source(source_text, origin, cached_code);
    v8::MaybeLocal<v8::Module> result =
        v8::ScriptCompiler::CompileModule(isolate, &script_source,
                  cached_code ? v8::ScriptCompiler::kConsumeCodeCache
                              : v8::ScriptCompiler::kNoCompileOptions);
    if (cached_code) CHECK(!cached_code->rejected);
    return result;
  }

  bool V8Context::exec_module(
    v8::Local<v8::Context> context,
    v8::Local<v8::Module> module)
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
    auto specifier_it =
      d->module_to_specifier_map.find(v8::Global<v8::Module>(isolate, referrer));
    CHECK(specifier_it != d->module_to_specifier_map.end());

    std::string absolute_path = NormalizePath(ToSTLString(isolate, specifier),
                                            DirName(specifier_it->second));

    auto module_it = d->module_map.find(absolute_path);
    CHECK(module_it != d->module_map.end());
    return module_it->second.Get(isolate);
  }

  // Adapted from v8/d8/d8.cc::ReadFile
  static v8::MaybeLocal<v8::String> ReadFile(v8::Local<v8::Context> context, const std::string& name)
  {
    v8::Isolate* isolate = context->GetIsolate();
    ModuleEmbedderData* d = ModuleEmbedderData::GetFromContext(context);
    CHECK(d->module_load_callback != nullptr);
    auto source_text = d->module_load_callback(name, d->module_load_callback_data);
    if (!source_text)
    {
      return v8::MaybeLocal<v8::String>();
    }
    v8::MaybeLocal<v8::String> result = v8::String::NewFromUtf8(
      isolate, source_text->c_str());
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
      if (!referrer.IsEmpty()) {
        auto specifier_it =
            d->module_to_specifier_map.find(v8::Global<v8::Module>(isolate, referrer));
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
              .insert(std::make_pair(file_name,
                                    v8::Global<v8::Module>(isolate, module)))
              .second);
    CHECK(d->module_to_specifier_map
              .insert(std::make_pair(v8::Global<v8::Module>(isolate, module), file_name))
              .second);

    std::string dir_name = DirName(file_name);
    
    v8::Local<v8::FixedArray> module_requests = module->GetModuleRequests();
    for (int i = 0, length = module_requests->Length(); i < length; ++i)
    {
      v8::Local<v8::ModuleRequest> module_request =
          module_requests->Get(context, i).As<v8::ModuleRequest>();
      v8::Local<v8::String> name = module_request->GetSpecifier();
      v8::Local<v8::FixedArray> import_assertions = module_request->GetImportAssertions();
      std::string absolute_path =
        NormalizePath(ToSTLString(isolate, name), dir_name);
      if (d->module_map.count(absolute_path)) {
        continue;
      }
      if (FetchModuleTree(module, context, absolute_path)
            .IsEmpty()) {
        return v8::MaybeLocal<v8::Module>();
      }
    }
    return module;
  }

} // namespace ccf