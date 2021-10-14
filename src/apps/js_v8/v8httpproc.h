// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Silence error: 'V8_CC_MSVC' is not defined
#define V8_CC_MSVC 0
#include <v8.h>
#include <libplatform/libplatform.h>

#include <cstdlib>
#include <map>
#include <string>

using std::map;
using std::pair;
using std::string;

using v8::Context;
using v8::EscapableHandleScope;
using v8::External;
using v8::Function;
using v8::FunctionTemplate;
using v8::Global;
using v8::HandleScope;
using v8::Isolate;
using v8::Local;
using v8::MaybeLocal;
using v8::Name;
using v8::NamedPropertyHandlerConfiguration;
using v8::NewStringType;
using v8::Object;
using v8::ObjectTemplate;
using v8::PropertyCallbackInfo;
using v8::Script;
using v8::String;
using v8::TryCatch;
using v8::Value;

// These interfaces represent an existing request processing interface.
// The idea is to imagine a real application that uses these interfaces
// and then add scripting capabilities that allow you to interact with
// the objects through JavaScript.

/**
 * A simplified http request.
 */
class HttpRequest {
 public:
  virtual ~HttpRequest() { }
  virtual const string& Path() = 0;
  virtual const string& Referrer() = 0;
  virtual const string& Host() = 0;
  virtual const string& UserAgent() = 0;
};


/**
 * The abstract superclass of http request processors.
 */
class HttpRequestProcessor {
 public:
  virtual ~HttpRequestProcessor() { }

  // Initialize this processor.  The map contains options that control
  // how requests should be processed.
  virtual bool Initialize(map<string, string>* options,
                          map<string, string>* output) = 0;

  // Process a single request.
  virtual bool Process(HttpRequest* req) = 0;

  static void Log(const char* event);
};


/**
 * An http request processor that is scriptable using JavaScript.
 */
class JsHttpRequestProcessor : public HttpRequestProcessor {
 public:
  // Creates a new processor that processes requests by invoking the
  // Process function of the JavaScript script given as an argument.
  JsHttpRequestProcessor(Isolate* isolate, Local<String> script)
      : isolate_(isolate), script_(script) {}
  virtual ~JsHttpRequestProcessor();

  virtual bool Initialize(map<string, string>* opts,
                          map<string, string>* output);
  virtual bool Process(HttpRequest* req);

 private:
  // Execute the script associated with this processor and extract the
  // Process function.  Returns true if this succeeded, otherwise false.
  bool ExecuteScript(Local<String> script);

  // Wrap the options and output map in a JavaScript objects and
  // install it in the global namespace as 'options' and 'output'.
  bool InstallMaps(map<string, string>* opts, map<string, string>* output);

  // Constructs the template that describes the JavaScript wrapper
  // type for requests.
  static Local<ObjectTemplate> MakeRequestTemplate(Isolate* isolate);
  static Local<ObjectTemplate> MakeMapTemplate(Isolate* isolate);

  // Callbacks that access the individual fields of request objects.
  static void GetPath(Local<String> name,
                      const PropertyCallbackInfo<Value>& info);
  static void GetReferrer(Local<String> name,
                          const PropertyCallbackInfo<Value>& info);
  static void GetHost(Local<String> name,
                      const PropertyCallbackInfo<Value>& info);
  static void GetUserAgent(Local<String> name,
                           const PropertyCallbackInfo<Value>& info);

  // Callbacks that access maps
  static void MapGet(Local<Name> name, const PropertyCallbackInfo<Value>& info);
  static void MapSet(Local<Name> name, Local<Value> value,
                     const PropertyCallbackInfo<Value>& info);

  // Utility methods for wrapping C++ objects as JavaScript objects,
  // and going back again.
  Local<Object> WrapMap(map<string, string>* obj);
  static map<string, string>* UnwrapMap(Local<Object> obj);
  Local<Object> WrapRequest(HttpRequest* obj);
  static HttpRequest* UnwrapRequest(Local<Object> obj);

  Isolate* GetIsolate() { return isolate_; }

  Isolate* isolate_;
  Local<String> script_;
  Global<Context> context_;
  Global<Function> process_;
  static Global<ObjectTemplate> request_template_;
  static Global<ObjectTemplate> map_template_;
};