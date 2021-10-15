// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// This is a local modified copy of v8/samples/process.cc from version
// 9.4.146.17. It will not work with earlier of later versions of V8,
// so this exact version needs to be checked out, and changes will need
// to be made if we want to upgrade.

// Silence error: 'V8_CC_MSVC' is not defined
#define V8_CC_MSVC 0
#include <v8.h>
#include <libplatform/libplatform.h>

#include <cstdlib>
#include <map>
#include <string>

// These interfaces represent an existing request processing interface.
// The idea is to imagine a real application that uses these interfaces
// and then add scripting capabilities that allow you to interact with
// the objects through Javav8::Script.

/**
 * The abstract superclass of http requests.
 */
struct HttpRequest {
  virtual ~HttpRequest() { }
  virtual const std::string& Path() = 0;
  virtual const std::string& Referrer() = 0;
  virtual const std::string& Host() = 0;
  virtual const std::string& UserAgent() = 0;
};

/**
 * A simple string-based http request.
 */
class StringHttpRequest : public HttpRequest {
 public:
  StringHttpRequest(const string& path,
                    const string& referrer,
                    const string& host,
                    const string& user_agent)
    : path_(path),
      referrer_(referrer),
      host_(host),
      user_agent_(user_agent) { }
  virtual const string& Path() { return path_; }
  virtual const string& Referrer() { return referrer_; }
  virtual const string& Host() { return host_; }
  virtual const string& UserAgent() { return user_agent_; }
 private:
  string path_;
  string referrer_;
  string host_;
  string user_agent_;
};

/// A map of strings for keys and values.
using StringMap = std::map<std::string, std::string>;

/**
 * The abstract superclass of http request processors.
 */
struct HttpRequestProcessor {
  virtual ~HttpRequestProcessor() { }

  // Initialize this processor.  The map contains options that control
  // how requests should be processed.
  virtual bool Initialize(StringMap* options,
                          StringMap* output) = 0;

  // Process a single request.
  virtual bool Process(HttpRequest* req) = 0;

  static void Log(const char* event);
};

/**
 * An http request processor that is scriptable using Javav8::Script.
 */
struct JsHttpRequestProcessor : public HttpRequestProcessor {
  // Creates a new processor that processes requests by invoking the
  // Process function of the Javav8::Script script given as an argument.
  JsHttpRequestProcessor(v8::Isolate* isolate, v8::Local<v8::String> script)
      : isolate_(isolate), script_(script) {}
  virtual ~JsHttpRequestProcessor();

  virtual bool Initialize(StringMap* opts,
                          StringMap* output);
  virtual bool Process(HttpRequest* req);

 private:
  // Execute the script associated with this processor and extract the
  // Process function.  Returns true if this succeeded, otherwise false.
  bool ExecuteScript(v8::Local<v8::String> script);

  // Wrap the options and output map in a Javav8::Script objects and
  // install it in the global namespace as 'options' and 'output'.
  bool InstallMaps(StringMap* opts, StringMap* output);

  // Constructs the template that describes the Javav8::Script wrapper
  // type for requests.
  static v8::Local<v8::ObjectTemplate> MakeRequestTemplate(v8::Isolate* isolate);
  static v8::Local<v8::ObjectTemplate> MakeMapTemplate(v8::Isolate* isolate);

  // Callbacks that access the individual fields of request objects.
  static void GetPath(v8::Local<v8::String> name,
                      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetReferrer(v8::Local<v8::String> name,
                          const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetHost(v8::Local<v8::String> name,
                      const v8::PropertyCallbackInfo<v8::Value>& info);
  static void GetUserAgent(v8::Local<v8::String> name,
                           const v8::PropertyCallbackInfo<v8::Value>& info);

  // Callbacks that access maps
  static void MapGet(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info);
  static void MapSet(v8::Local<v8::Name> name, v8::Local<v8::Value> value,
                     const v8::PropertyCallbackInfo<v8::Value>& info);

  // Utility methods for wrapping C++ objects as Javav8::Script objects,
  // and going back again.
  v8::Local<v8::Object> WrapMap(StringMap* obj);
  static StringMap* UnwrapMap(v8::Local<v8::Object> obj);
  v8::Local<v8::Object> WrapRequest(HttpRequest* obj);
  static HttpRequest* UnwrapRequest(v8::Local<v8::Object> obj);

  v8::Isolate* GetIsolate() { return isolate_; }

  v8::Isolate* isolate_;
  v8::Local<v8::String> script_;
  v8::Global<v8::Context> context_;
  v8::Global<v8::Function> process_;
  static v8::Global<v8::ObjectTemplate> request_template_;
  static v8::Global<v8::ObjectTemplate> map_template_;
};