## How to write templates

### Storing native pointers as internal fields in JavaScript objects

`template.h` provides helper functions to set and get native pointers.

Conventions:

- If the JavaScript object relies on the caller to keep the resource alive, then the `wrap()` function of a template class receives the resource as **raw pointer**. This indicates to the caller that care must be taken, since raw pointers are not generally used.
- If the JavaScript object does not rely on the caller to keep the resource alive, then the `wrap()` function receives the resource as **const reference**. An example is `receipt.h`.

### Expose a native function to JS

```cpp
void log(const v8::FunctionCallbackInfo<v8::Value>& info)
{ ... }

tmpl->Set(
    v8_util::to_v8_istr(isolate, "data"),
    v8::FunctionTemplate::New(isolate, log)).Check();
```

When, `obj.log` is accessed, then the function is returned, which means it can be called with `obj.log()`.

Note: The above doesn't use the template cache for the function template. This is fine because the object template that contains the function template is cached.

### Expose a constant to JS

```cpp
tmpl->Set(
    v8_util::to_v8_istr(isolate, "name"),
    v8_util::to_v8_istr(isolate, "ECMA")).Check();
```

When, `obj.name` is accessed, then the constant value is returned, here a string.

### Expose native read-only data to JS

```cpp
void get_data(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
{ ... }

tmpl->SetLazyDataProperty(
    v8_util::to_v8_istr(isolate, "data"),
    get_data);
```

When `obj.data` is accessed, then `get_data` is called and its value is cached and returned. Any further accesses return the cached value and will not call `get_data` again.

Note: Caching only affects the immediate value returned. Child objects and their properties may or may not use caching.

Note: If caching is undesired, use `SetAccessor` as described below for exposing native writable data (without providing a setter).

### Expose native writable data to JS

```cpp
void get_data(v8::Local<v8::String> name, const v8::PropertyCallbackInfo<v8::Value>& info)
{ ... }

void set_data(v8::Local<v8::String> name, v8::Local<v8::Value> value, const v8::PropertyCallbackInfo<v8::Value>& info)
{ ... }

tmpl->SetAccessor(
    v8_util::to_v8_istr(isolate, "data"),
    get_data, set_data);
```

When `obj.data` is accessed, then `get_data` is called and its value is returned. Any further accesses will call `get_data` again. When `obj.data` is set, then `set_data` is called with the value being set.

Note: The method `SetNativeDataProperty` defined in `Template` is functionally equivalent. `SetAccessor` is defined in `ObjectTemplate`.

### Expose native dynamic key-value pairs as JS object properties

```cpp
void get_property(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
{ ... }

tmpl->SetHandler(v8::NamedPropertyHandlerConfiguration(get_property));
```

When a property of `obj` is accessed, either via `obj.<name>` or `obj['<name>']`, then `get_property` is called. Keys are assumed to be strings or translatable to strings. Repeated accesses to the same property will call `get_property` again.

Note: `NamedPropertyHandlerConfiguration` has additional optional arguments for configuring setter, query, deleter, enumerator callbacks.

### Expose a native array to JS

```cpp
void get_value(uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info)
{ ... }

tmpl->SetHandler(v8::IndexedPropertyHandlerConfiguration(get_value));
```

When `obj[i]` is accessed, then `get_value` is called. Keys are assumed to be integers or translatable to integers. Repeated accesses of the same index will call `get_value` again.

Note: `IndexedPropertyHandlerConfiguration` has additional optional arguments for configuring setter, query, deleter, enumerator callbacks.
