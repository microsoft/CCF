// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/core/wrapped_value.h"

#include "ccf/js/core/constants.h"

namespace ccf::js::core
{
  JSWrappedValue::JSWrappedValue() :
    ctx(nullptr),
    val(ccf::js::core::constants::Null)
  {}
  JSWrappedValue::JSWrappedValue(JSContext* ctx, JSValue&& val) :
    ctx(ctx),
    val(std::move(val)) // NOLINT(performance-move-const-arg)
  {}

  JSWrappedValue::JSWrappedValue(JSContext* ctx, const JSValue& value) :
    ctx(ctx),
    val(JS_DupValue(ctx, value))
  {}

  JSWrappedValue::JSWrappedValue(const JSWrappedValue& other) :
    ctx(other.ctx),
    val(JS_DupValue(ctx, other.val))
  {}

  JSWrappedValue::JSWrappedValue(JSWrappedValue&& other) noexcept :
    ctx(other.ctx),
    val(other.val)
  {
    other.val = ccf::js::core::constants::Null;
  }

  JSWrappedValue::~JSWrappedValue()
  {
    if ((ctx != nullptr) && (JS_VALUE_GET_TAG(val) != JS_TAG_MODULE))
    {
      JS_FreeValue(ctx, val);
    }
  }

  JSWrappedValue& JSWrappedValue::operator=(const JSWrappedValue& other)
  {
    if (this != &other)
    {
      ctx = other.ctx;
      val = JS_DupValue(ctx, other.val);
    }
    return *this;
  }

  JSWrappedValue JSWrappedValue::operator[](const char* prop) const
  {
    return {ctx, JS_GetPropertyStr(ctx, val, prop)};
  }

  JSWrappedValue JSWrappedValue::operator[](const std::string& prop) const
  {
    return (*this)[prop.c_str()];
  }

  JSWrappedValue JSWrappedValue::operator[](uint32_t i) const
  {
    return {ctx, JS_GetPropertyUint32(ctx, val, i)};
  }

  // NOLINTBEGIN(cppcoreguidelines-rvalue-reference-param-not-moved)
  int JSWrappedValue::set(const char* prop, JSWrappedValue&& value) const
  // NOLINTEND(cppcoreguidelines-rvalue-reference-param-not-moved)
  {
    int rc = JS_SetPropertyStr(ctx, val, prop, value.val);
    if (rc == 1)
    {
      value.val = ccf::js::core::constants::Null;
    }
    return rc;
  }

  // NOLINTBEGIN(cppcoreguidelines-rvalue-reference-param-not-moved)
  int JSWrappedValue::set_getter(
    const char* prop, JSWrappedValue&& getter) const
  // NOLINTEND(cppcoreguidelines-rvalue-reference-param-not-moved)
  {
    JSAtom size_atom = JS_NewAtom(ctx, prop);
    if (size_atom == JS_ATOM_NULL)
    {
      getter.val = ccf::js::core::constants::Null;
      return -1;
    }

    // NB: Where other calls check the return code to determine whether they
    // are responsible for freeing, this call unconditionally frees the getter
    // arg, so we call .take() to always drop our local owning reference
    int rc = JS_DefinePropertyGetSet(
      ctx,
      val,
      size_atom,
      getter.take(),
      ccf::js::core::constants::Undefined,
      0);

    JS_FreeAtom(ctx, size_atom);

    return rc;
  }

  int JSWrappedValue::set(const std::string& prop, JSWrappedValue&& value) const
  {
    return set(prop.c_str(), std::move(value));
  }

  int JSWrappedValue::set(const std::string& prop, JSValue&& value) const
  {
    // NOLINTBEGIN(performance-move-const-arg)
    return JS_SetPropertyStr(ctx, val, prop.c_str(), std::move(value));
    // NOLINTEND(performance-move-const-arg)
  }

  int JSWrappedValue::set_null(const std::string& prop) const
  {
    return JS_SetPropertyStr(
      ctx, val, prop.c_str(), ccf::js::core::constants::Null);
  }

  int JSWrappedValue::set_uint32(const std::string& prop, uint32_t i) const
  {
    return JS_SetPropertyStr(ctx, val, prop.c_str(), JS_NewUint32(ctx, i));
  }

  int JSWrappedValue::set_int64(const std::string& prop, int64_t i) const
  {
    return JS_SetPropertyStr(ctx, val, prop.c_str(), JS_NewInt64(ctx, i));
  }

  int JSWrappedValue::set_bool(const std::string& prop, bool b) const
  {
    return JS_SetPropertyStr(
      ctx, val, prop.c_str(), JS_NewBool(ctx, static_cast<int>(b)));
  }

  // NOLINTBEGIN(readability-make-member-function-const,cppcoreguidelines-rvalue-reference-param-not-moved)
  int JSWrappedValue::set_at_index(uint32_t index, JSWrappedValue&& value)
  // NOLINTEND(readability-make-member-function-const,cppcoreguidelines-rvalue-reference-param-not-moved)
  {
    int rc =
      JS_DefinePropertyValueUint32(ctx, val, index, value.val, JS_PROP_C_W_E);
    if (rc == 1)
    {
      value.val = ccf::js::core::constants::Null;
    }
    return rc;
  }

  bool JSWrappedValue::is_exception() const
  {
    return JS_IsException(val) != 0;
  }

  bool JSWrappedValue::is_error() const
  {
    return JS_IsError(ctx, val) != 0;
  }

  bool JSWrappedValue::is_obj() const
  {
    return JS_IsObject(val) != 0;
  }

  bool JSWrappedValue::is_str() const
  {
    return JS_IsString(val) != 0;
  }

  bool JSWrappedValue::is_true() const
  {
    int rc = JS_ToBool(ctx, val);
    return rc > 0;
  }

  bool JSWrappedValue::is_undefined() const
  {
    return JS_IsUndefined(val) != 0;
  }

  JSValue JSWrappedValue::take()
  {
    JSValue r = val;
    val = ccf::js::core::constants::Null;
    return r;
  }
}
