// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/core/constants.h"

#include <quickjs/quickjs.h>
#include <string>

namespace ccf::js::core
{
  struct JSWrappedValue
  {
    JSContext* ctx;
    JSValue val;

    JSWrappedValue();
    JSWrappedValue(JSContext* ctx, JSValue&& val);
    JSWrappedValue(JSContext* ctx, const JSValue& value);
    JSWrappedValue(const JSWrappedValue& other);
    JSWrappedValue(JSWrappedValue&& other) noexcept;
    ~JSWrappedValue();

    JSWrappedValue& operator=(const JSWrappedValue& other);

    JSWrappedValue operator[](const char* prop) const;

    JSWrappedValue operator[](const std::string& prop) const;

    JSWrappedValue operator[](uint32_t i) const;

    int set(const char* prop, JSWrappedValue&& value) const;

    int set_getter(const char* prop, JSWrappedValue&& getter) const;

    int set(const std::string& prop, JSWrappedValue&& value) const;

    int set(const std::string& prop, JSValue value) const;

    int set_null(const std::string& prop) const;

    int set_uint32(const std::string& prop, uint32_t i) const;

    int set_int64(const std::string& prop, int64_t i) const;

    int set_bool(const std::string& prop, bool b) const;

    int set_at_index(uint32_t index, JSWrappedValue&& value);

    bool is_exception() const;

    bool is_error() const;

    bool is_obj() const;

    bool is_str() const;

    bool is_true() const;

    bool is_undefined() const;

    JSValue take();
  };
}
