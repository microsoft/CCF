// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "msgpack/serialization.h"
#include "tracing/trace.h"

namespace request_trace
{
  DECLARE_TRACE_EVENT(empty, "ccf.request");
  DECLARE_TRACE_EVENT(single, "ccf.request", value);
  DECLARE_TRACE_EVENT(request, "ccf.request", path, status, cached);

  struct Nested
  {
    int number;
    bool flag;
  };
  DECLARE_MSGPACK_TYPE(Nested);
  DECLARE_MSGPACK_FIELDS(Nested, number, flag);

  void empty_from_other_translation_unit();
  void single_from_other_translation_unit();
}
