// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "tracing/test/events.h"

namespace request_trace
{
  void empty_from_other_translation_unit()
  {
    empty();
  }

  void single_from_other_translation_unit()
  {
    single(Nested{7, false});
  }
}
