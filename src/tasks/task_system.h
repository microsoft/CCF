// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/resumable.h"

namespace ccf::tasks
{
  Resumable pause_current_task();
  void resume_task(Resumable&& resumable);
}