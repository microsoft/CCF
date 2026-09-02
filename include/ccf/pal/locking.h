// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// This header is kept for source compatibility only. The generic locking
// implementation has moved to ccf/ds/locking.h and the ccf::ds namespace,
// to break the crypto -> ds -> pal -> crypto source dependency cycle.
#include "ccf/ccf_deprecated.h"
#include "ccf/ds/locking.h"

namespace ccf::pal
{
  using Mutex CCF_DEPRECATED(
    "Use ccf::ds::Mutex from ccf/ds/locking.h instead") = ccf::ds::Mutex;
  using MutexGuard CCF_DEPRECATED(
    "Use ccf::ds::MutexGuard from ccf/ds/locking.h instead") =
    ccf::ds::MutexGuard;
  using ConditionVariable CCF_DEPRECATED(
    "Use ccf::ds::ConditionVariable from ccf/ds/locking.h instead") =
    ccf::ds::ConditionVariable;
}
