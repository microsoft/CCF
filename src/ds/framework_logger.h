// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"

// Defines the LOG_*_FMT macros that should be used for logging by
// framework-internal components. Alternatively, replace with macros which add a
// system-specific tag.

namespace ccf::logger
{
#define LOG_TRACE_FMT CCF_LOG_FMT(TRACE, "")
#define LOG_DEBUG_FMT CCF_LOG_FMT(DEBUG, "")
#define LOG_INFO_FMT CCF_LOG_FMT(INFO, "")
#define LOG_FAIL_FMT CCF_LOG_FMT(FAIL, "")
#define LOG_FATAL_FMT CCF_LOG_FMT(FATAL, "")
}
