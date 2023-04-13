// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"

#ifdef VERBOSE_LOGGING
#  define GOV_TRACE_FMT CCF_LOG_FMT(TRACE, "gov")
#  define GOV_DEBUG_FMT CCF_LOG_FMT(DEBUG, "gov")
#else
#  define GOV_TRACE_FMT(...) ((void)0)
#  define GOV_DEBUG_FMT(...) ((void)0)
#endif

#define GOV_INFO_FMT CCF_LOG_FMT(INFO, "gov")
#define GOV_FAIL_FMT CCF_LOG_FMT(FAIL, "gov")
#define GOV_FATAL_FMT CCF_LOG_FMT(FATAL, "gov")