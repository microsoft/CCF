// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/framework_logger.h"

#define GOV_TRACE_FMT CCF_LOG_FMT(TRACE, "gov")
#define GOV_DEBUG_FMT CCF_LOG_FMT(DEBUG, "gov")

#define GOV_INFO_FMT CCF_LOG_FMT(INFO, "gov")
#define GOV_FAIL_FMT CCF_LOG_FMT(FAIL, "gov")
#define GOV_FATAL_FMT CCF_LOG_FMT(FATAL, "gov")