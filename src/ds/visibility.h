// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef EXPORT_THREAD_LOCALS
#  define VISIBILITY_SPEC __attribute__((visibility("default")))
#else
#  define VISIBILITY_SPEC __attribute__((visibility("hidden")))
#endif
