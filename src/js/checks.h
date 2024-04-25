// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define JS_CHECK_EXC(val) \
  do \
  { \
    if (val.is_exception()) \
    { \
      return val.take(); \
    } \
  } while (0)

#define JS_CHECK_SET(val) \
  do \
  { \
    if (val != 1) \
    { \
      return ccf::js::constants::Exception; \
    } \
  } while (0)
