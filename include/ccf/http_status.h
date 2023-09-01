// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <llhttp/llhttp.h>

using http_status = llhttp_status;

// enum http_status
// {
// #define XX(num, name, string) HTTP_STATUS_##name = num,
//   HTTP_STATUS_MAP(XX)
// #undef XX
// };

/* Returns a string version of the HTTP status code. */
static inline const char* http_status_str(http_status s)
{
  return llhttp_status_name(s);
}