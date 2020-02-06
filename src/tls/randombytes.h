// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <stddef.h>

#include "entropy.h"

void randombytes(void *buf, size_t n)
{
  printf("Calling randombytes!\n");

  auto entropy = tls::create_entropy();
  entropy->random((unsigned char*)buf, n);
}

