// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/worker.h"

#include <stdexcept>

__attribute__((noinline)) void throw_from_installed_consumer()
{
  throw std::runtime_error("installed consumer");
}

int main()
{
  ccf::logger::config::default_init();
  try
  {
    throw_from_installed_consumer();
  }
  catch (const std::exception& e)
  {
    ccf::tasks::dump_stacktrace(e.what());
  }
}
