# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Minimal foundational library owning the thread-id support that the logger
# headers depend on (ccf::threading::get_current_thread_id and friends).
#
# Keeping this in its own library lets every logger user resolve the symbol by
# depending on ccf_threading, without having to link libccf.
add_ccf_static_library(
  ccf_threading
  SRCS ${CCF_DIR}/src/threading/thread_ids.cpp
)
