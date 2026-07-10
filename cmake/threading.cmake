# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# Minimal foundational library owning the thread-id support that the logger
# headers depend on (ccf::threading::get_current_thread_id and friends).
#
# Keeping this in its own library lets every logger user resolve the symbol by
# depending on ccf_threading, without having to link libccf. This is what
# avoids the circular dependency tracked in
# https://github.com/microsoft/CCF/issues/7596: ccfcrypto (and the other
# low-level libraries) use the logger, but are themselves dependencies of ccf.
add_ccf_static_library(
  ccf_threading
  SRCS ${CCF_DIR}/src/threading/thread_ids.cpp
)
