# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if(USE_SNMALLOC)
  set(SNMALLOC_BUILD_TESTING OFF)
  set(SNMALLOC_STATIC_LIBRARY_PREFIX "")
  add_subdirectory(3rdparty/internal/snmalloc EXCLUDE_FROM_ALL)

  install(
    TARGETS snmallocshim-static
    EXPORT ccf
    DESTINATION lib
  )

endif()
