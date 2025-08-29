# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if(USE_SNMALLOC)
  set(SNMALLOC_BUILD_TESTING OFF)
  set(SNMALLOC_STATIC_LIBRARY_PREFIX "")
  add_subdirectory(3rdparty/internal/snmalloc EXCLUDE_FROM_ALL)

  if(PACKAGING)
    # We only need snmalloc's includes to build CCF, users shall not see any.
    set_target_properties(snmalloc PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "")
  endif()

  # Only including -static leads to complaints about missing dependency on
  # snmalloc::snmalloc. To avoid doing this, snmalloc's cmake has to be patched.
  install(
    TARGETS snmalloc snmallocshim-static
    EXPORT ccf
    DESTINATION lib
  )

endif()
