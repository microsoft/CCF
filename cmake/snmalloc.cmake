# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if(USE_SNMALLOC)
  set(SNMALLOC_BUILD_TESTING OFF)
  set(SNMALLOC_STATIC_LIBRARY_PREFIX "")
  add_subdirectory(3rdparty/exported/snmalloc EXCLUDE_FROM_ALL)

  # We move snmalloc includes under 3rdparty/ when installing ccf, so overwrite
  # the existing value with what we want.
  set_target_properties(snmalloc PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "")
  target_include_directories(
    snmalloc INTERFACE $<INSTALL_INTERFACE:include/3rdparty/snmalloc>
  )
  # Only including -static leads to complaints about missing dependency on
  # snmalloc::snmalloc. To avoid doing this, snmalloc's cmake has to be patched.
  install(
    TARGETS snmalloc snmallocshim-static
    EXPORT ccf
    DESTINATION lib
  )

endif()
