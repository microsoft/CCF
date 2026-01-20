# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

if(USE_LIBCXX)
  list(APPEND COMPILE_LIBCXX -stdlib=libc++)
  list(APPEND LINK_LIBCXX -lc++ -lc++abi -stdlib=libc++)

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_compile_options(-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG)
  elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    add_compile_options(-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST)
  endif()
endif()

# Enclave library wrapper
function(add_ccf_app name)

  cmake_parse_arguments(
    PARSE_ARGV 1 PARSED_ARGS "" ""
    "SRCS;INCLUDE_DIRS;SYSTEM_INCLUDE_DIRS;LINK_LIBS;DEPS;INSTALL_LIBS"
  )

  # Build app executable
  add_executable(${name} ${PARSED_ARGS_SRCS})

  target_include_directories(${name} PRIVATE ${PARSED_ARGS_INCLUDE_DIRS})
  target_include_directories(
    ${name} SYSTEM PRIVATE ${PARSED_ARGS_SYSTEM_INCLUDE_DIRS}
  )
  add_warning_checks(${name})

  target_link_libraries(
    ${name} PRIVATE ${PARSED_ARGS_LINK_LIBS} ccf_launcher ccf
  )

  if(NOT (SAN OR TSAN))
    target_link_options(${name} PRIVATE LINKER:--no-undefined)
  endif()

  # Tracked in https://github.com/microsoft/CCF/issues/7596
  # Workaround for circular dependency between ccf.a and ccfcrypto.a
  target_link_options(
    ${name} PRIVATE
    LINKER:--undefined=_ZN3ccf9threading21get_current_thread_idEv
  )

  set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)

  add_san(${name})
  add_tidy(${name})

  if(USE_SNMALLOC)
    target_link_libraries(${name} INTERFACE snmallocshim-static)
  endif()

  add_dependencies(${name} ${name})
  if(PARSED_ARGS_DEPS)
    add_dependencies(${name} ${PARSED_ARGS_DEPS})
  endif()

  if(${PARSED_ARGS_INSTALL_LIBS})
    install(TARGETS ${name} DESTINATION bin)
  endif()
endfunction()

function(add_ccf_static_library name)
  cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS "" "" "SRCS;LINK_LIBS")

  add_library(${name} STATIC ${PARSED_ARGS_SRCS})

  target_link_libraries(${name} PUBLIC ${PARSED_ARGS_LINK_LIBS} ${LINK_LIBCXX})

  target_compile_options(${name} PUBLIC ${COMPILE_LIBCXX})

  set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)

  add_san(${name})
  add_tidy(${name})
  add_warning_checks(${name})

  install(
    TARGETS ${name}
    EXPORT ccf
    DESTINATION lib
  )

  if(USE_SNMALLOC)
    target_link_libraries(${name} INTERFACE snmallocshim-static)
  endif()
endfunction()
