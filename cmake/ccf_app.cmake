# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(ALLOWED_TARGETS "snp;virtual")

if(NOT DEFINED COMPILE_TARGET)
  set(COMPILE_TARGET
      "snp"
      CACHE STRING
            "Target compilation platforms, Choose from: ${ALLOWED_TARGETS}"
  )
endif()

if(NOT COMPILE_TARGET IN_LIST ALLOWED_TARGETS)
  message(
    FATAL_ERROR
      "${REQUESTED_TARGET} is not a valid target. Choose from: ${ALLOWED_TARGETS}"
  )
endif()
message(STATUS "Compile target platform: ${COMPILE_TARGET}")

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
    PARSE_ARGV
    1
    PARSED_ARGS
    ""
    ""
    "SRCS;INCLUDE_DIRS;SYSTEM_INCLUDE_DIRS;LINK_LIBS_ENCLAVE;LINK_LIBS_VIRTUAL;LINK_LIBS_SNP;DEPS;INSTALL_LIBS"
  )
  add_custom_target(${name} ALL)

  if(COMPILE_TARGET STREQUAL "snp")
    # Build an SNP enclave, loaded as a shared library
    set(snp_name ${name}.snp)

    add_library(${snp_name} SHARED ${PARSED_ARGS_SRCS})

    target_compile_definitions(${snp_name} PUBLIC PLATFORM_SNP)

    target_include_directories(${snp_name} PRIVATE ${PARSED_ARGS_INCLUDE_DIRS})
    target_include_directories(
      ${snp_name} SYSTEM PRIVATE ${PARSED_ARGS_SYSTEM_INCLUDE_DIRS}
    )
    add_warning_checks(${snp_name})

    target_link_libraries(
      ${snp_name} PRIVATE ${PARSED_ARGS_LINK_LIBS_SNP} ccf.snp
    )

    if(NOT (SAN OR TSAN))
      target_link_options(${snp_name} PRIVATE LINKER:--no-undefined)
    endif()

    target_link_options(
      ${snp_name} PRIVATE
      LINKER:--undefined=enclave_create_node,--undefined=enclave_run
    )

    set_property(TARGET ${snp_name} PROPERTY POSITION_INDEPENDENT_CODE ON)

    add_san(${snp_name})

    add_dependencies(${name} ${snp_name})
    if(PARSED_ARGS_DEPS)
      add_dependencies(${snp_name} ${PARSED_ARGS_DEPS})
    endif()

    if(${PARSED_ARGS_INSTALL_LIBS})
      install(TARGETS ${snp_name} DESTINATION lib)
    endif()

  elseif(COMPILE_TARGET STREQUAL "virtual")
    # Build a virtual enclave, loaded as a shared library
    set(virt_name ${name}.virtual)

    add_library(${virt_name} SHARED ${PARSED_ARGS_SRCS})

    target_compile_definitions(${virt_name} PUBLIC PLATFORM_VIRTUAL)

    target_include_directories(${virt_name} PRIVATE ${PARSED_ARGS_INCLUDE_DIRS})
    target_include_directories(
      ${virt_name} SYSTEM PRIVATE ${PARSED_ARGS_SYSTEM_INCLUDE_DIRS}
    )
    add_warning_checks(${virt_name})

    target_link_libraries(
      ${virt_name} PRIVATE ${PARSED_ARGS_LINK_LIBS_VIRTUAL} ccf.virtual
    )

    if(NOT (SAN OR TSAN))
      target_link_options(${virt_name} PRIVATE LINKER:--no-undefined)
    endif()

    target_link_options(
      ${virt_name} PRIVATE
      LINKER:--undefined=enclave_create_node,--undefined=enclave_run
    )

    set_property(TARGET ${virt_name} PROPERTY POSITION_INDEPENDENT_CODE ON)

    add_san(${virt_name})

    add_dependencies(${name} ${virt_name})
    if(PARSED_ARGS_DEPS)
      add_dependencies(${virt_name} ${PARSED_ARGS_DEPS})
    endif()

    if(${PARSED_ARGS_INSTALL_LIBS})
      install(TARGETS ${virt_name} DESTINATION lib)
    endif()
  endif()
endfunction()

function(add_host_library name)
  cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS "" "" "")
  set(files ${PARSED_ARGS_UNPARSED_ARGUMENTS})
  add_library(${name} ${files})
  target_compile_options(${name} PUBLIC ${COMPILE_LIBCXX})
  set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)
endfunction()
