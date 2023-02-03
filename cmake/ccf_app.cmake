# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(ALLOWED_TARGETS "sgx;snp;virtual")

if(NOT DEFINED COMPILE_TARGET)
  set(COMPILE_TARGET
      "sgx"
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

include(${CCF_DIR}/cmake/open_enclave.cmake)

list(APPEND COMPILE_LIBCXX -stdlib=libc++)
if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 9)
  list(APPEND LINK_LIBCXX -lc++ -lc++abi -stdlib=libc++)
else()
  # Clang <9 needs to link libc++fs when using <filesystem>
  list(APPEND LINK_LIBCXX -lc++ -lc++abi -lc++fs -stdlib=libc++)
endif()

# Sign a built enclave library with oesign
function(sign_app_library name app_oe_conf_path enclave_sign_key_path)
  cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS "" "" "INSTALL_LIBS")

  if(TARGET ${name})
    # Produce a debuggable variant. This doesn't need to be signed, but oesign
    # also stamps the other config (heap size etc) which _are_ needed
    set(DEBUG_CONF_NAME ${CMAKE_CURRENT_BINARY_DIR}/${name}.debuggable.conf)

    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.debuggable
      # Copy conf file locally
      COMMAND cp ${app_oe_conf_path} ${DEBUG_CONF_NAME}
      # Remove any existing Debug= lines
      COMMAND sed -i "/^Debug=\.*/d" ${DEBUG_CONF_NAME}
      # Add Debug=1 line
      COMMAND echo "Debug=1" >> ${DEBUG_CONF_NAME}
      COMMAND
        openenclave::oesign sign -e ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so -c
        ${DEBUG_CONF_NAME} -k ${enclave_sign_key_path} -o
        ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.debuggable
      DEPENDS ${name} ${app_oe_conf_path} ${enclave_sign_key_path}
    )

    add_custom_target(
      ${name}_debuggable ALL
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.debuggable
    )

    # Produce a releaseable signed variant. This is NOT debuggable - oegdb
    # cannot be attached
    set(SIGNED_CONF_NAME ${CMAKE_CURRENT_BINARY_DIR}/${name}.signed.conf)
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.signed
      # Copy conf file locally
      COMMAND cp ${app_oe_conf_path} ${SIGNED_CONF_NAME}
      # Remove any existing Debug= lines
      COMMAND sed -i "/^Debug=\.*/d" ${SIGNED_CONF_NAME}
      # Add Debug=0 line
      COMMAND echo "Debug=0" >> ${SIGNED_CONF_NAME}
      COMMAND
        openenclave::oesign sign -e ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so -c
        ${SIGNED_CONF_NAME} -k ${enclave_sign_key_path}
      DEPENDS ${name} ${app_oe_conf_path} ${enclave_sign_key_path}
    )

    add_custom_target(
      ${name}_signed ALL
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.signed
    )

    if(${PARSED_ARGS_INSTALL_LIBS})
      install(FILES ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.debuggable
              DESTINATION lib
      )
      install(FILES ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.signed
              DESTINATION lib
      )
    endif()
  endif()
endfunction()

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

  if(COMPILE_TARGET STREQUAL "sgx")
    set(enc_name ${name}.enclave)

    add_library(${enc_name} SHARED ${PARSED_ARGS_SRCS})

    target_compile_definitions(${enc_name} PUBLIC PLATFORM_SGX)

    target_include_directories(${enc_name} PRIVATE ${PARSED_ARGS_INCLUDE_DIRS})
    target_include_directories(
      ${enc_name} SYSTEM PRIVATE ${PARSED_ARGS_SYSTEM_INCLUDE_DIRS}
    )
    add_warning_checks(${enc_name})
    target_link_libraries(
      ${enc_name} PRIVATE ${PARSED_ARGS_LINK_LIBS_ENCLAVE}
                          ${OE_TARGET_ENCLAVE_CORE_LIBS} ccf.enclave
    )

    set_property(TARGET ${enc_name} PROPERTY POSITION_INDEPENDENT_CODE ON)

    add_lvi_mitigations(${enc_name})

    add_dependencies(${name} ${enc_name})
    if(PARSED_ARGS_DEPS)
      add_dependencies(${enc_name} ${PARSED_ARGS_DEPS})
    endif()

  elseif(COMPILE_TARGET STREQUAL "snp")
    # Build an SNP enclave, loaded as a shared library without OE
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

    if(NOT SAN)
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
    # Build a virtual enclave, loaded as a shared library without OE
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

    if(NOT SAN)
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

# Convenience wrapper to build C-libraries that can be linked in enclave, ie. in
# a CCF application.
if(COMPILE_TARGET STREQUAL "sgx")
  function(add_enclave_library_c name)
    cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS "" "" "")
    set(files ${PARSED_ARGS_UNPARSED_ARGUMENTS})
    add_library(${name} STATIC ${files})
    target_compile_options(${name} PRIVATE -nostdinc)
    target_link_libraries(${name} PRIVATE ${OE_TARGET_LIBC})
    set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)
  endfunction()

  # Convenience wrapper to build C++-libraries that can be linked in enclave,
  # ie. in a CCF application.
  function(add_enclave_library name)
    cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS "" "" "")
    set(files ${PARSED_ARGS_UNPARSED_ARGUMENTS})
    add_library(${name} ${files})
    target_compile_options(${name} PUBLIC -nostdinc -nostdinc++)
    target_compile_definitions(
      ${name} PUBLIC INSIDE_ENCLAVE _LIBCPP_HAS_THREAD_API_PTHREAD
    )
    target_link_libraries(${name} PUBLIC ${OE_TARGET_ENCLAVE_AND_STD} -lgcc)
    set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)
  endfunction()
endif()

function(add_host_library name)
  cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS "" "" "")
  set(files ${PARSED_ARGS_UNPARSED_ARGUMENTS})
  add_library(${name} ${files})
  target_compile_options(${name} PUBLIC ${COMPILE_LIBCXX})
  target_link_libraries(${name} PUBLIC ${LINK_LIBCXX} -lgcc ${OE_HOST_LIBRARY})
  set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)
endfunction()
