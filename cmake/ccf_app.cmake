# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(ALLOWED_TARGETS "sgx;virtual")

set(COMPILE_TARGETS
    "sgx;virtual"
    CACHE
      STRING
      "List of target compilation platforms. Choose from: ${ALLOWED_TARGETS}"
)

set(IS_VALID_TARGET "FALSE")
foreach(REQUESTED_TARGET ${COMPILE_TARGETS})
  if(${REQUESTED_TARGET} IN_LIST ALLOWED_TARGETS)
    set(IS_VALID_TARGET "TRUE")
  else()
    message(
      FATAL_ERROR
        "${REQUESTED_TARGET} is not a valid target. Choose from: ${ALLOWED_TARGETS}"
    )
  endif()
endforeach()

if((NOT ${IS_VALID_TARGET}))
  message(
    FATAL_ERROR
      "Variable list 'COMPILE_TARGETS' must include at least one supported target. Choose from: ${ALLOWED_TARGETS}"
  )
endif()

# Find OpenEnclave package, preferring local version if found (in the install
# case)
find_package(
  OpenEnclave 0.9 CONFIG PATHS ${CMAKE_CURRENT_LIST_DIR}/../openenclave
  NO_DEFAULT_PATH
)
find_package(OpenEnclave 0.9 CONFIG REQUIRED)
# As well as pulling in openenclave:: targets, this sets variables which can be
# used for our edge cases (eg - for virtual libraries). These do not follow the
# standard naming patterns, for example use OE_INCLUDEDIR rather than
# OpenEnclave_INCLUDE_DIRS

# Sign a built enclave library with oesign
function(sign_app_library name app_oe_conf_path enclave_sign_key_path)
  cmake_parse_arguments(PARSE_ARGV 1 PARSED_ARGS "" "" "INSTALL_LIBS")

  if(TARGET ${name})
    # Produce a debuggable variant. This doesn't need to be signed, but oesign
    # also stamps the other config (heap size etc) which _are_ needed
    set(DEBUG_CONF_NAME ${CMAKE_CURRENT_BINARY_DIR}/${name}.debuggable.conf)

    # Need to put in a temp folder, as oesign has a fixed output path, so
    # multiple calls will force unnecessary rebuilds
    set(TMP_FOLDER ${CMAKE_CURRENT_BINARY_DIR}/${name}_tmp)
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.debuggable
      COMMAND cp ${app_oe_conf_path} ${DEBUG_CONF_NAME}
      COMMAND echo "Debug=1" >> ${DEBUG_CONF_NAME}
      COMMAND mkdir -p ${TMP_FOLDER}
      COMMAND ln -s ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so
              ${TMP_FOLDER}/lib${name}.so
      COMMAND openenclave::oesign sign -e ${TMP_FOLDER}/lib${name}.so -c
              ${DEBUG_CONF_NAME} -k ${enclave_sign_key_path}
      COMMAND mv ${TMP_FOLDER}/lib${name}.so.signed
              ${CMAKE_CURRENT_BINARY_DIR}/lib${name}.so.debuggable
      COMMAND rm -rf ${TMP_FOLDER}
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
      COMMAND cp ${app_oe_conf_path} ${SIGNED_CONF_NAME}
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

# Util functions used by add_ccf_app and others
function(enable_quote_code name)
  if(QUOTES_ENABLED)
    target_compile_definitions(${name} PUBLIC -DGET_QUOTE)
  endif()
endfunction()

function(add_san name)
  if(SAN)
    target_compile_options(
      ${name}
      PRIVATE -fsanitize=undefined,address -fno-omit-frame-pointer
              -fno-sanitize-recover=all -fno-sanitize=function
              -fsanitize-blacklist=${CCF_DIR}/src/ubsan.blacklist
    )
    target_link_libraries(
      ${name}
      PRIVATE -fsanitize=undefined,address -fno-omit-frame-pointer
              -fno-sanitize-recover=all -fno-sanitize=function
              -fsanitize-blacklist=${CCF_DIR}/src/ubsan.blacklist
    )
  endif()
endfunction()

separate_arguments(
  COVERAGE_FLAGS UNIX_COMMAND "-fprofile-instr-generate -fcoverage-mapping"
)
separate_arguments(
  COVERAGE_LINK UNIX_COMMAND "-fprofile-instr-generate -fcoverage-mapping"
)

function(enable_coverage name)
  if(COVERAGE)
    target_compile_options(${name} PRIVATE ${COVERAGE_FLAGS})
    target_link_libraries(${name} PRIVATE ${COVERAGE_LINK})
  endif()
endfunction()

function(use_client_mbedtls name)
  target_include_directories(${name} PRIVATE ${CLIENT_MBEDTLS_INCLUDE_DIR})
  target_link_libraries(${name} PRIVATE ${CLIENT_MBEDTLS_LIBRARIES})
endfunction()

function(use_oe_mbedtls name)
  target_link_libraries(
    ${name} PRIVATE openenclave::oeenclave openenclave::oelibcxx
                    openenclave::oelibc
  )
endfunction()

# Enclave library wrapper
function(add_ccf_app name)

  cmake_parse_arguments(
    PARSE_ARGV 1 PARSED_ARGS "" ""
    "SRCS;INCLUDE_DIRS;LINK_LIBS_ENCLAVE;LINK_LIBS_VIRTUAL;DEPS;INSTALL_LIBS"
  )
  add_custom_target(${name} ALL)

  if("sgx" IN_LIST COMPILE_TARGETS)
    set(enc_name ${name}.enclave)

    add_library(${enc_name} SHARED ${PARSED_ARGS_SRCS})

    target_include_directories(
      ${enc_name} SYSTEM PRIVATE ${PARSED_ARGS_INCLUDE_DIRS}
    )

    target_link_libraries(
      ${enc_name}
      PRIVATE ${PARSED_ARGS_LINK_LIBS_ENCLAVE}
              # These oe libraries must be linked in correct order, so they are
              # re-declared here
              openenclave::oeenclave
              openenclave::oecore
              openenclave::oesyscall
              ccf.enclave
    )

    set_property(TARGET ${enc_name} PROPERTY POSITION_INDEPENDENT_CODE ON)

    add_dependencies(${name} ${enc_name})
    if(PARSED_ARGS_DEPS)
      add_dependencies(${enc_name} ${PARSED_ARGS_DEPS})
    endif()
  endif()

  if("virtual" IN_LIST COMPILE_TARGETS)
    # Build a virtual enclave, loaded as a shared library without OE
    set(virt_name ${name}.virtual)

    add_library(${virt_name} SHARED ${PARSED_ARGS_SRCS})

    target_include_directories(
      ${virt_name} SYSTEM PRIVATE ${PARSED_ARGS_INCLUDE_DIRS}
    )

    target_link_libraries(
      ${virt_name} PRIVATE ${PARSED_ARGS_LINK_LIBS_VIRTUAL} ccf.virtual
    )

    set_property(TARGET ${virt_name} PROPERTY POSITION_INDEPENDENT_CODE ON)

    enable_coverage(${virt_name})
    use_client_mbedtls(${virt_name})
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
function(add_enclave_library_c name files)
  add_library(${name} STATIC ${files})
  target_compile_options(${name} PRIVATE -nostdinc)
  target_link_libraries(${name} PRIVATE openenclave::oelibc)
  set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE ON)
endfunction()
