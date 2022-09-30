# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This must be done before the `project` command.
if (UNIX)
  if (NOT DEFINED ENV{CC} AND NOT DEFINED CMAKE_C_COMPILER)
    find_program(CMAKE_C_COMPILER clang-10 clang)
  endif ()
  if (NOT DEFINED ENV{CXX} AND NOT DEFINED CMAKE_CXX_COMPILER)
    find_program(CMAKE_CXX_COMPILER clang++-10 clang++)
  endif ()
endif ()

project(ravl LANGUAGES CXX C ASM)

cmake_minimum_required(VERSION 3.14)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(RAVL_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(RAVL_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

option(OE "enable support for Open Enclave attestation reports" ON)
option(SGX "enable support for Intel SGX attestation reports" ON)
option(SEV_SNP "enable support for AMD SEV/SNP attestation reports" ON)
option(TESTS "enable tests" ON)
option(PROFILE "enable profiling" OFF)
option(STATIC "build static library" ON)
option(SHARED "build shared library" OFF)
option(CLI "build the ravl CLI tool" ON)

option(USE_OE_VERIFIER "use the Open Enclave verifier directly (requires Open Enclave SDK)" OFF)

option(OE_TEST_ENCLAVE "enable Open Enclave test enclave (requires Open Enclave SDK)" OFF)
option(SGX_TEST_ENCLAVE "enable SGX test enclave (requires Intel SGX SDK)" OFF)
option(CURL "include CURL based URL request" ON)
option(OPENSSL "use OpenSSL" ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so")

set(RAVL_SRC ${RAVL_SRC_DIR}/http_client.cpp ${RAVL_SRC_DIR}/ravl.cpp)
set(RAVL_INCLUDE 3rdparty ${RAVL_DIR}/include)
set(RAVL_DEFS)
set(RAVL_LIB_DEPS)
set(RAVL_LIB_DIRS)

if(OPENSSL)
  find_package(OpenSSL REQUIRED)
  list(APPEND RAVL_DEFS HAVE_OPENSSL)
  list(APPEND RAVL_LIB_DEPS crypto)
endif()

if(SGX)
  list(APPEND RAVL_DEFS HAVE_SGX)
  list(APPEND RAVL_SRC ${RAVL_SRC_DIR}/sgx.cpp)
endif()

if(OE)
  list(APPEND RAVL_DEFS HAVE_OPEN_ENCLAVE)
  list(APPEND RAVL_SRC ${RAVL_SRC_DIR}/oe.cpp)

  if(USE_OE_VERIFIER)
    find_package(OpenEnclave REQUIRED)
    find_library(hostverify oehostverify PATHS ${OpenEnclave_DIR}/../host REQUIRED)
    list(APPEND RAVL_INCLUDE ${OE_INCLUDEDIR})
    list(APPEND RAVL_LIB_DIRS ${hostverify_DIR})
    list(APPEND RAVL_LIB_DEPS ${hostverify})
    list(APPEND RAVL_DEFS USE_OE_VERIFIER)
  endif()
elseif(USE_OE_VERIFIER)
  message(FATAL_ERROR "OE verifier requires OE")
endif()

if(SEV_SNP)
  list(APPEND RAVL_DEFS HAVE_SEV_SNP)
  list(APPEND RAVL_SRC ${RAVL_SRC_DIR}/sev_snp.cpp)
endif()

if(CURL)
  find_package(CURL REQUIRED)
  list(APPEND RAVL_LIB_DEPS curl)
  list(APPEND RAVL_SRC ${RAVL_SRC_DIR}/http_client_curl.cpp)
endif()

if(PROFILE)
  list(APPEND RAVL_FLAGS -g -pg)
  list(APPEND RAVL_LINK_OPTS -g -pg)
endif()

set(RAVL_TARGETS)

if(STATIC)
  add_library(ravl STATIC ${RAVL_SRC})
  target_include_directories(ravl
    PRIVATE ${RAVL_INCLUDE}
    PUBLIC
      "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
      "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
  target_compile_options(ravl PRIVATE ${RAVL_FLAGS})
  target_compile_definitions(ravl PRIVATE ${RAVL_DEFS})
  target_link_directories(ravl PRIVATE ${RAVL_LIB_DIRS})
  target_link_libraries(ravl INTERFACE ${RAVL_LIB_DEPS})
  target_link_options(ravl PRIVATE ${RAVL_LINK_OPTS})
  target_include_directories(ravl INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
  list(APPEND RAVL_TARGETS ravl)
endif()

if(SHARED)
  add_library(ravl-shared SHARED ${RAVL_SRC})
  target_include_directories(ravl-shared
    PRIVATE ${RAVL_INCLUDE}
    PUBLIC
      "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
      "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    )
  target_compile_options(ravl-shared PRIVATE ${RAVL_FLAGS})
  target_compile_definitions(ravl-shared PRIVATE ${RAVL_DEFS})
  target_link_directories(ravl-shared PRIVATE ${RAVL_LIB_DIRS})
  target_link_libraries(ravl-shared INTERFACE ${RAVL_LIB_DEPS})
  target_link_options(ravl-shared PRIVATE ${RAVL_LINK_OPTS})
  set_target_properties(ravl-shared PROPERTIES OUTPUT_NAME ravl)
  target_include_directories(ravl-shared INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
  list(APPEND RAVL_TARGETS ravl-shared)
endif()

if(CLI)
  add_executable(ravl-cli ${RAVL_SRC_DIR}/cli.cpp)
  target_include_directories(ravl-cli PRIVATE ${RAVL_DIR}/include)
  set_target_properties(ravl-cli PROPERTIES OUTPUT_NAME ravl)
  target_link_libraries(ravl-cli PRIVATE $<BUILD_INTERFACE:ravl> pthread)
  list(APPEND RAVL_TARGETS ravl-cli)
endif()


include(GNUInstallDirs)

install(TARGETS ${RAVL_TARGETS}
        EXPORT ravl-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT ravl-targets
        FILE ravl-config.cmake
        NAMESPACE ravl::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ravl
)

if(TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
