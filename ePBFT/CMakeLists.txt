cmake_minimum_required(VERSION 3.10)

# Note: this needs to be done before project(), otherwise CMAKE_*_COMPILER is already set by CMake
# If the user has not expressed any choice, we attempt to default to Clang >= 7
# If they have expressed even a partial choice, the usual CMake selection logic applies
# If we cannot find both a suitable clang and a suitable clang++, the usual CMake selection logic applies
if ((NOT CMAKE_C_COMPILER) AND (NOT CMAKE_CXX_COMPILER)
    AND "$ENV{CC}" STREQUAL "" AND "$ENV{CXX}" STREQUAL "")
  find_program(FOUND_CMAKE_C_COMPILER NAMES clang-7.0 clang-7 clang-8)
  find_program(FOUND_CMAKE_CXX_COMPILER NAMES clang++-7.0 clang++-7 clang++-8)
  if (NOT (FOUND_CMAKE_C_COMPILER AND FOUND_CMAKE_CXX_COMPILER))
    message(WARNING "Clang >= 7 not found, will use default compiler. "
      "Override the compiler by setting CC and CXX environment variables.")
  else()
    # CMAKE_*_COMPILER can only be set once, and cannot be unset, we either
    # want both, or none at all.
    set(CMAKE_C_COMPILER "${FOUND_CMAKE_C_COMPILER}")
    set(CMAKE_CXX_COMPILER "${FOUND_CMAKE_CXX_COMPILER}")
  endif()
endif()

project(pbft)

if (CMAKE_C_COMPILER_ID MATCHES "Clang")
    if (CMAKE_C_COMPILER_VERSION VERSION_LESS 7)
        message(WARNING "officially support Clang >= 7 only, "
            "but your Clang version (${CMAKE_C_COMPILER_VERSION}) "
            "is older than that. Build problems may occur.")
    endif()

endif()

find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(PBFT_DIR ${CMAKE_CURRENT_SOURCE_DIR})

configure_file(${PBFT_DIR}/tests/tests.sh ${CMAKE_CURRENT_BINARY_DIR}/tests.sh COPYONLY)

if(MSVC)
  # Set Windows compiler options.
  add_compile_options(/W3 /std:c++latest)
else()
  # Set Linux compiler options
  add_compile_options(-Wall -Werror)
endif()

set(default_build_type "RelWithDebInfo")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
    set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

option(COLORED_OUTPUT "Always produce ANSI-colored output (GNU/Clang only)." TRUE)
option(SAN "Enable Address and Undefined Behavior Sanitizers" OFF)
option(SIGN_BATCH "Should a replica sign the batch of messages it plans to execute" ON)

if (${COLORED_OUTPUT})
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
       add_compile_options (-fdiagnostics-color=always)
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       add_compile_options (-fcolor-diagnostics)
    endif ()
endif ()

## use the hint from above to find where 'zmq.hpp' is located
find_path(ZeroMQ_INCLUDE_DIR
        NAMES zmq.hpp
        PATHS ${PC_ZeroMQ_INCLUDE_DIRS}
        )

## use the hint from about to find the location of libzmq
find_library(ZeroMQ_LIBRARY
        NAMES zmq
        PATHS ${PC_ZeroMQ_LIBRARY_DIRS}
        )

option(BUILD_TESTS "Build tests" ON)

set(PBFT_BUILD_HOST TRUE)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/pbft.cmake)

set(EVERCRYPT_PREFIX ${PBFT_DIR}/3rdparty/evercrypt)

set(EVERCRYPT_INC
  ${EVERCRYPT_PREFIX}
  ${EVERCRYPT_PREFIX}/kremlin
)

file(GLOB_RECURSE EVERCRYPT_SRC "${EVERCRYPT_PREFIX}/*.[cS]")

enable_language(ASM)

add_library(evercrypt STATIC ${EVERCRYPT_SRC})
target_compile_options(evercrypt PRIVATE -Wno-everything)
target_include_directories(evercrypt PRIVATE ${EVERCRYPT_INC})

include_directories(
  SYSTEM ${PBFT_DIR}/3rdparty ${EVERCRYPT_INC}
)

set(SNMALLOC_ONLY_HEADER_LIBRARY ON)
add_subdirectory(3rdparty/snmalloc EXCLUDE_FROM_ALL)

add_library(libcommon STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libcommon/network_udp.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libcommon/network_udp_mt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libcommon/network_zmq_tcp.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libcommon/ITimer.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libcommon/Time.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libcommon/Statistics.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libcommon/snmalloc.cpp
)
target_link_libraries(libcommon PRIVATE snmalloc_lib)

target_include_directories(libcommon PRIVATE
  ${ZeroMQ_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libbyz
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libcommon
)

target_include_directories(libbyz.host PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libcommon
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libbyz
)

if(DEFINED PBFT_BUILD_ENCLAVE)
  target_include_directories(libbyz.enclave PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libcommon
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libbyz
  )
endif()

target_include_directories(libbyz.host PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/crypto
)

function(use_libbyz name)

  target_include_directories(${name} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libcommon
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/libbyz
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/crypto
    ${EVERCRYPT_INC}
  )
  target_link_libraries(${name} PRIVATE libbyz.host libcommon ${ZeroMQ_LIBRARY} evercrypt ${PLATFORM_SPECIFIC_TEST_LIBS})

endfunction()

function(add_san name)
  if(SAN)
    target_compile_options(${name} PRIVATE
      -fsanitize=undefined,address -fno-omit-frame-pointer -fno-sanitize-recover=all
      -fno-sanitize=function
    )
    target_link_libraries(${name} PRIVATE
      -fsanitize=undefined,address -fno-omit-frame-pointer -fno-sanitize-recover=all
      -fno-sanitize=function
    )
  endif()
endfunction()


## Unit test wrapper
function(add_unit_test name)
  add_executable(${name}
    ${ARGN})
  target_include_directories(${name} PRIVATE
    src)
  target_compile_options(${name} PRIVATE
    -fdiagnostics-color=always
    ${COVERAGE_FLAGS})
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
      target_link_libraries(${name} PRIVATE gcov libbyz.host libcommon)
    else()
      target_link_libraries(${name} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
    endif()

  use_libbyz(${name})

  add_test(
    NAME ${name}
    COMMAND ./${name} -nv)
endfunction()


add_executable(simple-server
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/bft-simple/replica_main.cpp
)
target_link_libraries(simple-server PRIVATE ${CMAKE_THREAD_LIBS_INIT})
use_libbyz(simple-server)
add_san(simple-server)

add_executable(simple-client
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/bft-simple/client_main.cpp
)
use_libbyz(simple-client)
add_san(simple-client)

add_executable(generate-keys
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pbft/crypto/generate_keypair.cpp
)
use_libbyz(generate-keys)
add_san(generate-keys)

add_library(libcommon.mock STATIC
  ${PBFT_DIR}/src/pbft/libcommon/mocks/network_mock_tcp.cpp)
target_link_libraries(libcommon.mock PRIVATE libcommon)
target_include_directories(libcommon.mock PRIVATE
  ${PBFT_DIR}/src/pbft/
  ${PBFT_DIR}/src/pbft/libbyz
  ${PBFT_DIR}/src/pbft/libcommon
)

if(BUILD_TESTS)
  # Tests
  enable_testing()

  ## Unit tests
  add_unit_test(test_keys
      ${PBFT_DIR}/src/pbft/crypto/test/test_keys.cpp)
  target_link_libraries(test_keys PRIVATE evercrypt)
  add_san(test_keys)

  add_unit_test(test_libbyz
      ${PBFT_DIR}/src/pbft/libbyz/test/main.cpp)
  target_include_directories(test_libbyz PRIVATE ${PBFT_DIR}/src/pbft/libcommon/mocks)
  target_link_libraries(test_libbyz PRIVATE libcommon.mock)
  add_san(test_libbyz)

  ## integration tests
  add_executable(replica-test
    ${PBFT_DIR}/src/pbft/bft-simple/test/replica_test.cpp
  )
  target_link_libraries(replica-test PRIVATE ${CMAKE_THREAD_LIBS_INIT})
  target_include_directories(replica-test PRIVATE ${PBFT_DIR}/src/pbft/bft-simple)
  use_libbyz(replica-test)
  add_san(replica-test)

  add_executable(ledger-reader
    ${PBFT_DIR}/src/pbft/bft-simple/test/ledger_reader_main.cpp
  )
  target_link_libraries(ledger-reader PRIVATE ${CMAKE_THREAD_LIBS_INIT})
  target_include_directories(ledger-reader PRIVATE ${PBFT_DIR}/src/pbft/bft-simple)
  use_libbyz(ledger-reader)

  add_executable(test-controller
    ${PBFT_DIR}/src/pbft/bft-simple/test/test_controller_main.cpp
  )
  target_link_libraries(test-controller PRIVATE ${CMAKE_THREAD_LIBS_INIT})
  target_include_directories(test-controller PRIVATE ${PBFT_DIR}/src/pbft/bft-simple)
  use_libbyz(test-controller)

  add_executable(client-test
    ${PBFT_DIR}/src/pbft/bft-simple/test/client_test.cpp
  )
  target_include_directories(client-test PRIVATE ${PBFT_DIR}/src/pbft/bft-simple)
  use_libbyz(client-test)
  add_san(client-test)

  add_test(
    NAME test_UDP
    COMMAND
      python3 ${PBFT_DIR}/tests/infra/e2e_test.py --ip 127.0.0.1 --servers 4 --clients 2 --test-config ${PBFT_DIR}/tests/test_config --run-time 30
  )

  add_test(
    NAME test_client_proxy
    COMMAND
      python3 ${PBFT_DIR}/tests/infra/e2e_test.py --ip 127.0.0.1 --servers 4 --clients 0 --test-config ${PBFT_DIR}/tests/test_config --test-client-proxy
      --run-time 30
  )

  add_test(
    NAME test_client_proxy_f_0
    COMMAND
      python3 ${PBFT_DIR}/tests/infra/e2e_test.py --ip 127.0.0.1 --servers 4 --clients 0 --test-config ${PBFT_DIR}/tests/test_config --test-client-proxy
      --run-time 60 --f 0
  )

  add_test(
    NAME test_UDP_with_delay
    COMMAND
      python3 ${PBFT_DIR}/tests/infra/e2e_test.py --ip 127.0.0.1 --servers 4 --clients 2 --test-config ${PBFT_DIR}/tests/test_config --with-delays
  )

  add_test(
    NAME test_TCP_with_delay
    COMMAND
      python3 ${PBFT_DIR}/tests/infra/e2e_test.py --ip 127.0.0.1 --servers 4 --clients 2 --test-config ${PBFT_DIR}/tests/test_config --transport TCP_ZMQ --with-delays
  )

  add_test(
    NAME test_UDP_with_delay_and_ledger
    COMMAND
      python3 ${PBFT_DIR}/tests/infra/e2e_test.py --ip 127.0.0.1 --servers 4 --clients 2 --test-config ${PBFT_DIR}/tests/test_config --with-delays --ledger
  )

endif()
