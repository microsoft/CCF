project(merklecpp LANGUAGES CXX C ASM)

cmake_minimum_required(VERSION 3.18.2)
set(CMAKE_CXX_STANDARD 17)

set(MERKLECPP_DIR ${CMAKE_CURRENT_SOURCE_DIR})

option(PROFILE "enable profiling" OFF)
option(TESTS "enable testing" OFF)
option(EVERCRYPT "enable comparison with EverCrypt Merkle trees" OFF)
option(OPENSSL "enable OpenSSL" OFF)
option(MBEDTLS "enable mbedTLS" OFF)

option(TRACE "enable debug traces" OFF)
option(USE_CCF_LOG "Use the CCF logging infrastructure for traces" OFF)

add_library(merklecpp INTERFACE)
target_include_directories(merklecpp INTERFACE .)

if(TRACE)
  target_compile_definitions(merklecpp INTERFACE WITH_TRACE)
endif()

if(USE_CCF_LOG)
  target_compile_definitions(merklecpp INTERFACE USE_CCF_LOG)
endif()

install(TARGETS merklecpp)

if(OPENSSL)
  find_package(OpenSSL)
endif()

if(MBEDTLS)
  find_library(MBEDCRYPTO_LIBRARY mbedcrypto)
endif()

if(TESTS)
  if(EVERCRYPT)
    if(NOT (DEFINED $ENV{EVERCRYPT_DIR}))
      set(EVERCRYPT_DIR ../../3rdparty/hacl-star/evercrypt)
    endif()

    file(GLOB EVERCRYPT_SRC "${EVERCRYPT_DIR}/*.c"
         "${EVERCRYPT_DIR}/*-x86_64-linux.S"
    )
    add_library(evercrypt.host STATIC ${EVERCRYPT_SRC})
    target_include_directories(
      evercrypt.host PUBLIC ${EVERCRYPT_DIR} ${EVERCRYPT_DIR}/kremlin
                            ${EVERCRYPT_DIR}/kremlin/kremlib
    )
    set_target_properties(evercrypt.host PROPERTIES LINKER_LANGUAGE C)
    target_compile_options(evercrypt.host PRIVATE -O3 -march=native -mtune=native)
  endif()

  enable_testing()

  function(add_unit_test NAME SRC)
    add_executable(${NAME} ${SRC})
    target_link_libraries(${NAME} PRIVATE $<BUILD_INTERFACE:merklecpp>)

    if(TRACE)
      target_compile_definitions(${NAME} PRIVATE WITH_TRACE)
      if(USE_CCF_LOG)
        target_compile_definitions(${NAME} PRIVATE USE_CCF_LOG)
      endif()
    endif()

    if(PROFILE)
      target_compile_options(${NAME} PRIVATE -g -pg)
      target_link_options(${NAME} PRIVATE -g -pg)
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
      target_compile_options(
        ${NAME} PRIVATE -fsanitize=address -fno-omit-frame-pointer
      )
      target_link_options(${NAME} PRIVATE -fsanitize=address)
    else()
      target_compile_options(${NAME} PRIVATE -O3 -march=native -mtune=native)
    endif()

    if(EVERCRYPT)
      target_link_libraries(${NAME} PRIVATE evercrypt.host)
      target_compile_definitions(${NAME} PRIVATE HAVE_EVERCRYPT)
    endif()

    if(OPENSSL)
      target_link_libraries(${NAME} PRIVATE crypto)
      target_compile_definitions(${NAME} PRIVATE HAVE_OPENSSL)
    endif()

    if(MBEDTLS)
      target_link_libraries(${NAME} PRIVATE mbedcrypto)
      target_compile_definitions(${NAME} PRIVATE HAVE_MBEDTLS)
    endif()

    add_test(${NAME} ${NAME})
  endfunction()

  add_subdirectory(test)
endif()
