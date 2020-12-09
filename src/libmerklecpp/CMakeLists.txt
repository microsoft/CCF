project(merklecpp LANGUAGES CXX C ASM)

cmake_minimum_required(VERSION 3.18.2)
set(CMAKE_CXX_STANDARD 17)

set(MERKLECPP_DIR ${CMAKE_CURRENT_SOURCE_DIR})

option(PROFILE "enable profiling" OFF)
option(EVERCRYPT "enable comparison with EverCrypt Merkle trees" OFF)
option(TRACE "enable debug traces" OFF)
option(TESTS "enable testing" OFF)

add_library(merklecpp INTERFACE)
target_include_directories(merklecpp INTERFACE .)

install(TARGETS merklecpp)

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
  endif()

  enable_testing()

  function(add_unit_test NAME SRC)
    add_executable(${NAME} ${SRC})
    target_link_libraries(${NAME} PRIVATE $<BUILD_INTERFACE:merklecpp>)

    if(TRACE)
      target_compile_definitions(${NAME} PRIVATE WITH_TRACE)
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
    endif()

    if(EVERCRYPT)
      target_link_libraries(${NAME} PRIVATE evercrypt.host)
      target_compile_definitions(${NAME} PRIVATE HAVE_EVERCRYPT)
    endif()

    add_test(${NAME} ${NAME})
  endfunction()

  add_subdirectory(test)
endif()
