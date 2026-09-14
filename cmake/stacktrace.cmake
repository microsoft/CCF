# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

include(CheckCXXSourceCompiles)
include(CMakePushCheckState)

set(
  CCF_STACKTRACE_BACKEND
  "AUTO"
  CACHE STRING
  "Task stacktrace backend: AUTO, STD, or LIBBACKTRACE"
)
set_property(
  CACHE CCF_STACKTRACE_BACKEND
  PROPERTY STRINGS AUTO STD LIBBACKTRACE
)

# Function scope also restores the caller's language and try_compile settings.
function(ccf_detect_stacktrace)
  if(NOT CCF_STACKTRACE_BACKEND MATCHES "^(AUTO|STD|LIBBACKTRACE)$")
    message(
      FATAL_ERROR
      "Invalid CCF_STACKTRACE_BACKEND='${CCF_STACKTRACE_BACKEND}'; expected AUTO, STD, or LIBBACKTRACE."
    )
  endif()

  cmake_push_check_state()
  set(CMAKE_CXX_STANDARD 23)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  # A static-library probe would incorrectly accept missing support symbols.
  set(CMAKE_TRY_COMPILE_TARGET_TYPE EXECUTABLE)
  set(required_libraries ${CMAKE_REQUIRED_LIBRARIES})
  set(backend "")
  set(support_library "")

  if(NOT CCF_STACKTRACE_BACKEND STREQUAL "LIBBACKTRACE")
    set(
      std_source
      [=[
#include <stacktrace>
#if !defined(__cpp_lib_stacktrace) || __cpp_lib_stacktrace < 202011L
#  error C++23 std::stacktrace is not available
#endif
int main()
{
  const auto trace = std::stacktrace::current(0, 128);
  for (const auto& entry : trace)
  {
    if (!entry.description().empty() || !entry.source_file().empty() ||
        entry.source_line() != 0 || entry.native_handle() != 0)
      return 0;
  }
  return 0;
}
]=]
    )
    foreach(candidate IN ITEMS default stdc++exp stdc++_libbacktrace)
      set(CMAKE_REQUIRED_LIBRARIES ${required_libraries})
      if(NOT candidate STREQUAL "default")
        list(APPEND CMAKE_REQUIRED_LIBRARIES "${candidate}")
      endif()
      # Recheck on reconfigure, including when the selected mode changes.
      unset(CCF_STACKTRACE_STD_LINKS CACHE)
      check_cxx_source_compiles("${std_source}" CCF_STACKTRACE_STD_LINKS)
      if(CCF_STACKTRACE_STD_LINKS)
        set(backend STD)
        if(NOT candidate STREQUAL "default")
          set(support_library "${candidate}")
        endif()
        break()
      endif()
    endforeach()
    unset(CCF_STACKTRACE_STD_LINKS CACHE)

    if(NOT backend AND CCF_STACKTRACE_BACKEND STREQUAL "STD")
      message(
        FATAL_ERROR
        "CCF_STACKTRACE_BACKEND=STD requires usable C++23 std::stacktrace with the active compiler and standard library. "
        "Executable compile-and-link probes failed with default libraries, stdc++exp, and stdc++_libbacktrace. "
        "Install the matching standard-library development package, or select AUTO/LIBBACKTRACE. See CMake's configure log."
      )
    endif()
  endif()

  if(NOT backend)
    find_path(BACKTRACE_INCLUDE_DIR backtrace.h)
    find_library(BACKTRACE_LIBRARY backtrace)
    if(NOT BACKTRACE_INCLUDE_DIR OR NOT BACKTRACE_LIBRARY)
      message(
        FATAL_ERROR
        "CCF_STACKTRACE_BACKEND=${CCF_STACKTRACE_BACKEND} selected LIBBACKTRACE, but backtrace.h or library 'backtrace' was not found. "
        "Install libbacktrace development files (libbacktrace-static on Azure Linux 3), or use a toolchain with C++23 std::stacktrace."
      )
    endif()
    list(APPEND CMAKE_REQUIRED_INCLUDES "${BACKTRACE_INCLUDE_DIR}")
    set(CMAKE_REQUIRED_LIBRARIES ${required_libraries} "${BACKTRACE_LIBRARY}")
    unset(CCF_STACKTRACE_LIBBACKTRACE_LINKS CACHE)
    check_cxx_source_compiles(
      [=[
#include <backtrace.h>
int main()
{
  auto error = +[](void*, const char*, int) {};
  auto* state = backtrace_create_state(nullptr, 1, error, nullptr);
  backtrace_simple(state, 0, +[](void*, uintptr_t) { return 0; }, error, nullptr);
  backtrace_pcinfo(state, 0,
    +[](void*, uintptr_t, const char*, int, const char*) { return 0; }, error, nullptr);
  backtrace_syminfo(state, 0,
    +[](void*, uintptr_t, const char*, uintptr_t, uintptr_t) {}, error, nullptr);
}
]=]
      CCF_STACKTRACE_LIBBACKTRACE_LINKS
    )
    if(NOT CCF_STACKTRACE_LIBBACKTRACE_LINKS)
      message(
        FATAL_ERROR
        "CCF_STACKTRACE_BACKEND=${CCF_STACKTRACE_BACKEND} selected LIBBACKTRACE, but its executable compile-and-link probe failed. "
        "Check BACKTRACE_INCLUDE_DIR and BACKTRACE_LIBRARY and install a compatible libbacktrace. See CMake's configure log."
      )
    endif()
    unset(CCF_STACKTRACE_LIBBACKTRACE_LINKS CACHE)
    set(backend LIBBACKTRACE)
    set(support_library backtrace)
  endif()

  cmake_pop_check_state()
  set(
    CCF_STACKTRACE_BACKEND_RESOLVED
    "${backend}"
    CACHE INTERNAL
    "Resolved task stacktrace backend"
    FORCE
  )
  set(
    CCF_STACKTRACE_SUPPORT_LIBRARY
    "${support_library}"
    CACHE INTERNAL
    "Task stacktrace support link library (empty for default libraries)"
    FORCE
  )
  if(support_library)
    message(
      STATUS
      "CCF stacktrace backend: ${backend} (support library: ${support_library})"
    )
  else()
    message(STATUS "CCF stacktrace backend: ${backend} (default libraries)")
  endif()
endfunction()

ccf_detect_stacktrace()
